#!/usr/bin/perl
###############################################################################
# Copyright (C) 2006-2025 Jonathan Michaelson
#
# https://github.com/waytotheweb/scripts
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 3 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, see <https://www.gnu.org/licenses>.
###############################################################################
# Added 2026-09-11 in https://github.com/nkyo/csf - see CHANGES.md.
#
# Server-side sessions for the unprivileged web tier. The cookie carries
# nothing but an opaque 32-byte random identifier; the username, role, CSRF
# nonce and both timestamps live in a file under /var/lib/csf-ui/sessions,
# mode 0600, that only csfui can read. This is deliberately not a signed or
# encrypted client-side token: a stolen cookie names a row this process can
# revoke by deleting a file, not a self-contained credential that stays valid
# until it expires no matter what the server does.
#
# Two rules bind everywhere below:
#
#   * A tampered or unknown identifier is refused identically to an expired
#     one - load() returns undef for all of "no such file", "wrong id
#     grammar", "corrupt record", "idle timeout" and "absolute timeout", with
#     nothing in the return value or in this module's behaviour that lets a
#     caller tell them apart. Distinguishing them would hand an attacker an
#     oracle for guessing valid session ids.
#   * There is no pre-authentication session anywhere in this design.
#     create() is the only way a session comes into existence, and csf-ui
#     only ever calls it after a positive verdict from the helper's
#     `authenticate` (docs/WEBUI-RPC.md S5.14). So there is nothing to fix
#     session-fixation against: an id never exists before the principal it
#     names has already proven who they are.
###############################################################################
package ConfigServer::UI::Session;

use strict;
use warnings;

use Fcntl qw(:DEFAULT);
use MIME::Base64 ();

our $VERSION = '1.00';

# Not part of docs/WEBUI-RPC.md - the RPC contract has nothing to say about
# HTTP cookies, so this name is this module's own to pick and document. Task
# 5 (which parses the incoming Cookie header) and Task 7 (whose login form
# receives the Set-Cookie) both need to agree with this exact string.
our $COOKIE_NAME = 'csfui_sid';

our $DEFAULT_DIR  = '/var/lib/csf-ui/sessions';
our $DEFAULT_IDLE = 1800;   # ui.conf UI_SESSION_IDLE default, docs/WEBUI-RPC.md S10
our $DEFAULT_MAX  = 43200;  # ui.conf UI_SESSION_MAX default, docs/WEBUI-RPC.md S10

# 32 raw bytes, base64url, padding stripped: always exactly 43 characters
# drawn from [A-Za-z0-9_-]. Fixed length and a fixed charset both matter -
# the id becomes a filename directly, in exactly one place (_path() below),
# and nowhere else in this module builds a path from caller input. A value
# that does not match this is never opened, never stat'd, and never told
# apart from "no such session": it is simply not a session id.
our $ID_BYTES = 32;
my $ID_RE = qr/\A[A-Za-z0-9_-]{43}\z/;

my %VALID_ROLE = (admin => 1, support => 1);

###############################################################################
# Random bytes and base64url - the same /dev/urandom idiom Auth.pm uses for
# salts, applied here to session ids and CSRF nonces.
###############################################################################
sub _random_bytes {
	my ($count) = @_;
	open(my $fh, '<', '/dev/urandom') or die "cannot open /dev/urandom: $!\n";
	binmode($fh);
	my $data = '';
	while (length($data) < $count) {
		my $chunk;
		my $read = sysread($fh, $chunk, $count - length($data));
		unless (defined $read && $read > 0) {
			close $fh;
			die "short read from /dev/urandom\n";
		}
		$data .= $chunk;
	}
	close $fh;
	return $data;
}

sub _b64url {
	my ($bytes) = @_;
	my $text = MIME::Base64::encode_base64($bytes, '');
	$text =~ tr{+/}{-_};
	$text =~ s/=+\z//;
	return $text;
}

###############################################################################
# Construction. idle/max/dir all default to the values above; a caller that
# has read ui.conf's UI_SESSION_IDLE/UI_SESSION_MAX may override them here -
# this module does not read ui.conf itself (see ui-src/bin/csf-ui, which
# does, the same best-effort way csf-ui-passwd already reads
# UI_CRYPT_ROUNDS).
###############################################################################
sub new {
	my ($class, %opt) = @_;
	return bless {
		dir  => $opt{dir}  || $DEFAULT_DIR,
		idle => defined $opt{idle} ? $opt{idle} : $DEFAULT_IDLE,
		max  => defined $opt{max}  ? $opt{max}  : $DEFAULT_MAX,
		now  => $opt{now} || sub { time() },
	}, $class;
}

sub _now { my ($self) = @_; return $self->{now}->() }

sub _path {
	my ($self, $id) = @_;
	return undef unless defined $id && !ref($id) && $id =~ $ID_RE;
	return "$self->{dir}/$id";
}

###############################################################################
# On-disk record: user:role:csrf:created:last_use - the same flat,
# colon-delimited shape Auth.pm uses for /etc/csf-ui/users, and for the same
# reason: every field here is drawn from a charset that cannot contain ':' or
# a newline (username per docs/WEBUI-RPC.md S4.9, role is one of two fixed
# words, the csrf nonce is base64url, both epochs are digits-only), so a
# JSON encoder would buy nothing that split(/:/) does not already give.
###############################################################################
sub _serialise {
	my (%rec) = @_;
	return join(':', $rec{user}, $rec{role}, $rec{csrf}, $rec{created}, $rec{last_use});
}

sub _parse {
	my ($line) = @_;
	return undef unless defined $line;
	$line =~ s/[\r\n]+\z//;
	my @field = split(/:/, $line, -1);
	return undef unless @field == 5;
	my ($user, $role, $csrf, $created, $last_use) = @field;
	return undef unless defined $user && length($user);
	return undef unless defined $role && $VALID_ROLE{$role};
	return undef unless defined $csrf && length($csrf);
	return undef unless defined $created  && $created  =~ /\A[0-9]+\z/;
	return undef unless defined $last_use && $last_use =~ /\A[0-9]+\z/;
	return {
		user     => $user,
		role     => $role,
		csrf     => $csrf,
		created  => $created  + 0,
		last_use => $last_use + 0,
	};
}

sub _write {
	my ($self, $id, $rec, $flags) = @_;
	my $path = $self->_path($id);
	return 0 unless defined $path;
	unless (-d $self->{dir}) {
		mkdir($self->{dir}, 0700) or return 0;
	}
	my $temp = "$path.tmp.$$";
	sysopen(my $fh, $temp, O_WRONLY | O_CREAT | ($flags || O_TRUNC), 0600) or return 0;
	print { $fh } _serialise(%$rec);
	close $fh;
	unless (rename($temp, $path)) {
		unlink $temp;
		return 0;
	}
	return 1;
}

###############################################################################
# create(user => ..., role => ...) -> \%session
#
# The only place a session id is minted. O_EXCL on the very first write of a
# freshly generated id: a collision among 256-bit random values is not a
# scenario this module expects to ever hit, and G3 says the fail-closed
# reading is to check for it anyway rather than assume the guarantee holds
# and silently overwrite a session that happens to already be using it.
###############################################################################
sub create {
	my ($self, %arg) = @_;
	die "create: user is required\n" unless defined $arg{user} && length $arg{user};
	die "create: role must be 'admin' or 'support'\n"
		unless defined $arg{role} && $VALID_ROLE{ $arg{role} };

	unless (-d $self->{dir}) {
		mkdir($self->{dir}, 0700) or die "cannot create $self->{dir}: $!\n";
	}

	my $now  = $self->_now;
	my $csrf = _b64url(_random_bytes(32));

	for (1 .. 5) {
		my $id   = _b64url(_random_bytes($ID_BYTES));
		my $path = $self->_path($id);
		die "generated a session id of the wrong shape\n" unless defined $path;

		if (sysopen(my $fh, $path, O_WRONLY | O_CREAT | O_EXCL, 0600)) {
			my $rec = {
				user => $arg{user}, role => $arg{role}, csrf => $csrf,
				created => $now, last_use => $now,
			};
			print { $fh } _serialise(%$rec);
			close $fh;
			$rec->{id} = $id;
			return $rec;
		}
		next if $!{EEXIST};
		die "cannot create session file $path: $!\n";
	}
	die "could not allocate a session id after 5 attempts\n";
}

###############################################################################
# load($id) -> \%session | undef
#
# Refreshes last_use on every successful load, which is what makes the idle
# timeout a sliding window rather than a fixed one - exactly the "checks
# session ... on every state-changing request" language in the brief, except
# this refresh happens on every request that carries a valid session,
# state-changing or not: a read-only page view is still activity.
#
# The rewrite that persists the refreshed last_use is best-effort: if it
# fails (a full disk, for instance) this request still proceeds on the
# verdict already reached from the record as read, because that verdict does
# not depend on the write succeeding. The consequence of the write failing
# leans toward the safe side on its own - the next request sees the older,
# unrefreshed last_use, so the idle timer can only expire a little earlier
# than it should, never later.
###############################################################################
sub load {
	my ($self, $id) = @_;
	my $path = $self->_path($id);
	return undef unless defined $path;

	open(my $fh, '<', $path) or return undef;
	my $line = <$fh>;
	close $fh;

	my $rec = _parse($line);
	return undef unless $rec;

	my $now = $self->_now;
	if ($now - $rec->{created} > $self->{max}) {
		$self->destroy($id);
		return undef;
	}
	if ($now - $rec->{last_use} > $self->{idle}) {
		$self->destroy($id);
		return undef;
	}

	$rec->{last_use} = $now;
	$self->_write($id, $rec);
	$rec->{id} = $id;
	return $rec;
}

sub destroy {
	my ($self, $id) = @_;
	my $path = $self->_path($id);
	return 0 unless defined $path;
	return 1 if unlink($path);
	return $!{ENOENT} ? 1 : 0;
}

###############################################################################
# csrf_ok($session, $submitted) - constant-time-in-content compare.
#
# Length is checked with an early return before the loop starts. That is
# deliberate, not an oversight: a CSRF nonce's length is fixed by this module
# (32 raw bytes, base64url) and is not secret - every legitimate nonce this
# process ever mints is the same length, so a length mismatch reveals
# nothing an attacker does not already know. What must never leak through
# timing is WHICH byte of a same-length value differs, which is what the
# XOR-accumulate loop below avoids by visiting every byte regardless of
# where - or whether - a difference is found.
#
# $COMPARE_VISITS exists only so t/30-session.t can prove the loop below
# really does run to completion rather than stopping at the first
# difference - the same test-only introspection Auth.pm's
# constant_time_equal() exposes, for the same reason: a timing assertion
# would be flaky, but counting how many byte positions the loop actually
# visited is not. Production code never reads it.
###############################################################################
our $COMPARE_VISITS = 0;

sub csrf_ok {
	my ($self, $session, $submitted) = @_;
	return 0 unless ref($session) eq 'HASH' && defined $session->{csrf};
	return 0 unless defined $submitted && !ref($submitted);

	my $a = $session->{csrf};
	my $b = "$submitted";
	return 0 unless length($a) == length($b);

	my $diff = 0;
	$COMPARE_VISITS = 0;
	for my $i (0 .. length($a) - 1) {
		$COMPARE_VISITS++;
		$diff |= ord(substr($a, $i, 1)) ^ ord(substr($b, $i, 1));
	}
	return $diff == 0 ? 1 : 0;
}

###############################################################################
# Cookie plumbing. Task 5 (or the front web server, in mode A) hands csf-ui a
# raw Cookie header value; this is the one place that knows the cookie's
# name and attributes, so parsing and emitting it live here instead of being
# re-invented per caller. All three may be called either as instance or
# class methods ($store->set_cookie_header($id) or
# ConfigServer::UI::Session->set_cookie_header($id)) - none of them touch
# $self, so both spellings work and the caller picks whichever reads better.
###############################################################################
sub id_from_cookie_header {
	my ($self, $header) = @_;
	return undef unless defined $header && length $header;
	for my $part (split(/;\s*/, $header)) {
		my ($name, $value) = split(/=/, $part, 2);
		next unless defined $name && defined $value;
		next unless $name eq $COOKIE_NAME;
		return ($value =~ $ID_RE) ? $value : undef;
	}
	return undef;
}

# HttpOnly; Secure; SameSite=Strict; Path=/ - exactly the four attributes the
# brief specifies, no more. No Max-Age or Expires: this cookie's lifetime is
# enforced entirely server-side (idle and absolute timeouts, above), and
# giving the browser an expiry would only tell an observer of the response
# how long a session is allowed to live for no benefit to the client.
sub set_cookie_header {
	my ($self, $id) = @_;
	return "$COOKIE_NAME=$id; HttpOnly; Secure; SameSite=Strict; Path=/";
}

sub clear_cookie_header {
	my ($self) = @_;
	return "$COOKIE_NAME=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0";
}

1;
