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
# The web tier's own login rate limiter: two rolling-window counters, one
# keyed by source address and one by the submitted username, both counting
# FAILED login attempts only. State lives under /var/lib/csf-ui/rl/, mode
# 0600, one file per dimension.
#
# This is NOT the same control as csf-ui-helper's per-username lockout
# (docs/WEBUI-RPC.md S5.14). That one is the helper's own, keeps holding even
# when this web tier is the attacker, and this module must never be treated
# as a substitute for it. What this module adds is a SECOND, independent
# guard that acts before a guess ever reaches the socket - by source address,
# which the helper's counter does not see at all, and as an earlier line of
# defence by username so an obviously-hostile client burns a local counter
# before it burns one of the helper's own crypt() calls.
#
# NEVER WRITES TO csf.deny, and cannot: this module has no dependency on
# Client.pm and calls no operation on the frozen allowlist at all. Letting
# unauthenticated traffic add a firewall entry would let an attacker get a
# chosen address blocked - a victim's, or a shared NAT egress a whole office
# sits behind - which is exactly the outcome a rate limiter must never be
# able to cause (spec S7).
#
# G3: every failure to read or maintain either counter's state is answered
# as "blocked", never as "not blocked". The measured failure this project is
# not going to repeat (csf-ui-helper once discarded a failed state write and
# its own rate limiter silently stopped enforcing while its test suite kept
# passing) is exactly what "unavailable therefore not blocked" would be, one
# layer up.
###############################################################################
package ConfigServer::UI::RateLimit;

use strict;
use warnings;

use Fcntl qw(:DEFAULT :flock);
use JSON::Tiny ();

our $VERSION = '1.00';

our $DEFAULT_DIR        = '/var/lib/csf-ui/rl';
our $DEFAULT_WINDOW     = 900;  # 15 minutes
our $DEFAULT_ADDR_LIMIT = 5;    # failed logins per address per window
our $DEFAULT_USER_LIMIT = 10;   # failed logins per username per window

sub new {
	my ($class, %opt) = @_;
	return bless {
		dir        => $opt{dir}        || $DEFAULT_DIR,
		window     => defined $opt{window}     ? $opt{window}     : $DEFAULT_WINDOW,
		addr_limit => defined $opt{addr_limit} ? $opt{addr_limit} : $DEFAULT_ADDR_LIMIT,
		user_limit => defined $opt{user_limit} ? $opt{user_limit} : $DEFAULT_USER_LIMIT,
		now        => $opt{now} || sub { time() },
	}, $class;
}

sub _now  { my ($self) = @_; return $self->{now}->() }
sub _path { my ($self, $kind) = @_; return "$self->{dir}/$kind.state" }

###############################################################################
# Locked state, read-modify-write, temp-file-and-rename - the same shape
# csf-ui-helper uses for its own rate.state and authfail.state (section 7,
# section 5.14), reproduced here rather than shared: this module runs in a
# different process under a different uid than the helper, so there is
# nothing to import from it, and the pattern is short enough that copying it
# is cheaper and clearer than inventing a dependency between the two halves
# for the sake of a dozen lines.
###############################################################################
sub _lock_state {
	my ($path) = @_;
	for (1 .. 10) {
		sysopen(my $fh, $path, O_RDWR | O_CREAT, 0600) or return undef;
		flock($fh, LOCK_EX) or do { close $fh; return undef };
		my @on_handle = stat($fh);
		my @on_path   = stat($path);
		if (@on_path && @on_handle && $on_handle[0] == $on_path[0] && $on_handle[1] == $on_path[1]) {
			return $fh;
		}
		close $fh;
	}
	return undef;
}

sub _read_state {
	my ($fh) = @_;
	seek($fh, 0, 0);
	local $/;
	my $data = <$fh>;
	return {} unless defined $data && length $data;
	my $struct = eval { JSON::Tiny::decode_json($data) };
	return (ref($struct) eq 'HASH') ? $struct : {};
}

sub _write_state {
	my ($path, $struct) = @_;
	my $temp = "$path.tmp.$$";
	sysopen(my $fh, $temp, O_WRONLY | O_CREAT | O_TRUNC, 0600) or return 0;
	my $json = eval { JSON::Tiny::encode_json($struct) };
	unless (defined $json) { close $fh; unlink $temp; return 0 }
	print { $fh } $json;
	close $fh;
	unless (rename($temp, $path)) { unlink $temp; return 0 }
	return 1;
}

# Returns undef when the state could not be opened, locked or (if the caller
# marked it dirty) rewritten. Every caller below treats undef as "the count
# cannot be trusted", never as "carry on unmetered" (G3).
sub _with_state {
	my ($self, $kind, $code) = @_;
	unless (-d $self->{dir}) {
		mkdir($self->{dir}, 0700) or return undef;
	}
	my $path = $self->_path($kind);
	my $fh = _lock_state($path);
	return undef unless $fh;
	my $struct = _read_state($fh);
	my ($result, $dirty) = $code->($struct);
	if ($dirty && !_write_state($path, $struct)) {
		close $fh;
		return undef;
	}
	close $fh;
	return $result;
}

# Drops seconds outside the rolling window from $bucket IN PLACE and returns
# the sum of what remains. Bucketed by whole seconds, the same granularity
# csf-ui-helper's own counters use.
sub _prune_and_count {
	my ($bucket, $now, $window) = @_;
	for my $second (keys %$bucket) {
		delete $bucket->{$second} if $second !~ /^[0-9]+$/ || $now - $second >= $window;
	}
	my $total = 0;
	$total += $bucket->{$_} for keys %$bucket;
	return $total;
}

###############################################################################
# blocked_addr / blocked_user / blocked - read-only. Call this BEFORE asking
# the helper to verify a password, so a caller already over either cap never
# reaches crypt() at all. Peeking never increments anything - only
# record_failure() below does that - so a successful login never counts
# against either bucket, and checking twice for the same attempt (once to
# decide whether to even try, once implicitly via the outcome) never
# double-counts.
###############################################################################
sub _peek {
	my ($self, $kind, $key, $limit) = @_;
	my $now = $self->_now;
	my $result = $self->_with_state($kind, sub {
		my ($state) = @_;
		my $bucket = $state->{$key} || {};
		my $total = _prune_and_count($bucket, $now, $self->{window});
		return ($total, 0); # peeking never writes
	});
	return 1 unless defined $result; # G3: unavailable -> fail closed -> blocked
	return $result >= $limit ? 1 : 0;
}

sub blocked_addr {
	my ($self, $addr) = @_;
	return 0 unless defined $addr && length $addr;
	return $self->_peek('addr', $addr, $self->{addr_limit});
}

sub blocked_user {
	my ($self, $user) = @_;
	return 0 unless defined $user && length $user;
	return $self->_peek('user', $user, $self->{user_limit});
}

sub blocked {
	my ($self, $addr, $user) = @_;
	return 1 if $self->blocked_addr($addr);
	return 1 if $self->blocked_user($user);
	return 0;
}

###############################################################################
# record_failure($addr, $user) - the only place either counter is
# incremented, and it is the caller's job to call it only after a login
# attempt has come back as a verified failure (wrong password, or the
# helper's own lockout) - never speculatively, and never on success.
#
# A write that cannot be persisted here is not separately alarmed: the same
# directory or disk problem that would break this write would also make the
# NEXT blocked() call answer "unavailable", which already fails closed
# (above). The two behaviours compose safely without this method needing to
# report anything back.
###############################################################################
sub record_failure {
	my ($self, $addr, $user) = @_;
	my $now = $self->_now;

	if (defined $addr && length $addr) {
		$self->_with_state('addr', sub {
			my ($state) = @_;
			my $bucket = $state->{$addr} || {};
			_prune_and_count($bucket, $now, $self->{window});
			$bucket->{$now}++;
			$state->{$addr} = $bucket;
			return (1, 1);
		});
	}
	if (defined $user && length $user) {
		$self->_with_state('user', sub {
			my ($state) = @_;
			my $bucket = $state->{$user} || {};
			_prune_and_count($bucket, $now, $self->{window});
			$bucket->{$now}++;
			$state->{$user} = $bucket;
			return (1, 1);
		});
	}
	return;
}

1;
