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

# §7: "A limit that cannot be counted is not a limit." That rule is about
# the helper's own counters, but the reasoning is not specific to the
# helper - it is what stops any counter in this design from silently
# becoming decorative. Bounding the number of distinct keys is the other
# half of the same rule applied here: an unbounded file is a counter this
# module could eventually fail to maintain (ENOSPC), and the fix for a
# counter that cannot be maintained is never to let it grow without limit
# in the first place. 4096 is generous headroom over any real deployment's
# concurrently-failing population within one 15-minute window while still
# bounding the cost of every read-decode-reencode-rename cycle.
our $DEFAULT_MAX_KEYS = 4096;

sub new {
	my ($class, %opt) = @_;
	return bless {
		dir        => $opt{dir}        || $DEFAULT_DIR,
		window     => defined $opt{window}     ? $opt{window}     : $DEFAULT_WINDOW,
		addr_limit => defined $opt{addr_limit} ? $opt{addr_limit} : $DEFAULT_ADDR_LIMIT,
		user_limit => defined $opt{user_limit} ? $opt{user_limit} : $DEFAULT_USER_LIMIT,
		max_keys   => defined $opt{max_keys}   ? $opt{max_keys}   : $DEFAULT_MAX_KEYS,
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

# Returns ($struct, 1) on a genuinely empty file (no state yet - a normal,
# common condition, not a failure) or a well-formed JSON object; returns
# (undef, 0) for anything else - unparseable JSON, or JSON that parsed to
# something other than an object. §7: a state file this module cannot make
# sense of is a counter that cannot be counted, and the only fail-closed
# reading is to say so, not to treat "I could not read this" the same as
# "there is nothing here yet". Reading corrupt content as {} is precisely
# what let a failed write "reset" a counter to zero one layer up, at the
# helper, in Task 2 (see the header comment above, and CHANGES.md) - the
# same failure mode, arriving here by a different door.
sub _read_state {
	my ($fh) = @_;
	seek($fh, 0, 0);
	local $/;
	my $data = <$fh>;
	return ({}, 1) unless defined $data && length $data;
	my $struct = eval { JSON::Tiny::decode_json($data) };
	return (ref($struct) eq 'HASH') ? ($struct, 1) : (undef, 0);
}

# Returns 1 only once the new content is confirmed written and in place.
# print() and close() are both checked - print() can report a failed write
# outright, and a short write that print() does not catch (buffered I/O can
# defer the error) is what close()'s own return value exists to surface, by
# flushing and reporting the flush's outcome. Checking only one of the two,
# which is the gap this replaces, lets a partially-written temp file reach
# rename() and land on top of the last known-good state - the ENOSPC path
# that turns a write failure into silent data loss rather than a refusal.
sub _write_state {
	my ($path, $struct) = @_;
	my $temp = "$path.tmp.$$";
	sysopen(my $fh, $temp, O_WRONLY | O_CREAT | O_TRUNC, 0600) or return 0;
	my $json = eval { JSON::Tiny::encode_json($struct) };
	unless (defined $json) { close $fh; unlink $temp; return 0 }
	unless (print { $fh } $json) { close $fh; unlink $temp; return 0 }
	unless (close $fh) { unlink $temp; return 0 }
	unless (rename($temp, $path)) { unlink $temp; return 0 }
	return 1;
}

# Returns undef when the state could not be opened, locked, read as a valid
# object, or (if the caller marked it dirty) rewritten. Every caller below
# treats undef as "the count cannot be trusted", never as "carry on
# unmetered" (G3, §7).
sub _with_state {
	my ($self, $kind, $code) = @_;
	unless (-d $self->{dir}) {
		mkdir($self->{dir}, 0700) or return undef;
	}
	my $path = $self->_path($kind);
	my $fh = _lock_state($path);
	return undef unless $fh;
	my ($struct, $readable) = _read_state($fh);
	unless ($readable) {
		close $fh;
		return undef;
	}
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

# Prunes every key's bucket IN PLACE, not just the one being touched, and
# drops any key whose bucket is empty afterwards. Without this, a key that
# is written once and never again (one failed login from an address never
# seen again) sits in the file forever, because nothing but a write to THAT
# SPECIFIC key would ever prune it - and every login attempt reads, decodes,
# re-encodes and renames the WHOLE file under an exclusive lock, so the cost
# of every login rises with the number of distinct addresses or usernames
# that have EVER failed one. An attacker with a large address range can grow
# this file without bound purely by trying, and failing, from a different
# address each time - which is the disk-exhaustion route into the ENOSPC
# failure §7 and the two functions above exist to answer safely rather than
# the route to prevent outright. Called on every write, so the file is
# always bounded by active keys, never by history.
sub _prune_all {
	my ($state, $now, $window) = @_;
	for my $key (keys %$state) {
		my $bucket = $state->{$key};
		next unless ref($bucket) eq 'HASH';
		_prune_and_count($bucket, $now, $window);
		delete $state->{$key} unless %$bucket;
	}
	return;
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
			_prune_all($state, $now, $self->{window});
			my $is_new = !exists $state->{$addr};
			# §7's "cap the number of keys" reading applied here: at
			# capacity, a brand-new key is not admitted rather than
			# evicting one that is actively being tracked - the file's
			# size stays bounded, and the keys already in it (which may
			# include the very address or username an operator is
			# investigating) are never displaced to make room for a new
			# one. Reaching this branch at all needs $max_keys distinct
			# addresses or usernames failing inside one window, which is
			# already an extreme population for this counter to hold.
			return (1, 0) if $is_new && scalar(keys %$state) >= $self->{max_keys};
			my $bucket = $state->{$addr} || {};
			$bucket->{$now}++;
			$state->{$addr} = $bucket;
			return (1, 1);
		});
	}
	if (defined $user && length $user) {
		$self->_with_state('user', sub {
			my ($state) = @_;
			_prune_all($state, $now, $self->{window});
			my $is_new = !exists $state->{$user};
			return (1, 0) if $is_new && scalar(keys %$state) >= $self->{max_keys};
			my $bucket = $state->{$user} || {};
			$bucket->{$now}++;
			$state->{$user} = $bucket;
			return (1, 1);
		});
	}
	return;
}

1;
