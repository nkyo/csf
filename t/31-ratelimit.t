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
# ConfigServer::UI::RateLimit - the web tier's own login rate limiter,
# independent of csf-ui-helper's per-username lockout (docs/WEBUI-RPC.md
# S5.14). Runs without root and without a network: every store used here is
# a temp directory this process owns.
###############################################################################
use strict;
use warnings;

use FindBin ();
use lib "$FindBin::Bin/..", "$FindBin::Bin/../ui-src/lib";

use File::Temp qw(tempdir);
use Fcntl qw(:DEFAULT);
use Test::More tests => 42;

require_ok('ConfigServer::UI::RateLimit');
my $R = 'ConfigServer::UI::RateLimit';

###############################################################################
# Opens and closes: the address bucket
###############################################################################
{
	my $dir = tempdir(CLEANUP => 1);
	my $now = 1000;
	my $rl = $R->new(dir => $dir, window => 900, addr_limit => 5, user_limit => 10,
		now => sub { $now });

	for my $n (1 .. 4) {
		is($rl->blocked_addr('203.0.113.7'), 0, "address not blocked before failure $n is recorded");
		$rl->record_failure('203.0.113.7', undef);
	}
	is($rl->blocked_addr('203.0.113.7'), 0, 'still open after 4 of 5 allowed failures');
	$rl->record_failure('203.0.113.7', undef);
	is($rl->blocked_addr('203.0.113.7'), 1, 'blocked once the 5th failure is recorded');
	is($rl->blocked('203.0.113.7', 'nobody-in-particular'), 1,
		'blocked() reports blocked when only the address dimension is over its cap');

	# A different address is never affected by another address's failures.
	is($rl->blocked_addr('198.51.100.9'), 0, 'a different address is unaffected');
}

###############################################################################
# Opens and closes: the username bucket, independently of address
###############################################################################
{
	my $dir = tempdir(CLEANUP => 1);
	my $now = 1000;
	my $rl = $R->new(dir => $dir, window => 900, addr_limit => 5, user_limit => 10,
		now => sub { $now });

	for my $n (1 .. 9) {
		$rl->record_failure("198.51.100.$n", 'alice'); # nine different addresses
	}
	is($rl->blocked_user('alice'), 0, 'still open after 9 of 10 allowed failures for one username');
	is($rl->blocked_addr('198.51.100.1'), 0,
		'no single address hit its own 5-failure cap from one failure each');

	$rl->record_failure('198.51.100.99', 'alice');
	is($rl->blocked_user('alice'), 1, 'blocked once the 10th failure for this username is recorded');
	is($rl->blocked_user('bob'), 0, 'a different username is unaffected');
	is($rl->blocked('9.9.9.9', 'alice'), 1,
		'blocked() reports blocked when only the username dimension is over its cap');
}

###############################################################################
# The window rolls: failures outside the window no longer count
###############################################################################
{
	my $dir = tempdir(CLEANUP => 1);
	my $now = 1000;
	my $rl = $R->new(dir => $dir, window => 900, addr_limit => 3, user_limit => 100,
		now => sub { $now });

	$rl->record_failure('203.0.113.5', undef) for 1 .. 3;
	is($rl->blocked_addr('203.0.113.5'), 1, 'blocked after 3 failures inside the window');

	$now += 901; # past the 900s window
	is($rl->blocked_addr('203.0.113.5'), 0, 'no longer blocked once every failure has aged out');

	$rl->record_failure('203.0.113.5', undef);
	is($rl->blocked_addr('203.0.113.5'), 0, 'one fresh failure after the window resets is not enough to block');
}

###############################################################################
# Peeking never counts: blocked()/blocked_addr()/blocked_user() must never
# themselves add to either counter, however many times they are called.
###############################################################################
{
	my $dir = tempdir(CLEANUP => 1);
	my $now = 1000;
	my $rl = $R->new(dir => $dir, window => 900, addr_limit => 2, user_limit => 2,
		now => sub { $now });

	$rl->blocked_addr('203.0.113.5') for 1 .. 50;
	$rl->blocked_user('trudy') for 1 .. 50;
	is($rl->blocked_addr('203.0.113.5'), 0, 'fifty peeks at an address never trip its cap');
	is($rl->blocked_user('trudy'), 0, 'fifty peeks at a username never trip its cap');
}

###############################################################################
# A successful login is never charged: only record_failure() increments
# anything, so a caller that never calls it after a success leaves both
# counters untouched.
###############################################################################
{
	my $dir = tempdir(CLEANUP => 1);
	my $now = 1000;
	my $rl = $R->new(dir => $dir, addr_limit => 1, user_limit => 1, now => sub { $now });

	is($rl->blocked('203.0.113.5', 'walter'), 0, 'a brand new address/username pair starts open');
	# Simulate 10 successful logins from the same address/username: nothing
	# in this test ever calls record_failure(), which is the whole point.
	for (1 .. 10) {
		is($rl->blocked('203.0.113.5', 'walter'), 0, 'still open after a run of successful logins');
	}
}

###############################################################################
# Fails closed (G3): when the state file cannot be read or written at all,
# blocked() answers "blocked", never "not blocked". This is the specific
# failure mode csf-ui-helper's own rate limiter was once found to have -
# this module must not repeat it silently, and this test is the guard that a
# reverted fix would fail loudly on.
###############################################################################
{
	my $dir = tempdir(CLEANUP => 1);
	my $rl = $R->new(dir => $dir, now => sub { 1000 });

	# Make the rate-limit directory itself unwritable and unreadable, so
	# _with_state() cannot even open a state file inside it.
	chmod(0000, $dir) or die "cannot chmod $dir: $!";

	SKIP: {
		skip 'running as root: permission bits do not block root', 5 if $> == 0;

		is($rl->blocked_addr('203.0.113.5'), 1,
			'blocked_addr() fails closed (blocked) when its state cannot be opened');
		is($rl->blocked_user('mallory'), 1,
			'blocked_user() fails closed (blocked) when its state cannot be opened');
		is($rl->blocked('203.0.113.5', 'mallory'), 1,
			'blocked() fails closed when the underlying state is unavailable');

		# record_failure() must not die just because it cannot persist -
		# it is best-effort, and the fail-closed guarantee lives entirely
		# in blocked() above, not in this call succeeding.
		eval { $rl->record_failure('203.0.113.5', 'mallory') };
		is($@, '', 'record_failure() does not die when the state cannot be written');

		chmod(0700, $dir) or die "cannot chmod $dir: $!";
		is($rl->blocked_addr('203.0.113.5'), 0,
			'access restored: the limiter goes back to reporting the true, uncorrupted count');
	}
	chmod(0700, $dir);
}

###############################################################################
# Directory-independent buckets: the file used for the address dimension is
# never the same file as the username dimension, so a caller cannot collide
# an address string with a username string that happens to look the same.
###############################################################################
{
	my $dir = tempdir(CLEANUP => 1);
	my $now = 1000;
	my $rl = $R->new(dir => $dir, addr_limit => 1, user_limit => 100, now => sub { $now });

	$rl->record_failure('trudy', undef); # 'trudy' used AS AN ADDRESS here
	is($rl->blocked_addr('trudy'), 1, 'the address bucket is charged for the address argument');
	is($rl->blocked_user('trudy'), 0,
		'the same literal string used as a username is a completely separate counter');
}

###############################################################################
# Defaults match the brief: 5 failed logins per 15 minutes per address, 10
# per 15 minutes per username.
###############################################################################
{
	no warnings 'once'; # each of these package variables is otherwise touched exactly once in this file
	is($ConfigServer::UI::RateLimit::DEFAULT_ADDR_LIMIT, 5, 'default address limit is 5');
	is($ConfigServer::UI::RateLimit::DEFAULT_USER_LIMIT, 10, 'default username limit is 10');
	is($ConfigServer::UI::RateLimit::DEFAULT_WINDOW, 900, 'default window is 900 seconds (15 minutes)');
}

###############################################################################
# Never writes to csf.deny, or to anything outside its own directory: the
# module has no dependency on Client.pm at all, so there is no code path
# here that could reach the firewall.
###############################################################################
{
	open(my $fh, '<', "$FindBin::Bin/../ui-src/lib/ConfigServer/UI/RateLimit.pm")
		or die "cannot read RateLimit.pm: $!";
	local $/;
	my $source = <$fh>;
	close $fh;
	unlike($source, qr/use\s+ConfigServer::UI::Client/, 'RateLimit.pm never loads the RPC client');
	unlike($source, qr/->call\(/, 'RateLimit.pm never calls an RPC operation');
}
