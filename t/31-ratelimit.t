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
use JSON::Tiny ();
use POSIX ();
use Test::More tests => 54;

require_ok('ConfigServer::UI::RateLimit');
my $R = 'ConfigServer::UI::RateLimit';

sub _decode_state_file {
	my ($path) = @_;
	open(my $fh, '<', $path) or return undef;
	local $/;
	my $raw = <$fh>;
	close $fh;
	return eval { JSON::Tiny::decode_json($raw) };
}

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
# R26: a corrupt or unparseable state file fails closed, and does not read
# as "zero failures recorded". This is the read-side half of the chain the
# review found - a state file that cannot be MADE SENSE of is exactly as
# unusable as one that cannot be opened, and treating it as {} is what let
# a write gone wrong elsewhere look identical to "nothing has ever failed
# here", which is a silent, unauthenticated bypass: fill the disk, then
# guess freely.
###############################################################################
{
	my $dir = tempdir(CLEANUP => 1);
	my $rl = $R->new(dir => $dir, addr_limit => 5, now => sub { 1000 });

	# A real prior failure first, so a "corrupt -> {}" regression is visible
	# as history actually being lost, not merely as an empty file behaving
	# like an empty file.
	$rl->record_failure('203.0.113.9', undef) for 1 .. 3;

	open(my $fh, '>', "$dir/addr.state") or die "cannot write $dir/addr.state: $!";
	print { $fh } "{ this is not valid json, on purpose }}}";
	close $fh;

	is($rl->blocked_addr('203.0.113.9'), 1,
		'a corrupt state file is treated as unavailable, not as zero recorded failures');
	is($rl->blocked_addr('an-address-never-seen-before'), 1,
		'a corrupt state file blocks every address, not only the one with real history');
}

{
	my $dir = tempdir(CLEANUP => 1);
	my $rl = $R->new(dir => $dir, now => sub { 1000 });

	# Valid JSON that is not an object (an array, here) is exactly as
	# unusable as unparseable JSON, and must be refused the same way -
	# ref($struct) eq 'HASH' is the actual gate, not "did decode_json die".
	open(my $fh, '>', "$dir/user.state") or die "cannot write $dir/user.state: $!";
	print { $fh } '["not", "an", "object"]';
	close $fh;

	is($rl->blocked_user('trudy'), 1, 'valid JSON that decodes to a non-object also fails closed');
}

###############################################################################
# R26: a real short write - not a property assertion. Mirrors the technique
# csf-ui-helper's own t/11-helper-validate.t uses for the identical claim
# about its audit log: stage the write's target as a FIFO with a shrunk
# pipe buffer and a reader that attaches, signals ready, and then goes away
# before draining it, so the write cannot complete and must fail rather
# than silently succeed with a truncated temp file that then gets renamed
# over good state.
#
# _write_state() writes to "$path.tmp.$$" before renaming it into place;
# since RateLimit's methods run in-process rather than forking, $$ is this
# test's own pid, so that exact path can be pre-staged.
###############################################################################
SKIP: {
	# 4, not 3: this block emits FOUR assertions when it runs - the two ok()s
	# below, plus the two is()s in the nested SKIP at the end of it.
	# Declaring 3 made the file emit 53 against its own 'tests => 54' plan
	# on any host without mkfifo or F_SETPIPE_SZ. Measured by forcing the
	# probe false: exit 255, "planned 54 tests but ran 53". The fixed plan
	# turned a silent miscount into a hard failure, which is the right
	# direction - but it made t/31 fail for a portability reason rather
	# than a real one. Every skip in this block counts the same four.
	skip 'needs mkfifo and F_SETPIPE_SZ, which is Linux-specific', 4
		unless eval { POSIX::mkfifo("$FindBin::Bin/../.mkfifo-probe-$$", 0600) };
	unlink "$FindBin::Bin/../.mkfifo-probe-$$";

	my $dir = tempdir(CLEANUP => 1);
	my $rl = $R->new(dir => $dir, addr_limit => 5, now => sub { 1000 });

	# Real prior state, to prove afterwards that it survived untouched.
	$rl->record_failure('203.0.113.77', undef);

	# Bulk the state past a shrunk 4 KiB pipe buffer using only the public
	# interface, so the write under test is actually large enough to be
	# forced short rather than fitting in one kernel-buffered chunk.
	$rl->record_failure("198.51.100.$_", undef) for 1 .. 300;

	my $temp_path = "$dir/addr.state.tmp.$$";
	unlink $temp_path;
	POSIX::mkfifo($temp_path, 0600) or skip 'could not create the fifo', 4;

	pipe(my $ready_read, my $ready_write) or skip 'could not create the sync pipe', 4;
	my $pid = fork();
	skip 'could not fork the reader', 4 unless defined $pid;
	unless ($pid) {
		close $ready_read;
		# O_NONBLOCK so the reader attaches without waiting for the writer,
		# and the buffer is shrunk while it is still empty - F_SETPIPE_SZ
		# refuses to shrink below what is already buffered.
		sysopen(my $reader, $temp_path, Fcntl::O_RDONLY() | Fcntl::O_NONBLOCK())
			or POSIX::_exit(1);
		my $sized = fcntl($reader, 1031, 4096) ? 'y' : 'n'; # F_SETPIPE_SZ
		syswrite($ready_write, "$sized\n");
		close $ready_write;
		# Never reads a byte - the point is a reader that goes away with
		# the buffer still full, not one that drains it.
		select(undef, undef, undef, 0.3);
		close $reader;
		POSIX::_exit(0);
	}
	close $ready_write;
	my $sized = <$ready_read>;
	close $ready_read;
	chomp($sized = defined $sized ? $sized : 'n');

	my $completed = eval {
		local $SIG{PIPE} = 'IGNORE';
		local $SIG{ALRM} = sub { die "the write did not return\n" };
		alarm(15);
		$rl->record_failure('203.0.113.99', undef); # this write is forced short
		alarm(0);
		1;
	};
	waitpid($pid, 0);
	unlink $temp_path;

	skip 'this kernel would not shrink the pipe buffer, so no short write can be staged', 4
		unless $sized eq 'y';

	ok($completed, 'a write that cannot complete returns rather than blocking forever');

	# Checked as its own assertion, and gated on before reading any further:
	# a fix that lets the FIFO itself get renamed over the real path (which
	# is exactly what an unchecked rename() does with a source that never
	# received real content) turns addr.state into a special file, and
	# opening that for a read blocks forever waiting for a writer that will
	# never come - a hang, not a failure, and a hang is worse than either.
	# This is the concrete, non-hanging signal that catches that case.
	my $intact = -f "$dir/addr.state";
	ok($intact, 'the state path is still a regular file - a failed write must never replace it with something else');

	SKIP: {
		skip 'the state path was not left as a regular file; reading it further is not safe', 2
			unless $intact;

		is($rl->blocked_addr('203.0.113.77'), 0,
			'the pre-existing state survived the failed write untouched, not corrupted and not reset');
		is($rl->blocked_addr('203.0.113.99'), 0,
			'the attempt that failed to persist is not counted either - it is simply as if it never happened, not as a false positive');
	}
}

###############################################################################
# R26: unbounded growth. A write must prune every key it is holding, not
# only the one being incremented - otherwise a key that fails once and is
# never touched again sits in the file forever, and every subsequent login
# pays the cost of reading, decoding, re-encoding and renaming a file that
# only ever grows. This is the remote-triggerable route to the ENOSPC the
# two tests above exist to answer safely.
###############################################################################
{
	my $now = 1000;
	my $dir = tempdir(CLEANUP => 1);
	my $rl = $R->new(dir => $dir, window => 100, now => sub { $now });

	$rl->record_failure("198.51.100.$_", undef) for 1 .. 20; # 20 one-off addresses

	$now += 200; # past the 100s window: all 20 above are now expired
	$rl->record_failure('203.0.113.1', undef); # any write should prune the whole table

	my $struct = _decode_state_file("$dir/addr.state");
	is(scalar(keys %$struct), 1,
		'a write prunes every stale key, not only the one being incremented - 20 expired addresses are gone, one fresh one remains');
}

###############################################################################
# R26: the key cap. §7's "a limit that cannot be counted is not a limit"
# applied to the file's own size: bounding it is what keeps the counter
# maintainable in the first place, rather than relying only on catching the
# failure once maintaining it has already become impossible.
###############################################################################
{
	my $now = 1000;
	my $dir = tempdir(CLEANUP => 1);
	my $rl = $R->new(dir => $dir, window => 900, addr_limit => 5, max_keys => 5, now => sub { $now });

	$rl->record_failure("198.51.100.$_", undef) for 1 .. 5; # fills the cap exactly
	is(scalar(keys %{ _decode_state_file("$dir/addr.state") }), 5,
		'the file holds exactly max_keys entries after filling it');

	$rl->record_failure('203.0.113.200', undef); # a 6th, brand-new address

	my $struct = _decode_state_file("$dir/addr.state");
	is(scalar(keys %$struct), 5, 'a new key beyond the cap is not admitted - the file does not grow past max_keys');
	ok(!exists $struct->{'203.0.113.200'}, 'and specifically, the address that arrived at capacity was not the one let in');

	# A key already inside the cap keeps counting normally even while the
	# table is completely full - the cap protects growth, not the keys
	# already being watched.
	$rl->record_failure('198.51.100.1', undef) for 1 .. 4; # 1 earlier + 4 now = 5
	is($rl->blocked_addr('198.51.100.1'), 1,
		'an existing key still reaches its own cap normally while the table is at max_keys');
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
