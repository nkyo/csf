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
# Added 2026-09-13 in https://github.com/nkyo/csf - see CHANGES.md.
#
# ConfigServer::UI::Server->run()'S ACCEPT LOOP, DRIVEN FOR REAL.
#
# Everything in this file needs the one thing t/40 and t/41 deliberately do
# without: a real listening socket, a real accept(), and real forked
# children. Server.pm's own header comment said for four rounds that the
# loop was "untested by design", and mode A is what made that untrue - in
# mode A there is no TLS in this process, so preflight() no longer refuses
# in a workspace without IO::Socket::SSL, and run() can reach its loop
# here. t/40 already drives run()'s mode-A STARTUP REFUSAL; this file
# drives what happens after it, which is where the review of round 1 found
# three load-bearing guards with no test at all between them:
#
#   * the child cap (a connection accepted while every slot is in use is
#     dropped, not forked for);
#   * the fork() failure branch (without it the PARENT falls through into
#     the child path and the daemon dies after one request);
#   * run()'s exit-time unlink of the socket it bound.
#
# and the two silent drops fix round 1's F2 gave a log line.
#
# HOW THE LOOP IS MADE TO RETURN. run() blocks in accept() forever by
# design. Every case here therefore runs it in a forked child of this test
# process, talks to it over its real socket, and then SIGTERMs it - which
# is not a workaround but the production shutdown path: run()'s own TERM
# handler clears $running, the blocked accept() returns EINTR,
# _accept_backoff() treats EINTR as "nothing is wrong" and returns at once,
# and the while loop's condition ends the loop. A daemon that does NOT exit
# on TERM within the deadline fails the test rather than hanging the file.
#
# WHY THE fork() STUB IS HERE AND NOT IN Server.pm. The fork()-failure
# branch needs fork() to fail, and there is no production reason for
# Server.pm to carry a seam for that - a seam that lets a caller make
# fork() fail is itself a liability in a daemon. So the stub is installed
# in this driver, in a BEGIN block that runs before Server.pm is compiled
# (a CORE::GLOBAL override only affects code compiled after it), and it
# calls the real CORE::fork() unless this file has explicitly asked for a
# failure. Server.pm is byte-for-byte what production runs.
###############################################################################
use strict;
use warnings;

BEGIN {
	# $main::FORK_FAILS is set only inside a daemon child, immediately
	# before run() is called, and only by the one case that needs it.
	*CORE::GLOBAL::fork = sub {
		return CORE::fork() unless $main::FORK_FAILS;
		$! = 11; # EAGAIN, which is what a real fork() failure under RLIMIT_NPROC sets
		return undef;
	};
}

use FindBin ();
use lib "$FindBin::Bin/..", "$FindBin::Bin/../ui-src/lib";

use File::Temp qw(tempdir);
use POSIX ();
use Socket ();
use Time::HiRes ();
use Test::More tests => 30;

require_ok('ConfigServer::UI::Server');
my $S = 'ConfigServer::UI::Server';

our $FORK_FAILS = 0;

{
	package LoopApp;
	sub new { my ($class, %opt) = @_; return bless { slow => $opt{slow} }, $class }
	sub dispatch {
		my ($self, $request) = @_;
		# `slow` exists for the reaping case below, which needs the forked
		# child to still be alive when the parent reaches the top of its
		# next loop iteration - otherwise the bug under test is a race
		# rather than a certainty.
		select(undef, undef, undef, $self->{slow}) if $self->{slow};
		return {
			status  => 200,
			headers => [['Content-Type', 'text/plain']],
			body    => "served $request->{path}",
		};
	}
}

###############################################################################
# A daemon, on a real unix socket in a temp directory this test owns.
#
# peer_uids is injected for the same reason t/40's run() case injects it:
# derived from the host's real group database the accepted set would depend
# on which accounts happen to share this test user's primary group, so the
# startup refusal ("no account other than this one can reach the socket")
# would fire on some hosts and not others. A second, fictitious uid is
# enough to get past it; admit_peer() still checks the real peer, which is
# this test process and therefore this process's own uid - way 1.
###############################################################################
my $dir = tempdir(CLEANUP => 1);

sub _start_daemon {
	my (%opt) = @_;
	my $n = $opt{n};
	my $path = "$dir/d$n.sock";
	my $log  = "$dir/d$n.err";
	my $conf = "$dir/d$n.conf";
	open(my $cf, '>', $conf) or die "cannot write $conf: $!";
	print $cf qq(UI_MODE="a"\nUI_ALLOW="10.0.0.0/8"\n);
	close $cf;

	my $pid = CORE::fork();
	die "fork: $!" unless defined $pid;
	if ($pid) {
		# Wait for the socket to appear rather than sleeping a guess.
		for (1 .. 200) {
			last if -S $path;
			Time::HiRes::sleep(0.01);
		}
		return { pid => $pid, path => $path, log => $log };
	}

	open(STDOUT, '>', '/dev/null') or POSIX::_exit(70);
	open(STDERR, '>', $log)        or POSIX::_exit(70);
	$main::FORK_FAILS = 1 if $opt{fork_fails};
	my $server = $S->new(
		app               => LoopApp->new(slow => $opt{slow}),
		ui_conf_path      => $conf,
		socket_path       => $path,
		peer_uids         => { $> + 0 => 1, 4294967294 => 1 },
		max_children      => defined $opt{max_children} ? $opt{max_children} : 4,
		drop_log_interval => defined $opt{drop_log_interval} ? $opt{drop_log_interval} : 60,
		header_timeout    => 2,
		body_timeout      => 2,
		write_timeout     => 2,
		dispatch_timeout  => 2,
	);
	my $rc = eval { $server->run() };
	POSIX::_exit(defined $rc ? $rc : 71);
}

###############################################################################
# EVERY WAIT ON THE DAEMON IS BOUNDED (fix round 2, R107's sweep).
#
# Three calls in this file can block indefinitely against a daemon that is
# present but wedged, and a hung test file produces ZERO "not ok" lines -
# indistinguishable from a dead run, which is precisely the failure R107
# was raised for over in t/40. They are:
#
#   * connect() to a live socket whose backlog is full;
#   * sysread() on a connection the daemon accepted and then neither wrote
#     to nor closed - and the wall-clock `while` in _request() below
#     cannot interrupt its OWN sysread(), so that deadline bounds the loop
#     and not the syscall inside it;
#   * the blocking waitpid() after SIGKILL in _stop_daemon().
#
# On the deadline each helper returns exactly what it already returns for
# the failure it is bounding, so the CALLER's own named assertion reddens
# instead of the file stopping. $BLOCKED records that a deadline was hit at
# all, and is asserted once at the end of this file - because "the request
# got nothing back" is a true statement about a wedged daemon too, and the
# two are different defects.
###############################################################################
our $BLOCKED = 0;

sub _bounded {
	my ($seconds, $code) = @_;
	local $SIG{ALRM} = sub { die "ALARM\n" };
	alarm($seconds);
	my @out = eval { $code->() };
	my $error = $@;
	alarm(0);
	if ($error ne '') {
		$BLOCKED++ if $error eq "ALARM\n";
		return ();
	}
	return @out;
}

sub _connect {
	my ($path) = @_;
	socket(my $socket, Socket::PF_UNIX(), Socket::SOCK_STREAM(), 0) or die "socket: $!";
	my ($connected) = _bounded(10,
		sub { return connect($socket, Socket::pack_sockaddr_un($path)) ? 1 : 0 });
	return undef unless $connected;
	return $socket;
}

# One request, one response, one connection - which is all this tier ever
# does. Returns the response text, '' when the daemon dropped us without
# writing anything, and undef when connect() itself failed.
sub _request {
	my ($path, $target) = @_;
	$target = '/ui/overview' unless defined $target;
	my $socket = _connect($path);
	return undef unless $socket;
	syswrite($socket, "GET $target HTTP/1.1\r\nHost: x\r\nX-Real-IP: 10.0.0.7\r\n\r\n");
	my $out = '';
	my $deadline = Time::HiRes::time() + 5;
	_bounded(10, sub {
		while (Time::HiRes::time() < $deadline) {
			my $chunk;
			my $read = sysread($socket, $chunk, 8192);
			last unless defined $read && $read > 0;
			$out .= $chunk;
			last if $out =~ /\r\n\r\n/;
		}
		return 1;
	});
	close $socket;
	return $out;
}

sub _stop_daemon {
	my ($daemon) = @_;
	kill 'TERM', $daemon->{pid};
	# Generous: a loaded host running the whole suite in parallel can take
	# a moment to schedule the daemon's TERM handler, and a flaky "it did
	# not exit" would be read as a real regression.
	my $deadline = Time::HiRes::time() + 20;
	while (Time::HiRes::time() < $deadline) {
		my $done = waitpid($daemon->{pid}, POSIX::WNOHANG());
		return $? if $done == $daemon->{pid};
		Time::HiRes::sleep(0.02);
	}
	kill 'KILL', $daemon->{pid};
	_bounded(10, sub { waitpid($daemon->{pid}, 0); return 1 });
	return undef; # "it did not exit on TERM" - the caller asserts on this
}

sub _alive {
	my ($daemon) = @_;
	return 0 if waitpid($daemon->{pid}, POSIX::WNOHANG()) == $daemon->{pid};
	return kill(0, $daemon->{pid}) ? 1 : 0;
}

sub _log {
	my ($daemon) = @_;
	open(my $fh, '<', $daemon->{log}) or return '';
	local $/;
	my $text = <$fh>;
	close $fh;
	return defined $text ? $text : '';
}

###############################################################################
# THE LOOP, END TO END. One real connection over a real bound socket,
# accepted by a real accept(), served by a real forked child, answered on
# the wire - and then the socket removed again by run()'s own exit path.
#
# The last assertion is the guard at run()'s tail (`unlink($unix_path) if
# defined $unix_path`), which had no test: a socket file outliving the
# process that answered it is a thing an administrator has to reason about,
# and _unlink_stale_socket() only clears it on the NEXT start.
###############################################################################
{
	my $daemon = _start_daemon(n => 1);
	ok(-S $daemon->{path}, 'run() binds a real unix socket and listens on it');

	my $out = _request($daemon->{path});
	like($out, qr{\AHTTP/1\.1 200 }, "run()'s accept loop serves a real connection, forked child and all");
	like($out, qr{served /ui/overview}, 'and the request reached dispatch() with its path intact');

	my $second = _request($daemon->{path});
	like($second, qr{\AHTTP/1\.1 200 },
		'and the parent survives its child to serve a second connection - one request per connection, many connections per daemon');

	my $status = _stop_daemon($daemon);
	isnt($status, undef, 'run() returns when SIGTERM clears $running, rather than having to be killed');
	ok(!-S $daemon->{path},
		"and removes the socket it bound: run()'s exit-time unlink, which nothing tested before");
	is(_log($daemon), '', 'a daemon that was never overloaded logs nothing at all');
}

###############################################################################
# THE CHILD CAP, and fix round 1's F2 log line on the drop it causes.
#
# max_children is 1, so one connection that never sends anything holds the
# only slot for HTTP.pm's absolute header deadline - which is CORRECT and
# is not what this asserts. What this asserts is the cap itself (the next
# connection is dropped, not forked for) and that the drop is no longer
# silent: before F2, three consecutive legitimate requests were each
# dropped in about 15ms with an empty response and ZERO bytes on the
# daemon's stderr, sustainable indefinitely by reconnecting, and the
# operator had no way to tell a busy UI from a broken one.
#
# The holder is closed and the cap proven to LIFT afterwards, because "the
# request got nothing back" would also be true of a daemon that had simply
# died.
###############################################################################
{
	my $daemon = _start_daemon(n => 2, max_children => 1, drop_log_interval => 60);
	ok(-S $daemon->{path}, 'a daemon with a cap of one slot starts');

	my $holder = _connect($daemon->{path}); # sends nothing, holds the slot
	ok($holder, 'a connection that sends nothing is still accepted (the cap is on children, not on accept)');
	Time::HiRes::sleep(0.3);

	my $out = _request($daemon->{path});
	is($out, '', 'the child cap drops a connection accepted while every slot is in use - it is not forked for');

	my $log = _log($daemon);
	like($log, qr/connection slots are in use/,
		'F2: and the drop is logged, so an operator can tell a busy UI from a broken one');
	like($log, qr/\ball 1 connection slots\b/, 'F2: the line names how many slots there are');
	like($log, qr/502/, 'F2: and what the front web server will be showing while this happens');
	like($log, qr/at most one line per 60s/, 'F2: and says the line is rate-limited, so its absence is not proof of health');

	close $holder;
	# The slot is freed when the HOLDER's child exits. The holder was
	# admitted and forked for like any other connection - the cap check
	# precedes fork(), so the first connection can never be the one it
	# refuses, and the holder occupying the only slot is exactly why the
	# cap fired on the request above. (This comment used to say "as here,
	# where no child was ever forked for it", which described the dropped
	# request, not the holder - fix round 2. The assertion below always
	# passed for the right reason; only the comment was wrong.) Either
	# way the cap must LIFT.
	my $recovered = '';
	my $deadline = Time::HiRes::time() + 8;
	while (Time::HiRes::time() < $deadline) {
		$recovered = _request($daemon->{path});
		last if defined $recovered && $recovered =~ /^HTTP/;
		Time::HiRes::sleep(0.1);
	}
	like($recovered, qr{\AHTTP/1\.1 200 },
		'and the cap lifts once the slot is free - the drop was the cap, not a dead daemon');

	isnt(_stop_daemon($daemon), undef, 'the capped daemon still exits on TERM');
}

###############################################################################
# THE fork() FAILURE BRANCH - the worst of the untested guards.
#
# Without `unless (defined $pid) { ... next }` the parent reads undef from
# fork(), `if ($pid)` is false, and THE PARENT RUNS THE CHILD PATH: it
# closes its own listener, serves this one request, and POSIX::_exit(0)s.
# Measured with the guard removed: the daemon is dead after request 1, a
# stale socket is left behind, and the next connect() is ECONNREFUSED. One
# EAGAIN under RLIMIT_NPROC terminates the firewall's admin interface.
#
# Three independent assertions, because each of them alone could be true
# for another reason: the request gets NOTHING (a fell-through parent would
# answer it with a 200), the daemon is STILL ALIVE afterwards, and a second
# connection still reaches a listening socket.
###############################################################################
{
	my $daemon = _start_daemon(n => 3, fork_fails => 1);
	ok(-S $daemon->{path}, 'a daemon whose fork() always fails still starts and listens');

	my $out = _request($daemon->{path});
	is($out, '',
		'a connection that cannot be forked for is dropped - the parent does NOT fall through and serve it itself');
	ok(_alive($daemon),
		'and the parent is still running afterwards: one fork() failure must not terminate the admin UI');

	my $log = _log($daemon);
	like($log, qr/fork\(\) failed/, 'F2: the fork() failure is logged rather than being the second silent drop');
	like($log, qr/RLIMIT_NPROC/, 'F2: and the line names what an operator should go and look at');

	my $still_listening = _connect($daemon->{path});
	ok(defined $still_listening,
		'the listener is still open, not closed by a parent that took the child path');
	close $still_listening if $still_listening;
	Time::HiRes::sleep(0.2); # let the loop finish dropping that one before TERM

	isnt(_stop_daemon($daemon), undef, 'and this daemon exits on TERM too');
	ok(!-S $daemon->{path}, 'leaving no stale socket behind');
}

###############################################################################
# THE REAPING ORDER - a PRE-EXISTING off-by-one, found by the round-1
# review and fixed here because it is the same denial F2 is about, reached
# without anyone attacking anything.
#
# The reap ran once per iteration, at the TOP, which is BEFORE accept() -
# and accept() is where the parent spends essentially all of its time. So
# every child that exited while the parent was blocked there left %child
# stale until the parent had already accepted, and been forced to judge,
# one more connection. At the cap that connection was dropped as "busy"
# against a slot that was in fact free: one legitimate request silently
# dropped per burst.
#
# Staged so it is a certainty rather than a race: the cap is one, dispatch()
# takes 0.4s so the child is unmistakably still alive when the parent
# reaches the top of its next iteration, and the second request is sent
# well after that child has both answered and exited. With the extra reap
# the second request is served; without it, it is dropped.
###############################################################################
{
	my $daemon = _start_daemon(n => 4, max_children => 1, slow => 0.4);
	ok(-S $daemon->{path}, 'a one-slot daemon with a deliberately slow route starts');

	my $first = _request($daemon->{path});
	like($first, qr{\AHTTP/1\.1 200 }, 'the first request is served by the only slot there is');

	# The child has written its response (we just read it) and exits right
	# after; the parent is blocked in accept() and cannot notice until it
	# has accepted something.
	Time::HiRes::sleep(0.4);

	my $second = _request($daemon->{path});
	like($second, qr{\AHTTP/1\.1 200 },
		'and so is the next one: the cap is judged against children that have been reaped, not against a table that went stale while the parent sat in accept()');
	unlike(_log($daemon), qr/connection slots are in use/,
		'and nothing was dropped as busy, because nothing actually was busy');

	_stop_daemon($daemon);
}

###############################################################################
# R107's own assertion for this file: not one of the waits above hit its
# deadline. Every assertion in this file reads a daemon's answer, and "the
# daemon answered nothing" and "the daemon never answered" are different
# defects that look identical from a response string. Without this line a
# wedged daemon would make the assertions above fail for a reason none of
# them names - or, before the bounds were added, make them not run at all.
###############################################################################
is($BLOCKED, 0,
	'R107: no wait on a daemon in this file hit its deadline - every connect(), read and reap returned on its own');
