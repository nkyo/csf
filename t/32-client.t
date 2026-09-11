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
# ConfigServer::UI::Client against a real Unix-domain socket, not a mock:
# read_message()/encode() in Proto.pm use sysread/syswrite on a real
# descriptor, so a fake helper forked in-process is what actually exercises
# the same code path production traffic takes. Runs without root: every
# socket here lives under a temp directory this process owns.
###############################################################################
use strict;
use warnings;

use FindBin ();
use lib "$FindBin::Bin/..", "$FindBin::Bin/../ui-src/lib";

use File::Temp qw(tempdir);
use IO::Socket::UNIX ();
use Socket qw(SOCK_STREAM);
use POSIX ();
use Test::More tests => 26;

require_ok('ConfigServer::UI::Client');
my $C = 'ConfigServer::UI::Client';

# Reap forked fake-helper children automatically; nothing in this file ever
# needs their exit status, only their behaviour on the socket.
$SIG{CHLD} = 'IGNORE';

my $dir = tempdir(CLEANUP => 1);
my $n = 0;
sub _sock_path { return "$dir/helper-" . (++$n) . '.sock' }

# Forks a one-shot fake helper: binds $path, accepts exactly one connection,
# hands it to $handler, then exits. Returns once the socket is bound and
# ready to accept, so the parent never races the child's listen().
sub _fake_helper {
	my ($path, $handler) = @_;
	my $listener = IO::Socket::UNIX->new(Type => SOCK_STREAM, Local => $path, Listen => 5)
		or die "cannot create fake helper listener: $!";
	my $pid = fork();
	die "fork failed: $!" unless defined $pid;
	if ($pid == 0) {
		my $conn = $listener->accept();
		$handler->($conn) if $conn && $handler;
		close $conn if $conn;
		close $listener;
		POSIX::_exit(0);
	}
	close $listener;
	return $pid;
}

# A response's 'ok' (and any nested JSON boolean, such as data->{enabled}
# below) decodes as a blessed scalar ref when it really came over the wire
# through Proto::decode - and a ref is always truthy regardless of what it
# points to, so plain `ok($response->{ok})` would pass no matter which way
# the helper answered. A LOCALLY synthesised failure from Client.pm's own
# _local_error(), on the other hand, uses a plain 0 - the same asymmetry
# ConfigServer::UI::App has to account for with its own _is_ok(), reproduced
# here so this test checks the value, not the ref.
sub _ok_flag {
	my ($value) = @_;
	return 0 unless defined $value;
	return ref($value) ? (${$value} ? 1 : 0) : ($value ? 1 : 0);
}

sub _read_one_line {
	my ($conn) = @_;
	my $line = '';
	while ($line !~ /\n/) {
		my $chunk;
		my $read = sysread($conn, $chunk, 4096);
		last unless $read;
		$line .= $chunk;
	}
	return $line;
}

###############################################################################
# generate_id()
###############################################################################
{
	my $client = $C->new(socket_path => _sock_path());
	my $id = $client->generate_id;
	like($id, qr/\A[0-9a-f]{32}\z/, 'generate_id() returns 32 lowercase hex characters');
	my $id2 = $client->generate_id;
	isnt($id, $id2, 'two generated ids are not the same value');
}

###############################################################################
# A successful round trip over a real socket
###############################################################################
{
	my $path = _sock_path();
	# The fake helper runs in a FORKED CHILD, which inherits a copy of this
	# process's Test::Builder state at the moment of fork() and would
	# corrupt the TAP stream if it called any Test::More assertion of its
	# own - two processes each numbering "ok 4" independently, interleaved
	# on the same inherited stdout. So the child only ever records what it
	# saw to a plain file; every assertion about it runs here, in the
	# parent, after call() has returned - which is only possible once the
	# child has already written this file, since the child writes it before
	# writing the response call() is waiting to read.
	my $received_path = "$dir/received-1.txt";
	_fake_helper($path, sub {
		my ($conn) = @_;
		my $line = _read_one_line($conn);
		open(my $fh, '>', $received_path) or die "cannot write $received_path: $!";
		print { $fh } $line;
		close $fh;
		print { $conn } qq({"id":"fixed-id-1","ok":true,"data":{"enabled":true}}\n);
	});

	my $client = $C->new(socket_path => $path, timeout => 5);
	my $response = $client->call('status', {}, id => 'fixed-id-1');

	open(my $fh, '<', $received_path) or die "cannot read $received_path: $!";
	local $/;
	my $received = <$fh>;
	close $fh;
	like($received, qr/"op":"status"/, 'the fake helper received the operation this test sent');
	like($received, qr/"id":"fixed-id-1"/, 'the fake helper received the id this test supplied');

	ok(_ok_flag($response->{ok}), 'call() reports success for a well-formed response');
	is($response->{id}, 'fixed-id-1', 'call() returns the id the caller supplied');
	ok(_ok_flag($response->{data}{enabled}), 'call() returns the data the helper sent, JSON booleans included');
}

###############################################################################
# A real wire-level error response is relayed unchanged
###############################################################################
{
	my $path = _sock_path();
	_fake_helper($path, sub {
		my ($conn) = @_;
		_read_one_line($conn);
		print { $conn } qq({"id":"fixed-id-2","ok":false,"error":"E_ARG","message":"ip: is required"}\n);
	});

	my $client = $C->new(socket_path => $path, timeout => 5);
	my $response = $client->call('deny', { ip => '' }, id => 'fixed-id-2');
	ok(!_ok_flag($response->{ok}), 'call() reports failure for a wire-level error response');
	is($response->{error}, 'E_ARG', 'the wire error code is passed through unchanged');
	is($response->{message}, 'ip: is required', 'the wire message is passed through unchanged');
}

###############################################################################
# Cannot reach the socket at all - no listener, nothing forked
###############################################################################
{
	my $client = $C->new(socket_path => "$dir/does-not-exist.sock", timeout => 5);
	my $response = $client->call('status', {});
	ok(!_ok_flag($response->{ok}), 'call() reports failure when the socket does not exist');
	is($response->{error}, 'E_UNAVAILABLE', 'an unreachable helper is E_UNAVAILABLE, a structural failure');
}

###############################################################################
# The helper closes without responding at all
###############################################################################
{
	my $path = _sock_path();
	_fake_helper($path, sub {
		my ($conn) = @_;
		_read_one_line($conn);
		# handler returns without writing anything; the caller closes $conn
	});

	my $client = $C->new(socket_path => $path, timeout => 5);
	my $response = $client->call('status', {});
	ok(!_ok_flag($response->{ok}), 'call() reports failure when the connection closes with no response');
	is($response->{error}, 'E_BACKEND', 'a silent close is E_BACKEND');
}

###############################################################################
# The helper sends something that is not a valid response line
###############################################################################
{
	my $path = _sock_path();
	_fake_helper($path, sub {
		my ($conn) = @_;
		_read_one_line($conn);
		print { $conn } "this is not json\n";
	});

	my $client = $C->new(socket_path => $path, timeout => 5);
	my $response = $client->call('status', {});
	ok(!_ok_flag($response->{ok}), 'call() reports failure for an unparseable response line');
	is($response->{error}, 'E_BACKEND', 'a malformed response line is E_BACKEND');
}

###############################################################################
# The helper answers with the wrong request id
###############################################################################
{
	my $path = _sock_path();
	_fake_helper($path, sub {
		my ($conn) = @_;
		_read_one_line($conn);
		print { $conn } qq({"id":"some-other-id","ok":true,"data":{}}\n);
	});

	my $client = $C->new(socket_path => $path, timeout => 5);
	my $response = $client->call('status', {}, id => 'fixed-id-3');
	ok(!_ok_flag($response->{ok}), 'call() reports failure when the response id does not match the request');
	is($response->{error}, 'E_BACKEND', 'a mismatched response id is E_BACKEND');
}

###############################################################################
# The client-side timeout, and proof that a timed-out call is never retried
###############################################################################
{
	my $path = _sock_path();
	my $counter = "$dir/accept-count";

	my $listener = IO::Socket::UNIX->new(Type => SOCK_STREAM, Local => $path, Listen => 5)
		or die "cannot create fake helper listener: $!";
	my $pid = fork();
	die "fork failed: $!" unless defined $pid;
	if ($pid == 0) {
		# Accepts up to 3 times, each time recording the accept and then
		# holding the connection open well past the client's short timeout
		# without ever writing a response - simulating a wedged helper.
		for (1 .. 3) {
			my $conn = $listener->accept() or last;
			open(my $fh, '>>', $counter);
			print { $fh } 'x';
			close $fh;
			sleep(1);
			close $conn;
		}
		close $listener;
		POSIX::_exit(0);
	}
	close $listener;

	my $client = $C->new(socket_path => $path, timeout => 0.2);
	my $started = time();
	my $response = $client->call('status', {});
	my $elapsed = time() - $started;

	ok(!_ok_flag($response->{ok}), 'call() reports failure when the helper never responds in time');
	is($response->{error}, 'E_BACKEND', 'a client-side timeout is E_BACKEND');
	ok($elapsed < 2, 'call() returns close to its own timeout, not after the full sleep');

	open(my $fh, '<', $counter) or die "cannot read $counter: $!";
	local $/;
	my $accepts = <$fh>;
	close $fh;
	is(length($accepts), 1, 'exactly one connection was ever attempted - call() never retries');

	kill('KILL', $pid);
}

###############################################################################
# A structural proof of the same property that does not depend on timing
# against a fake helper's own accept loop, which the empirical test above
# necessarily does (it can only count connections the fake helper got
# around to accepting before call() gave up, which is racy against exactly
# how long the fake helper sleeps for). There is exactly one call site in
# this module that ever opens a connection to the helper, and call() itself
# contains no loop of any kind around it - so there is no code path,
# reached from any input, that could open a second connection for one
# call() invocation, for any operation, mutating or not.
###############################################################################
{
	open(my $fh, '<', "$FindBin::Bin/../ui-src/lib/ConfigServer/UI/Client.pm")
		or die "cannot read Client.pm: $!";
	local $/;
	my $source = <$fh>;
	close $fh;

	# Strip comments first - the header comment above call() names
	# "IO::Socket::UNIX->new()" in prose while explaining why no separate
	# connect timeout is needed, which is a second textual occurrence that
	# has nothing to do with how many times the code actually calls it.
	(my $code_source = $source) =~ s/#.*$//mg;
	my $connects = () = $code_source =~ /IO::Socket::UNIX->new\(/g;
	is($connects, 1, 'Client.pm opens a connection to the helper from exactly one place in the code');

	# Isolate call()'s own body - up to the next sub definition in the file
	# - and confirm it contains no loop keyword. _write_all()'s internal
	# write-retry-on-EINTR loop is a different, already-connected socket
	# operation, not a second connection attempt, so this deliberately
	# checks call() alone rather than the whole file.
	my ($call_body) = $source =~ /\nsub call \{(.*?)\nsub _local_error\b/s;
	ok(defined $call_body && length($call_body), "isolated call()'s body from the source to check it");

	# Comments are prose, not code, and prose legitimately uses the English
	# word "for" (as in "responsible for it being valid") - strip full-line
	# and trailing comments before looking for an actual loop keyword, or
	# this check would be testing English grammar instead of Perl syntax.
	(my $code_only = $call_body) =~ s/#.*$//mg;
	unlike($code_only, qr/\b(?:for|foreach|while|until|redo)\s*[(\{]/,
		"call()'s own code contains no loop construct - there is nothing in it that could retry");
}
