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
# csf-ui-helper's dispatch, peer check, operations and self-imposed limits.
#
# Every test here runs unprivileged: the helper's dispatch is called directly
# with a fake peer-credential provider and a fake child runner, so no root, no
# socket and no real csf are needed. What that does not cover is stated in the
# report rather than papered over - binding the socket and reading real
# SO_PEERCRED need root and are skipped, loudly, below.
###############################################################################
use strict;
use warnings;

use FindBin ();
use lib "$FindBin::Bin/..", "$FindBin::Bin/../ui-src/lib";

use File::Temp qw(tempdir);
use JSON::Tiny ();
use Test::More tests => 227;

my $HELPER_PATH = "$FindBin::Bin/../ui-src/bin/csf-ui-helper";
my $PROTO_PATH  = "$FindBin::Bin/../ui-src/lib/ConfigServer/UI/Proto.pm";

ok(-f $HELPER_PATH, 'the helper source is where the contract says it is');
require $HELPER_PATH;
my $H = 'ConfigServer::UI::Helper';
my $P = 'ConfigServer::UI::Proto';
ok($H->can('handle_request'), 'the helper loads as a module without starting a daemon');

my $NOW = 1757548800;

###############################################################################
# G2 - no shell, asserted about the source itself
###############################################################################
{
	for my $file ($HELPER_PATH, $PROTO_PATH) {
		my $source = _read($file);
		my $name = ($file =~ m{([^/]+)$})[0];
		unlike($source, qr/\x60/, "$name contains no backquote");
		unlike($source, qr/\bqx\s*[\{\(\[\/'"|!#]/, "$name contains no qx");
		unlike($source, qr/\bsystem\s*\(/, "$name never calls system");
		unlike($source, qr/\bopen\s*\([^;]*?['"][^'"\n]*\|/, "$name never opens a pipe to a command string");
		unlike($source, qr/\bexec\s+["']/, "$name never execs a string");
	}
	my $source = _read($HELPER_PATH);
	like($source, qr/exec \{ \$argv\[0\] \} \@argv/,
		'the only exec is the block form, which cannot reach a shell even for a one-element list');
	my @exec = ($source =~ /^\s*exec\b/mg);
	is(scalar(@exec), 1, 'there is exactly one exec statement in the helper');
}

###############################################################################
# Peer authentication (section 2.2)
###############################################################################
{
	my $fx = fixture();
	my @case = (
		[undef,                            'E_PEER',        'credentials the kernel would not give us'],
		[{ pid => 1, uid => 0, gid => 0 }, 'E_PEER',        'uid 0, which has no reason to use this door'],
		[{ pid => 2, uid => 999, gid => 999 }, 'E_PEER',    'a uid that is not csfui'],
	);
	for my $case (@case) {
		my ($peer, $want, $why) = @$case;
		$fx->{ctx}{peercred} = sub { $peer };
		my ($code) = $H->can('check_peer')->($fx->{ctx}, undef);
		is($code, $want, "the peer check rejects $why");
	}

	$fx->{ctx}{peercred} = sub { undef };
	my (undef, undef, undef, $silent) = $H->can('check_peer')->($fx->{ctx}, undef);
	ok($silent, 'a connection the kernel will not vouch for is closed in silence');
	$fx->{ctx}{peercred} = sub { { pid => 1, uid => 0, gid => 0 } };
	(undef, undef, undef, $silent) = $H->can('check_peer')->($fx->{ctx}, undef);
	ok(!$silent, 'but a peer we can identify and refuse is told why');

	$fx->{ctx}{peercred} = sub { { pid => 3, uid => 1000, gid => 1000 } };
	my ($code) = $H->can('check_peer')->($fx->{ctx}, undef);
	is($code, undef, 'the peer check admits the csfui uid');

	$fx->{ctx}{group_ready} = 0;
	($code, my $peer, my $reason) = $H->can('check_peer')->($fx->{ctx}, undef);
	is($code, 'E_UNAVAILABLE', 'with no csfui group every connection is refused');
	like($reason, qr/csfui group/, 'and the refusal says what to fix');
	$fx->{ctx}{group_ready} = 1;

	$fx->{ctx}{expect_uid} = undef;
	($code) = $H->can('check_peer')->($fx->{ctx}, undef);
	is($code, 'E_UNAVAILABLE', 'with no csfui user there is no uid to compare against, so nothing is served');
}

###############################################################################
# Framing and dispatch (sections 3.2, 3.5)
###############################################################################
{
	my $fx = fixture();
	my $peer = { uid => 1000, pid => 4242 };

	my $response = $H->can('handle_line')->($fx->{ctx}, 'this is not json', $peer);
	is($response->{error}, 'E_PROTOCOL', 'a line that is not JSON is a protocol error');
	is($response->{id}, undef, 'and carries a null id, because none could be read');
	ok(!${ $response->{ok} }, 'ok is false on an error response');

	$response = $H->can('handle_line')->($fx->{ctx}, '[1,2,3]', $peer);
	is($response->{error}, 'E_PROTOCOL', 'a JSON array at the top level is a protocol error');

	$response = $H->can('handle_request')->($fx->{ctx}, { op => 'status' }, $peer);
	is($response->{error}, 'E_PROTOCOL', 'a missing id is a protocol error');

	$response = $H->can('handle_request')->($fx->{ctx}, { op => 'status', id => 'a b' }, $peer);
	is($response->{error}, 'E_PROTOCOL', 'an id outside its grammar is a protocol error');

	$response = $H->can('handle_request')->($fx->{ctx}, { op => 'flush', id => 'x1' }, $peer);
	is($response->{error}, 'E_UNKNOWN_OP', 'an operation that is not on the list is refused');
	is($response->{id}, 'x1', 'and the id is echoed so the caller can join its own log');

	$response = $H->can('handle_request')->($fx->{ctx}, { op => 'csf', id => 'x1' }, $peer);
	is($response->{error}, 'E_UNKNOWN_OP', 'there is no raw csf operation');

	$response = $H->can('handle_request')->($fx->{ctx}, { op => 'status', id => 'x1', args => [] }, $peer);
	is($response->{error}, 'E_ARG', 'args must be an object');

	$response = req($fx, 'status', { x => 1 });
	is($response->{error}, 'E_ARG', 'an unknown argument is rejected, never ignored');

	$response = req($fx, 'deny', { note => 'x' });
	is($response->{error}, 'E_ARG', 'a missing required argument is rejected');
	like($response->{message}, qr/^ip:/, 'and the message names the field');

	$response = req($fx, 'deny', { ip => '1.2.3.4', note => 'ok', chain => 'INPUT' });
	is($response->{error}, 'E_ARG', 'a chain cannot be smuggled in as an extra argument');

	$response = req($fx, 'reconcile', { chain => 'INPUT' });
	is($response->{error}, 'E_ARG', 'reconcile takes no arguments at all');

	$response = req($fx, 'restart', { force => JSON::Tiny::true() });
	is($response->{error}, 'E_ARG', 'restart takes no arguments at all');

	is(scalar @{ $fx->{calls} }, 0, 'not one child was started for any rejected request');
}

###############################################################################
# Hostile arguments, per operation (section 6)
###############################################################################
{
	my $fx = fixture();
	my @case = (
		['deny',     { ip => '1.2.3.4; rm -rf /', note => 'x' }, 'a shell fragment in ip'],
		['deny',     { ip => '$(id)', note => 'x' },             'command substitution in ip'],
		['deny',     { ip => '0.0.0.0/0', note => 'x' },         'the whole Internet'],
		['deny',     { ip => '1.0.0.0/4', note => 'x' },         'a prefix below the floor'],
		['deny',     { ip => '192.0.2.10/24', note => 'x' },     'host bits set'],
		['deny',     { ip => '127.0.0.1', note => 'x' },         'loopback'],
		['deny',     { ip => '::ffff:127.0.0.1', note => 'x' },  'an IPv4-mapped address'],
		['deny',     { ip => '999.1.1.1', note => 'x' },         'an impossible octet'],
		['deny',     { ip => '10.0.0.0/33', note => 'x' },       'an impossible prefix'],
		['deny',     { ip => '1.2.3.4', note => "x\nInclude /etc/shadow" }, 'a newline in the note'],
		['deny',     { ip => '1.2.3.4', note => "x\rmore" },     'a carriage return in the note'],
		['deny',     { ip => '1.2.3.4', note => '-p 22 -d out' },'an option-looking note'],
		['deny',     { ip => '1.2.3.4', note => 'a|b' },         'a pipe in the note'],
		['deny',     { ip => '1.2.3.4', note => 'x' x 201 },     'an overlong note'],
		['deny',     { ip => '1.2.3.4', note => '' },            'an empty note, which would make root resolve the address'],
		['tempdeny', { ip => '1.2.3.4', ttl => '1h' },           'a suffixed ttl'],
		['tempdeny', { ip => '1.2.3.4', ttl => 59 },             'a ttl under the floor'],
		['tempdeny', { ip => '1.2.3.4', ttl => 604801 },         'a ttl over the ceiling'],
		['tempdeny', { ip => '1.2.3.4', ttl => 3600, ports => '80;udp' }, 'a protocol suffix in ports'],
		['tempdeny', { ip => '1.2.3.4', ttl => 3600, ports => '*' },      'a wildcard in ports'],
		['tempdeny', { ip => '1.2.3.4', ttl => 3600, ports => '1000-2000' }, 'a range over the expansion cap'],
		['tempdeny', { ip => '1.2.3.4', ttl => 3600, note => 'hello' },   'a note, which tempdeny does not take'],
		['list',     { which => 'ignore' },                      'a which that is not in the table'],
		['list',     { which => '../../etc/shadow' },            'a path as which'],
		['list',     { which => 'deny', limit => 501 },          'a limit over the cap'],
		['list',     { which => 'deny', offset => -1 },          'a negative offset'],
		['list',     { which => 'deny', filter => 'x' x 101 },   'an overlong filter'],
		['grep',     { ip => '80' },                             'a port where grep takes an address'],
		['grep',     { ip => '0.0.0.0/0' },                      'a search for everything'],
		['reconcile_fix', { ids => ['../../x'] },                'a path as an id'],
		['reconcile_fix', { ids => 'notanarray' },               'a bare string instead of a list'],
		['reconcile_fix', { ids => [('a' x 32) x 501] },         'more ids than the cap'],
		['authenticate',  { user => 'Alice', pass => 'x' },      'a username outside the grammar'],
		['authenticate',  { user => '../../etc/shadow', pass => 'x' }, 'a path as a username'],
		['authenticate',  { user => 'alice', pass => "a\0b" },   'a NUL byte in the password'],
		['authenticate',  { user => 'alice', pass => 'x' x 1025 }, 'a password over the cap'],
	);
	for my $case (@case) {
		my ($op, $args, $why) = @$case;
		my $response = req($fx, $op, $args);
		is($response->{error}, 'E_ARG', "$op rejects $why");
	}
	is(scalar @{ $fx->{calls} }, 0, 'no hostile argument reached a child process');

	my $response = req($fx, 'authenticate', { user => 'alice', pass => "hunter2\0" });
	unlike($response->{message}, qr/hunter2/, 'a rejected password is never quoted back');
}

###############################################################################
# 5.3 deny - the outcome comes from the state delta, never from the exit status
###############################################################################
{
	my $fx = fixture();
	$fx->{ctx}{run} = csf_stub($fx);

	my $response = req($fx, 'deny', { ip => '192.0.2.10', note => 'abuse ticket 4471' });
	ok(${ $response->{ok} }, 'a first deny succeeds');
	ok(${ $response->{data}{added} }, 'and reports that the address was added');
	is_deeply($fx->{calls}[0],
		[$fx->{path}{csf_bin}, '-d', '192.0.2.10', 'abuse ticket 4471'],
		'csf is called with an argv list and nothing else');

	$response = req($fx, 'deny', { ip => '192.0.2.10', note => 'abuse ticket 4471' });
	ok(${ $response->{ok} }, 'denying the same address again is not an error');
	ok(!${ $response->{data}{added} }, 'and says nothing was added');
	ok(${ $response->{data}{already} }, 'and says it was already there');

	$response = req($fx, 'deny', { ip => '2001:DB8::1', note => 'canonical form' });
	is($fx->{calls}[-1][2], '2001:db8::1', 'the canonical form, not the caller text, is what reaches csf');

	# csf exits 0 after refusing (csf.pl:1541-1551), so a refusal has to be read
	# from the absence of a change plus the text it printed.
	$fx = fixture();
	$fx->{ctx}{run} = sub {
		my ($ctx, $deadline, @argv) = @_;
		push @{ $fx->{calls} }, [@argv];
		return { exit => 0, status => 0, output => "deny failed: [192.0.2.11] is one of this servers addresses!\n" };
	};
	$response = req($fx, 'deny', { ip => '192.0.2.11', note => 'x' });
	is($response->{error}, 'E_REFUSED', 'a refusal that exits 0 is still a refusal');
	like($response->{message}, qr/one of this servers addresses/, 'and csf\'s reason is passed through');

	$fx = fixture();
	$fx->{ctx}{run} = sub { return { exit => 0, status => 0, output => '' } };
	$response = req($fx, 'deny', { ip => '192.0.2.12', note => 'x' });
	is($response->{error}, 'E_BACKEND', 'no change and no reason we recognise is a backend failure, not a success');

	$fx = fixture();
	$fx->{ctx}{run} = sub { return { timeout => 1, exit => 0, status => 9, output => '' } };
	$response = req($fx, 'deny', { ip => '192.0.2.13', note => 'x' });
	is($response->{error}, 'E_BACKEND', 'a child that hit its deadline is a backend failure');
}

###############################################################################
# 5.4 undeny - removal counts come from the file, including "do not delete"
###############################################################################
{
	my $fx = fixture(deny => "198.51.100.1 # spam - date\n198.51.100.2 # do not delete - date\n");
	$fx->{ctx}{run} = csf_stub($fx);

	my $response = req($fx, 'undeny', { ip => '198.51.100.1' });
	is($response->{data}{removed}, 1, 'undeny reports the drop in matching lines');
	is($response->{data}{protected}, 0, 'and nothing was protected');
	is_deeply($fx->{calls}[0], [$fx->{path}{csf_bin}, '-dr', '198.51.100.1'], 'undeny runs csf -dr');

	$response = req($fx, 'undeny', { ip => '198.51.100.2' });
	is($response->{data}{removed}, 0, 'an entry marked do not delete is not removed');
	is($response->{data}{protected}, 1, 'and is reported as protected');

	$response = req($fx, 'undeny', { ip => '203.0.113.77' });
	ok(${ $response->{ok} }, 'removing something that is not there is not an error');
	is($response->{data}{removed}, 0, 'and reports nothing removed');

	$response = req($fx, 'undeny', { ip => '0.0.0.0/0' });
	ok(${ $response->{ok} }, 'the one entry capable of blocking everything can be removed');
}

###############################################################################
# 5.7 tempdeny - the fixed note is what keeps root out of a DNS lookup
###############################################################################
{
	my $fx = fixture();
	$fx->{ctx}{run} = csf_stub($fx);

	my $response = req($fx, 'tempdeny', { ip => '198.51.100.9', ttl => 3600, ports => '80,443' });
	ok(${ $response->{ok} }, 'tempdeny succeeds');
	is_deeply($fx->{calls}[0],
		[$fx->{path}{csf_bin}, '-td', '198.51.100.9', 3600, '-p', '80,443', 'csf-ui'],
		'the argv ends with the fixed csf-ui note, so csf never reaches its iplookup branch');
	is($response->{data}{note}, 'csf-ui', 'the note reported back is the fixed literal');
	is($response->{data}{ttl}, 3600, 'the ttl is echoed as an integer');

	$fx = fixture();
	$fx->{ctx}{run} = csf_stub($fx);
	req($fx, 'tempdeny', { ip => '198.51.100.10', ttl => '600' });
	is_deeply($fx->{calls}[0], [$fx->{path}{csf_bin}, '-td', '198.51.100.10', 600, 'csf-ui'],
		'with no ports no -p is passed at all, and a digit string becomes an integer');

	$fx = fixture();
	$fx->{ctx}{run} = csf_stub($fx);
	req($fx, 'tempdeny', { ip => '198.51.100.11', ttl => 600, ports => '1-3' });
	is($fx->{calls}[0][5], '1,2,3', 'a port range is expanded, because csf would otherwise keep only its lower bound');

	$fx = fixture();
	$fx->{ctx}{run} = sub {
		my ($ctx, $deadline, @argv) = @_;
		push @{ $fx->{calls} }, [@argv];
		return { exit => 0, status => 0, output => "csf: 198.51.100.12 is already permanently blocked\n" };
	};
	my $blocked = req($fx, 'tempdeny', { ip => '198.51.100.12', ttl => 600 });
	is($blocked->{error}, 'E_REFUSED', 'an address that is already permanently blocked is a refusal');
}

###############################################################################
# 5.8 temprm - csf -trd, never csf -tr
###############################################################################
{
	my $fx = fixture(tempban => ($NOW - 10) . "|198.51.100.20|80|in|3600|csf-ui\n");
	$fx->{ctx}{run} = csf_stub($fx);
	my $response = req($fx, 'temprm', { ip => '198.51.100.20' });
	is($fx->{calls}[0][1], '-trd',
		'temprm uses -trd, so it cannot silently delete a temporary allow the operator cannot see');
	is($response->{data}{removed}, 1, 'and reports the row it removed');
}

###############################################################################
# 5.9 list
###############################################################################
{
	my $deny = join('', map { "198.51.100.$_ # ticket $_ - date\n" } 1 .. 10);
	$deny .= "# a comment\n\nInclude /etc/csf/csf.deny.local\nnot-an-address at all\n";
	$deny .= "203.0.113.9 # do not delete - date\n";
	my $fx = fixture(deny => $deny);

	my $response = req($fx, 'list', { which => 'deny' });
	ok(${ $response->{ok} }, 'list reads the deny file');
	is($response->{data}{total}, 11, 'comments, blanks, includes and unparsable lines are not rows');
	is($response->{data}{includes}, 1, 'the include is counted, never followed');
	is($response->{data}{unparsable}, 1, 'a line that does not parse is counted, not rendered as half a row');
	is($response->{data}{returned}, 11, 'every row fits in one response here');
	is($response->{data}{next_offset}, undef, 'and there is no next page');
	is($response->{data}{rows}[0]{ip}, '198.51.100.1', 'the first row is the first entry');
	is($response->{data}{rows}[0]{note}, 'ticket 1 - date',
		'the note is the text after the address with its leading hash stripped, and nothing else guessed at');
	ok(${ $response->{data}{rows}[-1]{protected} }, 'a do-not-delete row is marked protected');

	$response = req($fx, 'list', { which => 'deny', offset => 0, limit => 4 });
	is($response->{data}{returned}, 4, 'a limit is honoured');
	is($response->{data}{next_offset}, 4, 'and next_offset is offset plus what was actually returned');
	is($response->{data}{total}, 11, 'the total is over the whole filtered set, not the page');

	$response = req($fx, 'list', { which => 'deny', filter => 'TICKET 3' });
	is($response->{data}{total}, 1, 'the filter is matched case-insensitively on address and note');
	$response = req($fx, 'list', { which => 'deny', filter => '.*' });
	is($response->{data}{total}, 0, 'a regex metacharacter finds nothing, because it is never compiled');

	$fx = fixture(tempban => join('',
		($NOW - 10) . "|198.51.100.30|80,443|in|3600|csf-ui\n",
		($NOW - 7200) . "|198.51.100.31||in|3600|expired\n"));
	$response = req($fx, 'list', { which => 'temp' });
	is($response->{data}{total}, 1, 'an expired temporary ban is not shown');
	is($response->{data}{rows}[0]{ttl_left}, 3590, 'the remaining time is reported');
	is($response->{data}{rows}[0]{dir}, 'in', 'the direction is reported');
	is($response->{data}{rows}[0]{ports}, '80,443', 'the stored ports are reported');
}

###############################################################################
# 5.2 counts
###############################################################################
{
	my $fx = fixture(
		deny  => "198.51.100.1\nInclude /etc/csf/csf.deny.local\n# comment\n",
		allow => "203.0.113.1\n203.0.113.2\n",
		tempban => ($NOW - 10) . "|198.51.100.30||in|3600|csf-ui\n" . ($NOW - 7200) . "|198.51.100.31||in|60|old\n",
		tempallow => ($NOW - 10) . "|203.0.113.9||in|3600|manual\n",
	);
	my $response = req($fx, 'counts', {});
	is($response->{data}{deny}, 1, 'counts counts parsable deny entries only');
	is($response->{data}{deny_includes}, 1, 'and reports includes separately rather than under-reporting');
	is($response->{data}{allow}, 2, 'counts the allow file');
	is($response->{data}{temp_deny}, 1, 'expired temporary bans are excluded');
	is($response->{data}{temp_allow}, 1, 'temporary allows are counted, because hiding them hides the riskier number');
	is(scalar @{ $fx->{calls} }, 0, 'counts starts no child process at all');
}

###############################################################################
# 5.1 status
###############################################################################
{
	my $fx = fixture();
	$fx->{ctx}{run} = sub {
		my ($ctx, $deadline, @argv) = @_;
		push @{ $fx->{calls} }, [@argv];
		return { exit => 0, status => 0, output => "-P INPUT ACCEPT\n-N DENYIN\n-A DENYIN -s 1.2.3.4/32 -j DROP\n" };
	};
	my $response = req($fx, 'status', {});
	ok(${ $response->{ok} }, 'status answers');
	ok(${ $response->{data}{rules_loaded} }, 'rules_loaded comes from the live ruleset, not from a file');
	ok(${ $response->{data}{enabled} }, 'csf is reported as enabled');
	ok(!${ $response->{data}{testing} }, 'TESTING is read from csf.conf');
	is($response->{data}{version}, '15.00', 'the version is accepted only in its own grammar');
	is_deeply($fx->{calls}[0], ['/sbin/iptables', '-S'], 'status spawns exactly one child, and it is iptables -S');

	$fx = fixture();
	$fx->{ctx}{run} = sub { return { exit => 1, status => 256, output => "cannot talk to the kernel\n" } };
	$response = req($fx, 'status', {});
	is($response->{error}, 'E_BACKEND',
		'"I could not find out" is never reported as "the firewall is not loaded"');
}

###############################################################################
# 5.0.5 csf disabled or in error
###############################################################################
{
	my $fx = fixture();
	_write($fx->{path}{csf_disable}, "");
	$fx->{ctx}{run} = csf_stub($fx);

	my $response = req($fx, 'deny', { ip => '198.51.100.40', note => 'x' });
	is($response->{error}, 'E_REFUSED', 'with csf disabled a mutating operation is refused');
	$response = req($fx, 'restart', {});
	is($response->{error}, 'E_REFUSED', 'and so is restart, because -r is not exempt from that check');
	is(scalar @{ $fx->{calls} }, 0, 'neither started a child');

	$fx->{ctx}{run} = sub { return { exit => 0, status => 0, output => "-N DENYIN\n" } };
	$response = req($fx, 'status', {});
	ok(${ $response->{ok} }, 'status still answers, because it is what tells the operator csf is disabled');
	ok(!${ $response->{data}{enabled} }, 'and it says csf is disabled');

	$fx = fixture();
	_write($fx->{path}{csf_error}, "iptables: No chain/target/match by that name\n");
	$fx->{ctx}{run} = csf_stub($fx);
	$response = req($fx, 'deny', { ip => '198.51.100.41', note => 'x' });
	is($response->{error}, 'E_REFUSED', 'with an unresolved start error a deny is refused');
	$response = req($fx, 'restart', {});
	ok(${ $response->{ok} }, 'but restart runs, because it is the only thing here that clears that state');
}

###############################################################################
# 5.13 restart
###############################################################################
{
	my $fx = fixture();
	$fx->{ctx}{run} = sub {
		return { exit => 0, status => 0, output => "*WARNING* TESTING mode is enabled\nDone.\n" };
	};
	my $response = req($fx, 'restart', {});
	ok(${ $response->{ok} }, 'restart succeeds');
	is($response->{data}{warnings}[0], '*WARNING* TESTING mode is enabled', 'warnings are passed through');

	$response = req($fx, 'restart', {});
	is($response->{error}, 'E_BUSY', 'a second restart inside the interval is refused');

	$fx = fixture();
	$fx->{ctx}{run} = sub { return { exit => 0, status => 0, output => "Error: csf is being restarted, try again in a moment\n" } };
	$response = req($fx, 'restart', {});
	is($response->{error}, 'E_BUSY', 'the csf lock being held is transient, not a failure');
}

###############################################################################
# 5.11 and 5.12 reconcile
###############################################################################
my $IPTABLES_OUT = join("\n",
	'-P INPUT ACCEPT',
	'-N DENYIN',
	'-N DENYOUT',
	'-A DENYIN -s 198.51.100.7/32 -j DROP',
	'-A DENYIN -s 203.0.113.5/32 -j DROP',
	'-A DENYIN -s 203.0.113.5/32 -j DROP',
	'-A DENYOUT -d 198.51.100.7/32 -j DROP',
	'-A DENYIN -s 192.0.2.99/32 -m comment --comment "hand written" -j DROP',
	'-A INPUT -j ACCEPT',
	''
);
{
	my $fx = fixture(deny => "203.0.113.5\n10.1.2.3\n");
	$fx->{ctx}{run} = sub {
		my ($ctx, $deadline, @argv) = @_;
		push @{ $fx->{calls} }, [@argv];
		return { exit => 0, status => 0, output => $IPTABLES_OUT } if $argv[1] eq '-S';
		return { exit => 0, status => 0, output => '' };
	};

	my $response = req($fx, 'reconcile', {});
	ok(${ $response->{ok} }, 'reconcile answers');
	is($response->{data}{totals}{orphan}, 3, 'rules with no configured entry are orphans, including the unreadable one');
	is($response->{data}{totals}{dup}, 1, 'a rule loaded twice is one duplicate finding');
	is($response->{data}{totals}{ghost}, 1, 'a configured entry with no rule is a ghost');

	my %by_ip = map { ($_->{ip} || 'none') => $_ } @{ $response->{data}{entries} };
	ok(${ $by_ip{'198.51.100.7/32'}{fixable} }, 'an orphan is fixable');
	is(scalar(grep { $_->{kind} eq 'ORPHAN' } @{ $response->{data}{entries} }), 3,
		'the same address orphaned in two chains is two findings, because two rules must be deleted');
	is($by_ip{'10.1.2.3'}{kind}, 'GHOST', 'the ghost is the deny entry with no rule');
	ok(!${ $by_ip{'10.1.2.3'}{fixable} }, 'a ghost is not fixable here; the remedy is a restart');
	my ($unreadable) = grep { ($_->{reason} || '') eq 'unparsable' } @{ $response->{data}{entries} };
	ok($unreadable, 'a rule that does not tokenise is reported');
	ok(!${ $unreadable->{fixable} }, 'and is never approximately parsed into a delete command');

	my ($orphan) = grep { $_->{kind} eq 'ORPHAN' && ($_->{chain} || '') eq 'DENYIN' && ${ $_->{fixable} } }
		@{ $response->{data}{entries} };
	my $orphan_id = $orphan->{id};
	like($orphan_id, qr/^[0-9a-f]{32}$/, 'a finding id is 32 lowercase hex characters');

	# A forged id names nothing, because reconcile_fix re-derives the whole set.
	$response = req($fx, 'reconcile_fix', { ids => ['0' x 32, 'f' x 32] });
	is($response->{error}, 'E_STALE', 'ids that are absent from a fresh scan are stale, and all-stale is E_STALE');

	$fx->{calls} = [];
	$response = req($fx, 'reconcile_fix', { ids => [$orphan_id] });
	ok(${ $response->{ok} }, 'fixing a live orphan succeeds');
	is($response->{data}{fixed}, 1, 'and reports one rule deleted');
	my ($delete) = grep { $_->[1] eq '-D' } @{ $fx->{calls} };
	is_deeply($delete, ['/sbin/iptables', '-D', 'DENYIN', '-s', '198.51.100.7/32', '-j', 'DROP'],
		'the delete is an argv list built from tokens iptables itself produced, with the chain from our own table');

	my $ghost_id = $by_ip{'10.1.2.3'}{id};
	$response = req($fx, 'reconcile_fix', { ids => [$ghost_id] });
	is($response->{data}{results}[0]{outcome}, 'unfixable', 'a ghost is never deleted');

	$fx = fixture(conf => qq(TESTING = "0"\nIPV6 = "0"\nLF_IPSET = "1"\nIPTABLES = "/sbin/iptables"\nIP6TABLES = "/sbin/ip6tables"\n));
	$response = req($fx, 'reconcile', {});
	is($response->{error}, 'E_UNAVAILABLE',
		'with ipsets a per-rule comparison would be thousands of false ghosts, so it is refused with a reason');
}

###############################################################################
# 5.10 grep
###############################################################################
{
	my $fx = fixture();
	$fx->{ctx}{run} = sub {
		my ($ctx, $deadline, @argv) = @_;
		push @{ $fx->{calls} }, [@argv];
		return { exit => 0, status => 0, output => join("\n", map { "line $_ \x1b[31m" } 1 .. 250) };
	};
	my $response = req($fx, 'grep', { ip => '198.51.100.50' });
	is_deeply($fx->{calls}[0], [$fx->{path}{csf_bin}, '-g', '198.51.100.50'], 'grep runs csf -g with an argv list');
	is($response->{data}{count}, 250, 'the count is over the whole output');
	is(scalar @{ $response->{data}{lines} }, 200, 'at most 200 lines are returned');
	ok(${ $response->{data}{truncated} }, 'and the response says it was truncated');
	unlike($response->{data}{lines}[0], qr/\x1b/, 'a terminal escape in csf output is sanitised away');
}

###############################################################################
# 5.14 authenticate
###############################################################################
{
	# R17: the credential check is Task 3's. Until it exists the seam fails
	# closed, and - this is the part that matters - it must not burn the
	# per-username failure counter.
	my $fx = fixture(users => "alice:6:\$6\$salt\$hash:admin:1757548800\n");
	my $response = req($fx, 'authenticate', { user => 'alice', pass => 'whatever' });
	is($response->{error}, 'E_UNAVAILABLE', 'with no verifier installed authenticate fails closed');
	like($response->{message}, qr/verifier is not installed/, 'and says what is missing');
	is(_authfail_count($fx, 'alice'), 0, 'and the failure counter is untouched, so nobody is locked out by a missing module');

	$fx = fixture(users => "alice:6:\$6\$salt\$hash:admin:1757548800\nbob:6:\$6\$salt\$other:support:1757548800\n");
	my @seen;
	$fx->{ctx}{auth_verify} = sub { my ($ctx, $hash, $pass) = @_; push @seen, $hash; return (($pass eq 'correct') ? 1 : 0, undef) };

	$response = req($fx, 'authenticate', { user => 'alice', pass => 'correct' });
	ok(${ $response->{ok} }, 'a valid login is a successful call');
	ok(${ $response->{data}{ok} }, 'with a positive verdict');
	is($response->{data}{role}, 'admin', 'and the role from the record');

	$response = req($fx, 'authenticate', { user => 'bob', pass => 'correct' });
	is($response->{data}{role}, 'support', 'the support role comes back as itself');

	$response = req($fx, 'authenticate', { user => 'alice', pass => 'wrong' });
	ok(${ $response->{ok} }, 'a wrong password is a successful call, not an RPC error');
	ok(!${ $response->{data}{ok} }, 'with a negative verdict');
	is($response->{data}{role}, undef, 'and no role');
	ok(!${ $response->{data}{locked} }, 'and not yet locked');
	is(_authfail_count($fx, 'alice'), 1, 'the failure is counted by the helper itself');

	@seen = ();
	$response = req($fx, 'authenticate', { user => 'nosuchuser', pass => 'wrong' });
	ok(!${ $response->{data}{ok} }, 'an unknown username gets the same shape as a wrong password');
	is(scalar @seen, 1, 'and one hash is still verified, so the timing does not enumerate users');
	like($seen[0], qr/^\$6\$/, 'and it is the fixed dummy record');

	req($fx, 'authenticate', { user => 'alice', pass => 'wrong' }) for 1 .. 4;
	$response = req($fx, 'authenticate', { user => 'alice', pass => 'wrong' });
	ok(${ $response->{data}{locked} }, 'five consecutive failures lock the username');
	cmp_ok($response->{data}{retry_after}, '>', 0, 'and the caller is told how long to wait');

	@seen = ();
	$response = req($fx, 'authenticate', { user => 'alice', pass => 'correct' });
	ok(${ $response->{data}{locked} }, 'while locked even the right password is answered locked');
	is(scalar @seen, 0, 'and no hashing is done at all, which is what makes the counter a CPU control');

	$fx->{ctx}{now} = sub { $NOW + 301 };
	$response = req($fx, 'authenticate', { user => 'alice', pass => 'correct' });
	ok(${ $response->{data}{ok} }, 'the lockout expires on its own');
	is(_authfail_count($fx, 'alice'), 0, 'and a success clears the record');

	$fx = fixture(users => "alice:2:\$2y\$salt\$hash:admin:1757548800\n");
	$fx->{ctx}{auth_verify} = sub { die 'the verifier must not be called for an algorithm we cannot verify' };
	$response = req($fx, 'authenticate', { user => 'alice', pass => 'x' });
	is($response->{error}, 'E_UNAVAILABLE', 'a record with an algorithm this helper cannot verify is unavailable, not wrong');
	is(_authfail_count($fx, 'alice'), 0, 'and the counter is untouched, so a bad store cannot lock out the administrator');

	$fx = fixture();
	unlink $fx->{path}{users};
	$response = req($fx, 'authenticate', { user => 'alice', pass => 'x' });
	is($response->{error}, 'E_UNAVAILABLE', 'a missing password store is unavailable');
	like($response->{message}, qr/csf-ui-passwd/, 'and the message carries the remedy');

	$fx = fixture(users => "alice:6:\$6\$salt\$hash:admin:1757548800\n");
	chmod 0644, $fx->{path}{users};
	$response = req($fx, 'authenticate', { user => 'alice', pass => 'x' });
	is($response->{error}, 'E_UNAVAILABLE', 'a password store readable by anyone else is refused');

	$fx = fixture(users => "# only a comment\n");
	$response = req($fx, 'authenticate', { user => 'alice', pass => 'x' });
	is($response->{error}, 'E_UNAVAILABLE', 'a store with no accounts is unavailable');
}

###############################################################################
# Section 7 limits
###############################################################################
{
	my $fx = fixture();
	_write($fx->{path}{rate_state}, JSON::Tiny::encode_json({ mutate => { $NOW => 120 } }));
	$fx->{ctx}{run} = csf_stub($fx);
	my $response = req($fx, 'deny', { ip => '198.51.100.60', note => 'x' });
	is($response->{error}, 'E_BUSY', 'past the mutation rate cap the helper says so rather than working harder');
	is(scalar @{ $fx->{calls} }, 0, 'and no child is started');

	$fx = fixture();
	_write($fx->{path}{rate_state}, JSON::Tiny::encode_json({ auth => { $NOW => 30 } }));
	$response = req($fx, 'authenticate', { user => 'alice', pass => 'x' });
	is($response->{error}, 'E_BUSY', 'authenticate has its own rate cap, because crypt now burns root CPU');

	$fx = fixture(users => "alice:6:\$6\$salt\$hash:admin:1757548800\n");
	_write($fx->{path}{rate_state},
		JSON::Tiny::encode_json({ auth_active => { $$ => $NOW, getppid() => $NOW } }));
	$response = req($fx, 'authenticate', { user => 'alice', pass => 'x' });
	is($response->{error}, 'E_BUSY', 'only two authenticate children may hash at once');
}

###############################################################################
# Section 8 audit
###############################################################################
{
	my $fx = fixture();
	$fx->{ctx}{run} = csf_stub($fx);
	req($fx, 'deny', { ip => '198.51.100.70', note => 'abuse ' . ('x' x 100) }, 'req-1');
	my @lines = split(/\n/, _read($fx->{path}{audit_log}));
	is(scalar @lines, 1, 'a mutating operation writes exactly one audit line');
	my $entry = JSON::Tiny::decode_json($lines[0]);
	is($entry->{op}, 'deny', 'the line says what ran');
	is($entry->{id}, 'req-1', 'and carries the request id that joins the two logs');
	is($entry->{peer}{uid}, 1000, 'and the peer uid the kernel reported');
	ok($entry->{ok}, 'and the outcome');
	is(length($entry->{args}{note}), 64, 'the note is truncated in the log');

	req($fx, 'deny', { ip => 'nonsense', note => 'x' }, 'req-2');
	@lines = split(/\n/, _read($fx->{path}{audit_log}));
	is(scalar @lines, 2, 'a rejected request is audited too');
	$entry = JSON::Tiny::decode_json($lines[1]);
	is($entry->{error}, 'E_ARG', 'with the code it was rejected with');

	$fx = fixture(users => "alice:6:\$6\$salt\$hash:admin:1757548800\n");
	$fx->{ctx}{auth_verify} = sub { return (0, undef) };
	req($fx, 'authenticate', { user => 'alice', pass => 'hunter2-secret' }, 'req-3');
	my $log = _read($fx->{path}{audit_log});
	unlike($log, qr/hunter2/, 'a password never reaches the audit log');
	unlike($log, qr/"pass"/, 'and there is no pass field left for a later change to start filling in');
	$entry = JSON::Tiny::decode_json((split(/\n/, $log))[0]);
	is($entry->{args}{user}, 'alice', 'but the username is recorded');
	is($entry->{detail}, 'bad', 'along with the outcome');

	# A control byte cannot reach the log through an argument, and if one ever
	# did the JSON encoder would escape it rather than write a raw newline.
	$fx = fixture();
	$H->can('audit')->($fx->{ctx}, { ts => $NOW, op => 'x', detail => "a\nb\x1bc" });
	@lines = split(/\n/, _read($fx->{path}{audit_log}));
	is(scalar @lines, 1, 'a control byte cannot split an audit line in two');
	like($lines[0], qr/\\n/, 'the newline is escaped by the encoder');
}

###############################################################################
# An unexpected failure never leaks anything back to the caller
###############################################################################
{
	my $fx = fixture();
	$fx->{ctx}{run} = sub { die "something broke in /etc/csf/secret-path\n" };
	my $response = req($fx, 'deny', { ip => '198.51.100.80', note => 'x' });
	is($response->{error}, 'E_INTERNAL', 'an unexpected error is an internal error');
	unlike($response->{message}, qr{secret-path}, 'and never carries a path back to the caller');
	my $log = _read($fx->{path}{audit_log});
	like($log, qr/secret-path/, 'the detail goes to the audit log instead');
}

###############################################################################
# run_argv - the one place a shell could ever get in
#
# These run real programs, unprivileged, and are the evidence behind the source
# greps above: a metacharacter in an argument arrives at the child as one argv
# element and nothing interprets it.
###############################################################################
SKIP: {
	skip 'needs /bin/echo, /bin/cat and /bin/sleep', 7
		unless -x '/bin/echo' && -x '/bin/cat' && -x '/bin/sleep';
	my $fx = fixture();
	my $run = $H->can('run_argv');

	my $result = $run->($fx->{ctx}, 10, '/bin/echo', 'hello');
	is($result->{exit}, 0, 'a child that succeeds reports exit 0');
	is($result->{output}, "hello\n", 'and its output is captured');

	$result = $run->($fx->{ctx}, 10, '/bin/echo', 'a; rm -rf /', '$(id)', '`id`', 'x|y');
	is($result->{output}, "a; rm -rf / \$(id) \`id\` x|y\n",
		'shell metacharacters arrive at the child as literal argv elements, because there is no shell');

	$result = $run->($fx->{ctx}, 10, '/does/not/exist/csf', '-d');
	is($result->{exit}, 127, 'a command that cannot be started reports 127 rather than pretending to have run');

	my $big = "$fx->{dir}/big";
	_write($big, 'x' x 70000);
	$result = $run->($fx->{ctx}, 10, '/bin/cat', $big);
	ok($result->{overflow}, 'a child that floods us past the 64 KiB cap is cut off');
	ok(length($result->{output}) <= 65536 + 8192, 'and we never buffer far past the cap');

	my $started = time();
	$result = $run->($fx->{ctx}, 1, '/bin/sleep', '30');
	ok($result->{timeout} && time() - $started < 10,
		'a child that outruns its deadline is killed rather than waited on');
}

###############################################################################
# What cannot be tested without root
###############################################################################
SKIP: {
	skip 'binding the helper socket and reading real SO_PEERCRED need root', 2 if $> != 0;
	my $fx = fixture();
	my $listener = eval { $H->can('open_socket')->($fx->{ctx}) };
	ok($listener, 'the socket can be created');
	my @stat = stat($fx->{path}{socket});
	is($stat[2] & 07777, (defined getgrnam('csfui') ? 0660 : 0600),
		'and carries the mode the contract gives it');
	close $listener if $listener;
}

###############################################################################
# Fixture
###############################################################################
sub fixture {
	my (%option) = @_;
	my $dir = tempdir(CLEANUP => 1);

	my %path = (
		socket_dir  => "$dir/run",
		socket      => "$dir/run/helper.sock",
		rate_state  => "$dir/rate.state",
		helper_dir  => "$dir/helper",
		authfail    => "$dir/authfail.state",
		audit_log   => "$dir/audit.log",
		users       => "$dir/users",
		csf_bin     => "$dir/csf",
		csf_conf    => "$dir/csf.conf",
		csf_deny    => "$dir/csf.deny",
		csf_allow   => "$dir/csf.allow",
		csf_disable => "$dir/csf.disable",
		csf_error   => "$dir/csf.error",
		csf_version => "$dir/version.txt",
		tempban     => "$dir/csf.tempban",
		tempallow   => "$dir/csf.tempallow",
		lfd_pid     => "$dir/lfd.pid",
	);

	_write($path{csf_conf}, $option{conf} || qq(TESTING = "0"\nIPV6 = "0"\nLF_IPSET = "0"\nIPTABLES = "/sbin/iptables"\nIP6TABLES = "/sbin/ip6tables"\n));
	_write($path{csf_deny},  defined $option{deny}  ? $option{deny}  : '');
	_write($path{csf_allow}, defined $option{allow} ? $option{allow} : '');
	_write($path{tempban},   defined $option{tempban} ? $option{tempban} : '');
	_write($path{tempallow}, defined $option{tempallow} ? $option{tempallow} : '');
	_write($path{csf_version}, "15.00\n");
	_write($path{users}, defined $option{users} ? $option{users} : "alice:6:\$6\$salt\$hash:admin:1757548800\n");
	chmod 0600, $path{users};

	my $fx = { dir => $dir, path => \%path, calls => [] };
	$fx->{ctx} = $H->can('new_context')->(
		path        => \%path,
		now         => sub { $NOW },
		expect_uid  => 1000,
		group_ready => 1,
		run         => sub {
			my ($ctx, $deadline, @argv) = @_;
			push @{ $fx->{calls} }, [@argv];
			return { exit => 0, status => 0, output => '' };
		},
	);
	return $fx;
}

# Stands in for csf: records the argv and makes the change csf would have made,
# so that the delta logic is exercised for real rather than mocked around.
sub csf_stub {
	my ($fx) = @_;
	return sub {
		my ($ctx, $deadline, @argv) = @_;
		push @{ $fx->{calls} }, [@argv];
		my $flag = defined $argv[1] ? $argv[1] : '';
		my $ip = $argv[2];
		if ($flag eq '-d' || $flag eq '-a') {
			my $file = ($flag eq '-d') ? $fx->{path}{csf_deny} : $fx->{path}{csf_allow};
			my $body = _read($file);
			unless ($body =~ /^\Q$ip\E(\s|$)/m) {
				_write($file, $body . "$ip # $argv[3] - date\n");
			}
		}
		elsif ($flag eq '-dr' || $flag eq '-ar') {
			my $file = ($flag eq '-dr') ? $fx->{path}{csf_deny} : $fx->{path}{csf_allow};
			my @keep;
			for my $line (split(/\n/, _read($file), -1)) {
				next if $line eq '';
				if ($line =~ /^\Q$ip\E(\s|$)/ && $line !~ /do not delete/i) { next }
				push @keep, $line;
			}
			_write($file, join('', map { "$_\n" } @keep));
		}
		elsif ($flag eq '-td') {
			my $ports = '';
			for my $index (0 .. $#argv - 1) {
				$ports = $argv[$index + 1] if $argv[$index] eq '-p';
			}
			_write($fx->{path}{tempban},
				_read($fx->{path}{tempban}) . join('|', $NOW, $ip, $ports, 'in', $argv[3], $argv[-1]) . "\n");
		}
		elsif ($flag eq '-trd') {
			my @keep = grep { $_ ne '' && $_ !~ /^\d+\|\Q$ip\E\|/ } split(/\n/, _read($fx->{path}{tempban}), -1);
			_write($fx->{path}{tempban}, join('', map { "$_\n" } @keep));
		}
		return { exit => 0, status => 0, output => '' };
	};
}

sub req {
	my ($fx, $op, $args, $id) = @_;
	return $H->can('handle_request')->(
		$fx->{ctx},
		{ op => $op, args => $args, id => (defined $id ? $id : 'testid') },
		{ uid => 1000, pid => 4242 },
	);
}

sub _authfail_count {
	my ($fx, $user) = @_;
	my $body = _read($fx->{path}{authfail});
	return 0 unless length $body;
	my $state = eval { JSON::Tiny::decode_json($body) } || {};
	my $record = $state->{users}{$user};
	return 0 unless $record;
	return $record->{fails} || 0;
}

sub _read {
	my ($path) = @_;
	open(my $fh, '<', $path) or return '';
	binmode($fh);
	local $/;
	my $data = <$fh>;
	close $fh;
	return defined $data ? $data : '';
}

sub _write {
	my ($path, $data) = @_;
	open(my $fh, '>', $path) or die "cannot write $path: $!";
	binmode($fh);
	print $fh $data;
	close $fh;
	return;
}
