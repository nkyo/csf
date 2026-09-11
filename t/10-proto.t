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
# The wire format and the argument grammars of docs/WEBUI-RPC.md sections 3 and
# 4. Runs without root, without a network and without IO::Socket::SSL.
#
# The hostile tables below are the floor, not the target: every value that has
# ever been a way into a root process through a firewall UI belongs here.
###############################################################################
use strict;
use warnings;

use FindBin ();
use lib "$FindBin::Bin/..", "$FindBin::Bin/../ui-src/lib";

use File::Temp ();
use Test::More tests => 189;

require_ok('ConfigServer::UI::Proto');
my $P = 'ConfigServer::UI::Proto';

###############################################################################
# Framing
###############################################################################
{
	my $line = $P->can('encode')->({ id => 'abc', ok => \1, data => { ip => '192.0.2.1' } });
	like($line, qr/\n\z/, 'encode terminates the line with one newline');
	unlike(substr($line, 0, -1), qr/\n/, 'encode puts no newline inside the line');

	my $back = $P->can('decode')->($line);
	is($back->{id}, 'abc', 'round trip keeps id');
	is($back->{data}{ip}, '192.0.2.1', 'round trip keeps nested data');
	is(ref($back->{ok}), 'JSON::Tiny::_Bool', 'a JSON boolean decodes as a boolean');
	ok($back->{ok}, 'a true boolean survives the round trip as true');
}

{
	my $huge = 'x' x 70000;
	my $err = _dies(sub { $P->can('encode')->({ id => 'a', ok => \1, data => { note => $huge } }) });
	ok($P->can('is_fault')->($err), 'encode dies with a fault when the line would be oversize');
	is($err->{code}, 'E_INTERNAL', 'an oversize response is an internal fault, not a wire error');
}

{
	my $err = _dies(sub { $P->can('decode')->('x' x 70000) });
	is($err->{code}, 'E_PROTOCOL', 'decode refuses an oversize line');

	$err = _dies(sub { $P->can('decode')->('{"op":') });
	is($err->{code}, 'E_PROTOCOL', 'decode refuses malformed JSON');

	$err = _dies(sub { $P->can('decode')->('') });
	is($err->{code}, 'E_PROTOCOL', 'decode refuses an empty line');

	$err = _dies(sub { $P->can('decode')->("{\"a\":1}\r") });
	is($err->{code}, 'E_PROTOCOL', 'a trailing carriage return is a protocol error, not framing');

	$err = _dies(sub { $P->can('decode')->("\xff\xfe not utf8") });
	is($err->{code}, 'E_PROTOCOL', 'decode refuses a line that is not valid UTF-8');
}

{
	# A real descriptor, because read_message uses sysread: an in-memory
	# filehandle has no file descriptor and would not exercise the same path a
	# socket takes.
	my $fh = _handle(qq({"op":"status","id":"a1"}\n));
	my $message = $P->can('read_message')->($fh);
	is($message->{op}, 'status', 'read_message returns the decoded message');
	close $fh;

	my $eof = _handle('');
	is($P->can('read_message')->($eof), undef, 'read_message returns undef at a clean end of file');
	close $eof;

	my $pipelined = _handle(qq({"op":"status","id":"a1"}\n{"op":"counts","id":"a2"}\n));
	my $err = _dies(sub { $P->can('read_message')->($pipelined) });
	is($err->{code}, 'E_PROTOCOL', 'bytes after the first newline are a protocol error');
	close $pipelined;

	my $big = _handle('y' x 70000);
	$err = _dies(sub { $P->can('read_message')->($big) });
	is($err->{code}, 'E_PROTOCOL', 'read_message refuses a line longer than the cap');
	close $big;

	my $short = _handle('{"op":"status"');
	$err = _dies(sub { $P->can('read_message')->($short) });
	is($err->{code}, 'E_PROTOCOL', 'end of file before a newline is a protocol error');
	close $short;

	my $late = _handle(qq({"op":"status","id":"a1"}\n));
	$err = _dies(sub { $P->can('read_message')->($late, 0) });
	is($err->{code}, 'E_TIMEOUT', 'a deadline already past raises the internal timeout fault');
	close $late;
}

###############################################################################
# 4.1 ip
###############################################################################
my @IP_GOOD = (
	['1.2.3.4',           '1.2.3.4'],
	['192.0.2.0/24',      '192.0.2.0/24'],
	['10.0.0.0/8',        '10.0.0.0/8'],
	['2001:DB8::1',       '2001:db8::1'],
	['2001:db8::/32',     '2001:db8::/32'],
	['0.0.0.0/8',         '0.0.0.0/8'],
);
for my $case (@IP_GOOD) {
	my ($input, $want) = @$case;
	is(scalar($P->can('validate_ip')->($input, mutating => 1)), $want, "ip accepts $input and canonicalises it");
}

my @IP_HOSTILE = (
	['1.2.3.4; rm -rf /',      'shell metacharacters'],
	['$(id)',                  'command substitution'],
	['`id`',                   'backquoted command'],
	["1.2.3.4\nmore",          'newline injection'],
	["1.2.3.4\0",              'NUL byte'],
	['::ffff:127.0.0.1',       'IPv4-mapped IPv6'],
	['::192.0.2.1',            'IPv4-compatible IPv6'],
	['999.1.1.1',              'out of range octet'],
	['10.0.0.0/33',            'prefix past the family width'],
	['1.2.3.04',               'leading zero octet'],
	['0x7f000001',             'hexadecimal address'],
	['192.0.2.10/24',          'host bits set'],
	['1.2.3.4/',               'empty prefix'],
	['1.2.3.4/1/2',            'two slashes'],
	['1.2.3.4/024',            'leading zero prefix'],
	['1.2.3.4/-1',             'negative prefix'],
	['1.2.3.4 ',               'trailing space'],
	[' 1.2.3.4',               'leading space'],
	['',                       'empty string'],
	['x' x 60,                 'over the length cap'],
	['fe80::1%eth0',           'scoped address'],
	[undef,                    'undef'],
	[[],                       'an array'],
	[{},                       'an object'],
);
for my $case (@IP_HOSTILE) {
	my ($input, $why) = @$case;
	is(scalar($P->can('validate_ip')->($input, mutating => 1)), undef, "ip rejects $why");
}

is(scalar($P->can('validate_ip')->('0.0.0.0/0', mutating => 1)), undef, 'ip rejects /0 for a mutating operation');
is(scalar($P->can('validate_ip')->('::/0', mutating => 1)), undef, 'ip rejects ::/0');
is(scalar($P->can('validate_ip')->('0.0.0.0/0')), undef, 'ip rejects /0 by default, which is what grep gets');
is(scalar($P->can('validate_ip')->('0.0.0.0/0', zero_prefix => 1)), '0.0.0.0/0',
	'ip accepts /0 for removal, because an entry that can exist must be removable');
is(scalar($P->can('validate_ip')->('127.0.0.1', mutating => 1)), undef, 'ip rejects loopback for a mutating operation');
is(scalar($P->can('validate_ip')->('127.0.0.0/8', mutating => 1)), undef, 'ip rejects a range covering loopback');
is(scalar($P->can('validate_ip')->('127.0.0.1', zero_prefix => 1)), '127.0.0.1', 'loopback can still be removed');
is(scalar($P->can('validate_ip')->('16.0.0.0/4', mutating => 1)), undef, 'ip rejects a prefix below the IPv4 floor');
is(scalar($P->can('validate_ip')->('2001:db8::/16', mutating => 1)), undef, 'ip rejects a prefix below the IPv6 floor');
is(scalar($P->can('validate_ip')->('16.0.0.0/4', zero_prefix => 1)), '16.0.0.0/4', 'the floor does not apply to removal');

is($P->can('ip_key')->('1.2.3.4/32'), '1.2.3.4', 'a /32 names the same host as a bare address');
is($P->can('ip_key')->('2001:db8::1/128'), '2001:db8::1', 'a /128 names the same host as a bare address');
is($P->can('ip_key')->('192.0.2.0/24'), '192.0.2.0/24', 'a real prefix is left alone');

{
	my ($value, $why) = $P->can('validate_ip')->('192.0.2.10/24');
	like($why, qr/192\.0\.2\.0\/24/, 'the host-bits message names the network the caller probably meant');
}

###############################################################################
# 4.2 ttl
###############################################################################
is(scalar($P->can('validate_ttl')->(3600)), 3600, 'ttl accepts an integer');
is(scalar($P->can('validate_ttl')->('3600')), 3600, 'ttl accepts a digit string from a form body');
is(scalar($P->can('validate_ttl')->(60)), 60, 'ttl accepts the minimum');
is(scalar($P->can('validate_ttl')->(604800)), 604800, 'ttl accepts the maximum');
for my $bad (59, 604801, -1, 0, '1h', '30m', '2d', "\n3600", '1e9', 1.5, undef, '', '3600 ', [1]) {
	my $shown = defined $bad ? (ref($bad) ? 'a reference' : "'$bad'") : 'undef';
	$shown =~ s/\n/\\n/g;
	is(scalar($P->can('validate_ttl')->($bad)), undef, "ttl rejects $shown");
}

###############################################################################
# 4.3 ports
###############################################################################
is(scalar($P->can('validate_ports')->(undef)), '', 'absent ports means every port');
is(scalar($P->can('validate_ports')->('')), '', 'an empty string means every port');
is(scalar($P->can('validate_ports')->('80,443')), '80,443', 'a port list survives');
is(scalar($P->can('validate_ports')->('1-20')), join(',', 1 .. 20), 'a range is expanded, because csf truncates it otherwise');
for my $bad ('80;udp', '*', '22 -d out', '80,', '0', '65536', '08', '1000-2000', '20-10', '80,80',
	join(',', 1 .. 21), '80:443', "80\n443", '-p80', [80]) {
	my $shown = ref($bad) ? 'a reference' : $bad;
	$shown =~ s/\n/\\n/g;
	is(scalar($P->can('validate_ports')->($bad)), undef, "ports rejects '$shown'");
}
{
	my ($value, $why) = $P->can('validate_ports')->('1000-2000');
	like($why, qr/1001 ports, maximum 20/, 'the expansion cap says how many ports the range would be');
}

###############################################################################
# 4.4 note
###############################################################################
is(scalar($P->can('validate_note')->('abuse ticket 4471')), 'abuse ticket 4471', 'a plain note survives');
is(scalar($P->can('validate_note')->('  spaced  ')), 'spaced', 'ASCII spaces are trimmed from both ends');
is(scalar($P->can('validate_note')->('<script>alert(1)</script>')), '<script>alert(1)</script>',
	'a note that looks like HTML is a legal note; escaping is the renderer\'s job');
is(scalar($P->can('validate_note')->('x' x 200)), 'x' x 200, 'a 200 byte note is accepted');
for my $case (
	["x\nInclude /etc/shadow", 'a newline, which would append a line to csf.deny'],
	["x\rInclude /etc/shadow", 'a carriage return'],
	["x\ty",                   'a tab'],
	["x\0y",                   'a NUL byte'],
	["x\x7fy",                 'a delete byte'],
	['-p 22 -d out',           'text csf would read as options'],
	['note -d inout',          'an option after a space'],
	['a|b',                    'a pipe, which corrupts the temp ban record'],
	['x' x 201,                'a note over the byte cap'],
	['   ',                    'only spaces'],
	['',                       'an empty note'],
	[undef,                    'undef'],
	[[],                       'an array'],
) {
	my ($input, $why) = @$case;
	is(scalar($P->can('validate_note')->($input)), undef, "note rejects $why");
}

###############################################################################
# 4.5 which - a table lookup, not a path
###############################################################################
is(scalar($P->can('validate_which')->($_)), $_, "which accepts $_") for qw(deny temp allow);
for my $bad ('ignore', 'DENY', '../../etc/shadow', "deny\0", 'deny ', '', undef, ['deny']) {
	my $shown = defined $bad ? (ref($bad) ? 'a reference' : $bad) : 'undef';
	$shown =~ s/\0/\\0/g;
	is(scalar($P->can('validate_which')->($bad)), undef, "which rejects '$shown'");
}

###############################################################################
# 4.6 offset and limit
###############################################################################
is(scalar($P->can('validate_offset')->(undef)), 0, 'an absent offset is 0');
is(scalar($P->can('validate_offset')->('250')), 250, 'offset accepts a digit string');
is(scalar($P->can('validate_offset')->(1000000)), 1000000, 'offset accepts its ceiling');
is(scalar($P->can('validate_offset')->($_)), undef, "offset rejects '" . (defined $_ ? $_ : 'undef') . "'")
	for (-1, 1000001, '1e9', 1.5, '');
is(scalar($P->can('validate_limit')->(undef)), 100, 'an absent limit is 100');
is(scalar($P->can('validate_limit')->(500)), 500, 'limit accepts its ceiling');
is(scalar($P->can('validate_limit')->($_)), undef, "limit rejects '$_'") for (0, 501, -5, '1e9');

###############################################################################
# 4.7 filter - matched with index(), never compiled
###############################################################################
is(scalar($P->can('validate_filter')->(undef)), '', 'an absent filter is empty');
is(scalar($P->can('validate_filter')->('.*')), '.*', 'a regex metacharacter is accepted as literal text');
is(scalar($P->can('validate_filter')->('(a+)+$')), '(a+)+$', 'a catastrophic pattern is just a string here');
is(scalar($P->can('validate_filter')->('x' x 101)), undef, 'filter rejects over 100 bytes');
is(scalar($P->can('validate_filter')->("a\nb")), undef, 'filter rejects a control byte');

###############################################################################
# 4.8 ids
###############################################################################
my $id = '9f1c' . ('0' x 28);
is_deeply(scalar($P->can('validate_ids')->([$id])), [$id], 'a well-formed id list survives');
is(scalar($P->can('validate_ids')->([uc $id])), undef, 'ids rejects uppercase hex');
is(scalar($P->can('validate_ids')->([$id, $id])), undef, 'ids rejects a duplicate');
is(scalar($P->can('validate_ids')->([1, 2])), undef, 'ids rejects numbers');
is(scalar($P->can('validate_ids')->($id)), undef, 'ids rejects a bare string');
is(scalar($P->can('validate_ids')->([])), undef, 'ids rejects an empty list');
is(scalar($P->can('validate_ids')->([('a' x 32) x 501])), undef, 'ids rejects more than 500 entries');
is(scalar($P->can('validate_ids')->(['../../x'])), undef, 'ids rejects a path');

###############################################################################
# 4.9 user and 4.10 pass
###############################################################################
is(scalar($P->can('validate_user')->('alice')), 'alice', 'a username survives');
for my $bad ('Alice', 'a' x 33, '../../etc/shadow', "root\0", '', 'root@host', undef, ['alice']) {
	my $shown = defined $bad ? (ref($bad) ? 'a reference' : $bad) : 'undef';
	$shown =~ s/\0/\\0/g;
	is(scalar($P->can('validate_user')->($bad)), undef, "user rejects '$shown'");
}
is(scalar($P->can('validate_pass')->('  spaces kept  ')), '  spaces kept  ', 'pass is never trimmed');
is(scalar($P->can('validate_pass')->('x' x 1024)), 'x' x 1024, 'pass accepts 1024 bytes');
is(scalar($P->can('validate_pass')->('x' x 1025)), undef, 'pass rejects 1025 bytes, before any hashing');
is(scalar($P->can('validate_pass')->("a\0b")), undef, 'pass rejects a NUL byte');
is(scalar($P->can('validate_pass')->("a\nb")), undef, 'pass rejects a newline');
{
	my ($value, $why) = $P->can('validate_pass')->("secret\0value");
	unlike($why, qr/secret/, 'a pass failure never quotes the value');
	unlike($why, qr/\b12\b/, 'a pass failure never gives its length away');
}

###############################################################################
# 3.2 id
###############################################################################
is(scalar($P->can('validate_id')->('7b9f1c2e4a5d6e8f')), '7b9f1c2e4a5d6e8f', 'a request id survives');
is(scalar($P->can('validate_id')->('a' x 65)), undef, 'a request id over 64 bytes is rejected');
is(scalar($P->can('validate_id')->('a b')), undef, 'a request id with a space is rejected');
is(scalar($P->can('validate_id')->('')), undef, 'an empty request id is rejected');

###############################################################################
# 3.6 output sanitising
###############################################################################
is($P->can('sanitise')->("a\nb"), 'a b', 'a newline out of a file becomes a space');
is($P->can('sanitise')->("a\tb"), 'a b', 'a tab becomes a space');
is($P->can('sanitise')->("a\x1bb"), 'a.b', 'an escape byte becomes a dot, so no terminal escape survives');
is($P->can('sanitise')->("a\x00b"), 'a.b', 'a NUL becomes a dot');
is($P->can('sanitise')->("a\x7fb"), 'a.b', 'a delete byte becomes a dot');
is($P->can('sanitise')->("a\xffb"), 'a?b', 'an invalid UTF-8 byte becomes a question mark');
is($P->can('sanitise')->("caf\xc3\xa9"), "caf\x{e9}", 'valid UTF-8 is preserved');
is($P->can('sanitise')->('abcdef', 3), 'abc', 'sanitise truncates to a byte count');
is($P->can('sanitise')->(undef), '', 'sanitise turns undef into an empty string');
is($P->can('message_text')->("caf\xc3\xa9 \x1b[31m"), 'caf? .[31m', 'a message is ASCII with no escapes');
is(length($P->can('message_text')->('x' x 900)), 512, 'a message is capped at 512 bytes');
is($P->can('bytelen')->("caf\x{e9}"), 4, 'bytelen counts UTF-8 bytes, not characters');

my @KEEP;

sub _handle {
	my ($data) = @_;
	my $temp = File::Temp->new(UNLINK => 1);
	push @KEEP, $temp;
	binmode($temp);
	print $temp $data;
	$temp->flush;
	open(my $fh, '<', $temp->filename) or die "cannot reopen the temporary file: $!";
	binmode($fh);
	return $fh;
}

sub _dies {
	my ($code) = @_;
	eval { $code->() };
	return $@;
}
