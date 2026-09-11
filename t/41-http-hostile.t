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
# The point of Task 5, not a formality: this is task-5-brief.md's own
# hostile-input table, one block per row, feeding ConfigServer::UI::HTTP
# from in-memory-backed real filehandles and socketpairs so no test here
# needs a network. Every row must:
#
#   * produce a 4xx (never a 2xx/3xx, never a 5xx that would suggest this
#     module crashed rather than refused);
#   * never hang - every case either fails fast (bounded elapsed time
#     asserted directly) or is deliberately a timeout case, in which case
#     the SHORT timeout given to it is what bounds it, never the real 15s
#     default;
#   * never die any way other than the controlled ConfigServer::UI::HTTP
#     fault() every other test in this tree already relies on - an
#     unrecognisable die would mean this module crashed instead of
#     refusing;
#   * never allocate a buffer sized by a number the peer chose (Content-
#     Length) before that number has been checked against the cap.
#
# A handful of rows are also driven through
# ConfigServer::UI::Server->handle_connection() with a fake App, proving
# the FULL pipeline - not only read_request() in isolation - turns hostile
# input into a written HTTP response and returns, never hangs and never
# lets a die escape to whatever called it (which in production is a forked
# child of Server.pm's own accept loop).
###############################################################################
use strict;
use warnings;

use FindBin ();
use lib "$FindBin::Bin/..", "$FindBin::Bin/../ui-src/lib";

use File::Temp ();
use Socket ();
use Time::HiRes ();
use Test::More tests => 320;

require_ok('ConfigServer::UI::HTTP');
require_ok('ConfigServer::UI::Server');
my $H = 'ConfigServer::UI::HTTP';
my $S = 'ConfigServer::UI::Server';

###############################################################################
# Helpers
###############################################################################
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

sub _pair {
	socketpair(my $near, my $far, Socket::AF_UNIX(), Socket::SOCK_STREAM(), Socket::PF_UNSPEC())
		or die "socketpair: $!";
	return ($near, $far);
}

# Runs read_request() and asserts, in ONE call, everything every row in
# this file must prove: it dies (never returns a request, never hangs
# forever), the death is a recognisable fault (never an uncaught crash),
# the fault's HTTP status is a 4xx, and it does not take unreasonably long.
# $max_seconds defaults to 2 - generous for anything that should fail
# immediately, far below the real 15s default, and a real bound rather than
# none for the handful of callers that pass a short deadline on purpose.
sub _hostile {
	my ($label, $fh, %opt) = @_;
	my $max_seconds = delete $opt{max_seconds} || 2;

	my $t0 = Time::HiRes::time();
	my $req = eval { $H->can('read_request')->($fh, %opt) };
	my $err = $@;
	my $elapsed = Time::HiRes::time() - $t0;

	ok($err, "$label: read_request does not return a request");
	ok($H->can('is_fault')->($err), "$label: the failure is a recognised fault, not an uncaught crash")
		or diag("got instead: " . (ref($err) ? ref($err) : (defined $err ? $err : 'undef')));
	if ($H->can('is_fault')->($err)) {
		ok($err->{status} >= 400 && $err->{status} < 500, "$label: the status (" . $err->{status} . ") is a 4xx")
	}
	else {
		fail("$label: the status is a 4xx");
	}
	cmp_ok($elapsed, '<', $max_seconds, "$label: it did not hang ($elapsed vs ${max_seconds}s)");
	return $err;
}

###############################################################################
# GET and POST only
###############################################################################
for my $method (qw(PUT DELETE HEAD OPTIONS PATCH CONNECT TRACE get)) {
	my $fh = _handle("$method / HTTP/1.1\r\nHost: x\r\n\r\n");
	my $err = _hostile("method $method", $fh);
	is($err->{status}, 405, "method $method: specifically 405, not merely some 4xx");
}

{
	# "without reading a body": an absurd Content-Length with NO body bytes
	# ever sent, and a short body_timeout that would be blown through if
	# this module tried to read the (nonexistent) body before checking the
	# method - it must refuse from the request line alone.
	my ($near, $far) = _pair();
	syswrite($far, "DELETE / HTTP/1.1\r\nContent-Length: 999999999\r\n\r\n");
	my $err = _hostile('bad method with a huge declared body and none sent',
		$near, body_timeout => 0.2, max_seconds => 1);
	is($err->{status}, 405, 'and it is the method that is refused, not a body-related status');
	close $near; close $far;
}

###############################################################################
# Oversize request line
###############################################################################
{
	no warnings 'once'; # one of two references to this package variable in this file
	my $fh = _handle('GET /' . ('a' x ($ConfigServer::UI::HTTP::MAX_REQUEST_LINE + 100)) . " HTTP/1.1\r\n\r\n");
	my $err = _hostile('oversize request line', $fh);
	is($err->{status}, 414, 'oversize request line: specifically 414');
}

###############################################################################
# R34 (task-5-review.md M5): the regression test the brief's own comment
# (HTTP.pm:80-82) invites - lower $MAX_REQUEST_LINE and prove the cap still
# bites. This is deliberately NOT the same shape as "oversize request line"
# above: that case is 8192+100 bytes against the real 8192-byte cap, so it
# is too big to ever arrive in a single sysread() and never exercises
# _await_first_byte()'s own read size at all (task-5-review.md notes this
# gap by name). Here the cap is lowered well below the line's actual
# length, but the whole line - terminator included - is still small enough
# to arrive in ONE read (it comes from a temp file, which is always
# "entirely available" the moment it is opened). Before this bug was
# fixed, _await_first_byte()'s first read was a flat 8192 regardless of the
# cap, so the terminator would already be sitting in the buffer by the
# time _read_line() got its first chance to check the buffer's length -
# and a line found complete is returned complete, cap or no cap.
###############################################################################
{
	no warnings 'once'; # the other reference to this package variable in this file
	local $ConfigServer::UI::HTTP::MAX_REQUEST_LINE = 20;
	my $fh = _handle('GET /' . ('a' x 80) . " HTTP/1.1\r\n\r\n"); # ~100 bytes, one whole read
	my $err = _hostile('R34: a request line over a (lowered) cap, arriving whole in a single read', $fh);
	is($err->{status}, 414, 'R34: still refused as too-long - the first read must itself respect the cap');
}

###############################################################################
# 200 headers
###############################################################################
{
	my $data = "GET / HTTP/1.1\r\n";
	$data .= "X-H$_: v\r\n" for (1 .. 200);
	$data .= "\r\n";
	my $fh = _handle($data);
	my $err = _hostile('200 headers', $fh);
	is($err->{status}, 431, '200 headers: specifically 431');
	like($err->{message}, qr/more than \d+ headers were sent/, '200 headers: the header-count guard, distinct from the header-line-length guard below');
}

###############################################################################
# Header with no colon
###############################################################################
{
	my $fh = _handle("GET / HTTP/1.1\r\nThisHasNoColon\r\n\r\n");
	my $err = _hostile('header with no colon', $fh);
	is($err->{status}, 400, 'header with no colon: specifically 400');
	like($err->{message}, qr/no colon/, 'header with no colon: the no-colon guard specifically, not some other 400');
}

###############################################################################
# Duplicate Content-Length / duplicate Host - request smuggling, per the
# brief's own words, not pedantry
###############################################################################
{
	my $fh = _handle("POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nabcde");
	my $err = _hostile('duplicate Content-Length', $fh);
	is($err->{status}, 400, 'duplicate Content-Length: specifically 400');
	like($err->{message}, qr/duplicate content-length header/, 'duplicate Content-Length: the duplicate-header guard specifically');
}
{
	my $fh = _handle("GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n");
	my $err = _hostile('duplicate Host', $fh);
	is($err->{status}, 400, 'duplicate Host: specifically 400');
	like($err->{message}, qr/duplicate host header/, 'duplicate Host: the duplicate-header guard specifically');
}

###############################################################################
# Transfer-Encoding - refused for its mere presence, not only for "chunked"
###############################################################################
{
	my $fh = _handle("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n");
	my $err = _hostile('Transfer-Encoding: chunked', $fh);
	is($err->{status}, 400, 'Transfer-Encoding: chunked: specifically 400');
	like($err->{message}, qr/Transfer-Encoding is not supported/, 'Transfer-Encoding: chunked: the Transfer-Encoding guard specifically');
}
{
	my $fh = _handle("POST / HTTP/1.1\r\nTransfer-Encoding: identity\r\nContent-Length: 0\r\n\r\n");
	my $err = _hostile('Transfer-Encoding: identity (any value, not only "chunked")', $fh);
	is($err->{status}, 400, 'Transfer-Encoding: identity: specifically 400');
	like($err->{message}, qr/Transfer-Encoding is not supported/, 'Transfer-Encoding: identity: the same presence guard, not a value check');
}

###############################################################################
# Content-Length larger than the body - closed early, and left dangling
###############################################################################
{
	my $fh = _handle("POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\nabc");
	my $err = _hostile('Content-Length larger than the body (EOF)', $fh);
	is($err->{status}, 400, 'Content-Length > body, closed early: 400');
	like($err->{message}, qr/closed before the declared request body/, 'Content-Length > body (EOF): the body-EOF guard specifically');
}
{
	my ($near, $far) = _pair();
	syswrite($far, "POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\nabc");
	# The connection is left open on purpose - the peer sent less than it
	# promised and then went idle, rather than closing. This is the
	# deadline path, not the EOF path, so max_seconds must be bigger than
	# the short body_timeout given, never the other way round.
	my $err = _hostile('Content-Length larger than the body (idle, never closes)',
		$near, body_timeout => 0.3, max_seconds => 1.5);
	is($err->{status}, 408, 'and it is a request timeout, not a 400, once the deadline (not EOF) is what ends it');
	ok($err->{silent}, 'a deadline with nothing useful to say back is marked silent - dropped, not answered');
	close $near; close $far;
}

###############################################################################
# %zz and %0 - percent-decoding rejects rather than guesses
###############################################################################
{
	my $fh = _handle("GET /api/list?x=%zz HTTP/1.1\r\n\r\n");
	my $err = _hostile('%zz in a query value', $fh);
	is($err->{status}, 400, '%zz: specifically 400');
	like($err->{message}, qr/percent sign not followed by two hex digits/, '%zz in a query value: the hex-validity guard, by way of the query-parameter wrapper');
}
{
	my $fh = _handle("GET /%zzpath HTTP/1.1\r\n\r\n");
	my $err = _hostile('%zz in the path', $fh);
	is($err->{status}, 400, '%zz in the path: specifically 400');
	like($err->{message}, qr/percent sign not followed by two hex digits/, '%zz in the path: the hex-validity guard, by way of the path wrapper');
}
{
	my $fh = _handle("GET /api/list?x=%0 HTTP/1.1\r\n\r\n");
	my $err = _hostile('%0 (an incomplete escape) in a query value', $fh);
	is($err->{status}, 400, '%0: specifically 400');
	like($err->{message}, qr/percent sign not followed by two hex digits/, '%0 in a query value: still the hex-validity guard (too short to be two digits)');
}
{
	my $fh = _handle("GET /a%0 HTTP/1.1\r\n\r\n");
	my $err = _hostile('%0 in the path', $fh);
	is($err->{status}, 400, '%0 in the path: specifically 400');
	like($err->{message}, qr/percent sign not followed by two hex digits/, '%0 in the path: still the hex-validity guard');
}

###############################################################################
# %00 - a syntactically VALID escape that is still refused, in a path and
# in every position a query parameter can carry it
###############################################################################
{
	my $fh = _handle("GET /api/%00list HTTP/1.1\r\n\r\n");
	my $err = _hostile('%00 in the path', $fh);
	is($err->{status}, 400, '%00 in the path: specifically 400');
	like($err->{message}, qr/decodes to a NUL byte/, '%00 in the path: the decoded-NUL guard, distinct from the hex-validity guard above');
}
{
	my $fh = _handle("GET /api/list?x=%00 HTTP/1.1\r\n\r\n");
	my $err = _hostile('%00 in a query value', $fh);
	is($err->{status}, 400, '%00 in a query value: specifically 400');
	like($err->{message}, qr/decodes to a NUL byte/, '%00 in a query value: the decoded-NUL guard');
}
{
	my $fh = _handle("GET /api/list?%00=x HTTP/1.1\r\n\r\n");
	my $err = _hostile('%00 in a query key', $fh);
	is($err->{status}, 400, '%00 in a query key: specifically 400');
	like($err->{message}, qr/decodes to a NUL byte/, '%00 in a query key: the decoded-NUL guard, applied to keys too');
}

###############################################################################
# %4z - task-5-review.md I4: %zz and %0 are both refused, but NOT because of
# the hex-validity guard as the two blocks above imply. hex('zz') and
# hex('') both evaluate to 0 in Perl (hex() stops at the first non-hex
# character rather than failing), so with the hex-validity guard alone
# deleted, both %zz and %0 still decode to chr(0) and are caught by the
# NUL-byte guard instead - a different guard entirely. %4z is the one input
# that tells the two guards apart: '4z' still fails the two-hex-digit
# regex (so it is refused here, with the guard present), but if the
# hex-validity guard were the one missing, hex('4z') is 4 - not 0 - so it
# would decode to byte 0x04 and pass with NO fault at all. The previous
# implementer verified this by hand (task-5-report.md) and never added it;
# added here as the actual regression test for the hex-validity guard.
###############################################################################
{
	my $fh = _handle("GET /api/list?x=%4z HTTP/1.1\r\n\r\n");
	my $err = _hostile('%4z in a query value (isolates the hex-validity guard from the NUL guard)', $fh);
	is($err->{status}, 400, '%4z: specifically 400');
	like($err->{message}, qr/percent sign not followed by two hex digits/,
		'%4z: the hex-validity guard by name - %zz/%0 above cannot prove this, only that SOME guard fired');
}
{
	my $fh = _handle("GET /a%4zpath HTTP/1.1\r\n\r\n");
	my $err = _hostile('%4z in the path (isolates the hex-validity guard from the NUL guard)', $fh);
	is($err->{status}, 400, '%4z in the path: specifically 400');
	like($err->{message}, qr/percent sign not followed by two hex digits/,
		'%4z in the path: the hex-validity guard by name');
}

###############################################################################
# Unsupported HTTP version
###############################################################################
{
	my $fh = _handle("GET / HTTP/2.0\r\n\r\n");
	my $err = _hostile('HTTP/2.0', $fh);
	is($err->{status}, 400, 'HTTP/2.0: specifically 400');
	like($err->{message}, qr/unsupported HTTP version/, 'HTTP/2.0: the version-allowlist guard specifically');
}
{
	my $fh = _handle("GET / HTTP/0.9\r\n\r\n");
	my $err = _hostile('HTTP/0.9', $fh);
	is($err->{status}, 400, 'HTTP/0.9: specifically 400');
	like($err->{message}, qr/unsupported HTTP version/, 'HTTP/0.9: the version-allowlist guard specifically');
}
{
	my $fh = _handle("GET / GARBAGE\r\n\r\n");
	my $err = _hostile('a version field that is not HTTP/x.y at all', $fh);
	is($err->{status}, 400, 'garbage version: specifically 400');
	like($err->{message}, qr/unsupported HTTP version/, 'garbage version: the version-allowlist guard, not a request-line-shape failure');
}

###############################################################################
# One header line over the per-line cap - distinct from "too many headers":
# this is a single line too long to ever complete.
###############################################################################
{
	no warnings 'once'; # the only reference to this package variable in this file
	my $fh = _handle("GET / HTTP/1.1\r\nX-Big: "
		. ('v' x ($ConfigServer::UI::HTTP::MAX_HEADER_BYTES + 100)) . "\r\n\r\n");
	my $err = _hostile('one header line over the per-line cap', $fh);
	is($err->{status}, 431, 'oversize header line: specifically 431, the same status as too many headers');
	like($err->{message}, qr/header line is longer than this server accepts/, 'oversize header line: the header-line-length guard specifically, not the count guard above');
}

###############################################################################
# A Content-Length that is not a whole number - not merely too large
###############################################################################
{
	my $fh = _handle("POST / HTTP/1.1\r\nContent-Length: abc\r\n\r\n");
	my $err = _hostile('Content-Length: abc', $fh);
	is($err->{status}, 400, 'non-numeric Content-Length: specifically 400');
	like($err->{message}, qr/Content-Length must be a whole number/, 'Content-Length: abc: the numeric-format guard specifically');
}
{
	my $fh = _handle("POST / HTTP/1.1\r\nContent-Length: -5\r\n\r\n");
	my $err = _hostile('Content-Length: -5', $fh);
	is($err->{status}, 400, 'negative Content-Length: specifically 400');
	like($err->{message}, qr/Content-Length must be a whole number/, 'Content-Length: -5: the same numeric-format guard, not a range check');
}
{
	my $fh = _handle("POST / HTTP/1.1\r\nContent-Length: 5 6\r\n\r\n");
	my $err = _hostile('Content-Length: "5 6" (whitespace inside the number)', $fh);
	is($err->{status}, 400, 'Content-Length with embedded whitespace: specifically 400');
	like($err->{message}, qr/Content-Length must be a whole number/, 'Content-Length: "5 6": the same numeric-format guard catches embedded whitespace too');
}

###############################################################################
# A raw NUL byte, not percent-encoded at all
###############################################################################
{
	my $fh = _handle("GET /a\0b HTTP/1.1\r\n\r\n");
	my $err = _hostile('a raw NUL byte in the request line', $fh);
	is($err->{status}, 400, 'raw NUL in the request line: specifically 400');
	like($err->{message}, qr/NUL byte/, 'raw NUL in the request line: the NUL-byte line guard specifically');
}
{
	my $fh = _handle("GET / HTTP/1.1\r\nX-Thing: a\0b\r\n\r\n");
	my $err = _hostile('a raw NUL byte in a header value', $fh);
	is($err->{status}, 400, 'raw NUL in a header: specifically 400');
	like($err->{message}, qr/NUL byte/, 'raw NUL in a header: the same NUL-byte line guard, applied to a header line');
}

###############################################################################
# CR without LF - a lone carriage return that is not part of a CRLF ending
###############################################################################
{
	my $fh = _handle("GET / HTTP/1.1\r\nX-Thing: a\rb\r\n\r\n");
	my $err = _hostile('CR without LF, embedded in a header value', $fh);
	is($err->{status}, 400, 'embedded CR: specifically 400');
	like($err->{message}, qr/carriage return that is not part of a CRLF/, 'embedded CR in a header value: the embedded-CR guard specifically');
}
{
	my $fh = _handle("GET /a\rb HTTP/1.1\r\n\r\n");
	my $err = _hostile('CR without LF, embedded in the request line', $fh);
	is($err->{status}, 400, 'embedded CR in the request line: specifically 400');
	like($err->{message}, qr/carriage return that is not part of a CRLF/, 'embedded CR in the request line: the same embedded-CR guard');
}

###############################################################################
# LF without CR - a bare LF line ending, never tolerated as CRLF's cousin
###############################################################################
{
	my $fh = _handle("GET / HTTP/1.1\n\n");
	my $err = _hostile('LF without CR ending the request line', $fh);
	is($err->{status}, 400, 'bare-LF request line: specifically 400');
	like($err->{message}, qr/bare LF, not CRLF/, 'bare-LF request line: the CRLF-terminator guard - though the downstream request-line regex would also refuse it (task-5-review.md notes this one is not fully isolated)');
}
{
	my $fh = _handle("GET / HTTP/1.1\r\nX-Thing: v\n\r\n");
	my $err = _hostile('LF without CR ending a header line', $fh);
	is($err->{status}, 400, 'bare-LF header line: specifically 400');
	like($err->{message}, qr/bare LF, not CRLF/, 'bare-LF header line: the CRLF-terminator guard - the row that actually isolates it (task-5-review.md)');
}

###############################################################################
# Absolute-form URI, and the other non-origin-form request targets
###############################################################################
{
	my $fh = _handle("GET http://evil.example/x HTTP/1.1\r\n\r\n");
	my $err = _hostile('absolute-form URI', $fh);
	is($err->{status}, 400, 'absolute-form URI: specifically 400');
	like($err->{message}, qr/origin-form request target/, 'absolute-form URI: the origin-form-only guard specifically');
}
{
	my $fh = _handle("GET example.com:80 HTTP/1.1\r\n\r\n");
	my $err = _hostile('authority-form target', $fh);
	is($err->{status}, 400, 'authority-form target: specifically 400');
	like($err->{message}, qr/origin-form request target/, 'authority-form target: the same origin-form-only guard');
}
{
	my $fh = _handle("POST * HTTP/1.1\r\nContent-Length: 0\r\n\r\n");
	my $err = _hostile('asterisk-form target', $fh);
	is($err->{status}, 400, 'asterisk-form target: specifically 400');
	like($err->{message}, qr/origin-form request target/, 'asterisk-form target: the same origin-form-only guard');
}

###############################################################################
# ..%2f..%2f traversal - docs/WEBUI-RPC.md section 14.1 is explicit that
# this tier is NOT required to reject or canonicalise it: routing is exact
# string match, so this decodes normally and the 404 comes from the route
# table, one layer up. Proven two ways: the decode itself is correct and
# raises no fault here, and the full pipeline (this module plus a fake App
# that behaves like the real router) answers 4xx for it end to end.
###############################################################################
{
	my $fh = _handle("GET /..%2f..%2fetc%2fpasswd HTTP/1.1\r\n\r\n");
	my $req = eval { $H->can('read_request')->($fh) };
	is($@, '', 'a %2f-encoded traversal path raises no fault in this tier');
	is($req->{path}, '/../../etc/passwd', 'it decodes to the literal path - canonicalising it is not this tier\'s job');
}

###############################################################################
# A 70000-byte body - over the cap, refused before it is read, not merely
# because it eventually proves too big
###############################################################################
{
	my $body = 'x' x 70000;
	my $fh = _handle("POST / HTTP/1.1\r\n" . 'Content-Length: ' . length($body) . "\r\n\r\n$body");
	my $err = _hostile('a 70000-byte body', $fh, max_seconds => 1);
	is($err->{status}, 413, '70000-byte body: specifically 413');
}
{
	# The declared length alone is enough to refuse, before a single body
	# byte is read - proven by never sending the body at all and bounding
	# the elapsed time tightly: a buggy implementation that read up to the
	# declared length before checking it would either hang on this (no body
	# was sent) or, worse, allocate a buffer sized by whatever the peer
	# claims, however large that claim is.
	my ($near, $far) = _pair();
	syswrite($far, "POST / HTTP/1.1\r\nContent-Length: 70000\r\n\r\n");
	my $err = _hostile('Content-Length: 70000 declared, nothing sent', $near, max_seconds => 1);
	is($err->{status}, 413, 'refused from the header alone, before any body byte was awaited');
	close $near; close $far;
}
{
	# Something far larger than the cap, to make the point that this is a
	# refusal on the declared number, not a coincidence of 70000 landing
	# just over 65536.
	my ($near, $far) = _pair();
	syswrite($far, "POST / HTTP/1.1\r\nContent-Length: 999999999\r\n\r\n");
	my $err = _hostile('Content-Length: 999999999 declared, nothing sent', $near, max_seconds => 1);
	is($err->{status}, 413, 'a nine-digit declared length is refused just as fast as 70000');
	close $near; close $far;
}

###############################################################################
# Content-Length required for POST (not in the brief's own table, but
# stated alongside it: "Content-Length required for POST and must match")
###############################################################################
{
	my $fh = _handle("POST /api/deny HTTP/1.1\r\n\r\n");
	my $err = _hostile('POST with no Content-Length at all', $fh);
	is($err->{status}, 411, 'missing Content-Length on POST: specifically 411');
}

###############################################################################
# Body content type must be application/x-www-form-urlencoded - no
# multipart, no JSON, nothing else, when a body is actually sent
###############################################################################
{
	my $body = '{"ip":"192.0.2.1"}';
	my $fh = _handle("POST / HTTP/1.1\r\nContent-Type: application/json\r\n"
		. 'Content-Length: ' . length($body) . "\r\n\r\n$body");
	my $err = _hostile('a JSON content-type', $fh);
	is($err->{status}, 415, 'application/json body: specifically 415');
}
{
	my $body = "--x\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--x--\r\n";
	my $fh = _handle("POST / HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=x\r\n"
		. 'Content-Length: ' . length($body) . "\r\n\r\n$body");
	my $err = _hostile('a multipart content-type', $fh);
	is($err->{status}, 415, 'multipart/form-data body: specifically 415');
}

###############################################################################
# Full pipeline: ConfigServer::UI::Server->handle_connection() over hostile
# input, proving Server.pm's own wiring (not only HTTP.pm in isolation)
# turns each of these into a written HTTP response and returns cleanly -
# the shape a forked child of the real accept loop actually needs.
###############################################################################
{
	package NotFoundApp;
	sub new { return bless {}, shift }
	sub dispatch {
		my ($self, $req) = @_;
		return { status => 404, headers => [ ['Content-Type', 'application/json'] ],
			body => '{"ok":false,"error":"WEB_NOT_FOUND"}' };
	}
}

my @PIPELINE_CASES = (
	['oversize request line',       "GET /" . ('a' x 9000) . " HTTP/1.1\r\n\r\n", {}],
	['bad method',                  "DELETE / HTTP/1.1\r\nHost: x\r\n\r\n", {}],
	['duplicate Content-Length',    "POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nabcde", {}],
	['chunked Transfer-Encoding',   "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n", {}],
	['%00 in the path',             "GET /a%00b HTTP/1.1\r\n\r\n", {}],
	['a 70000-byte body',           "POST / HTTP/1.1\r\nContent-Length: 70000\r\n\r\n" . ('x' x 70000), {}],
);

for my $case (@PIPELINE_CASES) {
	my ($label, $data, $opt) = @$case;
	my ($near, $far) = _pair();
	syswrite($far, $data);
	my $server = $S->new(app => NotFoundApp->new, header_timeout => 2, body_timeout => 2);

	my $t0 = Time::HiRes::time();
	my $died = 0;
	eval { $server->handle_connection($near, '203.0.113.9'); 1 } or $died = 1;
	my $elapsed = Time::HiRes::time() - $t0;
	close $near;

	ok(!$died, "pipeline/$label: handle_connection does not let a die escape");
	cmp_ok($elapsed, '<', 2, "pipeline/$label: and does not hang");

	local $/;
	my $out = <$far>;
	close $far;
	ok(defined($out) && length($out), "pipeline/$label: a response was written to the wire");
	if (defined $out) {
		like($out, qr{\AHTTP/1\.1 4\d\d}, "pipeline/$label: it is a 4xx response");
		like($out, qr{Connection: close\r\n}, "pipeline/$label: and still carries Connection: close");
	}
}

{
	# The traversal case through the full pipeline: HTTP.pm decodes it
	# without complaint, and the 404 comes from the (fake, here) router -
	# proving end to end that "every one must produce a 4xx" holds even for
	# the one row this tier is explicitly not the layer that rejects.
	my ($near, $far) = _pair();
	syswrite($far, "GET /..%2f..%2fetc%2fpasswd HTTP/1.1\r\n\r\n");
	my $server = $S->new(app => NotFoundApp->new, header_timeout => 2, body_timeout => 2);
	$server->handle_connection($near, '203.0.113.9');
	close $near;
	local $/;
	my $out = <$far>;
	close $far;
	like($out, qr{\AHTTP/1\.1 404}, 'pipeline/traversal: the router\'s 404 is what makes this row a 4xx, not this tier');
}

{
	# The idle-stall timeout case through the full pipeline: proves
	# Server.pm's own integration does not reintroduce a hang that
	# read_request() alone does not have, and that a silent fault really
	# does mean "no response, just close" rather than "no response, ever".
	my ($near, $far) = _pair();
	syswrite($far, "POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\nabc");
	my $server = $S->new(app => NotFoundApp->new, header_timeout => 2, body_timeout => 0.3);

	my $t0 = Time::HiRes::time();
	$server->handle_connection($near, '203.0.113.9');
	my $elapsed = Time::HiRes::time() - $t0;
	close $near;

	cmp_ok($elapsed, '<', 1.5, 'pipeline/idle body stall: bounded by the short deadline given, not the 15s default');

	local $/;
	my $out = <$far>;
	close $far;
	ok(!defined($out) || $out eq '', 'pipeline/idle body stall: nothing is written - a silent fault means silence, end to end');
}

print "# KEEP: " . scalar(@KEEP) . " temp files held open for the duration of this run\n";
