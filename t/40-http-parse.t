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
# ConfigServer::UI::HTTP's structural correctness on well-formed input - the
# request structure docs/WEBUI-RPC.md section 14.1 defines comes out shaped
# exactly right (method, decoded path, decoded query, lowercased headers,
# raw body bytes), write_response() puts docs/WEBUI-RPC.md section 14.3's
# response structure on the wire correctly, and ConfigServer::UI::Server's
# ui.conf reader, allowlist matcher and per-connection wiring all behave on
# the configurations and peers they are supposed to accept.
#
# The HOSTILE half of this task - the brief's own table, and the point of
# Task 5 - is t/41-http-hostile.t. This file is the "and it still parses a
# normal request correctly" half that table would not catch on its own.
###############################################################################
use strict;
use warnings;

use FindBin ();
use lib "$FindBin::Bin/..", "$FindBin::Bin/../ui-src/lib";

use File::Temp qw(tempdir);
use Socket ();
use Time::HiRes ();
use Test::More tests => 130;

require_ok('ConfigServer::UI::HTTP');
require_ok('ConfigServer::UI::Server');
my $H = 'ConfigServer::UI::HTTP';
my $S = 'ConfigServer::UI::Server';

###############################################################################
# Helpers
###############################################################################

# A real descriptor, because read_request() uses sysread()/select() - an
# in-memory filehandle has no file descriptor and would not exercise the
# same path a socket takes (the same reasoning t/10-proto.t already
# documents for ConfigServer::UI::Proto::read_message).
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

# A connected pair for tests that need to write from "the other end" -
# syswrite(), never print(): Perl's buffered print() on the write half can
# sit in userspace and never reach the read half at all, which looks
# indistinguishable from "the client sent nothing" and would make a timeout
# test pass for the wrong reason.
sub _pair {
	socketpair(my $near, my $far, Socket::AF_UNIX(), Socket::SOCK_STREAM(), Socket::PF_UNSPEC())
		or die "socketpair: $!";
	return ($near, $far);
}

sub _dies { my ($code) = @_; eval { $code->() }; return $@; }

###############################################################################
# Happy path: GET with a query string
###############################################################################
{
	my $fh = _handle("GET /api/list?which=deny&note=hi%20there&x=a%2Bb HTTP/1.1\r\n"
		. "Host: example.com\r\nCookie: sid=abc123\r\nX-CSRF-Token: tok\r\n\r\n");
	my $req = $H->can('read_request')->($fh);
	is($req->{method}, 'GET', 'method is GET');
	is($req->{path}, '/api/list', 'path has no query string');
	is($req->{query}{which}, 'deny', 'a plain query value decodes');
	is($req->{query}{note}, 'hi there', '%20 and the query convention both decode to a space');
	is($req->{query}{x}, 'a+b', '%2B decodes to a literal plus, not a second space');
	ok(!utf8::is_utf8($req->{query}{note}), 'a decoded query value carries no UTF-8 flag (section 14.2)');
	is($req->{headers}{host}, 'example.com', 'Host header is present and lowercased by name');
	is($req->{headers}{cookie}, 'sid=abc123', 'Cookie header value is preserved');
	is($req->{headers}{'x-csrf-token'}, 'tok', 'a hyphenated header name lowercases correctly');
	is($req->{body}, undef, 'a GET with no body decodes to an undef body');
}

###############################################################################
# Happy path: path decoding does not treat '+' as a space
###############################################################################
{
	my $fh = _handle("GET /a+b/c%2Fd HTTP/1.1\r\n\r\n");
	my $req = $H->can('read_request')->($fh);
	is($req->{path}, '/a+b/c/d', "'+' in the path is literal, and %2F decodes normally there");
}

###############################################################################
# Happy path: no query string at all
###############################################################################
{
	my $fh = _handle("GET /api/status HTTP/1.1\r\n\r\n");
	my $req = $H->can('read_request')->($fh);
	is($req->{path}, '/api/status', 'a bare path with no "?" parses');
	is_deeply($req->{query}, {}, 'query is an empty hashref, not undef, when there is none');
}

###############################################################################
# Happy path: POST with a form body
###############################################################################
{
	my $body = 'ip=192.0.2.1&note=hello+world';
	my $fh = _handle("POST /api/deny HTTP/1.1\r\nHost: x\r\n"
		. "Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n"
		. 'Content-Length: ' . length($body) . "\r\n\r\n$body");
	my $req = $H->can('read_request')->($fh);
	is($req->{method}, 'POST', 'method is POST');
	is($req->{body}, $body, 'the body is handed back raw, not parsed - that is ui-src/bin/csf-ui\'s job');
	ok(!utf8::is_utf8($req->{body}), 'the raw body carries no UTF-8 flag either');
}

###############################################################################
# Happy path: a Content-Type with no charset parameter, and no Content-Type
# at all, are both accepted for a form body (docs/WEBUI-RPC.md section 14.2:
# "no content-type at all" is the shape a plain <form> without enctype= uses)
###############################################################################
{
	my $body = 'a=1';
	my $fh = _handle("POST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n"
		. 'Content-Length: ' . length($body) . "\r\n\r\n$body");
	my $req = $H->can('read_request')->($fh);
	is($req->{body}, $body, 'a bare application/x-www-form-urlencoded content-type is accepted');
}
{
	my $body = 'a=1';
	my $fh = _handle("POST / HTTP/1.1\r\n" . 'Content-Length: ' . length($body) . "\r\n\r\n$body");
	my $req = $H->can('read_request')->($fh);
	is($req->{body}, $body, 'no Content-Type header at all is accepted for POST (defaults to form-encoded)');
}

###############################################################################
# Happy path: HTTP/1.0 is accepted too
###############################################################################
{
	my $fh = _handle("GET / HTTP/1.0\r\n\r\n");
	my $req = $H->can('read_request')->($fh);
	is($req->{path}, '/', 'HTTP/1.0 is accepted');
}

###############################################################################
# Happy path: a repeated, non-critical header folds last-wins
# (docs/WEBUI-RPC.md section 14.1 leaves the fold to the producer's choice)
###############################################################################
{
	my $fh = _handle("GET / HTTP/1.1\r\nX-Thing: first\r\nX-Thing: second\r\n\r\n");
	my $req = $H->can('read_request')->($fh);
	is($req->{headers}{'x-thing'}, 'second', 'a repeated ordinary header keeps the last value');
}

###############################################################################
# Happy path: exactly at the boundary of every limit still succeeds -
# proves each cap in t/41 rejects for being OVER the limit, not merely for
# being large.
###############################################################################
{
	# Exactly $H::MAX_HEADERS headers, no more.
	my $data = "GET / HTTP/1.1\r\n";
	$data .= "X-H$_: v\r\n" for (1 .. $ConfigServer::UI::HTTP::MAX_HEADERS);
	$data .= "\r\n";
	my $fh = _handle($data);
	my $req = eval { $H->can('read_request')->($fh) };
	ok(!$@, "exactly $ConfigServer::UI::HTTP::MAX_HEADERS headers is accepted") or diag("died: $@");
	is($req->{headers}{'x-h1'}, 'v', 'and they are all readable') if $req;
}
{
	# Exactly $MAX_BODY_BYTES body bytes, no more.
	my $body = 'x' x $ConfigServer::UI::HTTP::MAX_BODY_BYTES;
	my $fh = _handle("POST / HTTP/1.1\r\n" . 'Content-Length: ' . length($body) . "\r\n\r\n$body");
	my $req = eval { $H->can('read_request')->($fh) };
	ok(!$@, 'a body of exactly MAX_BODY_BYTES is accepted') or diag("died: $@");
	is(length($req->{body}), $ConfigServer::UI::HTTP::MAX_BODY_BYTES, 'and every byte of it arrives')
		if $req;
}

###############################################################################
# Content-Length: 0 is a bodyless request, not an error
###############################################################################
{
	my $fh = _handle("POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n");
	my $req = $H->can('read_request')->($fh);
	ok(!defined($req->{body}) || $req->{body} eq '', 'Content-Length: 0 yields an undef or empty body');
}

###############################################################################
# A clean, empty connection - the peer opened and closed without sending a
# byte - is not an error: read_request() returns undef, and the caller
# (ConfigServer::UI::Server) closes in silence rather than writing anything.
###############################################################################
{
	my ($near, $far) = _pair();
	close $far;
	my $req = eval { $H->can('read_request')->($near) };
	is($@, '', 'no fault is raised for a connection that sent nothing at all');
	is($req, undef, 'read_request returns undef for it');
	close $near;
}

###############################################################################
# fault()/is_fault()
###############################################################################
{
	my $err = _dies(sub { $H->can('fault')->(400, 'because') });
	ok($H->can('is_fault')->($err), 'fault() dies with something is_fault() recognises');
	is($err->{status}, 400, 'the status is carried on the fault');
	is($err->{message}, 'because', 'so is the message');
	is($err->{silent}, 0, 'silent defaults to false');

	$err = _dies(sub { $H->can('fault')->(408, 'timed out', silent => 1) });
	is($err->{silent}, 1, 'silent => 1 is carried through');

	ok(!$H->can('is_fault')->('a plain string'), 'is_fault is false for a non-fault error');
	ok(!$H->can('is_fault')->(undef), 'is_fault is false for no error at all');
}

###############################################################################
# write_response() - docs/WEBUI-RPC.md section 14.3's structure onto the
# wire: status line, ORDERED headers, forced Connection: close and a
# Content-Length this tier computes itself rather than trusting.
###############################################################################
sub _written {
	my ($response, %opt) = @_;
	my ($near, $far) = _pair();
	my $ok = $H->can('write_response')->($far, $response, %opt);
	close $far;
	local $/;
	my $out = <$near>;
	close $near;
	return ($ok, $out);
}

{
	my ($ok, $out) = _written({
		status  => 200,
		headers => [ ['Content-Type', 'application/json; charset=utf-8'], ['Set-Cookie', 'a=1'], ['Set-Cookie', 'b=2'] ],
		body    => '{"ok":true}',
	});
	ok($ok, 'write_response reports success');
	like($out, qr{\AHTTP/1\.1 200 OK\r\n}, 'the status line is correct');
	like($out, qr{Content-Type: application/json; charset=utf-8\r\n}, 'a response header is written');
	like($out, qr{Connection: close\r\n}, 'Connection: close is always added');
	like($out, qr{Content-Length: 11\r\n}, 'Content-Length is computed from the body\'s own byte length');
	like($out, qr{\r\n\r\n\{"ok":true\}\z}, 'the body follows the blank line, verbatim');

	my @set_cookie = ($out =~ /^(Set-Cookie: .*)\r$/mg);
	is(scalar(@set_cookie), 2, 'a repeated header name - Set-Cookie - is written twice, not deduplicated');
	ok((index($out, 'a=1') < index($out, 'b=2')), 'and in the order the response supplied them');
}

{
	my ($ok, $out) = _written({ status => 404, headers => [], body => '' });
	like($out, qr{\AHTTP/1\.1 404 Not Found\r\n}, 'a known status gets its standard reason phrase');
	like($out, qr{Content-Length: 0\r\n}, 'an empty body still gets an explicit Content-Length: 0');
}

{
	my ($ok, $out) = _written({ status => 799, headers => [], body => '' });
	like($out, qr{\AHTTP/1\.1 799 Error\r\n}, 'an unrecognised status code falls back to a generic reason phrase');
}

{
	# A response header Task 5 did not generate must never be able to
	# smuggle a second Connection or Content-Length into the reply, and a
	# literal CR or LF in a name/value must never split into a second
	# header or into the body boundary.
	my ($ok, $out) = _written({
		status  => 200,
		headers => [
			['Connection', 'keep-alive'],
			['Content-Length', '999999'],
			["X-Bad\r\nX-Injected", 'evil'],
			['X-Also-Bad', "value\r\nX-Injected: evil"],
			['X-Fine', 'ok'],
		],
		body => 'hi',
	});
	my @connection_lines = ($out =~ /^(Connection: .*)\r$/mg);
	is(scalar(@connection_lines), 1, 'exactly one Connection header reaches the wire');
	is($connection_lines[0], 'Connection: close', 'and it is always close, never a caller-supplied value');
	my @cl_lines = ($out =~ /^(Content-Length: .*)\r$/mg);
	is(scalar(@cl_lines), 1, 'exactly one Content-Length header reaches the wire');
	is($cl_lines[0], 'Content-Length: 2', 'and it is the byte length Task 5 measured, not a caller-supplied one');
	unlike($out, qr/X-Injected/, 'a header name or value carrying a CR/LF is dropped rather than written');
	like($out, qr{X-Fine: ok\r\n}, 'a well-formed header alongside the bad ones is still written');
}

###############################################################################
# error_response()
###############################################################################
{
	my $resp = $H->can('error_response')->(405, 'only GET and POST are accepted');
	is($resp->{status}, 405, 'error_response keeps the given status');
	is(ref($resp->{headers}), 'ARRAY', 'headers is an array of pairs, like every other response');
	like($resp->{body}, qr/"ok":false/, 'the body is the same {ok:false,...} JSON shape csf-ui itself uses');
	like($resp->{body}, qr/WEB_METHOD_NOT_ALLOWED/, 'and carries a WEB_* error code');
	like($resp->{body}, qr/only GET and POST/, 'and the message');

	$resp = $H->can('error_response')->(999, undef);
	is($resp->{status}, 999, 'a well-formed but unrecognised 3-digit status is kept as given');
	like($resp->{body}, qr/WEB_INTERNAL/, 'with a fallback WEB_INTERNAL code, since none is mapped for it');

	$resp = $H->can('error_response')->(undef, 'no status at all');
	is($resp->{status}, 500, 'no status at all falls back to 500');
	like($resp->{body}, qr/WEB_INTERNAL/, 'with the WEB_INTERNAL code');
}

###############################################################################
# ConfigServer::UI::Server::read_ui_conf() - docs/WEBUI-RPC.md section 10,
# the keys this task owns (UI_MODE, UI_LISTEN, UI_PORT, UI_ALLOW) and the
# file-level rules that bind the whole document.
###############################################################################
my $CONF_DIR = tempdir(CLEANUP => 1);
my $conf_n = 0;
sub _conf {
	my ($text) = @_;
	my $path = "$CONF_DIR/ui" . (++$conf_n) . '.conf';
	open(my $fh, '>', $path) or die $!;
	print $fh $text;
	close $fh;
	return $path;
}

{
	my $path = _conf(qq(UI_MODE="b"\nUI_LISTEN="127.0.0.1"\nUI_PORT="8443"\nUI_ALLOW="192.0.2.0/24, 198.51.100.7"\n));
	my ($conf, $problems) = $S->can('read_ui_conf')->($path);
	is_deeply($problems, [], 'a fully-specified, valid ui.conf has no problems');
	is($conf->{UI_MODE}, 'b', 'UI_MODE round-trips');
	is($conf->{UI_LISTEN}, '127.0.0.1', 'UI_LISTEN round-trips');
	is($conf->{UI_PORT}, 8443, 'UI_PORT round-trips as a number');
	is(scalar(@{ $conf->{UI_ALLOW} }), 2, 'UI_ALLOW parses both entries');
	is($conf->{UI_ALLOW}[0]{canonical}, '192.0.2.0/24', 'and each is the canonical ip_info() structure, not a raw string');
}

{
	my $path = _conf(qq(# a comment, and a blank line follow\n\nUI_MODE="b"\nUI_ALLOW="10.0.0.0/8"\n));
	my ($conf, $problems) = $S->can('read_ui_conf')->($path);
	is_deeply($problems, [], 'comments and blank lines are ignored');
	is($conf->{UI_PORT}, 8443, 'an absent UI_PORT defaults to 8443');
	is($conf->{UI_LISTEN}, '127.0.0.1', 'an absent UI_LISTEN defaults to 127.0.0.1');
}

{
	my $path = _conf(qq(UI_MODE="b"\nUI_ALLOW="10.0.0.0/8"\nUI_ALOW="typo"\n));
	my ($conf, $problems) = $S->can('read_ui_conf')->($path);
	is($conf, undef, 'an unknown key refuses the whole file');
	ok((grep { /UI_ALOW/ } @$problems), 'and the problem names the offending key, not just "invalid"');
}

{
	my $path = _conf(qq(UI_MODE="b"\nUI_MODE="a"\nUI_ALLOW="10.0.0.0/8"\n));
	my ($conf, $problems) = $S->can('read_ui_conf')->($path);
	is($conf, undef, 'a duplicate key refuses the whole file - last-one-wins is not this file\'s rule');
}

{
	my $path = _conf(qq(UI_MODE="b"\nUI_ALLOW=""\n));
	my ($conf, $problems) = $S->can('read_ui_conf')->($path);
	is($conf, undef, 'an empty UI_ALLOW refuses to start');
	ok((grep { /UI_ALLOW/ } @$problems), 'naming UI_ALLOW as the reason');
}

{
	my $path = _conf(qq(UI_ALLOW="10.0.0.0/8"\n));
	my ($conf, $problems) = $S->can('read_ui_conf')->($path);
	is($conf, undef, 'a missing UI_MODE refuses to start');
}

{
	my $path = _conf(qq(UI_MODE="c"\nUI_ALLOW="10.0.0.0/8"\n));
	my ($conf, $problems) = $S->can('read_ui_conf')->($path);
	is($conf, undef, 'UI_MODE must be exactly "a" or "b"');
}

{
	my $path = _conf(qq(UI_MODE="b"\nUI_LISTEN="notanaddress"\nUI_ALLOW="10.0.0.0/8"\n));
	my ($conf, $problems) = $S->can('read_ui_conf')->($path);
	is($conf, undef, 'UI_LISTEN must be a literal address, never a hostname');
}

{
	my $path = _conf(qq(UI_MODE="b"\nUI_PORT="80"\nUI_ALLOW="10.0.0.0/8"\n));
	my ($conf, $problems) = $S->can('read_ui_conf')->($path);
	is($conf, undef, 'UI_PORT below 1024 refuses - csfui can never bind it anyway');
}

{
	my $path = _conf(qq(UI_MODE="b"\nUI_PORT="70000"\nUI_ALLOW="10.0.0.0/8"\n));
	my ($conf, $problems) = $S->can('read_ui_conf')->($path);
	is($conf, undef, 'UI_PORT above 65535 refuses');
}

{
	my $path = _conf(qq(UI_MODE="b"\nUI_ALLOW="10.0.0.0/0"\n));
	my ($conf, $problems) = $S->can('read_ui_conf')->($path);
	is($conf, undef, 'a /0 entry in UI_ALLOW is refused, per section 4.1, even though the prefix floor itself does not apply');
}

{
	my $entries = join(',', map { "10.0.0.$_/32" } (0 .. 64));
	my $path = _conf(qq(UI_MODE="b"\nUI_ALLOW="$entries"\n));
	my ($conf, $problems) = $S->can('read_ui_conf')->($path);
	is($conf, undef, 'more than 64 UI_ALLOW entries refuses to start');
}

{
	my $path = _conf(qq(UI_MODE="b"\nUI_ALLOW="10.0.0.0/8, not-an-address"\n));
	my ($conf, $problems) = $S->can('read_ui_conf')->($path);
	is($conf, undef, 'a UI_ALLOW entry that is not a valid address or CIDR refuses the whole file');
	ok((grep { /not-an-address/ } @$problems), 'naming the offending entry');
}

{
	my $path = _conf(qq(UI_MODE="b"\nUI_ALLOW="10.0.0.0/8"\nUI_SESSION_IDLE="99999999"\n));
	my ($conf, $problems) = $S->can('read_ui_conf')->($path);
	is($conf, undef, 'an out-of-range UI_SESSION_IDLE refuses too, even though this task does not read it for its own use');
}

{
	my $path = _conf(qq(UI_MODE="b"\nUI_ALLOW="10.0.0.0/8"\nUI_SESSION_MAX="9999999"\n));
	my ($conf, $problems) = $S->can('read_ui_conf')->($path);
	is($conf, undef, 'an out-of-range UI_SESSION_MAX refuses too');
}

{
	my $path = _conf(qq(UI_MODE="b"\nUI_ALLOW="10.0.0.0/8"\nUI_SESSION_IDLE="50000"\nUI_SESSION_MAX="1000"\n));
	my ($conf, $problems) = $S->can('read_ui_conf')->($path);
	is($conf, undef, 'UI_SESSION_IDLE greater than UI_SESSION_MAX refuses');
}

{
	my $path = _conf(qq(UI_MODE="b"\nUI_ALLOW="10.0.0.0/8"\nUI_CRYPT_ROUNDS="1"\n));
	my ($conf, $problems) = $S->can('read_ui_conf')->($path);
	is($conf, undef, 'an out-of-range UI_CRYPT_ROUNDS refuses too, even though ui-src/bin/csf-ui-passwd is its own reader');
}

{
	my $path = _conf(qq(this is not KEY="VALUE" at all\nUI_MODE="b"\nUI_ALLOW="10.0.0.0/8"\n));
	my ($conf, $problems) = $S->can('read_ui_conf')->($path);
	is($conf, undef, 'a line that does not match the KEY="VALUE" grammar at all refuses the whole file');
}

{
	my ($conf, $problems) = $S->can('read_ui_conf')->('/nonexistent/path/ui.conf');
	is($conf, undef, 'a ui.conf that cannot be opened at all refuses, rather than defaulting to something');
	ok(scalar(@$problems) >= 1, 'with a problem explaining why');
}

###############################################################################
# ConfigServer::UI::Server::peer_allowed()
###############################################################################
{
	my $path = _conf(qq(UI_MODE="b"\nUI_ALLOW="192.0.2.0/24, 2001:db8::/32, 203.0.113.55"\n));
	my ($conf) = $S->can('read_ui_conf')->($path);
	my $allow = $conf->{UI_ALLOW};

	ok($S->can('peer_allowed')->('192.0.2.1', $allow), 'the first address of a IPv4 /24 is allowed');
	ok($S->can('peer_allowed')->('192.0.2.254', $allow), 'the last address of that /24 is allowed too');
	ok(!$S->can('peer_allowed')->('192.0.3.1', $allow), 'one address past the /24 is refused');
	ok($S->can('peer_allowed')->('2001:db8::1', $allow), 'an address inside the IPv6 /32 is allowed');
	ok(!$S->can('peer_allowed')->('2001:db9::1', $allow), 'an address outside it is refused');
	ok($S->can('peer_allowed')->('203.0.113.55', $allow), 'a bare address (no prefix) matches itself exactly');
	ok(!$S->can('peer_allowed')->('203.0.113.56', $allow), 'and nothing else');
	ok(!$S->can('peer_allowed')->('::1', $allow), 'an IPv6 peer is never matched against an IPv4-only entry');
	ok(!$S->can('peer_allowed')->('', $allow), 'an empty peer address is never allowed');
	ok(!$S->can('peer_allowed')->(undef, $allow), 'an undef peer address is never allowed');
	ok(!$S->can('peer_allowed')->('not an address', $allow), 'text that is not an address at all is never allowed');
}
{
	is($S->can('peer_allowed')->('192.0.2.1', []), 0, 'an empty allowlist allows nobody');
}

###############################################################################
# ConfigServer::UI::Server::preflight() - real, not mocked: IO::Socket::SSL
# genuinely is not installed in this workspace (G1), so this exercises the
# refusal for real rather than only through a stand-in.
###############################################################################
{
	my $path = _conf(qq(UI_MODE="b"\nUI_ALLOW="10.0.0.0/8"\n));
	my @problems = $S->can('preflight')->(ui_conf_path => $path);
	ok((grep { /IO::Socket::SSL/ } @problems),
		'preflight refuses to start without IO::Socket::SSL, and names the package to install');
}
{
	my $path = _conf(qq(UI_MODE="a"\nUI_ALLOW="10.0.0.0/8"\n));
	my @problems = $S->can('preflight')->(ui_conf_path => $path);
	ok((grep { /UI_MODE/ } @problems),
		'preflight also refuses when ui.conf configures mode A - this binary is the mode-B listener only');
}
{
	my $path = _conf(qq(UI_MODE="b"\nUI_ALOW="typo"\n));
	my @problems = $S->can('preflight')->(ui_conf_path => $path);
	ok((grep { /not a recognised key/ } @problems), 'and a malformed ui.conf\'s own problems are included');
}

###############################################################################
# ConfigServer::UI::Server->handle_connection() - HTTP.pm and a fake App
# wired together exactly the way run() wires them for real, over a real
# socketpair. t/41 covers the hostile half of this wiring.
###############################################################################
{
	package FakeApp;
	sub new { return bless { calls => [] }, shift }
	sub dispatch {
		my ($self, $req) = @_;
		push @{ $self->{calls} }, $req;
		return {
			status  => 200,
			headers => [ ['Content-Type', 'application/json'] ],
			body    => qq({"ok":true,"peer":"$req->{peer}","method":"$req->{method}","path":"$req->{path}"}),
		};
	}
}

{
	my ($near, $far) = _pair();
	syswrite($far, "GET /api/status?x=1 HTTP/1.1\r\nHost: x\r\n\r\n");
	my $app = FakeApp->new;
	my $server = $S->new(app => $app, header_timeout => 2, body_timeout => 2);
	$server->handle_connection($near, '203.0.113.9');
	close $near;
	local $/;
	my $out = <$far>;
	close $far;

	like($out, qr{\AHTTP/1\.1 200 OK\r\n}, 'handle_connection writes a well-formed response for a normal request');
	like($out, qr{Connection: close\r\n}, 'with Connection: close, as every response from this tier carries');
	like($out, qr/"peer":"203\.0\.113\.9"/, 'and the peer address handle_connection was given reaches dispatch()');
	is($app->{calls}[0]{path}, '/api/status', 'dispatch() receives the parsed, decoded path');
	is($app->{calls}[0]{query}{x}, '1', 'and the parsed query');
}

{
	# A dispatch() that misbehaves (docs/WEBUI-RPC.md section 14.3 promises
	# it never does, but this tier does not take that on faith) still gets
	# a well-formed 500, never a crash that leaves the connection hanging.
	package BrokenApp;
	sub new { return bless {}, shift }
	sub dispatch { return "not a hashref" }
}
{
	my ($near, $far) = _pair();
	syswrite($far, "GET / HTTP/1.1\r\n\r\n");
	my $server = $S->new(app => BrokenApp->new, header_timeout => 2, body_timeout => 2);
	$server->handle_connection($near, '203.0.113.9');
	close $near;
	local $/;
	my $out = <$far>;
	close $far;
	like($out, qr{\AHTTP/1\.1 500}, 'a dispatch() that returns something other than a hashref becomes a 500, not a crash');
}

{
	package DyingApp;
	sub new { return bless {}, shift }
	sub dispatch { die "boom\n" }
}
{
	my ($near, $far) = _pair();
	syswrite($far, "GET / HTTP/1.1\r\n\r\n");
	my $server = $S->new(app => DyingApp->new, header_timeout => 2, body_timeout => 2);
	eval { $server->handle_connection($near, '203.0.113.9') };
	is($@, '', 'handle_connection never propagates a die from dispatch() to its own caller');
	close $near;
	local $/;
	my $out = <$far>;
	close $far;
	like($out, qr{\AHTTP/1\.1 500}, 'a dispatch() that dies outright also becomes a 500');
}

###############################################################################
# ConfigServer::UI::Server->_serve_accepted() - task-5-review.md R31
# (Critical C1): a peer that completes the TCP handshake and then sends
# nothing must not be able to park a forked child forever. tls_wrap is
# injected to simulate exactly that - a "handshake" that never returns -
# and watchdog_exit is overridden so the test can observe the watchdog
# firing rather than being killed by it (the real default is
# POSIX::_exit(1), which would end this test process too).
#
# handshake_timeout is set explicitly and short (task-5-review.md R36):
# the handshake now has its own budget, separate from
# header_timeout/body_timeout/write_timeout below, so it is
# handshake_timeout alone that must bound this case - the fix-round-1
# version of this test left handshake_timeout at its 10s default and
# happened to still pass (barely) only because the stuck handshake was
# staged at exactly 10s too; this version does not depend on that
# coincidence.
###############################################################################
{
	my ($near, $far) = _pair();
	my $app = FakeApp->new;
	my $server = $S->new(
		app               => $app,
		handshake_timeout => 0.1,
		header_timeout    => 1,
		body_timeout      => 1,
		write_timeout     => 1,
		tls_wrap          => sub { select(undef, undef, undef, 10); return $_[0] },
		watchdog_exit     => sub { die "R31 watchdog fired\n" },
	);

	my $t0 = Time::HiRes::time();
	my $died = eval { $server->_serve_accepted($near, '203.0.113.9'); 1 } ? '' : $@;
	my $elapsed = Time::HiRes::time() - $t0;
	close $far;

	like($died, qr/R31 watchdog fired/,
		'R31: a tls_wrap that never returns is killed by the watchdog, not left to hang the child forever');
	cmp_ok($elapsed, '<', 2,
		"R31: and it is killed within the handshake's own budget ($elapsed s), not the 10s the stuck handshake simulated");
	is(scalar(@{ $app->{calls} }), 0, 'R31: dispatch() is never reached by a connection stuck in the handshake');
}

###############################################################################
# ConfigServer::UI::Server->_serve_accepted() - task-5-review.md R36
# (Important, found in the re-review of R31's own fix): R31's watchdog
# originally armed ONE alarm, sized to header_timeout + body_timeout +
# write_timeout, before the handshake even began - so the handshake spent
# from the SAME pool the request phase needed, and a legitimate client
# that used a meaningful slice of each phase's real allowance, without
# ever exceeding any one of them, could still be killed. This failure mode
# did not exist before R31 - there was no deadline at all to blow through
# before it.
#
# Proven both ends in one case: tls_wrap deliberately uses most (not all)
# of a short handshake_timeout before returning a real-enough TLS socket,
# and the total time this takes is already MORE than a since-removed
# single combined budget would have allowed (0.2s handshake against what
# would have been a 0.15s combined pool) - the exact shape of the bug.
# Under the two-budget fix, the handshake's own 0.3s budget comfortably
# covers the 0.2s spent, a fresh budget is armed for the request phase
# alone, and the already-buffered request (written before _serve_accepted
# is even called, so no further wait is needed) completes in a fraction of
# that fresh budget - the watchdog never fires, and a real response
# reaches the wire.
###############################################################################
{
	my ($near, $far) = _pair();
	syswrite($far, "GET /api/status HTTP/1.1\r\nHost: x\r\n\r\n");
	my $app = FakeApp->new;
	my $server = $S->new(
		app               => $app,
		handshake_timeout => 0.3,
		header_timeout    => 0.05,
		body_timeout      => 0.05,
		write_timeout     => 0.05,
		tls_wrap          => sub {
			select(undef, undef, undef, 0.2); # most of the 0.3s handshake budget, none of the 0.15s a combined pool would have given
			# A blessed stand-in, not a real IO::Socket::SSL (not installed
			# in this workspace) - Server.pm's own header comment on
			# tls_wrap promises exactly this is enough for a test: the
			# isa() check R32 added only cares that ref() names the class.
			bless $_[0], 'IO::Socket::SSL';
			return $_[0];
		},
		watchdog_exit => sub { die "R36 watchdog fired (should not have)\n" },
	);

	my $t0 = Time::HiRes::time();
	my $died = eval { $server->_serve_accepted($near, '203.0.113.9'); 1 } ? '' : $@;
	my $elapsed = Time::HiRes::time() - $t0;
	close $far;

	is($died, '', 'R36: a client slow in the handshake but within its own budget is not killed by the watchdog')
		or diag("died with: $died");
	cmp_ok($elapsed, '<', 0.4,
		"R36: total elapsed ($elapsed s) exceeds what a combined 0.15s budget would ever have allowed, and it still succeeded");
	is(scalar(@{ $app->{calls} }), 1, 'R36: and the request the client sent was actually served');
}

###############################################################################
# ConfigServer::UI::Server->_serve_accepted() - task-5-review.md R37: the
# handshake alarm must be cancelled on EVERY exit from the handshake phase,
# including tls_wrap dying outright, not only a normal or false/undef
# return. An unconditional alarm(0) placed textually after the call is
# skipped along with everything else once tls_wrap dies - inert today only
# because run() has no eval around _serve_accepted() (an uncaught die takes
# the whole child with it), but Task 9's mode-B daemon entry point is the
# obvious place for that eval to appear, and the day it does this becomes a
# live, silent leak into whatever the same child does next.
#
# alarm(0) itself is the assertion: the builtin (and Time::HiRes::alarm())
# both return the number of seconds remaining on any previously scheduled
# alarm, 0 if none is pending - so calling it immediately after
# _serve_accepted() has died and been caught is a direct, deterministic
# read of whether the handshake alarm is still armed, not an inference from
# timing.
###############################################################################
{
	my ($near, $far) = _pair();
	my $app = FakeApp->new;
	my $server = $S->new(
		app               => $app,
		handshake_timeout => 5, # long enough that a leak would be unmistakable, not a near-miss
		header_timeout    => 1, body_timeout => 1, write_timeout => 1,
		tls_wrap          => sub { die "R37 tls_wrap blew up\n" },
	);

	my $died = eval { $server->_serve_accepted($near, '203.0.113.9'); 1 } ? '' : $@;
	close $far;
	my $remaining = Time::HiRes::alarm(0); # query-and-cancel whatever is pending, if anything

	like($died, qr/R37 tls_wrap blew up/,
		'R37: a tls_wrap that dies still propagates its own die (unchanged behaviour)');
	is($remaining, 0,
		"R37: and no handshake alarm survives the die into whatever runs next (found pending: ${remaining}s)");
}

###############################################################################
# ConfigServer::UI::Server->_serve_accepted() - task-5-review.md R32/I3: a
# tls_wrap that returns a socket which is not really IO::Socket::SSL (the
# shape of the un-gated constructor-injection seam the review flagged) must
# be refused, not handed to HTTP.pm and served in the clear. A well-formed
# request is written by "the peer" first, so a version of this code that
# forgot the isa() check would answer it - proving this is a live refusal,
# not merely "nothing happened to be sent".
###############################################################################
{
	my ($near, $far) = _pair();
	syswrite($far, "GET /api/status HTTP/1.1\r\nHost: x\r\n\r\n");
	my $app = FakeApp->new;
	my $server = $S->new(
		app            => $app,
		header_timeout => 1, body_timeout => 1, write_timeout => 1,
		tls_wrap       => sub { return $_[0] }, # a plaintext pass-through, never real TLS
	);

	$server->_serve_accepted($near, '203.0.113.9');
	local $/;
	my $out = <$far>;
	close $far;

	is(scalar(@{ $app->{calls} }), 0,
		'R32: a socket tls_wrap did not actually wrap in TLS never reaches dispatch()');
	ok(!defined($out) || $out eq '',
		'R32: and nothing is written back over it either - refused outright, not served in the clear');
}

###############################################################################
# ConfigServer::UI::Server::_accept_backoff() - task-5-review.md I2: the
# accept()-failure policy run()'s loop delegates to. EINTR must retry at
# once (no log line, no delay); anything else must log once and back off,
# so a persistent error (EMFILE/ENFILE, which R31's fix makes reachable by
# closing off the escape valve stuck children used to provide) cannot spin
# the loop as fast as the CPU allows.
###############################################################################
{
	my $server = $S->new(app => FakeApp->new);
	my $stderr = '';
	my $t0 = Time::HiRes::time();
	{
		local *STDERR;
		open(STDERR, '>', \$stderr) or die;
		$server->_accept_backoff(1, 'Interrupted system call');
	}
	my $elapsed = Time::HiRes::time() - $t0;
	is($stderr, '', 'I2: an EINTR accept() failure logs nothing');
	cmp_ok($elapsed, '<', 0.05, 'I2: and retries at once rather than backing off');
}
{
	my $server = $S->new(app => FakeApp->new, accept_backoff => 0.15);
	my $stderr = '';
	my $t0 = Time::HiRes::time();
	{
		local *STDERR;
		open(STDERR, '>', \$stderr) or die;
		$server->_accept_backoff(0, 'Too many open files');
	}
	my $elapsed = Time::HiRes::time() - $t0;
	like($stderr, qr/accept\(\) failed/, 'I2: a non-EINTR accept() failure is logged, not silent');
	like($stderr, qr/Too many open files/, 'I2: naming the actual errno text, not merely "something failed"');
	cmp_ok($elapsed, '>=', 0.1, 'I2: and the loop backs off rather than spinning unthrottled');
}

print "# KEEP: " . scalar(@KEEP) . " temp files held open for the duration of this run\n";
