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
use Test::More tests => 264;

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
# read_ui_conf() - docs/WEBUI-RPC.md section 10's SECOND rule for UI_LISTEN,
# "mode A and it is present", which had no code at all until the mode-A
# listener landed. The trap this set exists to catch is that UI_LISTEN has
# a default, so by the time %conf is built a file that set it to the
# default and a file that never mentioned it are the same hash: presence
# has to be read from the raw file, with exists (not defined, and not
# "differs from the default"), or the rule silently does nothing for the
# files most likely to carry it.
###############################################################################
{
	my $path = _conf(qq(UI_MODE="a"\nUI_LISTEN="192.0.2.10"\nUI_ALLOW="10.0.0.0/8"\n));
	my ($conf, $problems) = $S->can('read_ui_conf')->($path);
	is($conf, undef, 'mode A with UI_LISTEN set refuses to start');
	ok((grep { /UI_LISTEN/ && /contradicts/ } @$problems),
		'and says the file contradicts itself, naming UI_LISTEN');
	ok(!(grep { /must be a literal IPv4/ } @$problems),
		'and does not ALSO complain about the address itself - the address is not the problem');
}
{
	# The sharpest case: the value IS the default. If presence were read
	# from %conf rather than from the raw file, this file would be
	# indistinguishable from one that omitted the key and would sail
	# straight through - which is exactly what section 10's own "defaults
	# apply only to keys that are absent" rule forbids.
	my $path = _conf(qq(UI_MODE="a"\nUI_LISTEN="127.0.0.1"\nUI_ALLOW="10.0.0.0/8"\n));
	my ($conf, $problems) = $S->can('read_ui_conf')->($path);
	is($conf, undef, 'UI_LISTEN set to exactly its own default still counts as present in mode A');
	ok((grep { /UI_LISTEN/ && /contradicts/ } @$problems), 'and is refused for the contradiction, by name');
}
{
	# Same rule, the other way an "empty means absent" reading would break
	# it: section 10 is explicit that an empty string is a value.
	my $path = _conf(qq(UI_MODE="a"\nUI_LISTEN=""\nUI_ALLOW="10.0.0.0/8"\n));
	my ($conf, $problems) = $S->can('read_ui_conf')->($path);
	is($conf, undef, 'mode A with an EMPTY UI_LISTEN refuses too - an empty string is a value, not an absence');
	# /contradicts/, not merely /UI_LISTEN/: an empty value ALSO fails the
	# "must be a literal address" check, whose message names UI_LISTEN as
	# well - so a laxer assertion here would stay green with the mode-A
	# rule bypassed entirely, which is the whole thing being tested.
	ok((grep { /contradicts/ } @$problems), 'for the contradiction, not because "" is not an address');
}
{
	my $path = _conf(qq(UI_MODE="a"\nUI_LISTEN="not-an-address"\nUI_ALLOW="10.0.0.0/8"\n));
	my ($conf, $problems) = $S->can('read_ui_conf')->($path);
	is($conf, undef, 'mode A with an unparsable UI_LISTEN refuses');
	ok((grep { /contradicts/ } @$problems),
		'for the contradiction, not for the syntax - correcting the syntax would not correct the file');
}
{
	my $path = _conf(qq(UI_MODE="a"\nUI_ALLOW="10.0.0.0/8"\n));
	my ($conf, $problems) = $S->can('read_ui_conf')->($path);
	is_deeply($problems, [], 'mode A with UI_LISTEN absent is the normal, valid case');
	is($conf->{UI_MODE}, 'a', 'and mode A is a mode read_ui_conf accepts');
	is($conf->{UI_LISTEN}, '127.0.0.1', 'the default is still applied, and is simply never used in mode A');
}
{
	my $path = _conf(qq(UI_MODE="b"\nUI_LISTEN="127.0.0.1"\nUI_ALLOW="10.0.0.0/8"\n));
	my ($conf, $problems) = $S->can('read_ui_conf')->($path);
	is_deeply($problems, [], 'mode B with UI_LISTEN set is untouched by the new rule');
	is($conf->{UI_LISTEN}, '127.0.0.1', 'still round-tripping the value it was given');
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
	# The refusal that used to live here - "UI_MODE is 'a'; this is the
	# mode-B standalone listener" - was the code's statement that mode A
	# did not exist. It is now a mode SELECTION, and the two halves of
	# that are asserted separately below: mode A no longer refuses on its
	# mode, and mode A no longer demands a TLS library it has no use for.
	# The second half is real rather than mocked in the same way the
	# mode-B assertion above is: IO::Socket::SSL genuinely is not
	# installed in this workspace, so if mode A still demanded it, this
	# would go red here rather than on somebody's server.
	my $directory = tempdir(CLEANUP => 1);
	my $path = _conf(qq(UI_MODE="a"\nUI_ALLOW="10.0.0.0/8"\n));
	my @problems = $S->can('preflight')->(
		ui_conf_path => $path,
		socket_path  => "$directory/csf-ui.sock",
	);
	ok(!(grep { /UI_MODE/ } @problems),
		'preflight no longer refuses on the mode itself - mode A is a mode this listener has');
	ok(!(grep { /IO::Socket::SSL/ } @problems),
		'and mode A does not demand IO::Socket::SSL: there is no TLS in this process when a front server terminated it');
	is_deeply(\@problems, [],
		'a mode-A ui.conf with a usable socket directory has no startup problems at all');
}
{
	my $path = _conf(qq(UI_MODE="b"\nUI_ALOW="typo"\n));
	my @problems = $S->can('preflight')->(ui_conf_path => $path);
	ok((grep { /not a recognised key/ } @problems), 'and a malformed ui.conf\'s own problems are included');
}
{
	# MODE A'S ONLY ENFORCED STARTUP GATE, REACHED THROUGH preflight()
	# RATHER THAN CALLED DIRECTLY. Every other mode_a_preflight() test in
	# this file calls that function itself, and the one preflight() mode-A
	# case above hands it a GOOD directory - so replacing preflight()'s
	# `push @problem, mode_a_preflight(...)` with `1;` left all 2866 tests
	# green, and Mode A's startup gate could have been deleted invisibly.
	# This is the case that notices: a mode-A ui.conf that is otherwise
	# perfect, pointed at a directory that cannot work.
	my $path = _conf(qq(UI_MODE="a"\nUI_ALLOW="10.0.0.0/8"\n));
	my @problems = $S->can('preflight')->(
		ui_conf_path => $path,
		socket_path  => '/nonexistent-csf-ui-dir/csf-ui.sock',
	);
	ok((grep { /mode-A socket directory/ } @problems),
		"preflight() actually runs mode_a_preflight() in mode A - Mode A's only enforced startup gate is wired in, not merely present");
}
{
	# FIX ROUND 1, F10: A FILE CAN BE WRONG AND STILL SAY WHICH MODE IT IS.
	# read_ui_conf() returns (undef, \@problems) on any failure, so
	# preflight() read the mode as "b" whenever ANY key was wrong - and a
	# mode-A host with one unrelated typo was then told to install
	# IO::Socket::SSL (which mode A must never demand) and never told
	# about its socket directory, which is the two-round diagnosis
	# preflight()'s own comment claims to avoid.
	#
	# The typo is in a key that has nothing to do with either mode, so the
	# only thing that can produce the right answer here is carrying
	# UI_MODE out of the failed read.
	my $path = _conf(qq(UI_MODE="a"\nUI_ALLOW="10.0.0.0/8"\nUI_CRYPT_ROUNDS="notanumber"\n));
	my @problems = $S->can('preflight')->(
		ui_conf_path => $path,
		socket_path  => '/nonexistent-csf-ui-dir/csf-ui.sock',
	);
	ok((grep { /UI_CRYPT_ROUNDS/ } @problems), "F10: the file's own problem is reported");
	ok((grep { /mode-A socket directory/ } @problems),
		"F10: and so is the socket directory - a mode-A host with an unrelated typo still learns about its environment in the same round");
	ok(!(grep { /IO::Socket::SSL/ } @problems),
		'F10: and it is NOT told to install a TLS library, which is what a mode-A listener must never demand');
}
{
	# The fallback is still mode B, and still for a reason: a file with no
	# usable UI_MODE has no answer to give, and mode B's preconditions are
	# no less right than mode A's for a host that has not said which it is.
	my $path = _conf(qq(UI_MODE="x"\nUI_ALLOW="10.0.0.0/8"\n));
	my @problems = $S->can('preflight')->(ui_conf_path => $path);
	ok((grep { /IO::Socket::SSL/ } @problems),
		'F10: a ui.conf whose UI_MODE is not a mode at all still falls back to mode B rather than to nothing');
	my ($conf, $cproblems, $mode) = $S->can('read_ui_conf')->($path);
	is($mode, undef, "F10: read_ui_conf() hands back no mode when the file did not write a valid one");
}
{
	# The third return value itself, both ways round.
	my $good = _conf(qq(UI_MODE="a"\nUI_ALLOW="10.0.0.0/8"\n));
	my (undef, undef, $mode_good) = $S->can('read_ui_conf')->($good);
	is($mode_good, 'a', 'F10: read_ui_conf() reports the mode a valid file wrote');
	my $bad = _conf(qq(UI_MODE="a"\nUI_ALLOW="10.0.0.0/8"\nUI_SESSION_IDLE="0"\n));
	my ($conf_bad, $problems_bad, $mode_bad) = $S->can('read_ui_conf')->($bad);
	is($conf_bad, undef, 'F10: a file with a bad key still returns no config');
	ok(scalar(@$problems_bad), 'F10: and still reports the problem');
	is($mode_bad, 'a', 'F10: but the mode it wrote survives the refusal, which is the whole point');
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

###############################################################################
# MODE A (ruling R82) - the unix-socket listen path.
#
# Everything below drives REAL unix sockets, REAL bind()/chmod()/listen()
# and REAL SO_PEERCRED, because the three things most likely to be wrong
# here all fail SILENTLY on a live host and none of them can be proven by
# reasoning:
#
#   * a socket whose mode the front server's worker cannot reach. The unit
#     runs with UMask=0077; a socket left at whatever that produces is 0700
#     and every proxied request becomes a 502 from a process that logged
#     nothing. So the mode is measured off a socket actually created under
#     that umask, not asserted about.
#   * a sockaddr this module cannot read. _peer_text()'s length heuristic
#     sent a unix sockaddr down the IPv4 branch, where it became undef and
#     then a closed connection. So a real accept()ed unix sockaddr is fed
#     through it.
#   * an identity that is not actually checked. SO_PEERCRED is the only
#     identity mode A has, so it is read off real connected sockets, and
#     the accepted/refused decision is driven with credentials that
#     genuinely do and do not match.
#
# The cross-UID half of the permission story - "and nobody else" - is the
# one part no test here can perform, because creating a process under a
# second account needs root and this is a non-root suite by contract. What
# IS proven is every part this process can perform: the mode is 0660 and
# not the umask's, the group is the one the installer grants, and a peer
# whose credentials are not in the accepted set is refused at the same
# point in the sequence as a mode-B peer outside UI_ALLOW.
###############################################################################
my $SOCK_DIR = tempdir(CLEANUP => 1);
my $sock_n = 0;
sub _sock_path { return "$SOCK_DIR/s" . (++$sock_n) . '.sock' }

sub _capture_stderr {
	my ($code) = @_;
	my $buffer = '';
	{
		local *STDERR;
		open(STDERR, '>', \$buffer) or die "cannot redirect STDERR: $!";
		$code->();
	}
	return $buffer;
}

# Connect to a unix socket this process is listening on, from this
# process: a listen backlog accepts the connection without anything
# calling accept() yet, so no fork and no second process is needed to
# produce a genuinely connected pair over a genuinely bound path.
sub _connect_unix {
	my ($path) = @_;
	socket(my $client, Socket::PF_UNIX(), Socket::SOCK_STREAM(), 0) or die "socket: $!";
	connect($client, Socket::pack_sockaddr_un($path)) or die "connect $path: $!";
	return $client;
}

###############################################################################
# _open_unix_listener() - requirement 1. Created and connected to, not
# reasoned about.
###############################################################################
{
	my $path = _sock_path();
	my ($listener, $gid);
	my $previous = umask(0077); # exactly what csf-ui.service's UMask= leaves
	eval { ($listener, $gid) = $S->can('_open_unix_listener')->($path); 1 }
		or diag("_open_unix_listener died: $@");
	umask($previous);

	ok(defined $listener, 'a unix listener is actually created at the path the templates point at');
	ok(-S $path, 'and what is at that path is a socket');

	my @st = stat($path);
	is(sprintf('%04o', $st[2] & 07777), '0660',
		'the socket is 0660 EVEN THOUGH it was bound under umask 0077 - the mode is set, never inherited');
	is($gid, $st[5], 'the gid returned is the socket\'s own gid, which is what the kernel checks the group bit against');

	my $client = _connect_unix($path);
	ok(defined $client, 'a client can connect to it');
	my $paddr = accept(my $connection, $listener);
	ok(defined $paddr, 'and the listener accepts that connection');

	# The sockaddr that used to become undef. This is the exact value
	# run() feeds the admission check, so it is the exact value that used
	# to close every mode-A connection in silence.
	is($S->can('_peer_text')->($paddr, Socket::AF_UNIX()), 'unix',
		'requirement 2: an accept()ed unix sockaddr has its own case in _peer_text(), not the IPv4 fallthrough');

	close $connection;
	close $client;
	close $listener;
	unlink $path;
}
{
	# The IPv4 fallthrough it used to take, shown for what it produced -
	# so that a future edit that removes the unix case cannot pass by
	# accident.
	my $unix_sockaddr = Socket::pack_sockaddr_un('');
	is($S->can('_peer_text')->($unix_sockaddr, Socket::AF_INET()), undef,
		'requirement 2: read as an IPv4 sockaddr, a unix one still produces undef - which is what run() used to close on');
}
{
	# A stale socket across a restart: bind() to an existing path is
	# EADDRINUSE, not an overwrite. systemd normally removes the
	# RuntimeDirectory on stop, but that is a property of one unit file,
	# not of this code.
	my $path = _sock_path();
	my ($first) = $S->can('_open_unix_listener')->($path);
	ok(-S $path, 'a first listener binds');

	my ($second, $second_gid);
	my $error = '';
	unless (eval { ($second, $second_gid) = $S->can('_open_unix_listener')->($path); 1 }) { $error = $@ }
	is($error, '', 'a second start over the stale socket succeeds rather than dying with EADDRINUSE');
	ok(defined $second, 'and produces a working listener');

	# Proven by which listener the connection actually lands on, not by
	# the absence of an error: the path must now name the NEW socket.
	my $client = _connect_unix($path);
	my $paddr = accept(my $connection, $second);
	ok(defined $paddr, 'a connection to the path reaches the SECOND listener, so the path was genuinely rebound');

	close $connection; close $client; close $first; close $second;
	unlink $path;
}
{
	my $path = _sock_path();
	open(my $fh, '>', $path) or die $!;
	print $fh "not a socket\n";
	close $fh;
	my $error = _dies(sub { $S->can('_open_unix_listener')->($path) });
	like($error, qr/is not a socket/, 'a regular file at the socket path is refused, never unlinked');
	ok(-f $path, 'and the file is still there - "never unlink an arbitrary path" (docs/WEBUI-RPC.md S2.1)');
	unlink $path;
}
{
	my $target = "$SOCK_DIR/symlink-target.txt";
	open(my $fh, '>', $target) or die $!;
	print $fh "important\n";
	close $fh;
	my $path = _sock_path();
	symlink($target, $path) or die "symlink: $!";

	my $error = _dies(sub { $S->can('_open_unix_listener')->($path) });
	like($error, qr/is not a socket/, 'a symlink at the socket path is refused');
	ok(-f $target, 'and the file it pointed at is untouched - lstat, so the link was never followed');
	unlink $path;
}
{
	my $long = "$SOCK_DIR/" . ('x' x 200) . '.sock';
	my $error = _dies(sub { $S->can('_open_unix_listener')->($long) });
	like($error, qr/too long/, 'a socket path too long for a sockaddr_un is refused rather than silently truncated');
}
{
	# The ownership half of "never unlink an arbitrary path". Creating a
	# file owned by a second account needs root, which this suite does not
	# have, so the OTHER side of the comparison is supplied instead - the
	# comparison itself is what is under test.
	my $path = _sock_path();
	my ($listener) = $S->can('_open_unix_listener')->($path);
	close $listener;
	my $error = _dies(sub { $S->can('_open_unix_listener')->($path, self_uid => $> + 1) });
	like($error, qr/owned by uid \Q$>\E, not by this process/,
		'a socket at the path owned by somebody else is refused, not unlinked');
	ok(-S $path, 'and it is still there');
	unlink $path;
}

###############################################################################
# mode_a_preflight() - the startup preconditions that are mode A's alone.
# This suite runs without root by contract (see t/80-templates.t's header),
# which is what makes the "owned by another uid" case testable at all: any
# path under / is owned by uid 0 and this process is not.
###############################################################################
{
	my @problems = $S->can('mode_a_preflight')->(socket_path => "$SOCK_DIR/ok.sock");
	is_deeply(\@problems, [], 'a directory this process owns, not writable by other, is accepted');
}
{
	# SO_PEERCRED resolves on every platform this project supports
	# (docs/WEBUI-RPC.md S2.1 states it as verified fact, S11.7 raised the
	# Perl floor to guarantee it), so the refusal cannot be reached by any
	# real configuration here - and an unreachable refusal is an unproven
	# one. The detection is two `defined &` checks; what this proves is
	# that the refusal fires, and says what to do, when the answer is no.
	my @problems = $S->can('mode_a_preflight')->(
		socket_path => "$SOCK_DIR/ok.sock", have_peercred => 0);
	ok((grep { /SO_PEERCRED/ } @problems),
		'requirement 5: without SO_PEERCRED mode A refuses to start - it is the only identity a unix socket carries');
	ok((grep { /Socket 1\.94/ } @problems), 'and names the floor that provides it');
}
{
	my @problems = $S->can('mode_a_preflight')->(socket_path => '/nonexistent-csf-ui-dir/csf-ui.sock');
	ok((grep { /does not exist/ } @problems),
		'a missing socket directory refuses at startup, rather than failing later as a confusing bind() error');
	ok((grep { /RuntimeDirectory/ } @problems),
		'and names where that directory normally comes from');
}
{
	my @problems = $S->can('mode_a_preflight')->(socket_path => '/csf-ui.sock');
	ok((grep { /owned by uid 0, not by this process/ } @problems),
		'a socket directory this process does not own refuses - it could not create a socket there anyway');
}
{
	# FIX ROUND 1, F3: NO GROUP WRITE BIT EITHER, not only no other write
	# bit. The check read 0002 alone and therefore accepted 0770 and 0775
	# in silence - measured, and then demonstrated end to end: a member of
	# the socket group unlinked the running daemon's socket, bound its own
	# in its place, and the administrator's request INCLUDING COOKIES was
	# delivered to a non-csfui account while that account's reply went back
	# through the administrator's real TLS as the UI.
	#
	# This is not a group that happens to have other members - the socket
	# is 0660 group-owned by a group the installer deliberately puts the
	# front server's worker account into, so "writable by that group"
	# always means "writable by an account that is not us".
	# docs/WEBUI-RPC.md section 2.1's template for the identical hazard on
	# the helper's socket directory already demanded both bits.
	#
	# Every mode is asserted in one table so that a future narrowing or
	# widening of the mask cannot pass by half: the shipped 0750 must still
	# be accepted (a directory the group cannot write but CAN traverse is
	# exactly the deployment), and 0700 as well.
	my @case = (
		[0700, 0, 'a directory only this process can enter is accepted'],
		[0750, 0, 'the shipped 0750 csfui:csf-ui-sock is accepted - the group traverses it, it does not write there'],
		[0770, 1, 'F3: a GROUP-writable socket directory refuses: a member of the socket group could replace the socket and be handed the administrator session'],
		[0775, 1, 'F3: and so does 0775, which the 0002-only check accepted in silence'],
		[0777, 1, 'a world-writable socket directory refuses'],
	);
	for my $case (@case) {
		my ($mode, $expect, $name) = @$case;
		my $dir = tempdir(CLEANUP => 1);
		chmod($mode, $dir) or die "chmod: $!";
		my @problems = $S->can('mode_a_preflight')->(socket_path => "$dir/csf-ui.sock");
		my $refused = (grep { /writable by its group or by other/ } @problems) ? 1 : 0;
		is($refused, $expect, $name);
		chmod(0700, $dir);
	}
	my $dir = tempdir(CLEANUP => 1);
	chmod(0770, $dir) or die "chmod: $!";
	my @problems = $S->can('mode_a_preflight')->(socket_path => "$dir/csf-ui.sock");
	ok((grep { /mode 0770/ } @problems),
		'F3: and the refusal names the mode it actually found, so the operator can see which bit to clear');
	chmod(0700, $dir);
}
{
	my $file = "$SOCK_DIR/a-file";
	open(my $fh, '>', $file) or die $!;
	close $fh;
	my @problems = $S->can('mode_a_preflight')->(socket_path => "$file/csf-ui.sock");
	ok((grep { /is not a directory/ } @problems), 'a socket "directory" that is a regular file refuses');
}

###############################################################################
# peercred() - requirement 5. Real credentials off real sockets.
###############################################################################
{
	my ($near, $far) = _pair();
	my ($pid, $uid, $gid) = $S->can('peercred')->($near);
	is($uid, $> + 0, 'peercred reads the peer uid the kernel reports');
	ok(defined $pid && $pid > 0, 'and a pid');
	ok(defined $gid, 'and a gid');
	close $near; close $far;
}
{
	my @credential = $S->can('peercred')->(undef);
	is(scalar(@credential), 0, 'peercred on nothing is the empty list, never a partial answer');
}
{
	my $fh = _handle("some bytes");
	my @credential = $S->can('peercred')->($fh);
	is(scalar(@credential), 0, 'peercred on a filehandle that is not a socket is the empty list too');
}

###############################################################################
# unix_peer_uids() - the accepted set, derived from the group that gates
# the socket rather than from a ui.conf key docs/WEBUI-RPC.md S10 does not
# have. The NSS lookups are injected here so the set is driven by known
# input; the real, uninjected path is exercised immediately afterwards.
###############################################################################
{
	my $unwanted_scan = 0;
	my $set = $S->can('unix_peer_uids')->(4242,
		self_uid     => 1000,
		group_lookup => sub { return ('csf-ui-sock', '', 4242, 'www-data nginx') },
		name_lookup  => sub { return ($_[0], '', { 'www-data' => 33, nginx => 104 }->{$_[0]}, 4242) },
		# Counted, never die(): a die here would abort this file and
		# produce no "not ok" line at all, which is the one way a guard
		# can look verified without being verified.
		passwd_scan  => sub { $unwanted_scan++; return (999) },
	);
	is($unwanted_scan, 0,
		'the passwd scan does NOT run when the member list already found somebody - it is the failure path only');
	is_deeply([sort { $a <=> $b } keys %$set], [33, 104, 1000],
		'the accepted set is the socket group\'s members plus this process itself');
}
{
	# The case getgrgid() cannot see: an account whose PRIMARY group is
	# the socket's group appears in no member list, while the kernel
	# admits it on exactly that group bit. The fallback scan exists for
	# it, and runs only here - in the path that would otherwise conclude
	# "nobody can reach this socket" and refuse to start.
	my $scanned = 0;
	my $set = $S->can('unix_peer_uids')->(4242,
		self_uid     => 1000,
		group_lookup => sub { return ('csf-ui-sock', '', 4242, '') },
		name_lookup  => sub { return () },
		passwd_scan  => sub { $scanned++; return (77) },
	);
	is($scanned, 1, 'an empty member list falls back to the passwd scan before concluding nobody can connect');
	is_deeply([sort { $a <=> $b } keys %$set], [77, 1000],
		'and an account whose primary group is the socket group is found by it');
}
{
	my $set = $S->can('unix_peer_uids')->(undef, self_uid => 1000);
	is_deeply([keys %$set], [1000], 'with no socket gid at all the set is this process alone - fail closed, not fail open');
}
{
	# The real NSS path, uninjected: this process's own primary group
	# must at minimum yield this process.
	my $set = $S->can('unix_peer_uids')->($( + 0);
	ok($set->{$> + 0}, 'against the real passwd/group database, the set always contains this process');
}

###############################################################################
# peer_uid_allowed() - the three ways in, each proven separately, and the
# deliberate absence of a fourth. docs/WEBUI-RPC.md S2.2's uid==0 rule is
# NOT copied here: root is not rejected for being root, it is simply not
# in a set derived from group membership - which is a different rule with
# a different consequence, as the last two blocks show.
###############################################################################
{
	my $server = $S->new(app => FakeApp->new, mode => 'a',
		self_uid => 1000, socket_gid => 4242, peer_uids => { 33 => 1 });
	ok($server->peer_uid_allowed(1000, 999), 'way 1: this process\'s own uid is admitted');
	ok($server->peer_uid_allowed(5000, 4242), 'way 2: a peer whose PRIMARY gid is the socket\'s gid is admitted');
	ok($server->peer_uid_allowed(33, 33), 'way 3: a peer in the socket group\'s member list is admitted');
	ok(!$server->peer_uid_allowed(5000, 999), 'and a peer matching none of the three is refused');
	ok(!$server->peer_uid_allowed(undef, 4242), 'an absent uid is refused, never treated as unknown-therefore-fine');
	ok(!$server->peer_uid_allowed(0, 0), 'root, not being in the group, is refused');
}
{
	my $server = $S->new(app => FakeApp->new, mode => 'a',
		self_uid => 1000, socket_gid => 4242, peer_uids => { 0 => 1 });
	ok($server->peer_uid_allowed(0, 0),
		'but root IS admitted when the install put root in the socket group - the rule is membership, not a uid==0 test');
}
{
	my $server = $S->new(app => FakeApp->new, mode => 'a', self_uid => 1000);
	ok(!$server->peer_uid_allowed(33, 44), 'with no accepted set built at all, every peer is refused');
}

###############################################################################
# admit_peer() - requirement 3. The mode-B allowlist check is REPLACED at
# the same point in run()'s sequence, not dropped and deferred to
# something later; and requirement 4, UI_ALLOW is not consulted in mode A.
###############################################################################
{
	my ($near, $far) = _pair();
	my $server = $S->new(app => FakeApp->new, mode => 'a', self_uid => $> + 0);
	is($server->admit_peer($near, Socket::pack_sockaddr_un('')), 'unix',
		'a peer whose credentials are accepted is admitted, and gets the unix peer text');
	close $near; close $far;
}
{
	my ($near, $far) = _pair();
	# Nothing matches: not our uid (self_uid is deliberately somebody
	# else), not our gid, and an empty member list.
	my $server = $S->new(app => FakeApp->new, mode => 'a',
		self_uid => $> + 1, socket_gid => $( + 1, peer_uids => {});
	my $admitted;
	my $stderr = _capture_stderr(sub { $admitted = $server->admit_peer($near, Socket::pack_sockaddr_un('')) });
	is($admitted, undef, 'requirement 5: a peer whose uid is not in the accepted set is refused');
	like($stderr, qr/refused a connection on the mode-A unix socket/,
		'and the refusal is logged rather than being a silent close nobody can diagnose');
	like($stderr, qr/uid \Q$>\E /, 'naming the uid that was turned away');
	close $near; close $far;
}
{
	my ($near, $far) = _pair();
	my $server = $S->new(app => FakeApp->new, mode => 'a',
		self_uid => $> + 1, socket_gid => $( + 1, peer_uids => {});
	my $stderr = _capture_stderr(sub {
		$server->admit_peer($near, Socket::pack_sockaddr_un('')) for 1 .. 5;
	});
	my @lines = grep { /\S/ } split(/\n/, $stderr);
	is(scalar(@lines), 1,
		'five refusals of the same uid produce ONE line - diagnostic kept, journal flood from a local peer bounded');
	close $near; close $far;
}
{
	# Requirement 4, proven as behaviour rather than as a comment: a
	# mode-A server carrying an allowlist that would reject 'unix' - and
	# would reject anything, since a uid is not an address - still admits
	# the peer, because in mode A UI_ALLOW is the front server's to
	# enforce (docs/WEBUI-RPC.md S10).
	my ($near, $far) = _pair();
	my $conf_path = _conf(qq(UI_MODE="b"\nUI_ALLOW="192.0.2.0/24"\n));
	my ($conf) = $S->can('read_ui_conf')->($conf_path);
	my $server = $S->new(app => FakeApp->new, mode => 'a', self_uid => $> + 0);
	$server->{allow} = $conf->{UI_ALLOW};
	is($server->admit_peer($near, Socket::pack_sockaddr_un('')), 'unix',
		'requirement 4: UI_ALLOW is not consulted in mode A, even when one is loaded on the object');
	close $near; close $far;
}
{
	# The same object in mode B, to show the check did not simply
	# disappear from the slot: same allowlist, same call, opposite answer.
	my $conf_path = _conf(qq(UI_MODE="b"\nUI_ALLOW="192.0.2.0/24"\n));
	my ($conf) = $S->can('read_ui_conf')->($conf_path);
	my $server = $S->new(app => FakeApp->new, mode => 'b');
	$server->{allow} = $conf->{UI_ALLOW};
	my $inside  = Socket::pack_sockaddr_in(1, Socket::inet_pton(Socket::AF_INET(), '192.0.2.5'));
	my $outside = Socket::pack_sockaddr_in(1, Socket::inet_pton(Socket::AF_INET(), '198.51.100.5'));
	is($server->admit_peer(undef, $inside), '192.0.2.5', 'mode B still admits an address inside UI_ALLOW at this same point');
	is($server->admit_peer(undef, $outside), undef, 'and still refuses one outside it, before a byte is parsed');
}

###############################################################################
# peer_from_front() - where `peer` comes from in mode A, and the shapes it
# refuses. docs/WEBUI-RPC.md S14.1: text form, no port, no brackets,
# per-connecting-client and never a constant.
###############################################################################
{
	my $from = sub { return $S->can('peer_from_front')->({ headers => { 'x-real-ip' => $_[0] } }) };
	is($from->('203.0.113.9'), '203.0.113.9', 'an IPv4 address passes through');
	is($from->('2001:DB8::1'), '2001:db8::1', 'an IPv6 address is canonicalised, so one client is one rate-limit bucket');
	is($from->('::1'), '::1', 'IPv6 loopback is a real front-server source address and is accepted');
	is($from->('203.0.113.9, 198.51.100.1'), undef, 'a comma-joined proxy chain is refused - this tier takes no chain');
	is($from->('[2001:db8::1]'), undef, 'a bracketed literal is refused (S14.1: no brackets)');
	is($from->('203.0.113.9:443'), undef, 'an address with a port is refused (S14.1: no port)');
	is($from->('203.0.113.0/24'), undef, 'a prefix is refused - a CIDR is not one client');
	is($from->('example.com'), undef, 'a hostname is refused; there is no DNS at this tier (G3)');
	is($from->('fe80::1%eth0'), undef, 'a zone index is refused');
	is($from->(''), undef, 'an empty header value is refused');
	is($from->(' '), undef, 'a whitespace-only value is refused');
}
{
	is($S->can('peer_from_front')->({ headers => {} }), undef, 'a missing header is refused');
	is($S->can('peer_from_front')->({}), undef, 'a request with no headers hash at all is refused');
	is($S->can('peer_from_front')->(undef), undef, 'and so is no request');
}

###############################################################################
# handle_connection() in mode A - the whole pipeline over a REAL unix
# socket, end to end: bind, connect, accept, admit, parse, dispatch,
# respond. This is the test that would have caught "mode A is inert".
###############################################################################
{
	my $path = _sock_path();
	my ($listener) = $S->can('_open_unix_listener')->($path);
	my $client = _connect_unix($path);
	syswrite($client, "GET /api/status HTTP/1.1\r\nHost: x\r\nX-Real-IP: 203.0.113.77\r\n\r\n");

	my $paddr = accept(my $connection, $listener);
	my $app = FakeApp->new;
	my $server = $S->new(app => $app, mode => 'a', self_uid => $> + 0,
		header_timeout => 2, body_timeout => 2, write_timeout => 2);

	my $peer = $server->admit_peer($connection, $paddr);
	is($peer, 'unix', 'end to end: the connection is admitted');
	$server->handle_connection($connection, $peer);
	close $connection;

	my $out = '';
	my $chunk;
	while (sysread($client, $chunk, 4096)) { $out .= $chunk }
	close $client; close $listener; unlink $path;

	like($out, qr{\AHTTP/1\.1 200 OK\r\n}, 'a real request over a real unix socket is served');
	is($app->{calls}[0]{peer}, '203.0.113.77',
		'and dispatch() receives the CLIENT\'s address from the front server, not the unix transport');
	unlike($out, qr/"peer":"unix"/, 'the unix marker never reaches dispatch() as a rate-limit key');
}
{
	# No X-Real-IP: refused with a 400 that says what is missing, rather
	# than served with an invented or constant peer.
	my ($near, $far) = _pair();
	syswrite($far, "GET /api/status HTTP/1.1\r\nHost: x\r\n\r\n");
	my $app = FakeApp->new;
	my $server = $S->new(app => $app, mode => 'a',
		header_timeout => 2, body_timeout => 2, write_timeout => 2);
	$server->handle_connection($near, 'unix');
	close $near;
	local $/;
	my $out = <$far>;
	close $far;

	like($out, qr{\AHTTP/1\.1 400 }, 'mode A refuses a request with no X-Real-IP');
	like($out, qr/x-real-ip/i, 'naming the header the front server has to send');
	is(scalar(@{ $app->{calls} }), 0, 'and dispatch() is never reached with a peer nobody can key a rate limit on');
}
{
	# A forged, hostile header value is the same refusal, not a lenient
	# best-effort parse.
	my ($near, $far) = _pair();
	syswrite($far, "GET /api/status HTTP/1.1\r\nHost: x\r\nX-Real-IP: not-an-address\r\n\r\n");
	my $app = FakeApp->new;
	my $server = $S->new(app => $app, mode => 'a',
		header_timeout => 2, body_timeout => 2, write_timeout => 2);
	$server->handle_connection($near, 'unix');
	close $near;
	local $/;
	my $out = <$far>;
	close $far;
	like($out, qr{\AHTTP/1\.1 400 }, 'an X-Real-IP that is not an address is refused, not passed through as a key');
	is(scalar(@{ $app->{calls} }), 0, 'dispatch() is not reached');
}
{
	# Mode B is untouched by any of this: its peer still comes from the
	# transport, and a header claiming otherwise changes nothing.
	my ($near, $far) = _pair();
	syswrite($far, "GET /api/status HTTP/1.1\r\nHost: x\r\nX-Real-IP: 198.51.100.1\r\n\r\n");
	my $app = FakeApp->new;
	my $server = $S->new(app => $app, header_timeout => 2, body_timeout => 2);
	$server->handle_connection($near, '203.0.113.9');
	close $near; close $far;
	is($app->{calls}[0]{peer}, '203.0.113.9',
		'in mode B the peer is still accept()\'s own answer - an X-Real-IP header is not consulted at all');
}

###############################################################################
# Requirement 7 - HTTP.pm's limits are NOT relaxed behind a front server.
# They are the defence against a local peer that got past the peercred
# check, and a bound on what the front server re-emits. Each of these
# drives the mode-A path specifically.
###############################################################################
{
	my $too_big = $ConfigServer::UI::HTTP::MAX_BODY_BYTES + 1;
	my ($near, $far) = _pair();
	syswrite($far, "POST /api/deny HTTP/1.1\r\nHost: x\r\nX-Real-IP: 203.0.113.9\r\n"
		. "Content-Length: $too_big\r\n\r\n");
	my $app = FakeApp->new;
	my $server = $S->new(app => $app, mode => 'a',
		header_timeout => 2, body_timeout => 2, write_timeout => 2);
	$server->handle_connection($near, 'unix');
	close $near;
	local $/;
	my $out = <$far>;
	close $far;
	like($out, qr{\AHTTP/1\.1 413 }, 'requirement 7: the body cap still applies in mode A');
	is(scalar(@{ $app->{calls} }), 0, 'and the oversized body is never read into memory to find out');
}
{
	my ($near, $far) = _pair();
	my $headers = join('', map { "X-Pad-$_: v\r\n" } 1 .. ($ConfigServer::UI::HTTP::MAX_HEADERS + 2));
	syswrite($far, "GET / HTTP/1.1\r\nX-Real-IP: 203.0.113.9\r\n$headers\r\n");
	my $app = FakeApp->new;
	my $server = $S->new(app => $app, mode => 'a',
		header_timeout => 2, body_timeout => 2, write_timeout => 2);
	$server->handle_connection($near, 'unix');
	close $near;
	local $/;
	my $out = <$far>;
	close $far;
	like($out, qr{\AHTTP/1\.1 431 }, 'requirement 7: the header count cap still applies in mode A');
}
{
	my ($near, $far) = _pair();
	syswrite($far, "DELETE / HTTP/1.1\r\nX-Real-IP: 203.0.113.9\r\n\r\n");
	my $app = FakeApp->new;
	my $server = $S->new(app => $app, mode => 'a',
		header_timeout => 2, body_timeout => 2, write_timeout => 2);
	$server->handle_connection($near, 'unix');
	close $near;
	local $/;
	my $out = <$far>;
	close $far;
	like($out, qr{\AHTTP/1\.1 405 }, 'requirement 7: the method allowlist still applies in mode A');
}
{
	my ($near, $far) = _pair();
	syswrite($far, "GET " . ('/x' x 6000) . " HTTP/1.1\r\nX-Real-IP: 203.0.113.9\r\n\r\n");
	my $app = FakeApp->new;
	my $server = $S->new(app => $app, mode => 'a',
		header_timeout => 2, body_timeout => 2, write_timeout => 2);
	$server->handle_connection($near, 'unix');
	close $near;
	local $/;
	my $out = <$far>;
	close $far;
	like($out, qr{\AHTTP/1\.1 414 }, 'requirement 7: the request-line cap still applies in mode A');
}

###############################################################################
# _serve_accepted() in mode A - no TLS, one watchdog, and the request
# budget is still enforced.
###############################################################################
{
	my ($near, $far) = _pair();
	syswrite($far, "GET /api/status HTTP/1.1\r\nHost: x\r\nX-Real-IP: 203.0.113.9\r\n\r\n");
	my $app = FakeApp->new;
	my $server = $S->new(app => $app, mode => 'a',
		header_timeout => 2, body_timeout => 2, write_timeout => 2,
		tls_wrap => sub { die "tls_wrap must never run in mode A\n" },
		watchdog_exit => sub { die "watchdog fired (should not have)\n" });

	my $died = eval { $server->_serve_accepted($near, 'unix'); 1 } ? '' : $@;
	is($died, '', 'mode A serves a connection without ever calling tls_wrap - there is no TLS in this process');
	is(scalar(@{ $app->{calls} }), 1, 'and the request reaches dispatch()');
	local $/;
	my $out = <$far>;
	close $far;
	like($out, qr{\AHTTP/1\.1 200 OK\r\n}, 'with a response written back over the plain socket');
}
{
	# R31's hazard reached by a different road, and the reason mode A
	# still arms the request budget even though HTTP.pm already bounds
	# every read and write it performs itself: dispatch() is inside that
	# budget and has no deadline of its own (docs/WEBUI-RPC.md S14.3
	# promises a return, not a prompt one). Without the alarm, one request
	# that hangs in the app holds a child slot forever, and
	# $DEFAULT_MAX_CHILDREN of them deny the UI with waitpid() never
	# reaping any, because none of them ever exit.
	package HangingApp;
	sub new { return bless {}, shift }
	sub dispatch { select(undef, undef, undef, 10); return { status => 200, headers => [], body => '' } }
}
{
	my ($near, $far) = _pair();
	syswrite($far, "GET /api/status HTTP/1.1\r\nHost: x\r\nX-Real-IP: 203.0.113.9\r\n\r\n");
	# The watchdog is COUNTED rather than only allowed to die: in
	# production it is POSIX::_exit(1), which cannot be caught, but a
	# test's dying stand-in is caught one frame in by handle_connection's
	# own eval around dispatch() and turned into a 500 - so "did it die
	# out here" is not the question. "Did the deadline fire, and did it
	# fire on time" is.
	#
	# dispatch_timeout is set explicitly and short for the same reason
	# handshake_timeout is in the R31 test above: since F1 the request
	# budget has a dispatch term, and leaving it at its 40s default would
	# make this test's "it fires on its own budget" assertion wait out the
	# whole 10s hang and then some. The property under test is that the
	# deadline exists and fires, not what it is sized to.
	my $fired = 0;
	my $server = $S->new(
		app             => HangingApp->new,
		mode            => 'a',
		header_timeout  => 0.1, body_timeout => 0.1, write_timeout => 0.1,
		dispatch_timeout => 0.2,
		watchdog_exit   => sub { $fired++; die "mode A watchdog fired\n" },
	);
	my $t0 = Time::HiRes::time();
	eval { $server->_serve_accepted($near, 'unix') };
	my $elapsed = Time::HiRes::time() - $t0;
	is($fired, 1,
		'a mode-A child stuck in dispatch() has the request budget fire on it - the only deadline over that call');
	cmp_ok($elapsed, '<', 5,
		'and it fires on its OWN budget, not after a ten-second hang - nothing waits for dispatch() to finish');
	close $far;
}

###############################################################################
# FIX ROUND 1, F1: THE REQUEST BUDGET MUST PRICE dispatch().
#
# The budget armed over the request phase covered header_timeout +
# body_timeout + write_timeout and nothing else, while dispatch() sat
# inside it with no term of its own - which _serve_accepted()'s own
# comment already admitted in so many words. Measured against the shipped
# numbers: headers delivered over 14s (legal - HEADER_TIMEOUT is 15) plus
# a dispatch() of 30s (three ConfigServer::UI::Client calls at that
# module's own 10s default, which _route_ui_overview genuinely makes) had
# the watchdog fire at 35.0s. watchdog_exit is POSIX::_exit(1), so the
# administrator got no response at all - the exact spurious kill R36 was
# raised to remove, reached through dispatch() instead of the handshake.
#
# Scaled down here rather than staged at 35s, because what has to be
# proven is the arithmetic, not the constants: header+body+write is 0.45s,
# dispatch() takes 1.2s, and the dispatch term is 3s. A budget without the
# dispatch term is 0.45s and kills this request; with it the budget is
# 3.45s and serves it. The response is read off the wire, so "not killed"
# is proven by what the peer received rather than only by the watchdog
# counter staying at zero.
###############################################################################
{
	package SlowDispatchApp;
	sub new { return bless {}, shift }
	sub dispatch {
		select(undef, undef, undef, 1.2); # longer than header+body+write, shorter than the dispatch term
		return { status => 200, headers => [['Content-Type', 'text/plain']], body => 'served' };
	}
}
{
	my ($near, $far) = _pair();
	syswrite($far, "GET /ui/overview HTTP/1.1\r\nHost: x\r\nX-Real-IP: 203.0.113.9\r\n\r\n");
	my $fired = 0;
	my $server = $S->new(
		app              => SlowDispatchApp->new,
		mode             => 'a',
		header_timeout   => 0.2, body_timeout => 0.2, write_timeout => 0.05,
		dispatch_timeout => 3,
		watchdog_exit    => sub { $fired++; die "F1 watchdog fired\n" },
	);

	my $died = eval { $server->_serve_accepted($near, 'unix'); 1 } ? '' : $@;
	is($fired, 0,
		'F1 mode A: a route whose dispatch() takes longer than header+body+write is not killed - the budget has a dispatch term')
		or diag("died with: $died");
	local $/;
	my $out = <$far>;
	close $far;
	like($out, qr{\AHTTP/1\.1 200 },
		'F1 mode A: and the administrator actually receives the response, rather than POSIX::_exit(1) and nothing at all');
}
{
	# The same arithmetic in mode B, which had the identical sum and would
	# otherwise have kept the bug this fix removed from mode A. A blessed
	# stand-in for IO::Socket::SSL, exactly as the R36 test above uses.
	my ($near, $far) = _pair();
	syswrite($far, "GET /ui/overview HTTP/1.1\r\nHost: x\r\n\r\n");
	my $fired = 0;
	my $server = $S->new(
		app               => SlowDispatchApp->new,
		handshake_timeout => 1,
		header_timeout    => 0.2, body_timeout => 0.2, write_timeout => 0.05,
		dispatch_timeout  => 3,
		tls_wrap          => sub { bless $_[0], 'IO::Socket::SSL'; return $_[0] },
		watchdog_exit     => sub { $fired++; die "F1 watchdog fired\n" },
	);

	my $died = eval { $server->_serve_accepted($near, '203.0.113.9'); 1 } ? '' : $@;
	is($fired, 0,
		'F1 mode B: the same route is not killed there either - both modes read one budget, not two copies of a sum')
		or diag("died with: $died");
	local $/;
	my $out = <$far>;
	close $far;
	like($out, qr{\AHTTP/1\.1 200 }, 'F1 mode B: and its response reaches the wire too');
}
{
	# And the term is a TERM, not the removal of the deadline: a dispatch()
	# that outruns the whole budget is still killed. Without this, "fix F1"
	# could be satisfied by deleting the alarm, which is the failure R31
	# exists to prevent.
	my ($near, $far) = _pair();
	syswrite($far, "GET /ui/overview HTTP/1.1\r\nHost: x\r\nX-Real-IP: 203.0.113.9\r\n\r\n");
	my $fired = 0;
	my $server = $S->new(
		app              => HangingApp->new, # sleeps 10s
		mode             => 'a',
		header_timeout   => 0.1, body_timeout => 0.1, write_timeout => 0.05,
		dispatch_timeout => 0.3,
		watchdog_exit    => sub { $fired++; die "F1 total-budget watchdog fired\n" },
	);
	my $t0 = Time::HiRes::time();
	eval { $server->_serve_accepted($near, 'unix') };
	my $elapsed = Time::HiRes::time() - $t0;
	is($fired, 1,
		'F1: a dispatch() that outruns even the dispatch term is still killed - the term prices the phase, it does not remove the deadline');
	cmp_ok($elapsed, '<', 5, "F1: and within the budget it was given ($elapsed s), not the 10s the hang simulated");
	close $far;
}
{
	# The budget itself, read directly, because the two behavioural cases
	# above can only ever bracket it. Every term of the sum is present and
	# the function is the single source both modes arm from.
	my $server = $S->new(app => FakeApp->new,
		header_timeout => 1, body_timeout => 2, write_timeout => 4, dispatch_timeout => 8);
	is($server->_request_budget, 15,
		'F1: _request_budget() is header + body + write + dispatch, all four terms');
	my $default = $S->new(app => FakeApp->new);
	no warnings 'once'; # the two package globals below are read here and nowhere else in this file
	is($default->{dispatch_timeout},
		$ConfigServer::UI::Client::DEFAULT_TIMEOUT * $ConfigServer::UI::Server::MAX_HELPER_CALLS_PER_REQUEST,
		"F1: and the default dispatch term is derived from ConfigServer::UI::Client's own per-call timeout, not copied from it");
	cmp_ok($ConfigServer::UI::Server::MAX_HELPER_CALLS_PER_REQUEST, '>=', 3,
		'F1: with room for the three sequential helper calls _route_ui_overview actually makes');
}

###############################################################################
# run() ITSELF, for the first time in this suite.
#
# Its own header comment has said since Task 5 that run() is untested by
# design, "because it needs a real listening socket, a real fork, and, in
# production, a real TLS library this workspace does not have installed,
# and it sits behind preflight(), which always refuses here for exactly
# that last reason". Mode A removes the last of those: there is no TLS in
# this process in mode A, preflight() therefore does not demand
# IO::Socket::SSL, and run() can genuinely reach its own mode-A startup
# path here.
#
# What is driven is the refusal, not the loop - a run() that got past this
# point would block in accept() forever, which is why the accepted set is
# injected rather than read off the host's real group database (where the
# answer would depend on which accounts happen to share this test user's
# primary group, and the test would hang on some hosts and pass on
# others).
###############################################################################
{
	my $directory = tempdir(CLEANUP => 1);
	my $path = "$directory/csf-ui.sock";
	my $conf_path = _conf(qq(UI_MODE="a"\nUI_ALLOW="10.0.0.0/8"\n));
	my $server = $S->new(
		app          => FakeApp->new,
		mode         => 'b', # deliberately wrong: run() reads the mode from the file
		ui_conf_path => $conf_path,
		socket_path  => $path,
		self_uid     => $> + 0,
		peer_uids    => { $> + 0 => 1 }, # deliberately: nobody but us
	);
	# Two devices, both so that REMOVING a guard below reddens a named
	# assertion instead of doing something a passing suite cannot tell
	# apart from success:
	#
	#   eval, so a guard removal that turns this refusal into a die leaves
	#   $rc undef and reddens, rather than aborting the file and producing
	#   no "not ok" line at all;
	#
	#   alarm, because the ALTERNATIVE to this refusal is not an error -
	#   it is run() proceeding into accept() and blocking forever. Without
	#   a deadline, removing the refusal would hang this file rather than
	#   fail it, which is the same "zero not ok lines" outcome by a
	#   different route. The alarm never fires when the guard is present.
	my $rc;
	my $stderr = _capture_stderr(sub {
		local $SIG{ALRM} = sub { die "run() never returned - it entered the accept loop\n" };
		alarm(5);
		$rc = eval { $server->run() };
		alarm(0);
	});

	is($rc, 1, 'run() refuses to start when no account but this one can reach the mode-A socket');
	like($stderr, qr/no account other than this one/,
		'the install whose front server was never granted the socket group is refused loudly, not left to 502 silently');
	like($stderr, qr/grant_socket_group/, 'and the remedy is named');
	ok(!-e $path, 'and the socket it bound to find out is removed again rather than left behind as a stale one');
	is($server->{mode}, 'a', 'run() read the mode from ui.conf rather than from whatever the constructor was told');
	is($server->{allow}, undef,
		'requirement 4: and left UI_ALLOW unloaded in mode A - the front server enforces it, from the same value');
}

print "# KEEP: " . scalar(@KEEP) . " temp files held open for the duration of this run\n";
