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
# The wire format between a raw TCP/TLS connection and this software, for
# Mode B (docs/WEBUI-RPC.md section 13: no front web server, csf-ui serves
# TLS itself). This is the only place in this project an HTTP parser reads
# bytes a network peer chose, so it is deliberately tiny and deliberately
# strict rather than a general-purpose HTTP implementation:
#
#   * GET and POST only - anything else is refused before a body is ever
#     read.
#   * No keep-alive (every response says Connection: close and this
#     process serves exactly one request per accepted connection - Server.pm
#     never loops back to read a second request off the same socket), no
#     chunked transfer encoding, no multipart, no ranges.
#   * Hard caps on every dimension a hostile peer controls: request-line
#     bytes, header count, bytes per header line, body bytes. Every cap is
#     enforced by bounding what is read BEFORE it is trusted, never by
#     reading first and checking after - in particular, a declared
#     Content-Length is checked against the cap before a single body byte
#     is read, so an attacker cannot make this process allocate a buffer
#     sized by a number they chose.
#   * Percent-decoding rejects anything it cannot decode unambiguously
#     (a malformed escape, or one that decodes to a NUL byte) rather than
#     passing it through or guessing - docs/WEBUI-RPC.md section 14.2's
#     "turn %XX into the single raw byte it names, and stop there" is a
#     licence to decode, not a licence to accept whatever results.
#   * Every read is bounded by a deadline (15s for the request line and
#     headers together, 15s more for the body), using the same
#     select()-then-sysread() shape ConfigServer::UI::Proto::read_message
#     and ConfigServer::UI::Client already use elsewhere in this tree -
#     never alarm()-based, so this coexists with whatever signal handling
#     Server.pm's own accept loop needs. A connection that does not keep up
#     is dropped, not hung on.
#
# What this module produces is exactly the request structure
# docs/WEBUI-RPC.md section 14.1 defines and ui-src/bin/csf-ui's own header
# comment restates for a reader of that file - method, path (decoded, no
# query string), query (decoded into raw bytes, no query string. Section
# 14.2 is explicit that a decoder here must turn %XX into the single raw
# byte it names and go no further: never set Perl's UTF-8 flag on the
# result, so that a value decoded here and a value ConfigServer::UI::App's
# own _url_decode() decodes from a form body are indistinguishable once
# they reach a validator (Proto::as_chars handles both shapes the same
# way). This module never touches `peer`: that is the connecting address,
# which only Server.pm (holding the accepted socket) can know, and it is
# added to the structure this module returns before it is handed to
# ConfigServer::UI::App::dispatch().
###############################################################################
package ConfigServer::UI::HTTP;

use strict;
use warnings;

use Encode ();
use Time::HiRes ();
use JSON::Tiny ();

our $VERSION = '1.00';

###############################################################################
# Limits (task-5-brief.md). All are 'our' so a test can lower them rather
# than construct megabyte-sized hostile input to prove a cap works; nothing
# in Server.pm's production path overrides any of them.
###############################################################################
our $MAX_REQUEST_LINE = 8192;
our $MAX_HEADERS       = 64;
our $MAX_HEADER_BYTES  = 8192;
our $MAX_BODY_BYTES    = 65536;

our $HEADER_TIMEOUT = 15;
our $BODY_TIMEOUT   = 15;
# Not asked for by the brief, which specifies only the two READ timeouts;
# added for the same reason csf-ui-helper bounds its own response write
# (section 7's "time to write one response line: 5s" row, for the
# analogous helper-side write) - a network peer that stops reading must not
# be able to hang this process on the write side either.
our $WRITE_TIMEOUT = 5;

my @ALLOWED_METHODS = qw(GET POST);
my %ALLOWED_METHOD = map { $_ => 1 } @ALLOWED_METHODS;

###############################################################################
# Faults - the same shape ConfigServer::UI::Proto uses for its own framing
# errors (a blessed hashref, died with rather than returned, so a caller
# cannot forget to check a return value). $status is an HTTP status code,
# not a wire error code: nothing on this side of Server.pm has ever heard
# of docs/WEBUI-RPC.md section 3.5's E_* vocabulary, and nothing needs to.
#
# `silent => 1` marks a fault that read a deadline expiry with nothing
# useful to say back to the peer - the brief's "a slow client is dropped"
# - so the caller (Server.pm) closes without attempting to write anything,
# the same distinction csf-ui-helper's own serve_connection() already makes
# for its E_TIMEOUT fault.
###############################################################################
sub fault {
	my ($status, $message, %opt) = @_;
	die bless { status => $status, message => $message, silent => $opt{silent} ? 1 : 0 },
		__PACKAGE__ . '::Fault';
}

sub is_fault {
	my ($err) = @_;
	return (ref($err) && ref($err) eq __PACKAGE__ . '::Fault') ? 1 : 0;
}

sub _now { return Time::HiRes::time() }

###############################################################################
# read_request($fh, %opt) -> \%request | undef
#
# Parses exactly one HTTP request from a connected, blocking filehandle
# (real socket or TLS-wrapped socket - anything sysread()/select() work on).
#
# Returns the normalised request hashref (docs/WEBUI-RPC.md section 14.1:
# method, path, query, headers, body - everything except `peer`, which is
# Server.pm's to add) on success.
#
# Returns undef when the peer closed the connection before sending a single
# byte - not an error, the ordinary shape of an idle connection closing or
# a health-checker that only opens and closes a socket. Every OTHER failure
# dies with a fault() (see above); this function never dies any other way -
# every branch below that can fail is either a fault() or a documented
# return.
#
# %opt: header_timeout, body_timeout (seconds, default the package
# variables above) - the only reason to override either is a test that
# would otherwise wait out the real default to prove the deadline works.
###############################################################################
sub read_request {
	my ($fh, %opt) = @_;

	my $header_timeout = defined $opt{header_timeout} ? $opt{header_timeout} : $HEADER_TIMEOUT;
	my $body_timeout    = defined $opt{body_timeout}    ? $opt{body_timeout}    : $BODY_TIMEOUT;

	my $buffer = '';
	my $deadline_headers = _now() + $header_timeout;

	return undef unless _await_first_byte($fh, \$buffer, $deadline_headers, $MAX_REQUEST_LINE);

	my $request_line = _read_line($fh, \$buffer, $MAX_REQUEST_LINE, $deadline_headers,
		too_long_status => 414, too_long_message => 'the request line is longer than this server accepts',
		timeout_status  => 408, timeout_message  => 'no complete request line within the read timeout',
		eof_message     => 'the connection closed before a complete request line was received');

	my ($clean, $why) = _clean_line($request_line);
	fault(400, $why) unless defined $clean;

	$clean =~ /^(\S+) (\S+) (\S+)\z/ or fault(400, 'the request line is not METHOD SP TARGET SP VERSION');
	my ($method, $target, $version) = ($1, $2, $3);

	# Section-of-brief: "GET and POST only. Any other method -> 405 without
	# reading a body." Checked before the target, the version, or a single
	# header is even looked at - the safest reading of "without reading a
	# body" is "without reading anything past the request line at all" for
	# a method this server will never route anywhere.
	fault(405, 'only GET and POST are accepted') unless $ALLOWED_METHOD{$method};

	# Origin-form only (RFC 7230 5.3.1): the target must start with '/'.
	# This rejects absolute-form ("GET http://host/path HTTP/1.1" - one of
	# the brief's own hostile cases), authority-form (CONNECT, which is not
	# an allowed method anyway) and asterisk-form ("*").
	fault(400, 'only an origin-form request target (starting with "/") is accepted')
		unless substr($target, 0, 1) eq '/';

	fault(400, 'unsupported HTTP version') unless $version eq 'HTTP/1.1' || $version eq 'HTTP/1.0';

	my ($raw_path, $raw_query) = split(/\?/, $target, 2);

	my ($path, $path_why) = _pct_decode($raw_path, plus_is_space => 0);
	fault(400, "the request path $path_why") unless defined $path;

	my ($query, $query_why) = _decode_query($raw_query);
	fault(400, "a query parameter $query_why") unless defined $query;

	my ($headers, $header_why) = _read_headers($fh, \$buffer, $deadline_headers);
	fault(400, $header_why) unless defined $headers;

	# Section 3.1-equivalent for this tier: chunked transfer encoding is not
	# supported in any form, so the header's mere presence is refused
	# rather than inspected for a value this server would then have to
	# parse correctly.
	fault(400, 'Transfer-Encoding is not supported') if exists $headers->{'transfer-encoding'};

	my $content_length = 0;
	if (exists $headers->{'content-length'}) {
		my $raw_cl = $headers->{'content-length'};
		fault(400, 'Content-Length must be a whole number') unless $raw_cl =~ /^[0-9]{1,10}\z/;
		$content_length = $raw_cl + 0;
		fault(413, "the request body exceeds the $MAX_BODY_BYTES byte limit")
			if $content_length > $MAX_BODY_BYTES;
	}
	elsif ($method eq 'POST') {
		fault(411, 'Content-Length is required for POST');
	}

	my $body;
	if ($content_length > 0) {
		if (exists $headers->{'content-type'}) {
			my $ctype = lc($headers->{'content-type'});
			fault(415, 'the request body must be application/x-www-form-urlencoded')
				unless $ctype =~ m{^application/x-www-form-urlencoded\b};
		}
		my $deadline_body = _now() + $body_timeout;
		$body = _read_body($fh, \$buffer, $content_length, $deadline_body);
	}

	# Whatever is left in $buffer past this point (a pipelined second
	# request, or bytes still unread on the socket) is never looked at:
	# section headline constraint "no keep-alive" means Server.pm closes
	# this connection the moment a response is written, so there is no
	# second request for those bytes to ever belong to.
	return {
		method  => $method,
		path    => $path,
		query   => $query,
		headers => $headers,
		body    => $body,
	};
}

###############################################################################
# Line reading - shared by the request line and every header line.
#
# _await_first_byte() exists only to give read_request() the one case it
# must NOT treat as a fault: a connection that closes having sent nothing
# at all. Every other empty-handed read (a deadline expiring, or EOF after
# some bytes but before a complete line) is a fault, raised by _read_line()
# itself.
###############################################################################
sub _ready_to_read {
	my ($fh, $timeout) = @_;
	# IO::Socket::SSL can already hold a full plaintext record decrypted in
	# its own buffer with nothing left to see at the socket layer - select()
	# alone would wait out the whole timeout on data that is already here.
	# Plain sockets do not implement pending(), so this is a no-op for them.
	return 1 if $fh->can('pending') && $fh->pending;
	my $rin = '';
	vec($rin, fileno($fh), 1) = 1;
	my $ready = select($rin, undef, undef, $timeout);
	return (defined $ready && $ready > 0) ? 1 : 0;
}

sub _await_first_byte {
	my ($fh, $bufref, $deadline, $max) = @_;
	while (1) {
		return 1 if length $$bufref;
		my $left = $deadline - _now();
		return 0 if $left <= 0;
		unless (_ready_to_read($fh, $left)) { next }
		# R34 (task-5-review.md): the same shape as the bug _read_line's
		# refill was fixed for below, and it is a live bug rather than a
		# theoretical one - a flat 8192 here is bounded by $MAX_REQUEST_LINE
		# only by coincidence, because the two numbers happen to be equal
		# today. Bounded to $max instead, this read can never hand
		# _read_line a buffer already holding more than the request-line
		# cap - including, critically, a buffer that already contains the
		# line's own terminator, which is exactly how the original bug let
		# an over-cap line be accepted whole: found via the newline branch
		# before the length check ever ran.
		my $chunk;
		my $read = sysread($fh, $chunk, $max - length($$bufref));
		if (!defined $read) {
			next if $!{EINTR};
			return 0;
		}
		return 0 if $read == 0;
		$$bufref .= $chunk;
	}
}

# Reads one line, including its terminator, out of $$bufref - refilling
# from $fh as needed - and removes it from the buffer. Never returns more
# than $max bytes without a newline in them: a hostile peer that never
# sends "\n" costs this process $max bytes of memory, not its own choice of
# memory (the same reasoning ConfigServer::UI::Proto::read_message already
# documents for the wire protocol's own line cap).
sub _read_line {
	my ($fh, $bufref, $max, $deadline, %fault_opt) = @_;
	while (1) {
		my $idx = index($$bufref, "\n");
		if ($idx >= 0) {
			my $line = substr($$bufref, 0, $idx + 1);
			substr($$bufref, 0, $idx + 1) = '';
			return $line;
		}
		if (length($$bufref) >= $max) {
			fault($fault_opt{too_long_status}, $fault_opt{too_long_message});
		}
		my $left = $deadline - _now();
		fault($fault_opt{timeout_status}, $fault_opt{timeout_message}, silent => 1) if $left <= 0;
		unless (_ready_to_read($fh, $left)) { next }
		# Bounded to exactly what still fits under $max, never a flat 8192:
		# a fixed chunk size can read PAST where the cap should have bitten
		# in one call (e.g. a line of $max + 100 bytes, already sitting
		# entirely in the peer's send buffer, arriving as a single readable
		# chunk that happens to include the terminating "\n") - which would
		# let the "found a newline" branch above return an oversize line on
		# the next iteration before the length check ever saw it go over.
		# Requesting no more than the remaining headroom means the buffer
		# can never exceed $max bytes at the top of this loop, so a line
		# that is genuinely too long is always caught here, at exactly
		# $max, before its terminator - wherever it lands - is ever read.
		my $chunk;
		my $read = sysread($fh, $chunk, $max - length($$bufref));
		if (!defined $read) {
			next if $!{EINTR};
			fault(400, 'a read error occurred on the connection');
		}
		if ($read == 0) {
			fault(400, $fault_opt{eof_message} || 'the connection closed before a complete line was received');
		}
		$$bufref .= $chunk;
	}
}

# One line's worth of framing rules, applied identically to the request
# line and to every header line:
#
#   * it must end "\r\n" - a bare "\n" (LF without a preceding CR) is
#     refused rather than tolerated, which is what makes the next rule
#     meaningful rather than cosmetic;
#   * with that terminator removed, the remaining content must contain no
#     other "\r" at all - a CR anywhere else is either a malformed line
#     ending (CR without a following LF) or an attempt to fold a second
#     header/status line into what this parser sees as one line, which is
#     exactly the shape a request-smuggling payload needs;
#   * and no NUL byte - never valid in a request line or a header, and
#     nothing downstream (argv, a shell-free exec, a log line) should ever
#     be handed one from an untrusted line of text.
#
# Returns ($content_without_terminator, undef) on success or (undef, $why)
# on the first rule broken.
sub _clean_line {
	my ($raw) = @_;
	return (undef, 'the connection sent a line ending in a bare LF, not CRLF')
		unless $raw =~ /\r\n\z/;
	my $content = substr($raw, 0, length($raw) - 2);
	return (undef, 'the line contains a NUL byte') if index($content, "\0") >= 0;
	return (undef, 'the line contains a carriage return that is not part of a CRLF line ending')
		if index($content, "\r") >= 0;
	return ($content, undef);
}

###############################################################################
# Headers
#
# Returns (\%headers, undef) with names lowercased (docs/WEBUI-RPC.md
# section 14.1) and one value per name - a repeated header folds by
# last-value-wins, which section 14.1 leaves to the producer's choice,
# EXCEPT Content-Length and Host: a second occurrence of either is refused
# outright rather than folded, because folding is exactly the ambiguity a
# request-smuggling payload needs from those two headers specifically (the
# brief's own words: "this is request smuggling, not pedantry").
###############################################################################
sub _read_headers {
	my ($fh, $bufref, $deadline) = @_;
	my %headers;
	my %seen;
	my $count = 0;

	while (1) {
		my $raw = _read_line($fh, $bufref, $MAX_HEADER_BYTES, $deadline,
			too_long_status => 431, too_long_message => 'a header line is longer than this server accepts',
			timeout_status  => 408, timeout_message  => 'the headers were not received within the read timeout',
			eof_message     => 'the connection closed before the headers were complete');

		my ($clean, $why) = _clean_line($raw);
		return (undef, $why) unless defined $clean;
		last if $clean eq '';

		$count++;
		# A fault(), not a returned reason: every other row this function
		# can fail on is a malformed-request 400, but "too many headers" is
		# the same "will not fit" shape as a too-long header line just
		# above, which is already a 431 - the two should not disagree only
		# because one is detected inside _read_line() and the other here.
		fault(431, "more than $MAX_HEADERS headers were sent") if $count > $MAX_HEADERS;

		my ($name, $value) = _parse_header_line($clean);
		return (undef, 'a header line has no colon, or whitespace before the colon') unless defined $name;

		if ($name eq 'content-length' || $name eq 'host') {
			return (undef, "duplicate $name header") if $seen{$name}++;
			$headers{$name} = $value;
		}
		else {
			$seen{$name}++;
			$headers{$name} = $value;
		}
	}

	return (\%headers, undef);
}

# "Name: Value" -> (lowercased-name, trimmed-value), or (undef, undef) when
# the line has no colon, an empty name, or whitespace between the name and
# the colon - the last of which RFC 7230 section 3.2.4 singles out by name
# as a request-smuggling vector (some implementations treat "Foo : bar" as
# the header "Foo ", others as "Foo"; refusing it removes the disagreement
# rather than picking a side).
sub _parse_header_line {
	my ($line) = @_;
	my $idx = index($line, ':');
	return (undef, undef) if $idx < 0;
	my $raw_name = substr($line, 0, $idx);
	return (undef, undef) if $raw_name eq '';
	return (undef, undef) if $raw_name =~ /[ \t]/;
	my $value = substr($line, $idx + 1);
	$value =~ s/^[ \t]+//;
	$value =~ s/[ \t]+\z//;
	return (lc($raw_name), $value);
}

###############################################################################
# Body - read only after content_length has already been proven <=
# $MAX_BODY_BYTES by the caller, so this never allocates more than that cap
# regardless of what a peer claims.
###############################################################################
sub _read_body {
	my ($fh, $bufref, $length, $deadline) = @_;
	while (length($$bufref) < $length) {
		my $left = $deadline - _now();
		fault(408, 'the request body was not received within the read timeout', silent => 1) if $left <= 0;
		unless (_ready_to_read($fh, $left)) { next }
		my $want = $length - length($$bufref);
		my $chunk;
		my $read = sysread($fh, $chunk, $want);
		if (!defined $read) {
			next if $!{EINTR};
			fault(400, 'a read error occurred while receiving the request body');
		}
		if ($read == 0) {
			fault(400, 'the connection closed before the declared request body was fully received');
		}
		$$bufref .= $chunk;
	}
	my $body = substr($$bufref, 0, $length);
	substr($$bufref, 0, $length) = '';
	return $body;
}

###############################################################################
# Percent-decoding (docs/WEBUI-RPC.md section 14.2)
#
# Turns %XX into the single raw byte it names and stops there - no UTF-8
# flag is ever set on the result, so a value decoded here and a value
# ConfigServer::UI::App's own _url_decode() produces from a form body are
# the same shape by the time either reaches a Proto validator.
#
# Refuses rather than guesses on two kinds of input: a '%' not followed by
# two hex digits (the brief's "%zz" and "%0"), and any escape - valid or
# not - that names a NUL byte (the brief's "%00"), in a path or a query
# key/value. This is stricter than ConfigServer::UI::App's own body decoder
# (_url_decode(), which just leaves an unrecognised "%" as literal text)
# because that decoder's leniency is csf-ui's own considered choice for
# form bodies (docs/WEBUI-RPC.md does not ask it to reject anything); this
# tier's job is the opposite one - refuse anything ambiguous before it ever
# reaches csf-ui at all.
#
# '+' is decoded to a space only when the caller says so
# (plus_is_space => 1) - true for query keys/values (the
# application/x-www-form-urlencoded convention _url_decode() also applies),
# false for the path, where '+' is an ordinary literal character
# (RFC 3986: reserved only inside a query component).
###############################################################################
sub _pct_decode {
	my ($text, %opt) = @_;
	return ('', undef) unless defined $text && length $text;

	my $out = '';
	my $i = 0;
	my $len = length $text;
	while ($i < $len) {
		my $c = substr($text, $i, 1);
		if ($c eq '%') {
			my $hex = substr($text, $i + 1, 2);
			return (undef, 'contains a percent sign not followed by two hex digits')
				unless $hex =~ /^[0-9A-Fa-f]{2}\z/;
			my $byte = chr(hex($hex));
			return (undef, 'decodes to a NUL byte') if $byte eq "\0";
			$out .= $byte;
			$i += 3;
		}
		elsif ($opt{plus_is_space} && $c eq '+') {
			$out .= ' ';
			$i += 1;
		}
		else {
			$out .= $c;
			$i += 1;
		}
	}
	return ($out, undef);
}

# Splits "a=1&b=2" into { a => '1', b => '2' }, percent-decoding each key
# and value with plus_is_space => 1. A repeated key folds last-value-wins
# (docs/WEBUI-RPC.md section 14.1). Returns ({}, undef) for an absent or
# empty query string.
sub _decode_query {
	my ($raw_query) = @_;
	return ({}, undef) unless defined $raw_query && length $raw_query;

	my %out;
	for my $pair (split(/&/, $raw_query, -1)) {
		next unless length $pair;
		my ($raw_key, $raw_value) = split(/=/, $pair, 2);
		$raw_value = '' unless defined $raw_value;

		my ($key, $key_why) = _pct_decode($raw_key, plus_is_space => 1);
		return (undef, "key $key_why") unless defined $key;
		my ($value, $value_why) = _pct_decode($raw_value, plus_is_space => 1);
		return (undef, "value $value_why") unless defined $value;

		$out{$key} = $value;
	}
	return (\%out, undef);
}

###############################################################################
# write_response($fh, \%response, %opt) -> 1 | 0
#
# Serialises the response structure docs/WEBUI-RPC.md section 14.3 defines
# (status, headers as an ORDERED list of [name, value] pairs, body as raw
# bytes already serialised by csf-ui) onto $fh, adding the two framing
# headers this tier alone is responsible for: Connection: close (this
# module never implements keep-alive, so every response says so) and
# Content-Length (computed from the body's own byte length - section 14.3:
# "Task 5 does not re-encode it", which means measuring it, not trusting
# any Content-Length csf-ui's own headers list might already carry, which
# by construction it never does).
#
# Never dies: like ConfigServer::UI::Client's _write_all, every failure is
# a return value, because this sits at the very end of a request's
# handling and a caller must not need its own eval to close the connection
# safely afterwards.
###############################################################################
my %REASON = (
	200 => 'OK',
	201 => 'Created',
	204 => 'No Content',
	301 => 'Moved Permanently',
	302 => 'Found',
	400 => 'Bad Request',
	401 => 'Unauthorized',
	403 => 'Forbidden',
	404 => 'Not Found',
	405 => 'Method Not Allowed',
	408 => 'Request Timeout',
	409 => 'Conflict',
	411 => 'Length Required',
	413 => 'Payload Too Large',
	414 => 'URI Too Long',
	415 => 'Unsupported Media Type',
	429 => 'Too Many Requests',
	431 => 'Request Header Fields Too Large',
	500 => 'Internal Server Error',
	502 => 'Bad Gateway',
	503 => 'Service Unavailable',
);

sub write_response {
	my ($fh, $response, %opt) = @_;
	my $timeout = defined $opt{timeout} ? $opt{timeout} : $WRITE_TIMEOUT;

	my $status = (ref($response) eq 'HASH' && $response->{status}) ? $response->{status} + 0 : 500;
	my $reason = $REASON{$status} || 'Error';

	my $body = (ref($response) eq 'HASH' && defined $response->{body}) ? $response->{body} : '';
	$body = Encode::encode('UTF-8', $body) if utf8::is_utf8($body);

	my @lines = ("HTTP/1.1 $status $reason\r\n");
	if (ref($response) eq 'HASH' && ref($response->{headers}) eq 'ARRAY') {
		for my $pair (@{ $response->{headers} }) {
			next unless ref($pair) eq 'ARRAY' && @$pair == 2;
			my ($name, $value) = @$pair;
			next unless defined $name && length $name;
			$value = '' unless defined $value;
			# Connection and Content-Length are this tier's alone to set
			# (below); csf-ui's own response never sets either, but a
			# defensive skip here means it could not smuggle a second one
			# in even if it tried. A literal CR or LF in a name or value
			# this tier did not itself generate would let one response
			# header split into another header or into the body boundary -
			# refused rather than written.
			my $lname = lc $name;
			next if $lname eq 'connection' || $lname eq 'content-length';
			next if $name =~ /[\r\n]/ || $value =~ /[\r\n]/;
			push @lines, "$name: $value\r\n";
		}
	}
	push @lines, "Connection: close\r\n";
	push @lines, 'Content-Length: ' . length($body) . "\r\n";
	push @lines, "\r\n";

	return _write_all($fh, join('', @lines) . $body, _now() + $timeout);
}

# Bounded by $deadline, mirroring ConfigServer::UI::Client's own _write_all
# exactly (select()-then-syswrite(), EINTR retried, never a blocking write
# with no ceiling).
sub _write_all {
	my ($fh, $bytes, $deadline) = @_;
	my $written = 0;
	while ($written < length $bytes) {
		my $left = $deadline - _now();
		return 0 if $left <= 0;

		my $win = '';
		vec($win, fileno($fh), 1) = 1;
		my $wout = $win;
		my $ready = select(undef, $wout, undef, $left);
		next if !defined $ready || $ready == 0;

		my $wrote = syswrite($fh, $bytes, length($bytes) - $written, $written);
		unless (defined $wrote) {
			next if $!{EINTR};
			return 0;
		}
		return 0 if $wrote <= 0;
		$written += $wrote;
	}
	return 1;
}

###############################################################################
# error_response($status, $message) -> \%response
#
# The small JSON body this tier writes for a failure of its own (a
# malformed request line, a header that will not fit, a method this server
# does not serve) - built in the same {ok, error, message} shape
# csf-ui's own _json_response() uses for section 3.5's WEB_* codes, so a
# client never has to tell a transport-level rejection from a routed one by
# its JSON shape, only by which error string it carries. These WEB_* names
# are this module's own, not part of docs/WEBUI-RPC.md section 14 (which
# is explicit that HTTP framing is entirely Task 5's problem) - listed here
# once rather than re-derived at each call site.
###############################################################################
my %CODE_FOR_STATUS = (
	400 => 'WEB_BAD_REQUEST',
	405 => 'WEB_METHOD_NOT_ALLOWED',
	408 => 'WEB_REQUEST_TIMEOUT',
	411 => 'WEB_LENGTH_REQUIRED',
	413 => 'WEB_PAYLOAD_TOO_LARGE',
	414 => 'WEB_URI_TOO_LONG',
	415 => 'WEB_UNSUPPORTED_MEDIA_TYPE',
	431 => 'WEB_HEADERS_TOO_LARGE',
	500 => 'WEB_INTERNAL',
	503 => 'WEB_UNAVAILABLE',
);

sub error_response {
	my ($status, $message) = @_;
	$status = 500 unless defined $status && $status =~ /^[0-9]{3}\z/;
	my $code = $CODE_FOR_STATUS{$status} || 'WEB_INTERNAL';

	my $json = eval { JSON::Tiny::encode_json({
		ok      => \0,
		error   => $code,
		message => defined $message ? "$message" : '',
	}) };
	$json = '{"ok":false,"error":"WEB_INTERNAL","message":"an internal error occurred"}'
		unless defined $json;

	return {
		status  => $status,
		headers => [ ['Content-Type', 'application/json; charset=utf-8'] ],
		body    => $json,
	};
}

1;
