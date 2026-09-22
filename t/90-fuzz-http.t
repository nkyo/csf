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
# Added 2026-09-22 in https://github.com/nkyo/csf - see CHANGES.md.
#
# Task 10: hostile-input fuzz pass, HTTP half.
#
# t/40 and t/41 are the floor: t/41 is a fixed, hand-picked hostile-input
# table, one case per row. This file is not a repeat of that table - it is a
# SEEDED, DETERMINISTIC RANDOM generator that produces byte strings t/41's
# author never thought to write by hand, and drives them at
# ConfigServer::UI::HTTP::read_request() and, for a smaller sample, the full
# ConfigServer::UI::Server->handle_connection() pipeline.
#
# What every case must do, whatever bytes it happens to be:
#   * never hang - bounded by alarm(), which is a backstop on top of the
#     module's own timeouts (both are exercised: temp-file-backed handles
#     make the module's internal deadlines a formality because a regular
#     file is always "ready" to select(), so alarm() is the only thing
#     standing between a real infinite loop in the parser and this file
#     going quiet forever - exactly the failure shape the brief warns
#     about);
#   * never die any way other than the module's own controlled fault() -
#     is_fault() is what tells a refusal (safe) apart from a crash (not);
#   * never return something that LOOKS like a successful parse of garbage -
#     when read_request() returns a hashref rather than dying or returning
#     undef, that hashref must at minimum carry a defined, non-empty
#     method and path, because those are the only two fields every code
#     path that builds one sets before returning it.
#
# REPRODUCIBILITY. The generator is seeded from $ENV{CSF_FUZZ_SEED} if set,
# else a fixed default - so a failure here is reproducible by re-running
# with the seed this run prints, and CI runs the same cases every time
# unless someone deliberately asks for a different seed.
###############################################################################
use strict;
use warnings;

use FindBin ();
use lib "$FindBin::Bin/..", "$FindBin::Bin/../ui-src/lib";

use File::Temp ();
use Socket ();
use Test::More;

require_ok('ConfigServer::UI::HTTP');
require_ok('ConfigServer::UI::Server');
my $H = 'ConfigServer::UI::HTTP';
my $S = 'ConfigServer::UI::Server';

# A fuzzed body can make a case close its own read side before the server
# writes a response (the pipeline sample below deliberately closes $far right
# after writing, to force a clean EOF rather than a real wait) - writing into
# that is a normal EPIPE this tier already handles, and must not take the
# whole test process down as SIGPIPE's default action would.
$SIG{PIPE} = 'IGNORE';

my $SEED = defined $ENV{CSF_FUZZ_SEED} ? $ENV{CSF_FUZZ_SEED} : 20260922;
srand($SEED);
diag("t/90-fuzz-http.t: seed=$SEED (set CSF_FUZZ_SEED to reproduce a different run)");

###############################################################################
# Bounded execution - every fuzz call goes through this. $BLOCKED counts a
# hit backstop alarm as its own kind of failure (t/42's own convention),
# because "it refused" and "it never returned" are different defects that
# look identical from the outside if you only check the return value.
###############################################################################
our $BLOCKED = 0;
sub _bounded {
	my ($seconds, $code) = @_;
	local $SIG{ALRM} = sub { die "FUZZ_ALARM\n" };
	alarm($seconds);
	my @out = eval { $code->() };
	my $err = $@;
	alarm(0);
	if ($err ne '') {
		$BLOCKED++ if $err eq "FUZZ_ALARM\n";
		return (undef, $err);
	}
	return (\@out, undef);
}

###############################################################################
# Generators
###############################################################################
sub _rand_byte { return chr(int(rand(256))) }
sub _rand_bytes { my ($n) = @_; return join('', map { _rand_byte() } (1 .. $n)) }

# Printable-ish garbage: mostly ASCII, occasionally a control byte or a high
# byte, which is where header/line parsers are most likely to trip.
sub _rand_garbage {
	my ($n) = @_;
	my $out = '';
	for (1 .. $n) {
		my $r = rand();
		if ($r < 0.70) { $out .= chr(32 + int(rand(95))) }       # printable ASCII
		elsif ($r < 0.85) { $out .= chr(int(rand(32))) }          # control bytes, incl NUL
		elsif ($r < 0.95) { $out .= chr(127 + int(rand(129))) }   # high/UTF-8-hostile bytes
		else { $out .= substr("\r\n\0%", int(rand(4)), 1) }       # framing-relevant bytes, weighted up
	}
	return $out;
}

my @CORPUS = (
	"GET /api/status HTTP/1.1\r\nHost: x\r\nCookie: csfui_sid=abc\r\n\r\n",
	"POST /api/deny HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\n"
		. "Content-Length: 21\r\n\r\nip=192.0.2.1&note=hi",
	"GET /ui/lists?which=deny&offset=0&limit=50 HTTP/1.1\r\nHost: x\r\nX-CSRF-Token: t\r\n\r\n",
	"POST /api/login HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 29\r\n\r\n"
		. '{"user":"a","pass":"b","x":1}',
	"GET / HTTP/1.0\r\n\r\n",
);

# One random mutation applied in place: substitute, delete, insert, or splice
# in a chunk of garbage/random bytes. Deterministic given the same rand()
# stream, which the fixed seed above guarantees run to run.
sub _mutate_once {
	my ($s) = @_;
	return $s if length($s) == 0 && rand() < 0.5;
	my $op = int(rand(5));
	my $len = length($s);
	my $at = $len ? int(rand($len)) : 0;
	if ($op == 0 && $len) {                                   # substitute one byte
		substr($s, $at, 1) = _rand_byte();
	}
	elsif ($op == 1 && $len) {                                # delete a run
		my $run = 1 + int(rand(8));
		substr($s, $at, $run) = '';
	}
	elsif ($op == 2) {                                        # insert garbage
		substr($s, $at, 0) = _rand_garbage(1 + int(rand(16)));
	}
	elsif ($op == 3 && $len) {                                # truncate here
		$s = substr($s, 0, $at);
	}
	else {                                                    # duplicate a chunk (header flood in miniature)
		my $run = $len ? (1 + int(rand($len - $at < 32 ? ($len - $at || 1) : 32))) : 1;
		my $chunk = substr($s, $at, $run);
		substr($s, $at, 0) = $chunk x (1 + int(rand(4)));
	}
	return $s;
}

# Every generator returns (data, must_reject). must_reject is TRUE only when
# the generator itself guarantees the bytes exceed a frozen, checkable cap
# ($MAX_HEADERS, $MAX_REQUEST_LINE, $MAX_HEADER_BYTES, $MAX_BODY_BYTES) - the
# one place a fuzz case can assert MORE than "did not crash or hang" without
# reasoning about arbitrary random content. This is what makes the generator
# bite a guard that was silently removed, rather than shape #5 from the task
# brief: a case that would pass whether or not the guard exists, because the
# only thing checked was "well-formed or a fault", and oversize input from a
# GENERIC generator can legitimately land on either side of that by chance.
sub _mutated_corpus_case {
	my $s = $CORPUS[int(rand(scalar @CORPUS))];
	my $rounds = 1 + int(rand(12));
	$s = _mutate_once($s) for (1 .. $rounds);
	return ($s, 0);
}

# _rand_garbage() can itself place a bare \r or \n (it is in the weighted
# byte set on purpose, for the OTHER generators) - which, placed inside what
# is meant to be ONE header's name/value here, splits it into extra lines or,
# worse, an accidental blank line that ends the header section early and
# makes the actual header count observed by the parser come out LOWER than
# $n. That would make must_reject's "$n > MAX_HEADERS" claim false for a
# reason that has nothing to do with MAX_HEADERS being enforced or not -
# exactly the kind of test-passes/fails-for-the-wrong-reason bug the report
# has to rule out, not merely avoid by luck. So this generator's garbage
# excludes \r and \n specifically: every other hostile byte (NUL, other
# control bytes, colons, high bytes) is still in play.
sub _rand_header_garbage {
	my ($n) = @_;
	my $out = '';
	for (1 .. $n) {
		my $r = rand();
		if ($r < 0.75) { $out .= chr(32 + int(rand(95))) }
		elsif ($r < 0.90) { my $c = int(rand(32)); $c = 32 if $c == 13 || $c == 10; $out .= chr($c) }
		else { $out .= chr(127 + int(rand(129))) }
	}
	return $out;
}

sub _header_flood_case {
	my $n = 10 + int(rand(300));   # deliberately spans below and well above MAX_HEADERS (64)
	my $data = "GET / HTTP/1.1\r\n";
	for (1 .. $n) {
		$data .= _rand_header_garbage(1 + int(rand(6))) . ': ' . _rand_header_garbage(int(rand(40))) . "\r\n";
	}
	$data .= "\r\n";
	return ($data, $n > $ConfigServer::UI::HTTP::MAX_HEADERS ? 1 : 0);
}

sub _oversize_case {
	my $which = int(rand(3));
	if ($which == 0) {   # oversize request line - CAP+1 as a floor, never just "large"
		my $len = $ConfigServer::UI::HTTP::MAX_REQUEST_LINE + 1 + int(rand($ConfigServer::UI::HTTP::MAX_REQUEST_LINE));
		return ('GET /' . ('a' x $len) . " HTTP/1.1\r\n\r\n", 1);
	}
	elsif ($which == 1) { # oversize single header value - same floor
		my $len = $ConfigServer::UI::HTTP::MAX_HEADER_BYTES + 1 + int(rand($ConfigServer::UI::HTTP::MAX_HEADER_BYTES));
		return ("GET / HTTP/1.1\r\nX-Big: " . ('b' x $len) . "\r\n\r\n", 1);
	}
	else {                 # Content-Length claims more than MAX_BODY_BYTES allows
		my $claim = $ConfigServer::UI::HTTP::MAX_BODY_BYTES + 1 + int(rand(1_000_000));
		my $body = 'x' x (10 + int(rand(200)));   # far less than claimed - must not block waiting for the rest
		return ("POST / HTTP/1.1\r\nContent-Length: $claim\r\n\r\n$body", 1);
	}
}

sub _encoding_abuse_case {
	my @piece = (
		'%', '%0', '%zz', '%00', '%2e%2e%2f' x (1 + int(rand(20))),
		'%c0%af', '%ff%fe', "\xC0\xAF", "\xED\xA0\x80",   # overlong/surrogate UTF-8
	);
	my $path = '/' . join('', map { $piece[int(rand(scalar @piece))] } (1 .. 1 + int(rand(10))));
	my $q = join('&', map {
		my $k = _rand_garbage(1 + int(rand(8)));
		$k =~ s/[=&\r\n]/_/g;
		"$k=" . $piece[int(rand(scalar @piece))];
	} (1 .. 1 + int(rand(6))));
	return ("GET $path?$q HTTP/1.1\r\nHost: x\r\n\r\n", 0);
}

sub _random_bytes_case {
	return (_rand_bytes(int(rand(4096))), 0);
}

my @STRATEGY = (\&_mutated_corpus_case, \&_header_flood_case, \&_oversize_case,
	\&_encoding_abuse_case, \&_random_bytes_case);

sub _generate_case { return $STRATEGY[int(rand(scalar @STRATEGY))]->() }

###############################################################################
# A real file descriptor per case - read_request() uses sysread()/select(),
# which an in-memory filehandle does not exercise (t/40's own reasoning).
###############################################################################
my @KEEP;
sub _handle_for {
	my ($data) = @_;
	my $temp = File::Temp->new(UNLINK => 1);
	push @KEEP, $temp;
	binmode($temp);
	print $temp $data;
	$temp->flush;
	open(my $fh, '<', $temp->filename) or die "cannot reopen temp file: $!";
	binmode($fh);
	return $fh;
}

sub _check_read_request_case {
	my ($data, $label, $must_reject) = @_;
	my $fh = _handle_for($data);
	my ($result, $blocked_err) = _bounded(5, sub {
		return $H->can('read_request')->($fh, header_timeout => 2, body_timeout => 2);
	});
	# Not hung: _bounded() already counted $BLOCKED if it was; this assertion
	# names the case so a real hang is traceable to which generator produced it.
	ok(!(defined $blocked_err && $blocked_err eq "FUZZ_ALARM\n"),
		"$label: does not hang (" . length($data) . ' bytes)') or diag("input(50)=" . _hexpeek($data));

	if (defined $blocked_err && $blocked_err ne "FUZZ_ALARM\n") {
		# Died, but not from the alarm - must be a recognised fault(), never
		# an uncaught crash (a wrong regex, an undef deref, anything else),
		# and the brief's own words: hostile input is answered 4xx, never
		# 5xx and never a 2xx/3xx that would mean garbage was accepted.
		my $is_fault = $H->can('is_fault')->($blocked_err);
		ok($is_fault, "$label: any die is a controlled fault(), not a crash")
			or diag("died with: $blocked_err");
		ok($is_fault && $blocked_err->{status} >= 400 && $blocked_err->{status} <= 499,
			"$label: a fault's status is always 4xx")
			or diag('status=' . ($is_fault ? $blocked_err->{status} : '(not a fault)'));
	}
	elsif (!defined $blocked_err) {
		my $req = $result->[0];
		if ($must_reject) {
			# The generator guaranteed this input exceeds a frozen cap - a
			# clean parse here means the cap stopped being enforced.
			ok(0, "$label: a case guaranteed to exceed a frozen cap must fault, not parse cleanly")
				or diag('req=' . (defined $req ? Dumper_lite($req) : 'undef'));
		}
		else {
			# Either undef (clean "nothing more to read") or a well-formed hashref.
			my $shaped = !defined($req) || (ref($req) eq 'HASH' && defined($req->{method}) && length($req->{method})
				&& defined($req->{path}) && length($req->{path}));
			ok($shaped, "$label: result is undef or a well-formed parsed request, never a half-built one")
				or diag("req=" . (defined $req ? Dumper_lite($req) : 'undef'));
		}
	}
	else {
		ok(1, "$label: alarm already recorded above");
	}
}

sub _hexpeek {
	my ($s) = @_;
	my $sample = substr($s, 0, 50);
	$sample =~ s/([^\x20-\x7e])/sprintf('\\x%02x', ord($1))/ge;
	return $sample;
}
sub Dumper_lite {
	my ($h) = @_;
	return join(',', map { "$_=" . (defined $h->{$_} ? $h->{$_} : 'undef') } sort keys %$h);
}

###############################################################################
# Direct read_request() fuzz: N cases, 2 assertions apiece (the count is
# fixed below in the plan).
###############################################################################
my $N_DIRECT = 300;
for my $i (1 .. $N_DIRECT) {
	my ($data, $must_reject) = _generate_case();
	_check_read_request_case($data, "direct #$i", $must_reject);
}

###############################################################################
# A handful of DELIBERATE, named edge cases on top of the random sweep -
# things worth pinning down even if the random generator happens to land on
# them too, because a named case is the one that survives if a future
# generator change stops producing it by chance.
###############################################################################
# A deterministic "too many headers" case, deliberately NOT built from the
# random generator above: 100 clean, well-formed "X-Hn: v" headers, ASCII
# only, guaranteed to contain no NUL and no embedded CRLF. This is what makes
# it able to pin down $MAX_HEADERS specifically, run after run - the random
# header-flood generator's OWN cases turned out NOT to (see the break-test
# table in the task report): most of its large-n cases were rejected earlier
# for an unrelated reason (a NUL byte landing in some header's garbage text),
# which is still a legitimate 4xx and still passes the generic must_reject
# check, but never actually exercises "$count > $MAX_HEADERS" on its own.
# Removing that one line must redden THIS case, deterministically.
my $clean_flood = "GET / HTTP/1.1\r\n";
$clean_flood .= "X-H$_: v\r\n" for (1 .. 100);
$clean_flood .= "\r\n";

my @NAMED = (
	['empty input',                          '',                                                   0],
	['a single NUL byte',                    "\0",                                                 0],
	['request line with embedded NUL',       "GET /\0x HTTP/1.1\r\n\r\n",                          0],
	['header name with no colon at all',     "GET / HTTP/1.1\r\nJustAWord\r\n\r\n",                0],
	['a body-less POST that claims a body',  "POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\n",       0],
	['CRLF.CRLF storm in place of headers',  "GET / HTTP/1.1\r\n" . ("\r\n" x 500),                0],
	['one line, no CRLF anywhere',           'GET / HTTP/1.1',                                     0],
	['request line only NULs',               "\0" x 200,                                           0],
	['100 clean headers, over MAX_HEADERS',  $clean_flood,                                         1],
);
for my $case (@NAMED) {
	my ($label, $data, $must_reject) = @$case;
	_check_read_request_case($data, "named: $label", $must_reject);
}

###############################################################################
# Full-pipeline sample: Server->handle_connection() over a real socketpair,
# for a smaller number of cases - proves the fuzzer's findings hold not only
# for read_request() in isolation but for the connection handler production
# actually runs (t/41's own reasoning for doing the same with its hand-picked
# rows).
###############################################################################
{
	package FuzzApp;
	sub new { return bless { calls => 0 }, shift }
	sub dispatch {
		my ($self, $req) = @_;
		$self->{calls}++;
		return { status => 200, headers => [['Content-Type', 'application/json']], body => '{"ok":true}' };
	}
}

sub _pair {
	socketpair(my $near, my $far, Socket::AF_UNIX(), Socket::SOCK_STREAM(), Socket::PF_UNSPEC())
		or die "socketpair: $!";
	return ($near, $far);
}

my $N_PIPELINE = 50;
for my $i (1 .. $N_PIPELINE) {
	my ($data, $must_reject) = _generate_case();
	my ($near, $far) = _pair();
	syswrite($far, $data);
	# Half-close $far's write side only (SHUT_WR=1): $near sees EOF right
	# after the request bytes (so a case with no natural terminator does not
	# make the server wait out its own timeout), but $far's READ side stays
	# open so the response handle_connection writes back onto $near can
	# still be read afterwards - closing $far outright (as the earlier draft
	# of this file did) discarded the response before it could be checked,
	# which is exactly how a must_reject case could have silently stopped
	# proving anything.
	shutdown($far, 1);
	my $app = FuzzApp->new;
	my $server = $S->new(app => $app, header_timeout => 2, body_timeout => 2, write_timeout => 2);

	my ($result, $blocked_err) = _bounded(5, sub { $server->handle_connection($near, '203.0.113.9'); return 1 });
	ok(!(defined $blocked_err && $blocked_err eq "FUZZ_ALARM\n"),
		"pipeline #$i: handle_connection does not hang (" . length($data) . ' bytes)')
		or diag("input(50)=" . _hexpeek($data));
	ok(!(defined $blocked_err && $blocked_err ne "FUZZ_ALARM\n"),
		"pipeline #$i: handle_connection never lets a die escape it")
		or diag("escaped with: " . (defined $blocked_err ? $blocked_err : ''));
	close $near;   # response already sitting in the socketpair's kernel buffer for $far to read

	if ($must_reject) {
		my ($out) = _bounded(5, sub {
			local $/;
			my $text = <$far>;
			return defined $text ? $text : '';
		});
		my $response_text = defined $out ? $out->[0] : '';
		like($response_text, qr{\AHTTP/1\.[01] 4\d\d},
			"pipeline #$i: a case guaranteed to exceed a frozen cap gets a 4xx over the wire, not 200")
			or diag('response(80)=' . substr((defined $response_text ? $response_text : ''), 0, 80));
	}
	close $far;
}

###############################################################################
# R107-style final assertion (t/42's own convention): no case above hit its
# backstop alarm. Without this, a wedged case would make one of the named
# assertions above fail for a reason it does not itself state.
###############################################################################
is($BLOCKED, 0, 'no fuzz case in this file hit its bounding alarm - every case returned or died on its own');

done_testing();
