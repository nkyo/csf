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
# Wire format and argument grammars for the WebUI RPC, shared by the
# unprivileged web tier and the root helper. Every rule here is the one written
# down in docs/WEBUI-RPC.md sections 3 and 4; that document is frozen and this
# file implements it rather than deciding anything of its own.
#
# Two properties are load-bearing and are the reason this is one module rather
# than two copies:
#
#   * every grammar is a positive match. There is no sanitise-and-continue path,
#     because csf re-splits its arguments into one string (csf.pl:340-343) and
#     parses options out of comment text (csf.pl:4311-4313), so a value that is
#     "mostly fine" is not fine at all.
#   * the caller cannot tell the helper what to accept. The helper re-validates
#     with this same code even for arguments the web tier claims to have checked.
###############################################################################
package ConfigServer::UI::Proto;

use strict;
use warnings;

use Encode ();
use Socket ();
use JSON::Tiny ();

our $VERSION = '1.00';

# Maximum bytes on one line, in either direction, newline included (section 3.1).
our $MAXLINE = 65536;

# Budget for row-building operations: the envelope gets the remaining 512 bytes
# (section 3.4).
our $ENVELOPE_RESERVE = 512;

###############################################################################
# Faults
#
# A fault is how this module reports a framing or JSON failure to its caller.
# It is a blessed hashref rather than a string so that the helper can map it to
# a wire error code without parsing an error message. E_TIMEOUT is internal and
# is never put on the wire: a connection that times out is closed in silence
# (section 7).
###############################################################################
sub fault {
	my ($code, $message) = @_;
	die bless { code => $code, message => $message }, __PACKAGE__ . '::Fault';
}

sub is_fault {
	my ($err) = @_;
	return (ref($err) && ref($err) eq __PACKAGE__ . '::Fault') ? 1 : 0;
}

###############################################################################
# Bytes and UTF-8
###############################################################################

# Length in bytes of a string that may be held as characters or as bytes. Every
# length limit in the contract is stated in bytes, so this is what enforces them.
sub bytelen {
	my ($string) = @_;
	return 0 unless defined $string;
	return length($string) unless utf8::is_utf8($string);
	return length(Encode::encode('UTF-8', $string));
}

# Returns the value as characters, or undef when it is not valid UTF-8.
sub as_chars {
	my ($string) = @_;
	return undef unless defined $string;
	return $string if utf8::is_utf8($string);
	my $chars = eval { Encode::decode('UTF-8', $string, Encode::FB_CROAK()) };
	return defined $chars ? $chars : undef;
}

# Byte-exact truncation. Applied before decoding so that a cut never lands in
# the middle of a UTF-8 sequence and leaves an invalid tail behind; the
# sanitiser turns whatever is left into '?'.
sub truncate_bytes {
	my ($string, $max) = @_;
	return $string unless defined $string;
	my $bytes = utf8::is_utf8($string) ? Encode::encode('UTF-8', $string) : $string;
	return $string if length($bytes) <= $max;
	return substr($bytes, 0, $max);
}

# One valid, non-overlong, non-surrogate, in-range UTF-8 sequence.
my $UTF8SEQ = qr/
	  [\xC2-\xDF][\x80-\xBF]
	| \xE0[\xA0-\xBF][\x80-\xBF]
	| [\xE1-\xEC][\x80-\xBF]{2}
	| \xED[\x80-\x9F][\x80-\xBF]
	| [\xEE-\xEF][\x80-\xBF]{2}
	| \xF0[\x90-\xBF][\x80-\xBF]{2}
	| [\xF1-\xF3][\x80-\xBF]{3}
	| \xF4[\x80-\x8F][\x80-\xBF]{2}
/x;

###############################################################################
# sanitise - section 3.6
#
# Applied on the way OUT, to anything that came from the system: a note read
# back from csf.deny, a line of csf -g output, an error message from csf. Those
# files are edited by hand, by lfd and by older versions of this software, and
# the web tier renders whatever it is handed.
###############################################################################
sub sanitise {
	my ($value, $max) = @_;
	return '' unless defined $value;
	my $bytes = utf8::is_utf8($value) ? Encode::encode('UTF-8', $value) : $value;
	$bytes = truncate_bytes($bytes, $max) if defined $max;

	$bytes =~ s/[\x09\x0A\x0D]/ /g;
	$bytes =~ s/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/./g;

	my $out = '';
	pos($bytes) = 0;
	while (pos($bytes) < length($bytes)) {
		if ($bytes =~ /\G([\x00-\x7F]|$UTF8SEQ)/gc) {
			$out .= $1;
		}
		else {
			$out .= '?';
			pos($bytes) = pos($bytes) + 1;
		}
	}
	my $chars = eval { Encode::decode('UTF-8', $out, Encode::FB_CROAK()) };
	return defined $chars ? $chars : '?';
}

# Messages are ASCII and at most 512 bytes (section 3.3). Anything outside
# printable ASCII becomes '?' so that a message can never carry a terminal
# escape or an encoding surprise into a log or a page.
sub message_text {
	my ($value) = @_;
	my $clean = sanitise($value, 512);
	$clean =~ s/[^\x20-\x7E]/?/g;
	return $clean;
}

###############################################################################
# Framing - section 3.1
###############################################################################
sub encode {
	my ($struct) = @_;
	my $json = eval { JSON::Tiny::encode_json($struct) };
	fault('E_INTERNAL', 'response could not be encoded') unless defined $json;
	my $line = $json . "\n";
	fault('E_INTERNAL', "response line exceeds $MAXLINE bytes")
		if length($line) > $MAXLINE;
	return $line;
}

sub decode {
	my ($line) = @_;
	fault('E_PROTOCOL', 'empty request') unless defined $line && length $line;
	fault('E_PROTOCOL', "line exceeds $MAXLINE bytes") if length($line) > $MAXLINE;
	# A line ending \r\n carries the \r inside the JSON text. It is not framing
	# and it is not stripped: our parser would treat it as trailing whitespace,
	# so it is refused here instead, which is the behaviour section 3.1 states.
	fault('E_PROTOCOL', 'the request line ends with a carriage return') if $line =~ /\r\z/;
	my $struct = eval { JSON::Tiny::decode_json($line) };
	fault('E_PROTOCOL', 'request is not valid JSON') unless defined $struct;
	return $struct;
}

# Reads exactly one newline-terminated line and returns the decoded message, or
# undef at a clean end of file. It never buffers past $MAXLINE, so an oversize
# line costs 64 KiB of memory rather than the sender's choice of memory.
#
# $deadline, when given, is an absolute Time::HiRes timestamp; a connection that
# has not produced a complete line by then raises an E_TIMEOUT fault, which the
# caller answers by closing in silence (section 7).
#
# Bytes after the first newline are E_PROTOCOL (section 3.1: exactly one request
# per connection). This catches everything that arrives in the same read window;
# a second line sent after the response is moot because the connection is closed.
sub read_message {
	my ($fh, $deadline) = @_;
	my $buffer = '';

	while (1) {
		my $index = index($buffer, "\n");
		if ($index >= 0) {
			my $line = substr($buffer, 0, $index);
			fault('E_PROTOCOL', 'bytes after the first newline')
				if length($buffer) > $index + 1;
			return decode($line);
		}

		if (length($buffer) >= $MAXLINE) {
			fault('E_PROTOCOL', "line exceeds $MAXLINE bytes");
		}

		if (defined $deadline) {
			my $left = $deadline - _now();
			fault('E_TIMEOUT', 'no complete request line within the read timeout')
				if $left <= 0;
			my $rin = '';
			vec($rin, fileno($fh), 1) = 1;
			my $rout = $rin;
			my $ready = select($rout, undef, undef, $left);
			next if !defined $ready || $ready == 0;
		}

		my $chunk = '';
		my $read = sysread($fh, $chunk, $MAXLINE - length($buffer));
		if (!defined $read) {
			next if $!{EINTR};
			fault('E_PROTOCOL', 'read error on the connection');
		}
		if ($read == 0) {
			return undef if $buffer eq '';
			fault('E_PROTOCOL', 'end of file before a complete request line');
		}
		$buffer .= $chunk;
	}
}

sub _now {
	return eval { require Time::HiRes; Time::HiRes::time() } || time();
}

###############################################################################
# Validators - section 4
#
# Each returns the normalised value, or undef when the value is not acceptable.
# In list context each also returns the reason, which the helper turns into the
# E_ARG message. The reason never quotes the value for 'pass' (section 4.10).
###############################################################################
sub _ok {
	my ($value) = @_;
	return wantarray ? ($value, undef) : $value;
}

sub _bad {
	my ($why) = @_;
	return wantarray ? (undef, $why) : undef;
}

sub _plain {
	my ($value) = @_;
	return (defined $value && !ref $value) ? 1 : 0;
}

# --- 4.1 ip -----------------------------------------------------------------
#
# %opt:
#   removal  => 1   the permissive side of section 4.1, for undeny, unallow and
#                   temprm - and for reading entries back out of the files csf
#                   wrote. Accepts /0, and accepts the two IPv6 literals :: and
#                   ::1 that the IPv4-mapped rule would otherwise catch (R18).
#   mutating => 1   apply the prefix floor and the loopback rule: deny, allow,
#                   tempdeny.
#
# Returns the canonical form - inet_ntop of the packed bytes, lowercased, with
# /len appended when a prefix was given. That canonical form, not the caller's
# text, is what reaches csf, the response and the audit log.
sub ip_info {
	my ($value, %opt) = @_;
	return _bad('is required') unless _plain($value);

	my $text = "$value";
	return _bad('must be 1-49 bytes') if length($text) < 1 || length($text) > 49;
	return _bad('contains characters that cannot appear in an IP address')
		if $text =~ /[^\x21-\x7E]/;

	my @parts = split(/\//, $text, -1);
	return _bad('may contain at most one "/"') if @parts > 2;
	my ($address, $prefix) = @parts;
	return _bad('is not a valid IP address') unless defined $address && length $address;

	my $family = ($address =~ /\./ && $address !~ /:/)
		? Socket::AF_INET() : Socket::AF_INET6();
	my $bits = ($family == Socket::AF_INET()) ? 32 : 128;

	my $packed = eval { Socket::inet_pton($family, $address) };
	return _bad('is not a valid IP address') unless defined $packed;
	return _bad('is not a valid IP address') unless length($packed) == $bits / 8;

	if ($family == Socket::AF_INET6()) {
		my $high = substr($packed, 0, 10);
		my $next = substr($packed, 10, 2);
		if ($high eq "\0" x 10 && ($next eq "\0\0" || $next eq "\xFF\xFF")) {
			# R18: :: and ::1 fall inside the numeric range this rule uses to
			# catch IPv4-in-IPv6 forms, but they are not aliases of an IPv4
			# address - they are the unspecified and loopback addresses of their
			# own family. csf's CLI will put ::1 into csf.deny, so refusing to
			# read or remove it would leave the UI unable to undo exactly the
			# self-inflicted state it exists to undo. Removal and file parsing
			# accept those two literals; adding still rejects them, and every
			# genuine mapped or compatible form is rejected everywhere.
			my $carve_out = $opt{removal}
				&& ($packed eq "\0" x 16 || $packed eq ("\0" x 15) . "\x01");
			return _bad('is an IPv4-mapped or IPv4-compatible IPv6 address; send the IPv4 form')
				unless $carve_out;
		}
	}

	my $plen;
	if (defined $prefix) {
		return _bad('prefix length must be digits with no leading zero and no sign')
			unless $prefix =~ /^(?:0|[1-9][0-9]{0,2})$/;
		$plen = $prefix + 0;
		return _bad("prefix length must be $bits or less") if $plen > $bits;

		my $mask = _netmask($plen, $bits / 8);
		return _bad('has host bits set; did you mean ' . lc(Socket::inet_ntop($family, $packed & $mask)) . "/$plen")
			unless ($packed & $mask) eq $packed;

		if ($plen == 0 && !$opt{removal}) {
			return _bad('a /0 prefix means the whole Internet and is not accepted here');
		}
	}

	if ($opt{mutating}) {
		my $floor = ($family == Socket::AF_INET()) ? 8 : 32;
		if (defined $plen && $plen < $floor) {
			return _bad("prefix length must be /$floor or narrower for this operation");
		}
		my $effective = defined $plen ? $plen : $bits;
		for my $loop ('127.0.0.1', '::1') {
			my $target = eval { Socket::inet_pton(
				($loop =~ /:/ ? Socket::AF_INET6() : Socket::AF_INET()), $loop) };
			next unless defined $target && length($target) == length($packed);
			return _bad('covers the loopback address')
				if _covers($packed, $effective, $target, $bits / 8);
		}
	}

	my $canonical = lc(Socket::inet_ntop($family, $packed));
	$canonical .= "/$plen" if defined $plen;

	return _ok({
		canonical => $canonical,
		family    => ($family == Socket::AF_INET()) ? 4 : 6,
		packed    => $packed,
		plen      => $plen,
		bits      => $bits,
	});
}

sub validate_ip {
	my ($value, %opt) = @_;
	my ($info, $why) = ip_info($value, %opt);
	return _bad($why) unless defined $info;
	return _ok($info->{canonical});
}

sub _netmask {
	my ($plen, $bytes) = @_;
	my $mask = '';
	my $left = $plen;
	for (1 .. $bytes) {
		my $byte = $left >= 8 ? 0xFF : ($left <= 0 ? 0 : ((0xFF << (8 - $left)) & 0xFF));
		$mask .= chr($byte);
		$left -= 8;
	}
	return $mask;
}

sub _covers {
	my ($network, $plen, $target, $bytes) = @_;
	my $mask = _netmask($plen, $bytes);
	return (($target & $mask) eq ($network & $mask)) ? 1 : 0;
}

# The key an address is compared by when matching a loaded iptables rule
# against a configured entry: a full-length prefix and no prefix name the same
# host, and csf writes both forms.
sub ip_key {
	my ($canonical) = @_;
	return '' unless defined $canonical;
	my $key = lc $canonical;
	$key =~ s{/32$}{} if $key =~ /\./;
	$key =~ s{/128$}{} if $key =~ /:/;
	return $key;
}

# --- 4.2 ttl ----------------------------------------------------------------
sub validate_ttl {
	my ($value) = @_;
	return _bad('is required') unless _plain($value);
	my $text = "$value";
	return _bad('must be a whole number of seconds, 1 to 6 digits')
		unless $text =~ /^[0-9]{1,6}$/;
	my $seconds = $text + 0;
	return _bad('must be between 60 and 604800 seconds')
		if $seconds < 60 || $seconds > 604800;
	return _ok($seconds);
}

# --- 4.3 ports --------------------------------------------------------------
#
# Absent, null and "" all mean every port, and the helper then passes no -p at
# all. Ranges are expanded because csf -td's port regex (csf.pl:4313) contains
# neither '-' nor ':': a range handed over verbatim is truncated to its lower
# bound and the rest is silently stored as the ban's comment.
sub validate_ports {
	my ($value) = @_;
	return _ok('') if !defined $value;
	return _bad('must be a string of ports') if ref $value;
	my $text = "$value";
	return _ok('') if $text eq '';

	return _bad('must be ports or low-high ranges separated by commas, at most 20 entries')
		unless $text =~ /^[0-9]{1,5}(?:-[0-9]{1,5})?(?:,[0-9]{1,5}(?:-[0-9]{1,5})?){0,19}$/;

	my @expanded;
	my %seen;
	for my $entry (split(/,/, $text, -1)) {
		my ($low, $high) = split(/-/, $entry, 2);
		for my $number (defined $high ? ($low, $high) : ($low)) {
			return _bad('every port must be 1 to 65535 with no leading zero')
				unless $number =~ /^[1-9][0-9]{0,4}$/ && $number + 0 <= 65535;
		}
		$high = $low unless defined $high;
		return _bad('a range must be low-high') if $high + 0 < $low + 0;
		my $count = $high - $low + 1;
		return _bad('expands to ' . (scalar(@expanded) + $count) . ' ports, maximum 20')
			if scalar(@expanded) + $count > 20;
		for my $port ($low + 0 .. $high + 0) {
			return _bad("port $port is listed more than once") if $seen{$port}++;
			push @expanded, $port;
		}
	}
	return _bad('expands to ' . scalar(@expanded) . ' ports, maximum 20')
		if @expanded > 20;
	return _ok(join(',', @expanded));
}

# --- 4.4 note ---------------------------------------------------------------
sub validate_note {
	my ($value) = @_;
	return _bad('is required') unless _plain($value);
	my $text = as_chars("$value");
	return _bad('is not valid UTF-8') unless defined $text;
	return _bad('contains a control byte') if $text =~ /[\x00-\x1F\x7F]/;
	$text =~ s/^ +//;
	$text =~ s/ +$//;
	my $length = bytelen($text);
	return _bad('must not be empty') if $length == 0;
	return _bad('must be 200 bytes or fewer') if $length > 200;
	return _bad('must not contain "|"') if index($text, '|') >= 0;
	return _bad('must not look like a command-line option')
		if $text =~ /(?:^|\s)-[A-Za-z]/;
	return _ok($text);
}

# --- 4.5 which --------------------------------------------------------------
my %WHICH = map { $_ => 1 } qw(deny temp allow);

sub validate_which {
	my ($value) = @_;
	return _bad('is required') unless _plain($value);
	my $text = "$value";
	return _bad('must be one of deny, temp, allow') unless $WHICH{$text};
	return _ok($text);
}

# --- 4.6 offset and limit ---------------------------------------------------
sub validate_offset {
	my ($value) = @_;
	return _ok(0) unless defined $value;
	return _bad('must be a whole number') if ref $value;
	my $text = "$value";
	return _bad('must be a whole number') unless $text =~ /^[0-9]{1,7}$/;
	my $offset = $text + 0;
	return _bad('must be between 0 and 1000000') if $offset > 1000000;
	return _ok($offset);
}

sub validate_limit {
	my ($value) = @_;
	return _ok(100) unless defined $value;
	return _bad('must be a whole number') if ref $value;
	my $text = "$value";
	return _bad('must be a whole number') unless $text =~ /^[0-9]{1,3}$/;
	my $limit = $text + 0;
	return _bad('must be between 1 and 500') if $limit < 1 || $limit > 500;
	return _ok($limit);
}

# --- 4.7 filter -------------------------------------------------------------
#
# Never compiled as a pattern. Matched with index() on an ASCII-lowercased copy,
# so there is no regular expression to be pathological about.
sub validate_filter {
	my ($value) = @_;
	return _ok('') unless defined $value;
	return _bad('must be a string') if ref $value;
	my $text = as_chars("$value");
	return _bad('is not valid UTF-8') unless defined $text;
	return _bad('contains a control byte') if $text =~ /[\x00-\x1F\x7F]/;
	return _bad('must be 100 bytes or fewer') if bytelen($text) > 100;
	return _ok($text);
}

# --- 4.8 ids ----------------------------------------------------------------
sub validate_ids {
	my ($value) = @_;
	return _bad('is required') unless defined $value;
	return _bad('must be an array of ids') unless ref($value) eq 'ARRAY';
	return _bad('must contain between 1 and 500 ids')
		if @$value < 1 || @$value > 500;
	my %seen;
	my @ids;
	for my $id (@$value) {
		return _bad('every id must be 32 lowercase hex characters')
			unless _plain($id) && "$id" =~ /^[0-9a-f]{32}$/;
		return _bad('contains a duplicate id') if $seen{"$id"}++;
		push @ids, "$id";
	}
	return _ok(\@ids);
}

# --- 4.9 user ---------------------------------------------------------------
#
# A lookup key and nothing else. It never names a file and it carries no
# authority: a username in a message is not an identity (section 2.2, G8).
sub validate_user {
	my ($value) = @_;
	return _bad('is required') unless _plain($value);
	my $text = "$value";
	return _bad('must be 1 to 32 characters of a-z, 0-9, underscore or hyphen')
		unless $text =~ /^[a-z0-9_-]{1,32}$/;
	return _ok($text);
}

# --- 4.10 pass --------------------------------------------------------------
#
# No trimming and no normalisation: the bytes are compared as sent. No failure
# here ever quotes, measures or locates the value.
sub validate_pass {
	my ($value) = @_;
	return _bad('is required') unless _plain($value);
	my $text = as_chars("$value");
	return _bad('is not valid UTF-8') unless defined $text;
	return _bad('contains a control byte') if $text =~ /[\x00-\x1F\x7F]/;
	my $length = bytelen($text);
	return _bad('must not be empty') if $length < 1;
	return _bad('must be 1024 bytes or fewer') if $length > 1024;
	return _ok($text);
}

# --- 3.2 id -----------------------------------------------------------------
sub validate_id {
	my ($value) = @_;
	return _bad('is required') unless _plain($value);
	my $text = "$value";
	return _bad('must be 1 to 64 characters of A-Z, a-z, 0-9, dot, underscore, colon or hyphen')
		unless $text =~ /^[A-Za-z0-9._:-]{1,64}$/;
	return _ok($text);
}

1;
