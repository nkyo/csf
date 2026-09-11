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
# The Mode B listener (docs/WEBUI-RPC.md section 13): TLS termination, the
# IP allowlist, and the accept loop, for hosts with no front web server or
# where the administrator does not want csf touching one. This is the mode
# that reintroduces exactly the risk Mode A removes - a process of ours
# parsing HTTP from the network as the thing that answers the TLS
# handshake - which is why every refusal below is loud and every default is
# the strict one.
#
# What this module is not: it does not parse HTTP (ConfigServer::UI::HTTP
# does, from a filehandle this module hands it) and it does not route,
# authenticate, or decide roles (ui-src/bin/csf-ui's ConfigServer::UI::App
# does, from the request structure this module hands it after adding
# `peer`). Its own job is three refusals and one loop:
#
#   * refuse to start without IO::Socket::SSL, naming the package to
#     install - never falls back to plain HTTP (a firewall admin interface
#     served unencrypted is worse than one that will not start);
#   * refuse to start with an empty or missing UI_ALLOW - an unconfigured
#     allowlist means "nobody", not "everybody" (docs/WEBUI-RPC.md
#     section 10);
#   * refuse to start on any other malformed or contradictory ui.conf,
#     reading the full section 10 grammar as the strict gate
#     ui-src/bin/csf-ui's own ConfigServer::UI::App already documents it is
#     not (that module's own _read_ui_conf() is a lenient, non-refusing
#     fallback for its own two session-timeout keys - not a substitute for
#     the startup gate this process is);
#   * accept, check the allowlist BEFORE TLS ever begins (the cheapest
#     rejection for a peer that has no business being here at all), wrap in
#     TLS, hand the socket to ConfigServer::UI::HTTP, hand the parsed
#     request to ConfigServer::UI::App, write the response, close - one
#     request per connection, always, because this tier implements no
#     keep-alive at all.
#
# run() itself - the loop's own control flow, wired to a real accept() -
# is untested by design, the same way ui-src/bin/csf-ui-helper's own main()
# is not unit-tested by t/11-helper-validate.t: it needs a real listening
# socket, a real fork, and, in production, a real TLS library this
# workspace does not have installed, and it sits behind preflight(), which
# always refuses here for exactly that last reason. Everything the loop
# actually DOES with one connection is factored out into plain functions or
# functions that take their socket as an argument instead, precisely so
# each piece is testable without any of that: preflight(), read_ui_conf(),
# peer_allowed(), handle_connection(), _serve_accepted() (the per-connection
# TLS-wrap-then-serve step, watchdog included - task-5-review.md R31/R32)
# and _accept_backoff() (the accept()-failure policy - I2). t/40 and t/41
# exercise all of them directly, using socketpair()s in place of accept()ed
# connections and a fake `app` in place of ConfigServer::UI::App.
###############################################################################
package ConfigServer::UI::Server;

use strict;
use warnings;

use Socket ();
use POSIX ();
use Time::HiRes ();
use ConfigServer::UI::Proto ();
use ConfigServer::UI::HTTP  ();

our $VERSION = '1.00';

my $P = 'ConfigServer::UI::Proto';
my $H = 'ConfigServer::UI::HTTP';

our $DEFAULT_UI_CONF_PATH = '/etc/csf-ui/ui.conf';

# Server.pm's own operational choices, not part of docs/WEBUI-RPC.md - the
# document is explicit (section 14.4) that framing, TLS and everything
# below it is entirely this task's problem. Both are constructor-overridable
# for the same reason ui-src/bin/csf-ui-helper's own %LIMIT values are not:
# a test should not have to spin up 33 real connections to prove a cap of
# 32 refuses the 33rd.
our $DEFAULT_MAX_CHILDREN = 32;
our $DEFAULT_LISTEN_BACKLOG = 64;
our $DEFAULT_ACCEPT_BACKOFF = 0.1;

# task-5-review.md R36: the TLS handshake's own watchdog budget, separate
# from HTTP.pm's header/body/write timeouts (see _serve_accepted() below
# for why they must not share a pool). No row in docs/WEBUI-RPC.md prices
# this - the contract is silent on Mode B's TLS layer entirely (S14.4) - so
# this is reasoned from first principles rather than derived: a TLS
# handshake is a machine-to-machine negotiation with no human typing or
# reading in the loop, unlike the 15s HEADER_TIMEOUT HTTP.pm gives a client
# that has to formulate a request, so it does not need that much slack.
# What it does need is margin for a genuinely slow or lossy network path -
# a congested mobile link, a slow VPN, a retransmit or two - and a real
# handshake, even a bad one, completes in low single-digit seconds. 10s is
# an order of magnitude above that normal case (room for real network
# trouble) while staying well under HEADER_TIMEOUT's 15s (a handshake has
# less excuse to be slow than a human does) and short enough that a child
# stuck in a hostile silent handshake is reaped quickly - strictly faster
# than before this fix existed at all, when such a child held its slot for
# the full combined budget rather than only this one.
our $DEFAULT_HANDSHAKE_TIMEOUT = 10;

###############################################################################
# ui.conf (docs/WEBUI-RPC.md section 10)
#
# read_ui_conf($path) -> (\%conf, \@problems)
#
# On success: (\%conf, []) with every one of the six keys present (defaults
# already applied) and already validated - UI_ALLOW as a parsed arrayref of
# ConfigServer::UI::Proto::ip_info() structures, ready for peer_allowed()
# below, not as the raw string.
#
# On any problem at all: (undef, \@problems), one entry per problem found.
# Every rule in section 10 is enforced here, not only the four keys
# (UI_MODE, UI_LISTEN, UI_PORT, UI_ALLOW) this task's row in section 12's
# checklist names - this function is the one place ui.conf's file-level
# rules (unknown key, duplicate key, "a default applies only when the key
# is absent") can be enforced once, and ui-src/bin/csf-ui's own comment on
# its ConfigServer::UI::App::new() says outright that "that full contract
# belongs to Task 5's Server.pm, which actually IS the long-running
# process". UI_CRYPT_ROUNDS/UI_SESSION_IDLE/UI_SESSION_MAX are validated
# for the same reason: a value out of range should fail loudly here, not
# fall back silently to csf-ui's own default the way that module's lenient
# reading of its own two keys already documents it will.
###############################################################################
our @UI_CONF_KEYS = qw(UI_MODE UI_LISTEN UI_PORT UI_ALLOW UI_CRYPT_ROUNDS UI_SESSION_IDLE UI_SESSION_MAX);
my %KNOWN_KEY = map { $_ => 1 } @UI_CONF_KEYS;

sub read_ui_conf {
	my ($path) = @_;

	open(my $fh, '<', $path)
		or return (undef, ["ui.conf ($path) could not be read: $!"]);

	my %raw;
	my @problem;
	my $line_number = 0;
	while (my $line = <$fh>) {
		$line_number++;
		chomp $line;
		next if $line =~ /^\s*$/;
		next if $line =~ /^\s*#/;
		unless ($line =~ /^\s*([A-Z][A-Z0-9_]*)\s*=\s*"([^"]*)"\s*$/) {
			# A typo'd line must not be able to hide as "absent" - the same
			# reasoning section 10 itself gives for treating an unknown key
			# as a startup failure rather than silently ignoring it.
			push @problem, "ui.conf line $line_number does not match the KEY=\"VALUE\" grammar";
			next;
		}
		my ($key, $value) = ($1, $2);
		unless ($KNOWN_KEY{$key}) {
			push @problem, "ui.conf line $line_number: \"$key\" is not a recognised key";
			next;
		}
		if (exists $raw{$key}) {
			push @problem, "ui.conf line $line_number: \"$key\" is set more than once (last-one-wins is how a reviewer and a program disagree)";
			next;
		}
		$raw{$key} = $value;
	}
	close $fh;
	return (undef, \@problem) if @problem;

	my %conf;

	# UI_MODE - no default; missing or anything but exactly "a"/"b" refuses.
	if (!defined $raw{UI_MODE}) {
		push @problem, 'ui.conf: UI_MODE is required and must be "a" or "b"';
	}
	elsif ($raw{UI_MODE} ne 'a' && $raw{UI_MODE} ne 'b') {
		push @problem, 'ui.conf: UI_MODE must be exactly "a" or "b"';
	}
	else {
		$conf{UI_MODE} = $raw{UI_MODE};
	}

	# UI_LISTEN - a literal address only (Socket::inet_pton - never a
	# hostname, never a DNS lookup at startup, per G3), default 127.0.0.1.
	my $listen_text = defined $raw{UI_LISTEN} ? $raw{UI_LISTEN} : '127.0.0.1';
	my $listen_family = ($listen_text =~ /:/) ? Socket::AF_INET6() : Socket::AF_INET();
	my $listen_packed = eval { Socket::inet_pton($listen_family, $listen_text) };
	unless (defined $listen_packed) {
		push @problem, 'ui.conf: UI_LISTEN must be a literal IPv4 or IPv6 address, not a hostname';
	}
	else {
		$conf{UI_LISTEN} = $listen_text;
	}

	# UI_PORT - 1024-65535 (csfui can never bind below 1024), default 8443.
	my $port_text = defined $raw{UI_PORT} ? $raw{UI_PORT} : '8443';
	if ($port_text !~ /^[0-9]{1,5}\z/ || $port_text + 0 < 1024 || $port_text + 0 > 65535) {
		push @problem, 'ui.conf: UI_PORT must be a whole number from 1024 to 65535';
	}
	else {
		$conf{UI_PORT} = $port_text + 0;
	}

	# UI_ALLOW - no default; empty or missing refuses ("nobody", never
	# "everybody"); 1-64 entries, each per section 4.1 with neither the
	# mutating prefix floor nor the removal carve-out - ip_info() with no
	# options is exactly that: /0 is rejected, and no floor is applied.
	if (!defined $raw{UI_ALLOW} || $raw{UI_ALLOW} eq '') {
		push @problem, 'ui.conf: UI_ALLOW must not be empty - an unconfigured allowlist refuses to start rather than allow everyone';
	}
	else {
		my @entries = split(/,/, $raw{UI_ALLOW}, -1);
		if (@entries < 1 || @entries > 64) {
			push @problem, 'ui.conf: UI_ALLOW must have between 1 and 64 entries';
		}
		else {
			my @parsed;
			my $allow_problem = 0;
			for my $raw_entry (@entries) {
				my $entry = $raw_entry;
				$entry =~ s/^ +//;
				$entry =~ s/ +\z//;
				my $info = $P->can('ip_info')->($entry);
				if (!$info) {
					push @problem, "ui.conf: UI_ALLOW entry \"$raw_entry\" is not a valid address or CIDR";
					$allow_problem = 1;
				}
				else {
					push @parsed, $info;
				}
			}
			$conf{UI_ALLOW} = \@parsed unless $allow_problem;
		}
	}

	# UI_CRYPT_ROUNDS - not this task's own reader (csf-ui-passwd is), but
	# this is the strict gate for the file as a whole.
	my $rounds_text = defined $raw{UI_CRYPT_ROUNDS} ? $raw{UI_CRYPT_ROUNDS} : '100000';
	if ($rounds_text !~ /^[0-9]{1,7}\z/ || $rounds_text + 0 < 5000 || $rounds_text + 0 > 2000000) {
		push @problem, 'ui.conf: UI_CRYPT_ROUNDS must be a whole number from 5000 to 2000000';
	}
	else {
		$conf{UI_CRYPT_ROUNDS} = $rounds_text + 0;
	}

	# UI_SESSION_IDLE / UI_SESSION_MAX - csf-ui's own ConfigServer::UI::App
	# reads these too, leniently, falling back to both defaults together on
	# any problem (including IDLE > MAX) rather than refusing - that is the
	# right choice for a request-handling process that must not refuse to
	# serve a request over a bad session config, but it is not a substitute
	# for refusing to START with one.
	my $idle_text = defined $raw{UI_SESSION_IDLE} ? $raw{UI_SESSION_IDLE} : '1800';
	my $max_text  = defined $raw{UI_SESSION_MAX}  ? $raw{UI_SESSION_MAX}  : '43200';
	my ($idle_ok, $max_ok) = (0, 0);
	if ($idle_text =~ /^[0-9]{1,6}\z/ && $idle_text + 0 >= 60 && $idle_text + 0 <= 86400) {
		$conf{UI_SESSION_IDLE} = $idle_text + 0;
		$idle_ok = 1;
	}
	else {
		push @problem, 'ui.conf: UI_SESSION_IDLE must be a whole number from 60 to 86400';
	}
	if ($max_text =~ /^[0-9]{1,7}\z/ && $max_text + 0 >= 300 && $max_text + 0 <= 604800) {
		$conf{UI_SESSION_MAX} = $max_text + 0;
		$max_ok = 1;
	}
	else {
		push @problem, 'ui.conf: UI_SESSION_MAX must be a whole number from 300 to 604800';
	}
	if ($idle_ok && $max_ok && $conf{UI_SESSION_IDLE} > $conf{UI_SESSION_MAX}) {
		push @problem, 'ui.conf: UI_SESSION_IDLE must not be greater than UI_SESSION_MAX';
	}

	return (undef, \@problem) if @problem;
	return (\%conf, []);
}

###############################################################################
# preflight(%opt) -> @problems
#
# Every startup precondition this process owns, mirroring the shape
# ui-src/bin/csf-ui-helper's own preflight() already established: a list of
# human-readable problems, empty when it is safe to bind and listen. %opt:
# ui_conf_path (default $DEFAULT_UI_CONF_PATH).
###############################################################################
sub preflight {
	my (%opt) = @_;
	my $ui_conf_path = $opt{ui_conf_path} || $DEFAULT_UI_CONF_PATH;
	my @problem;

	push @problem, 'Perl 5.14 or later is required' unless $] >= 5.014;

	# G3, and docs/WEBUI-RPC.md section 1.2: this process is the
	# UNPRIVILEGED half of the split by design - it is the one parsing
	# bytes a network peer chose. Running it as root would not make it
	# safer; it would erase the entire reason the split exists.
	push @problem, 'this process must not run as root; it is the unprivileged half of the WebUI split and must run as the unprivileged web-tier user'
		if $> == 0;

	# The one dependency this task adds, and the one this whole module
	# refuses to run without: TLS via IO::Socket::SSL, never a plain-HTTP
	# fallback. Not installed in this workspace by design (G1) - this
	# branch is exercised for real by t/41-http-hostile.t, not mocked,
	# because a refusal that only a mock ever exercises is not proven.
	unless (eval { require IO::Socket::SSL; 1 }) {
		push @problem, 'IO::Socket::SSL is not installed; install it '
			. '(Debian/Ubuntu: libio-socket-ssl-perl; RHEL/CloudLinux/cPanel: perl-IO-Socket-SSL) '
			. 'so the standalone web UI can serve TLS - it never serves plain HTTP instead';
	}

	my ($conf, $problems) = read_ui_conf($ui_conf_path);
	if (@$problems) {
		push @problem, @$problems;
	}
	elsif ($conf->{UI_MODE} ne 'b') {
		# Section 10's own grammar only requires UI_MODE to be "a" or "b";
		# this process is specifically the mode-B listener, so a
		# syntactically valid "a" is still this process's own refusal to
		# start - it has nothing to bind, and mode A's listener is a front
		# web server this module is not.
		push @problem, 'ui.conf: UI_MODE is "a"; this is the mode-B standalone listener and does not run when a front web server serves the UI instead';
	}

	return @problem;
}

###############################################################################
# peer_allowed($peer_addr, $allow_list) -> 1 | 0
#
# $allow_list is the already-parsed UI_ALLOW arrayref read_ui_conf()
# returns (a list of ip_info() structures), not raw strings - parsed once
# at startup, not on every connection. $peer_addr is the connecting
# address, text form, exactly as accept() plus inet_ntop() produces it -
# never a header, per docs/WEBUI-RPC.md section 14.1's own words on `peer`.
#
# `removal => 1` on the PEER's own parse (not on the allowlist entries,
# which were already validated strictly by read_ui_conf()) admits the two
# addresses ip_info()'s IPv4-mapped rule would otherwise catch as a false
# positive - :: and ::1 - because a peer connecting from IPv6 loopback is a
# real, unremarkable case (docs/WEBUI-RPC.md R18 makes the identical
# argument for reading entries back out of csf's own files); it is not
# being granted any extra permission by this, only being parsed at all, and
# still has to match a configured entry, like anything else, to be let in.
###############################################################################
sub peer_allowed {
	my ($peer_addr, $allow_list) = @_;
	return 0 unless defined $peer_addr && length $peer_addr;
	return 0 unless ref($allow_list) eq 'ARRAY' && @$allow_list;

	my $peer_info = $P->can('ip_info')->($peer_addr, removal => 1);
	return 0 unless $peer_info;

	for my $entry (@$allow_list) {
		next unless $entry->{family} == $peer_info->{family};
		my $bytes = $entry->{bits} / 8;
		my $plen  = defined $entry->{plen} ? $entry->{plen} : $entry->{bits};
		my $mask  = _netmask($plen, $bytes);
		return 1 if ($peer_info->{packed} & $mask) eq ($entry->{packed} & $mask);
	}
	return 0;
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

###############################################################################
# Construction
#
# Every dependency a test needs to replace is injectable, the same pattern
# ui-src/bin/csf-ui's own ConfigServer::UI::App::new() and
# ui-src/lib/ConfigServer/UI/Client.pm already use:
#
#   app            a ConfigServer::UI::App instance (ui-src/bin/csf-ui).
#                  REQUIRED by run() - Server.pm does not know how to load a
#                  package that lives in a bin/ script rather than under
#                  lib/, and does not guess a path for it; whatever process
#                  starts the mode-B daemon owns requiring that file and
#                  constructing the App it passes in here. Tests pass a
#                  fake with a dispatch() method instead.
#   tls_wrap       coderef($plain_socket) -> $tls_socket | undef, called
#                  once per accepted, allowlisted connection, in the forked
#                  child, before ConfigServer::UI::HTTP ever sees the
#                  socket. Defaults to a real IO::Socket::SSL::start_SSL()
#                  wrapper built in run() (never constructed, and never
#                  needed, when a test supplies its own).
#   listener       a pre-built listening socket, for a test that wants to
#                  drive run()'s loop directly rather than only
#                  handle_connection(). Nothing in t/40 or t/41 needs this;
#                  it exists so a future integration test can, without
#                  needing root or a privileged port.
#   watchdog_exit      the $SIG{ALRM} handler _serve_accepted() installs -
#                      twice, once per phase (task-5-review.md R31, R36).
#                      Defaults to POSIX::_exit(1), matching every other
#                      early exit a forked child takes in this file; a test
#                      overrides it with something that dies instead, so it
#                      can prove the watchdog actually fired without
#                      killing the test process itself.
#   handshake_timeout  the TLS handshake's own watchdog budget - separate
#                      from header_timeout/body_timeout/write_timeout
#                      below (R36: seconds spent negotiating TLS must not
#                      be charged against the request's own deadlines, or a
#                      legitimate client on a slow link that fully uses
#                      each phase's real allowance can be killed having
#                      violated none of them). Defaults to
#                      $DEFAULT_HANDSHAKE_TIMEOUT.
###############################################################################
sub new {
	my ($class, %opt) = @_;
	return bless {
		ui_conf_path      => $opt{ui_conf_path} || $DEFAULT_UI_CONF_PATH,
		app               => $opt{app},
		tls_wrap          => $opt{tls_wrap},
		listener          => $opt{listener},
		max_children      => defined $opt{max_children} ? $opt{max_children} : $DEFAULT_MAX_CHILDREN,
		backlog           => defined $opt{backlog} ? $opt{backlog} : $DEFAULT_LISTEN_BACKLOG,
		accept_backoff    => defined $opt{accept_backoff} ? $opt{accept_backoff} : $DEFAULT_ACCEPT_BACKOFF,
		handshake_timeout => defined $opt{handshake_timeout} ? $opt{handshake_timeout} : $DEFAULT_HANDSHAKE_TIMEOUT,
		header_timeout    => defined $opt{header_timeout} ? $opt{header_timeout} : $ConfigServer::UI::HTTP::HEADER_TIMEOUT,
		body_timeout      => defined $opt{body_timeout}   ? $opt{body_timeout}   : $ConfigServer::UI::HTTP::BODY_TIMEOUT,
		write_timeout     => defined $opt{write_timeout}  ? $opt{write_timeout}  : $ConfigServer::UI::HTTP::WRITE_TIMEOUT,
		watchdog_exit     => $opt{watchdog_exit} || sub { POSIX::_exit(1) },
		allow             => $opt{allow} || [],
	}, $class;
}

###############################################################################
# handle_connection($self, $socket, $peer_addr)
#
# The whole of one request's handling, from an already-accepted, already
# allowlist-checked, already TLS-wrapped (in production; a test may hand
# this a plain socketpair half instead) filehandle through to a written
# response. Never dies, whatever goes wrong: a parse fault becomes the
# matching HTTP status (or, for a fault marked silent - a deadline that
# expired with nothing useful to say - no response at all, only a close);
# an app that fails to return a well-formed response becomes a 500, the
# same "a caller of dispatch() must never need its own eval to stay safe"
# promise ui-src/bin/csf-ui's own header comment makes, verified here
# rather than trusted.
#
# Does not close $socket - the caller (run(), or a test) owns the
# filehandle it handed in and decides when to close it, the same division
# ConfigServer::UI::Client and Proto.pm's read_message()/write_response()
# already keep.
###############################################################################
sub handle_connection {
	my ($self, $socket, $peer_addr) = @_;

	my $request = eval {
		$H->can('read_request')->($socket,
			header_timeout => $self->{header_timeout},
			body_timeout   => $self->{body_timeout});
	};
	if (my $error = $@) {
		if ($H->can('is_fault')->($error)) {
			$H->can('write_response')->($socket,
				$H->can('error_response')->($error->{status}, $error->{message}),
				timeout => $self->{write_timeout})
				unless $error->{silent};
		}
		else {
			$H->can('write_response')->($socket,
				$H->can('error_response')->(500, 'an internal error occurred'),
				timeout => $self->{write_timeout});
		}
		return;
	}
	return unless defined $request; # nothing was ever sent; close in silence

	$request->{peer} = $peer_addr;

	my $response = eval { $self->{app}->dispatch($request) };
	$response = $H->can('error_response')->(500, 'an internal error occurred')
		unless ref($response) eq 'HASH';

	$H->can('write_response')->($socket, $response, timeout => $self->{write_timeout});
	return;
}

###############################################################################
# The daemon. See the module header comment for why this is not exercised
# by t/40 or t/41 - it needs a real listening socket, a real fork, and, in
# production, a real TLS library.
###############################################################################
sub _open_listener {
	my ($conf) = @_;
	my $family = ($conf->{UI_LISTEN} =~ /:/) ? Socket::AF_INET6() : Socket::AF_INET();
	my $packed_addr = Socket::inet_pton($family, $conf->{UI_LISTEN})
		or die "Server.pm: UI_LISTEN ($conf->{UI_LISTEN}) will not pack for its own family\n";
	my $sockaddr = ($family == Socket::AF_INET6())
		? Socket::pack_sockaddr_in6($conf->{UI_PORT}, $packed_addr)
		: Socket::pack_sockaddr_in($conf->{UI_PORT}, $packed_addr);

	socket(my $listener,
		($family == Socket::AF_INET6() ? Socket::PF_INET6() : Socket::PF_INET()),
		Socket::SOCK_STREAM(), 0) or die "Server.pm: socket: $!\n";
	setsockopt($listener, Socket::SOL_SOCKET(), Socket::SO_REUSEADDR(), pack('l', 1));
	bind($listener, $sockaddr) or die "Server.pm: bind $conf->{UI_LISTEN}:$conf->{UI_PORT}: $!\n";
	listen($listener, $DEFAULT_LISTEN_BACKLOG) or die "Server.pm: listen: $!\n";
	return $listener;
}

sub _peer_text {
	my ($paddr) = @_;
	return undef unless defined $paddr;
	if (length($paddr) >= 28) {
		my (undef, $addr) = eval { Socket::unpack_sockaddr_in6($paddr) };
		return undef unless defined $addr;
		return lc(Socket::inet_ntop(Socket::AF_INET6(), $addr));
	}
	my (undef, $addr) = eval { Socket::unpack_sockaddr_in($paddr) };
	return undef unless defined $addr;
	return Socket::inet_ntop(Socket::AF_INET(), $addr);
}

# The certificate/key pair is not a docs/WEBUI-RPC.md section 2.3 or
# section 10 path - that document is silent on where Mode B's TLS material
# lives, and this task adds no new ui.conf key to name one (out of scope).
# This is Server.pm's own placement, inside the already-frozen
# /etc/csf-ui/ tree, pending confirmation from whichever task actually
# provisions the certificate (installer/wizard).
our $TLS_CERT_FILE = '/etc/csf-ui/ssl/cert.pem';
our $TLS_KEY_FILE  = '/etc/csf-ui/ssl/key.pem';

sub _default_tls_wrap {
	my ($socket) = @_;
	return IO::Socket::SSL->start_SSL($socket,
		SSL_server    => 1,
		SSL_cert_file => $TLS_CERT_FILE,
		SSL_key_file  => $TLS_KEY_FILE,
	);
}

###############################################################################
# _serve_accepted($self, $connection, $peer_addr)
#
# Everything a forked child of run()'s accept loop does with one accepted,
# already allowlist-checked connection: wrap it in TLS, verify the wrap
# actually produced TLS, hand it to handle_connection(), close. Extracted
# from run() so it is callable - and its watchdogs provable - without a
# real fork (task-5-review.md R31/R32/R36).
#
# BOUNDED, END TO END, BY TWO WATCHDOGS, NOT ONE (R31, then R36). HTTP.pm's
# own 15s-headers/15s-body deadlines are excellent, and they do not start
# until start_SSL() returns - a peer that completes the TCP handshake and
# then sends nothing, or an SSL handshake that never completes on either
# side, parks this child forever with nothing of this module's own making
# to stop it. Thirty-two such connections - $DEFAULT_MAX_CHILDREN, no more
# - permanently deny the admin UI: every slot is held by a child that will
# never exit, waitpid() never reaps them because they never exit, and every
# further peer, however legitimate, is refused at the "busy" check with no
# attacker having sent a single byte HTTP.pm would ever see. R31's original
# fix armed one alarm, sized to header_timeout + body_timeout +
# write_timeout summed, before the handshake even began - which closed the
# hang but opened a narrower version of the same problem the review caught
# as R36: the handshake was drawing from the SAME budget the request phase
# needs, so a legitimate client with non-trivial handshake latency, who
# then goes on to use close to its own allowance for headers, body and the
# response write, can be killed having violated no single per-phase
# deadline at all - a failure mode that could not exist before R31, because
# before it there was no deadline of any kind here.
#
# The fix is two alarms, each covering only what it is named for, with a
# clean handoff between them: $handshake_timeout (own reasoning at
# $DEFAULT_HANDSHAKE_TIMEOUT above) covers ONLY tls_wrap; that alarm is
# cancelled the instant it returns (success or failure), and only then, if
# the wrap produced real TLS, is a second alarm armed - the same
# header_timeout + body_timeout + write_timeout sum as before, now
# starting fresh rather than continuing to run down a clock the handshake
# already spent from. A peer stuck in either phase is still killed,
# promptly, by that phase's own budget; a peer that is merely slow, in
# either phase, and stays within it, is not.
#
# alarm()/$SIG{ALRM}, not this module's usual select()-based style:
# select() cannot interrupt a blocking call already inside
# IO::Socket::SSL's own handshake loop, which is exactly what needs
# interrupting here, and a signal-based watchdog in a forked child that
# does one job and then exits carries none of the risk alarm() would in the
# parent's accept loop - which is why that loop still avoids it entirely.
# Time::HiRes::alarm() rather than the builtin: the builtin truncates to
# whole seconds, which would make a test's short, injected timeouts (0.1s
# each) round down to "cancel the alarm" instead of "fire almost at once".
###############################################################################
sub _serve_accepted {
	my ($self, $connection, $peer_addr) = @_;

	local $SIG{ALRM} = $self->{watchdog_exit};

	Time::HiRes::alarm($self->{handshake_timeout});
	my $tls_socket = $self->{tls_wrap}
		? $self->{tls_wrap}->($connection)
		: _default_tls_wrap($connection);
	Time::HiRes::alarm(0); # handshake phase over (however it went); its budget does not carry forward

	# R32: tls_wrap is a constructor injection so tests never need a real
	# certificate or IO::Socket::SSL installed - but that makes it a seam
	# that can put a plaintext socket into this pipeline if it is only
	# ever trusted, never checked. Asserted here, where the socket is
	# about to be handed to HTTP.pm, not where it was injected.
	# UNIVERSAL::isa's function form (not a method call) is used because
	# a handshake failure some path other than undef can hand back
	# something that is not a blessed reference at all, and a method call
	# on that would die instead of simply failing the check.
	if ($tls_socket && UNIVERSAL::isa($tls_socket, 'IO::Socket::SSL')) {
		my $request_budget = $self->{header_timeout} + $self->{body_timeout} + $self->{write_timeout};
		Time::HiRes::alarm($request_budget); # a fresh budget for this phase alone (R36)
		$self->handle_connection($tls_socket, $peer_addr);
		Time::HiRes::alarm(0);
		close $tls_socket;
	}
	else {
		close $tls_socket if $tls_socket;
		close $connection;
	}

	return;
}

###############################################################################
# _accept_backoff($self, $is_eintr, $errno_text)
#
# The whole of run()'s accept()-failure policy, extracted so it is directly
# testable (task-5-review.md I2) the same way _serve_accepted() was
# extracted for R31/R32: run()'s own while loop cannot be driven from a
# test at all (it sits behind preflight(), which always refuses in this
# workspace because IO::Socket::SSL is not installed - G1), so the policy
# itself has to be reachable without going through accept() or preflight().
#
# EINTR means "a signal arrived, nothing is actually wrong", and the right
# answer is to return immediately so run() calls accept() again at once.
# Everything else - EMFILE/ENFILE from descriptor exhaustion (which a
# pile-up of children stuck in an unbounded TLS handshake, R31's other
# half, makes reachable), ECONNABORTED, or anything this loop has not seen
# before - is a real condition that will not clear itself between one
# accept() and the next, so retrying instantly would spin this loop as
# fast as the CPU allows, forever, with no line anywhere to say why the
# admin UI went unresponsive. Back off briefly and log once per occurrence.
###############################################################################
sub _accept_backoff {
	my ($self, $is_eintr, $errno_text) = @_;
	return if $is_eintr;
	print STDERR "csf-ui (Server.pm): accept() failed: $errno_text\n";
	select(undef, undef, undef, $self->{accept_backoff});
	return;
}

sub run {
	my ($self) = @_;

	my @problem = preflight(ui_conf_path => $self->{ui_conf_path});
	if (@problem) {
		print STDERR "csf-ui (Server.pm) refuses to start:\n";
		print STDERR "  - $_\n" for @problem;
		return 1;
	}
	die "Server.pm: run() requires an app instance (ConfigServer::UI::App); nothing here loads ui-src/bin/csf-ui on its own\n"
		unless ref($self->{app}) && $self->{app}->can('dispatch');

	require IO::Socket::SSL; # already proven to load, by preflight() above

	my ($conf) = read_ui_conf($self->{ui_conf_path});
	$self->{allow} = $conf->{UI_ALLOW};

	my $listener = $self->{listener} || _open_listener($conf);

	$SIG{PIPE} = 'IGNORE';
	my %child;
	my $running = 1;
	local $SIG{TERM} = sub { $running = 0 };
	local $SIG{INT}  = sub { $running = 0 };

	while ($running) {
		while ((my $done = waitpid(-1, POSIX::WNOHANG())) > 0) { delete $child{$done} }

		my $paddr = accept(my $connection, $listener);
		unless ($paddr) {
			# See _accept_backoff() above for the reasoning; kept as a
			# named, unit-testable policy rather than inline logic.
			$self->_accept_backoff($!{EINTR} ? 1 : 0, "$!");
			next;
		}

		my $peer_addr = _peer_text($paddr);
		# Checked BEFORE TLS: the cheapest possible rejection for a peer
		# with no business here at all, and one that never spends a TLS
		# handshake, let alone an HTTP parse, on an address the
		# administrator never listed.
		unless (defined $peer_addr && peer_allowed($peer_addr, $self->{allow})) {
			close $connection;
			next;
		}

		if (scalar(keys %child) >= $self->{max_children}) {
			close $connection; # busy; dropped rather than queued without bound
			next;
		}

		my $pid = fork();
		unless (defined $pid) {
			close $connection;
			next;
		}
		if ($pid) {
			$child{$pid} = 1;
			close $connection;
			next;
		}

		close $listener;
		$SIG{CHLD} = 'DEFAULT';
		$SIG{TERM} = 'DEFAULT';
		$SIG{INT}  = 'DEFAULT';

		$self->_serve_accepted($connection, $peer_addr);
		POSIX::_exit(0);
	}

	close $listener;
	return 0;
}

1;
