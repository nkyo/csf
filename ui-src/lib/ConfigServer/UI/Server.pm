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
# Extended 2026-09-12 with the Mode A listen path (ruling R82) - see the
# "Two transports, one loop" note below.
#
# The listener, in both of docs/WEBUI-RPC.md's deployment modes:
#
#   * Mode B (section 13): TLS termination, the IP allowlist, and the
#     accept loop on a TCP port, for hosts with no front web server or
#     where the administrator does not want csf touching one. This is the
#     mode that reintroduces exactly the risk Mode A removes - a process
#     of ours parsing HTTP from the network as the thing that answers the
#     TLS handshake - which is why every refusal below is loud and every
#     default is the strict one.
#
#   * Mode A (docs/WEBUI-PLAN.md section 4): a unix socket that a front
#     nginx/Apache/LiteSpeed proxies to (ui-src/dist/*.conf.tpl). The
#     front server terminates TLS, enforces UI_ALLOW, and parses HTTP
#     from the network first; this process never touches a network
#     socket at all.
#
# TWO TRANSPORTS, ONE LOOP (ruling R82). Mode A is a listen path in this
# module, not a second listener beside it. The accept loop, the child cap,
# the reaping, the accept backoff and the per-phase watchdogs are
# transport-agnostic and carry four rounds of review; a second copy of
# them would be a second copy of every bug those rounds removed. What the
# two modes genuinely do NOT share is exactly three things, and each is a
# named branch rather than a scattered `if`:
#
#   1. what is opened          _open_listener() vs _open_unix_listener()
#   2. who is admitted         admit_peer(), which is peer_allowed() on an
#                              IP in mode B and peercred()/peer_uid_allowed()
#                              on a kernel-supplied uid in mode A - the SAME
#                              point in run()'s sequence either way: after
#                              accept(), before fork(), before HTTP.pm has
#                              seen one byte
#   3. what wraps the socket   a TLS handshake in mode B; nothing at all in
#                              mode A, where TLS was already terminated by
#                              the front server one hop earlier
#
# WHAT MODE A DELIBERATELY DOES NOT DO, because reading it as an omission
# is the likely mistake:
#
#   * it does not enforce UI_ALLOW (section 10 says outright that in mode
#     A csf-ui does not; the front server does, from the same value - see
#     run() and admit_peer(), both of which say so at the point of the
#     non-enforcement rather than only here);
#   * it does not require IO::Socket::SSL, because there is no TLS in
#     this process in mode A (preflight());
#   * it does not bind a TCP port, and refuses a ui.conf that names one
#     (read_ui_conf(), section 10's "mode A and it is present").
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
# In mode A the first two of those refusals are different rather than
# absent - see preflight() for what replaces the IO::Socket::SSL demand,
# and admit_peer() for what replaces the allowlist check in the same slot.
#
# run() itself IS tested now, and this comment used to say the opposite
# (fix round 1, F6). The claim was true while mode A did not exist: run()
# needed a real listening socket, a real fork, and, in production, a real
# TLS library this workspace does not have, and it sat behind preflight(),
# which always refused here for exactly that last reason. Mode A removed
# the last of those - there is no TLS in this process in mode A, so
# preflight() does not demand IO::Socket::SSL - and commit 4d57037 then
# drove run() for the first time. t/40 drives its mode-A startup refusal;
# t/42-listen-loop.t drives the accept loop itself, over a real bound
# socket, with real accept()s and real forked children, including the child
# cap, the fork()-failure branch, the reaping order and the exit-time
# unlink.
#
# What remains true, and is the reason the factoring below is still worth
# having, is that everything the loop DOES with one connection is a plain
# function or a function that takes its socket as an argument: preflight(),
# read_ui_conf(), peer_allowed(), handle_connection(), _serve_accepted()
# (the per-connection TLS-wrap-then-serve step, watchdog included -
# task-5-review.md R31/R32) and _accept_backoff() (the accept()-failure
# policy - I2). t/40 and t/41 exercise all of them directly, using
# socketpair()s in place of accept()ed connections and a fake `app` in
# place of ConfigServer::UI::App - which is how the hostile-input table
# gets driven without a daemon at all.
###############################################################################
package ConfigServer::UI::Server;

use strict;
use warnings;

use Fcntl ();
use Socket ();
use POSIX ();
use Time::HiRes ();
use ConfigServer::UI::Proto  ();
use ConfigServer::UI::HTTP   ();
# For $DEFAULT_TIMEOUT only - the per-helper-call bound the request
# budget's dispatch term is derived from (F1). This module never makes an
# RPC call itself; ui-src/bin/csf-ui's App does, and already loads this.
use ConfigServer::UI::Client ();

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

# How often the accept loop's two SILENT drops may each put a line on
# stderr (fix round 1, F2). See _log_drop() for the whole reasoning; the
# number itself is a minute because that is short enough that an
# administrator watching `journalctl -fu csf-ui` while the UI misbehaves
# sees a line promptly, and long enough that a peer reconnecting as fast
# as the kernel allows cannot turn the log into the denial.
our $DEFAULT_DROP_LOG_INTERVAL = 60;

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
# THE DISPATCH TERM OF THE REQUEST BUDGET (fix round 1, F1).
#
# _serve_accepted() arms ONE alarm over the whole request phase, and that
# phase contains three things: HTTP.pm reading the request, the app's
# dispatch(), and HTTP.pm writing the response. Until this constant
# existed the budget was header_timeout + body_timeout + write_timeout and
# nothing else - which prices the first and the third and leaves the
# second at zero, while _serve_accepted()'s own comment already said in
# so many words that dispatch() is inside the budget and has no deadline
# of its own. The arithmetic and the comment disagreed, and the comment
# was right.
#
# MEASURED, not argued. With the 35s budget that sum produced, a peer
# that delivered its headers over 14s - legal, HEADER_TIMEOUT is 15 - and
# a dispatch() that took 30s had the watchdog fire at 35.0s. watchdog_exit
# is POSIX::_exit(1), so the administrator gets no response at all: not a
# 500, not a 504, nothing. That is precisely the spurious kill R36 was
# raised to remove, arriving through dispatch() rather than through the
# handshake.
#
# 30s is not a pathological dispatch(). ui-src/bin/csf-ui's
# _route_ui_overview() makes THREE sequential ConfigServer::UI::Client
# calls (status, counts, reconcile), each bounded by that module's own
# $DEFAULT_TIMEOUT of 10s and by nothing shorter, so a helper that is slow
# rather than broken - a reconcile over a large rule set, an iptables
# under load - reaches 30s without anything being wrong.
#
# DERIVED RATHER THAN PICKED, so that the two numbers it depends on cannot
# drift away from it silently:
#
#   * $ConfigServer::UI::Client::DEFAULT_TIMEOUT is the per-call bound.
#     Read from that module rather than copied, the same way
#     header_timeout/body_timeout/write_timeout below are read from
#     ConfigServer::UI::HTTP rather than restated here.
#   * $MAX_HELPER_CALLS_PER_REQUEST is the worst-case number of SEQUENTIAL
#     helper calls one route makes. Three today (_route_ui_overview; every
#     other route makes one), and four here on purpose: a fourth call
#     added to that route would otherwise make it unserviceable
#     unconditionally whenever the helper is merely slow, which is the
#     failure this whole block exists to stop being one commit away.
#
#     AND THE THREE IS NOW COUNTED RATHER THAN ASSERTED (fix round 2,
#     R108). t/40-http-parse.t derives the real maximum from
#     ui-src/bin/csf-ui - it attributes every `->{client}->call(` site to
#     the sub that encloses it and takes the largest per-sub count - and
#     compares it to this constant twice: the budget must price the code
#     (max <= this), and this constant must keep exactly the one-call
#     headroom the paragraph above claims for it (this == max + 1). The
#     second is the one that fires on the FOURTH call rather than waiting
#     for the fifth, and it names the sub that grew. It also refuses a
#     call site inside a LOOP, which counting sites cannot price at all.
#     Before that, the only check was `>= 3` with the 3 written out by
#     hand in the test - a restatement of this comment, not a check of
#     it, while Task 10 and Task 11 are both places new routes land.
#
# WHAT THIS IS NOT. It is not a deadline over dispatch() - there is still
# exactly one alarm over the request phase, and a route that hangs forever
# is still killed, now at the sum below instead of at 35s. Giving
# dispatch() a deadline of its own means per-phase clocks that are not the
# total clock, which is a restructuring of the watchdog rather than a term
# in it, and is not a thing to improvise in a fix round. The honest
# statement of what this change does is: the budget now prices every
# phase it covers, instead of two of the three.
###############################################################################
our $MAX_HELPER_CALLS_PER_REQUEST = 4;
our $DEFAULT_DISPATCH_TIMEOUT =
	$ConfigServer::UI::Client::DEFAULT_TIMEOUT * $MAX_HELPER_CALLS_PER_REQUEST;

###############################################################################
# THE FRONT SERVER'S BACKEND READ DEADLINE, WHICH THE BUDGET ABOVE HAD
# QUIETLY OUTGROWN (fix round 2, R106).
#
# In mode A the daemon is never the last word on whether a request
# succeeded: a front server is reading its response, and that server has a
# deadline of its own. Every template this tree ships set that deadline to
# 30s - nginx.conf.tpl's proxy_read_timeout, apache.conf.tpl's ProxyPass
# timeout=, litespeed.conf.tpl's initTimeout - while the budget above is
# 75s. Three numbers in three files with nothing comparing them.
#
# MEASURED, behind real front servers, against the real listener in mode A
# with a dispatch() of 44s (the figure F1's own fix makes serviceable):
#
#   nginx 1.24, proxy_read_timeout 30s   -> 504 Gateway Time-out at 30.03s
#   Apache 2.4.58, timeout=30            -> 502 Proxy Error   at 30.03s
#   nginx, proxy_read_timeout 80s        -> 200 OK            at 44.00s
#   Apache, ProxyPass timeout=80         -> 200 OK            at 44.00s
#
# So behind the shipped configuration the administrator got an error page
# either way - which is F1's own failure mode (a response the daemon was
# about to produce, discarded) displaced one hop outward. Fix round 1
# widened the gap from 5s to 45s rather than opening it: 35 > 30 already.
#
# THE FRONT SERVER MUST NEVER BE THE THING THAT GIVES UP FIRST. The
# daemon's watchdog is the deadline that knows what it is bounding; the
# front server only knows that nothing has arrived yet. So the number
# below is the budget PLUS a margin, and the margin's only job is to keep
# that order - enough for accept/scheduling delay on a loaded host, and
# deliberately the same 5s the templates already give their CONNECT step,
# so it is a figure this deployment already uses rather than a new one.
#
# WHY THE FULL BUDGET AND NOT THE SMALLER TIME A PROXY CAN ACTUALLY REACH.
# A front server that buffers the whole request before connecting spends
# the header and body phases on its own clock, not on this daemon's, so
# the reachable time through it is only dispatch + write = 45s. That is
# true, and MEASURED for nginx: headers dribbled over 14s then a 30s
# dispatch was served 200 at 44.01s against a proxy_read_timeout of only
# 35s, which it could not have been had those 14s been charged to this
# daemon. It is still the wrong number to assert, for two reasons that
# are the same reason. First it is not one number: Apache's mod_proxy_http
# streams a request BODY rather than spooling it, so the reachable time
# there is body + dispatch + write = 60s, and LiteSpeed's behaviour is
# unverified - one tighter figure would be wrong for at least one shipped
# front server. Second, all of it rests on a third-party default an
# operator can turn off in one documented line (proxy_request_buffering
# off) with nothing here to notice. docs/WEBUI-RPC.md's own rule is that a
# limit that cannot be counted is not a limit; the budget below is the
# only figure in this relation that can be counted from inside this tree.
# What the choice costs is slack on a HUNG UI - a browser waits for this
# daemon's own watchdog instead of for an answer the front server invented
# - and that is the cost worth paying.
#
# t/80-templates.t asserts all three templates carry exactly
# front_server_read_timeout(), so none of the numbers can move alone.
###############################################################################
our $FRONT_SERVER_TIMEOUT_MARGIN = 5;

# The package-level twin of _request_budget(), for the one caller that has
# no $self: the cross-file check in t/80-templates.t, which is comparing
# three shipped config files against the defaults a shipped daemon runs
# with. That test also asserts this equals a real object's
# _request_budget(), so the two sums cannot drift apart.
sub default_request_budget {
	return $ConfigServer::UI::HTTP::HEADER_TIMEOUT
		+ $ConfigServer::UI::HTTP::BODY_TIMEOUT
		+ $ConfigServer::UI::HTTP::WRITE_TIMEOUT
		+ $DEFAULT_DISPATCH_TIMEOUT;
}

sub front_server_read_timeout {
	return default_request_budget() + $FRONT_SERVER_TIMEOUT_MARGIN;
}

###############################################################################
# Mode A's transport constants. NONE of these is a ui.conf key, and none of
# them may become one: docs/WEBUI-RPC.md section 10 is a frozen table whose
# own rules say "adding a key means amending this table first", and this
# module is not the place that amendment gets made by accident. They are
# module constants in the same way $TLS_CERT_FILE/$TLS_KEY_FILE below
# already are for the other mode's out-of-contract material, and
# constructor-overridable so a test never has to be root or own /run.
#
# $DEFAULT_UNIX_SOCKET_PATH is NOT a free choice. It is the path three
# already-shipped files point at and nothing until now created:
# ui-src/dist/nginx.conf.tpl's proxy_pass, ui-src/dist/apache.conf.tpl's
# ProxyPass, and ui-src/dist/install-webui.sh's own `sock=` - which is in
# turn the path csf-ui.service's RuntimeDirectory=csf-ui-web creates the
# directory for. Four places, one string: t/80-templates.t asserts they
# still agree, because the whole reason mode A was inert is that a path
# can be written in several files and implemented in none.
#
# $UNIX_SOCKET_MODE is 0660, not 0666 and not whatever UMask= leaves
# behind. csf-ui.service sets UMask=0077, under which bind() would create
# the socket 0700 and the front server's worker - which is in the
# directory's group, not this process's uid - could never connect. That is
# a silent failure: the socket exists, the unit is "active", and every
# proxied request becomes a 502 with nothing in any log of ours. The mode
# is therefore set explicitly and then VERIFIED (see _open_unix_listener),
# the same way ui-src/bin/csf-ui-helper's own preflight() chmod()s its
# socket rather than trusting UMask=.
###############################################################################
our $DEFAULT_UNIX_SOCKET_PATH = '/run/csf-ui-web/csf-ui.sock';
our $UNIX_SOCKET_MODE = 0660;

# What _peer_text() answers for a unix peer. Deliberately not an address:
# it must never be mistaken for one, and it must never reach
# ConfigServer::UI::RateLimit as a rate-limit key - in mode A the key is
# the per-client address the front server states in $FRONT_PEER_HEADER
# (see peer_from_front()), and a constant here would collapse every
# visitor into one bucket, which docs/WEBUI-RPC.md section 14.1 forbids by
# name. This value exists for this module's own diagnostics; if it ever
# shows up in an access log, something is wrong and it says so plainly.
our $UNIX_PEER_TEXT = 'unix';

# The header every mode-A front-end template sets unconditionally from its
# own view of the connecting peer (nginx.conf.tpl:84 proxy_set_header,
# apache.conf.tpl:97 RequestHeader set, litespeed.conf.tpl:65
# extraHeaders). See peer_from_front() for why a header is the right - and
# the only - source for `peer` in this mode, and what makes it trustworthy.
our $FRONT_PEER_HEADER = 'x-real-ip';

# The bound on the passwd enumeration unix_peer_uids() falls back to; see
# there for when it runs at all (rarely) and why it is bounded.
our $MAX_PASSWD_SCAN = 20000;

###############################################################################
# ui.conf (docs/WEBUI-RPC.md section 10)
#
# read_ui_conf($path) -> (\%conf, \@problems, $mode_as_written)
#
# On success: (\%conf, [], $mode) with every one of the six keys present
# (defaults already applied) and already validated - UI_ALLOW as a parsed
# arrayref of ConfigServer::UI::Proto::ip_info() structures, ready for
# peer_allowed() below, not as the raw string.
#
# On any problem at all: (undef, \@problems, $mode_as_written), one entry
# per problem found.
#
# THE THIRD RETURN VALUE EXISTS BECAUSE A FILE CAN BE WRONG AND STILL SAY
# WHICH MODE IT IS (fix round 1, F10). It is UI_MODE exactly as the file
# wrote it when the file wrote it validly ("a" or "b"), and undef
# otherwise - which means UI_MODE absent, or present with any value that
# is not exactly "a" or "b".
#
# A DUPLICATED UI_MODE IS NOT ONE OF THOSE CASES, and this sentence used
# to claim it was (fix round 2). The duplicate is its own startup problem
# and the file is refused either way - but $mode_as_written holds the
# FIRST of the two values, because the duplicate check below leaves
# $raw{UI_MODE} at the first assignment, and this value is read from
# %raw. Measured: "a" then "b" yields mode-A preconditions and no TLS
# library demand; "b" then "a" yields mode-B's. The inline comment at the
# assignment said this correctly all along, and the two contradicted each
# other.
# It is NOT a fourth copy of the mode: %conf's UI_MODE remains the only
# value anything acts on when the file is sound, and this one exists only
# so preflight() can pick the right set of PRECONDITIONS to report
# alongside the problems, rather than defaulting to mode B's and telling a
# mode-A host to install a TLS library it has no use for. Read from %raw,
# before defaults, for the same reason UI_LISTEN's "present in mode A"
# rule is: once anything has been substituted in, "what the file said" is
# no longer recoverable.
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

	# What the file said about its own mode, usable even when the file is
	# otherwise unusable. Duplicated UI_MODE lines never get here (the
	# duplicate is a problem and $raw{UI_MODE} holds only the first), and
	# a value that is not exactly "a" or "b" is no answer at all.
	my $mode_as_written =
		(defined $raw{UI_MODE} && ($raw{UI_MODE} eq 'a' || $raw{UI_MODE} eq 'b'))
			? $raw{UI_MODE} : undef;

	return (undef, \@problem, $mode_as_written) if @problem;

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
	#
	# Section 10's "refuses to start when" column carries TWO rules for
	# this key, not one: "mode B and the value is unparsable", AND "mode A
	# and it is present" - "in mode A csf-ui listens on a unix socket and a
	# listen address means the config contradicts itself". Only the first
	# was ever implemented. The second needs something the default above
	# would hide: once '127.0.0.1' has been substituted in, a file that
	# SET UI_LISTEN="127.0.0.1" and a file that never mentioned the key at
	# all produce an identical %conf, so "present" has to be read from
	# %raw - before any default - and can never be inferred afterwards.
	# exists, not defined: section 10's own last rule is that "defaults
	# apply only to keys that are absent - an empty string is a value", so
	# UI_LISTEN="" in mode A is present, and contradicts, like any other
	# value.
	#
	# The refusal does not depend on whether the address would parse. An
	# unparsable address in mode A is first of all an address in a mode
	# that has none; answering "must be a literal IPv4 or IPv6 address"
	# would send the reader off to correct the wrong half of the problem
	# and leave the contradiction in place once they had.
	my $mode_is_a = (defined $conf{UI_MODE} && $conf{UI_MODE} eq 'a') ? 1 : 0;
	if ($mode_is_a && exists $raw{UI_LISTEN}) {
		push @problem, 'ui.conf: UI_LISTEN must not be set when UI_MODE is "a"; in mode A csf-ui listens on a unix socket that a front web server proxies to, and a listen address means the file contradicts itself';
	}
	else {
		my $listen_text = defined $raw{UI_LISTEN} ? $raw{UI_LISTEN} : '127.0.0.1';
		my $listen_family = ($listen_text =~ /:/) ? Socket::AF_INET6() : Socket::AF_INET();
		my $listen_packed = eval { Socket::inet_pton($listen_family, $listen_text) };
		unless (defined $listen_packed) {
			push @problem, 'ui.conf: UI_LISTEN must be a literal IPv4 or IPv6 address, not a hostname';
		}
		else {
			$conf{UI_LISTEN} = $listen_text;
		}
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

	return (undef, \@problem, $mode_as_written) if @problem;
	return (\%conf, [], $mode_as_written);
}

###############################################################################
# preflight(%opt) -> @problems
#
# Every startup precondition this process owns, mirroring the shape
# ui-src/bin/csf-ui-helper's own preflight() already established: a list of
# human-readable problems, empty when it is safe to bind and listen. %opt:
# ui_conf_path (default $DEFAULT_UI_CONF_PATH), socket_path (mode A only,
# default $DEFAULT_UNIX_SOCKET_PATH).
#
# THE PRECONDITIONS ARE PER MODE, and this function used to say so in the
# bluntest possible way: it refused outright whenever UI_MODE was not "b",
# because at the time that was the truth - mode A had no listener at all.
# That refusal is now a mode SELECTION, and the two modes' preconditions
# are genuinely different rather than one being a subset of the other:
#
#   mode B needs IO::Socket::SSL, and needs it so badly that it never
#   serves plain HTTP instead. Mode A must NOT demand it - there is no TLS
#   in this process in mode A, the front server terminated it one hop
#   earlier, and a hard dependency on a TLS library for a process that
#   opens no TLS socket would refuse to start a perfectly sound
#   deployment for a reason that does not apply to it.
#
#   mode A needs SO_PEERCRED, and needs it exactly as badly as mode B
#   needs TLS, for the same kind of reason: it is the ONLY identity a unix
#   socket carries. Without it this process cannot tell the front server
#   from any local user who found the socket, and every guarantee mode A
#   makes - the front server's UI_ALLOW, the front server's own view of
#   the client address - rests on being able to tell those apart. So it is
#   a startup refusal, never a runtime degradation, and there is no
#   fallback (G3). docs/WEBUI-RPC.md section 2.1 makes the identical
#   demand of the helper for the identical reason, and section 11.7 raised
#   the whole project's Perl floor to 5.14 to get it.
###############################################################################
sub preflight {
	my (%opt) = @_;
	my $ui_conf_path = $opt{ui_conf_path} || $DEFAULT_UI_CONF_PATH;
	my $socket_path  = $opt{socket_path}  || $DEFAULT_UNIX_SOCKET_PATH;
	my @problem;

	push @problem, 'Perl 5.14 or later is required' unless $] >= 5.014;

	# G3, and docs/WEBUI-RPC.md section 1.2: this process is the
	# UNPRIVILEGED half of the split by design - it is the one parsing
	# bytes a network peer chose. Running it as root would not make it
	# safer; it would erase the entire reason the split exists.
	push @problem, 'this process must not run as root; it is the unprivileged half of the WebUI split and must run as the unprivileged web-tier user'
		if $> == 0;

	# $conf is deliberately not bound: preflight() reports problems and
	# picks which set of PRECONDITIONS to report them with, and the mode
	# for that comes from $mode_as_written. See the ternary below for why
	# the arm that used to read $conf->{UI_MODE} could never run.
	my (undef, $problems, $mode_as_written) = read_ui_conf($ui_conf_path);
	push @problem, @$problems if @$problems;

	# WHICH MODE'S PRECONDITIONS TO REPORT ALONGSIDE THE CONFIG PROBLEMS.
	# The point of reporting any is that a file with problems should not
	# have to be fixed and the process started a second time before the
	# environment's own problems are even mentioned - the comment here
	# used to say exactly that, and then got the mode wrong (fix round 1,
	# F10): read_ui_conf() returns (undef, \@problems) on ANY failure, so
	# a file whose UI_MODE parsed perfectly was treated as mode B the
	# moment any OTHER key was wrong. Measured: a mode-A host with one
	# unrelated typo was told to install IO::Socket::SSL - which this
	# listener must never demand in mode A - and was never told about its
	# socket directory at all, producing precisely the two-round diagnosis
	# this paragraph claims to avoid.
	#
	# So the mode comes from what the FILE said, which read_ui_conf() now
	# hands back even when it refuses. Mode B remains the fallback for the
	# case where there genuinely is no answer - an unreadable file, a
	# missing or misspelled UI_MODE - because that is the mode this file
	# had when it was the only one, and because in that case neither set
	# of preconditions is more right than the other.
	# TWO ARMS, NOT THREE. There used to be a middle one -
	# `(!@$problems && $conf) ? $conf->{UI_MODE}` - and it was DEAD CODE
	# (fix round 2): $mode_as_written is undef only when UI_MODE was
	# absent or was not exactly "a"/"b", and read_ui_conf() pushes a
	# problem for every one of those cases, so @$problems can never be
	# empty at the moment that arm would be consulted. Proven by
	# replacing it with `die "UNREACHABLE"` and getting a full green run.
	# Removed rather than left looking load-bearing: an arm that cannot
	# run is an arm no reader can check, and it would have gone on
	# reassuring people that the good-file case was handled here when the
	# first arm is what handles it.
	my $mode = defined $mode_as_written ? $mode_as_written : 'b';

	if ($mode eq 'b') {
		# The one dependency this task adds, and the one mode B refuses to
		# run without: TLS via IO::Socket::SSL, never a plain-HTTP
		# fallback. Not installed in this workspace by design (G1) - this
		# branch is exercised for real by t/41-http-hostile.t, not mocked,
		# because a refusal that only a mock ever exercises is not proven.
		unless (eval { require IO::Socket::SSL; 1 }) {
			push @problem, 'IO::Socket::SSL is not installed; install it '
				. '(Debian/Ubuntu: libio-socket-ssl-perl; RHEL/CloudLinux/cPanel: perl-IO-Socket-SSL) '
				. 'so the standalone web UI can serve TLS - it never serves plain HTTP instead';
		}
	}
	else {
		push @problem, mode_a_preflight(socket_path => $socket_path);
	}

	return @problem;
}

###############################################################################
# mode_a_preflight(%opt) -> @problems
#
# Mode A's own startup preconditions, split out from preflight() so they
# are reachable from a test without a mode-A ui.conf on disk, and so that
# the list is readable as a list rather than as one arm of an if.
#
# Two families, and both of them are "this cannot work, and would fail
# silently if allowed to proceed":
#
#   IDENTITY. SO_PEERCRED must resolve, and must be usable. See
#   preflight()'s own comment for why this is a refusal and not a
#   degradation.
#
#   THE DIRECTORY THE SOCKET GOES IN. Not the socket - that does not exist
#   yet - but the directory that decides who can reach it, which in the
#   shipped deployment is csf-ui.service's RuntimeDirectory=csf-ui-web,
#   created 0750 csfui:csf-ui-sock before ExecStart runs. Three things have
#   to hold and each has a distinct failure:
#
#     * it exists and is a directory - otherwise bind() fails with ENOENT
#       at a moment when the message would be about a socket rather than
#       about the directory that is actually missing;
#     * this process owns it - a directory this process does not own is
#       one it cannot create a socket in, and (docs/WEBUI-RPC.md section
#       2.1 makes the same argument for the helper's own socket
#       directory) one where somebody else chooses where our socket lives;
#     * NEITHER the group write bit NOR the other write bit is set. This
#       read 0002 alone until fix round 1 (F3), which accepted 0770 and
#       0775 without a word - and the shipped socket is 0660 group-owned
#       by a group that has at least one OTHER member in it by design
#       (the front server's worker account; the installer puts it there).
#       So a group-writable directory hands that member exactly what the
#       other-write bit hands the world: unlink our socket, bind their own
#       in its place, and the front server proxies the administrator's
#       session - cookies and all - to a process running as somebody
#       else, which answers as the UI over the administrator's real TLS.
#       Demonstrated end to end by the round-1 review, not argued.
#       docs/WEBUI-RPC.md section 2.1's template for the identical hazard
#       on the helper's own socket directory already demands no group OR
#       other write bit; only this copy of it was weaker. The comment
#       above states the stake correctly and always did: "The mode of the
#       socket itself cannot defend against that; only the directory can."
#       The shipped 0750 csfui:csf-ui-sock still passes, which is the
#       point - the group bit that matters for REACHING the socket is on
#       the socket (0660), and the directory needs only to be traversable
#       by that group, never writable by it.
###############################################################################
sub mode_a_preflight {
	my (%opt) = @_;
	my $socket_path = $opt{socket_path} || $DEFAULT_UNIX_SOCKET_PATH;
	my @problem;

	# have_peercred is injectable for one reason: on every platform this
	# project supports the constants DO resolve (docs/WEBUI-RPC.md section
	# 2.1 states it as verified fact, and section 11.7 raised the Perl
	# floor to guarantee it), so the refusal below cannot be reached here
	# by any real configuration - and an unreachable refusal is an
	# unproven one. The detection itself is the two `defined &` checks;
	# what the injection makes provable is that the refusal fires and says
	# the right thing when the detection says no.
	my $have_peercred = defined $opt{have_peercred}
		? $opt{have_peercred}
		: (defined &Socket::SO_PEERCRED && defined &Socket::SOL_SOCKET) ? 1 : 0;
	unless ($have_peercred) {
		push @problem, 'this Socket module does not provide SO_PEERCRED; mode A cannot identify the process at the other end of its unix socket and will not start without it (Perl 5.14 or later with Socket 1.94 or later is required - docs/WEBUI-RPC.md section 11.7)';
	}

	my $directory = _socket_directory($socket_path);
	my @st = stat($directory);
	if (!@st) {
		push @problem, "the mode-A socket directory ($directory) does not exist or cannot be read; it is created by csf-ui.service's RuntimeDirectory=, so a missing one usually means this process was started outside its unit";
	}
	elsif (!-d _) {
		push @problem, "the mode-A socket directory ($directory) is not a directory";
	}
	else {
		push @problem, "the mode-A socket directory ($directory) is owned by uid $st[4], not by this process (uid $>); it cannot create its socket there"
			unless $st[4] == $>;
		push @problem, sprintf("the mode-A socket directory (%s) is mode %04o, which is writable by its group or by other; a local user who can write there could replace the socket the front web server connects to, and be handed the administrator's session", $directory, $st[2] & 07777)
			if ($st[2] & 0022);
	}

	return @problem;
}

# The directory a socket path lives in, without File::Basename (core, but
# one more thing to load for one line) and without assuming the path has a
# directory part at all.
sub _socket_directory {
	my ($path) = @_;
	return '.' unless defined $path && length $path;
	my $index = rindex($path, '/');
	return '.' if $index < 0;
	return '/' if $index == 0;
	return substr($path, 0, $index);
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
# MODE A'S PEER IDENTITY
#
# peercred($socket) -> ($pid, $uid, $gid) | ()
#
# The kernel's answer to "what is at the other end of this unix socket",
# and in mode A the ONLY answer there is: a unix socket carries no
# address, so there is nothing else to ask. docs/WEBUI-RPC.md section 2.2
# uses the identical call for the identical reason on the helper's socket,
# and states as verified fact that SO_PEERCRED is 17, SOL_SOCKET is 1 and
# the three-integer "iii" layout is correct on the target platform.
#
# Returns the empty list, never a partial answer, when getsockopt fails or
# the option comes back too short to unpack - the same "fewer than 3
# values means close immediately" row section 2.2's own table carries.
# Callers must treat the empty list as a refusal, not as "unknown".
#
# MEASURED, so the next reader knows which of these four early returns
# are load-bearing and which are not - and the two REASONS this comment
# used to give were both simply false, which matters more than the
# conclusion because a later editor would have acted on them (fix round 1,
# F7). The conclusion is unchanged: only ONE of the four is reachable on
# this platform, a filehandle that is not a socket, where getsockopt
# returns undef. All four are kept, because the cost of a wrong answer
# here is the entire mode-A identity check. The corrections:
#
#   * `defined $socket` was called redundant "because getsockopt on undef
#     returns undef too and the next line catches it". Measured: it does
#     not return anything - `getsockopt(undef, ...)` DIES ("Bad symbol for
#     filehandle"). The check is redundant only because of the eval around
#     the getsockopt below, which that sentence never mentioned, and which
#     is there for a different reason. Remove `defined $socket` and this
#     function returns () from inside the eval instead of from the guard;
#     remove the EVAL and it dies. Neither is a thing to do by accident.
#
#   * unpack() on a short string was said to "pad with undef, which is
#     exactly the partial answer a caller would then read as a uid".
#     Measured: it does neither. unpack('iii', <2 bytes>) returns a
#     0-element list; unpack('iii', <8 bytes>) returns a 2-element list.
#     It TRUNCATES - it never produces an undef element - which is why
#     the guard that catches a short option is the `@credential == 3`
#     count, not a `defined` test on the elements. The separate `defined
#     $credential[1]` check below is therefore belt-and-braces over a case
#     unpack cannot produce, and is kept as such rather than as the thing
#     that catches truncation.
#
# The 12-byte and 3-value checks remain genuinely unreachable on Linux,
# which is the only platform with SO_PEERCRED, so no test enters them -
# and that is recorded as an exception in CHANGES.md rather than left to
# look verified.
###############################################################################
sub peercred {
	my ($socket) = @_;
	return () unless defined $socket;
	return () unless defined &Socket::SO_PEERCRED && defined &Socket::SOL_SOCKET;

	my $packed = eval { getsockopt($socket, Socket::SOL_SOCKET(), Socket::SO_PEERCRED()) };
	return () unless defined $packed;
	return () if length($packed) < 12; # three 32-bit ints; anything shorter is not an answer

	my @credential = unpack('iii', $packed);
	return () unless @credential == 3;
	return () unless defined $credential[1];
	return @credential;
}

###############################################################################
# unix_peer_uids($gid, %opt) -> \%uid_is_accepted
#
# THE ACCEPTED SET, AND WHY IT IS DERIVED RATHER THAN CONFIGURED.
#
# docs/WEBUI-RPC.md section 10 is frozen, so there is no ui.conf key
# naming the front web server's account and this module must not invent
# one. It does not need one: the deployment has already stated the answer
# twice, in the only two places that actually decide who can connect.
#
#   * The socket is 0660 and group-owned by the group that gates it -
#     csf-ui-sock in the shipped install, which exists for exactly this
#     one purpose and gates nothing else (install-webui.sh's
#     create_account()/grant_socket_group(), csf-ui.service's Group=).
#     The installer adds the detected front server's worker account to
#     that group and nothing else to it, so the group's membership IS the
#     list of accounts the administrator's install designated.
#   * The kernel already enforces that list on connect(). This check is
#     not a substitute for the file mode; it is the second, independent
#     gate for the cases the mode cannot cover - a directory or socket
#     relaxed by hand, and root, which bypasses mode bits entirely.
#
# WHY SECTION 2.2'S uid==0 RULE IS NOT COPIED HERE. That rule is
# csf-ui-helper's, and it is right there: the helper's only legitimate
# peer is csf-ui, so root arriving at the helper's socket is always
# something other than the caller it exists for, and "if root wants to run
# csf, root runs csf" disposes of it completely. Neither half of that
# transfers. This socket's legitimate peer is the front server's worker
# account, which is never root, so root is not rejected for being root -
# it is simply not in a set derived from group membership, exactly like
# any other uid the install did not designate. The difference matters in
# the one case where the two rules disagree: an administrator whose front
# server genuinely runs its workers as root (uncommon, and its own
# problem, but real) can put root in the socket group and have it work,
# where a copied uid==0 rule would refuse forever and say only "root".
#
# THREE WAYS IN, cheapest first, each with a distinct reason:
#
#   1. the peer's uid is this process's own. It owns the socket; the file
#     mode admits it; and a process already running as this uid holds the
#     session store and the rate-limit state, so refusing it would protect
#     nothing it could not simply take.
#   2. the peer's gid, as SO_PEERCRED reports it, is the socket's gid.
#     The case it exists FOR is the primary-gid account, which the member
#     list cannot see: getgrgid()'s member list names only supplementary
#     members, so an account created with the socket group as its primary
#     group appears nowhere in it - while the kernel admits it on exactly
#     that group bit. Checked per connection from the credentials
#     themselves, so it costs no NSS lookup at all.
#
#     WHAT IT ADMITS IS WIDER THAN THAT, and saying only "primary gid"
#     understates it (fix round 2). SO_PEERCRED reports the peer's
#     EFFECTIVE gid, not its primary one, so this way admits ANY account
#     whose egid equals the socket's gid at the moment it connected -
#     which every member of that group can arrange for itself with one
#     setegid(), and which root can arrange whatever its groups are.
#     Measured: peer_uid_allowed(3003, 4242) is 1 for an account that is
#     not in the group at all, and peer_uid_allowed(0, 4242) is 1. The
#     root half of this is already stated in CHANGES.md; this is the
#     general form of it. It is kept anyway, for the reason F4 resolved
#     it on: the alternative refuses a legitimate primary-gid front
#     server and tells its operator to add the account to a group it is
#     already in. The accounts it widens to are ones that can reach the
#     socket through the group bit in the first place, so the set is
#     bounded by the same group the install designated.
#   3. the peer's uid is in the socket group's member list, resolved once
#     at startup (section 2.2 resolves its own uid once at startup for
#     the same reason: an NSS lookup per connection is a dependency on a
#     name service in the request path).
#
# THE PASSWD SCAN, and why it is in the failure path only. run() refuses
# to start when the accepted set contains nobody but this process - that
# is the shape of an install whose grant_socket_group() never found a
# front-server account, where every proxied request becomes a 502 with
# nothing in any log of ours. But "the member list is empty" is not proof
# of that, because of case 2 above. So before that refusal can be
# concluded, and ONLY then, the passwd database is enumerated to look for
# an account whose primary group is the socket's group. It is bounded
# ($MAX_PASSWD_SCAN) because getpwent() over a directory-backed NSS is
# not guaranteed to be either fast or finite, and a startup that hangs in
# NSS is worse than one that refuses.
#
# THE BOUND IS REACHABLE WITH THE ANSWER STILL INSIDE IT, and this comment
# used to claim the opposite - "the bound is only ever reached on a host
# where the answer was already 'no local account'" (fix round 1, F9).
# Demonstrated false: with the bound at 3 and the target account 26th of
# 27, the function returned nothing, run() refused with "has no other
# member", and the account WAS in the group. getpwent() returns NSS order,
# which no caller chooses, and csf's market is shared hosting with account
# counts well past any bound worth setting. So the bound stays - a hang in
# NSS is still worse than a refusal - but truncation is now REPORTED
# (the `report` out-parameter below), and run()'s refusal says outright
# that the search stopped early rather than asserting a membership fact it
# did not establish.
#
# THE `report` OUT-PARAMETER. %opt may carry report => \%hash, which is
# filled in with what was actually consulted: the gid, whether a group
# with it exists, its name, how many members its list named, whether the
# passwd scan ran, and whether it was truncated. It exists because run()'s
# startup refusal has to describe a set that has several distinct ways of
# coming back empty, and a message that picks one of them and states it as
# fact is worse than no message (F8). Nothing branches on it; it is
# diagnosis only.
###############################################################################
sub unix_peer_uids {
	my ($gid, %opt) = @_;

	my $report = ref($opt{report}) eq 'HASH' ? $opt{report} : {};
	%$report = (
		gid            => $gid,
		group_found    => 0,
		group_name     => undef,
		members_named  => 0,
		scan_ran       => 0,
		scan_truncated => 0,
	);

	my $self_uid = defined $opt{self_uid} ? $opt{self_uid} : $> + 0;
	my %uid = ($self_uid => 1);
	return \%uid unless defined $gid;

	my $group_lookup = $opt{group_lookup} || sub { return getgrgid($_[0]) };
	my $name_lookup  = $opt{name_lookup}  || sub { return getpwnam($_[0]) };

	my @group = $group_lookup->($gid);
	if (@group) {
		$report->{group_found} = 1;
		$report->{group_name}  = $group[0];
		my $members = defined $group[3] ? $group[3] : '';
		for my $name (split(/\s+/, $members)) {
			next unless length $name;
			$report->{members_named}++;
			my @passwd = $name_lookup->($name);
			next unless @passwd && defined $passwd[2];
			$uid{ $passwd[2] + 0 } = 1;
		}
	}

	# Only when the member list produced nobody but ourselves: see the
	# header comment for why this cannot be skipped and why it is bounded.
	return \%uid if grep { $_ != $self_uid } keys %uid;

	my $passwd_scan = $opt{passwd_scan} || \&_primary_group_members;
	$report->{scan_ran} = 1;
	for my $found ($passwd_scan->($gid, report => $report)) {
		$uid{ $found + 0 } = 1;
	}
	return \%uid;
}

# EXACTLY $MAX_PASSWD_SCAN ENTRIES ARE CONSIDERED, and this used to be
# $MAX_PASSWD_SCAN + 1 fetched with the last one thrown away (F9: `last if
# ++$seen > $MAX_PASSWD_SCAN` tests the bound after the read that already
# happened). The read is now inside the bound and the bound is the loop
# condition, so the count in the log and the count actually examined are
# the same number.
#
# ONE probe past the bound, whose only purpose is to say so. Truncation
# cannot be detected without knowing whether there was more, and the
# alternative - reporting truncation whenever the bound was merely
# reached - would put "the search stopped early" in run()'s refusal on
# every host whose passwd database happens to be exactly $MAX_PASSWD_SCAN
# long. That probe's result is used for nothing else.
sub _primary_group_members {
	my ($gid, %opt) = @_;
	my $report = ref($opt{report}) eq 'HASH' ? $opt{report} : {};
	my @uid;
	my $seen = 0;
	setpwent();
	while ($seen < $MAX_PASSWD_SCAN) {
		my @passwd = getpwent();
		last unless @passwd;
		$seen++;
		next unless defined $passwd[3] && $passwd[3] == $gid;
		push @uid, $passwd[2];
	}
	$report->{scanned} = $seen;
	$report->{scan_truncated} = ($seen >= $MAX_PASSWD_SCAN && scalar(getpwent())) ? 1 : 0;
	endpwent();
	return @uid;
}

###############################################################################
# peer_uid_allowed($self, $uid, $gid) -> 1 | 0
#
# The three ways in from unix_peer_uids()' header comment, applied to one
# connection's credentials. Fails closed on anything missing: an undefined
# uid, or a set that was never built, is a refusal rather than a pass.
###############################################################################
sub peer_uid_allowed {
	my ($self, $uid, $gid) = @_;
	return 0 unless defined $uid;

	return 1 if defined $self->{self_uid} && $uid == $self->{self_uid};
	return 1 if defined $gid && defined $self->{socket_gid} && $gid == $self->{socket_gid};

	return 0 unless ref($self->{peer_uids}) eq 'HASH';
	return $self->{peer_uids}{$uid} ? 1 : 0;
}

###############################################################################
# peer_from_front($request) -> $address_text | undef
#
# WHERE `peer` COMES FROM IN MODE A, which is the one place this design
# has to reason its way out of an apparent contradiction in the contract
# rather than simply obey it.
#
# docs/WEBUI-RPC.md section 14.1 binds whoever fills in `peer` with two
# rules: (1) it must be per-connecting-client, never a constant, or
# RateLimit.pm's per-address cap collapses into one bucket where a handful
# of failed logins from any one visitor locks out every visitor; and (2)
# it must never come from a client-supplied header that this tier treats
# as trusted. On a unix socket those two rules have no common answer on
# their face: the transport carries no client address at all, so the only
# possible source of a per-client value is a header - and rule 2 appears
# to forbid exactly that.
#
# It does not, and the word doing the work is "client-supplied". The
# header is not the client's here. Every front-end template this project
# ships sets it unconditionally from the front server's own view of the
# connecting peer, overwriting whatever the client sent
# (nginx.conf.tpl:84, apache.conf.tpl:97, litespeed.conf.tpl:65 - all
# three carry the same comment saying so). So the value is the front
# server's statement, not the client's, and the whole question reduces to
# a single one: is the thing that connected actually that front server?
#
# That question is what admit_peer()'s SO_PEERCRED check answers, before
# this function is ever reached, and it is why that check is mandatory
# rather than defence in depth. Without it a local unprivileged user
# connects to the socket directly, is never seen by the front server's
# UI_ALLOW at all, and writes whatever X-Real-IP they like into the
# rate-limit key and the access log - which is to say, picks which other
# visitor gets locked out, and whose address the audit trail blames.
#
# The refusals below all fall closed to "no peer", never to a default,
# and handle_connection() turns that into a 400 rather than serving the
# request with an invented address. A front server that does not send the
# header is a front server that has not been configured to this module's
# contract; serving it anyway would mean either a constant `peer` (rule 1
# broken, silently) or an empty one (which ui-src/bin/csf-ui already
# refuses one layer in, with a worse message).
###############################################################################
sub peer_from_front {
	my ($request) = @_;
	return undef unless ref($request) eq 'HASH';
	return undef unless ref($request->{headers}) eq 'HASH';

	my $value = $request->{headers}{$FRONT_PEER_HEADER};
	return undef unless defined $value && !ref($value) && length $value;

	# A character-class pre-filter for the shapes a proxy chain, a
	# bracketed IPv6 literal, an address with a port, an IPv6 zone index
	# and a CIDR all take - none of which section 14.1 permits ("no port,
	# no brackets", and a prefix is not one client).
	#
	# MEASURED, so this comment neither overstates nor understates its own
	# guard. Four of those five are ALSO refused by ip_info() below on its
	# own: inet_pton is strict, and ip_info's own \x21-\x7E rule catches
	# the space in a comma-joined chain. The fifth is not. A prefix -
	# "203.0.113.0/24" - is something ip_info() with removal => 1
	# deliberately ACCEPTS, so the only things standing between a front
	# server's header and a whole subnet arriving as one client's identity
	# are this line and the plen check further down. They are load-bearing
	# AS A PAIR: remove either alone and the CIDR is still refused by the
	# other; remove both and it is accepted. So the pair is verified by
	# removing both together - each alone reddens nothing, and that is a
	# fact about their overlap, not about their necessity.
	return undef if $value =~ /[^0-9A-Fa-f:.]/;

	# removal => 1 for the same reason peer_allowed() uses it on a peer:
	# it admits :: and ::1, which are real, unremarkable source addresses
	# for a front server on the same host and which ip_info()'s
	# IPv4-mapped rule would otherwise catch as a false positive (R18). It
	# grants nothing - this value is a rate-limit key and a log line, not
	# a permission.
	my $info = $P->can('ip_info')->($value, removal => 1);
	return undef unless $info;

	# A prefix is not one client. removal => 1 accepts /0, and a front
	# server has no business sending any prefix at all, so the whole
	# question is settled by refusing every one of them rather than by
	# reasoning about which are harmless. The other half of the pair the
	# character-class filter above describes: either one of the two
	# refuses a CIDR, and both are kept because either could reasonably be
	# the one a later edit relaxes.
	return undef if defined $info->{plen};

	# The canonical form, not the bytes as sent: two spellings of one IPv6
	# address must not become two rate-limit buckets and two kinds of line
	# in the access log.
	return $info->{canonical};
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
#   mode           'a' or 'b'. NOT a free choice at runtime: run() always
#                  overwrites it from ui.conf, which is the single place
#                  the mode is decided (ui-src/bin/csf-ui's own entry
#                  point says the same thing about not re-deciding it).
#                  The constructor argument exists so a test can exercise
#                  a mode-specific path - admit_peer(), handle_connection(),
#                  _serve_accepted() - without a ui.conf and without run().
#                  Defaults to 'b', which is the mode this file had when
#                  it was the only one.
#   socket_path    mode A's unix socket. Defaults to
#                  $DEFAULT_UNIX_SOCKET_PATH; overridden by tests, which
#                  own neither /run nor root.
#   self_uid       this process's uid, resolved once. Injectable only so a
#                  test can construct a peer that is deliberately NOT this
#                  process without needing a second account to run as.
#   socket_gid     mode A: the gid the socket is group-owned by, which is
#                  what the kernel checks its 0660 group bit against.
#                  Normally read off the socket run() just bound, never
#                  guessed from the process's egid or the directory.
#   peer_uids      mode A: the accepted uid set. run() derives it from
#                  socket_gid (unix_peer_uids()) unless one was injected,
#                  the same "an injected dependency wins" rule tls_wrap,
#                  watchdog_exit and listener above already follow.
#   listen_family  mode B: the family of the listener this module opened,
#                  passed to _peer_text() so a peer address is unpacked by
#                  what it IS rather than by how long it happens to be.
#                  Deliberately left undef for an injected listener, whose
#                  family this module did not choose and must not assert.
###############################################################################
sub new {
	my ($class, %opt) = @_;
	return bless {
		ui_conf_path      => $opt{ui_conf_path} || $DEFAULT_UI_CONF_PATH,
		app               => $opt{app},
		tls_wrap          => $opt{tls_wrap},
		listener          => $opt{listener},
		mode              => (defined $opt{mode} && $opt{mode} eq 'a') ? 'a' : 'b',
		socket_path       => defined $opt{socket_path} ? $opt{socket_path} : $DEFAULT_UNIX_SOCKET_PATH,
		self_uid          => defined $opt{self_uid} ? $opt{self_uid} + 0 : $> + 0,
		socket_gid        => $opt{socket_gid},
		peer_uids         => $opt{peer_uids},
		listen_family     => $opt{listen_family},
		refused_logged    => {},
		drop_logged       => {},
		max_children      => defined $opt{max_children} ? $opt{max_children} : $DEFAULT_MAX_CHILDREN,
		backlog           => defined $opt{backlog} ? $opt{backlog} : $DEFAULT_LISTEN_BACKLOG,
		accept_backoff    => defined $opt{accept_backoff} ? $opt{accept_backoff} : $DEFAULT_ACCEPT_BACKOFF,
		drop_log_interval => defined $opt{drop_log_interval} ? $opt{drop_log_interval} : $DEFAULT_DROP_LOG_INTERVAL,
		handshake_timeout => defined $opt{handshake_timeout} ? $opt{handshake_timeout} : $DEFAULT_HANDSHAKE_TIMEOUT,
		dispatch_timeout  => defined $opt{dispatch_timeout}  ? $opt{dispatch_timeout}  : $DEFAULT_DISPATCH_TIMEOUT,
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

	# docs/WEBUI-RPC.md section 14.1's `peer`, and the one field whose
	# source differs between the two modes. In mode B it is the address
	# accept() reported, already checked against UI_ALLOW before this
	# connection was ever forked for. In mode A accept() reports no
	# address at all and the front server states the client's instead -
	# see peer_from_front() for why a header is both the only possible
	# source and a sound one, and for what makes it sound (admit_peer()'s
	# SO_PEERCRED check, which has already run by the time we are here).
	if ($self->{mode} eq 'a') {
		my $front_peer = peer_from_front($request);
		unless (defined $front_peer) {
			# Refused, not defaulted. A front server that did not state
			# the client's address has not been configured to this
			# module's contract, and the two things this could do instead
			# are both worse: a constant would collapse every visitor into
			# one rate-limit bucket (section 14.1 forbids it by name), and
			# an empty string is refused by ui-src/bin/csf-ui one layer in
			# anyway, with a message that cannot say what is actually
			# wrong because by then nothing knows.
			$H->can('write_response')->($socket,
				$H->can('error_response')->(400,
					"this server is behind a front web server, which must send the connecting client's address in a $FRONT_PEER_HEADER header"),
				timeout => $self->{write_timeout});
			return;
		}
		$request->{peer} = $front_peer;
	}
	else {
		$request->{peer} = $peer_addr;
	}

	my $response = eval { $self->{app}->dispatch($request) };
	$response = $H->can('error_response')->(500, 'an internal error occurred')
		unless ref($response) eq 'HASH';

	$H->can('write_response')->($socket, $response, timeout => $self->{write_timeout});
	return;
}

###############################################################################
# The daemon's own mode-B listener. This one genuinely is not exercised by
# the suite - it binds a TCP port, which the mode-A cases below deliberately
# never need - but the loop it feeds no longer is: see the module header
# comment, and t/42-listen-loop.t (fix round 1, F6; this comment said run()
# was untested long after commit 4d57037 had driven it).
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

###############################################################################
# _peer_text($paddr, $family) -> $text | undef
#
# THE UNIX CASE IS ITS OWN CASE, not a fallthrough - which is what it was,
# and what made every mode-A connection fail silently before the mode
# existed to fail. The shape of that bug is worth keeping written down,
# because it is the shape a "just add a transport" change naturally has:
# this function used to decide between IPv6 and IPv4 by the LENGTH of the
# sockaddr (>= 28 meant v6), with IPv4 as the else-branch. accept() on a
# unix socket returns a sockaddr of 2 bytes for the usual client that
# never bound an address of its own, so a unix peer took the IPv4 branch,
# unpack_sockaddr_in() died inside its eval, and the function returned
# undef - which run() then fed to the allowlist, which refused it, which
# closed the connection. Every unix connection, silently, with nothing
# logged anywhere and a 502 at the front server.
#
# So the family is now an ARGUMENT, supplied by whoever opened the
# listener and therefore actually knows, rather than inferred from a byte
# count. The length heuristic survives only as the fallback for a caller
# that passes nothing (the injected-listener path, which has no family to
# report), and Socket::sockaddr_family() is consulted first when this
# Socket provides it - so even that fallback recognises a unix sockaddr
# rather than mistaking it for a truncated IPv4 one.
#
# A unix peer's answer is the constant $UNIX_PEER_TEXT, never the path
# from the sockaddr even when the peer bound one: that path is text the
# peer chose, it would reach this module's own diagnostics, and there is
# nothing it could be used for that is worth carrying peer-controlled
# text to say it. The real per-client address in mode A arrives later and
# elsewhere (peer_from_front()).
###############################################################################
sub _peer_text {
	my ($paddr, $family) = @_;
	return undef unless defined $paddr;

	$family = _sockaddr_family($paddr) unless defined $family;

	if (defined $family) {
		return $UNIX_PEER_TEXT if $family == Socket::AF_UNIX();
		if ($family == Socket::AF_INET6()) {
			my (undef, $addr) = eval { Socket::unpack_sockaddr_in6($paddr) };
			return undef unless defined $addr;
			return lc(Socket::inet_ntop(Socket::AF_INET6(), $addr));
		}
		if ($family == Socket::AF_INET()) {
			my (undef, $addr) = eval { Socket::unpack_sockaddr_in($paddr) };
			return undef unless defined $addr;
			return Socket::inet_ntop(Socket::AF_INET(), $addr);
		}
		return undef;
	}

	if (length($paddr) >= 28) {
		my (undef, $addr) = eval { Socket::unpack_sockaddr_in6($paddr) };
		return undef unless defined $addr;
		return lc(Socket::inet_ntop(Socket::AF_INET6(), $addr));
	}
	my (undef, $addr) = eval { Socket::unpack_sockaddr_in($paddr) };
	return undef unless defined $addr;
	return Socket::inet_ntop(Socket::AF_INET(), $addr);
}

# Socket::sockaddr_family() when this Socket has it, undef otherwise -
# never a hand-rolled unpack of sa_family_t, whose width and whether it is
# preceded by a length byte are platform details this module has no
# business guessing at (G3's "no regex fallback for address parsing" is
# the same argument one layer down).
sub _sockaddr_family {
	my ($paddr) = @_;
	return undef unless defined $paddr && length($paddr) >= 2;
	return undef unless defined &Socket::sockaddr_family;
	my $family = eval { Socket::sockaddr_family($paddr) };
	return defined $family ? $family : undef;
}

###############################################################################
# _open_unix_listener($path, %opt) -> ($listener, $gid)
#
# Mode A's transport, and the four things that have to be true for the
# front server's worker to reach a socket here and for nobody else to.
# Every one of them was verified against a real socket rather than
# reasoned about, because three of the four fail SILENTLY - the socket
# exists, the unit is active, and the only symptom is a 502 from a process
# that logged nothing.
#
# 1. A STALE SOCKET IS AN EADDRINUSE, NOT AN OVERWRITE. bind() to a path
#    that already exists fails; it does not replace what is there. In the
#    shipped deployment systemd removes csf-ui.service's RuntimeDirectory
#    (and therefore the socket inside it) on every stop, so the path is
#    normally fresh - but that is a property of one unit file, not of this
#    code, and it does not hold for a hand-rolled start, a host without
#    systemd, or RuntimeDirectoryPreserve=. So the stale socket is removed
#    here, under the rule docs/WEBUI-RPC.md section 2.1 already states for
#    the helper's own socket - never unlink an arbitrary path:
#    _unlink_stale_socket() unlinks only a socket, only one this process
#    owns, and follows no symlink to get there.
#
# 2. THE MODE IS SET, NOT INHERITED. csf-ui.service sets UMask=0077, under
#    which bind() creates the socket 0700 and the front server's worker -
#    which reaches it through the directory's GROUP, not through this
#    process's uid - can never connect. The umask is narrowed rather than
#    widened around the bind (so a loose inherited umask cannot produce a
#    world-writable socket even for the instant before the chmod), and the
#    mode is then set explicitly to $UNIX_SOCKET_MODE.
#
# 3. THE MODE IS THEN CHECKED. A chmod() that returned success on a
#    filesystem that did not honour it would leave exactly the silent
#    failure this whole function exists to prevent, so the mode is read
#    back off the bound socket and disagreement is fatal.
#
# 4. listen() COMES LAST. Between bind() and chmod() the socket is
#    stricter than intended, never looser, and nothing can connect to it
#    at all until listen() - so the window is fail-closed on both counts
#    rather than being a moment when the wrong peers could get in.
#
#    IT IS NOT FAIL-CLOSED AGAINST A SECOND DAEMON, though, and that is
#    worth naming here rather than only in a review (fix round 2, I3).
#    The stale-socket probe in _socket_is_live() answers "is anybody
#    listening", and between the bind() above and this listen() the
#    answer for THIS socket is no - so a second daemon starting inside
#    that window reads our socket as stale, unlinks it and binds its own,
#    and both processes survive: F14's failure, through the window F14's
#    own fix opens. The SEQUENTIAL case - the one that actually happens,
#    a second start against an already-running daemon - is closed, and
#    that is what F14 claimed. Closing this one means publishing the
#    socket atomically: bind() at a temporary path in the same directory,
#    chmod and listen() there, then rename() over the final path, so the
#    path never names a socket that is not yet listening. That is a
#    restructuring of this function rather than a term in it, and is not
#    a thing to improvise in a fix round; recorded, not done.
#
# Returns the listener and the socket's own gid, which is what the kernel
# checks the 0660 group bit against and therefore what unix_peer_uids()
# must derive the accepted set from - not the directory's gid, and not
# this process's egid, either of which could differ from it (a setgid
# directory, a changed unit file) and would then describe a different set
# of accounts than the one that can actually connect.
###############################################################################
sub _open_unix_listener {
	my ($path, %opt) = @_;
	my $backlog = defined $opt{backlog} ? $opt{backlog} : $DEFAULT_LISTEN_BACKLOG;

	# sun_path is 108 bytes on Linux and shorter on some other platforms;
	# pack_sockaddr_un() truncates silently rather than failing, which
	# would bind a socket at a path nothing else names.
	die "Server.pm: the mode-A socket path ($path) is too long for a unix socket address\n"
		if length($path) > 100;

	_unlink_stale_socket($path, self_uid => $opt{self_uid});

	socket(my $listener, Socket::PF_UNIX(), Socket::SOCK_STREAM(), 0)
		or die "Server.pm: socket(AF_UNIX): $!\n";

	my $previous_umask = umask(0177);
	my $bound = bind($listener, Socket::pack_sockaddr_un($path));
	my $bind_error = $!;
	umask(defined $previous_umask ? $previous_umask : 0022);
	die "Server.pm: bind $path: $bind_error\n" unless $bound;

	unless (chmod($UNIX_SOCKET_MODE, $path)) {
		my $chmod_error = $!;
		unlink($path);
		die "Server.pm: chmod on $path: $chmod_error\n";
	}

	my @st = stat($path);
	unless (@st) {
		my $stat_error = $!;
		unlink($path);
		die "Server.pm: stat on the socket just bound at $path: $stat_error\n";
	}
	unless (($st[2] & 07777) == $UNIX_SOCKET_MODE) {
		unlink($path);
		die sprintf("Server.pm: %s is mode %04o after chmod, not %04o; the front web server could not reach it\n",
			$path, $st[2] & 07777, $UNIX_SOCKET_MODE);
	}

	unless (listen($listener, $backlog)) {
		my $listen_error = $!;
		unlink($path);
		die "Server.pm: listen on $path: $listen_error\n";
	}

	return ($listener, $st[5]);
}

# docs/WEBUI-RPC.md section 2.1's "an existing socket owned by uid 0 (then
# it is unlinked) - never unlink an arbitrary path", with the owner the
# only thing that changes: this process is not root and must not be, so
# "owned by uid 0" becomes "owned by us". lstat, not stat, and -S on the
# lstat buffer: a symlink at this path is refused rather than followed,
# because following one would unlink whatever it pointed at.
#
# AND "STALE" NOW MEANS STALE (fix round 1, F14). The two checks above ask
# "is this a socket" and "is it ours" and the word in the function's name
# asks a third question they do not: is anybody LISTENING on it. Measured
# without it: starting a second daemon on the same path left TWO alive -
# the second serving every request, the first permanently orphaned, still
# holding a listening socket nothing can reach, its own child cap and its
# own file descriptors, with no EADDRINUSE anywhere and no way for it to
# notice or exit. csf-ui.service prevents this by being a single unit; a
# hand-rolled start, a second unit, or a non-systemd host does not.
#
# The probe is a non-blocking connect(), which is the only thing that
# actually answers the question - a socket file says nothing about whether
# a process is behind it. Non-blocking rather than plain: connect() to a
# live unix socket whose backlog is full would otherwise block here, in
# startup, waiting on the very daemon we are about to decide the fate of.
#
# FAIL CLOSED ON "CANNOT TELL". A refusal names its remedy and costs one
# manual `rm`; guessing wrong in the other direction orphans a running
# daemon silently, which is the thing being fixed.
sub _unlink_stale_socket {
	my ($path, %opt) = @_;
	my $self_uid = defined $opt{self_uid} ? $opt{self_uid} + 0 : $> + 0;

	my @st = lstat($path);
	return 0 unless @st;

	die "Server.pm: $path already exists and is not a socket; refusing to unlink it\n"
		unless -S _;
	die "Server.pm: the socket at $path is owned by uid $st[4], not by this process (uid $self_uid); refusing to unlink it\n"
		unless $st[4] == $self_uid;

	my $live = defined $opt{socket_is_live}
		? $opt{socket_is_live}->($path)
		: _socket_is_live($path);
	if (!defined $live) {
		die "Server.pm: could not determine whether anything is listening on $path ($!);"
			. " refusing to unlink it. Remove it by hand once you have confirmed no csf-ui is running.\n";
	}
	if ($live) {
		die "Server.pm: something is already listening on $path; refusing to unlink it."
			. " Another csf-ui is running (systemctl status csf-ui) - unlinking its socket would"
			. " leave that process alive and unreachable, holding its connection slots and file"
			. " descriptors with no way to notice or exit. Stop it instead of starting a second one.\n";
	}

	unlink($path) or die "Server.pm: could not remove the stale socket at $path: $!\n";
	return 1;
}

# 1 = something is listening, 0 = nothing is, undef = could not tell (and
# $! is left set for the caller's message).
#
# socket_is_live is injectable above for the same reason self_uid is: it
# lets a test drive the DECISION the probe feeds without depending on
# what the host's kernel does. It is NOT because the "could not tell" arm
# is unreachable from a test - this comment used to say "which no test can
# arrange on a path it owns", and that is false (fix round 2). chmod 0000
# on a socket this process owns makes connect() fail with EACCES, which is
# neither ECONNREFUSED nor ENOENT nor EAGAIN/EINPROGRESS, so it lands in
# exactly this arm - and t/40-http-parse.t now does that, against a real
# socket, in four lines. The refusal it produces is a startup refusal that
# did not exist before fix round 1, so an unreached arm there was an
# unproven refusal.
sub _socket_is_live {
	my ($path) = @_;
	socket(my $probe, Socket::PF_UNIX(), Socket::SOCK_STREAM(), 0) or return undef;

	# Non-blocking, so a live socket with a full backlog answers the
	# question instead of blocking startup on it.
	my $flags = fcntl($probe, Fcntl::F_GETFL(), 0);
	fcntl($probe, Fcntl::F_SETFL(), $flags | Fcntl::O_NONBLOCK()) if defined $flags;

	my $connected = connect($probe, Socket::pack_sockaddr_un($path));
	my $errno = $!;
	close $probe;

	return 1 if $connected;
	# ECONNREFUSED is the answer for a socket file with no listener behind
	# it - the actual stale case. ENOENT means it went away between the
	# lstat above and here, which is also "nothing is listening".
	return 0 if $errno == POSIX::ECONNREFUSED() || $errno == POSIX::ENOENT();
	# A full backlog on a LIVE socket. Still a listener.
	return 1 if $errno == POSIX::EAGAIN() || $errno == POSIX::EINPROGRESS();
	$! = $errno;
	return undef;
}

###############################################################################
# admit_peer($self, $connection, $paddr) -> $peer_text | undef
#
# THE SAME SLOT IN THE SEQUENCE, IN BOTH MODES. run() calls this
# immediately after accept() returns and before anything else happens to
# the connection: before the child cap is consulted, before fork(), before
# TLS, and - the property that matters - before ConfigServer::UI::HTTP has
# seen a single byte. That ordering is deliberate in mode B and is stated
# as such in run(); it must not quietly become something weaker in mode A,
# which is exactly the risk in porting a listener to a transport that has
# no IP address to check.
#
# Because THE ALLOWLIST CHECK IS NOT MOVED IN MODE A - it is REPLACED, in
# place, by a different question with the same three properties. Mode B
# asks "is this address one the administrator listed", from accept()'s own
# report, never a header. Mode A asks "is this the front web server's
# account", from the kernel's own SO_PEERCRED answer, never a header. Both
# are: (1) evaluated at the same point, (2) answerable without parsing
# anything the peer wrote, and (3) fail-closed on an answer that is
# missing or unrecognised. What mode A must never do is drop the check
# here and lean on something later - a rate limiter, an authentication
# form, ui-src/bin/csf-ui's own routing - because all of those are things
# that happen AFTER this process has already read and parsed bytes chosen
# by whoever connected, and being able to refuse before that is the whole
# value of the slot.
#
# UI_ALLOW IS DELIBERATELY NOT CONSULTED IN THE MODE-A BRANCH, and this
# is the reason, kept here at the point of the non-enforcement rather than
# only in run(): docs/WEBUI-RPC.md section 10 says "UI_ALLOW in mode A is
# not enforced by csf-ui - in mode A csf-ui listens on a unix socket and
# the peer address it sees is the front web server". Checking it here
# would be checking the front server's own uid against a list of visitor
# IP addresses, which cannot match and would refuse every request. The
# same value IS enforced in mode A - by the front server, from the
# template Task 9 renders it into (nginx.conf.tpl's allow/deny include,
# apache.conf.tpl's RequireAny, litespeed.conf.tpl's accessControl) -
# which is why the key is still mandatory and still non-empty in this
# mode. run() sets $self->{allow} to undef in mode A so that this is a
# fact about the object and not only a fact about this branch.
###############################################################################
sub admit_peer {
	my ($self, $connection, $paddr) = @_;

	if ($self->{mode} eq 'a') {
		my ($pid, $uid, $gid) = peercred($connection);
		unless (defined $uid) {
			$self->_refuse_peer(undef,
				'the kernel would not report SO_PEERCRED for a connection on the unix socket, so there is no identity to check');
			return undef;
		}
		unless ($self->peer_uid_allowed($uid, $gid)) {
			$self->_refuse_peer($uid,
				"uid $uid connected to the unix socket but is not an account that may reach it; add the front web server's worker account to the group that owns the socket, and nothing else to that group");
			return undef;
		}
		return _peer_text($paddr, Socket::AF_UNIX());
	}

	my $peer_addr = _peer_text($paddr, $self->{listen_family});
	return undef unless defined $peer_addr;
	return undef unless peer_allowed($peer_addr, $self->{allow});
	return $peer_addr;
}

# One line per DISTINCT refusal, not one per refused connection. A refusal
# that said nothing at all would leave an administrator whose front server
# is not in the socket's group with a 502 and no way to find out why - the
# silent-failure class this whole mode was reviewed for. A refusal that
# logged every attempt would hand any local user who can see the socket an
# unbounded write into this process's journal. Keying on the uid keeps the
# diagnostic (which account was turned away, once) and bounds the volume
# by the number of accounts on the host rather than by the number of
# attempts.
sub _refuse_peer {
	my ($self, $uid, $why) = @_;
	my $key = defined $uid ? "uid:$uid" : 'no-credentials';
	return if $self->{refused_logged}{$key}++;
	print STDERR "csf-ui (Server.pm): refused a connection on the mode-A unix socket: $why\n";
	return;
}

###############################################################################
# _no_local_peer_message($self, $report) -> $text - fix round 1, F8.
#
# run() refuses to start when nothing but this process can reach the mode-A
# socket, and the refusal used to be one sentence for a condition that has
# several distinct causes:
#
#   "no account other than this one can reach the mode-A socket: group
#    1000, which owns it, has no other member."
#
# Three things wrong with it, all of them the same kind of wrong - it
# asserted what the code had not established:
#
#   * it printed a numeric GID where it told the operator to add an account
#     to a GROUP. unix_peer_uids() had already called getgrgid() and had
#     the name in its hand; `usermod -aG 1000` is not the command anybody
#     runs, and on a host where the gid and the name disagree with the
#     operator's expectation the number is the least useful half.
#   * it said "has no other member" from a set that can come back empty in
#     at least four distinct ways: the group has genuinely no other member;
#     no group with that gid exists at all; the passwd scan stopped at its
#     bound before reaching an account that IS in the group (F9); or the
#     set was handed to this process directly and no group was ever
#     consulted.
#   * measured on that last path: with peer_uids injected it printed "has
#     no other member" although getgrgid() was never called, and
#     socket_gid is undef there, so it read "group (unknown), which owns
#     it".
#
# So the message is now assembled from what was actually consulted, and
# each cause names its own remedy. The report comes from
# unix_peer_uids()'s `report` out-parameter; an absent one means
# unix_peer_uids() never ran, which is exactly the injected-set case.
###############################################################################
sub _no_local_peer_message {
	my ($self, $report) = @_;
	my $lead = 'no account other than this one can reach the mode-A socket: ';
	my $remedy = " Add the front web server's worker account to that group"
		. " (the installer's own grant_socket_group() does this) and start again.";

	unless (ref($report) eq 'HASH' && exists $report->{gid}) {
		return $lead
			. 'the accepted set this process was given names only its own account.'
			. ' That set was supplied directly rather than derived from the group that owns'
			. " the socket, so no group on this host was consulted and there is nothing"
			. ' this process can name as the thing to change.';
	}

	unless (defined $report->{gid}) {
		return $lead
			. 'the group that owns the socket could not be determined, so no account could be'
			. ' derived from it. This normally means the socket was not created by this process'
			. " (csf-ui.service's Group= is what decides that group).";
	}

	my $gid = $report->{gid};
	unless ($report->{group_found}) {
		my $text = $lead
			. "gid $gid owns the socket, but no group with that gid exists on this host, so its"
			. ' membership could not be read at all. Create that group, or correct'
			. " csf-ui.service's Group=, and add the front web server's worker account to it.";
		# AND THE TRUNCATION NOTICE BELONGS HERE TOO (fix round 2). This
		# branch used to return before reaching it, so an operator whose
		# passwd scan stopped at its bound on THIS path was told to create
		# a group while an account holding that gid as its primary group
		# may well exist past the bound - which is F9's defect exactly,
		# left in one of the four arms F8 split the message into. A gid
		# with no group entry is precisely a host where the primary-gid
		# account is the only way in, so it is the arm where the
		# distinction matters most.
		$text .= " The search for an account with gid $gid as its PRIMARY group also stopped"
			. " after the first $MAX_PASSWD_SCAN entries of the local account database without"
			. ' reaching the end, so such an account may exist and simply was not found.'
			. " Check with this before changing anything: getent passwd | awk -F: '\$4 == $gid'"
			if $report->{scan_truncated};
		return $text;
	}

	my $name = defined $report->{group_name} ? $report->{group_name} : '(unnamed)';
	my $text = $lead . "$name (gid $gid), the group that owns it, names no member other than"
		. ' this account';
	if ($report->{scan_truncated}) {
		# The one case where the refusal must NOT be stated as a fact about
		# the group: the search that would have found a primary-gid member
		# stopped before the end of the account database (F9).
		$text .= ", and the search for an account with $name as its PRIMARY group stopped after"
			. " the first $MAX_PASSWD_SCAN entries of the local account database without"
			. ' reaching the end - so such an account may exist and simply was not found.'
			. " Check with this before changing anything: getent passwd | awk -F: '\$4 == $gid'";
		return $text;
	}
	if ($report->{scan_ran}) {
		$text .= ", and no local account has $name as its primary group either";
	}
	return $text . '.' . $remedy;
}

###############################################################################
# _log_drop($self, $kind, $why) - fix round 1, F2.
#
# THE TWO SILENT PATHS IN THE ACCEPT LOOP, AND WHY THEY WERE THE WRONG TWO
# TO LEAVE SILENT. _accept_backoff() logs. _refuse_peer() logs. The busy
# drop and the fork() failure logged nothing at all - and those are exactly
# the two an attacker drives. Measured at max_children=4: four connections
# that send nothing occupy all four slots (each for the 15s HTTP.pm's own
# absolute header deadline allows, which is CORRECT and is not changed
# here), three consecutive legitimate requests were each dropped in about
# 15ms with an empty response, and the daemon's stderr was zero bytes.
# Sustainable indefinitely by reconnecting. The operator could not tell a
# busy UI from a broken one, because from outside both are a 502 at the
# front server and nothing anywhere else.
#
# RATE-LIMITED BY TIME, NOT DEDUPED PER LIFETIME, which is where this
# departs from _refuse_peer() on purpose. _refuse_peer()'s key is an
# ACCOUNT: the set is bounded by the host's passwd database, and the same
# account turned away twice really is the same fact, so once per lifetime
# says everything there is to say (measured: 327,711 refused connects in
# 6s changed nothing). "Busy" has no such key. A busy minute this morning
# and a busy minute next week are different operational facts, and a
# once-ever line answers the first while hiding the second - which is the
# same silence this is fixing, only harder to notice. So the bound is a
# window, and the line carries how many drops the window suppressed, so
# that the scale is in the log rather than only the fact.
#
# WHAT THIS DELIBERATELY DOES NOT DO:
#
#   * it does not write a 503 to the dropped peer. That write happens in
#     the PARENT, between accept() and the next accept(), and would put a
#     bounded-but-real blocking write into the one loop in this module
#     that must never block: a front server slow to read would then stall
#     accept() itself, turning a partial denial into a total one. The
#     front server already renders an unanswered connection as a 502; what
#     was missing was never the peer's diagnosis, it was the operator's.
#   * it does not raise max_children. The cap is the defence, not the
#     defect - without it the same four silent connections become as many
#     children as the host has processes.
#   * it does not shorten the slot hold time. THAT IS NO LONGER
#     HTTP.pm's absolute header deadline, and this bullet said it was
#     (fix round 2). It was true when written; F1 made it false in the
#     same round, because the binding constraint on how long one
#     connection can hold a slot is now _serve_accepted()'s REQUEST
#     BUDGET - one alarm over reading, dispatch() and writing together -
#     and HTTP.pm's own header deadline is only the first term of it.
#     Measured worst case for a single connection: 35.00s at 261221c,
#     58.03s at e20ea61, against an arithmetic ceiling of
#     _request_budget() = 75s. So a peer that holds a slot holds it for
#     longer than it used to, and max_children is the only thing bounding
#     how many can do it at once. Capping that is a design decision about
#     the watchdog rather than a term in it - the same reasoning F1 gave
#     for not giving dispatch() a deadline of its own - and is parked
#     deliberately. What this bullet must not do is go on claiming a
#     shorter ceiling than the code has.
###############################################################################
sub _log_drop {
	my ($self, $kind, $why) = @_;
	my $state = $self->{drop_logged}{$kind} ||= { suppressed => 0, last => undef };
	$state->{suppressed}++;
	my $now = Time::HiRes::time();
	return if defined $state->{last}
		&& ($now - $state->{last}) < $self->{drop_log_interval};
	my $count = $state->{suppressed};
	$state->{suppressed} = 0;
	$state->{last} = $now;
	print STDERR "csf-ui (Server.pm): $why"
		. " ($count such connection(s) since the last line of this kind;"
		. " at most one line per $self->{drop_log_interval}s)\n";
	return;
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
# cancelled the instant tls_wrap is done with it - on a normal return, on a
# false/undef return, OR ON A DIE (task-5-review.md R37: an unconditional
# alarm(0) placed textually after the call is skipped along with everything
# else once tls_wrap dies, which the eval/die-and-rethrow below exists to
# prevent) - and only then, if the wrap produced real TLS, is a second
# alarm armed - the same header_timeout + body_timeout + write_timeout sum
# as before, now starting fresh rather than continuing to run down a clock
# the handshake already spent from. A peer stuck in either phase is still
# killed, promptly, by that phase's own budget; a peer that is merely slow,
# in either phase, and stays within it, is not.
#
# R37: this is inert today only because run() has no eval around
# _serve_accepted(), so an uncaught die here takes the whole child with it
# and there is no second phase left for a leaked alarm to misfire into -
# the same "correct by coincidence" shape R34's flat-8192 read had, and the
# coincidence has a name: whatever script becomes Task 9's mode-B daemon
# entry point is the obvious place to wrap this call in an eval so one bad
# connection does not kill the process, and the day that happens this stops
# being inert.
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
#
# MODE A HAS NO HANDSHAKE PHASE AT ALL, and so has one watchdog rather
# than two. That is not a relaxation of R31/R36 - it is those rulings
# applied honestly to a connection that does no TLS: the front web server
# terminated TLS one hop earlier, this socket carries plain HTTP from a
# peer the kernel has already identified, and there is no negotiation here
# for a handshake budget to bound. Arming one anyway would be arming a
# deadline over nothing, and - worse - would invite the reading that
# $handshake_timeout is a general "time before the request starts" budget,
# which is exactly the conflation R36 was raised to remove.
#
# The request phase keeps its own full budget, unchanged, and in mode A
# that budget is doing something HTTP.pm's own deadlines do not. HTTP.pm
# bounds every read and every write it performs, so a mode-A peer that
# connects and sends nothing is already refused by it - but the child's
# time is not all spent in HTTP.pm. dispatch() has no deadline of its own
# (docs/WEBUI-RPC.md section 14.3 promises a return, not a prompt one),
# and that call is inside this budget. Without it, one request that hangs
# in the app holds a child slot forever, thirty-two of them deny the UI,
# and waitpid() never reaps any of them because none of them ever exit -
# R31's failure mode exactly, reached by a different road.
#
# $self->{tls_wrap} is ignored in mode A rather than consulted and found
# irrelevant. A tls_wrap on a mode-A server is a configuration mistake,
# and running it would produce a TLS server speaking into a plain-HTTP
# proxy connection - a hang, not an error.
###############################################################################
# THE REQUEST PHASE'S BUDGET, IN ONE PLACE RATHER THAN TWO (F1).
#
# Both modes arm the same budget over the same three things, and until F1
# both computed it from their own copy of the same sum - which is how mode
# B kept the arithmetic mode A had just had corrected. One function, so a
# term can only be added to both or to neither.
#
# Every term is priced, including dispatch() (see
# $DEFAULT_DISPATCH_TIMEOUT above for why the sum without it killed a
# legitimate request, measured). Read off $self, not the package globals,
# so an injected short timeout in a test shortens the budget it is testing.
sub _request_budget {
	my ($self) = @_;
	return $self->{header_timeout}
		+ $self->{body_timeout}
		+ $self->{write_timeout}
		+ $self->{dispatch_timeout};
}

sub _serve_accepted {
	my ($self, $connection, $peer_addr) = @_;

	local $SIG{ALRM} = $self->{watchdog_exit};

	if ($self->{mode} eq 'a') {
		Time::HiRes::alarm($self->_request_budget);
		$self->handle_connection($connection, $peer_addr);
		Time::HiRes::alarm(0);
		close $connection;
		return;
	}

	Time::HiRes::alarm($self->{handshake_timeout});
	my $tls_socket = eval {
		$self->{tls_wrap}
			? $self->{tls_wrap}->($connection)
			: _default_tls_wrap($connection);
	};
	my $handshake_error = $@;
	Time::HiRes::alarm(0); # handshake phase over - return, false, OR die - its budget never carries forward
	die $handshake_error if $handshake_error; # rethrow unchanged: same fate as before this eval existed, just with the alarm off first

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
		Time::HiRes::alarm($self->_request_budget); # a fresh budget for this phase alone (R36)
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

###############################################################################
# run() - the daemon, in whichever mode ui.conf selects.
#
# THE MODE IS READ HERE AND NOWHERE ELSE. ui-src/bin/csf-ui's entry point
# deliberately does not decide it ("re-deciding any of that here would
# just be a second place for the two to disagree"), and neither does
# anything the constructor was given: whatever $self->{mode} held is
# overwritten from the file, because a server told one mode by its caller
# and another by its config is a server with two answers to the only
# question that decides what it binds.
###############################################################################
sub run {
	my ($self) = @_;

	my @problem = preflight(
		ui_conf_path => $self->{ui_conf_path},
		socket_path  => $self->{socket_path},
	);
	if (@problem) {
		print STDERR "csf-ui (Server.pm) refuses to start:\n";
		print STDERR "  - $_\n" for @problem;
		return 1;
	}
	die "Server.pm: run() requires an app instance (ConfigServer::UI::App); nothing here loads ui-src/bin/csf-ui on its own\n"
		unless ref($self->{app}) && $self->{app}->can('dispatch');

	my ($conf) = read_ui_conf($self->{ui_conf_path});
	$self->{mode} = $conf->{UI_MODE};

	my $listener;
	my $unix_path;

	if ($self->{mode} eq 'a') {
		# UI_ALLOW IS DELIBERATELY NOT LOADED IN MODE A. Not "loaded and
		# happens to go unused" - set to undef, on purpose, so that the
		# object itself says so and admit_peer()'s mode-A branch could not
		# consult it even if a later edit tried to. docs/WEBUI-RPC.md
		# section 10: "UI_ALLOW in mode A is not enforced by csf-ui - in
		# mode A csf-ui listens on a unix socket and the peer address it
		# sees is the front web server. It does not trust X-Forwarded-For
		# for access control." The key is still mandatory and still
		# non-empty in this mode, and it is still enforced - by the front
		# server, from the same value, rendered into its vhost by the
		# installer. read_ui_conf() has already refused an empty one.
		# Code that silently stops enforcing a security key reads as a
		# bug; this is the line that says it is a ruling.
		$self->{allow} = undef;

		if ($self->{listener}) {
			$listener = $self->{listener};
		}
		else {
			$unix_path = $self->{socket_path};
			($listener, $self->{socket_gid}) =
				_open_unix_listener($unix_path, backlog => $self->{backlog});
		}

		# Derived from the socket's own gid, unless a caller injected a
		# set - the same "an injected dependency wins" rule tls_wrap,
		# watchdog_exit and listener already follow in this file, and
		# reachable from the same one place (a test; ui-src/bin/csf-ui
		# passes nothing but `app`).
		# %peer_report records what was actually consulted to build the
		# set, so the refusal below can describe the cause rather than
		# assert one (F8). An injected set leaves it empty, which is
		# itself the honest answer: nothing was consulted.
		my %peer_report;
		$self->{peer_uids} = unix_peer_uids($self->{socket_gid},
				self_uid => $self->{self_uid}, report => \%peer_report)
			unless ref($self->{peer_uids}) eq 'HASH';

		# A socket nothing but this process can reach is a mode-A install
		# whose front web server was never granted the socket's group -
		# the exact shape that produces a 502 on every request with
		# nothing logged by anything of ours. Refuse loudly at startup
		# instead, naming the remedy, rather than accept connections that
		# can only ever be refused one at a time.
		unless (grep { $_ != $self->{self_uid} } keys %{ $self->{peer_uids} }) {
			print STDERR "csf-ui (Server.pm) refuses to start:\n";
			print STDERR '  - ' . $self->_no_local_peer_message(\%peer_report) . "\n";
			close $listener;
			unlink($unix_path) if defined $unix_path;
			return 1;
		}
	}
	else {
		require IO::Socket::SSL; # already proven to load, by preflight() above
		$self->{allow} = $conf->{UI_ALLOW};
		if ($self->{listener}) {
			# An injected listener whose family this module did not
			# choose: _peer_text() falls back to its own detection rather
			# than being told something that might not be true.
			$listener = $self->{listener};
		}
		else {
			$listener = _open_listener($conf);
			$self->{listen_family} = ($conf->{UI_LISTEN} =~ /:/)
				? Socket::AF_INET6() : Socket::AF_INET();
		}
	}

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

		# Checked BEFORE TLS and before fork(): the cheapest possible
		# rejection for a peer with no business here at all, and one that
		# never spends a TLS handshake, let alone an HTTP parse, on an
		# address the administrator never listed - or, in mode A, on an
		# account the install never designated. See admit_peer() for what
		# each mode actually asks here and why the two questions occupy
		# the same slot rather than one of them being deferred.
		my $peer_addr = $self->admit_peer($connection, $paddr);
		unless (defined $peer_addr) {
			close $connection;
			next;
		}

		# REAPED AGAIN, HERE, and not only at the top of the loop. The
		# reap above runs BEFORE accept(), so every child that exits
		# while the parent is blocked in accept() - which is where the
		# parent spends nearly all of its time - leaves %child stale for
		# exactly one connection, and that connection is then dropped as
		# "busy" against slots that are in fact free. Measured as one
		# legitimate request silently dropped per burst. A second
		# non-blocking waitpid() sweep costs one syscall per accepted
		# connection and makes the cap check read the truth.
		while ((my $done = waitpid(-1, POSIX::WNOHANG())) > 0) { delete $child{$done} }

		if (scalar(keys %child) >= $self->{max_children}) {
			# Dropped rather than queued without bound - and said so.
			# F2: this was the loop's first silent path, and the one an
			# attacker drives. See _log_drop() for why the bound on the
			# volume is a time window rather than _refuse_peer()'s
			# per-lifetime key.
			$self->_log_drop('busy',
				"all $self->{max_children} connection slots are in use, so a connection was accepted and dropped"
				. " without a response; the front web server will report this as a 502."
				. " If it persists, connections are being held open without completing a request");
			close $connection;
			next;
		}

		my $pid = fork();
		unless (defined $pid) {
			# F2: the loop's second silent path. One EAGAIN under
			# RLIMIT_NPROC dropped a request with no record that anything
			# had happened at all.
			#
			# AND THIS BRANCH IS LOAD-BEARING FOR MORE THAN THE LOG.
			# Without it $pid is undef, `if ($pid)` below is false, and
			# the PARENT falls through into the child path: it closes its
			# own listener, serves this one request, and POSIX::_exit(0)s.
			# Measured: the daemon is dead after request 1, a stale socket
			# is left behind, and the next connect() is ECONNREFUSED. One
			# transient fork() failure terminates the firewall's admin
			# interface. t/42-listen-loop.t drives exactly that.
			$self->_log_drop('fork',
				"fork() failed, so a connection was accepted and dropped without a response ($!);"
				. " the host is out of processes or this account is at its RLIMIT_NPROC");
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
	# Only the parent, only on a clean exit, and only a path this process
	# bound itself: a child never reaches here (POSIX::_exit(0) above), and
	# an injected listener left $unix_path undef precisely because this
	# module did not create that socket and has no business removing it.
	# Leaving it behind is not fatal - _unlink_stale_socket() would clear
	# it on the next start - but a socket file outliving the process that
	# answered it is a thing an administrator has to reason about, and
	# there is no reason to make them.
	unlink($unix_path) if defined $unix_path;
	return 0;
}

1;
