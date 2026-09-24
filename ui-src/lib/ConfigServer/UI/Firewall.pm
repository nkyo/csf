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
# Backend detection and the setup wizard's temporary port
# (docs/WEBUI-PLAN.md S6, task-8-brief.md).
#
# WHAT THIS MODULE IS FOR, AND WHY IT IS SO RELUCTANT.
#
# ui-src/bin/csf-ui-setup binds 127.0.0.1 and tells the operator to reach it
# over ssh -L. That always works and costs nothing. The ONLY reason this
# module exists is the case where the operator would rather open one port to
# one address for a few minutes than build a tunnel - and the cost of getting
# that wrong is not a failed request, it is an operator locked out of a
# machine they are holding a support ticket about. So every routine below is
# written to decline rather than to guess:
#
#   * The backend is DETECTED, never inferred from the distribution. "This
#     looks like a RHEL box so it must be firewalld" is exactly the
#     reasoning that adds an iptables rule to a host where nothing will ever
#     read it, or - worse - adds one this code cannot afterwards remove.
#     Detection runs the binaries and reads what they say about themselves.
#
#   * unknown is a first-class outcome, not an error path. Six outcomes:
#     iptables-legacy, iptables-nft, nftables, firewalld, ufw, unknown. On
#     unknown every mutating entry point here refuses, and the wizard
#     falls back to the tunnel.
#
#   * A rule that is added is immediately READ BACK from the backend and it
#     is the backend's own rendering of it that is stored. Removal then
#     matches that stored text against a FRESH read-back and removes the
#     line the backend is showing right now. Nothing here ever rebuilds a
#     rule string from the port and address it remembers: the backend
#     normalises what you give it (iptables turns -s 203.0.113.5 into
#     -s 203.0.113.5/32 and reorders match modules), so a rebuilt string
#     is a string that matches nothing, and a -D that matches nothing
#     leaves the port open forever with this code believing it closed it.
#
#   * Nothing here ever reaches a shell. Every child is exec'd through the
#     block form with an argv LIST (G2), and the argv[0] is an absolute path
#     this module resolved itself from a fixed list of directories - never
#     a bare name looked up through the inherited $PATH. The values that
#     reach these argv lists came from a network request, which is the whole
#     reason both halves of that sentence matter.
#
# WHY nftables IS DETECTED BUT NEVER WRITTEN TO. nftables here means
# native nft with no iptables binary at all. Two independent reasons this
# module declines to add a rule there, and neither is "we did not get round
# to it":
#
#   1. In nftables, accept in a base chain does not end evaluation of the
#      other base chains registered at the same hook - a drop in any of
#      them still wins. So a permit rule this module put in its OWN table
#      (the only table it could safely create and safely destroy) would not
#      reliably open anything, while reporting to the operator that it had.
#      Adding a rule to somebody else's existing table means guessing which
#      of possibly several base chains is the one that matters, which is the
#      guessing this file exists to refuse.
#   2. csf itself cannot run on such a host: csf.pl drives $config{IPTABLES}
#      for everything it does. A host with no iptables binary is a host
#      where the thing being configured will not start, so opening a port to
#      reach its setup wizard is moot.
#
#   It is therefore reported as a KNOWN backend with a distinct refusal code
#   (E_NO_SAFE_RULE), not as unknown: "we know exactly what this is and it
#   is not safe to write to" is different information from "we have no idea
#   what this is", and the operator deserves the difference.
#
# WHY firewalld IS DETECTED AT ALL, given csf.pl:919 refuses to start while
# firewalld is running. Precisely because of that. If this module reported
# firewalld as unknown, the wizard would fall back to the tunnel and say
# nothing, and the operator would discover the incompatibility later, from
# csf. Detecting it means the wizard can say so up front. The temporary-port
# path is still implemented for it (a runtime-only rich rule, removable by
# the exact string firewalld itself prints) because the operator may well be
# about to stop firewalld, and a rule that only exists until the next
# firewall-cmd --reload is the safest kind of temporary rule there is.
###############################################################################
package ConfigServer::UI::Firewall;

use strict;
use warnings;

use POSIX ();
use Time::HiRes ();
use ConfigServer::UI::Proto ();

our $VERSION = '1.00';

my $P = 'ConfigServer::UI::Proto';

# Binaries are resolved from this fixed list, in this order, and never from
# the inherited $PATH. csf-ui-setup runs as root; an attacker-controlled or
# merely careless $PATH entry ahead of /sbin is a root exec of somebody
# else's iptables. The list is 'our' so a test can point it at a directory
# of fixture scripts without needing any of these to exist.
our @SEARCH_DIRS = qw(/sbin /usr/sbin /bin /usr/bin /usr/local/sbin /usr/local/bin);

# The comment stamped on every rule this module adds. It has NO SPACES on
# purpose: iptables' own -S output quotes a comment that contains
# whitespace, and _argv_from_canonical() below refuses to split a canonical
# line containing a quote character (it cannot do so without implementing
# shell quoting, which is the one thing this file will not do). A
# space-free comment keeps the canonical line splittable on whitespace and
# therefore keeps removal possible.
our $RULE_COMMENT = 'csf-ui-setup';

# Wall-clock budget for one child. Firewall tooling is local and fast; a
# probe that has not answered in ten seconds is a probe that has hit a
# blocked netlink socket or a wedged xtables lock, and the answer to that is
# to give up and fall back to the tunnel, not to hang the wizard.
our $DEFAULT_DEADLINE = 10;

# Output cap for one child, so nft list ruleset on a host with a large
# ruleset cannot be an unbounded read into root's memory.
our $MAX_CHILD_OUTPUT = 4 * 1024 * 1024;

our @BACKENDS = qw(iptables-legacy iptables-nft nftables firewalld ufw unknown);
my %IS_BACKEND = map { $_ => 1 } @BACKENDS;

###############################################################################
# Construction.
#
#   runner   => sub { my (@argv) = @_; return \%result }
#   locate   => sub { my ($name) = @_; return $absolute_path_or_undef }
#
# Both are injection seams and both exist for the same reason: t/70-firewall
# -detect.t must prove detection against fixture command output without
# running iptables, without root and without a network (G1). Production
# passes neither and gets _run_argv()/_locate() below.
#
# %result is the shape _run_argv() returns:
#   { exit => 0, output => "...", signal => 0, timeout => 0, error => undef }
# error set means the child never ran at all.
###############################################################################
sub new {
	my ($class, %opt) = @_;
	return bless {
		runner   => $opt{runner} || \&_run_argv,
		locate   => $opt{locate} || \&_locate,
		deadline => defined $opt{deadline} ? $opt{deadline} : $DEFAULT_DEADLINE,
		detected => undef,
	}, $class;
}

###############################################################################
# Locating a binary. Absolute path or undef; never a bare name, never $PATH.
###############################################################################
sub _locate {
	my ($name) = @_;
	return undef unless defined $name && $name =~ /^[A-Za-z0-9][A-Za-z0-9._-]*\z/;
	for my $dir (@SEARCH_DIRS) {
		my $path = "$dir/$name";
		return $path if -x $path && !-d $path;
	}
	return undef;
}

sub locate {
	my ($self, $name) = @_;
	return $self->{locate}->($name);
}

###############################################################################
# Running one child.
#
# The same pipe/fork/exec-block/select-with-deadline shape ui-src/bin/
# csf-ui-helper's run_argv() already uses, reproduced here rather than
# imported because that one is a private sub of a different program that
# this module must not load (loading it would start nothing, but it would
# pull the whole helper into the setup wizard's address space for one
# function).
#
# exec is the BLOCK form with an argv LIST. Perl's one-argument exec hands a
# string to /bin/sh; the block form cannot reach a shell whatever the list
# holds, not even for a one-element list (G2).
###############################################################################
sub _run_argv {
	my (@argv) = @_;
	my $deadline = pop @argv;   # last element is the deadline, pushed by run()

	return { error => 'no command', exit => -1, output => '' } unless @argv;
	return { error => 'argv[0] is not an absolute path', exit => -1, output => '' }
		unless $argv[0] =~ m{^/};

	my ($reader, $writer);
	pipe($reader, $writer) or return { error => 'pipe failed', exit => -1, output => '' };

	my $pid = fork();
	return { error => 'fork failed', exit => -1, output => '' } unless defined $pid;

	if (!$pid) {
		close $reader;
		open(STDIN, '<', '/dev/null');
		open(STDOUT, '>&', $writer) or POSIX::_exit(127);
		open(STDERR, '>&', $writer) or POSIX::_exit(127);
		close $writer;

		# EVERY disposition this process may have changed is put back before
		# exec (task-8-review.md R80). A signal HANDLER is reset by the
		# kernel across exec on its own - its address means nothing in the
		# new image - but SIG_IGN is INHERITED, and an inherited ignore is a
		# silent, lasting change to a program this code did not write. csf
		# in particular installs its own handling and is entitled to start
		# from the default; a child that cannot be killed by SIGTERM, or
		# that never notices a broken pipe, is a child debugged by somebody
		# who has no idea this program touched it.
		#
		# Added 2026-09-12 in https://github.com/nkyo/csf - see CHANGES.md.
		# NAMED, not derived: this list is every disposition THIS process is
		# known to change today, not "whatever %SIG currently holds" - the
		# latter would also reset a handler this process's own caller relies
		# on. A seventh signal changed anywhere in this codebase's callers
		# (ConfigServer::UI::Server::run() sets PIPE/TERM/INT already
		# covered here; csf-ui-setup scopes its own PIPE ignore with local,
		# which t/71-rollback.t asserts about the source; csf-ui's own
		# daemon entry point at the foot of ui-src/bin/csf-ui sets none)
		# needs adding to this list BY HAND - nothing enforces that the two
		# stay in sync.
		#
		# CORRECTED 2026-09-24. The survey above listed three callers and
		# omitted the fourth: ui-src/bin/csf-ui-helper's main(), which sets
		# $SIG{PIPE} = 'IGNORE' process-wide for its accept loop and has
		# its OWN fork+exec in run_argv(). It was written in Task 2, before
		# this rule was generalised in Task 8, and was never revisited - so
		# every csf and iptables the helper ran, AS ROOT, inherited an
		# ignored SIGPIPE. run_argv() now resets this same named list, and
		# t/11-helper-validate.t proves it the way t/70 proves it here:
		# from the exec'd child's own /proc/self/status. A survey comment
		# that names three of four callers is worse than none, because the
		# fourth is the one nobody re-derives.
		$SIG{$_} = 'DEFAULT' for qw(CHLD PIPE HUP INT TERM ALRM);

		{
			no warnings 'exec';
			exec { $argv[0] } @argv;
		}
		POSIX::_exit(127);
	}

	close $writer;
	my $output = '';
	my $expires = Time::HiRes::time() + $deadline;
	my ($timeout, $overflow) = (0, 0);

	while (1) {
		my $left = $expires - Time::HiRes::time();
		if ($left <= 0) { $timeout = 1; last }

		my $rin = '';
		vec($rin, fileno($reader), 1) = 1;
		my $rout = $rin;
		my $ready = select($rout, undef, undef, $left);
		if (!defined $ready) {
			next if $!{EINTR};
			$timeout = 1;
			last;
		}
		next if $ready == 0;

		my $chunk = '';
		my $read = sysread($reader, $chunk, 8192);
		if (!defined $read) {
			next if $!{EINTR};
			last;
		}
		last if $read == 0;
		$output .= $chunk;
		if (length($output) > $MAX_CHILD_OUTPUT) { $overflow = 1; last }
	}

	# kill's result is deliberately unread: the only reason it fails is ESRCH,
	# meaning the child is already dead, which is the state being asked for.
	if ($timeout || $overflow) { kill('KILL', $pid) }
	close $reader;

	# waitpid IS read. $? is a global, and if waitpid did not actually reap
	# THIS child (-1: no such process, because a stray SIGCHLD handler got
	# there first) then $? still holds whatever the last reaped child left
	# in it - which would be read here as an exit status for a command whose
	# outcome is in fact unknown. On this path that would mean believing an
	# iptables mutation succeeded on the strength of some other process's
	# exit code.
	my $reaped = waitpid($pid, 0);
	return {
		exit => -1, signal => 0, output => $output,
		timeout => $timeout, overflow => $overflow,
		error => 'the child could not be reaped, so its exit status is unknown',
	} if $reaped != $pid;

	my $raw = $?;

	return {
		exit     => ($raw >> 8),
		signal   => ($raw & 127),
		output   => $output,
		timeout  => $timeout,
		overflow => $overflow,
		error    => undef,
	};
}

sub run {
	my ($self, @argv) = @_;
	my $result = $self->{runner}->(@argv, $self->{deadline});
	$result = { error => 'the runner returned nothing', exit => -1, output => '' }
		unless ref($result) eq 'HASH';
	$result->{output} = '' unless defined $result->{output};
	$result->{exit}   = -1 unless defined $result->{exit};
	return $result;
}

# A child that ran and exited 0. Anything else - never started, killed,
# timed out, non-zero - is not a success, and nothing in this file is
# allowed to read the output of one as though it were.
sub _ok {
	my ($result) = @_;
	return 0 if $result->{error};
	return 0 if $result->{timeout} || $result->{overflow};
	return 0 if $result->{signal};
	return $result->{exit} == 0 ? 1 : 0;
}

###############################################################################
# detect() -> \%detection
#
#   {
#     backend => one of @BACKENDS,
#     certain => 1|0,            # 0 exactly when backend eq 'unknown'
#     reason  => 'human sentence saying what was observed',
#     tool    => '/sbin/iptables',   # the binary that would be driven, if any
#     supports_w => 1|0,             # iptables only: -w (xtables lock) usable
#     probes  => [ { argv => [...], exit => 0, output => '...' }, ... ],
#   }
#
# Cached after the first call; pass force => 1 to re-probe.
#
# ORDER MATTERS AND IS NOT ARBITRARY. firewalld and ufw are MANAGERS that
# sit on top of an iptables or nftables ruleset. On a host running either,
# the iptables binary is present and answers perfectly well - so probing
# iptables first would find it, report iptables-nft, and then this module
# would write a rule straight into a ruleset the manager rewrites from its
# own state whenever it is reloaded. The manager has to be asked first, and
# only if no manager is RUNNING does the raw layer get to answer.
###############################################################################
sub detect {
	my ($self, %opt) = @_;
	return $self->{detected} if $self->{detected} && !$opt{force};

	my @probe;
	my $detection = $self->_detect_firewalld(\@probe)
		|| $self->_detect_ufw(\@probe)
		|| $self->_detect_iptables(\@probe)
		|| $self->_detect_nftables(\@probe)
		|| {
			backend => 'unknown',
			reason  => 'no firewall backend could be identified: none of firewall-cmd, ufw, iptables or nft is present and usable',
		};

	$detection->{probes}  = \@probe;
	$detection->{certain} = ($detection->{backend} eq 'unknown') ? 0 : 1;
	$detection->{tool}    = undef unless exists $detection->{tool};
	$detection->{supports_w} = 0 unless exists $detection->{supports_w};

	die "ConfigServer::UI::Firewall: detect() produced '$detection->{backend}', which is not one of @BACKENDS\n"
		unless $IS_BACKEND{ $detection->{backend} };

	$self->{detected} = $detection;
	return $detection;
}

sub _probe {
	my ($self, $log, @argv) = @_;
	my $result = $self->run(@argv);
	push @$log, { argv => [@argv], exit => $result->{exit}, output => $result->{output} };
	return $result;
}

###############################################################################
# firewalld. Two binaries can speak for it and they do not say the same
# thing:
#
#   firewall-cmd --state   answers "running" only when the daemon is up AND
#                          this host has the client tool to drive it.
#   systemctl is-active    answers "active" even when firewall-cmd is not
#                          installed.
#
# The second case - firewalld running, no firewall-cmd - is unknown, not
# firewalld: something is holding the ruleset that this module can neither
# read back from nor remove a rule from. That is the textbook case for
# declining, and csf.pl:919 will refuse to start there anyway.
###############################################################################
sub _detect_firewalld {
	my ($self, $log) = @_;

	my $cmd = $self->locate('firewall-cmd');
	my $systemd_says = $self->_firewalld_per_systemctl($log);

	if ($cmd) {
		my $state = $self->_probe($log, $cmd, '--state');

		return {
			backend => 'firewalld',
			reason  => "firewall-cmd --state reports firewalld running (via $cmd)",
			tool    => $cmd,
		} if _ok($state) && $state->{output} =~ /^\s*running\b/m;

		# EVERY OTHER ANSWER IS NOT "not running" (task-8-review.md C5).
		# firewall-cmd exits 252 - NOT_RUNNING - and says so when firewalld
		# is simply stopped. A different failure means the question was not
		# answered: the daemon is unreachable, dbus is not there, the
		# binary is wedged. Treating that as "not running" and falling
		# through hands back iptables-nft with certain => 1 on a host
		# where firewalld may well be holding the ruleset - a confident
		# wrong answer, which is strictly worse than unknown, because
		# unknown is the safe path and this one writes a rule.
		my $says_not_running = ($state->{exit} == 252)
			|| ($state->{output} =~ /not\s+running/i) ? 1 : 0;

		unless ($says_not_running) {
			return {
				backend => 'unknown',
				reason  => "firewall-cmd --state neither confirmed nor denied that firewalld is running (exit $state->{exit}: "
					. _first_line($state->{output}) . '), so whether firewalld holds this ruleset is unanswered',
			};
		}

		# firewall-cmd says stopped and systemd says running. One of them
		# is wrong and this code cannot tell which, which is the definition
		# of the case it must decline.
		return {
			backend => 'unknown',
			reason  => 'firewall-cmd --state says firewalld is not running but systemctl says it is; the two disagree and this cannot tell which is right',
		} if $systemd_says eq 'running';

		return undef;   # genuinely not running; keep looking
	}

	# No firewall-cmd at all. Now systemd is the only witness, and two of
	# its three answers are refusals: a firewalld that is running cannot be
	# read back from or removed from without its client tool, and a
	# firewalld whose state could not be read is the same unanswered
	# question as above.
	return {
		backend => 'unknown',
		reason  => 'firewalld is running but firewall-cmd is not installed, so a rule could be added but not read back or removed',
	} if $systemd_says eq 'running';

	return {
		backend => 'unknown',
		reason  => 'whether firewalld is running could not be determined, and firewall-cmd is not installed to ask it directly',
	} if $systemd_says eq 'unclear';

	return undef;
}

# 'running' | 'stopped' | 'unclear' | 'absent'
#
# The WORD is what is read, not the exit status: systemctl is-active exits
# non-zero for anything but "active", including "activating" - and a
# firewalld in the middle of starting is exactly as unsafe to write
# underneath as one that has finished.
sub _firewalld_per_systemctl {
	my ($self, $log) = @_;

	my $systemctl = $self->locate('systemctl') or return 'absent';
	my $active = $self->_probe($log, $systemctl, 'is-active', 'firewalld');

	return 'running' if $active->{output} =~ /^\s*(?:active|activating|reloading)\s*$/m;
	return 'stopped' if $active->{output} =~ /^\s*(?:inactive|deactivating|failed|unknown)\s*$/m;
	return 'unclear';
}

###############################################################################
# ufw. ufw status prints "Status: active" or "Status: inactive". Inactive
# ufw is not a backend - the rules it would manage are not loaded - so fall
# through to the raw layer, which is what is actually filtering.
###############################################################################
sub _detect_ufw {
	my ($self, $log) = @_;
	my $ufw = $self->locate('ufw');
	return undef unless $ufw;

	my $status = $self->_probe($log, $ufw, 'status');
	return undef unless _ok($status);
	return undef unless $status->{output} =~ /^\s*Status:\s*active\b/mi;

	return {
		backend => 'ufw',
		reason  => "ufw status reports the firewall active (via $ufw)",
		tool    => $ufw,
	};
}

###############################################################################
# iptables. The version banner is the only honest answer to "which backend
# does THIS binary talk to", because on a modern host /sbin/iptables is an
# alternatives symlink that may point at either implementation:
#
#   iptables v1.8.7 (nf_tables)   -> iptables-nft
#   iptables v1.8.7 (legacy)      -> iptables-legacy
#   iptables v1.4.21              -> iptables-legacy (pre-split; there was
#                                    only one implementation)
#
# Then two gates before the answer counts:
#
#   * the ruleset must actually be readable (-S INPUT exits 0). A binary
#     that is present but cannot talk to the kernel - a container with no
#     CAP_NET_ADMIN, a missing module - is not a backend this module can add
#     a removable rule to, so it is unknown.
#
#   * if BOTH implementations are installed as their own binaries AND BOTH
#     hold live rules, the answer is unknown however confidently
#     /sbin/iptables identified itself. Two live rulesets in two different
#     kernel subsystems means a permit added to one can be overruled by a
#     drop in the other; which one is "in use" has no single answer, and the
#     whole premise of this module is that it only writes when there is one.
###############################################################################
sub _detect_iptables {
	my ($self, $log) = @_;
	my $iptables = $self->locate('iptables');
	return undef unless $iptables;

	my $version = $self->_probe($log, $iptables, '--version');
	return {
		backend => 'unknown',
		reason  => "$iptables is installed but iptables --version did not run",
	} unless _ok($version);

	my ($major, $minor, $patch) = $version->{output} =~ /\bv([0-9]+)\.([0-9]+)\.([0-9]+)/;
	my $flavour;
	if ($version->{output} =~ /\(\s*nf_tables\s*\)/) {
		$flavour = 'iptables-nft';
	}
	elsif ($version->{output} =~ /\(\s*legacy\s*\)/) {
		$flavour = 'iptables-legacy';
	}
	elsif (defined $major) {
		# No parenthetical at all: every iptables before the 1.8 split was
		# the legacy implementation and said nothing about it.
		$flavour = ($major < 1 || ($major == 1 && $minor < 8)) ? 'iptables-legacy' : undef;
	}
	unless (defined $flavour) {
		return {
			backend => 'unknown',
			reason  => 'iptables --version did not name a backend this code recognises: ' . _first_line($version->{output}),
		};
	}

	my $list = $self->_probe($log, $iptables, '-S', 'INPUT');
	return {
		backend => 'unknown',
		reason  => "$iptables identifies as $flavour but its INPUT chain could not be read, so a rule added there could not be read back",
	} unless _ok($list);

	# -w (wait for the xtables lock) arrived in 1.4.20. Passing it to an
	# older binary is a usage error that fails the mutation; omitting it on a
	# newer one risks losing a race with csf itself. Decided here, once,
	# from the version actually reported.
	my $supports_w = 0;
	if (defined $major) {
		$supports_w = 1 if $major > 1;
		$supports_w = 1 if $major == 1 && $minor > 4;
		$supports_w = 1 if $major == 1 && $minor == 4 && defined $patch && $patch >= 20;
	}

	if (my $ambiguous = $self->_both_implementations_live($log)) {
		return $ambiguous;
	}

	return {
		backend => $flavour,
		reason  => "$iptables --version reports the " .
			($flavour eq 'iptables-nft' ? 'nf_tables' : 'legacy') .
			' backend and its INPUT chain reads back',
		tool       => $iptables,
		supports_w => $supports_w,
	};
}

# Both iptables-legacy and iptables-nft installed as distinct binaries, and
# both holding at least one real rule (a line beginning -A; the -P
# policy lines are present on every host and prove nothing). Returns an
# unknown detection when that is the case, undef otherwise.
sub _both_implementations_live {
	my ($self, $log) = @_;

	my %live;
	for my $name (qw(iptables-legacy iptables-nft)) {
		my $path = $self->locate($name) or next;
		my $list = $self->_probe($log, $path, '-S');
		next unless _ok($list);
		$live{$name} = 1 if $list->{output} =~ /^-A\s/m;
	}
	return undef unless $live{'iptables-legacy'} && $live{'iptables-nft'};

	return {
		backend => 'unknown',
		reason  => 'both iptables-legacy and iptables-nft hold live rules; which one is in force cannot be determined, and a permit added to one can be overruled by a drop in the other',
	};
}

###############################################################################
# Native nftables - reached only when there is no iptables binary at all.
# See the module header for why this is detected and then never written to.
###############################################################################
sub _detect_nftables {
	my ($self, $log) = @_;
	my $nft = $self->locate('nft');
	return undef unless $nft;

	my $version = $self->_probe($log, $nft, '--version');
	return undef unless _ok($version);

	my $ruleset = $self->_probe($log, $nft, 'list', 'ruleset');
	return {
		backend => 'unknown',
		reason  => "$nft is installed but nft list ruleset did not run, so nothing here can be read back",
	} unless _ok($ruleset);

	return {
		backend => 'nftables',
		reason  => "nft is present, iptables is not, and nft list ruleset reads back (via $nft)",
		tool    => $nft,
	};
}

sub _first_line {
	my ($text) = @_;
	return '' unless defined $text;
	my ($line) = split(/\n/, $text, 2);
	$line = '' unless defined $line;
	return $P->can('sanitise')->($line, 200);
}

###############################################################################
# THE TEMPORARY PORT
#
# open_port($self, port => 8443, address => '203.0.113.5') -> \%outcome
#
#   { ok => 1, spec => \%spec }
#   { ok => 0, code => 'E_...', reason => '...' }
#
# %spec is the canonical, serialisable record of what was added - the ONLY
# thing close_port() is ever given, and the only thing csf-ui-setup writes
# to its state file so that --cleanup can close a port left open by a
# session that died badly.
###############################################################################
sub open_port {
	my ($self, %opt) = @_;

	my $detection = $self->detect;
	return _decline('E_BACKEND_UNKNOWN',
		'the firewall backend could not be identified with certainty, so no rule will be added that might not be removable: ' . $detection->{reason})
		if $detection->{backend} eq 'unknown';

	return _decline('E_NO_SAFE_RULE',
		'this host uses native nftables with no iptables binary: a permit rule in a table of our own would not reliably override a drop in another table at the same hook, and csf itself drives iptables and will not run here')
		if $detection->{backend} eq 'nftables';

	my ($port, $port_error) = _validate_port($opt{port});
	return _decline('E_PORT', $port_error) unless defined $port;

	my ($address, $address_error) = _validate_single_address($opt{address});
	return _decline('E_ADDRESS', $address_error) unless defined $address;

	my $family = ($address =~ /:/) ? 6 : 4;

	my $method = {
		'iptables-legacy' => \&_open_iptables,
		'iptables-nft'    => \&_open_iptables,
		'firewalld'       => \&_open_firewalld,
		'ufw'             => \&_open_ufw,
	}->{ $detection->{backend} };
	return _decline('E_BACKEND_UNKNOWN',
		"no way to add a temporary rule is implemented for backend '$detection->{backend}'")
		unless $method;

	return $self->$method($detection, $port, $address, $family);
}

sub _decline {
	my ($code, $reason) = @_;
	return { ok => 0, code => $code, reason => $reason };
}

# The best-effort undo, after a rule was added and could not be read back.
# Its RESULT is not ignored, even though the outcome is a refusal either way
# - because the two refusals mean different things to the operator. "Added
# something and took it back out" needs nothing from them. "Added something,
# cannot see it, and could not take it back out" is a rule installed on their
# machine that nothing is tracking and nothing will ever remove, and it has
# to be said out loud with the command to run.
sub _undo_note {
	my ($undone, $command) = @_;
	return '; the rule that was added has been removed again' if $undone;
	return '; WORSE, it could not be removed again either - a rule may be installed that nothing is tracking. Remove it by hand: '
		. $command;
}

# A port the wizard could actually be listening on. Below 1024 is refused
# for the same reason docs/WEBUI-RPC.md S10 refuses it for UI_PORT, and
# because a temporary hole in a privileged port is a different conversation
# from a temporary hole in an ephemeral one.
sub _validate_port {
	my ($value) = @_;
	return (undef, 'a port is required') unless defined $value && !ref $value;
	return (undef, 'the port must be digits with no leading zero')
		unless "$value" =~ /^(?:0|[1-9][0-9]{0,4})\z/;
	my $port = $value + 0;
	return (undef, 'the port must be between 1024 and 65535') if $port < 1024 || $port > 65535;
	return ($port, undef);
}

# EXACTLY one address. Not a network, not a range, not a /24 the operator
# happens to be inside. ConfigServer::UI::Proto::ip_info() does the parsing
# (one implementation of "is this an IP", already hostile-tested by
# t/10-proto.t); this adds three rules on top of it, because the claim being
# made to the operator is "open to your address and nobody else" and each of
# the three is a way that claim could be false while ip_info() was perfectly
# happy:
#
#   * a prefix other than the full host length is a network, not an address
#     (and /0 - the whole Internet - is exactly the shape a careless
#     $SSH_CLIENT parse would produce);
#   * the unspecified address (0.0.0.0, ::) means "any source" to every
#     backend here, i.e. the same hole with a narrower-looking spelling;
#   * loopback gains nothing (a rule permitting 127.0.0.1 to reach a port
#     reachable from 127.0.0.1 anyway) and its presence means the caller
#     derived the address from something that was not a remote peer.
#
# The canonical form ip_info() returns is what goes into the argv, never the
# caller's text.
sub _validate_single_address {
	my ($value) = @_;
	return (undef, 'no operator address is known, so there is nobody to restrict the rule to')
		unless defined $value && !ref $value && length "$value";

	my ($info, $why) = $P->can('ip_info')->($value);
	return (undef, "the operator address $why") unless defined $info;

	if (defined $info->{plen} && $info->{plen} != $info->{bits}) {
		return (undef, "the operator address must be a single host, not a /$info->{plen} network");
	}

	my $host = $info->{canonical};
	$host =~ s{/[0-9]+\z}{};

	return (undef, 'the operator address is the unspecified address, which every backend reads as "any source"')
		if $info->{packed} eq ("\0" x length($info->{packed}));
	return (undef, 'the operator address is a loopback address, which is not a remote peer')
		if $host eq '::1' || $host =~ /^127\./;

	return ($host, undef);
}

###############################################################################
# iptables (either implementation - the command line is identical; only the
# binary behind /sbin/iptables differs, and detect() already established
# which).
#
# Inserted at position 1 of INPUT. Not appended: csf's own rules live in
# INPUT and in chains INPUT jumps to, and an ACCEPT after csf's DROP is an
# ACCEPT that is never reached. Position 1 is the only position that is
# unconditionally in front of whatever is already there.
#
# Then read back with -S INPUT and the backend's own rendering of the rule
# is stored. That rendering is NOT the command line that was just issued -
# iptables normalises -s 203.0.113.5 to -s 203.0.113.5/32, inserts
# -m tcp for you, and orders the match modules its own way - which is
# exactly why removal has to use what came back rather than what went in.
###############################################################################
sub _open_iptables {
	my ($self, $detection, $port, $address, $family) = @_;

	my $binary = ($family == 6) ? $self->locate('ip6tables') : $detection->{tool};
	return _decline('E_BACKEND_UNKNOWN',
		'the operator address is IPv6 but no ip6tables binary was found, so a rule could be added but not removed')
		unless $binary;

	my @wait = $detection->{supports_w} ? ('-w', '5') : ();

	my @add = ($binary, @wait, '-I', 'INPUT', '1',
		'-s', $address,
		'-p', 'tcp', '--dport', $port,
		'-m', 'comment', '--comment', $RULE_COMMENT,
		'-j', 'ACCEPT');

	my $added = $self->run(@add);
	return _decline('E_ADD_FAILED',
		'iptables refused to add the temporary rule: ' . _first_line($added->{output}))
		unless _ok($added);

	my ($canonical, $problem) = $self->_iptables_find($binary, \@wait, $port, $address);
	unless (defined $canonical) {
		# Added something, cannot see it, cannot therefore promise to remove
		# it. Try once to take it back out with the command line that put it
		# in - best effort, explicitly NOT the removal path, and the outcome
		# is a refusal either way so the operator is never told a port is
		# open that this code has lost track of.
		my @undo = ($binary, @wait, '-D', 'INPUT',
			'-s', $address, '-p', 'tcp', '--dport', $port,
			'-m', 'comment', '--comment', $RULE_COMMENT, '-j', 'ACCEPT');
		my $undone = $self->run(@undo);
		return _decline('E_READBACK', $problem . _undo_note(_ok($undone), join(' ', @undo)));
	}

	return { ok => 1, spec => {
		backend   => $detection->{backend},
		kind      => 'iptables',
		binary    => $binary,
		wait      => [@wait],
		chain     => 'INPUT',
		port      => $port,
		address   => $address,
		family    => $family,
		canonical => $canonical,
	} };
}

# Find our rule in -S INPUT, by the comment we stamped on it and the port
# we asked for. Returns ($canonical_line, undef) or (undef, $why_not).
#
# More than one match is a refusal, not a choice. Two rules carrying this
# comment on this port means a previous session left one behind, and
# removing "the first one" would leave the other open with nothing tracking
# it.
sub _iptables_find {
	my ($self, $binary, $wait, $port, $address) = @_;

	my $list = $self->run($binary, @$wait, '-S', 'INPUT');
	return (undef, 'the rule was added but iptables -S INPUT would not run, so it cannot be read back or reliably removed')
		unless _ok($list);

	my @match = grep {
		/^-A\s+INPUT\s/
			&& /--comment\s+\Q$RULE_COMMENT\E(?:\s|\z)/
			&& /--dport\s+\Q$port\E(?:\s|\z)/
	} split(/\n/, $list->{output});

	return (undef, "the rule was added but does not appear in iptables -S INPUT, so it cannot be reliably removed")
		unless @match;
	return (undef, scalar(@match) . " rules carrying the $RULE_COMMENT comment on port $port are present; refusing to guess which one belongs to this session")
		if @match > 1;

	return ($match[0], undef);
}

###############################################################################
# firewalld. A RUNTIME rich rule - never --permanent. Two properties come
# free with that choice: it disappears on firewall-cmd --reload and on a
# reboot, so the worst case for a session that dies badly is a hole that
# closes itself; and it never touches the on-disk zone files, so nothing
# this module did can outlive the daemon.
#
# firewall-cmd takes the whole rule as ONE argv element, so the spaces
# inside it are not a quoting problem - there is no shell to quote for.
###############################################################################
sub _open_firewalld {
	my ($self, $detection, $port, $address, $family) = @_;

	my $cmd = $detection->{tool};
	my $ipv = ($family == 6) ? 'ipv6' : 'ipv4';
	my $rule = qq{rule family="$ipv" source address="$address" port port="$port" protocol="tcp" accept};

	my $added = $self->run($cmd, '--add-rich-rule=' . $rule);
	return _decline('E_ADD_FAILED',
		'firewall-cmd refused to add the temporary rich rule: ' . _first_line($added->{output}))
		unless _ok($added);

	my ($canonical, $problem) = $self->_firewalld_find($cmd, $port, $address);
	unless (defined $canonical) {
		my $undone = $self->run($cmd, '--remove-rich-rule=' . $rule);
		return _decline('E_READBACK', $problem . _undo_note(_ok($undone), "$cmd --remove-rich-rule='$rule'"));
	}

	return { ok => 1, spec => {
		backend   => $detection->{backend},
		kind      => 'firewalld',
		binary    => $cmd,
		port      => $port,
		address   => $address,
		family    => $family,
		canonical => $canonical,
	} };
}

sub _firewalld_find {
	my ($self, $cmd, $port, $address) = @_;

	my $list = $self->run($cmd, '--list-rich-rules');
	return (undef, 'the rich rule was added but firewall-cmd --list-rich-rules would not run, so it cannot be read back or reliably removed')
		unless _ok($list);

	my @match = grep {
		/\bsource\s+address="\Q$address\E"/ && /\bport="\Q$port\E"/ && /\baccept\b/
	} map { my $l = $_; $l =~ s/^\s+//; $l =~ s/\s+\z//; $l } split(/\n/, $list->{output});

	return (undef, 'the rich rule was added but does not appear in firewall-cmd --list-rich-rules, so it cannot be reliably removed')
		unless @match;
	return (undef, scalar(@match) . " rich rules for $address on port $port are present; refusing to guess which one belongs to this session")
		if @match > 1;

	return ($match[0], undef);
}

###############################################################################
# ufw. Inserted at position 1 for the same reason as the iptables path.
#
# ufw's removal story is the awkward one: ufw delete N takes an index into
# a list that RENUMBERS every time anything is added or removed, so an index
# captured now is meaningless later. The canonical form stored here is
# therefore ufw's own rendering of the rule WITHOUT its index, and
# close_port() re-reads ufw status numbered at removal time to find what
# index that rendering currently has. That is read-back in the strictest
# sense available on this backend.
###############################################################################
sub _open_ufw {
	my ($self, $detection, $port, $address, $family) = @_;

	my $ufw = $detection->{tool};

	my $added = $self->run($ufw, 'insert', '1', 'allow', 'from', $address,
		'to', 'any', 'port', $port, 'proto', 'tcp');
	return _decline('E_ADD_FAILED',
		'ufw refused to add the temporary rule: ' . _first_line($added->{output}))
		unless _ok($added);

	my ($canonical, $problem) = $self->_ufw_find($ufw, $port, $address);
	unless (defined $canonical) {
		my @undo = ($ufw, '--force', 'delete', 'allow', 'from', $address,
			'to', 'any', 'port', $port, 'proto', 'tcp');
		my $undone = $self->run(@undo);
		return _decline('E_READBACK', $problem . _undo_note(_ok($undone), join(' ', @undo)));
	}

	return { ok => 1, spec => {
		backend   => $detection->{backend},
		kind      => 'ufw',
		binary    => $ufw,
		port      => $port,
		address   => $address,
		family    => $family,
		canonical => $canonical,
	} };
}

# Returns ($canonical_without_index, undef) or (undef, $why_not). The
# index is deliberately dropped: see _open_ufw()'s comment.
sub _ufw_parse_numbered {
	my ($text) = @_;
	my @row;
	for my $line (split(/\n/, defined $text ? $text : '')) {
		next unless $line =~ /^\s*\[\s*([0-9]+)\s*\]\s*(.+?)\s*\z/;
		my ($index, $rest) = ($1, $2);
		$rest =~ s/\s+/ /g;
		push @row, { index => $index + 0, canonical => $rest };
	}
	return \@row;
}

sub _ufw_find {
	my ($self, $ufw, $port, $address) = @_;

	my $list = $self->run($ufw, 'status', 'numbered');
	return (undef, 'the rule was added but ufw status numbered would not run, so it cannot be read back or reliably removed')
		unless _ok($list);

	my @match = grep {
		$_->{canonical} =~ /\Q$address\E/
			&& $_->{canonical} =~ /\b\Q$port\E\/tcp\b/
			&& $_->{canonical} =~ /\bALLOW\s+IN\b/i
	} @{ _ufw_parse_numbered($list->{output}) };

	return (undef, 'the rule was added but does not appear in ufw status numbered, so it cannot be reliably removed')
		unless @match;
	return (undef, scalar(@match) . " ufw rules allow $address to port $port; refusing to guess which one belongs to this session")
		if @match > 1;

	return ($match[0]{canonical}, undef);
}

###############################################################################
# close_port($self, \%spec) -> \%outcome
#
#   { ok => 1, removed => 1 }   the rule was found and removed
#   { ok => 1, removed => 0 }   the rule was already gone; nothing to do
#   { ok => 0, code => ..., reason => ..., manual => '...' }
#
# THE RULE THIS FUNCTION EXISTS TO KEEP: the argv that removes a rule is
# derived from a FRESH read-back of the backend, matched against the
# canonical text stored at open time. It is never assembled from
# $spec->{port} and $spec->{address}.
#
# Why that is not pedantry. The backend normalises: -s 203.0.113.5 comes
# back as -s 203.0.113.5/32, -p tcp --dport 8443 acquires an -m tcp,
# and the module order is the backend's to choose. A -D built from memory
# differs from the installed rule in at least one of those particulars,
# iptables matches rules for deletion by exact specification, and the
# deletion therefore silently removes nothing while returning success on
# some versions - leaving the port open with this code certain it had closed
# it. That is the failure this whole module is shaped around.
#
# When the stored canonical text is not present in the fresh read-back, this
# function removes NOTHING and says so, including the exact command the
# operator can run themselves. Guessing at that point - "well, something
# that looks roughly like it is there, take that out" - is how a wizard
# deletes a rule the administrator added by hand.
###############################################################################
sub close_port {
	my ($self, $spec) = @_;

	return _decline('E_SPEC', 'no rule specification was given, so there is nothing this can remove')
		unless ref($spec) eq 'HASH' && defined $spec->{canonical} && length $spec->{canonical};

	my $kind = defined $spec->{kind} ? $spec->{kind} : '';
	return $self->_close_iptables($spec)  if $kind eq 'iptables';
	return $self->_close_firewalld($spec) if $kind eq 'firewalld';
	return $self->_close_ufw($spec)       if $kind eq 'ufw';

	return _decline('E_SPEC', "the stored rule specification names backend kind '$kind', which this code cannot remove");
}

###############################################################################
# Turning a canonical -S line into a -D argv list.
#
# The canonical line is iptables' own output, which is shell-free by
# construction EXCEPT that a match argument containing whitespace is printed
# inside double quotes. This module never creates such a rule (see
# $RULE_COMMENT), but the rule being removed is whatever the backend is
# showing, and a quote in it means the line cannot be split on whitespace
# without implementing shell quoting rules. Rather than implement them
# wrongly, this refuses - fail closed, and tell the operator the line so
# they can act on it.
###############################################################################
sub _argv_from_canonical {
	my ($canonical) = @_;

	return (undef, 'the rule as the backend prints it contains a quote character, which cannot be split into arguments without implementing shell quoting; refusing to guess')
		if $canonical =~ /["']/;
	return (undef, 'the rule as the backend prints it does not begin with -A, so it is not an appended rule this code can convert into a deletion')
		unless $canonical =~ /^-A\s+(\S+)\s+(.+)\z/;

	my ($chain, $rest) = ($1, $2);
	my @argument = split(/\s+/, $rest);
	return (undef, 'the rule as the backend prints it has no arguments after the chain name')
		unless @argument;

	return ([ '-D', $chain, @argument ], undef);
}

###############################################################################
# _current($self, \%spec) - the single read-back.
#
#   { ok => 1, found => 0|1, line => '...', index => N, ambiguous => N }
#   { ok => 0, reason => '...' }
#
# Factored out because THREE callers need the same fact from the backend and
# three copies of "look for the stored canonical in a fresh listing" is three
# places for the rule to drift. close_port() needs the line (or the index) to
# act on; rule_present() needs only whether it is there; and the temporary
# port's re-assertion after csf -r needs the same answer again. One
# implementation, one set of failure messages.
###############################################################################
sub _current {
	my ($self, $spec) = @_;

	my $kind = defined $spec->{kind} ? $spec->{kind} : '';
	return $self->_current_iptables($spec)  if $kind eq 'iptables';
	return $self->_current_firewalld($spec) if $kind eq 'firewalld';
	return $self->_current_ufw($spec)       if $kind eq 'ufw';
	return { ok => 0, code => 'E_SPEC',
		reason => "the stored rule specification names backend kind '$kind', which this code cannot read back" };
}

sub _current_iptables {
	my ($self, $spec) = @_;

	my $binary = $spec->{binary};
	return { ok => 0, code => 'E_SPEC', reason => 'the stored rule specification names no iptables binary' }
		unless defined $binary && length $binary;

	my @wait = (ref($spec->{wait}) eq 'ARRAY') ? @{ $spec->{wait} } : ();
	my $list = $self->run($binary, @wait, '-S', $spec->{chain} || 'INPUT');
	return { ok => 0, reason => 'iptables -S would not run, so the rule this session added can be neither confirmed present nor removed' }
		unless _ok($list);

	my ($line) = grep { $_ eq $spec->{canonical} }
		map { my $l = $_; $l =~ s/\s+\z//; $l } split(/\n/, $list->{output});

	return { ok => 1, found => (defined $line ? 1 : 0), line => $line };
}

sub _current_firewalld {
	my ($self, $spec) = @_;

	my $cmd = $spec->{binary};
	return { ok => 0, code => 'E_SPEC', reason => 'the stored rule specification names no firewall-cmd binary' }
		unless defined $cmd && length $cmd;

	my $list = $self->run($cmd, '--list-rich-rules');
	return { ok => 0, reason => 'firewall-cmd --list-rich-rules would not run, so the rule this session added can be neither confirmed present nor removed' }
		unless _ok($list);

	my ($line) = grep { $_ eq $spec->{canonical} }
		map { my $l = $_; $l =~ s/^\s+//; $l =~ s/\s+\z//; $l } split(/\n/, $list->{output});

	return { ok => 1, found => (defined $line ? 1 : 0), line => $line };
}

sub _current_ufw {
	my ($self, $spec) = @_;

	my $ufw = $spec->{binary};
	return { ok => 0, code => 'E_SPEC', reason => 'the stored rule specification names no ufw binary' }
		unless defined $ufw && length $ufw;

	my $list = $self->run($ufw, 'status', 'numbered');
	return { ok => 0, reason => 'ufw status numbered would not run, so the rule this session added can be neither confirmed present nor removed' }
		unless _ok($list);

	my @match = grep { $_->{canonical} eq $spec->{canonical} }
		@{ _ufw_parse_numbered($list->{output}) };

	return { ok => 1, found => 0 } unless @match;
	return { ok => 1, found => 1, ambiguous => scalar(@match) } if @match > 1;
	return { ok => 1, found => 1, line => $match[0]{canonical}, index => $match[0]{index} };
}

###############################################################################
# rule_present($self, \%spec) -> (1 | 0 | undef, $why_undef)
#
# 1 the backend is showing this exact rule right now; 0 it is not; undef the
# backend could not be asked. undef is NOT 0: "there is no rule" and "I could
# not find out whether there is a rule" lead to opposite actions, and
# collapsing them is how a caller adds a second copy of a rule it already has.
###############################################################################
sub rule_present {
	my ($self, $spec) = @_;

	return (undef, 'no rule specification was given')
		unless ref($spec) eq 'HASH' && defined $spec->{canonical} && length $spec->{canonical};

	my $current = $self->_current($spec);
	return (undef, $current->{reason}) unless $current->{ok};
	return ($current->{found} ? 1 : 0, undef);
}

sub _close_iptables {
	my ($self, $spec) = @_;

	my $binary = $spec->{binary};
	my @wait = (ref($spec->{wait}) eq 'ARRAY') ? @{ $spec->{wait} } : ();

	my $current = $self->_current($spec);
	return { ok => 0, code => ($current->{code} || 'E_READBACK'), reason => $current->{reason} }
		unless $current->{ok};

	unless ($current->{found}) {
		return { ok => 1, removed => 0,
			reason => 'the rule this session added is no longer present in iptables -S; nothing was removed' };
	}

	# The line acted on is the one THIS listing produced, never $spec's copy
	# of it - see close_port()'s header for why that distinction is the
	# whole point of this module.
	my ($argv, $problem) = _argv_from_canonical($current->{line});
	unless ($argv) {
		return { ok => 0, code => 'E_UNREMOVABLE', reason => $problem,
			manual => "$binary -D " . ($spec->{chain} || 'INPUT') . ' ... (see: ' . $current->{line} . ')' };
	}

	my $removed = $self->run($binary, @wait, @$argv);
	unless (_ok($removed)) {
		return { ok => 0, code => 'E_REMOVE_FAILED',
			reason => 'iptables refused to remove the temporary rule: ' . _first_line($removed->{output}),
			manual => join(' ', $binary, @wait, @$argv) };
	}

	# Confirmed by reading back again, because "the command exited 0" and
	# "the rule is gone" are not the same claim.
	my $after = $self->_current($spec);
	if ($after->{ok} && $after->{found}) {
		return { ok => 0, code => 'E_REMOVE_FAILED',
			reason => 'iptables reported success but the rule is still present',
			manual => join(' ', $binary, @wait, @$argv) };
	}

	return { ok => 1, removed => 1 };
}

sub _close_firewalld {
	my ($self, $spec) = @_;

	my $cmd = $spec->{binary};
	my $current = $self->_current($spec);
	return { ok => 0, code => ($current->{code} || 'E_READBACK'), reason => $current->{reason} }
		unless $current->{ok};

	unless ($current->{found}) {
		return { ok => 1, removed => 0,
			reason => 'the rich rule this session added is no longer present; nothing was removed' };
	}

	# One argv element, verbatim as firewalld printed it. No re-quoting, no
	# reassembly from $spec->{address}/$spec->{port}.
	my $removed = $self->run($cmd, '--remove-rich-rule=' . $current->{line});
	unless (_ok($removed)) {
		return { ok => 0, code => 'E_REMOVE_FAILED',
			reason => 'firewall-cmd refused to remove the temporary rich rule: ' . _first_line($removed->{output}),
			manual => "$cmd --remove-rich-rule='$current->{line}'" };
	}
	return { ok => 1, removed => 1 };
}

sub _close_ufw {
	my ($self, $spec) = @_;

	my $ufw = $spec->{binary};
	my $current = $self->_current($spec);
	return { ok => 0, code => ($current->{code} || 'E_READBACK'), reason => $current->{reason} }
		unless $current->{ok};

	unless ($current->{found}) {
		return { ok => 1, removed => 0,
			reason => 'the rule this session added is no longer present in ufw status numbered; nothing was removed' };
	}
	if ($current->{ambiguous}) {
		return { ok => 0, code => 'E_UNREMOVABLE',
			reason => $current->{ambiguous} . ' ufw rules now render identically to the one this session added; refusing to guess which index to delete',
			manual => "$ufw status numbered" };
	}

	# The index comes from the listing just read, never from open time -
	# ufw renumbers on every change.
	my $removed = $self->run($ufw, '--force', 'delete', $current->{index});
	unless (_ok($removed)) {
		return { ok => 0, code => 'E_REMOVE_FAILED',
			reason => 'ufw refused to delete the temporary rule: ' . _first_line($removed->{output}),
			manual => "$ufw --force delete $current->{index}" };
	}
	return { ok => 1, removed => 1 };
}

1;
