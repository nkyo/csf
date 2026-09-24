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
# Task 10: the integration half. Four sections, in order of how much of the
# real system each one touches:
#
#   1. csf-ui-setup, driven for real (a real ConfigServer::UI::Setup
#      instance, fixtured rollback/firewall so nothing on this shared host
#      is touched) - what R101 is: the wizard writes ui.conf and nothing
#      else, while install-webui.sh points five separate messages at it to
#      "finish Mode A".
#   2. install-webui.sh's own Apache-module-enable functions, sourced from
#      the real file and driven with stub a2enmod/apache2ctl binaries in a
#      throwaway PATH - what R100 is: a2enmod exiting 1 after already
#      enabling some of the modules it was given, and the installer's own
#      record-then-enable logic losing track of that success.
#   3. the helper's real accept loop, over a REAL unix socket, in a forked
#      child this process owns - same-uid success, and (skipped without a
#      way to become a second real uid, stated below) wrong-uid E_PEER
#      rejection. No root is needed for the same-uid half: it is the
#      web-and-helper-halves-over-real-sockets requirement itself.
#   4. one HTTP login, end to end, through a real ConfigServer::UI::Server
#      mode-A listener (App/Session/RateLimit, all real) talking to the
#      REAL helper from section 3 over its real socket - not a FakeApp, not
#      a FakeClient, anywhere in this section.
#
# HOST HYGIENE. Nothing here writes to /var/lib/csf-ui, /etc/csf-ui,
# /var/run/csf-ui, /run/csf-ui-web or any other real system path - every
# path in every section below is under a File::Temp tempdir this file owns,
# and install-webui.sh's own MODULES_RECORD global is overridden to one
# after sourcing only its functions (never `main "$@"`, which the real file
# calls unconditionally at end of file and this harness never lets run).
# a2enmod, apache2ctl and systemctl are all stubs on a throwaway PATH -
# nothing here calls the real binaries, so nothing here changes this host's
# actual Apache/systemd state, which is the whole point of not just running
# the installer for real on a machine other sessions are using.
###############################################################################
use strict;
use warnings;

use FindBin ();
use lib "$FindBin::Bin/..", "$FindBin::Bin/../ui-src/lib";

use File::Temp qw(tempdir);
use Fcntl ();
use Socket ();
use POSIX ();
use Time::HiRes ();
use Test::More;

$SIG{PIPE} = 'IGNORE';

# Never dies past its own boundary (t/42/t/90/t/91's own convention): a die
# escaping into the enclosing test file is shape #2/#3 from the task
# brief - it either kills the whole run silently or aborts everything after
# it while what already ran keeps printing "ok". Every caller below checks
# the returned $err itself and turns a failure into a named, still-alive
# assertion.
our $BLOCKED = 0;
sub _bounded {
	my ($seconds, $code) = @_;
	local $SIG{ALRM} = sub { die "BOUND_ALARM\n" };
	alarm($seconds);
	my @out = eval { $code->() };
	my $err = $@;
	alarm(0);
	if ($err ne '') {
		$BLOCKED++ if $err eq "BOUND_ALARM\n";
		return (undef, $err);
	}
	return (\@out, undef);
}

sub _write { my ($p, $t) = @_; open(my $fh, '>', $p) or die "write $p: $!"; print $fh $t; close $fh }
sub _slurp { my ($p) = @_; open(my $fh, '<', $p) or return undef; local $/; return <$fh> }

# Shared by 3c (S2.2, the helper's own peer check) and 4b (S2.4, the mode-A
# listener's peer check) - both need a SECOND real uid connecting, and
# computing "can this process become one" twice would drift the two
# sections' skip reasons apart from each other for no reason.
sub _can_switch_uid {
	return (1, 'running as root') if $< == 0 || $> == 0;
	my ($result, $err) = _bounded(10, sub { return system('sudo', '-n', '-u', 'nobody', 'true') == 0 ? 1 : 0 });
	return (1, 'passwordless sudo to a second uid is available') if !defined($err) && $result->[0];
	return (0, 'not root, and sudo -n -u nobody failed - cannot produce a second real uid to connect as');
}

###############################################################################
# SECTION 1 - R101: csf-ui-setup writes ui.conf, and nothing that would let
# Mode A actually serve a request.
###############################################################################
{
	my $SETUP_PATH = "$FindBin::Bin/../ui-src/bin/csf-ui-setup";
	ok(-f $SETUP_PATH, 'csf-ui-setup is where the contract says it is');
	require $SETUP_PATH;
	my $Setup = 'ConfigServer::UI::Setup';

	# The structural half: what running csf-ui-setup CAN touch, read
	# straight from its own source rather than asserted from memory - the
	# same file that must actually change before this claim could go stale
	# without the test noticing.
	my $setup_source = _slurp($SETUP_PATH);
	for my $token (qw(grant_socket_group RuntimeDirectory csf-ui-web a2enmod nginx apache litespeed)) {
		unlike($setup_source, qr/\Q$token\E/i,
			"R101: csf-ui-setup's source never mentions '$token' - it has no code path that could set up a front server or its socket");
	}

	# The dynamic half: a real apply(), fixtured so nothing on this host is
	# touched (systemd_marker points at a directory that exists, so
	# systemd_available() says yes without a real systemctl call; the
	# runner intercepts every argv csf's own Firewall/Rollback layer would
	# otherwise run for real).
	my $root = tempdir(CLEANUP => 1);
	mkdir "$root/run-systemd";
	_write("$root/csf.conf", qq(TESTING = "0"\nTESTING_INTERVAL = "5"\nTCP_IN = "22,80,443"\n));
	my @ran;
	my $runner = sub { my (@argv) = @_; pop @argv; push @ran, join(' ', @argv); return { exit => 0, output => '' } };
	my $firewall = ConfigServer::UI::Firewall->new(runner => $runner, locate => sub { my ($n) = @_; return "/bin/$n" });
	my $rollback = ConfigServer::UI::Rollback->new(
		dir => "$root/rollback", unit_dir => "$root/units", csf_conf => "$root/csf.conf",
		ui_conf => "$root/ui.conf", setup_bin => $SETUP_PATH, systemd_marker => "$root/run-systemd",
		firewall => $firewall,
		# This test runs as an ordinary user: a real getgrnam('csfui') would
		# find nothing and a real chown to root:csfui would fail outright -
		# t/71-rollback.t's own world() fixture injects both for the same
		# reason (its own comment: "the OWNERSHIP is what the previous round
		# proved nothing about").
		gid_for => sub { my ($name) = @_; return ($name eq 'csfui') ? 4242 : undef },
		chown   => sub { return 1 },
		chmod   => sub { return chmod($_[0], $_[1]) },
	);
	mkdir "$root/setup-state";
	my $setup = $Setup->new(rollback => $rollback, ui_conf => "$root/ui.conf", csf_conf => "$root/csf.conf",
		firewall => $firewall, state_dir => "$root/setup-state");
	my $outcome = $setup->apply(answers => { UI_MODE => 'a', UI_ALLOW => '10.0.0.0/8' });
	ok($outcome->{ok}, 'R101: a plain Mode A apply() succeeds')
		or diag("reason: " . ($outcome->{reason} || '') . '; problems: ' . join('; ', @{ $outcome->{problems} || [] }));
	like(_slurp("$root/ui.conf") // '', qr/UI_MODE="a"/, 'R101: ...and ui.conf now says Mode A');

	# What it did NOT do: no unit was enabled, no group was granted, no
	# a2enmod/nginx/systemctl-daemon-reload/RuntimeDirectory call is
	# anywhere in the runner's log - only the rollback timer's own systemctl
	# calls (armed as a safety net for the CONFIG change, not Mode A itself)
	# and csf's own restart.
	my $log = join("\n", @ran);
	unlike($log, qr/a2enmod|grant_socket_group|RuntimeDirectory/i,
		'R101: nothing in what apply() actually ran touches a front server or its socket group');
}

###############################################################################
# SECTION 2 - R100: install-webui.sh's Apache-enable functions and its
# record-before-enable decision block, sourced from the real file (function
# bodies and the exact decision block, by line range - not retyped), and
# driven against stub a2enmod/apache2ctl that reproduce the MEASURED
# behaviour the ruling is about: a2enmod exits 1 having already enabled
# some of the modules it was given.
###############################################################################
{
	my $INSTALL_PATH = "$FindBin::Bin/../ui-src/dist/install-webui.sh";
	ok(-f $INSTALL_PATH, 'install-webui.sh is where the contract says it is');
	my @lines = do { open(my $fh, '<', $INSTALL_PATH) or die $!; <$fh> };

	# The function definitions (apache_check_modules, apache_enable_modules,
	# apache_disable_modules, MODULES_RECORD, record_modules_enabled,
	# clear_modules_enabled_record) and the decision block inside
	# setup_mode_a() that calls them (STEP 2/3, R93/R96/R97/R98) - located
	# by their own named anchors rather than a hardcoded line range, so a
	# harmless edit elsewhere in the file cannot silently make this section
	# extract the wrong bytes and pass for nothing.
	my ($func_start) = grep { $lines[$_] =~ /^apache_check_modules\(\) \{/ } (0 .. $#lines);
	my ($func_end)   = grep { $lines[$_] =~ /^clear_modules_enabled_record\(\) \{/ } (0 .. $#lines);
	# advance $func_end to that function's own closing brace
	while ($func_end < $#lines && $lines[$func_end] !~ /^\}/) { $func_end++ }
	my ($decision_start) = grep { $lines[$_] =~ /^\tmodules_enabled_this_run=""/ } (0 .. $#lines);
	my ($decision_end)   = grep { $lines[$_] =~ /^\tfi\n?\z/ && $_ > $decision_start } (0 .. $#lines);
	# Fix round 2 correction: `my ($decision_end) = grep {...}` takes
	# grep's FIRST match (list-to-scalar assignment) - there is no walking
	# forward to a second one here. What makes that first match the right
	# one is the pattern itself: `^\tfi` is anchored to exactly ONE leading
	# tab, and the inner "if [ -n \"\$still_missing\" ]; then ... fi" block
	# is indented with TWO tabs, so its "fi" never matches this regex at
	# all. The only "fi" this pattern can find, from $decision_start
	# onward, is the outer one closing "if [ \"\$front\" = \"apache\" ]" -
	# by exclusion, not by position.
	ok(defined($func_start) && defined($func_end) && defined($decision_start) && defined($decision_end),
		'R100: all four anchors were found in the real install-webui.sh (extraction targets a moving file by name, not a frozen line number)')
		or diag("func_start=" . (defined $func_start ? $func_start : 'undef') . " func_end=" . (defined $func_end ? $func_end : 'undef')
			. " decision_start=" . (defined $decision_start ? $decision_start : 'undef') . " decision_end=" . (defined $decision_end ? $decision_end : 'undef'));

	SKIP: {
		skip 'R100 extraction anchors were not found - see the failure above', 6
			unless defined($func_start) && defined($func_end) && defined($decision_start) && defined($decision_end);

		my $functions = join('', @lines[$func_start .. $func_end]);
		my $decision  = join('', @lines[$decision_start .. $decision_end]);

		my $sandbox = tempdir(CLEANUP => 1);
		mkdir "$sandbox/bin";
		# a2enmod: "enables" ssl and headers by touching a marker (this
		# sandbox's stand-in for Debian's real module-enable symlinks) and
		# then FAILS on the third name, exactly R100's measured shape -
		# partial, real, silent success followed by a nonzero exit.
		_write("$sandbox/bin/a2enmod", "#!/bin/sh\nfor m in \"\$@\"; do\n"
			. "  case \$m in\n    ssl|headers) touch \"$sandbox/enabled-\$m\" ;;\n"
			. "    *) echo \"a2enmod: Module \$m does not exist!\" >&2; exit 1 ;;\n  esac\ndone\nexit 0\n");
		chmod 0755, "$sandbox/bin/a2enmod";
		# Nothing reported loaded at all, so all three checked modules are
		# "missing" and enable_names comes out "ssl proxy_http headers" -
		# a2enmod above enables "ssl" (first) then fails on "proxy_http"
		# (second, standing in for R100's "<absent>"), so "headers" is never
		# even attempted - still exactly the measured shape: SOME of the
		# requested modules really got enabled before the overall call
		# failed.
		_write("$sandbox/bin/apache2ctl", "#!/bin/sh\nif [ \"\$1\" = \"-M\" ]; then\n"
			. "  :\nfi\nexit 0\n");
		chmod 0755, "$sandbox/bin/apache2ctl";

		# The decision block's `read -r reply` needs real stdin content - "y",
		# the operator consenting - fed from a file rather than piped in from
		# Perl, so the child process this section runs via open(..., '-|')
		# (which only wires up stdout) still has something to read.
		_write("$sandbox/reply", "y\n");
		# The decision block is a fragment of the real setup_mode_a()
		# function body and, in the real file, ends with `return 1` on the
		# refusal path this sandbox is built to reach - valid there because
		# it is inside a function. Wrapped in one here too (decision_block),
		# rather than sourced at the top level, so that `return` means what
		# it means in the real file instead of producing a shell error that
		# has nothing to do with what this section is testing.
		my $script = "#!/bin/sh\nset -u\nexec < \"$sandbox/reply\"\nPATH=\"$sandbox/bin:\$PATH\"\n"
			. "$functions\n"
			. "MODULES_RECORD=\"$sandbox/modules-record\"\n"
			. "front=apache\n"
			. "decision_block() {\n$decision\n}\n"
			. "decision_block\n"
			. "echo \"RC=\$?\"\n"
			. "echo \"RECORD_EXISTS=\" \$( [ -f \"$sandbox/modules-record\" ] && echo yes || echo no )\n"
			. "echo \"SSL_ENABLED=\" \$( [ -f \"$sandbox/enabled-ssl\" ] && echo yes || echo no )\n"
			. "echo \"HEADERS_ENABLED=\" \$( [ -f \"$sandbox/enabled-headers\" ] && echo yes || echo no )\n";
		_write("$sandbox/run.sh", $script);
		chmod 0755, "$sandbox/run.sh";

		my ($result, $err) = _bounded(10, sub {
			open(my $fh, '-|', 'bash', "$sandbox/run.sh") or die "cannot run sandbox script: $!";
			binmode($fh);
			local $/;
			my $text = <$fh>;
			close $fh;
			return $text;
		});
		ok(!defined($err), 'R100: the sandboxed decision block ran to completion without hanging or dying')
			or diag("error: $err");
		my $out = (defined $result ? $result->[0] : '') // '';

		like($out, qr/SSL_ENABLED=\s*yes/,
			'R100: the sandboxed a2enmod really did enable ssl before the overall call failed (matches the measured behaviour)');
		like($out, qr/RECORD_EXISTS=\s*no/,
			'R100: yet MODULES_RECORD no longer exists - clear_modules_enabled_record() ran on a call that partially succeeded');
		like($out, qr/not enabling Apache modules without confirmation/,
			'R100: and the operator is told nothing was enabled, though ssl demonstrably was - the message denies what the sandbox proves happened')
			or diag("sandbox output:\n$out");

		###########################################################################
		# R100's OTHER half - fix round 2, Task 11 minor #4. The a2enmod-
		# partial-failure path above is only half of R100; the other half is
		# at install-webui.sh's success path (setup_mode_a(), just after
		# write_ui_conf()/grant_socket_group()): `clear_modules_enabled_record`
		# runs UNCONDITIONALLY there, for every front end, not only the one
		# that might have written the record. A successful NGINX run - nginx
		# never touches Apache modules at all - deletes a MODULES_RECORD an
		# EARLIER, unrelated Apache run left behind as R98's own "dead-man's
		# note" for a crash between record-and-enable. Reproduced here by
		# anchor-extracting that exact 3-line success snippet (not the whole
		# function, which also calls the real write_ui_conf()/
		# grant_socket_group() - stubbed to no-ops in this sandbox, since
		# exercising THEM is not what this row is about and the real ones
		# write to /etc/csf-ui) and running it with front=nginx against a
		# MODULES_RECORD this test seeds itself, standing in for that earlier
		# Apache run.
		###########################################################################
		my ($success_start) = grep { $lines[$_] =~ /^\twrite_ui_conf a "\$port" "\$allow"/ } (0 .. $#lines);
		my ($success_end)   = grep { $lines[$_] =~ /^\tclear_modules_enabled_record\s*$/ } (0 .. $#lines);
		ok(defined($success_start) && defined($success_end) && $success_end > $success_start,
			'R100 (second half): the success-path anchor (write_ui_conf ... clear_modules_enabled_record) was found')
			or diag("success_start=" . (defined $success_start ? $success_start : 'undef')
				. " success_end=" . (defined $success_end ? $success_end : 'undef'));

		SKIP: {
			skip 'R100 (second half) anchors were not found - see the failure above', 2
				unless defined($success_start) && defined($success_end) && $success_end > $success_start;

			my $success_snippet = join('', @lines[$success_start .. $success_end]);
			my $sandbox2 = tempdir(CLEANUP => 1);
			_write("$sandbox2/modules-record", "ssl headers\n");   # the earlier Apache run's own dead-man's note

			my $script2 = "#!/bin/sh\nset -u\n"
				. "MODULES_RECORD=\"$sandbox2/modules-record\"\n"
				. "front=nginx\n"                                  # THIS run is nginx - never touched a module
				. "port=8443\nallow='10.0.0.0/8'\n"
				. "write_ui_conf() { :; }\n"                       # real one writes to /etc/csf-ui; not what this row tests
				. "grant_socket_group() { :; }\n"
				. "clear_modules_enabled_record() { rm -f \"\$MODULES_RECORD\" 2>/dev/null; }\n"
				. "success_snippet() {\n$success_snippet\n}\n"
				. "success_snippet\n"
				. "echo \"RECORD_EXISTS_AFTER=\" \$( [ -f \"$sandbox2/modules-record\" ] && echo yes || echo no )\n";
			_write("$sandbox2/run2.sh", $script2);
			chmod 0755, "$sandbox2/run2.sh";

			my ($result2, $err2) = _bounded(10, sub {
				open(my $fh, '-|', 'bash', "$sandbox2/run2.sh") or die "cannot run sandbox script: $!";
				binmode($fh);
				local $/;
				my $text = <$fh>;
				close $fh;
				return $text;
			});
			ok(!defined($err2), 'R100 (second half): the sandboxed success-path snippet ran to completion')
				or diag("error: $err2");
			my $out2 = (defined $result2 ? $result2->[0] : '') // '';
			like($out2, qr/RECORD_EXISTS_AFTER=\s*no/,
				'R100 (second half): a successful NGINX run deletes a MODULES_RECORD it never wrote - '
				. 'clear_modules_enabled_record() is unconditional on every front end\'s success path, not only Apache\'s')
				or diag("sandbox output:\n$out2");
		}
	}

	# R101's other half, named in the brief: five OPERATOR-FACING messages
	# point at csf-ui-setup to "finish" Mode A. Fix round 2, Task 11 minor
	# #3: a bare count of the substring "csf-ui-setup" is 9, not 5 - two
	# `for bin in csf-ui csf-ui-helper csf-ui-passwd csf-ui-setup` install
	# loops, one `csf-ui-helper|csf-ui-passwd|csf-ui-setup) : ;;` case arm,
	# and one header comment make up the other four, and a
	# `cmp_ok(..., '>=', 4)` deleting all FIVE real messages at once - the
	# exact thing Task 11 will be tempted to do while rewording this file -
	# would still pass, because "9 mentions minus 5 real ones" is still 4.
	# Each message asserted by name below instead.
	#
	# CHANGED 2026-09-24, deliberately, and this list was RED for one run
	# while the change was made. The five messages above characterised
	# wording that was WRONG, not wording that was right: bare
	# `csf-ui-setup` falls through every branch of run() to _usage() and
	# exit 2, and even used correctly (--web) it enables no unit, writes
	# no front-server vhost and creates no account - so it could not
	# "finish" or "turn on" anything. Pinning the old strings is what a
	# characterisation test is FOR; what it must not do is outlive the
	# decision it recorded. The five replacements below all point at the
	# one thing that does configure the WebUI, which is this installer.
	my $source = join('', @lines);
	my @EXPECTED_MESSAGE = (
		'csf-ui: when ready, then re-run this installer at a terminal:',
		'csf-ui:   anything else = skip for now (re-run this installer to set it up)',
		'csf-ui: skipping WebUI setup. Re-run this installer at a terminal to set it up.',
		'csf-ui: no address given - leaving the WebUI unconfigured. Re-run this installer',
		'csf-ui: re-run this installer at a terminal to set it up: it is the only thing',
	);
	for my $message (@EXPECTED_MESSAGE) {
		like($source, qr/\Q$message\E/,
			"R101: install-webui.sh tells the operator: $message");
	}

	# ...and none of them may go back to naming csf-ui-setup as the way to
	# set the WebUI up. Asserted as an ABSENCE too, because the five
	# positives above would all still pass if a sixth message reintroduced
	# the claim somewhere else in the file.
	unlike($source, qr/run\s+'?csf-ui-setup/i,
		'R101: no message tells the operator to "run csf-ui-setup" to set the WebUI up');

	###########################################################################
	# C1 - setup_mode_a() must ENABLE the Mode A listener it just configured.
	#
	# This is the assertion whose absence let the defect ship. The stale
	# text it replaces was true when Task 9 wrote it and false at the
	# commit that added Server.pm's Mode A listen path; nothing anywhere
	# in the branch asserted it either way, so nothing reddened. A Mode A
	# install - the mode this installer RECOMMENDS - wrote a correct
	# vhost, started the helper, never started the web tier, returned 502
	# for every request, and told the operator to delete the vhost.
	#
	# Extracted by name, like the R100 block above, rather than by line.
	###########################################################################
	my ($mode_a_start) = grep { $lines[$_] =~ /^setup_mode_a\(\) \{/ } (0 .. $#lines);
	my $mode_a_end = defined $mode_a_start ? $mode_a_start : 0;
	while ($mode_a_end < $#lines && $lines[$mode_a_end] !~ /^\}/) { $mode_a_end++ }
	ok(defined($mode_a_start) && $mode_a_end > $mode_a_start,
		'C1: setup_mode_a() was located in the real install-webui.sh');

	SKIP: {
		skip 'C1: setup_mode_a() was not found - see the failure above', 5
			unless defined($mode_a_start) && $mode_a_end > $mode_a_start;
		my $mode_a = join('', @lines[$mode_a_start .. $mode_a_end]);

		like($mode_a, qr/^\s*_enable_now csf-ui\.service$/m,
			'C1: setup_mode_a() enables csf-ui.service - the Mode A listener Server.pm now provides');
		like($mode_a, qr/^\s*_enable_now csf-ui-helper\.service$/m,
			'C1: ...and the root helper, as it always did');
		unlike($mode_a, qr/has no Mode A listener/,
			'C1: setup_mode_a() no longer claims this build has no Mode A listener');
		unlike($mode_a, qr/deliberately NOT enabled/,
			'C1: ...nor that csf-ui.service is deliberately left disabled');
		unlike($mode_a, qr/remove \$out first/,
			'C1: ...nor tells the operator to delete the vhost it just wrote and validated');
	}

	# The premise of the C1 assertions above, measured at its source
	# rather than assumed: Server.pm really does have a Mode A listen
	# path. If this ever stops being true, the right answer is to stop
	# enabling the unit again - not to leave the two disagreeing.
	my $server_source = _slurp("$FindBin::Bin/../ui-src/lib/ConfigServer/UI/Server.pm");
	like($server_source, qr/sub _open_unix_listener/,
		'C1 (premise): ConfigServer::UI::Server has a unix-socket listener');
	like($server_source, qr/sub mode_a_preflight/,
		'C1 (premise): ...and a mode-A preflight, so mode A is a supported start, not a refusal');
}

###############################################################################
# SECTION 3 - the helper's real accept loop, over a real unix socket, in a
# forked child this test owns. open_socket() itself is not called here: it
# hard-codes chown(0, gid-of-csfui, ...) and dies without the real csfui
# group and root, neither of which this task may create on a shared host
# (see the report's host-hygiene section) - so the listener is bound the
# same way t/42-listen-loop.t binds Server.pm's own mode-A socket: for
# real, by hand, with the mode set explicitly rather than inherited.
###############################################################################
my $HELPER_PATH = "$FindBin::Bin/../ui-src/bin/csf-ui-helper";
require $HELPER_PATH;
my $H = 'ConfigServer::UI::Helper';
my $P = 'ConfigServer::UI::Proto';

our $ITEST_DIR = tempdir(CLEANUP => 1);
our $HELPER_SOCK = "$ITEST_DIR/helper.sock";

sub _start_helper_daemon {
	my $pid = fork();
	die "fork: $!" unless defined $pid;
	if ($pid) {
		for (1 .. 200) { last if -S $HELPER_SOCK; Time::HiRes::sleep(0.01) }
		return $pid;
	}

	# Mode 0666 so BOTH this process's own uid (the "correct peer" case)
	# and, when section 4b below can become a second real uid, that second
	# uid (the "wrong peer" case) can complete connect() - the identity
	# decision under test is check_peer()'s SO_PEERCRED read, not the
	# filesystem permission bit, which is deliberately left permissive here
	# so the application-level gate is what is actually being exercised.
	socket(my $listener, Socket::PF_UNIX(), Socket::SOCK_STREAM(), 0) or POSIX::_exit(70);
	unlink $HELPER_SOCK;
	bind($listener, Socket::pack_sockaddr_un($HELPER_SOCK)) or POSIX::_exit(71);
	chmod 0666, $HELPER_SOCK;
	listen($listener, 16) or POSIX::_exit(72);

	my %path = (
		socket_dir => $ITEST_DIR, socket => $HELPER_SOCK, rate_state => "$ITEST_DIR/rate.state",
		helper_dir => "$ITEST_DIR/helperstate", authfail => "$ITEST_DIR/helperstate/authfail.state",
		audit_log => "$ITEST_DIR/audit.log", users => "$ITEST_DIR/users", csf_bin => "$ITEST_DIR/csf",
		csf_conf => "$ITEST_DIR/csf.conf", csf_deny => "$ITEST_DIR/csf.deny", csf_allow => "$ITEST_DIR/csf.allow",
		csf_disable => "$ITEST_DIR/csf.disable", csf_error => "$ITEST_DIR/csf.error",
		csf_version => "$ITEST_DIR/version.txt", tempban => "$ITEST_DIR/csf.tempban",
		tempallow => "$ITEST_DIR/csf.tempallow", lfd_pid => "$ITEST_DIR/lfd.pid",
	);
	mkdir $path{helper_dir};
	_write($path{csf_conf}, qq(TESTING = "0"\nIPV6 = "0"\nLF_IPSET = "0"\nIPTABLES = "/sbin/iptables"\nIP6TABLES = "/sbin/ip6tables"\n));
	_write($path{csf_deny}, ''); _write($path{csf_allow}, ''); _write($path{tempban}, ''); _write($path{tempallow}, '');
	_write($path{csf_version}, "15.00\n");
	# A REAL crypt() hash for a known password, section 5.14's own path -
	# this daemon answers `authenticate` for real, not from a stub.
	my $hash = crypt('itest-secret-9f2', '$6$itestsalt$');
	_write($path{users}, "alice:6:$hash:admin:1757548800\n");
	chmod 0600, $path{users};

	my $ctx = $H->can('new_context')->(
		path => \%path, now => sub { time() }, expect_uid => $> + 0, group_ready => 1,
		run => sub { return { exit => 0, status => 0, output => '' } },
	);

	$SIG{TERM} = sub { POSIX::_exit(0) };
	while (1) {
		my $connection;
		my $addr = accept($connection, $listener);
		next unless $addr;
		my ($problem, $peer, $reason, $silent) = $H->can('check_peer')->($ctx, $connection);
		if ($problem) {
			$H->can('write_response')->($connection, { id => undef, ok => \0, error => $problem, message => $reason }, 2)
				unless $silent;
			close $connection;
			next;
		}
		my $response = $H->can('serve_connection')->($ctx, $connection, $peer);
		$H->can('write_response')->($connection, $response, 2) if $response;
		close $connection;
	}
}

my $HELPER_PID = _start_helper_daemon();
ok(-S $HELPER_SOCK, 'the helper daemon bound a real unix socket');

sub _stop_daemon {
	my ($pid) = @_;
	return unless defined $pid;
	kill 'TERM', $pid;
	my $deadline = Time::HiRes::time() + 10;
	while (Time::HiRes::time() < $deadline) {
		my $done = waitpid($pid, POSIX::WNOHANG());
		return if $done == $pid;
		Time::HiRes::sleep(0.02);
	}
	kill 'KILL', $pid;
	my (undef, $err) = _bounded(10, sub { waitpid($pid, 0); return 1 });
	diag("_stop_daemon: final waitpid did not return on its own: $err") if defined $err;
}

###############################################################################
# 3a. SAME uid: the connecting process's own uid IS expect_uid - no root
# needed for this half, and it is what "helper ... over real sockets" means.
###############################################################################
{
	socket(my $client, Socket::PF_UNIX(), Socket::SOCK_STREAM(), 0) or die "socket: $!";
	my ($connect_result, $connect_err) = _bounded(10, sub { return connect($client, Socket::pack_sockaddr_un($HELPER_SOCK)) ? 1 : 0 });
	ok(!defined($connect_err) && $connect_result->[0], '3a: this process (same uid as expect_uid) can connect to the real helper socket')
		or diag(defined $connect_err ? "error: $connect_err" : 'connect() returned false');

	my $line = $P->can('encode')->({ op => 'status', args => {}, id => '3a3a3a3a3a3a3a3a' });
	syswrite($client, $line);
	my ($read_result, $read_err) = _bounded(10, sub { return $P->can('read_message')->($client, time() + 5) });
	close $client;
	ok(!defined($read_err), '3a: reading the response does not hang') or diag("error: $read_err");
	my $resp = defined $read_result ? $read_result->[0] : undef;
	ok(ref($resp) eq 'HASH' && $resp->{ok}, '3a: a same-uid request over the real socket gets a real ok:true response')
		or diag('resp=' . (ref($resp) eq 'HASH' ? join(',', map {"$_=".(defined $resp->{$_}?$resp->{$_}:'undef')} sort keys %$resp) : 'not a hashref'));
	is($resp->{id}, '3a3a3a3a3a3a3a3a', '3a: and the id echoes back verbatim') if ref($resp) eq 'HASH';
}

###############################################################################
# 3b. ConfigServer::UI::Client itself, against the same real socket - the
# module Task 5/7's App actually uses, not a hand-rolled Proto call.
###############################################################################
{
	my $client = ConfigServer::UI::Client->new(socket_path => $HELPER_SOCK, timeout => 5);
	my ($result, $err) = _bounded(10, sub { return $client->call('counts', {}) });
	ok(!defined($err), '3b: ConfigServer::UI::Client->call does not hang') or diag("error: $err");
	my $resp = defined $result ? $result->[0] : undef;
	ok(ref($resp) eq 'HASH' && $resp->{ok}, '3b: ConfigServer::UI::Client gets a real ok:true "counts" response over the real socket');
}

###############################################################################
# 3c. WRONG uid: skipped, with a stated reason, unless this process can
# become a second real uid. True root ($< == 0) always can; a passwordless
# sudo grant (measured directly, not assumed from $<) can too - both are
# "root" for this purpose, because what the peer-credential check needs is
# a SECOND real uid connecting, and root is what makes that possible either
# way. Recorded rather than silently skipped either way (one of the five
# shapes this task's own brief warns a hollow skip can take).
#
# NOT silent. check_peer()'s own header comment (ui-src/bin/csf-ui-helper,
# above sub check_peer) is explicit that $silent - "answer nothing at all" -
# is set on exactly ONE of its four rejection rows: SO_PEERCRED itself
# failing (the kernel won't vouch for the peer at all). The wrong-uid row
# and the uid-0 row both return $silent undef, so the helper DOES write a
# real {"ok":false,"error":"E_PEER",...} response for a wrong-uid peer -
# rejected, but answered. An earlier draft of this section asserted the
# wrong thing here (empty output) and that assertion happened to keep
# passing through a real bug in the read loop below (see the report's
# fix-round-1 entry) that was silently discarding real bytes - two defects
# masking each other until the read loop was fixed and this one stopped
# matching reality. Fixed to assert what section 2.2 actually specifies.
###############################################################################
our ($CAN_SWITCH_UID, $SWITCH_UID_WHY) = _can_switch_uid();
{
	SKIP: {
		skip "3c/3d: wrong-uid peer rejection needs a second real uid ($SWITCH_UID_WHY)", 4 unless $CAN_SWITCH_UID;

		# Every early exit prints a DISTINCT, greppable marker before it
		# exits - a socket()/connect() failure must never look identical to
		# "connected fine and got nothing back", or a broken sandbox (wrong
		# permissions, wrong path) would make section 3c pass for having
		# proven nothing at all, which is exactly the hollow-skip failure
		# shape this task's own brief warns about, just one layer deeper
		# than a SKIP block.
		# The prober writes its result to a FILE under /tmp (sticky,
		# world-writable, so a process running as 'nobody' can create one)
		# rather than relying on `open(..., '-|', 'sudo', ...)` capturing
		# its stdout - measured on this host: sudo's own handling of a
		# piped, non-tty stdout across a uid switch did not reliably
		# deliver the child's output back through the pipe, which would
		# make an infrastructure gap look identical to "got nothing back",
		# exactly the false-positive this section exists to rule out. A
		# file both processes can name is a plain, unambiguous channel.
		my $result_path = "/tmp/csf-ui-itest-3c-$$-" . int(rand(1_000_000)) . '.out';
		my $prober = <<PERL;
use Socket ();
my (\$sock_path, \$line) = \@ARGV;
open(my \$rf, '>', '$result_path') or exit 4;
socket(my \$c, Socket::PF_UNIX(), Socket::SOCK_STREAM(), 0) or do { print \$rf "PROBE_SOCKET_FAILED:\$!"; exit 2 };
connect(\$c, Socket::pack_sockaddr_un(\$sock_path)) or do { print \$rf "PROBE_CONNECT_FAILED:\$!"; exit 3 };
my \$out = '';
eval {
	local \$SIG{ALRM} = sub { die "t\\n" };
	# 10s (widened from 5s in fix round 2, on a since-disproven timeout
	# theory - the real cause was the EPIPE race fixed just below, not a
	# deadline anywhere being too tight). Kept anyway: it costs nothing
	# measurable (t/92 alone runs in well under a second) and is still
	# real margin against unrelated host contention, so there is no reason
	# to narrow it back just because it was not the actual fix.
	alarm(10);
	# NOT "or die": the helper answers a wrong-uid peer with E_PEER and
	# CLOSES (section 2.2's own behaviour, proven by 3c's own assertion
	# below). Under contention the close can land before this write
	# completes, syswrite() then fails with EPIPE, and the response is
	# ALREADY SITTING in this process's receive buffer, unread. Dying here
	# would throw that real, correct answer away and misreport it as "the
	# peer answered nothing" - a false negative on the exact behaviour this
	# section exists to prove. Fix round 3: measured as the actual cause of
	# an intermittent failure (misdiagnosed as a timeout in fix round 2,
	# which widened alarms that turned out to be irrelevant to this race).
	# A syswrite() failure here is not fatal; the read loop below is what
	# decides whether anything real came back.
	syswrite(\$c, \$line);
	# NOT "1 while sysread(\$c, my \$chunk, 4096) > 0 and (...)" - a 'my'
	# declared inside a postfix-while's own condition does not carry its
	# value into the low-precedence 'and' clause of that SAME condition on
	# each re-evaluation (reproduced in isolation, minimal case, outside
	# this file entirely - see the fix-round-1 report). It silently read
	# real bytes and then silently threw them away: \$out stayed '' even
	# though sysread() was genuinely returning data, which is exactly what
	# made an accepted wrong-uid connection look identical to a rejected
	# one. An explicit while-block with \$chunk declared as its own
	# statement is the form every other read loop in this file already
	# uses (see \$wc's read loop below) and does not have this failure mode.
	while (1) {
		my \$chunk;
		my \$n = sysread(\$c, \$chunk, 4096);
		last unless defined \$n && \$n > 0;
		\$out .= \$chunk;
	}
	alarm(0);
};
print \$rf "PROBE_EVAL_DIED:\$@" if \$@ && \$@ ne "t\\n";
print \$rf \$out;
close \$rf;
PERL
		# world-readable/traversable so the SECOND uid can read and run this
		# script at all - otherwise "no bytes came back" could mean nothing
		# more than "nobody could not open the file", which would pass this
		# assertion for a reason that has nothing to do with check_peer().
		chmod 0755, $ITEST_DIR;
		my $script_path = "$ITEST_DIR/prober.pl";
		_write($script_path, $prober);
		chmod 0755, $script_path;
		my $line = $P->can('encode')->({ op => 'status', args => {}, id => '3c3c3c3c3c3c3c3c' });

		my (undef, $err) = _bounded(20, sub {
			return system('sudo', '-n', '-u', 'nobody', $^X, $script_path, $HELPER_SOCK, $line);
		});
		ok(!defined($err), '3c: the wrong-uid prober process returns rather than hanging') or diag("error: $err");
		my $out = _slurp($result_path) // '';
		# /tmp is sticky: a file 'nobody' created there can only be removed
		# by 'nobody' (or root), not by this process - unlink() alone would
		# silently fail and leak it, which this task's host-hygiene rules forbid.
		system('sudo', '-n', '-u', 'nobody', 'rm', '-f', $result_path);
		unlink $result_path;   # in case it was somehow created as this uid instead

		unlike($out, qr/^PROBE_(SOCKET|CONNECT)_FAILED/,
			'3c: the prober actually reached connect() as the second uid - a sandbox/permission failure here would prove nothing about check_peer()')
			or diag("prober infra failure: $out");
		# section 2.2: the wrong-uid row is a REAL E_PEER response, not a
		# silent close (only the SO_PEERCRED-unavailable row is silent) -
		# see the header comment above this section for how this file's
		# earlier, wrong assertion here (expecting nothing at all) survived
		# undetected.
		like($out, qr/"error":"E_PEER"/,
			'3c: a peer with the wrong uid is answered a real E_PEER rejection over the real socket')
			or diag("got: " . length($out) . ' bytes: ' . substr($out, 0, 200));
		unlike($out, qr/"ok":true/,
			'3c: ...and never ok:true - whatever it is, it is not success');
	}
}

_stop_daemon($HELPER_PID);
ok(1, 'the helper daemon was stopped');

###############################################################################
# SECTION 4 - a real ConfigServer::UI::Server mode-A listener (real App,
# real Session, real RateLimit) talking to a FRESH real helper daemon (the
# same launcher as section 3) over ITS real socket - one HTTP login, start
# to finish, through both real halves.
###############################################################################
{
	require "$FindBin::Bin/../ui-src/bin/csf-ui";
	# By module name, not by file path: csf-ui's own login route already
	# pulls Server.pm in via `require ConfigServer::UI::Server;` (a bareword
	# require, keyed in %INC by module name), so requiring the same module
	# again by its file path here would bypass that key and load it a
	# second time, redefining every sub in it.
	require ConfigServer::UI::Server;
	my $S = 'ConfigServer::UI::Server';
	my $A = 'ConfigServer::UI::App';

	# A second helper socket/daemon, independent of section 3's (which is
	# already stopped), so this section stands on its own.
	my $dir2 = tempdir(CLEANUP => 1);
	local $HELPER_SOCK = "$dir2/helper.sock";
	local $ITEST_DIR = $dir2;
	my $pid2 = _start_helper_daemon();

	my $client = ConfigServer::UI::Client->new(socket_path => $HELPER_SOCK, timeout => 5);
	my $sessions  = ConfigServer::UI::Session->new(dir => "$dir2/sessions", now => sub { time() });
	my $ratelimit = ConfigServer::UI::RateLimit->new(dir => "$dir2/rl", now => sub { time() });
	my $app = $A->new(client => $client, sessions => $sessions, ratelimit => $ratelimit,
		access_log => "$dir2/access.log", now => sub { time() });

	my $web_sock = "$dir2/web.sock";
	my $web_conf = "$dir2/ui.conf";
	_write($web_conf, qq(UI_MODE="a"\nUI_ALLOW="10.0.0.0/8"\n));

	my $web_pid = fork();
	die "fork: $!" unless defined $web_pid;
	if (!$web_pid) {
		# admit_peer()'s own _refuse_peer() logs to STDERR (S2.4's own
		# words: "one line per distinct refused uid goes to stderr") -
		# captured to a file rather than left to interleave with TAP
		# output, and surfaced via diag() only when 4b's own assertion
		# below actually fails.
		open(STDERR, '>', "$dir2/web-daemon.err") or POSIX::_exit(70);
		my $server = $S->new(
			app => $app, ui_conf_path => $web_conf, socket_path => $web_sock,
			# Fix round 2, Task 11 minor #5: this uid is not a stand-in for
			# a real peer - admit_peer()'s own peer_uid_allowed() already
			# admits $self_uid (this process's own uid) unconditionally, so
			# `$> + 0 => 1` here is redundant with that. What it is NOT
			# redundant with is run()'s own startup refusal ("no account
			# other than this one can reach the mode-A socket") at
			# _no_local_peer_message() - an accepted set naming ONLY self
			# refuses to start outright (S2.4's own words: "csf-ui refuses
			# to start in mode A when the accepted set names nobody but
			# itself"). A second, fictitious uid that is never actually
			# used to connect (same device t/42-listen-loop.t's own daemon
			# fixture uses, for the same reason) is what lets this section
			# get past that refusal without a real second host account.
			peer_uids => { $> + 0 => 1, 4294967294 => 1 },
			header_timeout => 5, body_timeout => 5, write_timeout => 5, dispatch_timeout => 5,
		);
		my $rc = eval { $server->run() };
		POSIX::_exit(defined $rc ? $rc : 71);
	}
	for (1 .. 200) { last if -S $web_sock; Time::HiRes::sleep(0.01) }
	ok(-S $web_sock, 'section 4: the mode-A web listener also bound a real unix socket');

	socket(my $wc, Socket::PF_UNIX(), Socket::SOCK_STREAM(), 0) or die "socket: $!";
	my ($connect_result, $connect_err) = _bounded(10, sub { return connect($wc, Socket::pack_sockaddr_un($web_sock)) ? 1 : 0 });
	ok(!defined($connect_err) && $connect_result->[0], 'section 4: can connect to the real web-tier socket')
		or diag(defined $connect_err ? "error: $connect_err" : 'connect() returned false');

	my $body = 'user=alice&pass=itest-secret-9f2';
	my $req = "POST /api/login HTTP/1.1\r\nHost: x\r\nX-Real-IP: 10.0.0.7\r\n"
		. "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: " . length($body) . "\r\n\r\n$body";
	syswrite($wc, $req);

	my $out = '';
	my (undef, $read_err) = _bounded(15, sub {
		my $deadline = Time::HiRes::time() + 10;
		while (Time::HiRes::time() < $deadline) {
			my $chunk;
			my $read = sysread($wc, $chunk, 8192);
			last unless defined $read && $read > 0;
			$out .= $chunk;
			last if $out =~ /\r\n\r\n\{/ && $out =~ /\}\s*\z/;
		}
		return 1;
	});
	ok(!defined($read_err), 'section 4: reading the login response does not hang') or diag("error: $read_err");
	close $wc;

	like($out, qr{\AHTTP/1\.1 200}, 'section 4: end-to-end login over two real unix sockets returns 200')
		or diag("response(200)=" . substr($out, 0, 200));
	like($out, qr/Set-Cookie:/i, 'section 4: ...and mints a real session cookie')
		or diag("response(200)=" . substr($out, 0, 200));
	like($out, qr/"role":"admin"/, 'section 4: ...carrying the role the real helper answered with, from a real crypt() verify')
		or diag("response(300)=" . substr($out, 0, 300));

	###########################################################################
	# 4b. Fix round 2, Task 11 minor #5: S2.4's OWN peer check, on the
	# mode-A LISTENER's socket - the whole point of this listener, and
	# previously untested by anything in this file. Row 3c already proves
	# S2.2 (the HELPER's peer check); this is the other one, admit_peer()
	# in Server.pm, and the two are explicitly NOT the same rule (S2.4:
	# "the two rules are not the same"). Chief difference proven here: S2.2
	# answers a wrong uid with a real E_PEER JSON response; S2.4 answers
	# with NOTHING AT ALL - "The connection is closed before a byte is
	# read" (S2.4's own words) - so the assertion below is not "empty
	# JSON", it is zero bytes, full stop.
	###########################################################################
	SKIP: {
		skip "4b: wrong-uid S2.4 rejection needs a second real uid ($SWITCH_UID_WHY)", 3 unless $CAN_SWITCH_UID;

		# The socket's own mode (0660, asserted elsewhere against
		# $UNIX_SOCKET_MODE) would refuse 'nobody' at the filesystem layer
		# before admit_peer() is ever reached - which would prove nothing
		# about admit_peer() itself, only about a mode bit S2.3 already
		# covers. Loosened here, on this test's own throwaway socket only,
		# so the REJECTION under test is the application-level one.
		#
		# Worth stating plainly rather than leaving implicit: this host is
		# explicitly shared with other agents' labs (this project's own
		# CLAUDE.md says so), and for the remainder of THIS SKIP block any
		# local account on the host - not only 'nobody' - can connect to
		# this one throwaway mode-A socket, because 0666 admits anyone who
		# can reach the path and 0755 on $dir2 makes the path reachable.
		# Bounded in scope (this socket only, this tempdir only, torn down
		# with the rest of $dir2 when this file exits) and bounded in time
		# (only while this SKIP block runs), but real for that window - not
		# a mode this project would ever ship, and not one any other file
		# in this test tree leaves open past the one check that needs it.
		chmod 0666, $web_sock;
		chmod 0755, $dir2;

		my $result_path4b = "/tmp/csf-ui-itest-4b-$$-" . int(rand(1_000_000)) . '.out';
		my $prober4b = <<PERL;
use Socket ();
my \$sock_path = shift \@ARGV;
open(my \$rf, '>', '$result_path4b') or exit 4;
socket(my \$c, Socket::PF_UNIX(), Socket::SOCK_STREAM(), 0) or do { print \$rf "PROBE_SOCKET_FAILED:\$!"; exit 2 };
connect(\$c, Socket::pack_sockaddr_un(\$sock_path)) or do { print \$rf "PROBE_CONNECT_FAILED:\$!"; exit 3 };
my \$out = '';
eval {
	local \$SIG{ALRM} = sub { die "t\\n" };
	alarm(10);
	syswrite(\$c, "GET /api/status HTTP/1.1\\r\\nHost: x\\r\\nX-Real-IP: 10.0.0.7\\r\\n\\r\\n");
	while (1) {
		my \$chunk;
		my \$n = sysread(\$c, \$chunk, 4096);
		last unless defined \$n && \$n > 0;
		\$out .= \$chunk;
	}
	alarm(0);
};
print \$rf "PROBE_EVAL_DIED:\$@" if \$@ && \$@ ne "t\\n";
# Fix round 3, shape 9 (the review's own name: "the expected observation
# is the null observation" - a pass condition of "nothing came back"
# cannot tell the guard firing apart from the probe never running at all).
# A POSITIVE CONTROL: this marker is written unconditionally, right before
# close, whenever execution reaches this far - so its ABSENCE (not merely
# an empty \$out) is what "the probe never ran, or died, or could not be
# read back" looks like, and THAT must redden this row, not pass it.
print \$rf "PROBE_DONE:" . length(\$out) . "\\n" . \$out;
close \$rf;
PERL
		my $script_path4b = "$dir2/prober4b.pl";
		_write($script_path4b, $prober4b);
		chmod 0755, $script_path4b;

		my (undef, $probe_err) = _bounded(20, sub {
			return system('sudo', '-n', '-u', 'nobody', $^X, $script_path4b, $web_sock);
		});
		ok(!defined($probe_err), '4b: the wrong-uid prober process returns rather than hanging') or diag("error: $probe_err");
		my $out4b = _slurp($result_path4b) // '';
		system('sudo', '-n', '-u', 'nobody', 'rm', '-f', $result_path4b);
		unlink $result_path4b;

		unlike($out4b, qr/^PROBE_(SOCKET|CONNECT)_FAILED/,
			'4b: the prober actually reached connect() as the second uid on the WEB socket')
			or diag("prober infra failure: $out4b");
		# The positive control IS the assertion now, not a separate check:
		# "S2.4 refuses with nothing at all" is read off PROBE_DONE:0, not
		# off an empty string that a probe which never ran would also
		# produce. A prober that could not exec (permission denied), could
		# not open its result file, or whose result file this process
		# could not read back all yield '' here too - and all three must
		# fail this assertion, not pass it (proven below by deliberately
		# causing the first one and confirming this line reddens).
		is($out4b, "PROBE_DONE:0\n",
			'4b: S2.4 refuses a wrong-uid peer with NOTHING AT ALL - closed before a byte is read, unlike S2.2\'s real E_PEER response')
			or diag('got: ' . length($out4b) . ' bytes: ' . substr($out4b, 0, 200)
				. "; web-daemon.err: " . (_slurp("$dir2/web-daemon.err") // '(none)'));
	}

	kill 'TERM', $web_pid;
	my (undef, $web_wait_err) = _bounded(10, sub { waitpid($web_pid, 0); return 1 });
	diag("web listener did not exit on TERM within the bound: $web_wait_err") if defined $web_wait_err;
	_stop_daemon($pid2);
}

is($BLOCKED, 0, 'no wait in this file hit its bounding alarm - every connect()/read/reap returned on its own');

done_testing();
