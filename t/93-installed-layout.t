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
# Added 2026-09-25 in https://github.com/nkyo/csf - see CHANGES.md.
#
# THE GAP THIS FILE EXISTS TO CLOSE, STATED BEFORE THE FIRST TEST.
#
# Four defects reached the branch owner from ONE real install, and the suite
# saw none of them while reporting 5651 passing tests. The reason is
# structural, not an oversight in any one test:
#
#   * every other file here runs from the REPOSITORY, with `prove -I.`, so
#     @INC contains the repo root - which happens to hold JSON/Tiny.pm. The
#     installed layout has no such directory, and the four binaries' own
#     `use lib` is the only thing that decides what they can load there.
#   * nothing had ever run a line of this code as the `csfui` account, and
#     the first defect was an EACCES that only an unprivileged reader sees.
#   * nothing had ever executed the installer's own file-placement code, so
#     "the installer never copies JSON::Tiny" was invisible.
#   * nothing modelled a systemd unit that starts, dies, and is restarted -
#     so the installer's one-shot `is-active` sample looked correct.
#
# So every section below works in the INSTALLED shape rather than the repo
# shape: it replays install-webui.sh's own directory and copy code into a
# sandbox, compiles the binaries against only that sandbox plus core Perl,
# and (where a second real uid is available) does it as a different user.
#
# HOST HYGIENE. Nothing here writes outside a File::Temp tempdir this file
# owns. No real path under /usr/local/csf-ui, /etc/csf-ui, /var/lib/csf-ui,
# /var/run/csf-ui, /run/csf-ui-web or /usr/sbin is created, changed or
# removed; `systemctl` is a stub on a throwaway PATH in every section that
# uses one, so nothing here touches this host's services. install-webui.sh
# is never run as a whole - only named functions extracted from it, by
# anchor, and driven in the sandbox. `main "$@"` at the foot of the real
# file is never reached.
###############################################################################
use strict;
use warnings;

use FindBin ();
use lib "$FindBin::Bin/..", "$FindBin::Bin/../ui-src/lib";

use File::Temp qw(tempdir);
use File::Path qw(make_path);
use Test::More;

my $ROOT      = "$FindBin::Bin/..";
my $BIN_DIR   = "$ROOT/ui-src/bin";
my $UI_LIB    = "$ROOT/ui-src/lib/ConfigServer/UI";
my $INSTALLER = "$ROOT/ui-src/dist/install-webui.sh";
my @BINARIES  = qw(csf-ui csf-ui-helper csf-ui-passwd csf-ui-setup);

sub slurp { my ($p) = @_; open(my $fh, '<', $p) or die "open $p: $!"; local $/; return <$fh> }
sub spew  { my ($p, $t) = @_; open(my $fh, '>', $p) or die "write $p: $!"; print $fh $t; close $fh }

# Every child process in this file goes through here: the command is WRITTEN
# to a script in the caller's own sandbox and run with a list-form open, the
# way t/92-integration.t runs its sandboxed installer fragments. No qx, no
# backticks, no single-string system() anywhere in this file - the same G2
# rule ci/gates.sh enforces over ui-src/, kept here because a test that
# reached a shell through a string would be a poor place to argue that the
# shipped code must not. stderr is merged inside the script rather than by a
# shell redirection the caller has to spell. Returns (output, exit status).
sub run_sh {
	my ($dir, $name, $body) = @_;
	my $path = "$dir/$name";
	spew($path, "#!/bin/sh\nexec 2>&1\n$body");
	open(my $fh, '-|', 'sh', $path) or die "run $path: $!";
	local $/;
	my $out = <$fh>;
	close $fh;
	return (defined $out ? $out : '', $?);
}

# Every section that needs a second real uid asks the same way t/92 does,
# so the two files' skip reasons cannot drift apart.
sub second_uid {
	return 'nobody' if $< == 0 || $> == 0;
	return 'nobody' if system('sudo', '-n', '-u', 'nobody', 'true') == 0;
	return undef;
}

###############################################################################
# SECTION 1 - THE DEFECT ITSELF: no binary's @INC may name a path under
# /usr/local/csf.
#
# Ruling R11 moved every WebUI path to /usr/local/csf-ui, /etc/csf-ui and
# /var/lib/csf-ui precisely so the unprivileged tier would never depend on a
# directory csf keeps clamping shut - csf's installer creates
# /usr/local/csf/lib mode 0600 and runs `chmod -R 600` over it
# (install.generic.sh:82,:458), and lfd re-applies chmod(0600,
# "/usr/local/csf") on every pass of its main loop. The `use lib` line was
# left pointing back at it, `use lib` PREPENDS, and the csfui process died
# scanning @INC before it could load core Fcntl.
#
# This is the assertion that would have caught it, and it costs nothing.
###############################################################################
{
	for my $bin (@BINARIES) {
		my $src = slurp("$BIN_DIR/$bin");
		my @use_lib = ($src =~ /^(use \s+ lib \s+ [^\n]*)$/gmx);

		is(scalar(@use_lib), 1, "$bin has exactly one 'use lib' line")
			or diag(join("\n", @use_lib));
		is($use_lib[0], "use lib '/usr/local/csf-ui/lib';",
			"$bin: 'use lib' names csf-ui's own lib and nothing else");
		unlike($use_lib[0], qr{/usr/local/csf/},
			"$bin: 'use lib' does not name a path under /usr/local/csf (R11; the EACCES that crash-looped the first real install)");
	}

	# The same rule for the modules, where a second `use lib` would be just
	# as fatal and even easier to miss.
	for my $pm (sort glob("$UI_LIB/*.pm")) {
		my $src = slurp($pm);
		my ($name) = $pm =~ m{([^/]+)\z};
		unlike($src, qr{^ \s* use \s+ lib \b [^\n]* /usr/local/csf/ }mx,
			"ConfigServer/UI/$name: no 'use lib' naming a path under /usr/local/csf");
	}
}

###############################################################################
# SECTION 2 - THE ENUMERATION, FROZEN.
#
# What do the four binaries and the nine modules actually load, and which of
# those does csf's own lib supply? Answered by reading every use/require in
# all thirteen files rather than by memory, and frozen as a list so that a
# fourteenth dependency cannot arrive unnoticed - which is the only way the
# JSON::Tiny problem can come back in a different costume.
#
# csf's lib ships ConfigServer/*, Crypt/*, HTTP/Tiny.pm, JSON/Tiny.pm,
# Net/*, Geo/* and version.pm (install.generic.sh:382-389). Of everything
# below, JSON::Tiny is the ONLY name that intersects that set.
###############################################################################
{
	my %CORE = map { $_ => 1 } qw(
		Digest::SHA Encode Errno Fcntl IO::Handle MIME::Base64 POSIX Socket Time::HiRes
	);
	my %PRAGMA  = map { $_ => 1 } qw(strict warnings lib);
	# Not core, not in csf's lib either: a runtime `require` in Server.pm,
	# needed only by mode B, supplied by the distribution's own package.
	# install-webui.sh's mode_b_tls_problem() is what checks for it.
	my %RUNTIME = map { $_ => 1 } qw(IO::Socket::SSL);
	# The one module csf vendors that this tree genuinely needs, and
	# therefore the one install-webui.sh must ship into csf-ui's own lib.
	my %VENDORED = map { $_ => 1 } qw(JSON::Tiny);

	my %seen;
	for my $file (map({ "$BIN_DIR/$_" } @BINARIES), sort glob("$UI_LIB/*.pm")) {
		my $src = slurp($file);
		for my $line (split /\n/, $src) {
			next if $line =~ /^\s*#/;
			# A CAPITAL first letter is required, and that is not cosmetic:
			# without it the sentence "root does not use this socket" inside
			# a string literal in csf-ui-helper parses as `use this`. Every
			# real module here is capitalised; the three lowercase names
			# (strict, warnings, lib) are pragmas and excluded below anyway.
			next unless $line =~ /(?:^|\s|\{)(?:use|require)\s+([A-Z][A-Za-z0-9_]*(?:::[A-Za-z0-9_]+)*)/;
			my $mod = $1;
			next if $PRAGMA{$mod};
			next if $mod =~ /^ConfigServer::UI::/;   # csf-ui's own lib
			$seen{$mod}++;
		}
	}

	my @unexplained = sort grep {
		!$CORE{$_} && !$RUNTIME{$_} && !$VENDORED{$_}
	} keys %seen;
	is_deeply(\@unexplained, [],
		'every module the four binaries and the nine UI modules load is core Perl, ConfigServer::UI, the vendored JSON::Tiny, or the runtime-optional IO::Socket::SSL')
		or diag('unexplained: ' . join(', ', @unexplained));

	ok($seen{'JSON::Tiny'},
		'JSON::Tiny really is loaded (so shipping it is not dead weight) - it is the only module this tree took from csf lib');
	ok(!grep({ /^ConfigServer::(?!UI::)/ } keys %seen),
		'nothing loads a ConfigServer:: module from csf own lib - only ConfigServer::UI::*');
}

###############################################################################
# SECTION 3 - THE INSTALLED LAYOUT, BUILT BY THE INSTALLER'S OWN CODE, AND
# COMPILED AGAINST NOTHING ELSE.
#
# The directory list comes out of setup_directories() and the copies out of
# install_files(), both extracted from the real install-webui.sh by anchor
# and replayed with /usr/local/csf-ui redirected into a sandbox. Nothing is
# retyped: if install_files() stops copying JSON/Tiny.pm, or
# setup_directories() stops creating the directory it goes in, this section
# reddens at `perl -c`, exactly as the real install did at BEGIN.
#
# @INC for the compile is the sandbox lib plus core, and nothing else -
# PERL5LIB is cleared and the repo root is NOT on the path. That is the
# whole point: `prove -I.` is what hid this defect for the life of the
# branch.
###############################################################################
my $SANDBOX_LIB;
{
	my $sandbox = tempdir(CLEANUP => 1);
	chmod 0755, $sandbox;
	my $prefix = "$sandbox/usr/local/csf-ui";
	my $installer = slurp($INSTALLER);

	my ($dirs_body) = $installer =~ /^setup_directories\(\) \{\n(.*?)^\}$/ms;
	my ($copy_body) = $installer =~ /^install_files\(\) \{\n(.*?)^\}$/ms;
	ok(defined($dirs_body) && defined($copy_body),
		'setup_directories() and install_files() were both located in the real install-webui.sh');

	SKIP: {
		skip 'could not extract the installer functions - see the failure above', 7
			unless defined($dirs_body) && defined($copy_body);

		# The directories, as the installer creates them, minus the
		# ownership flags a non-root test cannot apply. Verified: the
		# extraction must find the whole S2.3 set, not one line of it.
		my @dir_lines = grep { m{^\s*install -d .*\Q/usr/local/csf-ui\E} } split(/\n/, $dirs_body);
		cmp_ok(scalar(@dir_lines), '>=', 7,
			'setup_directories() creates the expected number of /usr/local/csf-ui directories (extraction really matched)');
		my @mkdirs;
		for my $line (@dir_lines) {
			my ($path) = $line =~ m{(/usr/local/csf-ui\S*)};
			next unless defined $path;
			push @mkdirs, "$sandbox$path";
		}
		make_path(@mkdirs);
		ok(-d "$prefix/lib/JSON",
			'setup_directories() creates /usr/local/csf-ui/lib/JSON - the home the vendored JSON::Tiny needs');

		# The copies. Two verified substitutions and nothing else: the
		# install prefix, and chown (which needs root and is not what this
		# section is about). A sed that silently matched nothing is the
		# exact hazard this project has been bitten by before, so both are
		# counted rather than assumed.
		my $want_prefix_hits = () = $copy_body =~ m{/usr/local/csf-ui}g;
		my $want_chown_hits  = () = $copy_body =~ m{^(\s*)chown }mg;
		cmp_ok($want_prefix_hits, '>=', 5, 'install_files() names /usr/local/csf-ui enough times for the redirect to be real');
		cmp_ok($want_chown_hits,  '>=', 1, 'install_files() calls chown, which this sandbox neutralises');

		my $body = $copy_body;
		$body =~ s{/usr/local/csf-ui}{$prefix}g;
		$body =~ s{^(\s*)chown }{$1: chown }mg;
		my $got_prefix_hits = () = $body =~ m{\Q$prefix\E}g;
		is($got_prefix_hits, $want_prefix_hits,
			'every /usr/local/csf-ui in install_files() was redirected into the sandbox (the substitution was verified, not assumed)');

		my (undef, $rc) = run_sh($sandbox, 'install-files.sh',
			"UI_SRC=\"$ROOT/ui-src\"\n"
			. "SRC_ROOT=\"$ROOT\"\n"
			. "install_files() {\n$body\n}\n"
			. "install_files\n");
		is($rc, 0, 'the real install_files(), replayed into a sandbox, ran to completion');

		my $installed_json = "$prefix/lib/JSON/Tiny.pm";
		ok(-f $installed_json,
			'install_files() puts JSON::Tiny into /usr/local/csf-ui/lib/JSON/Tiny.pm - the fix for the crash loop');
		# Read through a guard, not straight into slurp(). A die here would
		# ABORT this file, and an aborted test file is not a red test - it
		# is the rest of the section never running while what already
		# printed still says "ok". Measured: removing the copy from
		# install_files() did exactly that before this guard existed.
		my $copied = -f $installed_json ? slurp($installed_json) : '';
		like($copied, qr/Artistic 2\.0 license/,
			'the copied JSON::Tiny still carries its own licence header (copied verbatim, never edited)');
		is($copied, slurp("$ROOT/JSON/Tiny.pm"),
			'the copied JSON::Tiny is byte-identical to the vendored original');

		# Now compile, from the installed paths, against the installed lib
		# and core Perl only.
		$SANDBOX_LIB = "$prefix/lib";
		for my $bin (@BINARIES) {
			my $path = "$prefix/bin/$bin";
			ok(-f $path, "install_files() installed $bin");
			next unless -f $path;

			# The one thing a sandbox cannot supply is an absolute path.
			# Rewrite it, and verify the rewrite changed exactly the line
			# section 1 froze.
			my $src = slurp($path);
			my $n = ($src =~ s{^use lib '/usr/local/csf-ui/lib';$}{use lib '$SANDBOX_LIB';}m);
			is($n, 1, "$bin: the sandbox rewrote exactly one 'use lib' line");
			chmod 0755, $path;
			spew($path, $src);

			my ($out, $rc) = run_sh($sandbox, "compile-$bin.sh",
				"PERL5LIB= perl -c -- '$path'\n");
			is($rc, 0, "$bin compiles from the installed layout with only csf-ui lib and core Perl in \@INC")
				or diag($out);
		}
	}

	# A SECOND REAL UID. The first defect was an EACCES only an
	# unprivileged reader ever saw; root would have sailed through it.
	SKIP: {
		my $user = second_uid();
		skip 'not root, and sudo -n -u nobody failed - cannot compile as a second real uid', 2
			unless defined $user;
		skip 'the sandbox install did not complete', 2 unless defined $SANDBOX_LIB;

		system('chmod', '-R', 'a+rX', $sandbox);
		my $path = "$prefix/bin/csf-ui";
		my $as = $< == 0 || $> == 0
			? qq{su -s /bin/sh -c "PERL5LIB= perl -c -- '$path'" $user\n}
			: qq{sudo -n -u $user env PERL5LIB= perl -c -- '$path'\n};
		my ($out, $rc) = run_sh($sandbox, 'compile-as-user.sh', $as);
		is($rc, 0, "csf-ui compiles as the unprivileged '$user' account, from the installed layout")
			or diag($out);

		# AND THE REPRODUCTION. Put JSON::Tiny back where csf keeps it, in
		# a directory with csf's own 0600 mode, and restore the old second
		# @INC entry. This is the owner's failure, byte for byte, produced
		# on demand - which is what makes section 1's assertion a guard
		# rather than a style rule.
		make_path("$sandbox/fake-csf/lib/JSON");
		spew("$sandbox/fake-csf/lib/JSON/Tiny.pm", slurp("$ROOT/JSON/Tiny.pm"));
		chmod 0600, "$sandbox/fake-csf/lib";
		my $old = slurp($path);
		$old =~ s{^use lib '\Q$SANDBOX_LIB\E';$}{use lib '$SANDBOX_LIB', '$sandbox/fake-csf/lib';}m;
		spew("$sandbox/oldline", $old);
		chmod 0755, "$sandbox/oldline";
		my $as_old = $< == 0 || $> == 0
			? qq{su -s /bin/sh -c "PERL5LIB= perl -c -- '$sandbox/oldline'" $user\n}
			: qq{sudo -n -u $user env PERL5LIB= perl -c -- '$sandbox/oldline'\n};
		my ($bad) = run_sh($sandbox, 'compile-oldline.sh', $as_old);
		like($bad, qr/Permission denied/,
			"restoring the old second \@INC entry, with csf's own 0600 directory mode, reproduces the owner's exact failure as '$user'")
			or diag($bad);
		chmod 0700, "$sandbox/fake-csf/lib";
	}
}

###############################################################################
# SECTION 4 - MODE B'S OWN PRECONDITION, ASKED BEFORE MODE B IS OFFERED.
#
# The fourth defect: the installer verified the TLS CERTIFICATE and never
# the module that reads it, so a host without IO::Socket::SSL was offered
# mode B, given a ui.conf, and left with a unit restarting every five
# seconds - 81 times and climbing when the owner looked.
#
# mode_b_tls_problem() does not restate Server.pm's message. It shells out
# to Server.pm's own preflight() and prints the problems mentioning
# IO::Socket::SSL, so the package names cannot drift from the ones the
# service itself prints. These tests assert that property directly, on
# whichever side of the fence this host happens to sit.
###############################################################################
{
	my $installer = slurp($INSTALLER);
	my ($fn) = $installer =~ /^(mode_b_tls_problem\(\) \{\n.*?^\})$/ms;
	ok(defined($fn), 'mode_b_tls_problem() was located in the real install-webui.sh');

	unlike($installer, qr/libio-socket-ssl-perl/,
		'install-webui.sh does NOT carry its own copy of the distro package names - it reuses Server.pm message');
	like($installer, qr/mode_b_tls_problem/,
		'install-webui.sh calls the precondition rather than merely defining it');
	my $gate_b = 'if [ "$mode" = "b" ] && [ "$mode_b_ok" -eq 0 ]; then';
	like($installer, qr/\Q$gate_b\E/,
		'interactive_setup() actually GATES on the mode-B precondition, not just consults it');

	SKIP: {
		skip 'mode_b_tls_problem() could not be extracted', 3 unless defined $fn;
		skip 'the sandbox install did not complete', 3 unless defined $SANDBOX_LIB;

		my $tmp = tempdir(CLEANUP => 1);
		spew("$tmp/fn.sh", "$fn\n");
		my ($out) = run_sh($tmp, 'run.sh',
			qq{. "$tmp/fn.sh"\nmode_b_tls_problem "$SANDBOX_LIB"\necho "RC=\$?"\n});

		my $have_ssl = eval { require IO::Socket::SSL; 1 } ? 1 : 0;
		if ($have_ssl) {
			like($out, qr/^RC=0$/m,
				'IO::Socket::SSL is installed on this host, and mode_b_tls_problem() says mode B can start');
			unlike($out, qr/IO::Socket::SSL is not installed/,
				'...and reports no problem');
			pass('(the missing-module branch is covered on a host without IO::Socket::SSL)');
		}
		else {
			like($out, qr/^RC=1$/m,
				'IO::Socket::SSL is absent on this host, and mode_b_tls_problem() refuses mode B');
			like($out, qr/\QIO::Socket::SSL is not installed; install it (Debian\/Ubuntu: libio-socket-ssl-perl; RHEL\/CloudLinux\/cPanel: perl-IO-Socket-SSL) so the standalone web UI can serve TLS - it never serves plain HTTP instead\E/,
				'...with Server.pm own message, byte for byte - one source for the package names, so they cannot drift')
				or diag($out);
			# The same words, read out of Server.pm itself: if that message
			# is ever reworded, this pins that the installer follows it
			# rather than keeping a stale copy.
			my $server_src = slurp("$UI_LIB/Server.pm");
			my ($msg) = $server_src =~ /'(IO::Socket::SSL is not installed; install it )'/;
			ok(defined($msg) && index($out, 'IO::Socket::SSL is not installed; install it ') >= 0,
				'the text the installer printed begins with the literal Server.pm carries');
		}
	}

	# MODE A MUST NOT BE HELD TO THIS. Read out of Server.pm rather than
	# assumed: an earlier fix round specifically corrected a bug where a
	# mode-A host was told to install IO::Socket::SSL.
	require ConfigServer::UI::Server;
	my $tmp = tempdir(CLEANUP => 1);
	spew("$tmp/ui.conf", qq{UI_MODE="a"\nUI_ALLOW="10.0.0.1"\n});
	my @problem = ConfigServer::UI::Server::preflight(
		ui_conf_path => "$tmp/ui.conf",
		socket_path  => "$tmp/absent/csf-ui.sock",
	);
	is(scalar(grep { /IO::Socket::SSL/ } @problem), 0,
		'Server.pm preflight() demands no IO::Socket::SSL in mode A - so the installer does not check for it there either')
		or diag(join("\n", @problem));
}

###############################################################################
# SECTION 5 - "RUNNING" versus "DYING AND BEING RESTARTED".
#
# The second defect. _enable_now() took ONE instantaneous `systemctl
# is-active` sample; a unit with Restart=on-failure and RestartSec=5 that
# fails at startup spends most of every five seconds looking `active`, so
# the sample caught it mid-cycle and the installer printed
# "active=active" and then "WebUI install verified OK" over a service whose
# restart counter was past 50.
#
# This host has no systemd (measured: /proc/1/comm is not systemd), so the
# stub below stands in for it - and it is built to reproduce exactly the
# ambiguity that fooled the old code, not a convenient failure: `is-active`
# answers `active` every single time, `is-failed` says the unit is fine,
# and the ONLY evidence of trouble is the restart counter moving. A check
# that still believes `is-active` here cannot pass.
###############################################################################
{
	my $installer = slurp($INSTALLER);
	my ($prop_fn) = $installer =~ /^(_unit_prop\(\) \{\n.*?^\})$/ms;
	my ($enable_fn) = $installer =~ /^(_enable_now\(\) \{\n.*?^\})$/ms;
	ok(defined($prop_fn) && defined($enable_fn),
		'_unit_prop() and _enable_now() were both located in the real install-webui.sh');

	# The shipped watch window has to outlast the shipped RestartSec, or the
	# whole thing samples inside one healthy-looking phase again. Both
	# numbers are read from the files that carry them.
	my ($settle) = $installer =~ /^_SETTLE_SECONDS=(\d+)$/m;
	my ($step)   = $installer =~ /^_SETTLE_STEP=(\d+)$/m;
	ok(defined($settle) && defined($step), '_enable_now() has an explicit watch window');
	for my $unit (qw(csf-ui.service csf-ui-helper.service)) {
		my ($rsec) = slurp("$ROOT/ui-src/dist/$unit") =~ /^RestartSec=(\d+)$/m;
		ok(defined($rsec), "$unit declares RestartSec");
		cmp_ok($settle, '>', $rsec,
			"the watch window (${settle}s) is longer than $unit RestartSec (${rsec}s) - a shorter one can sit inside a single restart cycle and see nothing");
	}

	SKIP: {
		skip 'the _enable_now extraction failed - see above', 6
			unless defined($prop_fn) && defined($enable_fn);

		my $sandbox = tempdir(CLEANUP => 1);
		mkdir "$sandbox/bin";

		# THE CRASH-LOOP STUB. Faithful to what the owner measured:
		#   is-active  -> "active", every time, never anything else
		#   is-failed  -> exit 1 (systemd is still restarting it)
		#   NRestarts  -> climbs, one per query after the first
		#   ExecMainStartTimestampMonotonic -> changes with it
		spew("$sandbox/bin/systemctl", <<"STUB");
#!/bin/sh
case "\$1" in
  enable) exit 0 ;;
  is-enabled) echo enabled; exit 0 ;;
  is-active) echo active; exit 0 ;;
  is-failed) exit 1 ;;
  show)
    n=0
    [ -f "$sandbox/n" ] && n=\$(cat "$sandbox/n")
    n=\$((n + 1))
    echo "\$n" > "$sandbox/n"
    case "\$3" in
      NRestarts) echo "NRestarts=\$((n - 1))" ;;
      ExecMainStartTimestampMonotonic) echo "ExecMainStartTimestampMonotonic=\$((1000 + n))" ;;
      Result) echo "Result=exit-code" ;;
      *) : ;;
    esac
    exit 0 ;;
esac
exit 0
STUB
		chmod 0755, "$sandbox/bin/systemctl";

		# The control: a unit that really is up. Same stub shape, frozen
		# counters. Without this row the section would pass just as well
		# with an _enable_now() that condemns everything.
		mkdir "$sandbox/good";
		spew("$sandbox/good/systemctl", <<'STUB2');
#!/bin/sh
case "$1" in
  enable) exit 0 ;;
  is-enabled) echo enabled; exit 0 ;;
  is-active) echo active; exit 0 ;;
  is-failed) exit 1 ;;
  show)
    case "$3" in
      NRestarts) echo "NRestarts=0" ;;
      ExecMainStartTimestampMonotonic) echo "ExecMainStartTimestampMonotonic=4242" ;;
      Result) echo "Result=success" ;;
      *) : ;;
    esac
    exit 0 ;;
esac
exit 0
STUB2
		chmod 0755, "$sandbox/good/systemctl";

		my $harness = sub {
			my ($binpath) = @_;
			my $script = "PATH=\"$binpath:\$PATH\"\n"
				. "$prop_fn\n$enable_fn\n"
				# Shortened for the test only; the shipped values are
				# asserted above against the units' own RestartSec.
				. "_SETTLE_SECONDS=2\n_SETTLE_STEP=1\n"
				. "_enable_now csf-ui.service\n"
				. "echo \"RC=\$?\"\n";
			my ($out) = run_sh($sandbox, 'run.sh', $script);
			return $out;
		};

		my $bad_out = $harness->("$sandbox/bin");
		like($bad_out, qr/^RC=1$/m,
			'_enable_now() FAILS on a unit that is crash-looping, although is-active says "active" every time it is asked');
		like($bad_out, qr/is NOT running/,
			'...and says so in words an operator can act on');
		like($bad_out, qr/restart count went/,
			'...naming the evidence (the restart counter), not just asserting a verdict');

		my $good_out = $harness->("$sandbox/good");
		like($good_out, qr/^RC=0$/m,
			'_enable_now() PASSES a unit that is genuinely up - the check condemns crash loops, not everything');
		unlike($good_out, qr/is NOT running/,
			'...and says nothing alarming about it');

		# THE OLD CODE, AGAINST THE SAME STUB. This is the break-it row:
		# the one-shot sample that shipped is run against exactly the
		# scenario above and shown to report success, so the new check is
		# demonstrably doing something the old one could not.
		my $old = <<'OLD';
_enable_now_old() {
	unit=$1
	systemctl enable --now "$unit" >/dev/null 2>&1
	enabled=$(systemctl is-enabled "$unit" 2>/dev/null)
	active=$(systemctl is-active "$unit" 2>/dev/null)
	echo "csf-ui: $unit: enabled=$enabled active=$active"
	[ "$active" = "active" ]
}
OLD
		my ($old_out) = run_sh($sandbox, 'old.sh',
			"PATH=\"$sandbox/bin:\$PATH\"\n$old\n_enable_now_old csf-ui.service\necho \"RC=\$?\"\n");
		like($old_out, qr/^RC=0$/m,
			'the ONE-SHOT sample that shipped reports success against this very stub - which is why a second signal was needed, not a reworded message');
	}
}

###############################################################################
# SECTION 6 - verify_install() must not bless a crash-looping unit.
#
# The decisive number is NRestarts: systemd zeroes it when a unit is
# started, and the install started these units minutes earlier, so any
# nonzero value means it has already died. The owner's run had 52 and was
# told "WebUI install verified OK".
###############################################################################
{
	my $installer = slurp($INSTALLER);
	my ($block) = $installer =~ /^(\tif command -v systemctl >\/dev\/null 2>&1; then\n\t\tfor unit in csf-ui-helper\.service csf-ui\.service; do\n.*?^\tfi)$/ms;
	ok(defined($block), 'verify_install() unit-health block was located in the real install-webui.sh');

	my ($prop_fn) = $installer =~ /^(_unit_prop\(\) \{\n.*?^\})$/ms;

	SKIP: {
		skip 'the verify_install() unit-health extraction failed', 3
			unless defined($block) && defined($prop_fn);

		my $sandbox = tempdir(CLEANUP => 1);
		mkdir "$sandbox/bin";
		spew("$sandbox/bin/systemctl", <<'STUB');
#!/bin/sh
case "$1" in
  is-enabled) echo enabled; exit 0 ;;
  is-active) echo active; exit 0 ;;
  show)
    case "$3" in
      NRestarts) echo "NRestarts=52" ;;
      *) : ;;
    esac
    exit 0 ;;
esac
exit 0
STUB
		chmod 0755, "$sandbox/bin/systemctl";

		my $wrap = "PATH=\"$sandbox/bin:\$PATH\"\nproblems=0\n"
			. "$prop_fn\n"
			. "health() {\n$block\n}\nhealth\necho \"PROBLEMS=\$problems\"\n";
		my ($out) = run_sh($sandbox, 'run.sh', $wrap);

		like($out, qr/PROBLEMS=2/,
			'verify_install() counts BOTH enabled-but-crash-looping units as problems, so it cannot print "verified OK"');
		like($out, qr/reports active, but systemd has already restarted/,
			'...and names exactly what is wrong rather than only failing');
		like($out, qr/52 time\(s\)/,
			'...quoting the restart count the owner had to find in journalctl');
	}

	# The success sentence must still be reachable only when problems is 0 -
	# a presence-only check would pass on code that printed it regardless.
	my $ok_guard = 'if [ "$problems" -gt 0 ]; then';
	my $ok_line  = 'echo "csf-ui: WebUI install verified OK."';
	like($installer, qr/\Q$ok_guard\E[\s\S]{0,400}?\Q$ok_line\E/,
		'"WebUI install verified OK." is still printed only on the zero-problems branch');
}

###############################################################################
# SECTION 7 - the first command an operator must run has to be on PATH.
#
# There is no account by default and no way into the WebUI until one exists,
# so `csf-ui-passwd add ...` is mandatory and is the first thing anyone
# types. On the owner's install it answered "command not found".
###############################################################################
{
	my $installer = slurp($INSTALLER);

	like($installer, qr/^install_path_symlinks\(\) \{/m,
		'install-webui.sh has an install_path_symlinks() function');
	my $link_line = 'ln -sfn "/usr/local/csf-ui/bin/$cmd" "/usr/sbin/$cmd"';
	like($installer, qr/\Q$link_line\E/,
		'...which links the operator commands into /usr/sbin, where csf itself already lives');
	like($installer, qr{\Q	install_path_symlinks\E\n},
		'...and main() actually calls it');
	like($installer, qr/for cmd in csf-ui-passwd csf-ui-setup; do/,
		'exactly the two operator commands are linked (csf-ui and csf-ui-helper are ExecStart targets, not commands)');
	my $verify_link = '/usr/sbin/$cmd is not a symlink';
	like($installer, qr/\Q$verify_link\E/,
		'verify_install() checks the symlinks exist');

	for my $script (qw(uninstall.sh uninstall.cwp.sh uninstall.cyberpanel.sh
		uninstall.directadmin.sh uninstall.generic.sh uninstall.interworx.sh
		uninstall.vesta.sh)) {
		my $src = slurp("$ROOT/$script");
		like($src, qr{^rm -fv /usr/sbin/csf-ui-passwd$}m,
			"$script removes /usr/sbin/csf-ui-passwd");
		like($src, qr{^rm -fv /usr/sbin/csf-ui-setup$}m,
			"$script removes /usr/sbin/csf-ui-setup");

		# The properties the existing csf-ui removal block already has, and
		# which these two lines must match: every path absolute and
		# literal, no shell variable in any rm, and no pkill anywhere.
		my @rm = ($src =~ /^(rm\s+[^\n]*)$/mg);
		my @bad = grep { /\$/ } @rm;
		is_deeply(\@bad, [], "$script: no rm line interpolates a shell variable")
			or diag(join("\n", @bad));
		unlike($src, qr/\bpkill\b/, "$script: no pkill");
		my @relative = grep { !m{^rm\s+(-\S+\s+)*/} } @rm;
		is_deeply(\@relative, [], "$script: every rm names an absolute path")
			or diag(join("\n", @relative));
	}
}

###############################################################################
# SECTION 8 - the installer proves the installed tree loads, as the account
# that will run it, before it offers to configure anything.
###############################################################################
{
	my $installer = slurp($INSTALLER);
	like($installer, qr/^check_installed_perl_deps\(\) \{/m,
		'install-webui.sh has a check_installed_perl_deps() function');
	like($installer, qr/su -s \/bin\/sh -c "PERL5LIB= perl -c -- '\$bin_dir\/\$bin'" "\$as_user"/,
		'...which compiles each installed binary AS the unprivileged account, with PERL5LIB cleared');
	like($installer, qr{\Q	check_installed_perl_deps\E\n\tdeps_rc=\$\?},
		'...and main() keeps its verdict');
	my $gate_deps = 'if [ "$deps_rc" -eq 1 ]; then';
	like($installer, qr/\Q$gate_deps\E/,
		'...and actually GATES on it: a tree that does not load is never offered a mode');
	like($installer, qr/require 5\.014; require Socket; Socket->VERSION\(1\.94\)/,
		'...and checks docs/WEBUI-RPC.md S11.7 Perl floor at install time, which S11.7 has always claimed happened');

	SKIP: {
		my ($fn) = $installer =~ /^(check_installed_perl_deps\(\) \{\n.*?^\})$/ms;
		skip 'check_installed_perl_deps() could not be extracted', 2 unless defined $fn;
		my $user = second_uid();
		skip 'not root, and sudo -n -u nobody failed - cannot run the check as a second real uid', 2
			unless defined $user;
		skip 'the sandbox install did not complete', 2 unless defined $SANDBOX_LIB;

		my $tmp = tempdir(CLEANUP => 1);
		chmod 0755, $tmp;
		spew("$tmp/fn.sh", "$fn\n");
		my $bin = $SANDBOX_LIB;
		$bin =~ s{/lib$}{/bin};

		# The function switches user with su, so it has to run as root.
		# Already root: run it directly. Otherwise go through the same
		# passwordless sudo second_uid() just proved is available.
		my $sudo = ($< == 0 || $> == 0) ? '' : 'sudo -n ';
		my $cmd = qq{${sudo}sh -c '. "$tmp/fn.sh"; check_installed_perl_deps "$bin" $user; echo "RC=\$?"'\n};
		my ($out) = run_sh($tmp, 'deps-ok.sh', $cmd);
		like($out, qr/^RC=0$/m,
			"check_installed_perl_deps() passes the real installed sandbox as '$user'")
			or diag($out);

		# Break it exactly the way the real install was broken: take
		# JSON::Tiny away.
		rename("$SANDBOX_LIB/JSON/Tiny.pm", "$SANDBOX_LIB/Tiny.hidden");
		my ($broken) = run_sh($tmp, 'deps-broken.sh', $cmd);
		rename("$SANDBOX_LIB/Tiny.hidden", "$SANDBOX_LIB/JSON/Tiny.pm");
		like($broken, qr/RC=1/,
			'...and FAILS, with perl own message, the moment JSON::Tiny is not where install_files() puts it')
			or diag($broken);
	}
}

###############################################################################
# SECTION 9 - defect 5: Mode B bound loopback because UI_LISTEN was never
# written, and nothing said so.
#
# Server.pm:514 - `my $listen_text = defined $raw{UI_LISTEN} ? $raw{UI_LISTEN}
# : '127.0.0.1';` - so an absent key IS loopback. write_ui_conf() wrote
# UI_MODE, UI_PORT and UI_ALLOW and stopped, which meant the menu offered
# "standalone (csf-ui serves TLS itself)", the operator named an address
# that may connect and a port, and the result served the one address on
# which none of that is reachable.
#
# The file is driven for real here, with /etc/csf-ui redirected into a
# sandbox and chown neutralised, and the result is handed to the actual
# Server.pm read_ui_conf() rather than pattern-matched - because the
# question is not "does it contain a line", it is "does the library that
# reads this file agree with what the installer wrote".
###############################################################################
{
	my $installer = slurp($INSTALLER);
	my ($fn) = $installer =~ /^(write_ui_conf\(\) \{\n.*?^\})$/ms;
	ok(defined($fn), 'write_ui_conf() was located in the real install-webui.sh');

	# The mode-A call must pass an empty listen, and the mode-B call must
	# pass a real one - checked as the actual call sites, because a
	# write_ui_conf() that can write UI_LISTEN and two callers that never
	# give it one is the same defect with more code.
	like($installer, qr/^\twrite_ui_conf a "\$port" "\$allow" ""$/m,
		'setup_mode_a() passes an EMPTY listen - a mode-A ui.conf must not carry UI_LISTEN at all');
	like($installer, qr/^\twrite_ui_conf b "\$port" "\$allow" "\$listen"$/m,
		'setup_mode_b() passes a listen address through to write_ui_conf()');
	like($installer, qr/^\t\tlisten=\$\(ask_listen_address "\$allow" "\$port"\)$/m,
		'interactive_setup() ASKS for the listen address before configuring Mode B');

	SKIP: {
		skip 'write_ui_conf() could not be extracted', 10 unless defined $fn;

		my $sandbox = tempdir(CLEANUP => 1);
		make_path("$sandbox/etc/csf-ui");
		my $body = $fn;
		my $want_hits = () = $body =~ m{/etc/csf-ui}g;
		cmp_ok($want_hits, '>=', 3, 'write_ui_conf() names /etc/csf-ui enough times for the redirect to be real');
		$body =~ s{/etc/csf-ui}{$sandbox/etc/csf-ui}g;
		$body =~ s{^(\s*)chown }{$1: chown }mg;
		my $got_hits = () = $body =~ m{\Q$sandbox/etc/csf-ui\E}g;
		is($got_hits, $want_hits, 'every /etc/csf-ui in write_ui_conf() was redirected (substitution verified)');

		my $conf = "$sandbox/etc/csf-ui/ui.conf";
		my $read_conf = sub {
			require ConfigServer::UI::Server;
			my ($c, $problems) = ConfigServer::UI::Server::read_ui_conf($conf);
			return ($c, $problems);
		};

		# MODE B, all interfaces.
		run_sh($sandbox, 'wb.sh', "$body\nwrite_ui_conf b 8443 '198.51.100.4' '0.0.0.0'\n");
		my $text = -f $conf ? slurp($conf) : '';
		like($text, qr/^UI_LISTEN="0\.0\.0\.0"$/m,
			'mode B: write_ui_conf() writes UI_LISTEN - the key whose absence bound loopback');
		my ($c, $problems) = $read_conf->();
		is_deeply($problems, [], 'mode B: the real Server.pm read_ui_conf() accepts the file the installer wrote')
			or diag(join("\n", @$problems));
		is($c ? $c->{UI_LISTEN} : undef, '0.0.0.0',
			'mode B: and reads back the all-interfaces address, not the 127.0.0.1 default');

		# MODE B, loopback on purpose - still WRITTEN, never left implicit.
		run_sh($sandbox, 'wb2.sh', "$body\nwrite_ui_conf b 8443 '198.51.100.4' '127.0.0.1'\n");
		like(slurp($conf), qr/^UI_LISTEN="127\.0\.0\.1"$/m,
			'mode B, loopback: the key is written anyway, so the file states its own listen address either way');

		# MODE A: the key must be ABSENT, not empty. Server.pm refuses a
		# mode-A file that mentions it at all (S10: "the config contradicts
		# itself"), and read_ui_conf() reads presence from %raw before any
		# default precisely so the two cases stay distinguishable.
		run_sh($sandbox, 'wa.sh', "$body\nwrite_ui_conf a 8443 '198.51.100.4' ''\n");
		unlike(slurp($conf), qr/UI_LISTEN/,
			'mode A: UI_LISTEN is not written at all - not even empty');
		my (undef, $a_problems) = $read_conf->();
		is_deeply($a_problems, [], 'mode A: Server.pm accepts the mode-A file unchanged')
			or diag(join("\n", @$a_problems));

		# And the proof that the mode-A rule is real rather than cargo:
		# add the key and watch the same library refuse it.
		spew($conf, qq{UI_MODE="a"\nUI_LISTEN="0.0.0.0"\nUI_PORT="8443"\nUI_ALLOW="198.51.100.4"\n});
		my (undef, $bad) = $read_conf->();
		ok(scalar(grep { /UI_LISTEN must not be set when UI_MODE is "a"/ } @$bad),
			'...and Server.pm really does refuse a mode-A ui.conf that carries UI_LISTEN, which is why setup_mode_a() passes ""');
	}
}

###############################################################################
# SECTION 10 - the listen-address prompt itself.
###############################################################################
{
	my $installer = slurp($INSTALLER);
	my ($ask) = $installer =~ /^(ask_listen_address\(\) \{\n.*?^\})$/ms;
	my ($val) = $installer =~ /^(validate_ui_listen\(\) \{\n.*?^\})$/ms;
	ok(defined($ask) && defined($val),
		'ask_listen_address() and validate_ui_listen() were located in the real install-webui.sh');

	SKIP: {
		skip 'the prompt functions could not be extracted', 11 unless defined($ask) && defined($val);
		my $sandbox = tempdir(CLEANUP => 1);
		spew("$sandbox/fn.sh", "$val\n$ask\n");

		# THE ANSWER GOES TO STDOUT AND THE PROMPT DOES NOT. The caller
		# reads this function with $(...), so a prompt line on stdout is
		# captured into the value instead of shown to the operator - a
		# silent-failure shape worth one assertion of its own.
		for my $case (
			[ '',            '0.0.0.0',     'pressing enter takes the default' ],
			[ 'a',           '0.0.0.0',     'a = all IPv4 interfaces' ],
			[ 'l',           '127.0.0.1',   'l = loopback only' ],
			[ 'L',           '127.0.0.1',   'the answer is case-insensitive' ],
			[ '203.0.113.7', '203.0.113.7', 'a literal address is taken as given' ],
			[ '::',          '::',          ':: is accepted for all IPv6 interfaces' ],
			[ 'example.com', '0.0.0.0',     'a hostname is refused (Socket::inet_pton is the judge) and the default stands' ],
		) {
			my ($answer, $want, $label) = @$case;
			spew("$sandbox/answer", "$answer\n");
			my ($out) = run_sh($sandbox, 'ask.sh',
				". \"$sandbox/fn.sh\"\nexec < \"$sandbox/answer\"\nresult=\$(ask_listen_address 198.51.100.4 8443 2>/dev/null)\nprintf 'RESULT=%s\\n' \"\$result\"\n");
			like($out, qr/^RESULT=\Q$want\E$/m, "ask_listen_address: $label")
				or diag($out);
		}

		# The consequence of each choice has to be at the prompt, not only
		# in the commit message.
		like($ask, qr/reachable over the network/,
			'the all-interfaces option says it is reachable over the network');
		like($ask, qr/reachable ONLY from this machine/,
			'the loopback option says it is reachable only from this machine');
		like($ask, qr/UI_ALLOW \(\$allow_for_prompt\) gates who may connect/,
			'the prompt names the allowlist rather than letting it be assumed to be the whole answer');
	}

	# And the operator must be told which one they got before the installer
	# exits - for BOTH answers, not only the surprising one.
	like($installer, qr/LOOPBACK ONLY\. Nothing off this machine can reach/,
		'setup_mode_b() states plainly when the listener is loopback-only');
	like($installer, qr/ssh -N -L \$port:\$listen:\$port root@/,
		'...and gives the SSH tunnel command that makes that choice usable');
	like($installer, qr/listening on ALL interfaces\. Only UI_ALLOW/,
		'setup_mode_b() states plainly when the listener is on every interface');
}

###############################################################################
# SECTION 11 - defect 6: nothing opened the port in csf's own firewall.
#
# Driven against the SHIPPED configuration files rather than a fixture,
# because the measurement is the point: only one of the seven has the
# default 8443 in its port list.
###############################################################################
{
	my $installer = slurp($INSTALLER);
	my ($fn)  = $installer =~ /^(check_firewall_port\(\) \{\n.*?^\})$/ms;
	my ($val) = $installer =~ /^(csf_conf_value\(\) \{\n.*?^\})$/ms;
	my ($lst) = $installer =~ /^(port_in_list\(\) \{\n.*?^\})$/ms;
	ok(defined($fn) && defined($val) && defined($lst),
		'check_firewall_port(), csf_conf_value() and port_in_list() were located in the real install-webui.sh');

	# It must not edit csf.conf. Stated as an assertion because "the
	# installer does not write another component's config" is a decision,
	# and a decision nothing checks is a decision that gets reversed by
	# accident.
	unlike($installer, qr/sed[^\n]*-i[^\n]*csf\.conf/,
		'install-webui.sh never edits /etc/csf/csf.conf in place');
	# "Runs it" means the command begins a statement. A `csf -r` inside an
	# echo is the opposite of the thing being forbidden, so the anchor is
	# the start of a line (optionally indented), not the string anywhere.
	unlike($installer, qr{^\s*(?:/usr/sbin/)?csf\s+-r\b}m,
		'install-webui.sh never RUNS csf -r - it prints it for the operator');
	unlike($installer, qr{^\s*(?:/usr/sbin/)?csf\s+(?:-a|-d|-x|-e|-tr)\b}m,
		'install-webui.sh never runs any other csf sub-command either');
	like($installer, qr/csf -r/,
		'...and it does print it, so the operator has the exact command');

	SKIP: {
		skip 'the firewall-check functions could not be extracted', 8
			unless defined($fn) && defined($val) && defined($lst);
		my $sandbox = tempdir(CLEANUP => 1);
		spew("$sandbox/fn.sh", "$val\n$lst\n$fn\n");

		my $call = sub {
			my ($port, $conf) = @_;
			my ($out) = run_sh($sandbox, 'fw.sh',
				". \"$sandbox/fn.sh\"\ncheck_firewall_port $port \"$conf\"\necho \"RC=\$?\"\n");
			return $out;
		};

		# MEASURED, on the shipped files. csf.conf (cPanel) carries 8443;
		# csf.generic.conf - the plain server, and what the owner ran -
		# does not.
		my $generic = $call->(8443, "$ROOT/csf.generic.conf");
		like($generic, qr/^RC=1$/m,
			'the shipped csf.generic.conf does NOT have 8443 in TCP_IN - check_firewall_port() says so');
		like($generic, qr/is NOT open in csf's own firewall/,
			'...in words, prominently');
		like($generic, qr/^csf-ui:   TCP_IN = "[^"]*,8443"$/m,
			'...printing the complete replacement TCP_IN line, ready to paste');
		like($generic, qr/^csf-ui:   TCP6_IN = "[^"]*,8443"$/m,
			'...and TCP6_IN, which is a separate list and a separate way to be unreachable');
		like($generic, qr/TESTING = "1"/,
			'...and flags TESTING = "1", under which the port list is only true between a csf start and the next cron clear');

		my $cpanel = $call->(8443, "$ROOT/csf.conf");
		like($cpanel, qr/^RC=0$/m,
			'the shipped csf.conf (cPanel) DOES carry 8443 - the check does not cry wolf where the port is already open');

		# A port nobody ships open, on the file that is otherwise fine.
		my $odd = $call->(9443, "$ROOT/csf.conf");
		like($odd, qr/^RC=1$/m,
			'a non-default port is closed even on the one configuration that ships 8443 open');

		my $missing = $call->(8443, "$sandbox/no-such-csf.conf");
		like($missing, qr/^RC=2$/m,
			'an unreadable csf.conf is "could not tell" (2), never silently "open"');
	}

	# port_in_list must understand csf's own lo:hi ranges, or it reports an
	# open port as closed and sends the operator to edit a line that is
	# already correct.
	SKIP: {
		skip 'port_in_list() could not be extracted', 4 unless defined $lst;
		my $sandbox = tempdir(CLEANUP => 1);
		spew("$sandbox/fn.sh", "$lst\n");
		for my $case ([22, 1], [2025, 1], [8443, 0], [2031, 0]) {
			my ($port, $want) = @$case;
			my ($out) = run_sh($sandbox, 'pil.sh',
				". \"$sandbox/fn.sh\"\nif port_in_list $port '20,21,22,2020:2030,443'; then echo YES; else echo NO; fi\n");
			like($out, $want ? qr/YES/ : qr/NO/,
				"port_in_list: $port is " . ($want ? 'inside' : 'outside') . " '20,21,22,2020:2030,443'");
		}
	}
}

###############################################################################
# SECTION 12 - the connect check: does the configured thing actually answer?
#
# This is the gap all six defects fell through. _enable_now() proves a unit
# starts and stays up; nothing proved anything was listening. Driven here
# against a REAL listener this test owns and shuts down, not a stub - a
# connect check verified with a mock would be exactly the shape it exists
# to replace.
###############################################################################
{
	my $installer = slurp($INSTALLER);
	my ($fn) = $installer =~ /^(probe_listener\(\) \{\n.*?^\})$/ms;
	ok(defined($fn), 'probe_listener() was located in the real install-webui.sh');

	# The honesty requirement, asserted: a local connect must not be
	# reported as reachability.
	like($installer, qr/it did not cross/,
		'the success message says what the probe did NOT cross (csf rules, upstream firewall, routing)');
	like($installer, qr/That is all this proves/,
		'...and bounds its own claim in as many words');

	SKIP: {
		skip 'probe_listener() could not be extracted', 5 unless defined $fn;
		my $sandbox = tempdir(CLEANUP => 1);
		spew("$sandbox/fn.sh", "$fn\n");

		# A real listener, in a child this process owns, on a unix socket -
		# no TCP port, so nothing here can collide with anything else on a
		# shared host.
		my $sockpath = "$sandbox/probe.sock";
		my $pid = fork();
		die "fork: $!" unless defined $pid;
		unless ($pid) {
			socket(my $srv, Socket::AF_UNIX(), Socket::SOCK_STREAM(), 0) or POSIX::_exit(1);
			bind($srv, Socket::pack_sockaddr_un($sockpath)) or POSIX::_exit(1);
			listen($srv, 5) or POSIX::_exit(1);
            sleep 60;
			POSIX::_exit(0);
		}
		# Wait for the child to bind rather than sleeping a guessed amount.
		my $waited = 0;
		while (!-e $sockpath && $waited < 100) { Time::HiRes::sleep(0.05); $waited++ }
		ok(-e $sockpath, 'the test listener bound its socket');

		my ($live) = run_sh($sandbox, 'p1.sh',
			". \"$sandbox/fn.sh\"\nprobe_listener \"$sockpath\"\necho \"RC=\$?\"\n");
		like($live, qr/^RC=0$/m, 'probe_listener() CONNECTS to a real listener')
			or diag($live);

		kill('TERM', $pid);
		waitpid($pid, 0);
		unlink $sockpath;

		my ($dead) = run_sh($sandbox, 'p2.sh',
			". \"$sandbox/fn.sh\"\nprobe_listener \"$sockpath\"\necho \"RC=\$?\"\necho \"REASON=\$probe_reason\"\n");
		like($dead, qr/^RC=1$/m, 'probe_listener() FAILS once that listener is gone - the state defects 5 and 6 produced')
			or diag($dead);
		like($dead, qr/REASON=REFUSED/, '...and reports the reason rather than only the verdict');

		my ($bad) = run_sh($sandbox, 'p3.sh',
			". \"$sandbox/fn.sh\"\nprobe_listener not-an-address 8443\necho \"RC=\$?\"\n");
		like($bad, qr/^RC=2$/m, 'an address that will not parse is "could not test" (2), never "connected"');
	}

	# verify_install() must act on both halves, and must not be able to
	# print its success sentence over either.
	# EACH OF THESE THREE PINS THE GUARD TO ITS CONSEQUENCE, not the
	# message on its own. Measured while writing them: an assertion that
	# only looked for the wording stayed GREEN when the condition above it
	# was replaced with `if false` - the same presence-only hazard this
	# tree already recorded for apache_check_modules(), reached again from
	# a different direction. What has to survive is the pairing.
	my $listen_guard = 'if [ -z "$installed_listen" ]; then';
	like($installer, qr/\Q$listen_guard\E[\s\S]{0,600}?\Qis mode B with no UI_LISTEN\E[\s\S]{0,600}?\Qproblems=$((problems + 1))\E/,
		'verify_install() treats a mode-B ui.conf with no UI_LISTEN as a problem in its own right - and COUNTS it');
	my $dead_msg = 'nothing is accepting connections on $probe_target:$installed_port';
	like($installer, qr/\Q$dead_msg\E[\s\S]{0,400}?\Qproblems=$((problems + 1))\E/,
		'verify_install() counts a listener that does not answer as a problem, not merely mentions it');
	my $fw_gate = 'check_firewall_port "$installed_port"';
	like($installer, qr/\Q$fw_gate\E\s*\n\s*if \[ \$\? -eq 1 \]; then\s*\n\s*\Qproblems=$((problems + 1))\E/,
		'verify_install() asks the firewall question AND gates on its answer - a closed port is a problem, so "verified OK" cannot be printed over it');
}

done_testing();
