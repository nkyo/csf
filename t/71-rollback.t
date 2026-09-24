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
# ConfigServer::UI::Rollback and ui-src/bin/csf-ui-setup (task-8-brief.md:
# "rollback timer unit is written and removed; answers file round-trips
# through the CLI path", plus the atomic commit and the token-never-in-a-URL
# rule).
#
# Nothing here needs root, systemd, a network or IO::Socket::SSL (G1). Every
# path is a temp directory and every child is a fixture - including
# /etc/systemd/system, which is just another directory as far as this module
# is concerned, and systemctl, which is an argv list this test reads back.
###############################################################################
use strict;
use warnings;

use FindBin ();
use lib "$FindBin::Bin/..", "$FindBin::Bin/../ui-src/lib";

use File::Temp qw(tempdir);
use Socket ();
use POSIX ();
use Test::More tests => 498;

use ConfigServer::UI::Rollback ();
use ConfigServer::UI::Firewall ();
use ConfigServer::UI::Server   ();

my $SETUP_PATH = "$FindBin::Bin/../ui-src/bin/csf-ui-setup";
ok(-f $SETUP_PATH, 'csf-ui-setup is where docs/WEBUI-RPC.md S2.3 says it is');
require $SETUP_PATH;
my $S = 'ConfigServer::UI::Setup';
ok($S->can('handle_request'), 'csf-ui-setup loads as a module without starting a listener');

###############################################################################
# Fixtures.
###############################################################################
package FakeRunner;

sub new { return bless { rules => [], log => [] }, shift }

sub on {
	my ($self, $pattern, $answer) = @_;
	push @{ $self->{rules} }, [$pattern, $answer];
	return $self;
}

sub runner {
	my ($self) = @_;
	return sub {
		my (@argv) = @_;
		pop @argv;
		my $line = join(' ', @argv);
		push @{ $self->{log} }, $line;
		for my $rule (@{ $self->{rules} }) {
			next unless $line =~ $rule->[0];
			my $answer = $rule->[1];
			$answer = $answer->($self, \@argv) if ref($answer) eq 'CODE';
			return { exit => 0, output => '', %$answer };
		}
		return { exit => 0, output => '' };     # a permissive default; tests that care assert on the log
	};
}

sub ran { my ($self, $pattern) = @_; return scalar grep { /$pattern/ } @{ $self->{log} } }
sub log_lines { return @{ $_[0]{log} } }

package main;

sub slurp {
	my ($path) = @_;
	open(my $fh, '<:raw', $path) or return undef;
	local $/;
	my $text = <$fh>;
	close $fh;
	return $text;
}

sub spew {
	my ($path, $text) = @_;
	open(my $fh, '>:raw', $path) or die "cannot write $path: $!";
	print $fh $text;
	close $fh;
	return $path;
}

# A stand-in for the csfui group's gid. Nothing in this workspace has one,
# which is exactly why it is injected.
my $CSFUI_GID = 143;

my $CSF_CONF_FIXTURE = <<'CONF';
# /etc/csf/csf.conf - a very small stand-in for the real 1,500-line file.
TESTING = "0"
TESTING_INTERVAL = "5"

# Allow incoming TCP ports
TCP_IN = "22,80,443"
TCP_OUT = "22,80,443"
IPV6 = "0"
LF_ALERT_TO = ""
CONF

# A Firewall whose runner and locate() are both fixtures.
sub firewall_for {
	my ($runner, %where) = @_;
	return ConfigServer::UI::Firewall->new(
		runner => $runner->runner,
		locate => sub { my ($name) = @_; return $where{$name} },
	);
}

# A temp world: csf.conf, ui.conf, a snapshot dir, a unit dir, and - when
# asked - a /run/systemd/system stand-in so systemd_available() says yes.
sub world {
	my (%opt) = @_;
	my $root = tempdir(CLEANUP => 1);
	mkdir "$root/etc";
	mkdir "$root/units";
	spew("$root/etc/csf.conf", $CSF_CONF_FIXTURE);
	mkdir "$root/run-systemd" if $opt{systemd};

	my $runner = FakeRunner->new;
	my $firewall = firewall_for($runner,
		systemctl => '/bin/systemctl',
		csf       => '/usr/sbin/csf',
		($opt{no_iptables_save} ? () : ('iptables-save' => '/sbin/iptables-save')),
	);
	$runner->on(qr{^/sbin/iptables-save\z}, { output => "*filter\n-A INPUT -j ACCEPT\nCOMMIT\n" });

	# chown and the group lookup are injected, because this test runs as an
	# ordinary user: a real chown to root:csfui would fail and a real
	# getgrnam('csfui') would find nothing. Injecting them is what lets the
	# OWNERSHIP be asserted as a value - which is the whole finding
	# (task-8-review.md C1): the previous round proved ui.conf was valid by
	# reading it AS ROOT, which says nothing at all about the csfui the web
	# tier execs as.
	my @chown;
	my $rollback = ConfigServer::UI::Rollback->new(
		dir            => "$root/rollback",
		unit_dir       => "$root/units",
		csf_conf       => "$root/etc/csf.conf",
		ui_conf        => "$root/etc/ui.conf",
		# The REAL file, not the installed path, so that every arm() in this
		# file is armed against something that must actually be exec'able -
		# which makes the R73 check load-bearing in every test that arms,
		# not only in the ones written for it.
		setup_bin      => ($opt{setup_bin} || $SETUP_PATH),
		systemd_marker => "$root/run-systemd",
		firewall       => $firewall,
		gid_for        => sub {
			my ($name) = @_;
			return undef if $opt{no_csfui_group};
			return ($name eq 'csfui') ? $CSFUI_GID : undef;
		},
		chown          => sub {
			my ($uid, $gid, $path) = @_;
			push @chown, { uid => $uid, gid => $gid, path => $path, existed => (-e $path ? 1 : 0) };
			return $opt{chown_fails} ? 0 : 1;
		},
		# chmod is injected for the same reason: its FAILURE is what the
		# check around it is for, and a chmod on a file this process owns
		# does not fail on demand.
		chmod          => sub {
			my ($mode, $path) = @_;
			return 0 if $opt{chmod_fails};
			return chmod($mode, $path);
		},
		(defined $opt{window} ? (window => $opt{window}) : ()),
	);
	return { root => $root, runner => $runner, firewall => $firewall,
		rollback => $rollback, chown => \@chown };
}

sub mode_of {
	my ($path) = @_;
	return undef unless -e $path;
	return sprintf('%04o', (stat($path))[2] & 07777);
}

###############################################################################
# THE INSTALLED ARTIFACTS THEMSELVES (task-8-review.md R69).
#
# THE WHOLE SUITE MISSED A DEAD RESCUE MECHANISM BECAUSE IT NEVER LOOKED AT A
# FILE. Fix round 1 dropped csf-ui-setup's exec bit, 100755 -> 100644. The
# rollback unit's ExecStart runs that path directly, so the timer would have
# fired 203/EXEC and restored nothing - the one mechanism that exists for
# when everything else has gone wrong, killed by a file mode, by the very
# round that hardened it. Two thousand four hundred tests did not notice,
# because they load modules and call functions and never once ask what is on
# disk.
#
# So this reads the filesystem, not the git index, and checks every file
# against docs/WEBUI-RPC.md S2.3's table - which Task 9 installs against too,
# so the check pays for itself twice.
#
# WHAT CAN AND CANNOT BE ASSERTED HERE, stated plainly so the next person
# does not think this is weaker than it looks by accident. Git records ONE
# permission bit, owner-execute; a fresh clone's modes are otherwise the
# umask's business, so asserting a literal 0750 would fail on any machine
# with a different umask and prove nothing about the installed system. What
# git does carry - and what actually broke - is exactly the executable /
# not-executable distinction, and that is what is checked here, against the
# same table, plus "never writable by group or other", which holds for every
# umask that is not itself a bug. The literal 0750 and 0644 are the
# INSTALLER's to set (Task 9); this is the half of S2.3 a repository can
# keep.
###############################################################################
{
	# docs/WEBUI-RPC.md S2.3, verbatim: path => installed mode.
	my %S2_3 = (
		'ui-src/bin/csf-ui'        => 0750,
		'ui-src/bin/csf-ui-helper' => 0750,
		'ui-src/bin/csf-ui-passwd' => 0750,
		'ui-src/bin/csf-ui-setup'  => 0750,
	);

	my $bin = "$FindBin::Bin/../ui-src/bin";
	opendir(my $dh, $bin) or die "cannot read $bin: $!";
	my @found = sort grep { -f "$bin/$_" } grep { !/^\./ } readdir $dh;
	closedir $dh;

	# Nothing may appear in the installed directory that the frozen table
	# does not name: a binary S2.3 has never heard of is one Task 9 will
	# install with no agreed mode at all.
	is_deeply(\@found, [sort map { m{([^/]+)\z} } keys %S2_3],
		'every file in ui-src/bin is one docs/WEBUI-RPC.md S2.3 names, and every one it names is there');

	for my $relative (sort keys %S2_3) {
		my $path = "$FindBin::Bin/../$relative";
		my $want = $S2_3{$relative};
		my $mode = (stat($path))[2];
		ok(defined $mode, "$relative exists on disk");
		next unless defined $mode;
		$mode &= 07777;

		# The bit that broke. S2.3 says 0750; the owner-execute bit is the
		# part of that a git checkout carries, and without it the rollback
		# timer's ExecStart is 203/EXEC and restores nothing.
		is((($mode & 0100) ? 1 : 0), (($want & 0100) ? 1 : 0),
			sprintf('%s is executable by its owner, as S2.3\'s %04o requires', $relative, $want));
		is(($mode & 0022), 0, "$relative is not writable by group or other");
	}

	# And the mirror image for the library: S2.3 freezes those at 0644, so
	# an exec bit there is just as wrong, in the other direction.
	my $lib = "$FindBin::Bin/../ui-src/lib/ConfigServer/UI";
	opendir(my $lh, $lib) or die "cannot read $lib: $!";
	my @module = sort grep { /\.pm\z/ } readdir $lh;
	closedir $lh;
	ok(scalar(@module) >= 8, 'the module directory is where it should be (not a vacuous pass)');
	for my $module (@module) {
		my $mode = (stat("$lib/$module"))[2] & 07777;
		is(($mode & 0111), 0, "ConfigServer/UI/$module is NOT executable, per S2.3's 0644");
		is(($mode & 0022), 0, "ConfigServer/UI/$module is not writable by group or other");
	}
}

###############################################################################
# THE ATOMIC COMMIT: temp file, validate, rename.
###############################################################################
{
	my $w = world();
	my $target = "$w->{root}/etc/atomic.conf";
	spew($target, "ORIGINAL\n");

	my $out = $w->{rollback}->write_atomic($target, "REPLACED\n", mode => 0600);
	is($out->{ok}, 1, 'write_atomic writes');
	is(slurp($target), "REPLACED\n", 'and the content is what was asked for');
	is(sprintf('%04o', (stat($target))[2] & 07777), '0600', 'with the mode that was asked for, umask notwithstanding');

	my @stray = glob("$w->{root}/etc/.csf-ui-setup.*");
	is(scalar @stray, 0, 'and no temporary file is left behind');
}
{
	# THE GUARD: a validator that refuses must leave the original untouched
	# and must leave nothing behind.
	my $w = world();
	my $target = "$w->{root}/etc/atomic.conf";
	spew($target, "ORIGINAL\n");

	my $saw_path;
	my $out = $w->{rollback}->write_atomic($target, "REPLACED\n",
		mode     => 0600,
		validate => sub {
			$saw_path = $_[0];
			return (0, ['deliberately refused']);
		});

	is($out->{ok}, 0, 'a validator that refuses fails the write');
	is_deeply($out->{problems}, ['deliberately refused'], 'and its problems come back');
	is(slurp($target), "ORIGINAL\n", 'THE ORIGINAL FILE IS BYTE-FOR-BYTE UNTOUCHED');
	isnt($saw_path, $target, 'the validator was handed the TEMP path, not the target');
	ok(defined $saw_path && !-e $saw_path, 'and the temp file is gone');
	is(scalar(my @stray = glob("$w->{root}/etc/.csf-ui-setup.*")), 0, 'nothing is left behind');
}
{
	my $w = world();
	my $target = "$w->{root}/etc/atomic.conf";
	spew($target, "ORIGINAL\n");
	my $out = $w->{rollback}->write_atomic($target, "REPLACED\n",
		validate => sub { die "the validator exploded\n" });
	is($out->{ok}, 0, 'a validator that DIES also fails the write');
	like($out->{reason}, qr/validation of the new file died/, 'saying so');
	is(slurp($target), "ORIGINAL\n", 'and the original is still untouched');
}
{
	# The validator reads the finished file off the disk - not the string
	# the caller passed - which is the whole reason it is handed a path.
	my $w = world();
	my $target = "$w->{root}/etc/atomic.conf";
	my $seen;
	$w->{rollback}->write_atomic($target, "CONTENT ON DISK\n",
		validate => sub { $seen = slurp($_[0]); return (1, []) });
	is($seen, "CONTENT ON DISK\n", 'the validator can read the exact bytes that are about to go live');
	is(slurp($target), "CONTENT ON DISK\n", 'and they did');
}
{
	my $w = world();
	my $out = $w->{rollback}->write_atomic("$w->{root}/no/such/dir/x.conf", "x\n");
	is($out->{ok}, 0, 'a target in a directory that does not exist is a refusal, not a die');
	my $none = $w->{rollback}->write_atomic(undef, 'x');
	is($none->{ok}, 0, 'and so is no path at all');
}

###############################################################################
# THE SNAPSHOT
###############################################################################
{
	my $w = world();
	spew("$w->{root}/etc/ui.conf", qq{UI_MODE="a"\n});

	my $snap = $w->{rollback}->snapshot;
	is($snap->{ok}, 1, 'a snapshot is taken');
	ok(-d $snap->{dir}, 'into a directory of its own');
	is(slurp("$snap->{dir}/csf.conf"), $CSF_CONF_FIXTURE, 'csf.conf is copied byte for byte');
	is(slurp("$snap->{dir}/ui.conf"), qq{UI_MODE="a"\n}, 'and so is ui.conf');
	is(slurp("$snap->{dir}/ruleset.v4"), "*filter\n-A INPUT -j ACCEPT\nCOMMIT\n",
		'and the live ruleset, from iptables-save on stdout - no shell redirection');

	my $meta = $w->{rollback}->read_meta($snap->{dir});
	is($meta->{CSF_CONF}, "$w->{root}/etc/csf.conf", 'the metadata records where csf.conf came from');
	like($meta->{SAVED}, qr/csf\.conf/, 'and what was saved');
}
{
	# No csf.conf: there is nothing to roll back to, so there is no snapshot.
	my $w = world();
	unlink "$w->{root}/etc/csf.conf";
	my $snap = $w->{rollback}->snapshot;
	is($snap->{ok}, 0, 'no csf.conf means no snapshot');
	like($snap->{reason}, qr/no known-good configuration to restore/, 'and says why');
}
{
	# No ui.conf yet (first-ever setup) is perfectly ordinary and must not
	# stop the snapshot - it is the case this wizard mostly exists for.
	my $w = world();
	my $snap = $w->{rollback}->snapshot;
	is($snap->{ok}, 1, 'a missing ui.conf does not stop a snapshot');
	is_deeply($snap->{missing}, ['ui.conf'], 'it is recorded as missing instead');
}
{
	my $w = world(no_iptables_save => 1);
	my $snap = $w->{rollback}->snapshot;
	is($snap->{ok}, 1, 'a host with no iptables-save can still be snapshotted');
	ok(!-e "$snap->{dir}/ruleset.v4", 'there is simply no ruleset file');
}

###############################################################################
# THE UNIT TEXT - independence from csf and lfd, asserted about the generated
# text rather than trusted from a comment.
###############################################################################
{
	# unit_text() is a pure function of its inputs and does not care whether
	# the binary exists - that is arm()'s check (R73) - so this one uses the
	# frozen installed path from docs/WEBUI-RPC.md S2.3, which is what a
	# real unit file will contain.
	my $w = world(systemd => 1, setup_bin => '/usr/local/csf-ui/bin/csf-ui-setup');
	my ($service, $timer) = $w->{rollback}->unit_text('/var/lib/csf-ui/rollback/123-456');

	like($service, qr/^\[Service\]$/m, 'the service unit has a [Service] section');
	like($service, qr{^ExecStart=/usr/local/csf-ui/bin/csf-ui-setup --rollback-now --snapshot /var/lib/csf-ui/rollback/123-456$}m,
		'whose ExecStart restores exactly this snapshot');
	like($service, qr/^Type=oneshot$/m, 'as a oneshot');

	like($timer, qr/^OnActiveSec=300$/m, 'the timer fires after the confirmation window');
	like($timer, qr/^OnBootSec=60$/m, 'and also after a reboot, so a power cycle mid-apply does not disarm it');
	like($timer, qr/^Unit=csf-ui-rollback\.service$/m, 'and it triggers the rollback service');
	like($timer, qr/^\[Install\]$/m, 'it has an [Install] section...');
	like($timer, qr/^WantedBy=timers\.target$/m, '...so that enabling it means something');

	# THE INDEPENDENCE PROPERTY.
	for my $text ($service, $timer) {
		unlike($text, qr/^(?:After|Before|Requires|Requisite|Wants|BindsTo|PartOf|WantedBy|RequiredBy|Conflicts)=.*\bcsf\.service\b/m,
			'no dependency directive names csf.service');
		unlike($text, qr/^(?:After|Before|Requires|Requisite|Wants|BindsTo|PartOf|WantedBy|RequiredBy|Conflicts)=.*\blfd\.service\b/m,
			'no dependency directive names lfd.service');
	}
}
{
	my $w = world(systemd => 1, window => 42);
	my (undef, $timer) = $w->{rollback}->unit_text('/var/lib/csf-ui/rollback/1');
	like($timer, qr/^OnActiveSec=42$/m, 'the window is configurable');
}
{
	my $w = world(systemd => 1);
	for my $bad ('relative/path', '', '/var/lib/csf-ui/rollback/a%ib', "/var/lib/x\nExecStart=/bin/sh") {
		my ($service, $why) = $w->{rollback}->unit_text($bad);
		is($service, undef, 'a snapshot path that would change a unit file\'s meaning is refused');
		ok(defined $why && length $why, 'with a reason');
	}
}
{
	for my $window (0, 29, 3601, 'soon') {
		my $w = world(systemd => 1, window => $window);
		my ($service, $why) = $w->{rollback}->unit_text('/var/lib/csf-ui/rollback/1');
		is($service, undef, "a window of \"$window\" is refused");
	}
	{
		# An undef window cannot arrive through new() (it falls back to the
		# default), so it is set directly - a unit file with an empty
		# OnActiveSec= is a timer that never fires.
		my $w = world(systemd => 1);
		$w->{rollback}{window} = undef;
		my ($service) = $w->{rollback}->unit_text('/var/lib/csf-ui/rollback/1');
		is($service, undef, 'a window of undef is refused');
	}
}

###############################################################################
# R73: arm() REFUSES A ExecStart IT CANNOT EXEC.
#
# The mode test above guards ui-src/ - the repository. The timer arms against
# the INSTALLED path, and until this check nothing verified that at all. So
# the exact failure that killed this rescue mechanism in fix round 1 could
# still arrive at the only path that matters at runtime: a bad install, a
# partial upgrade, or Task 9, which is the task that does the installing.
#
# A timer that will 203/EXEC is worse than no timer, because the operator is
# told they are covered.
###############################################################################
{
	my $w = world(systemd => 1, setup_bin => "$FindBin::Bin/../no-such-binary");
	my $snap = $w->{rollback}->snapshot;
	my $armed = $w->{rollback}->arm($snap->{dir});
	is($armed->{ok}, 0, 'arming against a binary that does not exist is refused');
	is($armed->{code}, 'E_EXEC', 'with its own code');
	like($armed->{reason}, qr/does not exist/, 'saying which of the three things is wrong with it');
	like($armed->{reason}, qr/203\/EXEC/, 'naming the failure it would have produced');
	ok(!-e "$w->{root}/units/csf-ui-rollback.timer", 'and no unit file is written');
	is($w->{runner}->ran(qr/systemctl/), 0, 'and systemctl is never called');
}
{
	my $w = world(systemd => 1, setup_bin => "$FindBin::Bin/../CHANGES.md");
	my $snap = $w->{rollback}->snapshot;
	my $armed = $w->{rollback}->arm($snap->{dir});
	is($armed->{ok}, 0, 'arming against a file that is not executable is refused');
	is($armed->{code}, 'E_EXEC', 'with the same code');
	like($armed->{reason}, qr/not executable \(mode [0-7]{4}\)/,
		'and the mode it actually has, which is the fact that decides it');
	ok(!-e "$w->{root}/units/csf-ui-rollback.service", 'and nothing is written');
}
{
	my $w = world(systemd => 1, setup_bin => "$FindBin::Bin/..");
	my $snap = $w->{rollback}->snapshot;
	my $armed = $w->{rollback}->arm($snap->{dir});
	is($armed->{ok}, 0, 'arming against a directory is refused');
	like($armed->{reason}, qr/not a plain file/, 'saying so');
}
{
	# And the whole point of the refusal: apply() stops, so an operator is
	# never handed a configuration guarded by a timer that cannot run.
	my $w = world(systemd => 1, setup_bin => "$FindBin::Bin/../no-such-binary");
	my $setup = setup_for($w);
	my ($answer) = $S->can('parse_answers')->(qq{TCP_IN="22,443"\n});
	my $result = $setup->apply(answers => $answer);
	is($result->{ok}, 0, 'and apply() will not apply anything without a rollback that can run');
	is($result->{code}, 'E_EXEC', 'naming why');
	is(slurp("$w->{root}/etc/csf.conf"), $CSF_CONF_FIXTURE, 'csf.conf untouched');
}
{
	# The live one: armed against the real file, which must be exec'able.
	my $w = world(systemd => 1);
	my $snap = $w->{rollback}->snapshot;
	is($w->{rollback}->arm($snap->{dir})->{ok}, 1,
		'arming against a real, executable binary succeeds - so every other arm() in this file is load-bearing for R73');
}

###############################################################################
# ARM AND CONFIRM - the timer unit is written, and it is removed.
###############################################################################
{
	my $w = world(systemd => 1);
	my $snap = $w->{rollback}->snapshot;

	my $armed = $w->{rollback}->arm($snap->{dir});
	is($armed->{ok}, 1, 'the rollback timer arms');
	ok(-f "$w->{root}/units/csf-ui-rollback.service", 'the service unit file exists');
	ok(-f "$w->{root}/units/csf-ui-rollback.timer",   'the timer unit file exists');
	is($w->{rollback}->armed, 1, 'armed() says so');
	is(sprintf('%04o', (stat("$w->{root}/units/csf-ui-rollback.timer"))[2] & 07777), '0644',
		'unit files are readable by systemd');

	is($w->{runner}->ran(qr{^/bin/systemctl daemon-reload\z}), 1, 'systemd was reloaded');
	is($w->{runner}->ran(qr{^/bin/systemctl enable --now csf-ui-rollback\.timer\z}), 1,
		'and the timer was ENABLED as well as started, so a reboot does not disarm it');

	my $confirmed = $w->{rollback}->confirm;
	is($confirmed->{ok}, 1, 'confirming succeeds');
	is($confirmed->{cancelled}, 1, 'and reports that it cancelled something');
	ok(!-e "$w->{root}/units/csf-ui-rollback.service", 'the service unit is REMOVED');
	ok(!-e "$w->{root}/units/csf-ui-rollback.timer",   'the timer unit is REMOVED');
	is($w->{rollback}->armed, 0, 'armed() says so');
	is($w->{runner}->ran(qr{systemctl stop csf-ui-rollback\.timer}), 1, 'the timer was stopped');
	is($w->{runner}->ran(qr{systemctl disable csf-ui-rollback\.timer}), 1, 'and disabled');
}
{
	# THE GUARD: no systemd, no arming - and no approximation.
	my $w = world(systemd => 0);
	my $snap = $w->{rollback}->snapshot;
	my ($available, $why) = $w->{rollback}->systemd_available;
	is($available, 0, 'systemd_available says no when /run/systemd/system is absent');
	like($why, qr/not running systemd/, 'naming the reason');

	my $armed = $w->{rollback}->arm($snap->{dir});
	is($armed->{ok}, 0, 'arm() refuses');
	is($armed->{code}, 'E_NO_SYSTEMD', 'with E_NO_SYSTEMD');
	ok(!-e "$w->{root}/units/csf-ui-rollback.timer", 'and writes no unit file at all');
	is($w->{runner}->ran(qr/systemctl/), 0, 'and never calls systemctl');
	like($armed->{reason}, qr/no independent rollback timer can be installed/,
		'the refusal says what is missing rather than pretending');
}
{
	my $w = world(systemd => 1);
	$w->{firewall} = firewall_for(FakeRunner->new);       # locate() finds no systemctl
	my $rollback = ConfigServer::UI::Rollback->new(
		dir => "$w->{root}/rollback", unit_dir => "$w->{root}/units",
		csf_conf => "$w->{root}/etc/csf.conf", ui_conf => "$w->{root}/etc/ui.conf",
		systemd_marker => "$w->{root}/run-systemd", firewall => $w->{firewall},
	);
	my ($available, $why) = $rollback->systemd_available;
	is($available, 0, 'systemd running but no systemctl binary is also a refusal');
	like($why, qr/no systemctl binary/, 'with its own reason, because the advice differs');
}
{
	# A half-installed timer is worse than none: daemon-reload failing must
	# leave nothing behind.
	my $w = world(systemd => 1);
	$w->{runner}->on(qr{daemon-reload}, { exit => 1, output => "Failed to reload.\n" });
	my $snap = $w->{rollback}->snapshot;
	my $armed = $w->{rollback}->arm($snap->{dir});
	is($armed->{ok}, 0, 'a failed daemon-reload fails the arm');
	ok(!-e "$w->{root}/units/csf-ui-rollback.service", 'and the units are removed again');
	ok(!-e "$w->{root}/units/csf-ui-rollback.timer",   'both of them');
	is($w->{rollback}->armed, 0, 'nothing is left armed');
}
{
	my $w = world(systemd => 1);
	$w->{runner}->on(qr{enable --now}, { exit => 1, output => "Failed to enable unit.\n" });
	my $snap = $w->{rollback}->snapshot;
	my $armed = $w->{rollback}->arm($snap->{dir});
	is($armed->{ok}, 0, 'a failed enable fails the arm');
	is($w->{rollback}->armed, 0, 'and leaves nothing armed');
}

###############################################################################
# RESTORE - what the timer runs when the operator never confirmed.
###############################################################################
{
	my $w = world(systemd => 1);
	spew("$w->{root}/etc/ui.conf", qq{UI_MODE="a"\nUI_ALLOW="203.0.113.5"\n});
	my $snap = $w->{rollback}->snapshot;
	$w->{rollback}->arm($snap->{dir});

	# The apply happens: both files are replaced with something else.
	spew("$w->{root}/etc/csf.conf", qq{TESTING = "1"\nTCP_IN = "22"\n});
	spew("$w->{root}/etc/ui.conf",  qq{UI_MODE="b"\n});

	my $restored = $w->{rollback}->restore($snap->{dir});
	is($restored->{ok}, 1, 'the snapshot restores');
	is(slurp("$w->{root}/etc/csf.conf"), $CSF_CONF_FIXTURE, 'csf.conf is back to what it was');
	is(slurp("$w->{root}/etc/ui.conf"), qq{UI_MODE="a"\nUI_ALLOW="203.0.113.5"\n}, 'and so is ui.conf');
	is($w->{runner}->ran(qr{^/usr/sbin/csf -r\z}), 1, 'csf was restarted with the restored configuration');
	is($w->{runner}->ran(qr{iptables-restore}), 0,
		'and the saved ruleset was NOT replayed - that is the fallback, not the primary');

	is($w->{rollback}->armed, 0, 'the rollback disarms itself, so it cannot fire again on the next boot');
	like(join("\n", @{ $restored->{steps} }), qr/disarmed/, 'and says so');
}
{
	my $w = world(systemd => 1);
	$w->{runner}->on(qr{^/usr/sbin/csf -r\z}, { exit => 1, output => "csf: cannot start\n" });
	$w->{firewall} = firewall_for($w->{runner},
		systemctl => '/bin/systemctl', csf => '/usr/sbin/csf',
		'iptables-save' => '/sbin/iptables-save', 'iptables-restore' => '/sbin/iptables-restore');
	my $rollback = ConfigServer::UI::Rollback->new(
		dir => "$w->{root}/rollback", unit_dir => "$w->{root}/units",
		csf_conf => "$w->{root}/etc/csf.conf", ui_conf => "$w->{root}/etc/ui.conf",
		systemd_marker => "$w->{root}/run-systemd", firewall => $w->{firewall});
	my $snap = $rollback->snapshot;
	spew("$w->{root}/etc/csf.conf", qq{TESTING = "1"\n});

	my $restored = $rollback->restore($snap->{dir});
	is($w->{runner}->ran(qr{^/sbin/iptables-restore }), 1,
		'when csf will not restart, the saved ruleset IS replayed - connectivity beats tidiness');
	my ($replay) = grep { m{^/sbin/iptables-restore } } $w->{runner}->log_lines;
	like($replay, qr{ \Q$snap->{dir}\E/ruleset\.v4\z},
		'and the ruleset is passed as a file operand, not through a shell redirect');
}
{
	my $w = world(systemd => 1);
	my $restored = $w->{rollback}->restore("$w->{root}/not-a-snapshot");
	is($restored->{ok}, 0, 'restoring from a directory this code did not write is refused');
	like($restored->{reason}, qr/no snapshot metadata/, 'naming the reason');
	is(slurp("$w->{root}/etc/csf.conf"), $CSF_CONF_FIXTURE, 'and csf.conf is untouched');
}

###############################################################################
# THE ANSWERS FILE, AND ITS ROUND TRIP THROUGH THE CLI PATH.
###############################################################################
{
	my $text = <<'ANSWERS';
# a comment
TCP_IN="22,80,443,30000:35000"
UI_MODE="a"
UI_ALLOW="203.0.113.0/24, 198.51.100.7"
UI_PORT="8443"
ANSWERS
	my ($answer, $problems) = $S->can('parse_answers')->($text);
	ok($answer, 'a good answers file parses');
	is_deeply($problems, [], 'with no problems');
	is($answer->{TCP_IN}, '22,80,443,30000:35000', 'port lists survive, ranges and all');
	is($answer->{UI_ALLOW}, '203.0.113.0/24,198.51.100.7',
		'the allowlist comes back canonicalised, with the spaces gone');
	is($answer->{UI_PORT}, '8443', 'numbers come back as numbers');

	my $round = $S->can('serialise_answers')->($answer);
	my ($again) = $S->can('parse_answers')->($round);
	is_deeply($again, $answer, 'and serialise -> parse is a round trip, so a browser session is reproducible');
	like($round, qr/csf-ui-setup --answers THIS-FILE --yes/, 'the file says how to apply itself');
}
{
	my @case = (
		[qq{UI_ALOW="1.2.3.4"\n},                  qr/not a setting this wizard writes/, 'a typo\'d key'],
		[qq{UI_MODE="a"\nUI_MODE="b"\n},           qr/set more than once/,               'a duplicate key'],
		[qq{UI_MODE=a\n},                          qr/does not match the KEY/,           'an unquoted value'],
		[qq{UI_MODE="A"\n},                        qr/exactly "a" or "b"/,               'the wrong case'],
		[qq{UI_PORT="80"\n},                       qr/between 1024 and 65535/,           'a privileged port'],
		[qq{UI_ALLOW=""\n},                        qr/must not be empty/,                'an empty allowlist'],
		[qq{UI_ALLOW="0.0.0.0/0"\n},               qr/whole Internet/,                   'an allowlist of everybody'],
		[qq{UI_ALLOW="nonsense"\n},                qr/not a valid IP address/,           'a hostname in the allowlist'],
		[qq{TCP_IN="22,notaport"\n},               qr/only digits, commas and colons/,   'a non-numeric port'],
		[qq{TCP_IN="22,99999"\n},                  qr/not a port between 1 and 65535/,   'a port above 65535'],
		[qq{TCP_IN="500:100"\n},                   qr/low bound is above its high bound/, 'a backwards range'],
		[qq{IPV6="yes"\n},                         qr/must be 0 or 1/,                   'a non-boolean'],
		[qq{UI_LISTEN="example.com"\n},            qr/not a hostname/,                   'a hostname where a literal is required'],
	);
	for my $case (@case) {
		my ($text, $why, $label) = @$case;
		my ($answer, $problems) = $S->can('parse_answers')->($text);
		is($answer, undef, "$label is refused");
		like(join(' ', @$problems), $why, "$label says why");
	}
}
{
	# THE GUARD: TESTING cannot be answered away.
	my ($answer, $problems) = $S->can('parse_answers')->(qq{TESTING="0"\n});
	is($answer, undef, 'an answers file that turns TESTING off is refused');
	like(join(' ', @$problems), qr/is always set to "1" by this wizard/,
		'rather than silently overridden - somebody wrote that on purpose and is entitled to be told');

	my ($ok) = $S->can('parse_answers')->(qq{TESTING="1"\n});
	ok($ok, 'mentioning TESTING with the value it is going to have anyway is fine');

	my ($bad_interval, $why) = $S->can('parse_answers')->(qq{TESTING_INTERVAL="9000"\n});
	is($bad_interval, undef, 'and TESTING_INTERVAL cannot be answered away either');
}

###############################################################################
# csf.conf rewriting and its validator.
###############################################################################
{
	my $new = $S->can('rewrite_csf_conf')->($CSF_CONF_FIXTURE,
		{ TCP_IN => '22,443', TESTING => '1', NEW_KEY => 'x' });

	like($new, qr/^TCP_IN = "22,443"$/m, 'an existing setting is replaced where it stands');
	like($new, qr/^TESTING = "1"$/m, 'and so is another');
	like($new, qr/^# Allow incoming TCP ports$/m, 'comments survive');
	like($new, qr/^LF_ALERT_TO = ""$/m, 'settings this wizard was not asked about survive');
	like($new, qr/^NEW_KEY = "x"$/m, 'a setting that was absent is appended');
	is(scalar(() = $new =~ /^TCP_IN\s*=/mg), 1, 'and nothing is written twice');
}
{
	my $w = world();
	my $path = "$w->{root}/etc/candidate.conf";

	spew($path, qq{TCP_IN = "22"\nTCP_IN = "80"\n});
	my ($ok, $problems) = $S->can('validate_csf_conf')->($path, {});
	is($ok, 0, 'a duplicated setting is caught before the rename');
	like(join(' ', @$problems), qr/appears more than once/, 'naming it');

	spew($path, qq{TCP_IN = 22\n});
	($ok, $problems) = $S->can('validate_csf_conf')->($path, {});
	is($ok, 0, 'an unquoted value is caught - csf croaks on those and then will not start');

	spew($path, qq{TCP_IN = "22"\n});
	($ok, $problems) = $S->can('validate_csf_conf')->($path, { TCP_IN => '22,443' });
	is($ok, 0, 'a setting that did not actually take is caught');
	like(join(' ', @$problems), qr/reads back as "22", not the "22,443"/,
		'which is the interesting bug: a valid file that does not contain the change');

	($ok, $problems) = $S->can('validate_csf_conf')->($path, { TCP_IN => '22' });
	is($ok, 1, 'and a file that does contain it passes');

	($ok, $problems) = $S->can('validate_csf_conf')->("$w->{root}/etc/nope.conf", {});
	is($ok, 0, 'an unreadable candidate is a refusal, not a die');
}

###############################################################################
# APPLY - the whole CLI path, end to end, against a fixture world.
###############################################################################
sub setup_for {
	my ($w, %opt) = @_;
	return $S->new(
		firewall  => $w->{firewall},
		rollback  => $w->{rollback},
		state_dir => "$w->{root}/state",
		csf_conf  => "$w->{root}/etc/csf.conf",
		ui_conf   => "$w->{root}/etc/ui.conf",
		setup_cli => '/usr/local/csf-ui/bin/csf-ui-setup',
		token     => 'fixture-token',
		tls_available => ($opt{tls} ? sub { 1 } : sub { 0 }),
		%opt,
	);
}

{
	my $w = world(systemd => 1);
	my $setup = setup_for($w);
	my ($answer) = $S->can('parse_answers')->(<<'ANSWERS');
TCP_IN="22,443"
UI_MODE="a"
UI_ALLOW="203.0.113.5"
UI_PORT="8443"
ANSWERS

	my $result = $setup->apply(answers => $answer);
	is($result->{ok}, 1, 'the answers apply');

	my $csf = slurp("$w->{root}/etc/csf.conf");
	like($csf, qr/^TCP_IN = "22,443"$/m, 'csf.conf carries the answered setting');
	like($csf, qr/^TESTING = "1"$/m, 'TESTING is forced on, whatever the answers said');
	# CHANGED 2026-09-24 and RED for one run while it was changed: this
	# pinned 300, which was the rollback window in SECONDS written into a
	# cron MINUTE field. It is 5 - the same duration, in this key's own
	# unit, and csf's own shipped default.
	like($csf, qr/^TESTING_INTERVAL = "5"$/m, 'and TESTING_INTERVAL is forced to 5 (minutes)');
	like($csf, qr/^LF_ALERT_TO = ""$/m, 'and everything else in the file survived');

	my $ui = slurp("$w->{root}/etc/ui.conf");
	like($ui, qr/^UI_MODE="a"$/m, 'ui.conf is written');
	like($ui, qr/^UI_ALLOW="203\.0\.113\.5"$/m, 'with the allowlist');
	my ($conf, $problems) = ConfigServer::UI::Server::read_ui_conf("$w->{root}/etc/ui.conf");
	is_deeply($problems, [], 'and csf-ui\'s OWN startup gate accepts the file the wizard wrote');

	is($w->{rollback}->armed, 1, 'the rollback timer is armed');
	ok(-d $result->{snapshot}, 'and the snapshot it will restore is on disk');
	is($w->{runner}->ran(qr{^/usr/sbin/csf -r\z}), 1,
		'csf was restarted, so the configuration being guarded is the one in force');

	my $confirmed = $setup->confirm;
	is($confirmed->{cancelled}, 1, 'confirming cancels the timer');
	is($w->{rollback}->armed, 0, 'and removes its units');
}
{
	# THE GUARD THE BRIEF NAMES: no independent rollback, no apply.
	my $w = world(systemd => 0);
	my $setup = setup_for($w);
	my ($answer) = $S->can('parse_answers')->(qq{TCP_IN="22,443"\n});

	my $result = $setup->apply(answers => $answer);
	is($result->{ok}, 0, 'without systemd, nothing is applied');
	is($result->{code}, 'E_NO_SYSTEMD', 'and the reason is named');
	is(slurp("$w->{root}/etc/csf.conf"), $CSF_CONF_FIXTURE,
		'CSF.CONF IS BYTE-FOR-BYTE UNTOUCHED - the apply stopped before it wrote anything');
	ok(!-e "$w->{root}/etc/ui.conf", 'and no ui.conf was written either');
	like($result->{reason}, qr/Apply from a shell you can watch instead/,
		'the operator is told what to do instead of being left with a silent refusal');
	ok(-d $result->{snapshot}, 'the snapshot was still taken, so nothing was wasted');
}
{
	# A ui.conf the startup gate would reject never reaches /etc.
	my $w = world(systemd => 1);
	my $setup = setup_for($w);
	# UI_SESSION_IDLE > UI_SESSION_MAX: each is in range on its own, and the
	# pair is what S10 refuses - so this cannot be caught by per-key checks.
	my ($answer) = $S->can('parse_answers')->(<<'ANSWERS');
UI_MODE="a"
UI_ALLOW="203.0.113.5"
UI_SESSION_IDLE="80000"
UI_SESSION_MAX="600"
ANSWERS
	ok($answer, 'each key passes its own check');
	my $result = $setup->apply(answers => $answer);
	is($result->{ok}, 0, 'but the apply fails on the pair');
	like(join(' ', @{ $result->{problems} }), qr/UI_SESSION_IDLE/, 'named by Server.pm\'s own gate');
	ok(!-e "$w->{root}/etc/ui.conf", 'and no ui.conf was written');
	is(slurp("$w->{root}/etc/csf.conf"), $CSF_CONF_FIXTURE,
		'AND CSF.CONF IS UNTOUCHED TOO - both candidates are judged before either is renamed');
	ok(!-e "$w->{root}/state/ui.conf.candidate", 'the scratch candidate is not left behind');
	is($w->{rollback}->armed, 1, 'the timer stays armed, because the snapshot is what covers the rest');
}

###############################################################################
# THE WEB TIER: the token is never in a URL, and the wizard applies through
# the CLI rather than editing csf.conf itself.
###############################################################################
sub request {
	my (%opt) = @_;
	return {
		method  => $opt{method} || 'GET',
		path    => $opt{path},
		query   => $opt{query} || {},
		headers => $opt{headers} || {},
		body    => $opt{body},
		peer    => '127.0.0.1',
	};
}

sub cookie_from {
	my ($response) = @_;
	for my $header (@{ $response->{headers} }) {
		next unless lc($header->[0]) eq 'set-cookie';
		my ($value) = $header->[1] =~ /^csfui_setup=([^;]*)/;
		return $value;
	}
	return undef;
}

{
	my $w = world(systemd => 1);
	my $setup = setup_for($w);

	my $landing = $setup->handle_request(request(path => '/'));
	is($landing->{status}, 200, 'the landing page renders');
	like($landing->{body}, qr/<form method="post" action="\/token">/, 'with a form that POSTs the token');
	like($landing->{body}, qr/type="password"/, 'into a field the browser will not echo');
	unlike($landing->{body}, qr/token=/, 'and nothing on the page puts a token in a URL');

	# GUARD: any query string at all is refused, on every route.
	for my $path ('/', '/wizard') {
		my $refused = $setup->handle_request(request(path => $path, query => { token => 'secret' }));
		is($refused->{status}, 400, "a query string on $path is refused outright");
		like($refused->{body}, qr/must never appear in a URL/, 'saying why');
	}
	my $harmless = $setup->handle_request(request(path => '/', query => { anything => '1' }));
	is($harmless->{status}, 400,
		'and it is the SHAPE that is refused, not the key name - there is no URL a secret could arrive in');

	my $wrong = $setup->handle_request(request(method => 'POST', path => '/token', body => 'token=nope'));
	is($wrong->{status}, 403, 'the wrong token is refused');
	is(cookie_from($wrong), undef, 'and sets no cookie');

	my $right = $setup->handle_request(request(method => 'POST', path => '/token', body => 'token=fixture-token'));
	is($right->{status}, 303, 'the right token redirects');
	my ($location) = map { $_->[1] } grep { lc($_->[0]) eq 'location' } @{ $right->{headers} };
	is($location, '/wizard', 'to the wizard');
	unlike($location, qr/[?&]/, 'and the redirect carries no query string of its own');

	my $cookie = cookie_from($right);
	ok(defined $cookie && length $cookie, 'a cookie is set');
	isnt($cookie, 'fixture-token',
		'and it is NOT the token - the printed secret is used once and never stored by the browser');
	my ($set) = map { $_->[1] } grep { lc($_->[0]) eq 'set-cookie' } @{ $right->{headers} };
	like($set, qr/HttpOnly/, 'the cookie is HttpOnly');
	like($set, qr/SameSite=Strict/, 'and SameSite=Strict');

	my $denied = $setup->handle_request(request(path => '/wizard'));
	is($denied->{status}, 303, 'the wizard is not reachable without the cookie');

	my $page = $setup->handle_request(request(path => '/wizard', headers => { cookie => "csfui_setup=$cookie" }));
	is($page->{status}, 200, 'and is reachable with it');
	like($page->{body}, qr/name="_csrf"/, 'carrying a CSRF token in the form');
	like($page->{body}, qr/TCP_IN/, 'and the settings it asks about');
}
{
	my $w = world(systemd => 1);
	my $setup = setup_for($w);
	$setup->handle_request(request(method => 'POST', path => '/token', body => 'token=fixture-token'));
	my $cookie = $setup->{session}{id};
	my $csrf   = $setup->{session}{csrf};

	my $no_csrf = $setup->handle_request(request(method => 'POST', path => '/apply',
		headers => { cookie => "csfui_setup=$cookie" }, body => 'TCP_IN=22'));
	is($no_csrf->{status}, 403, 'a POST with no CSRF token is refused');

	my $wrong_csrf = $setup->handle_request(request(method => 'POST', path => '/apply',
		headers => { cookie => "csfui_setup=$cookie" }, body => "_csrf=wrong&TCP_IN=22"));
	is($wrong_csrf->{status}, 403, 'and so is one with the wrong token');
	is($w->{runner}->ran(qr/--answers/), 0, 'neither reached the setup CLI');

	# The real thing.
	my $applied = $setup->handle_request(request(method => 'POST', path => '/apply',
		headers => { cookie => "csfui_setup=$cookie" },
		body => "_csrf=$csrf&TCP_IN=22%2C443&UI_MODE=a&UI_ALLOW=203.0.113.5"));
	is($applied->{status}, 200, 'a well-formed apply is accepted');

	my ($invocation) = grep { /--answers/ } $w->{runner}->log_lines;
	is($invocation, "/usr/local/csf-ui/bin/csf-ui-setup --answers $w->{root}/state/answers.conf --yes",
		'THE BROWSER PATH RE-INVOKES THE CLI - it does not apply anything in this process');

	my $answers = slurp("$w->{root}/state/answers.conf");
	like($answers, qr/^TCP_IN="22,443"$/m, 'the answers file it wrote carries the answers');
	like($answers, qr/^UI_ALLOW="203\.0\.113\.5"$/m, 'all of them');
	is(slurp("$w->{root}/etc/csf.conf"), $CSF_CONF_FIXTURE,
		'and the web tier itself NEVER TOUCHED csf.conf');
	like($applied->{body}, qr/Open a NEW ssh connection/,
		'the page tells the operator to prove a NEW connection works, not to trust the one they have');
}
{
	# EVERYTHING THE APPLY SAID ALSO REACHES THE TERMINAL.
	#
	# The page carrying that output travels back over the very port the
	# apply may have just closed, so a re-assertion that failed would send
	# the one message saying "your route is gone" down the route that is
	# gone. The terminal is on the SSH session the wizard was started from,
	# which a rule flush cannot break.
	my $w = world(systemd => 1);
	my $setup = setup_for($w);
	$w->{runner}->on(qr/--answers/, { exit => 0, output => "csf.conf: written\nWARNING: your route back in is gone\n" });
	$setup->handle_request(request(method => 'POST', path => '/token', body => 'token=fixture-token'));
	my ($cookie, $csrf) = ($setup->{session}{id}, $setup->{session}{csrf});

	my $captured = '';
	{
		open(my $save, '>&', \*STDERR) or die "dup: $!";
		close STDERR;
		open(STDERR, '>', \$captured) or die "reopen: $!";
		$setup->handle_request(request(method => 'POST', path => '/apply',
			headers => { cookie => "csfui_setup=$cookie" },
			body => "_csrf=$csrf&TCP_IN=22&UI_MODE=a&UI_ALLOW=203.0.113.5"));
		close STDERR;
		open(STDERR, '>&', $save) or die "restore: $!";
		close $save;
	}
	like($captured, qr/apply said:/, 'the apply output is echoed to the wizard\'s own terminal');
	like($captured, qr/your route back in is gone/,
		'including the warning that would otherwise have travelled down the route it is warning about');
}
{
	# A bad answer from the browser comes back as a page, not a crash, and
	# nothing is invoked.
	my $w = world(systemd => 1);
	my $setup = setup_for($w);
	$setup->handle_request(request(method => 'POST', path => '/token', body => 'token=fixture-token'));
	my ($cookie, $csrf) = ($setup->{session}{id}, $setup->{session}{csrf});

	my $out = $setup->handle_request(request(method => 'POST', path => '/apply',
		headers => { cookie => "csfui_setup=$cookie" },
		body => "_csrf=$csrf&TCP_IN=notaport&UI_MODE=a"));
	is($out->{status}, 200, 'an invalid answer renders the form again');
	like($out->{body}, qr/Nothing was changed/, 'saying nothing was changed');
	like($out->{body}, qr/only digits, commas and colons/, 'and what was wrong');
	is($w->{runner}->ran(qr/--answers/), 0, 'and the CLI was never invoked');

	# An attempt to turn TESTING off from the browser is refused by the same
	# table the CLI uses, because it IS the same table.
	my $testing = $setup->handle_request(request(method => 'POST', path => '/apply',
		headers => { cookie => "csfui_setup=$cookie" },
		body => "_csrf=$csrf&TESTING=0&UI_MODE=a"));
	like($testing->{body}, qr/is always set to/, 'a browser cannot turn TESTING off either');
	is($w->{runner}->ran(qr/--answers/), 0, 'and that did not reach the CLI');
}
{
	# Lifetimes. 30 minutes absolute, 10 minutes idle.
	my $w = world(systemd => 1);
	my $clock = 1_757_548_800;
	my $setup = setup_for($w, now => sub { $clock });
	$setup->handle_request(request(method => 'POST', path => '/token', body => 'token=fixture-token'));
	my $cookie = $setup->{session}{id};

	$clock += 500;
	is($setup->handle_request(request(path => '/wizard', headers => { cookie => "csfui_setup=$cookie" }))->{status},
		200, 'a session is good inside the idle window');

	$clock += 601;
	is($setup->handle_request(request(path => '/wizard', headers => { cookie => "csfui_setup=$cookie" }))->{status},
		303, 'and is gone once it has been idle for ten minutes');

	# Absolute: keep it busy, and it still ends at thirty minutes.
	my $busy = setup_for($w, now => sub { $clock });
	$busy->handle_request(request(method => 'POST', path => '/token', body => 'token=fixture-token'));
	my $busy_cookie = $busy->{session}{id};
	for (1 .. 5) {
		$clock += 300;
		$busy->handle_request(request(path => '/wizard', headers => { cookie => "csfui_setup=$busy_cookie" }));
	}
	$clock += 300;
	is($busy->handle_request(request(path => '/wizard', headers => { cookie => "csfui_setup=$busy_cookie" }))->{status},
		303, 'a busy session still ends at thirty minutes');
}
{
	# Routing basics.
	my $w = world(systemd => 1);
	my $setup = setup_for($w);
	is($setup->handle_request(request(path => '/nope'))->{status}, 404, 'an unknown path is 404');
	my $wrong_method = $setup->handle_request(request(method => 'GET', path => '/token'));
	is($wrong_method->{status}, 405, 'the wrong method is 405');
	my ($allow) = map { $_->[1] } grep { lc($_->[0]) eq 'allow' } @{ $wrong_method->{headers} };
	is($allow, 'POST', 'with an Allow header');
	is($setup->handle_request('not a hash')->{status}, 400, 'a malformed request is 400, not a die');

	# Every page is no-store and no-referrer: this one shows a firewall's
	# configuration and mints a session.
	my $page = $setup->handle_request(request(path => '/'));
	my %header = map { lc($_->[0]) => $_->[1] } @{ $page->{headers} };
	is($header{'cache-control'}, 'no-store', 'pages are not cached');
	is($header{'referrer-policy'}, 'no-referrer', 'and send no Referer');
	like($header{'content-security-policy'}, qr/default-src 'none'/, 'with a restrictive CSP');
}

###############################################################################
# THE OPERATOR'S JOURNEY OVER THE TEMPORARY PORT, END TO END
# (task-8-review.md C2).
#
# csf -r is dostop;dostart (csf.pl:125) and dostop FLUSHES. The wizard's own
# INPUT 1 rule goes with everything else - so the operator who reached the
# wizard on the temporary port has no route left to POST /confirm, this tier
# having no keep-alive, and the rollback fires every time. The confirmation
# route is destroyed by the very apply it exists to confirm.
#
# The fixture below models the flush: csf -r empties the rule list. The test
# walks the whole journey - open the port, record it, apply, and then ask the
# question that actually matters, which is whether the operator can still get
# back in.
###############################################################################
sub flushing_world {
	my (%opt) = @_;
	my $w = world(systemd => 1);

	my @rules;
	my $runner = FakeRunner->new;
	# systemctl answers plainly that firewalld is not running: this test is
	# about iptables, and leaving that probe to the permissive default would
	# make detect() decline for a reason that has nothing to do with it.
	$runner->on(qr{is-active firewalld}, { exit => 3, output => "inactive\n" })
	       ->on(qr{^/sbin/iptables --version\z}, { output => "iptables v1.8.7 (nf_tables)\n" })
	       ->on(qr{ -I INPUT 1 }, sub {
			push @rules, '-A INPUT -s 203.0.113.5/32 -p tcp -m comment --comment csf-ui-setup -m tcp --dport 8444 -j ACCEPT';
			return { exit => 0, output => '' };
		})
	       ->on(qr{ -D INPUT }, sub { @rules = (); return { exit => 0, output => '' } })
	       ->on(qr{ -S INPUT\z}, sub {
			return { exit => 0, output => join("\n", '-P INPUT ACCEPT', @rules) . "\n" };
		})
	       # csf -r == dostop;dostart. dostop flushes.
	       ->on(qr{^/usr/sbin/csf -r\z}, sub { @rules = (); return { exit => 0, output => "csf restarted\n" } });

	my $firewall = ConfigServer::UI::Firewall->new(
		runner => $runner->runner,
		locate => sub {
			my ($name) = @_;
			return '/sbin/iptables' if $name eq 'iptables';
			return '/usr/sbin/csf'  if $name eq 'csf';
			return '/bin/systemctl' if $name eq 'systemctl';
			return undef;
		});

	# The rollback's own runner must see the same systemctl.
	$w->{rollback}{firewall} = $firewall;
	$w->{runner} = $runner;
	$w->{firewall} = $firewall;
	$w->{rules} = \@rules;
	return $w;
}

{
	my $w = flushing_world();
	my $setup = setup_for($w, tls => 1, port => 8444);

	# 1. The operator is on SSH; the wizard opens one port to their address.
	my $offer = $setup->offer_port(address => '203.0.113.5');
	is($offer->{ok}, 1, 'the wizard opens the temporary port');

	# 2. ...and records it, which is what makes it closable later.
	my $recorded = $setup->record_offer($offer);
	is($recorded->{ok}, 1, 'and records it');
	my ($open_now) = $w->{firewall}->rule_present($setup->load_state);
	is($open_now, 1, 'the operator can reach the wizard');

	# 3. They fill the form in and apply.
	my ($answer) = $S->can('parse_answers')->(qq{TCP_IN="22,443"\n});
	my $result = $setup->apply(answers => $answer);
	is($result->{ok}, 1, 'the apply succeeds');
	is($w->{runner}->ran(qr{^/usr/sbin/csf -r\z}), 1, 'csf was restarted, which flushed every rule');

	# 4. THE QUESTION THAT MATTERS: can they get back in to confirm?
	my ($still_open) = $w->{firewall}->rule_present($setup->load_state);
	is($still_open, 1,
		'THE PORT IS STILL OPEN AFTER THE APPLY - the operator can make the new connection /confirm needs');
	is($w->{runner}->ran(qr{ -I INPUT 1 }), 2, 'because the rule was put back after the flush');
	like(join("\n", @{ $result->{steps} }), qr/csf -r flushed the wizard rule; it has been put back/,
		'and the operator is told that happened');

	# The record follows the new rule, read back from the backend, so the
	# rule that now exists is the rule cleanup will remove.
	my $spec = $setup->load_state;
	like($spec->{canonical}, qr/^-A INPUT /, 'the recorded canonical is the backend\'s own rendering');
	my $done = $setup->cleanup;
	like(join("\n", @$done), qr/temporary firewall rule was removed/, 'and cleanup closes it');
	is(scalar @{ $w->{rules} }, 0, 'leaving nothing behind');
}
{
	# Idempotent: when csf did NOT flush the rule, nothing is added, because
	# a second copy would be a rule only one close_port() ever removes.
	my $w = flushing_world();
	my $setup = setup_for($w, tls => 1, port => 8444);
	$setup->record_offer($setup->offer_port(address => '203.0.113.5'));
	my $before = $w->{runner}->ran(qr{ -I INPUT 1 });

	my $again = $setup->reassert_temporary_port;
	is($again->{ok}, 1, 're-asserting an intact rule succeeds');
	is($again->{restored}, 0, 'without restoring anything');
	is($w->{runner}->ran(qr{ -I INPUT 1 }), $before, 'and without adding a second copy');
}
{
	# Nothing to re-assert when there was never a temporary port.
	my $w = flushing_world();
	my $setup = setup_for($w, tls => 1, port => 8444);
	is($setup->reassert_temporary_port, undef, 'with no state file there is nothing to re-assert');
}
{
	# A backend that will not answer must not be read as "the rule is gone",
	# because that would add a second copy of a rule that is still there.
	my $w = world(systemd => 1);
	my $runner = FakeRunner->new->on(qr{ -S INPUT\z}, { exit => 1, output => "cannot read\n" });
	my $firewall = firewall_for($runner, iptables => '/sbin/iptables');
	my $setup = $S->new(firewall => $firewall, rollback => $w->{rollback},
		state_dir => "$w->{root}/state", token => 't');
	$setup->save_state({ kind => 'iptables', binary => '/sbin/iptables', chain => 'INPUT',
		port => 8444, address => '203.0.113.5',
		canonical => '-A INPUT -s 203.0.113.5/32 -j ACCEPT' });

	my $again = $setup->reassert_temporary_port;
	is($again->{ok}, 0, 'an unanswerable backend fails the re-assertion');
	like($again->{reason}, qr/could not be determined/, 'saying so');
	is($runner->ran(qr{ -I INPUT 1 }), 0, 'and adds nothing');
}

###############################################################################
# C3: the record is part of opening the port, not a note about it.
###############################################################################
{
	my $w = world();
	my $runner = FakeRunner->new
		->on(qr{ -S INPUT\z}, { output =>
			"-P INPUT ACCEPT\n-A INPUT -s 203.0.113.5/32 -j ACCEPT\n" })
		->on(qr{ -D INPUT }, { exit => 0, output => '' });
	my $firewall = firewall_for($runner, iptables => '/sbin/iptables');
	# A state directory that cannot be created, because its parent is a FILE.
	spew("$w->{root}/blocked", "not a directory\n");
	my $setup = $S->new(firewall => $firewall, rollback => $w->{rollback},
		state_dir => "$w->{root}/blocked/state", token => 't');

	my $offer = { ok => 1, spec => { kind => 'iptables', binary => '/sbin/iptables',
		chain => 'INPUT', port => 8444, address => '203.0.113.5',
		canonical => '-A INPUT -s 203.0.113.5/32 -j ACCEPT' } };

	my $recorded = $setup->record_offer($offer);
	is($recorded->{ok}, 0, 'an offer whose record cannot be written is not an offer');
	is($recorded->{code}, 'E_NO_STATE', 'with its own code');
	is($runner->ran(qr{ -D INPUT }), 1,
		'AND THE PORT WAS CLOSED AGAIN - a rule nothing is tracking is a rule nothing will ever close');
	is($setup->listen_plan($recorded)->{bind}, '127.0.0.1',
		'so the wizard falls back to the tunnel, which costs the operator nothing');
}
{
	my $w = world();
	my $setup = setup_for($w);
	my $unchanged = $setup->record_offer({ ok => 0, reason => 'declined earlier' });
	is($unchanged->{ok}, 0, 'a refusal passes through record_offer untouched');
}

###############################################################################
# C4: "the timer has been cancelled" is a claim, and it has to be true.
###############################################################################
{
	my $w = world(systemd => 1);
	my $snap = $w->{rollback}->snapshot;
	$w->{rollback}->arm($snap->{dir});
	$w->{runner}->on(qr{systemctl stop csf-ui-rollback\.timer}, { exit => 1, output => "Failed to stop unit.\n" });

	my $confirmed = $w->{rollback}->confirm;
	is($confirmed->{cancelled}, 0, 'a stop that failed is NOT a cancellation');
	is($confirmed->{ok}, 0, 'and the whole result says so');
	like(join(' ', @{ $confirmed->{problems} }), qr/could not stop/, 'naming what failed');
	like($confirmed->{reason}, qr/could not stop/, 'in the reason too');
}
{
	my $w = world(systemd => 1);
	my $snap = $w->{rollback}->snapshot;
	$w->{rollback}->arm($snap->{dir});
	$w->{runner}->on(qr{systemctl disable csf-ui-rollback\.timer}, { exit => 1, output => "Failed to disable unit.\n" });
	my $confirmed = $w->{rollback}->confirm;
	is($confirmed->{cancelled}, 0, 'a disable that failed is not a cancellation either');
	like(join(' ', @{ $confirmed->{problems} }), qr/could not disable/, 'naming it');
}
{
	# The unit files will not delete. Everything else "worked"; the timer is
	# still installed, and that is the only fact the operator cares about.
	my $w = world(systemd => 1);
	my $snap = $w->{rollback}->snapshot;
	$w->{rollback}->arm($snap->{dir});
	chmod 0500, "$w->{root}/units";

	my $confirmed = $w->{rollback}->confirm;
	chmod 0755, "$w->{root}/units";
	SKIP: {
		skip 'running as root, where a read-only directory is no obstacle', 4 if $> == 0;
		is($confirmed->{cancelled}, 0, 'unit files that will not delete is not a cancellation');
		is($confirmed->{ok}, 0, 'and not an ok');
		like(join(' ', @{ $confirmed->{problems} }), qr/could not be removed/, 'naming the file');
		is($w->{rollback}->armed, 1, 'and armed() still says the timer is there, which is the truth');
	}
}
{
	my $w = world(systemd => 1);
	my $snap = $w->{rollback}->snapshot;
	$w->{rollback}->arm($snap->{dir});
	# Armed already, so this only ever answers the reload that follows the
	# units being removed.
	$w->{runner}->on(qr{systemctl daemon-reload}, { exit => 1, output => "Failed to reload.\n" });
	my $confirmed = $w->{rollback}->confirm;
	is($confirmed->{cancelled}, 0, 'a daemon-reload that failed after removal is reported, not swallowed');
	like(join(' ', @{ $confirmed->{problems} }), qr/daemon-reload failed/, 'naming it');
	is($w->{rollback}->armed, 0, 'though the unit files really are gone');
}
{
	my $w = world(systemd => 1);
	my $snap = $w->{rollback}->snapshot;
	$w->{rollback}->arm($snap->{dir});
	my $confirmed = $w->{rollback}->confirm;
	is($confirmed->{cancelled}, 1, 'and on the happy path it really was cancelled');
	is_deeply($confirmed->{problems}, [], 'with nothing to report');
}
{
	# restore() checks disarm the same way: a rollback unit left installed
	# fires again on the next boot.
	my $w = world(systemd => 1);
	my $snap = $w->{rollback}->snapshot;
	$w->{rollback}->arm($snap->{dir});
	chmod 0500, "$w->{root}/units";
	my $restored = $w->{rollback}->restore($snap->{dir});
	chmod 0755, "$w->{root}/units";
	SKIP: {
		skip 'running as root', 2 if $> == 0;
		is($restored->{ok}, 0, 'a restore that could not disarm is not a success');
		like(join("\n", @{ $restored->{steps} }), qr/NOT DISARMED/,
			'and says so loudly, because it will otherwise fire again on the next boot');
	}
}

###############################################################################
# MODE AND OWNERSHIP, ASSERTED AS VALUES (task-8-review.md C1).
#
# The previous round's evidence that ui.conf was good was that csf-ui's own
# startup gate accepted it - but that gate ran as ROOT in this test, and root
# reads a root:root 0640 file perfectly well. It proved nothing whatsoever
# about the csfui the web tier actually execs as. So: the numbers, read back
# off the filesystem, and the chown, recorded as arguments.
###############################################################################
{
	my $w = world(systemd => 1);
	my $setup = setup_for($w);
	my ($answer) = $S->can('parse_answers')->(<<'ANSWERS');
TCP_IN="22,443"
UI_MODE="a"
UI_ALLOW="203.0.113.5"
ANSWERS
	my $result = $setup->apply(answers => $answer);
	is($result->{ok}, 1, 'the answers apply');

	is(mode_of("$w->{root}/etc/ui.conf"), '0640',
		'ui.conf ends up 0640 - the value docs/WEBUI-RPC.md S2.3 freezes, read back off the disk');
	is(mode_of("$w->{root}/etc/csf.conf"), '0600', 'and csf.conf 0600');

	my @ui_chown = grep { $_->{gid} == $CSFUI_GID } @{ $w->{chown} };
	ok(scalar(@ui_chown) >= 1, 'ui.conf was chowned to the csfui group');
	is($ui_chown[-1]{uid}, 0, 'owner root');
	is($ui_chown[-1]{gid}, $CSFUI_GID, 'group csfui - the group csf-ui execs as, not root');
	isnt($ui_chown[-1]{path}, "$w->{root}/etc/ui.conf",
		'and the chown happened on the TEMP file, so the file is never visible at its real path owned wrongly');
	is($ui_chown[-1]{existed}, 1, 'on a file that existed at the time');
}
{
	# No csfui group: refused, and refused BEFORE csf.conf is committed,
	# because a missing group is as foreseeable as a read-only /etc.
	my $w = world(systemd => 1, no_csfui_group => 1);
	my $setup = setup_for($w);
	my ($answer) = $S->can('parse_answers')->(qq{TCP_IN="22,443"\nUI_MODE="a"\nUI_ALLOW="203.0.113.5"\n});
	my $result = $setup->apply(answers => $answer);
	is($result->{ok}, 0, 'with no csfui group on the system, nothing is applied');
	like(join(' ', @{ $result->{problems} }), qr/no "csfui" group/,
		'and the refusal names the group rather than writing a file csf-ui could not read');
	ok(!-e "$w->{root}/etc/ui.conf", 'no ui.conf was written');
	is(slurp("$w->{root}/etc/csf.conf"), $CSF_CONF_FIXTURE, 'and csf.conf is untouched');
}
{
	my $w = world(systemd => 1, chown_fails => 1);
	my $setup = setup_for($w);
	my ($answer) = $S->can('parse_answers')->(qq{TCP_IN="22,443"\nUI_MODE="a"\nUI_ALLOW="203.0.113.5"\n});
	my $result = $setup->apply(answers => $answer);
	is($result->{ok}, 0, 'a chown that fails fails the write');
	ok(!-e "$w->{root}/etc/ui.conf", 'and leaves no file behind at all');
	is(slurp("$w->{root}/etc/csf.conf"), $CSF_CONF_FIXTURE, 'csf.conf untouched');
}
{
	# The restore path writes ui.conf too, and it is the same file with the
	# same requirement - a rollback that hands back a ui.conf csf-ui cannot
	# read is a rollback that leaves the UI broken.
	my $w = world(systemd => 1);
	spew("$w->{root}/etc/ui.conf", qq{UI_MODE="a"\nUI_ALLOW="203.0.113.5"\n});
	my $snap = $w->{rollback}->snapshot;
	spew("$w->{root}/etc/ui.conf", qq{UI_MODE="b"\n});
	@{ $w->{chown} } = ();
	$w->{rollback}->restore($snap->{dir});
	is(mode_of("$w->{root}/etc/ui.conf"), '0640', 'the restored ui.conf is 0640');
	my @ui_chown = grep { $_->{gid} == $CSFUI_GID } @{ $w->{chown} };
	is(scalar(@ui_chown), 1, 'and was chowned to csfui on the way back too');
}
{
	# write_atomic's own checks, directly.
	my $w = world();
	my $target = "$w->{root}/etc/grouped.conf";
	spew($target, "ORIGINAL\n");
	my $out = $w->{rollback}->write_atomic($target, "NEW\n", mode => 0640, group => 'nosuchgroup');
	is($out->{ok}, 0, 'an unresolvable group is a refusal');
	like($out->{reason}, qr/no "nosuchgroup" group/, 'naming it');
	is(slurp($target), "ORIGINAL\n", 'and the original is untouched');

	$out = $w->{rollback}->write_atomic($target, "NEW\n", mode => 0640);
	is($out->{ok}, 1, 'without a group, no chown is attempted');
	is(scalar(@{ $w->{chown} }), 0, 'literally none');
	is(mode_of($target), '0640', 'and the mode is still set as a value');
}
{
	# A chmod that fails. sysopen's mode is masked by the umask, so the
	# explicit chmod is the ONLY thing that puts the frozen mode on the
	# file - and an unchecked one is how a config file ships with
	# permissions nobody chose.
	my $w = world(chmod_fails => 1);
	my $target = "$w->{root}/etc/moded.conf";
	spew($target, "ORIGINAL\n");
	my $out = $w->{rollback}->write_atomic($target, "NEW\n", mode => 0640);
	is($out->{ok}, 0, 'a chmod that fails fails the write');
	like($out->{reason}, qr/could not be given mode 0640/, 'naming the mode it could not set');
	is(slurp($target), "ORIGINAL\n", 'and the original is untouched');
	is(scalar(my @stray = glob("$w->{root}/etc/.csf-ui-setup.*")), 0, 'with no temp file left behind');
}

###############################################################################
# C10: WRITABILITY IS PROVED BEFORE ANYTHING IS COMMITTED.
#
# The residual window between the two renames is acceptable because the timer
# covers it. A read-only /etc is not in that category: it is foreseeable, and
# a foreseeable failure deserves a check rather than a net.
###############################################################################
{
	my $w = world();
	my $probe = $w->{rollback}->writable_probe("$w->{root}/etc/anything.conf");
	is($probe->{ok}, 1, 'a writable directory probes clean');
	is(scalar(my @stray = glob("$w->{root}/etc/.csf-ui-setup.probe*")), 0,
		'and the probe leaves nothing behind');

	my $nowhere = $w->{rollback}->writable_probe("$w->{root}/no-such-dir/x.conf");
	is($nowhere->{ok}, 0, 'a directory that does not exist does not probe clean');

	SKIP: {
		skip 'running as root, where a read-only directory is no obstacle', 2 if $> == 0;
		mkdir "$w->{root}/readonly";
		chmod 0500, "$w->{root}/readonly";
		my $ro = $w->{rollback}->writable_probe("$w->{root}/readonly/x.conf");
		chmod 0755, "$w->{root}/readonly";
		is($ro->{ok}, 0, 'a read-only directory does not probe clean');
		like($ro->{reason}, qr/cannot be written to/, 'saying so');
	}
}
{
	SKIP: {
		skip 'running as root, where a read-only directory is no obstacle', 4 if $> == 0;
		my $w = world(systemd => 1);
		my $setup = setup_for($w);
		my ($answer) = $S->can('parse_answers')->(qq{TCP_IN="22,443"\nUI_MODE="a"\nUI_ALLOW="203.0.113.5"\n});

		# ui.conf's directory is writable; csf.conf's is not. Under the old
		# order this would have been found only after ui.conf had already
		# been committed.
		chmod 0500, "$w->{root}/etc";
		my $result = $setup->apply(answers => $answer);
		chmod 0755, "$w->{root}/etc";

		is($result->{ok}, 0, 'a read-only configuration directory stops the apply');
		like($result->{reason}, qr/nothing was applied/, 'before anything is committed');
		is(slurp("$w->{root}/etc/csf.conf"), $CSF_CONF_FIXTURE, 'csf.conf is untouched');
		ok(!-e "$w->{root}/etc/ui.conf", 'and no ui.conf was written');
	}
}
{
	# THE CASE THE PROBE IS ACTUALLY FOR: the FIRST file is perfectly
	# writable and the SECOND is not. Without a probe, csf.conf is committed
	# and then ui.conf fails - the machine half-configured, inside the one
	# window this design cannot close. With it, neither is touched.
	SKIP: {
		skip 'running as root, where a read-only directory is no obstacle', 3 if $> == 0;
		my $w = world(systemd => 1);
		mkdir "$w->{root}/etcui";
		my $setup = setup_for($w, ui_conf => "$w->{root}/etcui/ui.conf");
		$w->{rollback}{ui_conf} = "$w->{root}/etcui/ui.conf";
		my ($answer) = $S->can('parse_answers')->(qq{TCP_IN="22,443"\nUI_MODE="a"\nUI_ALLOW="203.0.113.5"\n});

		chmod 0500, "$w->{root}/etcui";
		my $result = $setup->apply(answers => $answer);
		chmod 0755, "$w->{root}/etcui";

		is($result->{ok}, 0, 'an unwritable ui.conf directory stops the apply');
		is(slurp("$w->{root}/etc/csf.conf"), $CSF_CONF_FIXTURE,
			'AND CSF.CONF - which was perfectly writable - IS STILL UNTOUCHED');
		ok(!-e "$w->{root}/etcui/ui.conf", 'with no ui.conf either');
	}
}

###############################################################################
# DIRECTORY MODES (task-8-review.md C6). A 0700 directory is not a stricter
# 0700 file - it is a wall in front of everything beneath it, including for
# csfui traversing /var/lib/csf-ui to reach its own session store.
###############################################################################
{
	my $w = world();
	my $snap = $w->{rollback}->snapshot;
	is(mode_of($snap->{dir}), '0700', 'the snapshot directory itself is private');
	is(mode_of("$w->{root}/rollback"), '0755',
		'but the directory above it, which this code created on the way, is TRAVERSABLE');
}
{
	my $w = world();
	my $setup = setup_for($w, state_dir => "$w->{root}/var/csf-ui/setup");
	$setup->save_state({ kind => 'iptables', binary => '/sbin/iptables',
		canonical => '-A INPUT -j ACCEPT' });
	is(mode_of("$w->{root}/var/csf-ui/setup"), '0700', 'the state directory is private');
	is(mode_of("$w->{root}/var/csf-ui"), '0755', 'its parent is not private on its behalf');
	is(mode_of("$w->{root}/var"), '0755', 'nor is its grandparent');
	is(mode_of($setup->state_path), '0600', 'and the state file itself is root-only');
}
{
	my $w = world();
	is(ConfigServer::UI::Rollback::make_path("$w->{root}/a/b/c", mode => 0700, parent_mode => 0755),
		undef, 'make_path succeeds');
	is(mode_of("$w->{root}/a/b/c"), '0700', 'leaf gets its mode');
	is(mode_of("$w->{root}/a/b"), '0755', 'parents get theirs');
	# A directory somebody else made is left exactly as it is.
	mkdir "$w->{root}/theirs", 0711;
	ConfigServer::UI::Rollback::make_path("$w->{root}/theirs/mine", mode => 0700);
	is(mode_of("$w->{root}/theirs"), '0711',
		'an existing directory is left alone - this creates directories, it does not have opinions about them');
}

###############################################################################
# R70: THE SENTENCE THE OPERATOR READS AND ACTS ON.
#
# Fix round 1 made confirm()'s DATA honest and left this sentence saying
# "Nothing was armed to cancel" for the case the data was added to describe -
# a cancel that FAILED while the timer is sitting there about to revert the
# configuration the operator has just been told is theirs to keep. Three
# outcomes, three sentences.
###############################################################################
{
	my $w = world(systemd => 1);
	my $setup = setup_for($w);
	my $snap = $w->{rollback}->snapshot;
	$w->{rollback}->arm($snap->{dir});
	$w->{runner}->on(qr{systemctl stop csf-ui-rollback\.timer}, { exit => 1, output => "Failed to stop unit.\n" });
	chmod 0500, "$w->{root}/units";

	my $result = $setup->confirm;
	my ($headline, $detail, $still_armed) = $setup->confirm_outcome($result);
	chmod 0755, "$w->{root}/units";

	SKIP: {
		skip 'running as root, where a read-only directory is no obstacle', 5 if $> == 0;
		is($still_armed, 1, 'a failed cancel with the units still on disk is reported as still armed');
		like($headline, qr/STILL ARMED/,
			'and the HEADLINE says so - not "Nothing was armed to cancel", which is the opposite of the truth');
		unlike($headline, qr/Nothing was armed/, 'that sentence does not appear');
		like($detail, qr/systemctl stop csf-ui-rollback\.timer/,
			'and the operator is handed the command to run right now');
		is($w->{rollback}->armed, 1, 'because the timer really is still there');
	}
}
{
	my $w = world(systemd => 1);
	my $setup = setup_for($w);
	my $snap = $w->{rollback}->snapshot;
	$w->{rollback}->arm($snap->{dir});
	my ($headline, $detail, $still_armed) = $setup->confirm_outcome($setup->confirm);
	is($still_armed, 0, 'a cancel that worked is not still armed');
	like($headline, qr/has been cancelled/, 'and says so');
}
{
	# Nothing was ever armed. Now - and only now - that sentence is true.
	my $w = world(systemd => 0);
	my $setup = setup_for($w);
	my ($headline, $detail, $still_armed) = $setup->confirm_outcome($setup->confirm);
	is($still_armed, 0, 'with nothing armed, nothing is still armed');
	like($headline, qr/Nothing was armed to cancel/, 'and THAT is when the sentence is used');
	is($w->{rollback}->armed, 0, 'which armed() - a file test - confirms independently');
}
{
	# The browser page, end to end, on the dangerous branch.
	my $w = world(systemd => 1);
	my $setup = setup_for($w);
	my $snap = $w->{rollback}->snapshot;
	$w->{rollback}->arm($snap->{dir});
	$w->{runner}->on(qr{systemctl stop}, { exit => 1, output => "Failed.\n" });
	chmod 0500, "$w->{root}/units";
	$setup->handle_request(request(method => 'POST', path => '/token', body => 'token=fixture-token'));
	my ($cookie, $csrf) = ($setup->{session}{id}, $setup->{session}{csrf});
	my $page = $setup->handle_request(request(method => 'POST', path => '/confirm',
		headers => { cookie => "csfui_setup=$cookie" }, body => "_csrf=$csrf"));
	chmod 0755, "$w->{root}/units";
	SKIP: {
		skip 'running as root', 3 if $> == 0;
		like($page->{body}, qr/<h1>NOT kept<\/h1>/, 'the page does not say "Kept" when it was not');
		like($page->{body}, qr/STILL ARMED/, 'it says the timer is still armed');
		like($page->{body}, qr/systemctl stop/, 'with the command to fix it');
	}
}

###############################################################################
# R75: a response that never reaches the browser is REPORTED.
#
# The previous round's version read an eval's value instead of
# write_response()'s, and write_response() never dies - it returns 0 - so the
# check was always true and nothing was ever reported. These drive the real
# function over a real socket, in both directions.
###############################################################################
{
	my $w = world();
	my $setup = setup_for($w);
	my $request = request(method => 'GET', path => '/wizard');
	my $response = { status => 200,
		headers => [['Content-Type', 'text/html']], body => 'hello' };

	# A socket that works: nothing to report.
	socketpair(my $near, my $far, Socket::AF_UNIX(), Socket::SOCK_STREAM(), 0)
		or die "socketpair: $!";
	is($setup->write_response_to($near, $response, $request), undef,
		'a response that was written reports nothing');
	close $near; close $far;

	# A socket whose peer has gone. write_response() returns 0 here; it does
	# not die, which is the whole point of the finding.
	SKIP: {
		# NOTE: SIGPIPE is NOT ignored around the assertions below - only
		# around this test's own probe, which needs it to survive staging the
		# condition. write_response_to() has to protect ITSELF (R79); if it
		# does not, this test dies of SIGPIPE rather than failing politely,
		# which is a red either way and is the behavioural evidence the
		# previous round could only assert about the source.
		my $refuses = do {
			local $SIG{PIPE} = 'IGNORE';
			socketpair(my $p, my $q, Socket::AF_UNIX(), Socket::SOCK_STREAM(), 0)
				or last;
			close $q;
			my $failed = 0;
			my $sent = 0;
			while ($sent < 8 * 1024 * 1024) {
				my $wrote = syswrite($p, 'x' x 65536);
				unless (defined $wrote && $wrote > 0) { $failed = 1; last }
				$sent += $wrote;
			}
			close $p;
			$failed;
		};
		skip 'this platform absorbs writes to a closed peer, so the failure cannot be staged', 3
			unless $refuses;

		socketpair(my $a, my $b, Socket::AF_UNIX(), Socket::SOCK_STREAM(), 0)
			or die "socketpair: $!";
		close $b;
		my $big = { status => 200, headers => [['Content-Type', 'text/html']],
			body => 'x' x (8 * 1024 * 1024) };
		my $note = $setup->write_response_to($a, $big, $request);
		close $a;
		ok(defined $note, 'a response that was NOT written is reported');
		like(($note || ''), qr/never reached the browser \(/, 'saying it never arrived, and why');
		like(($note || ''), qr/GET \/wizard/, 'naming the request it belonged to');
	}
}
{
	# The signal that would otherwise get there first. Without SIGPIPE
	# ignored, writing to a socket the browser has closed kills this process
	# outright - taking the wizard down mid-session and skipping the cleanup
	# that removes the temporary firewall rule.
	open(my $fh, '<', $SETUP_PATH) or die;
	local $/;
	my $source = <$fh>;
	close $fh;
	like($source, qr/local \$SIG\{PIPE\}\s*=\s*'IGNORE'/,
		'the SIGPIPE ignore is local - scoped to the write, so it is not inherited across exec (R80)');
	unlike($source, qr/^\s*\$SIG\{PIPE\}\s*=\s*'IGNORE'/m,
		'and never set unscoped, which is how it would reach a child');
}

###############################################################################
# R76: the unit FILES being gone is not the same as the cancel having worked.
###############################################################################
{
	# stop, disable and daemon-reload all fail; both unlinks succeed. The
	# files are gone, so armed() says no - but systemd has a timer loaded
	# that can still fire, and nothing on disk explains it.
	my $w = world(systemd => 1);
	my $setup = setup_for($w);
	my $snap = $w->{rollback}->snapshot;
	is($w->{rollback}->arm($snap->{dir})->{ok}, 1, 'armed to begin with');
	$w->{runner}->on(qr{systemctl (?:stop|disable|daemon-reload)}, { exit => 1, output => "Failed.\n" });

	my $result = $setup->confirm;
	is($w->{rollback}->armed, 0, 'the unit files really are gone');
	is($result->{ok}, 0, 'but confirm() knows the cancel did not go cleanly');

	my ($headline, $detail, $needs_action) = $setup->confirm_outcome($result);
	is($needs_action, 1, 'so the operator is told there is something to do');
	like($headline, qr/MAY STILL FIRE/, 'and the headline says the rollback may still fire');
	unlike($headline, qr/Nothing was armed to cancel/,
		'NOT "Nothing was armed to cancel" - which is what it said before, while a loaded timer sat there');
	like($detail, qr/systemctl daemon-reload/, 'with the command that settles it');
}
{
	# And the genuinely clean nothing-to-do case still reads as such.
	my $w = world(systemd => 0);
	my $setup = setup_for($w);
	my ($headline, undef, $needs_action) = $setup->confirm_outcome($setup->confirm);
	is($needs_action, 0, 'a clean no-op needs no action');
	like($headline, qr/Nothing was armed to cancel/, 'and that is the only place that sentence is used');
}

###############################################################################
# R77: /proc/<pid>/stat's field 2 is not escaped, so the LAST ')' is the only
# reliable landmark. The previous regex matched the FIRST - harmless for a
# paren-free name, and wrong exactly for the crafted one the reused-pid guard
# exists to catch.
###############################################################################
{
	my $P = 'ConfigServer::UI::Setup';

	# A real line, as Linux writes it. Field 22 (starttime) is 9876543.
	my @after_comm = ('S', 1, 1000, 1000, 0, -1, 4194560,
		100, 200, 0, 0, 10, 20, 5, 5, 20, 0, 1, 0, 9876543, 12345678, 999);
	my $ordinary = "4242 (perl) " . join(' ', @after_comm) . "\n";
	is($P->can('_parse_proc_stat')->($ordinary)->{started}, '9876543', 'an ordinary stat line parses');
	is($P->can('_parse_proc_stat')->($ordinary)->{state}, 'S', 'and yields the process state too');

	# The same process, named so that its comm contains ") " - which is
	# legal, and is what an attacker who can name a process would choose.
	my $hostile = "4242 (evil) 1 2 3 4) " . join(' ', @after_comm) . "\n";
	is($P->can('_parse_proc_stat')->($hostile)->{started}, '9876543',
		'and so does one whose executable name contains ") " - the LAST paren is the landmark');
	is($P->can('_parse_proc_stat')->($hostile)->{state}, 'S',
		'with the state still read from the right field');

	# Spaces alone, without a paren, were never the problem but must survive.
	my $spaced = "4242 (my program) " . join(' ', @after_comm) . "\n";
	is($P->can('_parse_proc_stat')->($spaced)->{started}, '9876543', 'a name with spaces parses');

	# R78: the state that matters.
	my @zombie_fields = @after_comm;
	$zombie_fields[0] = 'Z';
	my $zombie = "4242 (perl) " . join(' ', @zombie_fields) . "\n";
	is($P->can('_parse_proc_stat')->($zombie)->{state}, 'Z', 'a zombie is read as Z');
	is($P->can('_parse_proc_stat')->($zombie)->{started}, '9876543',
		'and keeps its start time - which is exactly why the state has to be checked separately');

	is_deeply($P->can('_parse_proc_stat')->('4242 perl S 1 2 3'), {},
		'a line with no parenthesis at all yields nothing, rather than a wrong number');
	is_deeply($P->can('_parse_proc_stat')->("4242 (perl) S 1 2\n"), {},
		'and so does a line too short to hold field 22');
	is_deeply($P->can('_parse_proc_stat')->(undef), {}, 'undef yields nothing');
}
{
	# R78 END TO END: a ZOMBIE owner must not be treated as confirmed-live.
	#
	# kill(0) succeeds on a zombie, its pid is still there and its start time
	# still matches - so before this check it satisfied every test
	# _state_is_live() applied, and R74's "a confirmed live owner outranks
	# the clock" then honoured the record of a wizard that had EXITED. That
	# re-opens a firewall port inside a process that will not close it, which
	# is R71's hole reached through R74's fix.
	#
	# A real zombie is forked here rather than simulated: the whole finding is
	# that kill(0) and the start time cannot tell one apart, so a fake would
	# be testing the wrong thing.
	SKIP: {
		skip 'no /proc, so a zombie cannot be told from a live process here', 4
			unless -r "/proc/$$/stat";

		my $child = fork();
		defined $child or skip 'fork unavailable', 4;
		if (!$child) { POSIX::_exit(0) }          # exits at once; never reaped below
		select(undef, undef, undef, 0.3);

		my $stat = ConfigServer::UI::Setup::_proc_stat($child);
		skip 'the child was reaped before it could be observed as a zombie', 4
			unless ($stat->{state} || '') eq 'Z';

		ok(kill(0, $child), 'kill(0) succeeds on the zombie - which is why it fooled the old check');

		my $w = world(systemd => 1);
		# Stateful, so that WITHOUT the zombie check this re-assertion would
		# SUCCEED - otherwise it would fail on E_READBACK instead and the
		# assertion below would pass for entirely the wrong reason.
		my $RENDERED = '-A INPUT -s 203.0.113.5/32 -p tcp -m comment --comment csf-ui-setup -m tcp --dport 8444 -j ACCEPT';
		my @rules;
		my $runner = FakeRunner->new
			->on(qr{is-active firewalld}, { exit => 3, output => "inactive\n" })
			->on(qr{^/sbin/iptables --version\z}, { output => "iptables v1.8.7 (nf_tables)\n" })
			->on(qr{ -I INPUT 1 }, sub { push @rules, $RENDERED; return { exit => 0, output => '' } })
			->on(qr{ -S INPUT\z}, sub {
				return { exit => 0, output => join("\n", '-P INPUT ACCEPT', @rules) . "\n" };
			});
		my $firewall = firewall_for($runner, iptables => '/sbin/iptables');
		my $setup = $S->new(firewall => $firewall, rollback => $w->{rollback},
			state_dir => "$w->{root}/state", token => 't');

		$setup->save_state({ kind => 'iptables', binary => '/sbin/iptables', chain => 'INPUT',
			port => 8444, address => '203.0.113.5', canonical => $RENDERED },
			owner => { pid => $child, started => $stat->{started}, created => time() });

		my $out = $setup->reassert_temporary_port;
		is($out->{ok}, 0, 'a record owned by a zombie is NOT acted on');
		like($out->{reason}, qr/waiting to be reaped/, 'and says the session it belonged to is over');
		is($runner->ran(qr{ -I INPUT 1 }), 0,
			'AND NO PORT WAS RE-OPENED - the hole R71 closed stays closed');

		waitpid($child, 0);
	}
}

###############################################################################
# Message quality: text that asserts no more than the code established, and
# advice for every refusal rather than only the first one that got written.
###############################################################################
{
	# E_EXEC blocks the SHELL path exactly as it blocks the browser path, so
	# "apply from a shell instead" is not advice to somebody who already is.
	# A refusal that leaves the operator nowhere to go is one they work
	# around, and the way around this one is applying with no rollback.
	my $w = world(systemd => 1, setup_bin => "$FindBin::Bin/../no-such-binary");
	my $setup = setup_for($w);
	my ($answer) = $S->can('parse_answers')->(qq{TCP_IN="22,443"\n});
	my $result = $setup->apply(answers => $answer);

	is($result->{code}, 'E_EXEC', 'an unexecutable rollback binary stops the apply');
	like($result->{reason}, qr/installation fault/,
		'and the operator is told what kind of problem it is');
	like($result->{reason}, qr/0750 root:csfui/, 'with the mode and owner to restore');
	unlike($result->{reason}, qr/Apply from a shell you can watch instead/,
		'and NOT advice that is useless to the shell operator who just hit this');
	like($result->{reason}, qr/nothing will undo a mistake for you/,
		'though they are still told what applying without a rollback means');
}
{
	my $w = world(systemd => 0);
	my $setup = setup_for($w);
	my ($answer) = $S->can('parse_answers')->(qq{TCP_IN="22,443"\n});
	my $result = $setup->apply(answers => $answer);
	is($result->{code}, 'E_NO_SYSTEMD', 'the systemd refusal still has its own advice');
	like($result->{reason}, qr/Apply from a shell you can watch instead/, 'which is this one');
}
{
	# R76's headline must be true in the case that branch is actually
	# reached: _remove_units unlinks TWO files and either can fail on its
	# own, and armed() is true only when BOTH are present - so this branch
	# is also reached with one unit file still sitting on disk.
	my $w = world(systemd => 1);
	my $setup = setup_for($w);
	my $snap = $w->{rollback}->snapshot;
	$w->{rollback}->arm($snap->{dir});
	$w->{runner}->on(qr{systemctl (?:stop|disable|daemon-reload)}, { exit => 1, output => "Failed.\n" });
	unlink "$w->{root}/units/csf-ui-rollback.timer";   # half-removed by hand

	my ($headline, $detail, $needs_action) = $setup->confirm_outcome($setup->confirm);
	is($needs_action, 1, 'a half-removal that did not go cleanly needs action');
	unlike($headline, qr/unit files are gone/,
		'and the headline does NOT claim the files are gone - one of them may still be there');
	like($detail, qr/rm -f /, 'the advice includes the rm -f a half-removal needs');
	like($detail, qr/systemctl daemon-reload/, 'and the reload that makes systemd forget it');
}
{
	# Both failure branches hand out the same complete sequence.
	my $w = world(systemd => 1);
	my $setup = setup_for($w);
	my $snap = $w->{rollback}->snapshot;
	$w->{rollback}->arm($snap->{dir});
	$w->{runner}->on(qr{systemctl stop}, { exit => 1, output => "Failed.\n" });
	chmod 0500, "$w->{root}/units";
	my (undef, $armed_detail) = $setup->confirm_outcome($setup->confirm);
	chmod 0755, "$w->{root}/units";
	SKIP: {
		skip 'running as root, where a read-only directory is no obstacle', 3 if $> == 0;
		like($armed_detail, qr/systemctl stop csf-ui-rollback\.timer/, 'stop');
		like($armed_detail, qr/rm -f .*csf-ui-rollback\.timer .*csf-ui-rollback\.service/, 'both unit files');
		like($armed_detail, qr/systemctl daemon-reload/, 'and the reload');
	}
}

###############################################################################
# R71: A STALE RECORD MUST NOT RE-OPEN A FIREWALL PORT.
#
# A leftover session.state would otherwise make a later shell
# csf-ui-setup --answers FILE --yes open a port inside a process that has no
# END block for it and exits seconds later - a hole nothing on the system
# will ever close, reached by a leftover file. Which is the exact outcome
# this whole task exists to prevent.
###############################################################################
{
	my $w = world(systemd => 1);
	my $runner = FakeRunner->new
		->on(qr{is-active firewalld}, { exit => 3, output => "inactive\n" })
		->on(qr{^/sbin/iptables --version\z}, { output => "iptables v1.8.7 (nf_tables)\n" })
		->on(qr{ -I INPUT 1 }, { exit => 0, output => '' })
		->on(qr{ -S INPUT\z}, { output => "-P INPUT ACCEPT\n" });   # flushed: our rule is gone
	my $firewall = firewall_for($runner, iptables => '/sbin/iptables');
	my $setup = $S->new(firewall => $firewall, rollback => $w->{rollback},
		state_dir => "$w->{root}/state", token => 't');

	my %rule = (kind => 'iptables', binary => '/sbin/iptables', chain => 'INPUT',
		port => 8444, address => '203.0.113.5',
		canonical => '-A INPUT -s 203.0.113.5/32 -j ACCEPT');

	# A record whose owning process is long gone. pid 2 is the kernel's
	# kthreadd on Linux and is certainly not a csf-ui-setup, so the
	# start-time check catches it even where the pid is alive.
	$setup->save_state(\%rule, owner => { pid => 999999, started => '12345', created => time() });
	my $stale = $setup->reassert_temporary_port;
	is($stale->{ok}, 0, 'a record from a dead session is not acted on');
	is($stale->{stale}, 1, 'and is marked stale rather than failed');
	like($stale->{reason}, qr/no longer running/, 'saying why');
	like($stale->{reason}, qr/--cleanup/, 'and pointing at the command that does clear it');
	is($runner->ran(qr{ -I INPUT 1 }), 0,
		'AND NOT ONE RULE WAS ADDED - a leftover file must never open a port');
}
{
	my $w = world(systemd => 1);
	my $runner = FakeRunner->new
		->on(qr{is-active firewalld}, { exit => 3, output => "inactive\n" })
		->on(qr{^/sbin/iptables --version\z}, { output => "iptables v1.8.7 (nf_tables)\n" })
		->on(qr{ -I INPUT 1 }, { exit => 0, output => '' })
		->on(qr{ -S INPUT\z}, { output => "-P INPUT ACCEPT\n" });
	my $clock = 1_757_548_800;
	# Stateful, so that a rule this test puts back can actually be read
	# back - otherwise the re-assertion fails on E_READBACK and the test
	# would "pass" its refusal for entirely the wrong reason.
	my @rules;
	my $RENDERED = '-A INPUT -s 203.0.113.5/32 -p tcp -m comment --comment csf-ui-setup -m tcp --dport 8444 -j ACCEPT';
	$runner->{rules}[2][1] = sub { push @rules, $RENDERED; return { exit => 0, output => '' } };
	$runner->{rules}[3][1] = sub {
		return { exit => 0, output => join("\n", '-P INPUT ACCEPT', @rules) . "\n" };
	};
	my $firewall = firewall_for($runner, iptables => '/sbin/iptables');
	my $setup = $S->new(firewall => $firewall, rollback => $w->{rollback},
		state_dir => "$w->{root}/state", token => 't', now => sub { $clock });

	my %rule = (kind => 'iptables', binary => '/sbin/iptables', chain => 'INPUT',
		port => 8444, address => '203.0.113.5', canonical => $RENDERED);

	# Owned by THIS process, which is certainly alive.
	$setup->save_state(\%rule);

	my $fresh = $setup->reassert_temporary_port;
	is($fresh->{ok}, 1, 'a live, fresh record IS acted on - this gate only ever refuses');
	is($fresh->{restored}, 1, 'the flushed rule was put back');

	# R74: A CONFIRMED LIVE OWNER OUTRANKS AN EXPIRED CLOCK.
	#
	# This is the operator who pressed Apply at second 1790 of their 1800
	# second session. The apply forks, snapshots, arms, writes two files and
	# runs csf -r - and by the time the re-assertion runs the RECORD is past
	# 1800 seconds old while the wizard that owns it is alive, in waitpid,
	# waiting for this very process. Refusing there closes their route back
	# in, silently, and tells them a running session is not running.
	SKIP: {
		skip 'no /proc, so the owner\'s identity cannot be confirmed here', 4
			unless -r "/proc/$$/stat";
		@rules = ();
		$clock += 1801;
		my $late = $setup->reassert_temporary_port;
		is($late->{ok}, 1,
			'an expired CLOCK does not disqualify a record whose owner is confirmed alive');
		is($late->{restored}, 1, 'the operator gets their route back');
		is($late->{stale}, undef, 'and is never told their live session is stale');

		# And the principle, not just the scenario: a confirmed live owner
		# outranks the clock at ANY age. Past the grace allowance too -
		# which is what makes this test bind to the identity branch rather
		# than to the grace happening to be wide enough.
		@rules = ();
		$clock += 5000;
		my $ancient = $setup->reassert_temporary_port;
		is($ancient->{ok}, 1,
			'a record of any age is live while its owner is confirmed to be the process that made it');
		$clock -= 5000;
		$clock -= 1801;
	}
}
{
	# The age cap still exists - it is the reuse guard for a platform where
	# identity CANNOT be confirmed, which is the only place it now applies.
	my $w = world(systemd => 1);
	my $runner = FakeRunner->new
		->on(qr{is-active firewalld}, { exit => 3, output => "inactive\n" })
		->on(qr{^/sbin/iptables --version\z}, { output => "iptables v1.8.7 (nf_tables)\n" })
		->on(qr{ -I INPUT 1 }, { exit => 0, output => '' })
		->on(qr{ -S INPUT\z}, { output => "-P INPUT ACCEPT\n" });
	my $clock = 1_757_548_800;
	# Stateful, so a rule put back can be read back - otherwise the last
	# assertion below would fail on E_READBACK and look like a refusal.
	my $RENDERED = '-A INPUT -s 203.0.113.5/32 -p tcp -m comment --comment csf-ui-setup -m tcp --dport 8444 -j ACCEPT';
	my @rules;
	$runner->{rules}[2][1] = sub { push @rules, $RENDERED; return { exit => 0, output => '' } };
	$runner->{rules}[3][1] = sub {
		return { exit => 0, output => join("\n", '-P INPUT ACCEPT', @rules) . "\n" };
	};
	my $firewall = firewall_for($runner, iptables => '/sbin/iptables');
	my $setup = $S->new(firewall => $firewall, rollback => $w->{rollback},
		state_dir => "$w->{root}/state", token => 't', now => sub { $clock });
	ConfigServer::UI::Rollback::make_path("$w->{root}/state", mode => 0700);

	my $body = qq{KIND="iptables"\nBINARY="/sbin/iptables"\nCHAIN="INPUT"\nPORT="8444"\nADDRESS="203.0.113.5"\nCANONICAL="$RENDERED"\nPID="$$"\n};

	# No STARTED field: identity unconfirmable, so the clock is all there is.
	spew($setup->state_path, $body . qq{CREATED="$clock"\n});
	$clock += 1800 + 600 + 1;
	my $too_old = $setup->reassert_temporary_port;
	is($too_old->{ok}, 0,
		'without a confirmable identity, a record past the session lifetime PLUS the apply grace is refused');
	like($too_old->{reason}, qr/cannot confirm/, 'and says that is why the clock had to decide it');
	is($runner->ran(qr{ -I INPUT 1 }), 0, 'nothing was opened');

	# Inside the grace: the late-apply operator is served even here.
	$clock -= 601;
	my $late = $setup->reassert_temporary_port;
	is($late->{ok}, 1, 'and inside the grace the same record is still acted on');
}
{
	# A record written before this check existed carries no owner at all.
	my $w = world(systemd => 1);
	my $runner = FakeRunner->new->on(qr{ -S INPUT\z}, { output => "-P INPUT ACCEPT\n" });
	my $firewall = firewall_for($runner, iptables => '/sbin/iptables');
	my $setup = $S->new(firewall => $firewall, rollback => $w->{rollback},
		state_dir => "$w->{root}/state", token => 't');
	ConfigServer::UI::Rollback::make_path("$w->{root}/state", mode => 0700);
	my $body = qq{KIND="iptables"\nBINARY="/sbin/iptables"\nCHAIN="INPUT"\nPORT="8444"\nADDRESS="203.0.113.5"\nCANONICAL="-A INPUT -s 203.0.113.5/32 -j ACCEPT"\n};

	# The two halves of an owner are checked SEPARATELY. A single test that
	# accepted either message would pass with one of the two checks deleted,
	# which is the shape of test this project keeps finding.
	spew($setup->state_path, $body);
	my $no_owner = $setup->reassert_temporary_port;
	is($no_owner->{ok}, 0, 'a record naming no process is refused, not trusted');
	like($no_owner->{reason}, qr/names no owning process/, 'and says it is the process that is missing');

	spew($setup->state_path, $body . qq{PID="$$"\n});
	my $no_time = $setup->reassert_temporary_port;
	is($no_time->{ok}, 0, 'a record with a live pid but no creation time is refused too');
	like($no_time->{reason}, qr/carries no creation time/, 'and says it is the time that is missing');

	is($runner->ran(qr{ -I INPUT 1 }), 0, 'and neither opened anything');

	# PID REUSE, which kill(0) alone cannot see: the number is alive - it is
	# this very test - but it is not the process that wrote the record.
	SKIP: {
		skip 'no /proc on this platform, so start times cannot be compared', 3
			unless -r "/proc/$$/stat";
		spew($setup->state_path, $body . qq{PID="$$"\nSTARTED="1"\nCREATED="} . time() . qq{"\n});
		my $reused = $setup->reassert_temporary_port;
		is($reused->{ok}, 0, 'a live pid that is not the process that made the record is refused');
		like($reused->{reason}, qr/the number has been reused/, 'saying exactly that');
		is($runner->ran(qr{ -I INPUT 1 }), 0, 'and opens nothing');
	}
}
{
	# --cleanup does NOT apply the liveness gate: acting on leftovers is its
	# entire job, and a stale record is the only route to a stale rule.
	my $w = world();
	my $runner = FakeRunner->new
		->on(qr{ -S INPUT\z}, { output => "-P INPUT ACCEPT\n-A INPUT -s 203.0.113.5/32 -j ACCEPT\n" })
		->on(qr{ -D INPUT }, { exit => 0, output => '' });
	my $deleted = 0;
	$runner->{rules}[0][1] = sub { return { exit => 0, output => $deleted
		? "-P INPUT ACCEPT\n" : "-P INPUT ACCEPT\n-A INPUT -s 203.0.113.5/32 -j ACCEPT\n" } };
	$runner->{rules}[1][1] = sub { $deleted = 1; return { exit => 0, output => '' } };
	my $firewall = firewall_for($runner, iptables => '/sbin/iptables');
	my $setup = $S->new(firewall => $firewall, rollback => $w->{rollback},
		state_dir => "$w->{root}/state", token => 't');
	$setup->save_state({ kind => 'iptables', binary => '/sbin/iptables', chain => 'INPUT',
		canonical => '-A INPUT -s 203.0.113.5/32 -j ACCEPT' },
		owner => { pid => 999999, started => '12345', created => 1 });

	my $done = $setup->cleanup;
	like(join("\n", @$done), qr/temporary firewall rule was removed/,
		'cleanup closes a STALE record\'s port - that is what it is for');
	ok(!-e $setup->state_path, 'and clears the record');
}
{
	# _proc_stat, on this very process: the check has to actually work, not
	# merely be called.
	my $mine = ConfigServer::UI::Setup::_proc_stat($$);
	SKIP: {
		skip 'no /proc on this platform', 4 unless -r "/proc/$$/stat";
		like($mine->{started}, qr/^[0-9]+\z/, 'a start time is read for a live process');
		like($mine->{state}, qr/^[A-Za-z]\z/, 'and its state');
		is_deeply(ConfigServer::UI::Setup::_proc_stat(999999), {},
			'and nothing for a pid that is not there');
		is_deeply(ConfigServer::UI::Setup::_proc_stat('not-a-pid'), {}, 'or for a non-pid');
	}
}

###############################################################################
# THE LISTEN PLAN - the decision that stops the temporary port being either a
# hole that leads nowhere or a cleartext listener on a public address.
###############################################################################
{
	my $w = world();
	my $setup = setup_for($w);

	my $none = $setup->listen_plan(undef);
	is($none->{bind}, '127.0.0.1', 'with no offer, the wizard binds loopback');
	is($none->{tls}, 0, 'and speaks plain HTTP, because the SSH tunnel is the encryption');
	is($none->{peer}, undef, 'with no peer restriction of its own - loopback is the restriction');
	is($none->{tunnel}, 1, 'and the ssh -L instructions are what gets printed');

	for my $declined ({ ok => 0, code => 'E_NO_TLS' }, { ok => 1 }, undef, 'nonsense') {
		my $plan = $setup->listen_plan($declined);
		is($plan->{bind}, '127.0.0.1', 'anything short of an accepted offer with a spec stays on loopback');
	}

	my $v4 = $setup->listen_plan({ ok => 1, spec => { address => '203.0.113.5' } });
	is($v4->{bind}, '0.0.0.0', 'an accepted offer binds where the rule actually leads...');
	is($v4->{tls}, 1, '...and ONLY over TLS - the condition offer_port() imposed is not undone here');
	is($v4->{peer}, '203.0.113.5',
		'and the listener itself will talk to that one address, independently of the firewall rule');
	is($v4->{tunnel}, 0, 'so the tunnel instructions are not what gets printed');

	my $v6 = $setup->listen_plan({ ok => 1, spec => { address => '2001:db8::5' } });
	is($v6->{bind}, '::', 'an IPv6 operator gets an IPv6 listener');

	# The inner wall.
	is($setup->peer_allowed(undef, '198.51.100.1'), 1, 'no restriction means anyone (the loopback case)');
	is($setup->peer_allowed('203.0.113.5', '203.0.113.5'), 1, 'the permitted peer is allowed');
	is($setup->peer_allowed('203.0.113.5', '198.51.100.1'), 0, 'and nobody else is');
	is($setup->peer_allowed('203.0.113.5', undef), 0, 'a peer that could not be read is refused, not waved through');
	is($setup->peer_allowed('203.0.113.5', ''), 0, 'and so is an empty one');
	is($setup->peer_allowed('2001:DB8::5', '2001:db8::5'), 1, 'IPv6 comparison is case-insensitive');
}

###############################################################################
# The listener's stopping policy. serve()'s loop itself needs a real socket
# and is untested by design (the same precedent Server.pm's run() and
# csf-ui-helper's main() already set), so the policy it runs on is a plain
# function instead - because BOTH lifetimes ending the process, not merely
# the session, is what stops a dead wizard from leaving a port bound and a
# firewall rule installed.
###############################################################################
{
	my $w = world();
	my $setup = setup_for($w);
	my $start = 1_000_000;
	my $deadline = $start + 1800;

	is($setup->stop_reason($start + 10, $deadline, $start), undef, 'a fresh, busy session keeps serving');
	like($setup->stop_reason($start + 601, $deadline, $start), qr/10 minutes/,
		'ten minutes with no request stops the PROCESS, not just the session');
	is($setup->stop_reason($start + 599, $deadline, $start + 1), undef,
		'and a request inside that window keeps it alive');
	like($setup->stop_reason($start + 1800, $deadline, $start + 1799), qr/30-minute/,
		'thirty minutes stops it however busy it has been');
	$setup->{confirmed} = 1;
	like($setup->stop_reason($start, $deadline, $start), qr/operator confirmed/,
		'and confirming stops it at once, without waiting for either clock');
}

###############################################################################
# THE TEMPORARY PORT, FROM THE WIZARD'S SIDE.
###############################################################################
{
	# The backend here is one this code WOULD open a port on, and the
	# operator address is a good one - so the only thing standing between
	# this call and an open port is the TLS condition. Anything less would
	# be a test that passes because something else refused.
	my $w = world(systemd => 1);
	my $runner = FakeRunner->new
		->on(qr{^/sbin/iptables --version\z}, { output => "iptables v1.8.7 (nf_tables)\n" })
		->on(qr{ -I INPUT 1 }, { exit => 0, output => '' })
		->on(qr{ -S INPUT\z}, { output =>
			"-P INPUT ACCEPT\n-A INPUT -s 203.0.113.5/32 -p tcp -m comment --comment csf-ui-setup -m tcp --dport 8444 -j ACCEPT\n" });
	my $firewall = firewall_for($runner, iptables => '/sbin/iptables');
	my $openable = $S->new(firewall => $firewall, rollback => $w->{rollback},
		state_dir => "$w->{root}/state", token => 't', tls_available => sub { 0 });

	my $offer = $openable->offer_port(address => '203.0.113.5');
	is($offer->{ok}, 0, 'with no TLS material the temporary port is declined - on a backend it could otherwise open');
	is($offer->{code}, 'E_NO_TLS', 'with its own code');
	like($offer->{reason}, qr/cleartext/, 'saying the traffic would be in the clear');
	like($offer->{reason}, qr/SSH tunnel/, 'and pointing at the tunnel that is already encrypted');
	is($runner->ran(qr/iptables/), 0,
		'and not one firewall command was run to find that out');

	# Proof the refusal above is the TLS condition and nothing else: with
	# TLS material present, this exact fixture DOES open the port.
	my $with_tls = $S->new(firewall => $firewall, rollback => $w->{rollback},
		state_dir => "$w->{root}/state", token => 't', tls_available => sub { 1 });
	is($with_tls->offer_port(address => '203.0.113.5')->{ok}, 1,
		'with TLS material present the same call opens the port');
}
{
	my $w = world(systemd => 1);
	my $runner = FakeRunner->new
		->on(qr{^/sbin/iptables --version\z}, { output => "iptables v1.8.7 (nf_tables)\n" })
		->on(qr{ -S INPUT\z}, { output => "-P INPUT ACCEPT\n" });
	my $firewall = firewall_for($runner, iptables => '/sbin/iptables');
	my $setup = $S->new(firewall => $firewall, rollback => $w->{rollback},
		state_dir => "$w->{root}/state", token => 't', tls_available => sub { 1 });
	my $offer = $setup->offer_port(address => undef);
	is($offer->{ok}, 0, 'with TLS but no operator address, the port is still declined');
	is($offer->{code}, 'E_ADDRESS', 'by Firewall.pm\'s own gate, not a second copy of it here');
}
{
	# $SSH_CLIENT is read, never trusted - whatever it holds goes through the
	# same single-host validation.
	my $w = world();
	my $setup = setup_for($w);
	is($setup->operator_address({ SSH_CLIENT => '203.0.113.9 55231 22' }), '203.0.113.9',
		'the operator address comes out of SSH_CLIENT');
	is($setup->operator_address({ SSH_CONNECTION => '2001:db8::9 55231 2001:db8::1 22' }), '2001:db8::9',
		'or SSH_CONNECTION');
	is($setup->operator_address({}), undef, 'a session that is not over SSH has no operator address');
	is($setup->operator_address({ SSH_CLIENT => 'nonsense here' }), undef,
		'and a value that is not an address is not one');
}

###############################################################################
# THE STATE FILE - what makes --cleanup able to close a port a dead session
# left open.
###############################################################################
{
	my $w = world();
	my $runner = FakeRunner->new
		->on(qr{ -S INPUT\z}, { output =>
			"-P INPUT ACCEPT\n-A INPUT -s 203.0.113.5/32 -p tcp -m comment --comment csf-ui-setup -m tcp --dport 8444 -j ACCEPT\n" })
		->on(qr{ -D INPUT }, { exit => 0, output => '' });
	# After the delete, the listing no longer shows it.
	my $deleted = 0;
	$runner->{rules}[0][1] = sub { return { exit => 0, output => $deleted
		? "-P INPUT ACCEPT\n"
		: "-P INPUT ACCEPT\n-A INPUT -s 203.0.113.5/32 -p tcp -m comment --comment csf-ui-setup -m tcp --dport 8444 -j ACCEPT\n" } };
	$runner->{rules}[1][1] = sub { $deleted = 1; return { exit => 0, output => '' } };

	my $firewall = firewall_for($runner, iptables => '/sbin/iptables');
	my $setup = $S->new(firewall => $firewall, rollback => $w->{rollback},
		state_dir => "$w->{root}/state", token => 't');

	my $spec = {
		backend => 'iptables-nft', kind => 'iptables', binary => '/sbin/iptables',
		wait => ['-w', '5'], chain => 'INPUT', port => 8444, address => '203.0.113.5', family => 4,
		canonical => '-A INPUT -s 203.0.113.5/32 -p tcp -m comment --comment csf-ui-setup -m tcp --dport 8444 -j ACCEPT',
	};
	my $saved = $setup->save_state($spec);
	is($saved->{ok}, 1, 'the rule specification is written to a state file');
	is(sprintf('%04o', (stat($setup->state_path))[2] & 07777), '0600', 'readable only by root');

	my $loaded = $setup->load_state;
	is($loaded->{canonical}, $spec->{canonical}, 'and reads back with the canonical text intact');
	is_deeply($loaded->{wait}, ['-w', '5'], 'and the wait arguments');

	my $done = $setup->cleanup;
	like(join("\n", @$done), qr/temporary firewall rule was removed/, 'cleanup closes the port');
	ok(!-e $setup->state_path, 'and removes the state file once the port is confirmed shut');

	is($setup->load_state, undef, 'a second cleanup finds nothing to do');
	my $again = $setup->cleanup;
	is(ref($again), 'ARRAY', 'and does not die');
}
{
	# A port that CANNOT be closed keeps its record, so a later --cleanup can
	# try again. Deleting the record would be deleting the only thing that
	# knows a hole is open.
	my $w = world();
	my $runner = FakeRunner->new
		->on(qr{ -S INPUT\z}, { exit => 1, output => "cannot read\n" });
	my $firewall = firewall_for($runner, iptables => '/sbin/iptables');
	my $setup = $S->new(firewall => $firewall, rollback => $w->{rollback},
		state_dir => "$w->{root}/state", token => 't');
	$setup->save_state({ kind => 'iptables', binary => '/sbin/iptables', chain => 'INPUT',
		canonical => '-A INPUT -s 203.0.113.5/32 -j ACCEPT' });

	my $done = $setup->cleanup;
	like(join("\n", @$done), qr/could NOT be removed/, 'a failure to close is reported loudly');
	ok(-e $setup->state_path, 'and the record is KEPT so this can be retried');
}

###############################################################################
# The source itself: no URL anywhere in this program carries a secret.
###############################################################################
{
	open(my $fh, '<', $SETUP_PATH) or die "cannot read $SETUP_PATH: $!";
	local $/;
	my $source = <$fh>;
	close $fh;

	unlike($source, qr/[?&]token=/, 'no URL in the source carries a token');
	unlike($source, qr/[?&](?:sid|session|csrf)=/, 'nor a session id or CSRF token');
	unlike($source, qr/Location['"]?\s*,\s*['"][^'"]*\?/, 'no redirect is built with a query string');
	like($source, qr/refuses any request carrying ANY query string/,
		'and the reasoning is written down where the next person will read it');
}
