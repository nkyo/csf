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
use Test::More tests => 272;

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

	my $rollback = ConfigServer::UI::Rollback->new(
		dir            => "$root/rollback",
		unit_dir       => "$root/units",
		csf_conf       => "$root/etc/csf.conf",
		ui_conf        => "$root/etc/ui.conf",
		setup_bin      => '/usr/local/csf-ui/bin/csf-ui-setup',
		systemd_marker => "$root/run-systemd",
		firewall       => $firewall,
		(defined $opt{window} ? (window => $opt{window}) : ()),
	);
	return { root => $root, runner => $runner, firewall => $firewall, rollback => $rollback };
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
	my $w = world(systemd => 1);
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
	like($csf, qr/^TESTING_INTERVAL = "300"$/m, 'and TESTING_INTERVAL is forced to 300');
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
