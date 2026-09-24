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
# The independent rollback (docs/WEBUI-PLAN.md S6, task-8-brief.md).
#
# WHY THIS EXISTS WHEN csf ALREADY HAS TESTING.
#
# csf's own TESTING=1 / TESTING_INTERVAL is a cron job csf installs that runs
# csf -f - flush every rule - unless TESTING is turned off in time. It is
# genuinely good and the wizard always turns it on. It is also not enough on
# its own, for two reasons that have nothing to do with how well it is
# written:
#
#   1. It assumes csf's OWN timer is still running. The configurations most
#      likely to lock an operator out are the configurations most likely to
#      stop lfd, break the cron environment, or leave csf unable to start -
#      and csf's safety net is hung from the same hook as the thing that
#      fell. A net that is only present when the failure is mild is not a
#      net.
#   2. What it does on expiry is FLUSH, which is not the same as RESTORE. A
#      flush removes every rule in the table, including rules csf never
#      created - a Docker or Kubernetes NAT chain, a hand-written rule from
#      the hosting provider's build, another tool's ruleset. The operator
#      gets their SSH back and loses something else, silently.
#
# So this module adds a second, independent net: a systemd timer that belongs
# to neither csf nor lfd, that fires after a fixed window, and that RESTORES
# the exact configuration and ruleset that were in place before the wizard
# touched anything. Confirming cancels it. The two nets fail independently,
# which is the only property that makes a second one worth having.
#
# WHAT "INDEPENDENT" MEANS IN THE UNIT FILE, CONCRETELY. The units written
# here name no csf or lfd unit in any dependency directive - no After=,
# Requires=, PartOf=, BindsTo=, WantedBy= pointing at csf.service or
# lfd.service. If the rollback were ordered after csf.service, then csf
# failing to start would stop the rollback from running, which is precisely
# the case the rollback exists for. t/71-rollback.t asserts this about the
# generated text rather than trusting this paragraph.
#
# WHY THE TIMER IS ENABLED, NOT JUST STARTED. A transient OnActiveSec=
# timer dies with the reboot. "Reboot mid-apply" is one of the named test
# cases in the plan (S9), and it is a realistic one: a configuration that
# breaks the network is a configuration somebody power-cycles the machine
# over. So the unit carries an [Install] section and OnBootSec= as well,
# is enabled, and therefore still fires on the way back up. confirm()
# disables and deletes it, and the restore path disarms itself the moment it
# has run, so neither leaves anything behind to fire twice.
#
# ON A HOST WITHOUT systemd, THIS REFUSES. It does not fall back to cron, to
# at, or to a forked background process that sleeps. A forked sleeper dies
# with the session (which is exactly the event the rollback is for); cron's
# minimum granularity and environment are not something to discover during a
# lockout; and at is frequently not installed. An approximation of this
# net is worse than no net, because the operator would be told they had one.
# arm() returns a refusal naming the reason, and ui-src/bin/csf-ui-setup
# refuses to apply rather than applying without it.
###############################################################################
package ConfigServer::UI::Rollback;

use strict;
use warnings;

use Fcntl qw(:DEFAULT);
use IO::Handle ();
use POSIX ();
use Time::HiRes ();

our $VERSION = '1.00';

our $DEFAULT_DIR       = '/var/lib/csf-ui/rollback';
our $DEFAULT_UNIT_DIR  = '/etc/systemd/system';
our $DEFAULT_CSF_CONF  = '/etc/csf/csf.conf';
our $DEFAULT_UI_CONF   = '/etc/csf-ui/ui.conf';
our $DEFAULT_SETUP_BIN = '/usr/local/csf-ui/bin/csf-ui-setup';

# The systemd marker directory. Its presence is what distinguishes "systemd
# is the init on this running system" from "the systemctl binary happens to
# be installed", which is true inside plenty of containers where nothing
# will ever run a timer.
our $SYSTEMD_MARKER = '/run/systemd/system';

# docs/WEBUI-RPC.md section 2.3: /etc/csf-ui/ui.conf is 0640 root:csfui.
our $UI_CONF_GROUP = 'csfui';

our $SERVICE_UNIT = 'csf-ui-rollback.service';
our $TIMER_UNIT   = 'csf-ui-rollback.timer';

# The confirmation window, in SECONDS, because that is what systemd's
# OnActiveSec= takes. 300 seconds is five minutes, the same DURATION the
# wizard writes to csf's own TESTING_INTERVAL - deliberately, so an operator
# watching the clock has one number to watch and not two. Long enough to
# notice SSH still works and click a button; short enough that a locked-out
# operator is not sitting in front of a dead machine for a quarter of an hour.
#
# "the same FIGURE" is what this said, and the wizard was writing 300 into
# TESTING_INTERVAL to make the two literals match. They are not the same
# unit: TESTING_INTERVAL is MINUTES (csf.pl renders it into the minute field
# of a line in /etc/crontab), so the two settings were five minutes and five
# HOURS apart, and the sentence claiming they agreed is what made that look
# deliberate. The wizard now writes 5 there. See $FORCED_TESTING_INTERVAL in
# ui-src/bin/csf-ui-setup for what a step of 300 in a cron minute field was
# measured to do.
our $DEFAULT_WINDOW = 300;

# systemd's own comment character is '#', and '%' introduces a specifier it
# expands. A newline ends a directive. None of these may appear in a value
# this module interpolates into a unit file: a path containing one would
# either be silently truncated or turned into something else entirely, and
# the unit would then run a different command from the one intended. See
# _unit_safe_path().
my $UNIT_UNSAFE = qr/[\n\r%]/;

###############################################################################
# Construction. Every path and every external command is an injection seam,
# for the same reason ConfigServer::UI::Firewall's are: t/71-rollback.t must
# prove the timer is written, the units are removed, and the atomic commit
# refuses an invalid file, WITHOUT root, without systemd and without
# touching /etc (G1).
###############################################################################
sub new {
	my ($class, %opt) = @_;
	return bless {
		dir       => $opt{dir}       || $DEFAULT_DIR,
		unit_dir  => $opt{unit_dir}  || $DEFAULT_UNIT_DIR,
		csf_conf  => $opt{csf_conf}  || $DEFAULT_CSF_CONF,
		ui_conf   => $opt{ui_conf}   || $DEFAULT_UI_CONF,
		setup_bin => $opt{setup_bin} || $DEFAULT_SETUP_BIN,
		window    => defined $opt{window} ? $opt{window} : $DEFAULT_WINDOW,
		firewall  => $opt{firewall},        # a ConfigServer::UI::Firewall, for run()/locate()
		# chown and the group lookup are injection seams for the same reason
		# the runner is: t/71-rollback.t runs as an ordinary user, where a
		# real chown to root:csfui would fail and a real getgrnam('csfui')
		# would find nothing - and the OWNERSHIP of ui.conf is exactly what
		# has to be asserted as a value rather than inferred from whether
		# something downstream happened to work.
		chown     => $opt{chown}   || sub { my ($uid, $gid, $path) = @_; return chown($uid, $gid, $path) },
		chmod     => $opt{chmod}   || sub { my ($mode, $path) = @_; return chmod($mode, $path) },
		gid_for   => $opt{gid_for} || \&_gid_for,
		systemd_marker => defined $opt{systemd_marker} ? $opt{systemd_marker} : $SYSTEMD_MARKER,
		now       => $opt{now} || sub { time() },
	}, $class;
}

sub _run {
	my ($self, @argv) = @_;
	return { error => 'no firewall runner was supplied', exit => -1, output => '' }
		unless $self->{firewall};
	return $self->{firewall}->run(@argv);
}

sub _locate {
	my ($self, $name) = @_;
	return undef unless $self->{firewall};
	return $self->{firewall}->locate($name);
}

sub _ran_ok {
	my ($result) = @_;
	return 0 unless ref($result) eq 'HASH';
	return 0 if $result->{error} || $result->{timeout} || $result->{signal};
	return (defined $result->{exit} && $result->{exit} == 0) ? 1 : 0;
}

###############################################################################
# THE ATOMIC COMMIT
#
# write_atomic($path, $content, validate => \&check, mode => 0600)
#   -> { ok => 1, path => $path } | { ok => 0, reason => ..., problems => [...] }
#
# Build in a temp file in the SAME DIRECTORY (rename is only atomic within a
# filesystem), flush it to disk, hand the finished temp file to the caller's
# validator, and only then rename over the target. A failed validation
# unlinks the temp file and leaves the original byte-for-byte untouched.
#
# The validator is handed the TEMP FILE'S PATH, not the content string, on
# purpose: the thing that must be proved good is the thing that is about to
# become the live file, read back off the disk by the same parser that will
# read it in production. Validating the string in memory proves the string
# was right, which is a different claim - it says nothing about a short
# write, a full filesystem, or an encoding layer someone adds later.
#
# The directory is fsync'd after the rename as well as the file before it.
# Without that, a crash can leave the rename itself unreached even though
# the new file's contents are safely on disk - and "csf.conf is now empty"
# is the single worst outcome available to this whole task.
###############################################################################
sub write_atomic {
	my ($self, $path, $content, %opt) = @_;

	return { ok => 0, reason => 'no path was given' }
		unless defined $path && length $path;
	return { ok => 0, reason => 'no content was given' }
		unless defined $content;

	my ($dir) = $path =~ m{^(.*)/[^/]+\z};
	$dir = '.' unless defined $dir && length $dir;

	my $temp = sprintf('%s/.csf-ui-setup.%d.%d.tmp', $dir, $$, int(Time::HiRes::time() * 1000) % 1000000);
	unlink $temp;

	my $mode = defined $opt{mode} ? $opt{mode} : 0600;
	sysopen(my $fh, $temp, O_WRONLY | O_CREAT | O_EXCL, $mode)
		or return { ok => 0, reason => "could not create the temporary file $temp: $!" };
	binmode($fh);

	my $written = syswrite($fh, $content);
	unless (defined $written && $written == length($content)) {
		my $why = defined $written ? "only $written of " . length($content) . ' bytes were written' : "write failed: $!";
		close $fh;
		unlink $temp;
		return { ok => 0, reason => "the temporary file was not written in full ($why)" };
	}
	# The file's own fsync. Its failure is recorded, not fatal: what it buys
	# is durability across a crash, and refusing to install a correct file
	# because the kernel would not promise it had hit the platter would be
	# trading a certain failure for an unlikely one.
	my $synced = eval { $fh->sync; 1 } ? 1 : 0;
	unless (close $fh) {
		unlink $temp;
		return { ok => 0, reason => "the temporary file could not be closed cleanly: $!" };
	}

	# chmod explicitly, AND CHECKED: sysopen's mode is masked by the process
	# umask, so a config file can end up 0644 because root's umask was 0022.
	# An unchecked chmod is how a file ships with permissions nobody chose -
	# and for ui.conf the permissions are frozen in docs/WEBUI-RPC.md S2.3,
	# which means they are a correctness property and not a preference.
	unless ($self->{chmod}->($mode, $temp) == 1) {
		my $why = "$!";
		unlink $temp;
		return { ok => 0, reason => sprintf('the new file could not be given mode %04o: %s', $mode, $why) };
	}

	# Ownership, before the rename, so the file is never visible at its real
	# path owned by the wrong group even for an instant. /etc/csf-ui/ui.conf
	# is 0640 root:csfui (S2.3): root writes it and the csfui the web tier
	# execs as READS it, so a file left root:root is a csf-ui that cannot
	# read its own configuration - and a startup gate run as root proves
	# nothing at all about that.
	if (defined $opt{group}) {
		my $gid = $self->{gid_for}->($opt{group});
		unless (defined $gid) {
			unlink $temp;
			return { ok => 0, reason => "there is no \"$opt{group}\" group on this system, so $path cannot be given the ownership docs/WEBUI-RPC.md section 2.3 freezes for it" };
		}
		unless ($self->{chown}->(0, $gid, $temp)) {
			my $why = "$!";
			unlink $temp;
			return { ok => 0, reason => "the new file could not be given root:$opt{group} ownership: $why" };
		}
	}

	if ($opt{validate}) {
		my ($ok, $problems) = eval { $opt{validate}->($temp) };
		if (my $error = $@) {
			unlink $temp;
			return { ok => 0, reason => "validation of the new file died: $error", problems => [] };
		}
		unless ($ok) {
			unlink $temp;
			return {
				ok       => 0,
				reason   => 'the new file did not validate, so the existing one was left untouched',
				problems => (ref($problems) eq 'ARRAY' ? $problems : []),
			};
		}
	}

	unless (rename($temp, $path)) {
		my $why = "$!";
		unlink $temp;
		return { ok => 0, reason => "the validated file could not be renamed into place: $why" };
	}

	# fsync the directory so the rename itself survives a crash. Recorded,
	# not fatal, for the same reason as the file's own fsync above: the
	# rename has already happened and the file is already correct.
	my $dir_synced = 0;
	if (opendir(my $dh, $dir)) {
		$dir_synced = eval { IO::Handle::sync($dh); 1 } ? 1 : 0;
		closedir $dh;
	}

	return { ok => 1, path => $path, synced => $synced, dir_synced => $dir_synced };
}

###############################################################################
# writable_probe($path) -> { ok => 1 } | { ok => 0, reason => ... }
#
# Proves that a file could be created, and renamed over, AT $path - before
# anything irreversible is done elsewhere. Not the same question as "is the
# content valid": a read-only /etc, a full filesystem or a directory this
# process cannot write are all foreseeable, and finding out about them after
# csf.conf has already been committed puts a predictable failure inside the
# one window this design cannot close (task-8-review.md C10).
#
# It creates and renames a real file, because the failure being ruled out is
# a failed create or a failed rename, and -w on the directory answers a
# weaker question than either.
###############################################################################
sub writable_probe {
	my ($self, $path) = @_;

	my ($dir) = $path =~ m{^(.*)/[^/]+\z};
	$dir = '.' unless defined $dir && length $dir;
	return { ok => 0, reason => "$dir is not a directory, so $path cannot be written" } unless -d $dir;

	my $probe  = sprintf('%s/.csf-ui-setup.probe.%d', $dir, $$);
	my $target = sprintf('%s/.csf-ui-setup.probe.%d.renamed', $dir, $$);
	unlink $probe, $target;

	my $fh;
	unless (sysopen($fh, $probe, O_WRONLY | O_CREAT | O_EXCL, 0600)) {
		return { ok => 0, reason => "$dir cannot be written to ($!), so $path could not be replaced" };
	}
	my $wrote = syswrite($fh, "probe\n");
	unless (defined $wrote) {
		my $why = "$!";
		close $fh;
		unlink $probe;
		return { ok => 0, reason => "$dir accepted a file but would not take its contents ($why)" };
	}
	# close on a WRITE handle is where a deferred write error surfaces - a
	# full filesystem most of all, which is one of the exact conditions this
	# probe exists to find. An unchecked close here would have the probe
	# report a directory usable when the first real write to it is about to
	# fail (task-8-review.md R72).
	unless (close $fh) {
		my $why = "$!";
		unlink $probe;
		return { ok => 0, reason => "$dir would not complete a write ($why), which is how a full filesystem shows itself" };
	}
	unless (rename($probe, $target)) {
		my $why = "$!";
		unlink $probe;
		return { ok => 0, reason => "a file in $dir could not be renamed ($why), which is how every write here is committed" };
	}
	unlink $target;
	return { ok => 1 };
}

###############################################################################
# THE SNAPSHOT
#
# snapshot() -> { ok => 1, id => ..., dir => ... } | { ok => 0, reason => ... }
#
# Copies the two configuration files and saves the live ruleset, before the
# wizard changes anything. Saving the ruleset is best effort and its absence
# is recorded rather than fatal: on a host where csf has never been started
# there may be nothing to save, and refusing to snapshot would then refuse
# the one case - first-ever setup - this wizard mostly exists for. What is
# NOT best effort is csf.conf: if the file that is about to be rewritten
# cannot be copied, there is no rollback and snapshot() says so.
###############################################################################
sub snapshot {
	my ($self, %opt) = @_;

	my $id = sprintf('%d-%d', $self->{now}->(), $$);
	my $dir = "$self->{dir}/$id";

	my $made = make_path($dir, mode => 0700, parent_mode => 0755);
	return { ok => 0, reason => "the snapshot directory $dir could not be created: $made" }
		if defined $made;

	my @saved;
	my @missing;

	for my $pair ([csf_conf => $self->{csf_conf}, 'csf.conf'],
	              [ui_conf  => $self->{ui_conf},  'ui.conf']) {
		my ($key, $source, $name) = @$pair;
		unless (-f $source) {
			push @missing, $name;
			next;
		}
		my $content = _slurp($source);
		unless (defined $content) {
			return { ok => 0, reason => "$source exists but could not be read, so there is nothing to roll back to" }
				if $key eq 'csf_conf';
			push @missing, $name;
			next;
		}
		my $write = $self->write_atomic("$dir/$name", $content, mode => 0600);
		return { ok => 0, reason => "the snapshot of $source could not be written: $write->{reason}" }
			unless $write->{ok};
		push @saved, $name;
	}

	return { ok => 0, reason => "$self->{csf_conf} is not present, so there is no known-good configuration to restore" }
		unless grep { $_ eq 'csf.conf' } @saved;

	# The live ruleset, per family. iptables-save writes to stdout, which is
	# what the runner captures - no shell redirection anywhere (G2).
	for my $pair ([4 => 'iptables-save', 'ruleset.v4'], [6 => 'ip6tables-save', 'ruleset.v6']) {
		my (undef, $tool, $name) = @$pair;
		my $binary = $self->_locate($tool) or next;
		my $result = $self->_run($binary);
		next unless _ran_ok($result);
		next unless length $result->{output};
		my $write = $self->write_atomic("$dir/$name", $result->{output}, mode => 0600);
		push @saved, $name if $write->{ok};
	}

	my $meta = join('', map { "$_->[0]=\"$_->[1]\"\n" } (
		[CREATED  => $self->{now}->()],
		[CSF_CONF => $self->{csf_conf}],
		[UI_CONF  => $self->{ui_conf}],
		[SAVED    => join(',', @saved)],
		[MISSING  => join(',', @missing)],
	));
	my $write = $self->write_atomic("$dir/meta", $meta, mode => 0600);
	return { ok => 0, reason => "the snapshot metadata could not be written: $write->{reason}" }
		unless $write->{ok};

	return { ok => 1, id => $id, dir => $dir, saved => \@saved, missing => \@missing };
}

sub read_meta {
	my ($self, $dir) = @_;
	my $text = _slurp("$dir/meta");
	return undef unless defined $text;
	my %meta;
	for my $line (split(/\n/, $text)) {
		next unless $line =~ /^\s*([A-Z][A-Z0-9_]*)\s*=\s*"([^"]*)"\s*\z/;
		$meta{$1} = $2;
	}
	return \%meta;
}

###############################################################################
# systemd availability. Two separate conditions, reported separately,
# because the two failures need different advice: "systemd is not the init
# here" means use the tunnel and apply from the CLI where you can watch it;
# "systemctl is missing" means something is broken about this install.
###############################################################################
sub systemd_available {
	my ($self) = @_;

	return (0, 'this host is not running systemd (' . $self->{systemd_marker} . ' is absent), so no independent rollback timer can be installed')
		unless -d $self->{systemd_marker};

	my $systemctl = $self->_locate('systemctl');
	return (0, 'systemd appears to be running but no systemctl binary was found, so no timer can be installed or cancelled')
		unless $systemctl;

	return (1, $systemctl);
}

###############################################################################
# UNIT TEXT
#
# unit_text($snapshot_dir) -> ($service_text, $timer_text) or (undef, $why)
#
# A pure function of its inputs, so t/71-rollback.t can read the generated
# text and assert on it directly rather than inferring it from a systemctl
# call that never happens in this workspace.
###############################################################################
sub _unit_safe_path {
	my ($path, $what) = @_;
	return "the $what is empty" unless defined $path && length $path;
	return "the $what ($path) is not an absolute path" unless $path =~ m{^/};
	return "the $what contains a character that would change the meaning of a systemd unit file"
		if $path =~ $UNIT_UNSAFE;
	return undef;
}

sub unit_text {
	my ($self, $snapshot_dir) = @_;

	for my $pair ([$snapshot_dir => 'snapshot directory'], [$self->{setup_bin} => 'setup binary path']) {
		my ($value, $what) = @$pair;
		if (my $why = _unit_safe_path($value, $what)) {
			return (undef, $why);
		}
	}
	my $window = $self->{window};
	return (undef, 'the rollback window must be a whole number of seconds between 30 and 3600')
		unless defined $window && $window =~ /^[0-9]+\z/ && $window >= 30 && $window <= 3600;

	# DefaultDependencies=no + Conflicts/Before=shutdown.target so the
	# restore is not ordered behind the normal service graph: this has to be
	# able to run on a host where the normal service graph is exactly what
	# is broken. Nothing here names csf.service or lfd.service, by design -
	# see the module header.
	my $service = <<"SERVICE";
[Unit]
Description=csf-ui setup rollback - restore the pre-setup snapshot unless confirmed
Documentation=man:csf(8)
DefaultDependencies=no
Conflicts=shutdown.target
Before=shutdown.target

[Service]
Type=oneshot
ExecStart=$self->{setup_bin} --rollback-now --snapshot $snapshot_dir
SERVICE

	my $timer = <<"TIMER";
[Unit]
Description=csf-ui setup rollback deadline

[Timer]
OnActiveSec=$window
OnBootSec=60
AccuracySec=1s
Unit=$SERVICE_UNIT
Persistent=false

[Install]
WantedBy=timers.target
TIMER

	return ($service, $timer);
}

###############################################################################
# arm($snapshot_dir) -> { ok => 1, units => [...] } | { ok => 0, reason => ... }
#
# Writes both units atomically, reloads systemd, and enables AND starts the
# timer. Enabling is what makes it survive a reboot; starting is what makes
# OnActiveSec= begin counting now.
#
# Every failure here leaves nothing armed and says so, because a
# half-installed timer is worse than none: the operator would be told the
# net is up.
###############################################################################
sub arm {
	my ($self, $snapshot_dir) = @_;

	# systemd_available() returns (1, $systemctl_path) or (0, $reason) - the
	# second value is only a path when the first is true.
	my ($available, $systemctl) = $self->systemd_available;
	return { ok => 0, reason => $systemctl, code => 'E_NO_SYSTEMD' } unless $available;

	my ($service, $timer) = $self->unit_text($snapshot_dir);
	return { ok => 0, reason => $timer, code => 'E_UNIT' } unless defined $service;

	# CAN THE THING IN ExecStart ACTUALLY BE EXEC'D? (task-8-review.md R73.)
	#
	# The timer arms against an INSTALLED path, and until now nothing
	# anywhere checked it. t/71's mode test guards the copies in ui-src/,
	# which is the repository - not the file systemd will run. So the exact
	# failure that killed this rescue mechanism in fix round 1 could still
	# arrive at the only path that matters at runtime, from a bad install, a
	# partial upgrade, or Task 9, which is the task that does the
	# installing.
	#
	# A timer that will 203/EXEC is WORSE THAN NO TIMER, because the
	# operator is told they are covered and then acts on it - which is the
	# whole reason this refuses rather than warning: ui-src/bin/
	# csf-ui-setup's apply() stops dead when arm() refuses, and an operator
	# who cannot arm a rollback should be applying from a shell they can
	# watch, not from a browser that has promised them a safety net it does
	# not have.
	my $binary = $self->{setup_bin};
	unless (-e $binary) {
		return { ok => 0, code => 'E_EXEC',
			reason => "the rollback timer would run $binary, which does not exist - it would fail with 203/EXEC and restore nothing" };
	}
	unless (-f $binary) {
		return { ok => 0, code => 'E_EXEC',
			reason => "the rollback timer would run $binary, which is not a plain file - it would fail with 203/EXEC and restore nothing" };
	}
	unless (-x $binary) {
		return { ok => 0, code => 'E_EXEC',
			reason => sprintf('the rollback timer would run %s, which is not executable (mode %04o) - it would fail with 203/EXEC and restore nothing; docs/WEBUI-RPC.md section 2.3 freezes it at 0750',
				$binary, ((stat($binary))[2] & 07777)) };
	}

	my $made = make_path($self->{unit_dir}, mode => 0755, parent_mode => 0755);
	return { ok => 0, reason => "the unit directory $self->{unit_dir} could not be created: $made", code => 'E_UNIT' }
		if defined $made;

	my $service_path = "$self->{unit_dir}/$SERVICE_UNIT";
	my $timer_path   = "$self->{unit_dir}/$TIMER_UNIT";

	my $wrote = $self->write_atomic($service_path, $service, mode => 0644);
	return { ok => 0, reason => "the rollback service unit could not be written: $wrote->{reason}", code => 'E_UNIT' }
		unless $wrote->{ok};

	$wrote = $self->write_atomic($timer_path, $timer, mode => 0644);
	unless ($wrote->{ok}) {
		# The service unit is already on disk and the timer is not. Take the
		# service back out, and CHECK that it went: armed() requires both
		# files, so a stray service unit does not make anything claim to be
		# armed - but it is a unit file this program put in
		# /etc/systemd/system and then walked away from, and leaving one
		# behind silently is how the next person finds a rollback service
		# nobody can account for.
		my $stray = (-e $service_path && !unlink($service_path))
			? " (and $service_path could not be removed again: $!)" : '';
		return { ok => 0, code => 'E_UNIT',
			reason => "the rollback timer unit could not be written: $wrote->{reason}$stray" };
	}

	my $reload = $self->_run($systemctl, 'daemon-reload');
	unless (_ran_ok($reload)) {
		my $swept = $self->_remove_units($systemctl);
		return { ok => 0, code => 'E_SYSTEMCTL',
			reason => 'systemctl daemon-reload failed, so the rollback timer was removed again rather than left unloaded: '
				. _said($reload) . (@{ $swept->{problems} } ? ' (and ' . join('; ', @{ $swept->{problems} }) . ')' : '') };
	}

	my $enable = $self->_run($systemctl, 'enable', '--now', $TIMER_UNIT);
	unless (_ran_ok($enable)) {
		my $swept = $self->_remove_units($systemctl);
		return { ok => 0, code => 'E_SYSTEMCTL',
			reason => 'systemctl could not enable and start the rollback timer, so nothing was left armed: '
				. _said($enable) . (@{ $swept->{problems} } ? ' (and ' . join('; ', @{ $swept->{problems} }) . ')' : '') };
	}

	return { ok => 1, units => [$service_path, $timer_path], window => $self->{window} };
}

sub armed {
	my ($self) = @_;
	return (-f "$self->{unit_dir}/$SERVICE_UNIT" && -f "$self->{unit_dir}/$TIMER_UNIT") ? 1 : 0;
}

###############################################################################
# confirm() - the operator said "yes, I still have my session".
#
# Stop, disable, delete, reload. Deleting the files is what makes this
# idempotent and what makes --cleanup able to finish the job for a session
# that died between arming and confirming: armed() is a file test, not a
# systemctl call, so it is answerable even when systemd is not talking.
###############################################################################
sub confirm {
	my ($self) = @_;
	my ($available, $systemctl_or_why) = $self->systemd_available;

	unless ($available) {
		# No systemd: there was never a timer to cancel (arm() refused).
		# Remove any unit files anyway - they may be left over from a host
		# that HAD systemd when they were written - and report honestly.
		my $swept = $self->_remove_units(undef);
		return { ok => $swept->{ok}, cancelled => 0, removed => $swept->{removed},
			problems => $swept->{problems}, reason => $systemctl_or_why };
	}

	# EVERY ONE OF THESE RESULTS IS CHECKED, and cancelled is the AND of
	# all of them (task-8-review.md R66/C4). This is the mechanism whose
	# entire job is to be trustworthy when everything else on the machine is
	# wrong; reporting "the rollback timer has been cancelled" because three
	# commands were issued, rather than because they worked, is the one
	# sentence in this program that must never be a guess. An operator who
	# believes it and walks away comes back to a machine that reverted
	# itself; one who is told the truth can run systemctl stop by hand.
	my @problem;
	my $stopped = $self->_run($systemctl_or_why, 'stop', $TIMER_UNIT);
	push @problem, 'systemctl could not stop ' . $TIMER_UNIT . ': ' . _said($stopped)
		unless _ran_ok($stopped);

	my $disabled = $self->_run($systemctl_or_why, 'disable', $TIMER_UNIT);
	push @problem, 'systemctl could not disable ' . $TIMER_UNIT . ': ' . _said($disabled)
		unless _ran_ok($disabled);

	my $swept = $self->_remove_units($systemctl_or_why);
	push @problem, @{ $swept->{problems} };

	# Belt and braces, and the check that matters most: whatever the three
	# commands said, is the timer actually gone? armed() is a file test, so
	# it is answerable even when systemd is not talking.
	push @problem, 'the rollback unit files are still present after removing them'
		if $self->armed;

	return {
		ok        => (@problem ? 0 : 1),
		cancelled => (@problem ? 0 : 1),
		removed   => $swept->{removed},
		problems  => \@problem,
		(@problem ? (reason => join('; ', @problem)) : ()),
	};
}

# What a failed child said, for a message. Never interpolated into a command.
sub _said {
	my ($result) = @_;
	return 'it could not be started' if $result->{error};
	return 'it exceeded its deadline' if $result->{timeout};
	return 'it was killed by a signal' if $result->{signal};
	my $text = defined $result->{output} ? $result->{output} : '';
	$text =~ s/\s+/ /g;
	$text =~ s/^\s+|\s+\z//g;
	return length($text) ? substr($text, 0, 200) : "exit $result->{exit}";
}

# -> { ok, removed => \@paths, problems => \@problems }
#
# unlink's result is checked, and so is daemon-reload's: a unit file that
# would not delete is a timer that still fires, which is the opposite of
# what every caller of this is trying to achieve.
sub _remove_units {
	my ($self, $systemctl) = @_;
	my (@removed, @problem);
	for my $unit ($SERVICE_UNIT, $TIMER_UNIT) {
		my $path = "$self->{unit_dir}/$unit";
		next unless -e $path;
		if (unlink $path) { push @removed, $path }
		else { push @problem, "$path could not be removed: $!" }
	}
	if ($systemctl && @removed) {
		my $reload = $self->_run($systemctl, 'daemon-reload');
		push @problem, 'systemctl daemon-reload failed after removing the rollback units: ' . _said($reload)
			unless _ran_ok($reload);
	}
	return { ok => (@problem ? 0 : 1), removed => \@removed, problems => \@problem };
}

###############################################################################
# restore($snapshot_dir) - what the timer actually runs.
#
# Order matters and is the opposite of the order the wizard wrote things in:
#
#   1. put csf.conf back (atomically - a rollback that truncates the file it
#      is restoring is not a rollback);
#   2. put ui.conf back, if one was snapshotted;
#   3. ask csf to restart, so the rules in force are the ones that
#      configuration describes;
#   4. only if csf could not restart, load the saved ruleset directly with
#      iptables-restore. This is the fallback, not the primary: replaying a
#      saved ruleset leaves csf's idea of the world and the kernel's
#      disagreeing, which is a state to reach for when the alternative is no
#      connectivity at all, and not otherwise.
#   5. disarm, always - whatever happened above. A rollback unit left
#      installed fires again on the next boot and restores a snapshot the
#      operator may by then have deliberately moved on from.
###############################################################################
sub restore {
	my ($self, $snapshot_dir) = @_;

	my @step;
	my $failed;

	my $meta = $self->read_meta($snapshot_dir);
	unless ($meta) {
		my $disarmed = $self->disarm;
		push @step, "NOT DISARMED: $_" for @{ $disarmed->{problems} };
		return { ok => 0, reason => "no snapshot metadata under $snapshot_dir; refusing to restore from a directory this code did not write", steps => \@step };
	}

	for my $pair (['csf.conf' => ($meta->{CSF_CONF} || $self->{csf_conf})],
	              ['ui.conf'  => ($meta->{UI_CONF}  || $self->{ui_conf})]) {
		my ($name, $target) = @$pair;
		my $source = "$snapshot_dir/$name";
		next unless -f $source;
		my $content = _slurp($source);
		unless (defined $content) {
			push @step, "$name: the snapshot copy could not be read";
			$failed = 1;
			next;
		}
		my $write = $self->write_atomic($target, $content,
			($name eq 'ui.conf') ? (mode => 0640, group => $UI_CONF_GROUP) : (mode => 0600));
		if ($write->{ok}) { push @step, "$name: restored to $target" }
		else { push @step, "$name: $write->{reason}"; $failed = 1 }
	}

	my $csf = $self->_locate('csf');
	my $restarted = 0;
	if ($csf) {
		my $result = $self->_run($csf, '-r');
		$restarted = _ran_ok($result) ? 1 : 0;
		push @step, $restarted ? 'csf -r: restarted with the restored configuration'
		                       : 'csf -r: failed';
	}
	else {
		push @step, 'csf: binary not found';
	}

	unless ($restarted) {
		for my $pair (['ruleset.v4' => 'iptables-restore'], ['ruleset.v6' => 'ip6tables-restore']) {
			my ($name, $tool) = @$pair;
			my $source = "$snapshot_dir/$name";
			next unless -f $source;
			my $binary = $self->_locate($tool) or next;
			# iptables-restore takes the file as an operand; there is no
			# shell redirection anywhere in this tree (G2).
			my $result = $self->_run($binary, $source);
			push @step, _ran_ok($result) ? "$tool: the saved ruleset was reloaded"
			                             : "$tool: refused to reload the saved ruleset";
			$failed = 1 unless _ran_ok($result);
		}
	}

	my $disarmed = $self->disarm;
	if ($disarmed->{ok}) {
		push @step, 'disarmed: the rollback units were removed so this cannot fire again';
	}
	else {
		# Loud, and fatal to the verdict: a rollback unit left installed
		# fires again on the next boot and restores a snapshot the operator
		# may by then have deliberately moved on from.
		push @step, "NOT DISARMED - this will fire again unless the units are removed by hand: $_"
			for @{ $disarmed->{problems} };
		$failed = 1;
	}

	return { ok => ($failed ? 0 : 1), steps => \@step };
}

# Stop-and-delete without the "operator confirmed" framing, used by
# restore() and by --cleanup.
sub disarm {
	my ($self) = @_;
	my ($available, $systemctl_or_why) = $self->systemd_available;
	return $self->_remove_units(undef) unless $available;

	my @problem;
	for my $verb ('stop', 'disable') {
		my $result = $self->_run($systemctl_or_why, $verb, $TIMER_UNIT);
		push @problem, "systemctl could not $verb $TIMER_UNIT: " . _said($result)
			unless _ran_ok($result);
	}
	my $swept = $self->_remove_units($systemctl_or_why);
	push @problem, @{ $swept->{problems} };
	push @problem, 'the rollback unit files are still present after removing them' if $self->armed;

	return { ok => (@problem ? 0 : 1), removed => $swept->{removed}, problems => \@problem };
}

###############################################################################
# Small filesystem helpers. mkdir -p without File::Path, which is core but
# whose error reporting ($File::Path::errstr, or a die under some versions)
# has changed shape more than once; three lines of mkdir are easier to be
# sure about than a dependency whose failure mode varies by Perl version.
###############################################################################
###############################################################################
# make_path($path, %opt) -> undef on success, or a reason
#
#   mode        the mode of the LAST component (default 0755)
#   parent_mode the mode of any intermediate directory this has to create
#               (default 0755)
#
# THE TWO MODES ARE SEPARATE BECAUSE CONFLATING THEM IS A WALL. Creating
# /var/lib/csf-ui/rollback/<id> at 0700 all the way down leaves
# /var/lib/csf-ui itself at 0700 - and docs/WEBUI-RPC.md section 2.3 freezes
# that directory at 0755 precisely because csfui has to TRAVERSE it to reach
# its own session store. Section 2.3 says it in as many words: a 0700
# directory is not a stricter version of a 0700 file, it is a wall in front
# of every file beneath it. The leaf may be as private as it likes; what is
# above it may not be private on the leaf's behalf.
#
# An intermediate that already exists is left exactly as it is: this creates
# directories, it does not have opinions about directories somebody else
# made.
###############################################################################
sub make_path {
	my ($path, %opt) = @_;
	my $mode        = defined $opt{mode}        ? $opt{mode}        : 0755;
	my $parent_mode = defined $opt{parent_mode} ? $opt{parent_mode} : 0755;

	return undef if -d $path;
	my @part = grep { length } split(m{/}, $path);
	my $so_far = '';
	for my $index (0 .. $#part) {
		$so_far .= "/$part[$index]";
		next if -d $so_far;
		my $this_mode = ($index == $#part) ? $mode : $parent_mode;
		unless (mkdir($so_far, $this_mode)) {
			return "$!" unless -d $so_far;   # lost a race with another mkdir: fine
		}
		# mkdir's mode is masked by the umask exactly as sysopen's is, and
		# 0755 under a 0027 umask is 0750 - which is the wall again, one
		# permission bit narrower. Set it explicitly and check.
		unless (chmod($this_mode, $so_far) == 1) {
			return sprintf('%s could not be given mode %04o: %s', $so_far, $this_mode, $!);
		}
	}
	return -d $path ? undef : 'the directory does not exist after creating it';
}

# getgrnam, wrapped so that the one place this program asks "what is the
# csfui group" is replaceable in a test. Returns undef when the group does
# not exist, which write_atomic() treats as a refusal rather than a reason
# to write the file with whatever ownership it happens to get.
sub _gid_for {
	my ($name) = @_;
	return undef unless defined $name && length $name;
	my @entry = getgrnam($name);
	return undef unless @entry;
	return $entry[2];
}

sub _slurp {
	my ($path) = @_;
	open(my $fh, '<:raw', $path) or return undef;
	local $/;
	my $content = <$fh>;
	close $fh;
	return $content;
}

1;
