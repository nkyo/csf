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

our $SERVICE_UNIT = 'csf-ui-rollback.service';
our $TIMER_UNIT   = 'csf-ui-rollback.timer';

# The confirmation window. 300 seconds, the same figure the wizard writes to
# TESTING_INTERVAL - deliberately, so an operator watching the clock has one
# number to watch and not two. Long enough to notice SSH still works and
# click a button; short enough that a locked-out operator is not sitting in
# front of a dead machine for a quarter of an hour.
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
	eval { $fh->sync; 1 };   # not fatal where the platform has no fsync
	unless (close $fh) {
		unlink $temp;
		return { ok => 0, reason => "the temporary file could not be closed cleanly: $!" };
	}

	# chmod explicitly: sysopen's mode is masked by the process umask, and a
	# config file that ends up 0644 because root's umask was 0022 is a
	# different file from the one this asked for.
	chmod($mode, $temp);

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

	# fsync the directory so the rename itself survives a crash.
	if (opendir(my $dh, $dir)) {
		eval { IO::Handle::sync($dh); 1 };
		closedir $dh;
	}

	return { ok => 1, path => $path };
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

	my $made = _make_path($dir, 0700);
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

	my ($available, $systemctl) = $self->systemd_available;
	return { ok => 0, reason => $systemctl, code => 'E_NO_SYSTEMD' } unless $available;

	my ($service, $timer) = $self->unit_text($snapshot_dir);
	return { ok => 0, reason => $timer, code => 'E_UNIT' } unless defined $service;

	my $made = _make_path($self->{unit_dir}, 0755);
	return { ok => 0, reason => "the unit directory $self->{unit_dir} could not be created: $made", code => 'E_UNIT' }
		if defined $made;

	my $service_path = "$self->{unit_dir}/$SERVICE_UNIT";
	my $timer_path   = "$self->{unit_dir}/$TIMER_UNIT";

	my $wrote = $self->write_atomic($service_path, $service, mode => 0644);
	return { ok => 0, reason => "the rollback service unit could not be written: $wrote->{reason}", code => 'E_UNIT' }
		unless $wrote->{ok};

	$wrote = $self->write_atomic($timer_path, $timer, mode => 0644);
	unless ($wrote->{ok}) {
		unlink $service_path;
		return { ok => 0, reason => "the rollback timer unit could not be written: $wrote->{reason}", code => 'E_UNIT' };
	}

	my $reload = $self->_run($systemctl, 'daemon-reload');
	unless (_ran_ok($reload)) {
		$self->_remove_units($systemctl);
		return { ok => 0, reason => 'systemctl daemon-reload failed, so the rollback timer was removed again rather than left unloaded', code => 'E_SYSTEMCTL' };
	}

	my $enable = $self->_run($systemctl, 'enable', '--now', $TIMER_UNIT);
	unless (_ran_ok($enable)) {
		$self->_remove_units($systemctl);
		return { ok => 0, reason => 'systemctl could not enable and start the rollback timer, so nothing was left armed', code => 'E_SYSTEMCTL' };
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
	my ($available, $systemctl) = $self->systemd_available;

	unless ($available) {
		# No systemd: there was never a timer to cancel (arm() refused).
		# Remove any unit files anyway - they may be left over from a host
		# that HAD systemd when they were written - and report honestly.
		my $removed = $self->_remove_units(undef);
		return { ok => 1, cancelled => 0, removed => $removed,
			reason => $systemctl };
	}

	$self->_run($systemctl, 'stop', $TIMER_UNIT);
	$self->_run($systemctl, 'disable', $TIMER_UNIT);
	my $removed = $self->_remove_units($systemctl);

	return { ok => 1, cancelled => 1, removed => $removed };
}

sub _remove_units {
	my ($self, $systemctl) = @_;
	my @removed;
	for my $unit ($SERVICE_UNIT, $TIMER_UNIT) {
		my $path = "$self->{unit_dir}/$unit";
		next unless -e $path;
		push @removed, $path if unlink $path;
	}
	$self->_run($systemctl, 'daemon-reload') if $systemctl && @removed;
	return \@removed;
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
		$self->disarm;
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
		my $write = $self->write_atomic($target, $content, mode => ($name eq 'ui.conf' ? 0640 : 0600));
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

	$self->disarm;
	push @step, 'disarmed: the rollback units were removed so this cannot fire again';

	return { ok => ($failed ? 0 : 1), steps => \@step };
}

# Stop-and-delete without the "operator confirmed" framing, used by
# restore() and by --cleanup.
sub disarm {
	my ($self) = @_;
	my ($available, $systemctl) = $self->systemd_available;
	if ($available) {
		$self->_run($systemctl, 'stop', $TIMER_UNIT);
		$self->_run($systemctl, 'disable', $TIMER_UNIT);
		return $self->_remove_units($systemctl);
	}
	return $self->_remove_units(undef);
}

###############################################################################
# Small filesystem helpers. mkdir -p without File::Path, which is core but
# whose error reporting ($File::Path::errstr, or a die under some versions)
# has changed shape more than once; three lines of mkdir are easier to be
# sure about than a dependency whose failure mode varies by Perl version.
###############################################################################
sub _make_path {
	my ($path, $mode) = @_;
	return undef if -d $path;
	my @part = split(m{/}, $path);
	my $so_far = '';
	for my $part (@part) {
		next if $part eq '';
		$so_far .= "/$part";
		next if -d $so_far;
		unless (mkdir($so_far, $mode)) {
			return "$!" unless -d $so_far;   # lost a race with another mkdir: fine
		}
	}
	return -d $path ? undef : 'the directory does not exist after creating it';
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
