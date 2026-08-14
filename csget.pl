#!/usr/bin/perl
###############################################################################
# Copyright (C) 2006-2025 Jonathan Michaelson
#
# Modified 2026-08-14 in https://github.com/nkyo/csf — see CHANGES.md.
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
# Daily version check, installed as /etc/cron.daily/csget. Writes the published
# version to /var/lib/configserver/csf.txt, which the UI reads to decide whether
# to offer an upgrade.
#
# Changed from the original in three ways:
#
#   1. curl no longer runs with -k. The original used `curl -skLf`, where -k is
#      --insecure: it accepted ANY certificate. A check that cannot tell the
#      real host from an impostor is not a check.
#
#   2. It asks GitHub instead of download.configserver.com, which stopped
#      resolving when the original project closed on 2025-08-31.
#
#   3. It only looks up csf. The original also polled for cxs, cmm, cse, cmq,
#      cmc, osm and msfe — ConfigServer products with no server left to answer.
#
# This only reports a version number. Nothing here downloads or installs code;
# that is `csf -u`, which verifies a GPG signature first.
###############################################################################
use strict;
use warnings;

if (my $pid = fork) {
	exit 0;
} elsif (defined($pid)) {
	$pid = $$;
} else {
	die "Error: Unable to fork: $!";
}
chdir("/");
close (STDIN);
close (STDOUT);
close (STDERR);
open STDIN, "<","/dev/null";
open STDOUT, ">","/dev/null";
open STDERR, ">","/dev/null";

$0 = "csf Version Check";

exit unless (-e "/etc/csf/csf.pl");

# Prefer the installed module so the repository is named in one place, but keep
# working if it is not loadable yet — the installers run this script during
# installation, before everything is in place.
my $versionurl = "https://raw.githubusercontent.com/nkyo/csf/main/version.txt";
eval {
	local $SIG{__DIE__} = undef;
	require "/usr/local/csf/lib/ConfigServer/Release.pm"; ##no critic
	$versionurl = ConfigServer::Release::version_url();
};

my $outfile = "/var/lib/configserver/csf.txt";
system("mkdir", "-p", "/var/lib/configserver");
unlink($outfile, $outfile.".error");

sub failed {
	my $why = shift;
	unlink($outfile);
	if (open (my $ERROR, ">", $outfile.".error")) {
		print $ERROR $why."\n";
		close ($ERROR);
	}
	exit;
}

my @cmd;
if (-e "/usr/bin/curl") {
	# -f fail on HTTP errors, -L follow redirects, -s quiet, -m timeout.
	# Deliberately NOT -k: an unverified certificate is a failed check.
	@cmd = ("/usr/bin/curl", "-sLf", "-m", "120", "--proto", "=https",
	        "-o", $outfile, $versionurl);
} elsif (-e "/usr/bin/wget") {
	@cmd = ("/usr/bin/wget", "-q", "-T", "120", "--https-only",
	        "-O", $outfile, $versionurl);
} else {
	&failed("Cannot find /usr/bin/curl or /usr/bin/wget to retrieve the version");
}

unless (@ARGV and $ARGV[0] eq "--nosleep") {
	# Spread the load across the day rather than every server asking at once.
	sleep(int(rand(60 * 60 * 6)));
}

if (system(@cmd) != 0) {
	&failed("Failed to retrieve the latest version from $versionurl");
}

# Leave behind a version number or nothing at all: whatever is in this file is
# rendered in the UI, and an error page saved as "the latest version" would be
# both wrong and ugly.
my $got = "";
if (open (my $IN, "<", $outfile)) {
	$got = <$IN>;
	close ($IN);
}
$got = "" unless defined $got;
$got =~ s/\s+//g;
unless ($got =~ /^[\d\.]+$/) {
	&failed("Unexpected response from $versionurl");
}

if (open (my $OUT, ">", $outfile)) {
	print $OUT $got."\n";
	close ($OUT);
}

exit;
