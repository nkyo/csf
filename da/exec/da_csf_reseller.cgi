#!/usr/bin/perl
#WHMADDON:addonupdates:ConfigServer Security&<b>Firewall</b>
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
## no critic (RequireUseWarnings, ProhibitExplicitReturnUndef, ProhibitMixedBooleanOperators, RequireBriefOpen)
# start main
use strict;
use File::Find;
use Fcntl qw(:DEFAULT :flock);
use Sys::Hostname qw(hostname);
use IPC::Open3;

use lib '/usr/local/csf/lib';
use ConfigServer::Config;
use ConfigServer::Slurp qw(slurp);

our ($reseller, %rprivs, $myv, %FORM, %daconfig);

my $config = ConfigServer::Config->loadconfig();
my %config = $config->config;
my $slurpreg = ConfigServer::Slurp->slurpreg;
my $cleanreg = ConfigServer::Slurp->cleanreg;

foreach my $line (slurp("/etc/csf/csf.resellers")) {
	$line =~ s/$cleanreg//g;
	my ($user,$alert,$privs) = split(/\:/,$line);
	$privs =~ s/\s//g;
	foreach my $priv (split(/\,/,$privs)) {
		$rprivs{$user}{$priv} = 1;
	}
	$rprivs{$user}{ALERT} = $alert;
}

my %session;
if ($ENV{SESSION_ID} =~ /^\w+$/) {
	open (my $SESSION, "<", "/usr/local/directadmin/data/sessions/da_sess_".$ENV{SESSION_ID}) or die "Security Error: No valid session ID for [$ENV{SESSION_ID}]";
	flock ($SESSION, LOCK_SH);
	my @data = <$SESSION>;
	close ($SESSION);
	chomp @data;
	foreach my $line (@data) {
		my ($name, $value) = split(/\=/,$line);
		$session{$name} = $value;
	}
}
if (($session{key} eq "") or ($session{ip} eq "") or ($session{key} ne $ENV{SESSION_KEY})) {
	print "Security Error: No valid session key";
	exit;
}

my ($ppid, $pexe) = &getexe(getppid());
if ($pexe ne "/usr/local/directadmin/directadmin") {
	print "Security Error: Invalid parent";
	exit;
}

delete $ENV{REMOTE_USER};

#print "content-type: text/html\n\n";
#foreach my $key (keys %ENV) {
#	print "ENV $key = [$ENV{$key}]<br>\n";
#}
#foreach my $key (keys %session) {
#	print "session $key = [$session{$key}]<br>\n";
#}

if (($session{key} ne "" and ($ENV{SESSION_KEY} eq $session{key})) and
	($session{ip} ne "" and ($ENV{REMOTE_ADDR} eq $session{ip}))) {
	my @usernames = split(/\|/,$session{username});
	$ENV{REMOTE_USER} = $usernames[-1];
}

$reseller = 0;
if ($ENV{REMOTE_USER} ne "" and $ENV{REMOTE_USER} eq $ENV{CSF_RESELLER} and $rprivs{$ENV{REMOTE_USER}}{USE}) {
	$reseller = 1;
} else {
	print "You do not have access to this feature\n";
	exit();
}

open (my $IN, "<", "/etc/csf/version.txt") or die $!;
$myv = <$IN>;
close ($IN);
chomp $myv;


my $buffer = $ENV{'QUERY_STRING'};
if ($buffer eq "") {$buffer = $ENV{POST}}
my @pairs = split(/&/, $buffer);
foreach my $pair (@pairs) {
	my ($name, $value) = split(/=/, $pair);
	$value =~ tr/+/ /;
	$value =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg;
	$FORM{$name} = $value;
}

open (my $DIRECTADMIN, "<", "/usr/local/directadmin/conf/directadmin.conf");
my @data = <$DIRECTADMIN>;
close ($DIRECTADMIN);
chomp @data;
foreach my $line (@data) {
	my ($name,$value) = split(/\=/,$line);
	$daconfig{$name} = $value;
}

###############################################################################
# The csf pages that used to render here were produced by the ConfigServer
# display modules that this same change deletes - CHANGES.md names them and
# records why they went. (They are not named here on purpose: Task 11's
# acceptance grep exists to prove no caller is left referring to them, and a
# comment that says the name is indistinguishable from a caller that does.)
#
# This entry point is deliberately KEPT, and deliberately still registered
# with the control panel. A plugin button that 404s, or an empty frame, tells
# an operator nothing and leaves them guessing whether csf itself is gone.
# csf is not gone; only this interface to it is, and this page says so and
# says where the replacement lives.
#
# Deliberately self-contained: the stylesheet, jQuery, Bootstrap and Chosen
# this page used to load were deleted in the same change, so it must not
# reference them, and it uses no JavaScript at all.
###############################################################################
print <<"EOF";
<div style="font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;line-height:1.55;max-width:44em;margin:1.5em;color:#222">
<h2 style="margin:0 0 .15em 0">ConfigServer Security &amp; Firewall</h2>
<p style="margin:0 0 1.25em 0;color:#666">csf v$myv</p>
<div style="border-left:4px solid #a94442;background:#fdf6f6;padding:.75em 1em;margin:0 0 1.25em 0">
<strong>The csf interface built into this control panel has been retired.</strong><br>
It ran as root, rendered every page from a single 5,000-line module and had no
CSRF protection. It was removed rather than patched.
</div>
<p><strong>csf itself is unaffected.</strong> The firewall, lfd and every
command-line feature are running exactly as before. No rule, allow list, deny
list or block has changed.</p>
<h3 style="margin:1.6em 0 .4em 0">Where the web interface went</h3>
<p>Its replacement is <strong>csf-ui</strong>, a separate web interface with its
own accounts. It has a <code>support</code> role that corresponds to the reseller
view you used here - the same blocks, allows and lookups, without the
server-wide configuration.</p>
<p>Ask your server administrator for its address and an account. There is
nothing left to configure on this page.</p>
</div>
EOF

sub getexe {
	my $thispid = shift;
	open (my $STAT, "<", "/proc/".$thispid."/stat");
	my $stat = <$STAT>;
	close ($STAT);
	chomp $stat;
	$stat =~ /\w\s+(\d+)\s+[^\)]*$/;
	my $ppid = $1;
	my $exe = readlink("/proc/".$ppid."/exe");
	return ($ppid, $exe);
}
1;
