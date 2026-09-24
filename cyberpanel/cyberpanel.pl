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
# start main
use strict;
use File::Find;
use Fcntl qw(:DEFAULT :flock);
use Sys::Hostname qw(hostname);
use IPC::Open3;
use lib '/usr/local/csf/lib';
use ConfigServer::Config;

our ($myv, %FORM, %in);

my $config = ConfigServer::Config->loadconfig();
my %config = $config->config;

open (my $IN, "<", "/etc/csf/version.txt");
$myv = <$IN>;
close ($IN);
chomp $myv;


my $file = $ARGV[0];
unless (-e $file) {die "Cannot find tempfile [$file]"}
my (undef,undef,$uuid,$ugid) = getpwnam("cyberpanel");
my $uid = (stat($file))[4];
my $gid = (stat($file))[5];
if ($uid != $uuid or $gid != $ugid) {die "Invalid tempfile ownership [$file]"}

open (my $DATA, "<", $file);
my $buffer = <$DATA>;
close ($DATA);
my @pairs = split(/&/, $buffer);
foreach my $pair (@pairs) {
	my ($name, $value) = split(/=/, $pair);
	$value =~ tr/+/ /;
	$value =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg;
	$FORM{$name} = $value;
}

#print "<pre>$ARGV[0]:$ARGV[1]:[[$buffer]]</pre>\n";
#foreach my $key (keys %ENV) {
#	print "$key = [$ENV{$key}]<br>\n";
#}

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
<p>Its replacement is <strong>csf-ui</strong>. It runs as an unprivileged user
behind your own web server and reaches root only through a small helper over a
unix socket with a fixed list of operations.</p>
<p>The csf installer sets it up: re-run it at a terminal, as root, and it asks
which mode to use and which addresses may reach the interface, writes this
server's web server configuration and enables the services. Then create an
account - there is no default one, and nothing can log in until you do:</p>
<pre style="background:#f4f4f4;padding:.6em 1em;overflow:auto;margin:0 0 1em 0">/usr/local/csf-ui/bin/csf-ui-passwd add &lt;user&gt; admin</pre>
<p>The role is <code>admin</code> or <code>support</code>. If
<code>/usr/local/csf-ui/</code> is not there at all, csf-ui was not installed -
re-run the csf installer.</p>
<h3 style="margin:1.6em 0 .4em 0">Or use the command line</h3>
<p><code>csf -h</code> lists every option. The full manual is
<code>/etc/csf/readme.txt</code>.</p>
<h3 style="margin:1.6em 0 .4em 0">One thing worth doing now</h3>
<p>The retired interface kept its password in plain text in
<code>/etc/csf/csf.conf</code>, as <code>UI_PASS</code>. Nothing reads that
setting any more, but the value is still sitting in the file. If it is a
password you use anywhere else, change it there.</p>
</div>
EOF

1;
