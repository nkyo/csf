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

$FORM{action} = $FORM{iworxme};
delete $FORM{iworxme};

print "content-type: text/html\n\n";

#foreach my $key (keys %ENV) {
#	print "$key = [$ENV{$key}]<br>\n";
#}

###############################################################################
# The csf pages that used to render here came from ConfigServer::DisplayUI
# (and ConfigServer::DisplayResellerUI for the reseller view). Those modules
# were removed - see CHANGES.md for the whole retirement.
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
<!doctype html>
<html lang='en'>
<head>
<title>ConfigServer Security &amp; Firewall</title>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
</head>
<body>
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
<p>On this server, as root:</p>
<pre style="background:#f4f4f4;padding:.6em 1em;overflow:auto;margin:0 0 1em 0">/usr/local/csf-ui/bin/csf-ui-setup</pre>
<p>It asks which addresses may reach the interface and creates the first
account, then prints the address to browse to. If that command is not there,
csf-ui was not installed - re-run the csf installer.</p>
<h3 style="margin:1.6em 0 .4em 0">Or use the command line</h3>
<p><code>csf -h</code> lists every option. The full manual is
<code>/etc/csf/readme.txt</code>.</p>
<h3 style="margin:1.6em 0 .4em 0">One thing worth doing now</h3>
<p>The retired interface kept its password in plain text in
<code>/etc/csf/csf.conf</code>, as <code>UI_PASS</code>. Nothing reads that
setting any more, but the value is still sitting in the file. If it is a
password you use anywhere else, change it there.</p>
</div>
</body>
</html>
EOF

1;
