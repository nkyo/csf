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
# Added 2026-09-12 in https://github.com/nkyo/csf - see CHANGES.md.
#
# Task 9's packaging layer: the three front-end vhost templates
# (ui-src/dist/{nginx,apache,litespeed}.conf.tpl), the renderer they are
# rendered through (ui-src/dist/render-template.sh), the two systemd
# units, and the sh -n cleanliness of every installer script this task
# touches.
#
# Runs with no root and no network (this file only ever invokes `sh` and
# reads plain files - never useradd, systemctl or an actual install), and
# without IO::Socket::SSL, per the global constraints every other test
# file in this suite already holds to.
#
# task-9-brief.md's own Tests paragraph, verbatim, is what this file
# proves: "templates render with substituted values and contain no
# placeholder left over; systemd units parse with `systemd-analyze
# verify` when available, skipped with a reason when not; installer
# snippets are `sh -n` clean."
###############################################################################
use strict;
use warnings;

use FindBin ();
use lib "$FindBin::Bin/..", "$FindBin::Bin/../ui-src/lib";

use File::Temp qw(tempdir tempfile);
use POSIX ();
use Test::More tests => 214;

my $DIST = "$FindBin::Bin/../ui-src/dist";
my $RENDERER = "$DIST/render-template.sh";

ok(-f $RENDERER, 'render-template.sh is where install-webui.sh expects it');
ok(-x $RENDERER || -r $RENDERER, 'render-template.sh is readable/executable');

###############################################################################
# render($template, @kv) -> ($rc, $content_or_undef)
#
# Runs the REAL renderer as a subprocess (no root, no network - `sh` and
# `sed` are the only things it shells out to), the same way
# install-webui.sh invokes it, so this proves the shipped script behaves
# correctly rather than re-implementing its substitution logic in Perl
# and testing THAT instead.
###############################################################################
sub render {
	my ($template, @kv) = @_;
	my $dir = tempdir(CLEANUP => 1);
	my $out = "$dir/rendered.conf";
	my @cmd = ('sh', $RENDERER, $template, $out, @kv);
	system(@cmd);
	my $rc = $? == -1 ? -1 : ($? >> 8);
	return ($rc, undef) unless -f $out;
	open(my $fh, '<', $out) or return ($rc, undef);
	local $/;
	my $content = <$fh>;
	close $fh;
	return ($rc, $content);
}

###############################################################################
# Each of the three templates, rendered with real values, must: succeed
# (exit 0), contain every value it was given, and carry no "@@NAME@@"
# placeholder anywhere in the output - the exact two guarantees
# task-9-brief.md's Tests paragraph names.
###############################################################################
my %TEMPLATE = (
	nginx     => "$DIST/nginx.conf.tpl",
	apache    => "$DIST/apache.conf.tpl",
	litespeed => "$DIST/litespeed.conf.tpl",
);

for my $name (sort keys %TEMPLATE) {
	my $tpl = $TEMPLATE{$name};
	ok(-f $tpl, "$name.conf.tpl exists");

	my $sock    = '/run/csf-ui-web/csf-ui.sock';
	my $allow_f = "/etc/csf-ui/allow-$name.conf";
	my ($rc, $content) = render($tpl, "UI_PORT=8443", "UI_SOCK=$sock", "UI_ALLOW_INCLUDE=$allow_f");

	is($rc, 0, "$name.conf.tpl renders successfully with all three values supplied");
	ok(defined $content, "$name.conf.tpl produced an output file");

	SKIP: {
		skip "no rendered content to inspect", 4 unless defined $content;
		like($content, qr/8443/, "$name: UI_PORT was substituted");
		like($content, qr/\Q$sock\E/, "$name: UI_SOCK was substituted");
		like($content, qr/\Q$allow_f\E/, "$name: UI_ALLOW_INCLUDE was substituted");
		unlike($content, qr/@@[A-Za-z_][A-Za-z0-9_]*@@/,
			"$name: no placeholder token survives rendering");
	}

	# TLS material and the socket scheme are frozen paths (Ruling R29;
	# this task's own choice of socket path), not installer-supplied
	# values - a template that hardcodes them wrong is wrong regardless
	# of what render-template.sh is given, so this is checked directly
	# rather than via substitution.
	like($content, qr{/etc/csf-ui/ssl/cert\.pem}, "$name: references the frozen certificate path")
		if defined $content;
	like($content, qr{/etc/csf-ui/ssl/key\.pem}, "$name: references the frozen key path")
		if defined $content;
}

###############################################################################
# A template rendered with a MISSING value must fail loudly (non-zero
# exit) and must not silently emit a file with a literal placeholder in
# it - the failure mode render-template.sh exists to prevent.
###############################################################################
{
	my ($rc, $content) = render($TEMPLATE{nginx}, "UI_PORT=8443");
	isnt($rc, 0, 'rendering with a missing value fails (non-zero exit), not silently');
	ok(!defined $content, 'and no output file is left behind with an unresolved placeholder in it');
}

###############################################################################
# The two systemd units: exist, and carry the exact hardening
# task-9-brief.md mandates for each. Parsed with `systemd-analyze verify`
# when available; skipped with a named reason otherwise (neither this
# repository nor its CI is assumed to have systemd running under it -
# G1's own reasoning for IO::Socket::SSL applies here too).
###############################################################################
my %UNIT = (
	'csf-ui.service'        => "$DIST/csf-ui.service",
	'csf-ui-helper.service' => "$DIST/csf-ui-helper.service",
);

for my $name (sort keys %UNIT) {
	ok(-f $UNIT{$name}, "$name exists in ui-src/dist");
}

sub slurp {
	my ($path) = @_;
	open(my $fh, '<', $path) or return '';
	local $/;
	return <$fh>;
}

my $csf_ui        = slurp($UNIT{'csf-ui.service'});
my $csf_ui_helper = slurp($UNIT{'csf-ui-helper.service'});

# task-9-brief.md, verbatim: "csf-ui runs as csfui with NoNewPrivileges=yes,
# ProtectSystem=strict, ProtectHome=yes, PrivateTmp=yes,
# RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6, CapabilityBoundingSet=
# (empty), ReadWritePaths=/var/lib/csf-ui."
like($csf_ui, qr/^User=csfui$/m,        'csf-ui.service runs as csfui');
# Group=csf-ui-sock (not csfui) as of fix round 2 (R90) - checked in the
# dedicated block below, alongside SupplementaryGroups=csfui.
like($csf_ui, qr/^NoNewPrivileges=yes$/m, 'csf-ui.service: NoNewPrivileges=yes');
like($csf_ui, qr/^ProtectSystem=strict$/m, 'csf-ui.service: ProtectSystem=strict');
like($csf_ui, qr/^ProtectHome=yes$/m,   'csf-ui.service: ProtectHome=yes');
like($csf_ui, qr/^PrivateTmp=yes$/m,    'csf-ui.service: PrivateTmp=yes');
like($csf_ui, qr/^RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6$/m,
	'csf-ui.service: RestrictAddressFamilies is exactly the three named families');
like($csf_ui, qr/^CapabilityBoundingSet=\s*$/m, 'csf-ui.service: CapabilityBoundingSet is empty');
like($csf_ui, qr{^ReadWritePaths=.*\Q/var/lib/csf-ui\E}m,
	'csf-ui.service: ReadWritePaths includes /var/lib/csf-ui');
like($csf_ui, qr{^ExecStart=/usr/local/csf-ui/bin/csf-ui$}m,
	'csf-ui.service execs the S2.3 frozen path, not a fifth binary');

# task-9-brief.md: "csf-ui-helper runs as root with the narrowest set that
# still works" - root means no User= directive at all (systemd defaults
# to root), which is itself part of what "runs as root" is tested for.
unlike($csf_ui_helper, qr/^User=/m, 'csf-ui-helper.service has no User= - it runs as root');
like($csf_ui_helper, qr/^NoNewPrivileges=yes$/m, 'csf-ui-helper.service: NoNewPrivileges=yes');
like($csf_ui_helper, qr/^ProtectSystem=strict$/m, 'csf-ui-helper.service: ProtectSystem=strict');
like($csf_ui_helper, qr{^ExecStart=/usr/local/csf-ui/bin/csf-ui-helper$}m,
	'csf-ui-helper.service execs the S2.3 frozen path');

# Fix round 1 (task-9-review.md C2): the helper's only direct child is
# /usr/sbin/csf (ui-src/bin/csf-ui-helper never execs iptables/nft/ipset
# itself), and csf shells out to whichever of those the host's detected
# backend uses - a host-time fact, not a build-time one
# (ConfigServer::UI::Firewall detects iptables-legacy, iptables-nft OR
# nftables). The unit has to grant what EITHER backend needs, or it works
# on some hosts and silently fails on others depending on which backend
# they run - exactly the class of defect this fix round exists to close.
like($csf_ui_helper, qr/^RestrictAddressFamilies=.*\bAF_UNIX\b/m,
	'csf-ui-helper.service: RestrictAddressFamilies keeps AF_UNIX (its own listening socket)');
like($csf_ui_helper, qr/^RestrictAddressFamilies=.*\bAF_NETLINK\b/m,
	'csf-ui-helper.service: RestrictAddressFamilies allows AF_NETLINK (nft/iptables-nft/modern ipset)');
like($csf_ui_helper, qr/^RestrictAddressFamilies=.*\bAF_INET\b/m,
	'csf-ui-helper.service: RestrictAddressFamilies allows AF_INET (iptables-legacy raw sockets)');
like($csf_ui_helper, qr/^RestrictAddressFamilies=.*\bAF_INET6\b/m,
	'csf-ui-helper.service: RestrictAddressFamilies allows AF_INET6 (ip6tables-legacy raw sockets)');
like($csf_ui_helper, qr/^CapabilityBoundingSet=.*\bCAP_NET_ADMIN\b/m,
	'csf-ui-helper.service: CapabilityBoundingSet grants CAP_NET_ADMIN (netfilter rule mutation, both backends)');
like($csf_ui_helper, qr/^CapabilityBoundingSet=.*\bCAP_NET_RAW\b/m,
	'csf-ui-helper.service: CapabilityBoundingSet grants CAP_NET_RAW (iptables-legacy raw socket creation)');
like($csf_ui_helper, qr/^CapabilityBoundingSet=.*\bCAP_DAC_READ_SEARCH\b/m,
	'csf-ui-helper.service: CapabilityBoundingSet grants CAP_DAC_READ_SEARCH (/etc/csf is a 0600 directory - S13.2)');
# /usr/local/csf REMOVED as of fix round 2 (R89) and never restored -
# checked explicitly below, alongside the R91 CapabilityBoundingSet/
# Protect* assertions (fix round 3 inverted those, not this one).
for my $tree (qw(/etc/csf /var/lib/csf /run)) {
	like($csf_ui_helper, qr{^ReadWritePaths=.*\Q$tree\E}m,
		"csf-ui-helper.service: ReadWritePaths includes $tree (csf.pl's own tree or /run/xtables.lock, not this task's)");
}
unlike($csf_ui_helper, qr/^SystemCallFilter=~/m,
	'csf-ui-helper.service: no narrowing SystemCallFilter=~... line (fix round 1: could not rule out it blocks a syscall csf/iptables/nft needs)');

# Fix round 1 (task-9-review.md I2): the interim Mode A socket must live
# somewhere csfui can actually create it. /var/run/csf-ui (S2.3) is 0755
# root:root, frozen for csf-ui-helper's own root-owned socket - csfui has
# no write access there at all. RuntimeDirectory is systemd's mechanism
# for handing this unit a directory it owns, compatible with
# ProtectSystem=strict without a matching ReadWritePaths entry.
like($csf_ui, qr/^RuntimeDirectory=csf-ui-web$/m,
	'csf-ui.service: RuntimeDirectory=csf-ui-web (a directory csfui can actually write to)');
like($csf_ui, qr/^RuntimeDirectoryMode=0750$/m,
	'csf-ui.service: RuntimeDirectoryMode=0750');

###############################################################################
# THE MODE-A SOCKET PATH, ASSERTED ACROSS ALL FOUR FILES THAT NAME IT.
#
# This guard exists because of exactly what it prevents, which already
# happened once: the path was written into the front-end templates, into
# the installer, and into the systemd unit's RuntimeDirectory - and
# implemented in none of them. Mode A shipped inert, and no test in this
# suite could see it, because every file was individually consistent with
# itself.
#
# So the module that now binds the socket
# (ConfigServer::UI::Server::$DEFAULT_UNIX_SOCKET_PATH) is the single
# authority, and what can be compared against it is compared against it.
#
# THAT IS TWO FILES, NOT FOUR, and this header used to claim four (fix
# round 1, F12). The templates cannot carry the literal path at all -
# they carry @@UI_SOCK@@ - so a test that renders $SOCKET_PATH into the
# placeholder and then asserts the output contains $SOCKET_PATH is
# asserting that a substitution substituted. Proven by moving
# $DEFAULT_UNIX_SOCKET_PATH: only the installer's `sock=` and the unit's
# RuntimeDirectory reddened; the three "proxies to that exact socket path"
# cases stayed green, as they always will.
#
# What closes the loop for the templates is a different pair of facts, and
# both are asserted below instead: the INSTALLER passes its own `sock=`
# into the renderer as UI_SOCK (so the value the templates receive is the
# one already compared against Server.pm), and each template puts whatever
# it receives into the PROXY DIRECTIVE its own server uses rather than
# into a comment (asserted with a sentinel path, so the assertion is about
# the template's structure and cannot be satisfied by coincidence with the
# real value).
###############################################################################
require_ok('ConfigServer::UI::Server');
# Each of these package variables is read exactly once here, which is
# what "used only once: possible typo" is for - the names are correct and
# are the point of this block.
no warnings 'once';
my $SOCKET_PATH = $ConfigServer::UI::Server::DEFAULT_UNIX_SOCKET_PATH;
ok(defined $SOCKET_PATH && length $SOCKET_PATH,
	'Server.pm names the mode-A socket path it binds');

my $installer = slurp("$DIST/install-webui.sh");
like($installer, qr/^\s*sock=\Q$SOCKET_PATH\E\s*$/m,
	"install-webui.sh renders the same socket path Server.pm binds ($SOCKET_PATH)");

# The directory half: the socket cannot exist unless something creates
# the directory it lives in, and in the shipped deployment that something
# is this one systemd directive.
my ($runtime_directory) = $csf_ui =~ /^RuntimeDirectory=(\S+)$/m;
ok(defined $runtime_directory, 'csf-ui.service names a RuntimeDirectory');
my $socket_directory = $SOCKET_PATH;
$socket_directory =~ s{/[^/]+\z}{};
is($socket_directory, '/run/' . (defined $runtime_directory ? $runtime_directory : ''),
	'and that RuntimeDirectory IS the directory Server.pm binds its socket in - nothing else creates it');

# The installer's own `sock=` is what reaches the templates, and that is
# the link that makes their placeholder equivalent to Server.pm's value.
# Without this line the installer could agree with Server.pm about `sock=`
# and then render something else entirely into the vhosts.
like($installer, qr/"UI_SOCK=\$sock"/,
	'install-webui.sh passes its own $sock into the template renderer as UI_SOCK - which is what makes the templates agree with Server.pm at all');

# And each template must put whatever it receives into the PROXY DIRECTIVE
# its own server uses to reach a unix socket, not into a comment (which
# would sail through the generic no-placeholder check above). A SENTINEL
# path, not $SOCKET_PATH: rendering the real value in and then asserting
# the real value comes out is a tautology (F12), while a value that
# appears nowhere in any template proves the placeholder actually feeds
# that directive.
my $SENTINEL = '/run/csf-ui-sentinel/only-here.sock';
{
	my (undef, $out) = render($TEMPLATE{nginx}, 'UI_PORT=8443', "UI_SOCK=$SENTINEL",
		'UI_ALLOW_INCLUDE=/etc/csf-ui/allow-nginx.conf');
	like($out, qr{proxy_pass\s+http://unix:\Q$SENTINEL\E:},
		'nginx\'s proxy_pass is fed by the @@UI_SOCK@@ placeholder - whatever the installer passes is where nginx proxies to');
}
{
	my (undef, $out) = render($TEMPLATE{apache}, 'UI_PORT=8443', "UI_SOCK=$SENTINEL",
		'UI_ALLOW_INCLUDE=/etc/csf-ui/allow-apache.conf');
	like($out, qr{ProxyPass\s+"/"\s+"unix:\Q$SENTINEL\E\|},
		"Apache's ProxyPass is fed by it too");
}
{
	my (undef, $out) = render($TEMPLATE{litespeed}, 'UI_PORT=8443', "UI_SOCK=$SENTINEL",
		'UI_ALLOW_INCLUDE=/etc/csf-ui/allow-litespeed.conf');
	like($out, qr{address\s+UDS://\Q$SENTINEL\E},
		"and so is LiteSpeed's address UDS://");
}

###############################################################################
# THE FRONT SERVER'S BACKEND READ DEADLINE AGAINST THE DAEMON'S REQUEST
# BUDGET (fix round 2, R106).
#
# Every one of these three templates set that deadline to 30 - nginx's
# proxy_read_timeout, Apache's ProxyPass timeout=, LiteSpeed's initTimeout
# - while ConfigServer::UI::Server's request budget is 75. FOUR numbers in
# four files with nothing comparing them, and the comparison is the whole
# point: the daemon is not the last word on whether a request succeeded in
# mode A, and if the front server gives up first the administrator is
# shown an error page for a response the daemon was about to deliver.
#
# Measured behind the real servers, against the real mode-A listener with
# a dispatch() of 44s - the figure F1's own fix exists to make serviceable:
#
#   nginx 1.24, proxy_read_timeout 30s -> 504 Gateway Time-out at 30.03s
#   Apache 2.4.58, timeout=30          -> 502 Proxy Error      at 30.03s
#   nginx, proxy_read_timeout 80s      -> 200 OK               at 44.00s
#   Apache, ProxyPass timeout=80       -> 200 OK               at 44.00s
#
# So the shipped configuration failed either way, and fix round 1 widened
# the gap (35 > 30 already) rather than opening it.
#
# WHAT IS ASSERTED, and why it is an equality rather than ">=":
# docs/WEBUI-RPC.md's own rule (S14.2) is that a limit that cannot be
# counted is not a limit, and ">=" would let any of these numbers drift on
# its own as long as it drifted the harmless way - which is how three
# files came to hold 30 against a budget of 75 in the first place. So
# Server.pm derives the figure once
# (front_server_read_timeout() = default_request_budget() + margin) and
# each template is asserted to carry exactly that. Move the budget, the
# margin or any one template alone and this block reddens.
#
# The margin exists so the DAEMON's watchdog is always the deadline that
# fires first: it knows what it was bounding, while the front server only
# knows nothing has arrived yet.
###############################################################################
{
	my $budget = ConfigServer::UI::Server::default_request_budget();
	my $front  = ConfigServer::UI::Server::front_server_read_timeout();

	# The package-level sum must be the sum a shipped daemon actually
	# arms, or every assertion below is about a number nothing uses.
	my $server = ConfigServer::UI::Server->new(app => undef);
	is($server->_request_budget, $budget,
		"R106: default_request_budget() is the budget a default daemon actually arms ($budget s), not a second copy of the sum");
	cmp_ok($front, '>', $budget,
		"R106: and the front server's deadline is strictly longer ($front s vs $budget s), so csf-ui's own watchdog is what gives up first - the front server only knows nothing has arrived yet");

	my $nginx     = slurp($TEMPLATE{nginx});
	my $apache    = slurp($TEMPLATE{apache});
	my $litespeed = slurp($TEMPLATE{litespeed});

	my ($nginx_read)     = $nginx     =~ /^\s*proxy_read_timeout\s+(\d+)s;/m;
	my ($apache_read)    = $apache    =~ /^\s*ProxyPass\s+.*\btimeout=(\d+)\s*$/m;
	my ($litespeed_read) = $litespeed =~ /^\s*initTimeout\s+(\d+)\s*$/m;

	is($nginx_read, $front,
		"R106: nginx.conf.tpl's proxy_read_timeout is csf-ui's request budget plus its margin ($front s) - at 30s a request csf-ui served at 44s was a 504 the administrator never saw past");
	is($apache_read, $front,
		"R106: apache.conf.tpl's ProxyPass timeout= is the same figure ($front s) - at 30 it was a 502 Proxy Error at 30.03s");
	is($litespeed_read, $front,
		"R106: litespeed.conf.tpl's initTimeout is the same figure ($front s) - it is the same deadline under a third name, and it was 30 too");
}

# The socket's own mode is the other half of "the front server can reach
# it": the directory being traversable is necessary and not sufficient,
# which is what csf-ui.service's own comment already says. 0660 is what
# _open_unix_listener() sets and then verifies; asserted here so changing
# it has to be a deliberate change to a documented number.
is(sprintf('%04o', $ConfigServer::UI::Server::UNIX_SOCKET_MODE), '0660',
	'the socket is served at 0660, so the group csf-ui.service hands to the front server can connect');

SKIP: {
	my $analyzer = `command -v systemd-analyze 2>/dev/null`;
	chomp $analyzer;
	skip 'systemd-analyze not found on this host - unit files are not verified against a real systemd', 2
		unless length $analyzer;

	for my $name (sort keys %UNIT) {
		my $rc = system('systemd-analyze', 'verify', $UNIT{$name});
		is($rc, 0, "systemd-analyze verify accepts $name");
	}
}

###############################################################################
# render-template.sh must escape sed's own special replacement characters
# ('&', '#', '\') IN THE VALUE rather than reject them - a real installer
# value is never attacker-controlled here, but a socket path or an
# UI_ALLOW include path is an ordinary filesystem path, and '&' or '\'
# appearing in one must not corrupt the rendered line.
###############################################################################
{
	my ($rc, $content) = render($TEMPLATE{nginx},
		'UI_PORT=8443',
		'UI_SOCK=/run/csf-ui-web/csf-ui.sock',
		'UI_ALLOW_INCLUDE=/etc/csf-ui/weird&name#with\\backslash.conf');
	is($rc, 0, 'a value containing sed-special characters (& # \\) still renders');
	like($content, qr{/etc/csf-ui/weird&name#with\\backslash\.conf},
		'and the value survives byte-for-byte rather than being interpreted by sed')
		if defined $content;
}

###############################################################################
# The mode-B entry point (this task's item A / Ruling R30): running
# ui-src/bin/csf-ui DIRECTLY must no longer print the old "csf-ui is a
# library... not executed directly" message and exit 0 - it must instead
# reach ConfigServer::UI::Server's own preflight(), which in THIS
# environment (no IO::Socket::SSL, no /etc/csf-ui/ui.conf - G1, the same
# environment every other test file in this suite runs in) refuses
# loudly and exits non-zero. Proving it reaches preflight() - rather than
# merely "exits non-zero", which the old stub also could be made to do -
# is what actually distinguishes the wiring being present from being
# absent.
###############################################################################
{
	my $app_path = "$FindBin::Bin/../ui-src/bin/csf-ui";
	my $lib1 = "$FindBin::Bin/..";
	my $lib2 = "$FindBin::Bin/../ui-src/lib";
	# BOUNDED, AND THE CHILD IS REAPED RATHER THAN ORPHANED (fix round 2,
	# R107's sweep). The whole point of this block is that csf-ui now
	# reaches Server.pm's run(), and run()'s alternative to refusing is
	# entering accept() and blocking forever - so the day this
	# environment acquires a usable ui.conf (or preflight() stops
	# refusing for an unrelated reason) a plain backtick here would hang
	# this file with zero "not ok" lines. Run through a pipe rather than
	# backticks so the deadline has a pid to SIGKILL: an alarm over a
	# backtick would leave a wedged csf-ui running after this file has
	# finished with it.
	my $out = '';
	my $rc;
	my $blocked = 0;
	my $pid = open(my $fh, '-|');
	die "fork: $!" unless defined $pid;
	if (!$pid) {
		open(STDERR, '>&', \*STDOUT) or POSIX::_exit(126);
		exec($^X, "-I$lib1", "-I$lib2", $app_path) or POSIX::_exit(127);
	}
	{
		local $SIG{ALRM} = sub { die "ALARM\n" };
		alarm(60);
		my $completed = eval { local $/; my $text = <$fh>; $out = defined $text ? $text : ''; 1 };
		alarm(0);
		if ($completed) {
			close $fh;
			$rc = $? >> 8;
		}
		else {
			$blocked = 1;
			kill 'KILL', $pid;
			waitpid($pid, 0);
			close $fh;
		}
	}

	is($blocked, 0,
		'R107: running ui-src/bin/csf-ui directly RETURNS - it refuses, rather than entering the accept loop and hanging this file');
	isnt($rc, 0, 'running ui-src/bin/csf-ui directly exits non-zero (no ui.conf/SSL in this environment)');
	unlike($out, qr/is a library/, 'and no longer claims to be a library that cannot be executed directly');
	like($out, qr/ui\.conf|IO::Socket::SSL/,
		'and the failure is Server.pm\'s own preflight() refusal, not an unrelated crash');
}

###############################################################################
# LiteSpeed's accessControl wrapper and deny-by-default (fix round 1,
# task-9-review.md C3): a bare `include` of "allow ..." lines is not
# itself an ACL in LiteSpeed's native config - nothing enforced it before
# this fix, so the vhost was reachable from anywhere despite the
# template's own comments describing it as restricted.
###############################################################################
{
	my (undef, $content) = render($TEMPLATE{litespeed},
		"UI_PORT=8443", "UI_SOCK=/run/csf-ui-web/csf-ui.sock",
		"UI_ALLOW_INCLUDE=/etc/csf-ui/allow-litespeed.conf");
	like($content, qr/accessControl\s*\{/, 'litespeed.conf.tpl: the UI_ALLOW include sits inside an accessControl block');
	like($content, qr/accessControl\s*\{[^}]*deny\s+ALL/s, 'litespeed.conf.tpl: accessControl has a default deny');
	like($content, qr/accessControl\s*\{[^}]*include\s+\/etc\/csf-ui\/allow-litespeed\.conf/s,
		'litespeed.conf.tpl: the generated allow list is inside the same accessControl block, not a bare top-level include');
}

###############################################################################
# Apache module guards (fix round 1, task-9-review.md I6): an unguarded
# directive from a module that is not loaded is a FATAL error for
# Apache's ENTIRE configuration, not just this vhost - confirmed for real
# against a stock Ubuntu apache2 install with mod_ssl/mod_proxy_http/
# mod_headers all disabled (see the task report for the reproduction);
# this is the regression test that keeps it fixed.
###############################################################################
{
	my (undef, $content) = render($TEMPLATE{apache},
		"UI_PORT=8443", "UI_SOCK=/run/csf-ui-web/csf-ui.sock",
		"UI_ALLOW_INCLUDE=/etc/csf-ui/allow-apache.conf");
	like($content, qr/<IfModule\s+mod_ssl\.c>/, 'apache.conf.tpl: SSLEngine et al are guarded by <IfModule mod_ssl.c>');
	like($content, qr/<IfModule\s+mod_proxy_http\.c>/, 'apache.conf.tpl: the proxy directives are guarded by <IfModule mod_proxy_http.c>');
	like($content, qr/<IfModule\s+mod_headers\.c>\s*\n\s*RequestHeader/,
		'apache.conf.tpl: RequestHeader is guarded by <IfModule mod_headers.c>');
	like($content, qr/LimitRequestFields 64\b/,
		'apache.conf.tpl: LimitRequestFields matches ConfigServer::UI::HTTP\'s $MAX_HEADERS (64), not 100');
}

###############################################################################
# C1 (task-9-review.md): the installer must find install-webui.sh even
# after the calling script has `cd`ed elsewhere - `cd webmin ; tar -czf
# ...` near the end of six of the seven install.*.sh does exactly that,
# and a bare relative `[ -f ui-src/dist/install-webui.sh ]` silently
# skipped the entire WebUI setup on every one of them. This reproduces
# the failure mode directly: capture CSF_SRC_ROOT the way each installer
# now does, `cd` away, and confirm the captured root still resolves.
###############################################################################
{
	my $dir = tempdir(CLEANUP => 1);
	mkdir("$dir/webmin") or die "mkdir: $!";
	mkdir("$dir/ui-src") or die "mkdir: $!";
	mkdir("$dir/ui-src/dist") or die "mkdir: $!";
	open(my $fh, '>', "$dir/ui-src/dist/install-webui.sh") or die "open: $!";
	print $fh "#!/bin/sh\necho ran\n";
	close $fh;

	my $script = "$dir/repro.sh";
	open(my $sh, '>', $script) or die "open: $!";
	print $sh <<'SCRIPT';
#!/bin/sh
CSF_SRC_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || CSF_SRC_ROOT=.
cd webmin
if [ -f "$CSF_SRC_ROOT/ui-src/dist/install-webui.sh" ]; then
	sh "$CSF_SRC_ROOT/ui-src/dist/install-webui.sh"
else
	echo "csf-ui: ui-src/dist/install-webui.sh not found under $CSF_SRC_ROOT - WebUI packaging was not run"
fi
SCRIPT
	close $sh;

	my $out = `sh "$script" 2>&1`;
	like($out, qr/^ran$/m, 'C1 regression: install-webui.sh still runs after the calling script cd-s into webmin/');
	unlike($out, qr/not found under/, 'and the "not found" fallback message is not the one that fired');
}

###############################################################################
# Every installer script this task touches must stay `sh -n` clean -
# task-9-brief.md's own Tests paragraph and the global constraint both
# say so. Includes the three new ui-src/dist/*.sh files and all seven
# install.*.sh this task modifies, so a syntax error introduced in either
# direction is caught here rather than only at install time on someone's
# server.
###############################################################################
my @SH_FILES = (
	"$DIST/install-webui.sh",
	"$DIST/render-template.sh",
	"$DIST/csf-ui-cert.sh",
	"$FindBin::Bin/../install.generic.sh",
	"$FindBin::Bin/../install.cpanel.sh",
	"$FindBin::Bin/../install.cwp.sh",
	"$FindBin::Bin/../install.cyberpanel.sh",
	"$FindBin::Bin/../install.directadmin.sh",
	"$FindBin::Bin/../install.interworx.sh",
	"$FindBin::Bin/../install.vesta.sh",
);

for my $path (@SH_FILES) {
	my $label = $path;
	$label =~ s{.*/}{};
	ok(-f $path, "$label exists");
	my $rc = system('sh', '-n', $path);
	is($rc, 0, "$label is sh -n clean");
}

###############################################################################
# The synthetic reproduction earlier in this file proves the
# CSF_SRC_ROOT pattern is sound; this proves each of the seven REAL
# install.*.sh files actually uses it - the gap a synthetic-only test
# would leave, since C1 (task-9-review.md) was a bug in six real files,
# not in the pattern itself. Running all seven end to end (each does
# ~500 lines of real file/systemctl/useradd work with no `set -e`,
# against paths that do not exist in a bare checkout) is fragile to the
# point of being its own source of false reds, so this checks statically
# that (a) the capture line exists and (b) the WebUI invocation
# references it rather than a bare relative path - exactly the two ways
# C1's fix could silently regress.
###############################################################################
for my $installer (@SH_FILES) {
	next unless $installer =~ m{install\.\w+\.sh$};
	my $src = slurp($installer);
	my $label = $installer;
	$label =~ s{.*/}{};
	like($src, qr/^CSF_SRC_ROOT=\$\(CDPATH=/m,
		"$label: captures CSF_SRC_ROOT before anything can cd elsewhere");
	like($src, qr{if \[ -f "\$CSF_SRC_ROOT/ui-src/dist/install-webui\.sh" \]},
		"$label: the WebUI invocation guard uses \$CSF_SRC_ROOT, not a bare relative path");
	like($src, qr{sh "\$CSF_SRC_ROOT/ui-src/dist/install-webui\.sh"},
		"$label: the WebUI invocation itself uses \$CSF_SRC_ROOT, not a bare relative path");
}

###############################################################################
# install-webui.sh static properties, fix round 1 (task-9-review.md I4,
# I5): behaviours that need root/systemd/useradd to exercise end to end,
# checked here the way this file already checks the rest of it - directly
# against the shipped source, for the specific properties the review
# named.
###############################################################################
{
	my $install_webui = slurp("$DIST/install-webui.sh");

	# I5: the function existed and this task removed it outright, not
	# narrowed it - if it comes back, group csfui (which also gates
	# /var/run/csf-ui/helper.sock, S2.3) must not be the mechanism again.
	unlike($install_webui, qr/^grant_frontend_group\s*\(\)/m,
		'install-webui.sh: grant_frontend_group() was removed, not narrowed (I5 - false premise, standing widening)');
	unlike($install_webui, qr/usermod -aG csfui/,
		'install-webui.sh: nothing adds a front-server account to group csfui anywhere');

	# I4: the port must be range-checked against docs/WEBUI-RPC.md S10
	# (1024-65535) before it reaches write_ui_conf(), and _enable_now()
	# must ask systemctl what actually happened rather than assume it.
	like($install_webui, qr/-ge 1024.*-le 65535|-ge 1024\b[\s\S]*-le 65535/,
		'install-webui.sh: the interactive port prompt range-checks against 1024-65535 (S10)');
	like($install_webui, qr/^_enable_now\s*\(\)/m,
		'install-webui.sh: an _enable_now() helper exists');
	like($install_webui, qr/systemctl is-enabled/,
		'install-webui.sh: _enable_now() asks systemctl is-enabled rather than assuming');
	like($install_webui, qr/systemctl is-active/,
		'install-webui.sh: _enable_now() asks systemctl is-active rather than assuming');

	# I3 / M9: verify_install() must check §2.3's modes/owners, not only
	# existence, and must check the installed bin/ holds only the four
	# names (the report previously claimed this and the code did not).
	like($install_webui, qr/_check_path\b/,
		'install-webui.sh: verify_install() uses a mode/owner-checking helper, not just -e/-x');
	like($install_webui, qr/is not one of the four docs\/WEBUI-RPC\.md S2\.3 names/,
		'install-webui.sh: verify_install() checks the installed bin/ holds only the four S2.3 names');
}

###############################################################################
# Fix round 2 (task-9-review.md R87-R90 and the lower-priority findings):
# structural checks for what root/systemd/a-real-front-server would be
# needed to exercise end to end (done manually against real, freshly
# installed apache2/nginx on this host - see the task report for the
# full reproduction, including the negative cases), plus a real,
# no-root invocation of the one new function that is pure string logic.
###############################################################################
{
	my $install_webui = slurp("$DIST/install-webui.sh");

	# R87: UI_ALLOW must be validated - shape-checked and explicitly
	# refused at /0 - before either csf-ui or a front server ever sees it.
	like($install_webui, qr/^validate_ui_allow\s*\(\)/m,
		'install-webui.sh: a validate_ui_allow() function exists');
	# Both checked as "if ! validate_ui_allow ...; then return" - not
	# merely "the string appears somewhere in the function" - because a
	# call whose result is never checked is indistinguishable from no
	# call at all to a presence-only regex (checked directly: the
	# apache_missing_modules assertion below used to be presence-only,
	# and a guard rewritten to `if false` left it green - see the task
	# report's guard-removal table).
	like($install_webui, qr{setup_mode_a\(\) \{[\s\S]*?if ! validate_ui_allow "\$allow"; then},
		'install-webui.sh: setup_mode_a() actually GATES on validate_ui_allow, not just calls it');
	like($install_webui, qr{setup_mode_b\(\) \{[\s\S]*?if ! validate_ui_allow "\$allow"; then},
		'install-webui.sh: setup_mode_b() actually GATES on validate_ui_allow too');

	# R87/R88: the front server's OWN validator gates success, and a
	# missing validator is treated as a refusal (exit 2), never a pass.
	like($install_webui, qr/^front_configtest\s*\(\)/m,
		'install-webui.sh: a front_configtest() function exists');
	like($install_webui, qr/return 2/,
		'install-webui.sh: front_configtest() has a distinct "no validator found" return, not silent success');
	like($install_webui, qr{test_rc=\$\?\n\n?\tif \[ "\$test_rc" -ne 0 \]; then},
		'install-webui.sh: setup_mode_a() actually GATES on front_configtest()\'s exit status, not just calls it');
	like($install_webui, qr/front_disable_vhost/,
		'install-webui.sh: a rollback path (front_disable_vhost) exists for a failed validation');

	# R88: a missing Apache module must be caught directly - configtest
	# alone cannot see it, because <IfModule> is what stops it being a
	# fatal error in the first place.
	like($install_webui, qr/^apache_check_modules\s*\(\)/m,
		'install-webui.sh: an apache_check_modules() function exists');
	# Deliberately not just "the string apache_check_modules appears
	# after setup_mode_a() {" - that regex still matches a call sitting
	# behind a guard that can never be true (checked directly, fix round
	# 2: replacing the condition below with `if false; then` left this
	# assertion green while the real behaviour was gone). The exact
	# guard shape is what has to survive.
	like($install_webui,
		qr{if \[ "\$front" = "apache" \]; then\n\t\tstill_missing=\$\(apache_check_modules\)},
		'install-webui.sh: setup_mode_a() checks for still-missing modules specifically when $front is apache');

	# R93: apache_check_modules() must be a PURE check - fix round 2's
	# apache_missing_modules() silently ran a2enmod itself, unannounced,
	# which activates 'Listen 443' via Debian's ports.conf regardless of
	# anything this vhost does. Enabling a module is now a separate,
	# named function, called only after an explicit y/N prompt.
	{
		# Anchored to apache_check_modules()'s OWN closing brace (its body
		# never has a nested `{`), not a generic "the string a2enmod does
		# not appear somewhere after this point" - the earlier, unanchored
		# version matched past the closing brace into apache_enable_modules()
		# (which legitimately does call a2enmod) and reported this function
		# as still-silent when it was not.
		$install_webui =~ /apache_check_modules\(\) \{([\s\S]*?)\n\}/
			or die "could not extract apache_check_modules() body";
		unlike($1, qr/a2enmod/,
			'install-webui.sh: apache_check_modules() does NOT itself run a2enmod (R93 - no more silent module enabling)');
	}
	like($install_webui, qr/^apache_enable_modules\s*\(\)/m,
		'install-webui.sh: a separate apache_enable_modules() function exists');
	like($install_webui, qr/read -r reply/,
		'install-webui.sh: setup_mode_a() asks before enabling any Apache module (R93)');
	like($install_webui, qr/apache_enable_modules "\$enable_names"/,
		'install-webui.sh: apache_enable_modules() is only called after the y/N prompt, inside its [Yy]* case arm');
	like($install_webui, qr/activates 'Listen 443'/,
		'install-webui.sh: the prompt names the actual exposure change (R93 - "ask first, or refuse and print the command")');

	# R87: a certificate csf-ui-cert.sh failed to create must not be
	# referenced by a rendered vhost.
	like($install_webui, qr{\[ ! -s /etc/csf-ui/ssl/cert\.pem \]},
		'install-webui.sh: setup_mode_a() checks the certificate exists before rendering a vhost that references it');

	# Fix round 2 found write_allow_include()'s own `out=$3` colliding
	# with setup_mode_a()'s own `$out` once a reorder moved the call
	# after $out was set. Fix round 3's own sibling audit found one more
	# inert instance: write_ui_conf()'s `mode` against interactive_setup()'s
	# own `mode`. Both renamed; checked here so neither regresses back to
	# a name shared with its caller.
	like($install_webui, qr/^\tdest=\$3$/m,
		"install-webui.sh: write_allow_include()'s third parameter is named dest, not out");
	like($install_webui, qr/^\tui_mode=\$1$/m,
		"install-webui.sh: write_ui_conf()'s first parameter is named ui_mode, not mode");

	# R92: LiteSpeed ships no configuration-test command, ever - treating
	# that identically to nginx/Apache's ANOMALOUS "no validator found"
	# made Mode A permanently impossible for a supported platform.
	# front_configtest() needs its own litespeed arm rather than falling
	# through to the generic refusal.
	{
		# Anchored to front_configtest()'s OWN closing brace - the
		# earlier, unanchored version of this assertion kept matching
		# after the litespeed arm was deliberately deleted (to prove the
		# guard-removal works), because "litespeed)" and "return 0" both
		# also appear later in the file, inside setup_mode_a()'s own
		# case statement. Extract the function body precisely instead.
		$install_webui =~ /front_configtest\(\) \{([\s\S]*?)\n\}/
			or die "could not extract front_configtest() body";
		my $fn_body = $1;
		like($fn_body, qr/litespeed\)[\s\S]*?return 0/,
			'install-webui.sh: front_configtest() has an explicit litespeed arm that returns 0, not the generic "no validator" refusal (R92)');
	}
	like($install_webui, qr/MANUAL VERIFICATION IS REQUIRED/,
		'install-webui.sh: setup_mode_a() prints an explicit manual-verification step for LiteSpeed (R92 - "a documented manual step is fine")');

	# R94: a BASELINE test before this script writes anything, so a
	# pre-existing, unrelated failure in $front's config is diagnosed as
	# pre-existing rather than blamed on the vhost this run adds.
	like($install_webui, qr/baseline_rc=\$\?/,
		'install-webui.sh: setup_mode_a() captures a baseline configtest result before writing anything (R94)');
	like($install_webui, qr/configuration ALREADY failed its own test before this run/,
		'install-webui.sh: a pre-existing failure is reported as pre-existing, not as this vhost\'s fault (R94)');
	# The baseline capture must come BEFORE the certificate check and
	# the render - not merely exist somewhere in the function.
	like($install_webui,
		qr{baseline_output=\$\(front_configtest "\$front"\)[\s\S]*?\[ ! -s /etc/csf-ui/ssl/cert\.pem \][\s\S]*?render-template\.sh}s,
		'install-webui.sh: the baseline test runs before the certificate check and before rendering, not after (R94)');

	# R95: three findings, all about ordering, fixed as one re-sequence:
	# baseline, consent, enable, write, validate, then a rollback that
	# reverts everything this run changed.
	# 1. A real (non-2) baseline failure must NOT return immediately - it
	# has to be carried forward so this run's own write (which can repair
	# exactly what the baseline found broken, e.g. our own missing
	# allow-include) gets a chance to fix it before anything is judged.
	# Only the STRUCTURAL case - no validator binary at all (rc 2), which
	# nothing this run does can ever change - exits immediately.
	{
		# Extracted and counted directly, not matched against a guessed
		# whitespace shape with unlike() - the fragile version of this
		# check (a hand-written unlike() regex trying to describe the
		# WRONG code) stayed green when the guard-removal test below
		# actually reintroduced "return 1 on any non-zero baseline",
		# because the regex's assumed indentation did not match what the
		# reverted code actually looked like. A precise extraction cannot
		# have that failure mode: it counts `return 1` inside the
		# baseline block directly, whatever the surrounding whitespace.
		$install_webui =~ /if \[ "\$front" != "litespeed" \]; then\n(.*?)\n\tfi\n/s
			or die "could not extract the baseline block from setup_mode_a()";
		my $baseline_block = $1;
		my $return_count = () = $baseline_block =~ /return 1/g;
		is($return_count, 1,
			'install-webui.sh: the baseline block returns 1 exactly once (only the rc-2 structural case), not on every non-zero result (R95)');
		like($baseline_block, qr/if \[ "\$baseline_rc" -eq 2 \]; then\n\t\t\techo "\$baseline_output"[\s\S]*?return 1/,
			'install-webui.sh: that one return is specifically gated on baseline_rc -eq 2, with the baseline output printed first (R95)');
	}
	like($install_webui, qr/if \[ "\$baseline_rc" -eq 2 \]; then/,
		'install-webui.sh: only the structural "no validator at all" baseline result (rc 2) is still an immediate refusal (R95)');

	# 2. $baseline_output must not be discarded on that one remaining
	# immediate-refusal path - review's own words: "A refusal with no
	# reason, in the round whose entire subject was making refusals
	# honest."
	like($install_webui,
		qr{if \[ "\$baseline_rc" -eq 2 \]; then
			echo "\$baseline_output"},
		'install-webui.sh: the rc-2 baseline refusal prints $baseline_output, not just "leaving the WebUI unconfigured" (R95)');

	# 3. Consent and enable (Apache modules) must happen BEFORE write -
	# the whole point of the re-sequence - not after, which is what let
	# fix round 3's version leave a half-written vhost around while
	# asking, and made a module-enable failure look like a vhost failure.
	like($install_webui,
		qr{if \[ "\$front" = "apache" \]; then\n\t\tstill_missing=\$\(apache_check_modules\)[\s\S]*?\n\tfi\n[\s\S]*?\n\twrite_allow_include "\$front" "\$allow" "\$allow_include"}s,
		'install-webui.sh: Apache module consent/enable (STEP 2/3) runs before write_allow_include (STEP 4), not after (R95)');

	# 4. Modules THIS RUN enabled must be tracked separately from
	# whatever apache_check_modules() reports later, and reverted on a
	# failed final validation - not left active with nothing said.
	like($install_webui, qr/^apache_disable_modules\s*\(\)/m,
		'install-webui.sh: an apache_disable_modules() function exists (R95 - the rollback half apache_enable_modules() was missing)');
	like($install_webui, qr/modules_enabled_this_run=\$enable_names/,
		'install-webui.sh: setup_mode_a() records exactly which modules THIS RUN enabled, not a name recomputed later');
	like($install_webui,
		qr{if \[ "\$test_rc" -ne 0 \]; then[\s\S]*?front_disable_vhost "\$front" "\$out" "\$allow_include"
		if \[ -n "\$modules_enabled_this_run" \]; then
			apache_disable_modules "\$modules_enabled_this_run"}s,
		'install-webui.sh: a failed final validation reverts BOTH the vhost (and its allow-include file, R99) and any module this run enabled (R95)');

	# 5. The failure message must be derived from what the baseline
	# actually established, not assume the vhost (or the module-enable)
	# is the cause when the config was already broken - and must name
	# the module-enable specifically when it happened, so a failure the
	# ENABLE caused is not misattributed to "this vhost" alone (the exact
	# regression R95 found arriving through R93's own fix).
	like($install_webui, qr/what_changed="this vhost and enabling module\(s\) \$modules_enabled_this_run"/,
		'install-webui.sh: the failure message names the module-enable specifically when it happened (R95 - no more blaming only "this vhost")');
	like($install_webui, qr/cannot tell whether this vhost is the cause of a problem that was/,
		"install-webui.sh: a failure on top of an already-broken baseline says the attribution is uncertain, not that this vhost caused it (R95)");

	# Fix round 5 (task-9-review.md R96/R97/R98/R99): "the re-sequencing
	# is the right shape... but moving the consent gate in front of the
	# write put a BLIND INSTRUMENT there" - apache2ctl -M reports every
	# module missing whenever Apache's config does not parse, for a
	# reason the vhost has nothing to do with, and this used to be
	# indistinguishable from "genuinely missing". apache_check_modules()
	# now has a third state - "could not ask" - and setup_mode_a() must
	# never (a) blindly re-ask it after enabling (R96), (b) treat "could
	# not ask" as either "none missing" or "all missing" (R97), (c) lose
	# track of what it enabled if it dies before finishing (R98), or (d)
	# claim more got cleaned up on rollback than actually did (R99).
	{
		$install_webui =~ /apache_check_modules\(\) \{([\s\S]*?)\n\}/
			or die "could not extract apache_check_modules() body";
		my $fn_body = $1;
		my $rc_captures = () = $fn_body =~ /check_rc=\$\?/g;
		is($rc_captures, 3,
			'install-webui.sh: apache_check_modules() captures the REAL exit status of each candidate binary it tries (R97)');
		like($fn_body, qr/if \[ "\$check_rc" -ne 0 \]; then\n\t\treturn 1\n\tfi/,
			'install-webui.sh: apache_check_modules() has a distinct "could not ask" return, separate from its missing-list output (R97)');
		unlike($fn_body, qr/apache2ctl -M 2>\/dev\/null \|\| httpd -M/,
			'install-webui.sh: apache_check_modules() no longer uses the (A || B || C) subshell that discarded which command actually ran, or its real exit code (R97)');
	}

	# R96: setup_mode_a() must trust apache_enable_modules()'s OWN exit
	# status - the tool that just did the enabling - not re-ask the same
	# blind instrument R97 exists to stop trusting. Counted, not just
	# matched: a second call anywhere in this function is the exact
	# regression (the re-check that let a2enmod succeed while the
	# installer printed "not enabling Apache modules without
	# confirmation" and returned without disabling anything it had just
	# enabled).
	{
		$install_webui =~ /\nsetup_mode_a\(\) \{([\s\S]*?)\n\}\n/
			or die "could not extract setup_mode_a() body";
		my $fn_body = $1;
		my $call_count = () = $fn_body =~ /apache_check_modules\)/g;
		is($call_count, 1,
			'install-webui.sh: setup_mode_a() calls apache_check_modules() exactly once - no post-enable re-check (R96)');
		like($fn_body, qr/if apache_enable_modules "\$enable_names"; then\n\t+modules_enabled_this_run=\$enable_names\n\t+enabled_now=1/,
			q{install-webui.sh: enabled_now is set from apache_enable_modules()'s own exit status, not a re-check (R96)});
		unlike($fn_body, qr/still_missing=\$\(apache_check_modules\)\n\t+\[ -z "\$still_missing" \] && enabled_now=1/,
			'install-webui.sh: the old blind re-check ("enabled_now" gated on asking apache_check_modules() again) is gone (R96)');
	}

	# R97 (caller half): "could not ask" must be treated as "skip the
	# consent/enable step entirely", never silently coerced into "none
	# missing" (which would leave a genuinely-missing module unnoticed
	# and never explained) - the explanatory message is what makes the
	# difference between the two visible to whoever is reading the
	# installer's output.
	like($install_webui, qr/still_missing=\$\(apache_check_modules\)\n\t\tcheck_rc=\$\?\n\t\tif \[ "\$check_rc" -ne 0 \]; then/,
		q{install-webui.sh: setup_mode_a() captures apache_check_modules()'s own exit status immediately (R97)});
	like($install_webui, qr/could not determine which Apache modules are enabled/,
		'install-webui.sh: a "could not ask" result says so, distinctly from "none are missing" (R97)');
	like($install_webui,
		qr{if \[ "\$check_rc" -ne 0 \]; then[\s\S]*?still_missing=""\n\t\tfi},
		'install-webui.sh: "could not ask" clears still_missing so consent/enable is skipped, rather than guessed at (R97)');

	# R98: what this run is ABOUT to enable must be persisted BEFORE
	# a2enmod runs, not only held in a shell variable that a crash,
	# SIGKILL or Ctrl-C between the two would take down with it.
	like($install_webui, qr/^record_modules_enabled\s*\(\)/m,
		'install-webui.sh: a record_modules_enabled() function exists (R98)');
	like($install_webui, qr/^clear_modules_enabled_record\s*\(\)/m,
		'install-webui.sh: a clear_modules_enabled_record() function exists (R98)');
	like($install_webui, qr/^MODULES_RECORD=\/var\/lib\/csf-ui\//m,
		'install-webui.sh: the R98 durability record lives under /var/lib/csf-ui, not a shell variable alone');
	like($install_webui,
		qr{record_modules_enabled "\$enable_names"[\s\S]*?\n\t+if apache_enable_modules "\$enable_names"; then},
		'install-webui.sh: record_modules_enabled() runs BEFORE apache_enable_modules() - the ordering R98 exists for');
	like($install_webui,
		qr{apache_disable_modules "\$modules_enabled_this_run"\n\t\t\tclear_modules_enabled_record},
		'install-webui.sh: a rollback that disables modules also retires the R98 durability record for them');
	like($install_webui,
		qr{grant_socket_group "\$front"\n\tclear_modules_enabled_record},
		'install-webui.sh: a successful run also retires the R98 durability record - it is not a permanent audit log');
	{
		$install_webui =~ /\nverify_install\(\) \{([\s\S]*?)\n\}\n/s
			or die "could not extract verify_install() body";
		my $fn_body = $1;
		like($fn_body, qr/if \[ -f "\$MODULES_RECORD" \]; then/,
			'install-webui.sh: verify_install() surfaces a leftover R98 record from a run that died before clearing it');
	}

	# R99: front_disable_vhost() must remove BOTH files this run wrote,
	# or "nothing this run touched is still active" is not actually true
	# - write_allow_include()'s own $allow_include survived it before.
	like($install_webui, qr/^\tallow_include=\$3$/m,
		'install-webui.sh: front_disable_vhost() takes allow_include as a third parameter (R99)');
	like($install_webui, qr/rm -f "\$out" "\$allow_include"/,
		'install-webui.sh: front_disable_vhost() removes both the vhost and the allow-include file (R99)');
	like($install_webui, qr/removed the vhost, its allow-include file, and disabled the module\(s\)/,
		'install-webui.sh: the module-rollback message now says the allow-include file was removed too (R99)');
	like($install_webui, qr/removed the vhost and its allow-include file - nothing this run/,
		'install-webui.sh: the no-modules rollback message now says the allow-include file was removed too (R99)');
	unlike($install_webui, qr/\(it passed before - see above\)/,
		'install-webui.sh: the dangling "see above" reference is gone - a passing baseline prints nothing to point at (R99)');
	unlike($install_webui, qr/echo "csf-ui: - the WebUI vhost is NOT active:"/,
		'install-webui.sh: the dead empty-baseline_rc branch (unreachable - LiteSpeed always returns 0 from front_configtest) is gone (R99)');
	{
		my $header_count = () = $install_webui =~ /WHY VALIDATE RATHER THAN TRUST OUR OWN RENDER/g;
		is($header_count, 1,
			q{install-webui.sh: setup_mode_a()'s comment header is no longer duplicated (R99)});
	}
	unlike($install_webui, qr/per R87's own instruction/,
		'install-webui.sh: the stale pre-R92 comment claim (removed with the duplicate header) is gone (R99)');

	# R89: /usr/local/csf must not be a helper ReadWritePaths entry -
	# nothing in S5 writes there, and it is where csfpre.sh/csfpost.sh
	# (executed by `csf -r`) live.
	my $csf_ui_helper = slurp("$DIST/csf-ui-helper.service");
	unlike($csf_ui_helper, qr{^ReadWritePaths=.*/usr/local/csf\b}m,
		'csf-ui-helper.service: ReadWritePaths no longer includes /usr/local/csf (R89)');
	# Fix round 3 (task-9-review.md R91): fix round 2's CAP_SYS_MODULE +
	# ProtectKernelModules/ProtectKernelTunables removal was reverted in
	# full - the grant was inert (SystemCallFilter=@system-service is an
	# allow-list that excludes @module regardless of any capability), the
	# helper never execs modprobe at all (only /usr/sbin/csf), and
	# ProtectSystem=strict does not confine /proc or /sys on its own, so
	# ProtectKernelTunables was the only thing keeping them read-only -
	# removing it opened kernel-context execution paths
	# (/proc/sys/kernel/modprobe, /sys/kernel/uevent_helper) that need no
	# capability at all, to buy a write that was never confirmed to need
	# the hole. These assertions are inverted from fix round 2's own.
	unlike($csf_ui_helper, qr/^CapabilityBoundingSet=.*\bCAP_SYS_MODULE\b/m,
		'csf-ui-helper.service: CapabilityBoundingSet does NOT grant CAP_SYS_MODULE (R91 - inert, reverted)');
	like($csf_ui_helper, qr/^ProtectKernelModules=yes$/m,
		'csf-ui-helper.service: ProtectKernelModules restored (R91)');
	like($csf_ui_helper, qr/^ProtectKernelTunables=yes$/m,
		'csf-ui-helper.service: ProtectKernelTunables restored (R91 - ProtectSystem=strict does not cover /proc or /sys on its own)');

	# R90: the RuntimeDirectory must be traversable by a front-server
	# worker WITHOUT reusing csfui (that reuse is exactly R(I5)/fix round
	# 1's own removed mistake) - a second, dedicated group does this.
	my $csf_ui = slurp("$DIST/csf-ui.service");
	like($csf_ui, qr/^Group=csf-ui-sock$/m,
		'csf-ui.service: primary Group is csf-ui-sock, not csfui (R90 - so RuntimeDirectory is owned by it)');
	like($csf_ui, qr/^SupplementaryGroups=csfui$/m,
		'csf-ui.service: csfui kept as a SUPPLEMENTARY group (still needed to read ui.conf/the mode-B key)');
	like($install_webui, qr/^grant_socket_group\s*\(\)/m,
		'install-webui.sh: a grant_socket_group() function exists');
	like($install_webui, qr/usermod -aG csf-ui-sock/,
		'install-webui.sh: grant_socket_group() grants csf-ui-sock, never csfui');
	like($install_webui, qr/getent group csf-ui-sock/,
		'install-webui.sh: create_account() creates the csf-ui-sock group');

	# Lower-priority findings: detect_frontend() must not treat a
	# leftover config directory as proof a server is installed.
	unlike($install_webui, qr{detect_frontend\(\) \{[\s\S]*?-d /etc/nginx[\s\S]*?\n\}},
		'install-webui.sh: detect_frontend() no longer trusts a bare -d /etc/nginx');
}

###############################################################################
# validate_ui_allow(), run for real as a subprocess (no root needed - it
# is pure string logic) - the same "exercise the real script, do not
# reimplement its logic in Perl and test that instead" approach this file
# already uses for render-template.sh.
###############################################################################
{
	my $src = slurp("$DIST/install-webui.sh");
	$src =~ /(\nvalidate_ui_allow\(\) \{.*?\n\})/s
		or die "could not extract validate_ui_allow() from install-webui.sh";
	my $fn = $1;

	my ($fh, $harness) = tempfile(SUFFIX => '.sh');
	print $fh "#!/bin/sh\n$fn\nvalidate_ui_allow \"\$1\"\nexit \$?\n";
	close $fh;

	my %case = (
		'203.0.113.5'                    => 0,
		'203.0.113.0/24'                 => 0,
		'2001:db8::1'                    => 0,
		'203.0.113.5,198.51.100.0/24'    => 0,
		'not-an-ip'                      => 1,
		'0.0.0.0/0'                      => 1,
		'::/0'                           => 1,
		''                               => 1,
	);
	for my $input (sort keys %case) {
		my $rc = system('sh', $harness, $input);
		$rc = $rc == -1 ? -1 : ($rc >> 8);
		my $label = length($input) ? $input : '(empty)';
		is($rc == 0 ? 0 : 1, $case{$input}, "validate_ui_allow('$label') " . ($case{$input} ? 'rejects' : 'accepts') . " as expected");
	}
}
