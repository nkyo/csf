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
use Test::More tests => 153;

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
# /usr/local/csf REMOVED as of fix round 2 (R89) - checked explicitly,
# below, alongside CAP_SYS_MODULE and the two Protect* removals.
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
	my $out = `"$^X" -I"$lib1" -I"$lib2" "$app_path" 2>&1`;
	my $rc = $? >> 8;

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
	like($install_webui, qr{test_rc=\$\?\n\tif \[ "\$test_rc" -ne 0 \]; then},
		'install-webui.sh: setup_mode_a() actually GATES on front_configtest()\'s exit status, not just calls it');
	like($install_webui, qr/front_disable_vhost/,
		'install-webui.sh: a rollback path (front_disable_vhost) exists for a failed validation');

	# R88: a missing Apache module must be caught directly - configtest
	# alone cannot see it, because <IfModule> is what stops it being a
	# fatal error in the first place.
	like($install_webui, qr/^apache_missing_modules\s*\(\)/m,
		'install-webui.sh: an apache_missing_modules() function exists');
	like($install_webui, qr/a2enmod ssl proxy proxy_http headers/,
		'install-webui.sh: apache_missing_modules() attempts to enable the needed modules first');
	# Deliberately not just "the string apache_missing_modules appears
	# after setup_mode_a() {" - that regex still matches a call sitting
	# behind a guard that can never be true (checked directly: replacing
	# the condition below with `if false; then` left this assertion
	# green while the real behaviour was gone). The exact guard shape is
	# what has to survive.
	like($install_webui,
		qr{if \[ "\$front" = "apache" \]; then\n\t\tstill_missing=\$\(apache_missing_modules\)},
		'install-webui.sh: setup_mode_a() checks for still-missing modules specifically when $front is apache');

	# R87: a certificate csf-ui-cert.sh failed to create must not be
	# referenced by a rendered vhost.
	like($install_webui, qr{\[ ! -s /etc/csf-ui/ssl/cert\.pem \]},
		'install-webui.sh: setup_mode_a() checks the certificate exists before rendering a vhost that references it');

	# R89: /usr/local/csf must not be a helper ReadWritePaths entry -
	# nothing in S5 writes there, and it is where csfpre.sh/csfpost.sh
	# (executed by `csf -r`) live.
	my $csf_ui_helper = slurp("$DIST/csf-ui-helper.service");
	unlike($csf_ui_helper, qr{^ReadWritePaths=.*/usr/local/csf\b}m,
		'csf-ui-helper.service: ReadWritePaths no longer includes /usr/local/csf (R89)');
	like($csf_ui_helper, qr/^CapabilityBoundingSet=.*\bCAP_SYS_MODULE\b/m,
		'csf-ui-helper.service: CapabilityBoundingSet grants CAP_SYS_MODULE (csf -r calls modprobe)');
	unlike($csf_ui_helper, qr/^ProtectKernelModules=yes$/m,
		'csf-ui-helper.service: ProtectKernelModules removed (would strip CAP_SYS_MODULE regardless of the grant above)');
	unlike($csf_ui_helper, qr/^ProtectKernelTunables=yes$/m,
		'csf-ui-helper.service: ProtectKernelTunables removed (csf -r writes /proc/sys/net/ipv4/ip_forward)');

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
