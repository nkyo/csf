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
use Test::More tests => 75;

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

	my $sock    = '/var/run/csf-ui/csf-ui.sock';
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
like($csf_ui, qr/^Group=csfui$/m,       'csf-ui.service runs as group csfui');
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
like($csf_ui_helper, qr/^CapabilityBoundingSet=\s*$/m, 'csf-ui-helper.service: CapabilityBoundingSet is empty');
like($csf_ui_helper, qr/^ProtectSystem=strict$/m, 'csf-ui-helper.service: ProtectSystem=strict');
like($csf_ui_helper, qr{^ExecStart=/usr/local/csf-ui/bin/csf-ui-helper$}m,
	'csf-ui-helper.service execs the S2.3 frozen path');

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
		'UI_SOCK=/var/run/csf-ui/csf-ui.sock',
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
