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
# ConfigServer::UI::Firewall: backend detection and the temporary port
# (task-8-brief.md: "backend detection against fixture command outputs for all
# six cases; `unknown` declines; canonical spec round-trip").
#
# EVERY probe in this file is answered from a fixture. Nothing here runs
# iptables, needs root, or touches a network (G1) - which is the point: a
# detector that could only be tested by running the thing it detects would be
# a detector nobody ever tested against the case that matters, which is the
# host that is NOT like this one.
#
# The fixtures are real command output, spelled the way the real tools spell
# it (the iptables banner's parenthetical, ufw's "Status: active", firewalld's
# bare "running", the `[ 3]` index in `ufw status numbered`), because a
# detector tuned to a fixture nobody checked against reality is a detector
# tuned to nothing.
###############################################################################
use strict;
use warnings;

use FindBin ();
use POSIX ();
use lib "$FindBin::Bin/..", "$FindBin::Bin/../ui-src/lib";

use Test::More tests => 206;

use ConfigServer::UI::Firewall ();
my $F = 'ConfigServer::UI::Firewall';

###############################################################################
# The fixture runner. Answers an argv list from a list of [pattern, answer]
# rules, in order, and records every argv list it was handed so a test can
# assert about what was NOT run as well as what was.
###############################################################################
package FakeRunner;

sub new {
	my ($class) = @_;
	return bless { rules => [], log => [], state => {} }, $class;
}

# $pattern is matched against the argv list joined with single spaces.
# $answer is a hashref (returned as-is) or a coderef (called with the runner
# and the argv list, so a fixture can model a ruleset that changes when
# something is added to it).
sub on {
	my ($self, $pattern, $answer) = @_;
	push @{ $self->{rules} }, [$pattern, $answer];
	return $self;
}

sub runner {
	my ($self) = @_;
	return sub {
		my (@argv) = @_;
		pop @argv;                      # the deadline run() appends
		my $line = join(' ', @argv);
		push @{ $self->{log} }, $line;
		for my $rule (@{ $self->{rules} }) {
			next unless $line =~ $rule->[0];
			my $answer = $rule->[1];
			$answer = $answer->($self, \@argv) if ref($answer) eq 'CODE';
			return { exit => 0, output => '', %$answer };
		}
		return { exit => 127, output => 'no such fixture', error => undef };
	};
}

sub ran { my ($self, $pattern) = @_; return scalar grep { /$pattern/ } @{ $self->{log} } }
sub log_lines { return @{ $_[0]{log} } }

package main;

# A locate() that answers from a fixed table, so no test depends on what this
# workspace happens to have in /sbin.
sub locator {
	my (%where) = @_;
	return sub { my ($name) = @_; return $where{$name} };
}

sub firewall {
	my ($runner, %where) = @_;
	return $F->new(runner => $runner->runner, locate => locator(%where));
}

###############################################################################
# THE SIX CASES (task-8-brief.md). One detection each, from fixture output.
###############################################################################
{
	# --- 1. iptables-legacy ---------------------------------------------
	my $r = FakeRunner->new
		->on(qr{^/sbin/iptables --version\z}, { output => "iptables v1.8.7 (legacy)\n" })
		->on(qr{^/sbin/iptables -S INPUT\z},  { output => "-P INPUT ACCEPT\n" });
	my $d = firewall($r, iptables => '/sbin/iptables')->detect;
	is($d->{backend}, 'iptables-legacy', 'a (legacy) banner is iptables-legacy');
	is($d->{certain}, 1, 'and it is certain');
	is($d->{tool}, '/sbin/iptables', 'the tool it would drive is named');
	is($d->{supports_w}, 1, '1.8.7 supports -w');
	like($d->{reason}, qr/legacy/, 'the reason says what was observed');
}
{
	# --- 2. iptables-nft ------------------------------------------------
	my $r = FakeRunner->new
		->on(qr{^/sbin/iptables --version\z}, { output => "iptables v1.8.7 (nf_tables)\n" })
		->on(qr{^/sbin/iptables -S INPUT\z},  { output => "-P INPUT DROP\n-A INPUT -j LOCALINPUT\n" });
	my $d = firewall($r, iptables => '/sbin/iptables')->detect;
	is($d->{backend}, 'iptables-nft', 'an (nf_tables) banner is iptables-nft');
	is($d->{certain}, 1, 'and it is certain');
}
{
	# --- 3. nftables (native; no iptables binary at all) ----------------
	my $r = FakeRunner->new
		->on(qr{^/usr/sbin/nft --version\z},     { output => "nftables v1.0.6 (Lester Gooch)\n" })
		->on(qr{^/usr/sbin/nft list ruleset\z},  { output => "table inet filter {\n\tchain input {\n\t}\n}\n" });
	my $d = firewall($r, nft => '/usr/sbin/nft')->detect;
	is($d->{backend}, 'nftables', 'nft with no iptables is nftables');
	is($d->{certain}, 1, 'and it is certain - "known but not writable" is not the same as unknown');
}
{
	# --- 4. firewalld ---------------------------------------------------
	my $r = FakeRunner->new
		->on(qr{^/usr/bin/firewall-cmd --state\z}, { output => "running\n" });
	my $d = firewall($r, 'firewall-cmd' => '/usr/bin/firewall-cmd')->detect;
	is($d->{backend}, 'firewalld', 'firewall-cmd --state saying running is firewalld');
	is($d->{tool}, '/usr/bin/firewall-cmd', 'firewall-cmd is the tool');
}
{
	# --- 5. ufw ---------------------------------------------------------
	my $r = FakeRunner->new
		->on(qr{^/usr/sbin/ufw status\z}, { output => "Status: active\n\nTo  Action  From\n" });
	my $d = firewall($r, ufw => '/usr/sbin/ufw')->detect;
	is($d->{backend}, 'ufw', 'ufw status saying active is ufw');
}
{
	# --- 6. unknown -----------------------------------------------------
	my $r = FakeRunner->new;
	my $d = firewall($r)->detect;
	is($d->{backend}, 'unknown', 'nothing installed is unknown');
	is($d->{certain}, 0, 'and unknown is never certain');
	like($d->{reason}, qr/no firewall backend could be identified/, 'the reason says so plainly');
}

###############################################################################
# Detection is by PROBING, not by distribution - so the same fixture set with
# a different answer from the same binary produces a different backend, and
# the manager wins over the raw layer when it is running.
###############################################################################
{
	my $r = FakeRunner->new
		->on(qr{^/usr/bin/firewall-cmd --state\z}, { output => "running\n" })
		->on(qr{^/sbin/iptables --version\z},      { output => "iptables v1.8.7 (nf_tables)\n" })
		->on(qr{^/sbin/iptables -S INPUT\z},       { output => "-P INPUT ACCEPT\n" });
	my $d = firewall($r, 'firewall-cmd' => '/usr/bin/firewall-cmd', iptables => '/sbin/iptables')->detect;
	is($d->{backend}, 'firewalld',
		'a running manager wins over the iptables binary underneath it');
	is($r->ran(qr{iptables}), 0,
		'and iptables is never probed at all once the manager has answered');
}
{
	my $r = FakeRunner->new
		->on(qr{^/usr/bin/firewall-cmd --state\z}, { exit => 252, output => "not running\n" })
		->on(qr{^/sbin/iptables --version\z},      { output => "iptables v1.8.7 (legacy)\n" })
		->on(qr{^/sbin/iptables -S INPUT\z},       { output => "-P INPUT ACCEPT\n" });
	my $d = firewall($r, 'firewall-cmd' => '/usr/bin/firewall-cmd', iptables => '/sbin/iptables')->detect;
	is($d->{backend}, 'iptables-legacy',
		'firewalld installed but NOT running falls through to what is actually filtering');
}
{
	my $r = FakeRunner->new
		->on(qr{^/usr/sbin/ufw status\z},     { output => "Status: inactive\n" })
		->on(qr{^/sbin/iptables --version\z}, { output => "iptables v1.8.7 (nf_tables)\n" })
		->on(qr{^/sbin/iptables -S INPUT\z},  { output => "-P INPUT ACCEPT\n" });
	my $d = firewall($r, ufw => '/usr/sbin/ufw', iptables => '/sbin/iptables')->detect;
	is($d->{backend}, 'iptables-nft', 'inactive ufw is not the backend');
}
{
	my $r = FakeRunner->new
		->on(qr{^/usr/sbin/ufw status\z},     { output => "Status: active\n" })
		->on(qr{^/sbin/iptables --version\z}, { output => "iptables v1.8.7 (nf_tables)\n" });
	my $d = firewall($r, ufw => '/usr/sbin/ufw', iptables => '/sbin/iptables')->detect;
	is($d->{backend}, 'ufw', 'active ufw wins over the iptables binary underneath it');
}
{
	# An iptables binary present alongside nft: the iptables answer is the
	# one that counts, because that is the binary csf itself drives.
	my $r = FakeRunner->new
		->on(qr{^/sbin/iptables --version\z}, { output => "iptables v1.8.9 (nf_tables)\n" })
		->on(qr{^/sbin/iptables -S INPUT\z},  { output => "-P INPUT ACCEPT\n" })
		->on(qr{^/usr/sbin/nft --version\z},  { output => "nftables v1.0.6\n" });
	my $d = firewall($r, iptables => '/sbin/iptables', nft => '/usr/sbin/nft')->detect;
	is($d->{backend}, 'iptables-nft',
		'nft alongside iptables is iptables-nft, not nftables - csf drives iptables');
}

###############################################################################
# The `unknown` cases that are not "nothing installed". Each one is a host
# where something IS there and this code still declines, which is the whole
# behaviour the brief is asking for.
###############################################################################
{
	my $r = FakeRunner->new
		->on(qr{^/bin/systemctl is-active firewalld\z}, { exit => 0, output => "active\n" });
	my $d = firewall($r, systemctl => '/bin/systemctl')->detect;
	is($d->{backend}, 'unknown',
		'firewalld running with no firewall-cmd is unknown: a rule could go in but not come out');
	like($d->{reason}, qr/firewall-cmd is not installed/, 'and says exactly that');
}
{
	my $r = FakeRunner->new
		->on(qr{^/bin/systemctl is-active firewalld\z}, { exit => 3, output => "activating\n" });
	my $d = firewall($r, systemctl => '/bin/systemctl')->detect;
	is($d->{backend}, 'unknown',
		'"activating" is read as running - is-active exits non-zero for it, so the word is what counts');
}
{
	my $r = FakeRunner->new
		->on(qr{^/sbin/iptables --version\z}, { output => "iptables v1.8.7 (nf_tables)\n" })
		->on(qr{^/sbin/iptables -S INPUT\z},  { exit => 3, output => "Permission denied (you must be root)\n" });
	my $d = firewall($r, iptables => '/sbin/iptables')->detect;
	is($d->{backend}, 'unknown',
		'an iptables whose ruleset cannot be read is unknown - a rule added there could not be read back');
}
{
	my $r = FakeRunner->new
		->on(qr{^/sbin/iptables --version\z}, { output => "some other program entirely\n" });
	my $d = firewall($r, iptables => '/sbin/iptables')->detect;
	is($d->{backend}, 'unknown', 'an unrecognised version banner is unknown, not a guess');
}
{
	my $r = FakeRunner->new
		->on(qr{^/sbin/iptables --version\z}, { exit => 127, output => '' });
	my $d = firewall($r, iptables => '/sbin/iptables')->detect;
	is($d->{backend}, 'unknown', 'an iptables that will not even run its own --version is unknown');
}
{
	my $r = FakeRunner->new
		->on(qr{^/usr/sbin/nft --version\z},    { output => "nftables v1.0.6\n" })
		->on(qr{^/usr/sbin/nft list ruleset\z}, { exit => 1, output => "Operation not permitted\n" });
	my $d = firewall($r, nft => '/usr/sbin/nft')->detect;
	is($d->{backend}, 'unknown', 'an nft whose ruleset cannot be listed is unknown');
}
{
	# Both implementations installed and both holding live rules. /sbin/
	# iptables identifies itself perfectly confidently; the answer is still
	# `unknown`, because "which one is in force" has two answers.
	my $r = FakeRunner->new
		->on(qr{^/sbin/iptables --version\z},        { output => "iptables v1.8.7 (nf_tables)\n" })
		->on(qr{^/sbin/iptables -S INPUT\z},         { output => "-P INPUT ACCEPT\n" })
		->on(qr{^/sbin/iptables-legacy -S\z},        { output => "-P INPUT ACCEPT\n-A INPUT -j DROP\n" })
		->on(qr{^/sbin/iptables-nft -S\z},           { output => "-P INPUT ACCEPT\n-A INPUT -p tcp -j ACCEPT\n" });
	my $d = firewall($r,
		iptables => '/sbin/iptables',
		'iptables-legacy' => '/sbin/iptables-legacy',
		'iptables-nft'    => '/sbin/iptables-nft')->detect;
	is($d->{backend}, 'unknown',
		'two live rulesets in two kernel subsystems is unknown, however confident the banner was');
	like($d->{reason}, qr/both iptables-legacy and iptables-nft/, 'and names the ambiguity');
}
{
	# Same host, but only the legacy table holds rules: no ambiguity.
	my $r = FakeRunner->new
		->on(qr{^/sbin/iptables --version\z},  { output => "iptables v1.8.7 (legacy)\n" })
		->on(qr{^/sbin/iptables -S INPUT\z},   { output => "-P INPUT ACCEPT\n-A INPUT -j DROP\n" })
		->on(qr{^/sbin/iptables-legacy -S\z},  { output => "-P INPUT ACCEPT\n-A INPUT -j DROP\n" })
		->on(qr{^/sbin/iptables-nft -S\z},     { output => "-P INPUT ACCEPT\n" })   # policy only
		;
	my $d = firewall($r,
		iptables => '/sbin/iptables',
		'iptables-legacy' => '/sbin/iptables-legacy',
		'iptables-nft'    => '/sbin/iptables-nft')->detect;
	is($d->{backend}, 'iptables-legacy',
		'a policy-only second table is not a live ruleset and does not create ambiguity');
}

###############################################################################
# firewall-cmd --state: EVERY NON-ZERO EXIT IS NOT "not running"
# (task-8-review.md C5).
#
# The confident-wrong-answer case. firewall-cmd exits 252 (NOT_RUNNING) and
# says so when firewalld is merely stopped. Any OTHER failure means the
# question was not answered - and answering it "iptables-nft, certain" on a
# host where firewalld may well hold the ruleset is strictly worse than
# `unknown`, because `unknown` is the safe path and this one writes a rule.
###############################################################################
{
	my @case = (
		[252, "firewalld is not running\n", 'iptables-nft',
			'exit 252 with "not running" is firewalld genuinely stopped'],
		[1, "Failed to connect to bus: No such file or directory\n", 'unknown',
			'a dbus failure is unanswered, not "not running"'],
		[1, "Authorization failed.\n", 'unknown',
			'an authorization failure is unanswered too'],
		[127, "", 'unknown',
			'a firewall-cmd that will not run at all is unanswered'],
		[0, "something unexpected\n", 'unknown',
			'exit 0 with an answer this code does not recognise is unanswered'],
	);
	for my $case (@case) {
		my ($exit, $output, $expected, $label) = @$case;
		my $r = FakeRunner->new
			->on(qr{^/usr/bin/firewall-cmd --state\z}, { exit => $exit, output => $output })
			->on(qr{^/bin/systemctl is-active firewalld\z}, { exit => 3, output => "inactive\n" })
			->on(qr{^/sbin/iptables --version\z}, { output => "iptables v1.8.7 (nf_tables)\n" })
			->on(qr{^/sbin/iptables -S INPUT\z},  { output => "-P INPUT ACCEPT\n" });
		my $d = firewall($r, 'firewall-cmd' => '/usr/bin/firewall-cmd',
			systemctl => '/bin/systemctl', iptables => '/sbin/iptables')->detect;
		is($d->{backend}, $expected, $label);
	}
}
{
	# The two witnesses disagree. This code cannot tell which is right, and
	# that is the definition of the case it declines.
	my $r = FakeRunner->new
		->on(qr{^/usr/bin/firewall-cmd --state\z}, { exit => 252, output => "not running\n" })
		->on(qr{^/bin/systemctl is-active firewalld\z}, { exit => 0, output => "active\n" })
		->on(qr{^/sbin/iptables --version\z}, { output => "iptables v1.8.7 (nf_tables)\n" })
		->on(qr{^/sbin/iptables -S INPUT\z},  { output => "-P INPUT ACCEPT\n" });
	my $d = firewall($r, 'firewall-cmd' => '/usr/bin/firewall-cmd',
		systemctl => '/bin/systemctl', iptables => '/sbin/iptables')->detect;
	is($d->{backend}, 'unknown',
		'firewall-cmd saying stopped while systemctl says active is unknown, not a choice between them');
	like($d->{reason}, qr/the two disagree/, 'and says exactly that');
}
{
	# No firewall-cmd, and systemctl's answer is not one of the words this
	# code knows: unanswered again, and there is no client tool to ask.
	my $r = FakeRunner->new
		->on(qr{^/bin/systemctl is-active firewalld\z}, { exit => 1, output => "Failed to get properties\n" })
		->on(qr{^/sbin/iptables --version\z}, { output => "iptables v1.8.7 (nf_tables)\n" })
		->on(qr{^/sbin/iptables -S INPUT\z},  { output => "-P INPUT ACCEPT\n" });
	my $d = firewall($r, systemctl => '/bin/systemctl', iptables => '/sbin/iptables')->detect;
	is($d->{backend}, 'unknown', 'an unreadable systemctl answer with no firewall-cmd is unknown');
	like($d->{reason}, qr/could not be determined/, 'saying so');
}
{
	# And the ordinary host: no firewalld anywhere, systemctl says so plainly.
	for my $word (qw(inactive failed unknown deactivating)) {
		my $r = FakeRunner->new
			->on(qr{^/bin/systemctl is-active firewalld\z}, { exit => 3, output => "$word\n" })
			->on(qr{^/sbin/iptables --version\z}, { output => "iptables v1.8.7 (nf_tables)\n" })
			->on(qr{^/sbin/iptables -S INPUT\z},  { output => "-P INPUT ACCEPT\n" });
		my $d = firewall($r, systemctl => '/bin/systemctl', iptables => '/sbin/iptables')->detect;
		is($d->{backend}, 'iptables-nft', "systemctl saying \"$word\" is firewalld not running");
	}
	for my $word (qw(active activating reloading)) {
		my $r = FakeRunner->new
			->on(qr{^/bin/systemctl is-active firewalld\z}, { exit => 3, output => "$word\n" });
		my $d = firewall($r, systemctl => '/bin/systemctl')->detect;
		is($d->{backend}, 'unknown', "systemctl saying \"$word\" with no firewall-cmd is unknown");
	}
}

###############################################################################
# rule_present() - the read-back the temporary port's re-assertion depends on.
# 1, 0 and undef are three answers, not two: "there is no rule" and "I could
# not find out" lead to opposite actions.
###############################################################################
{
	my $spec = { kind => 'iptables', binary => '/sbin/iptables', chain => 'INPUT', wait => [],
		canonical => '-A INPUT -s 203.0.113.5/32 -j ACCEPT' };

	my $there = firewall(FakeRunner->new->on(qr{ -S INPUT\z},
		{ output => "-P INPUT ACCEPT\n-A INPUT -s 203.0.113.5/32 -j ACCEPT\n" }));
	my ($is_there) = $there->rule_present($spec);
	is($is_there, 1, 'a rule the backend is showing is present');

	my $gone = firewall(FakeRunner->new->on(qr{ -S INPUT\z}, { output => "-P INPUT ACCEPT\n" }));
	my ($is_gone) = $gone->rule_present($spec);
	is($is_gone, 0, 'a rule it is not showing is absent');

	my $mute = firewall(FakeRunner->new->on(qr{ -S INPUT\z}, { exit => 1, output => "cannot read\n" }));
	my ($answer, $why) = $mute->rule_present($spec);
	is($answer, undef, 'a backend that will not answer gives undef, NOT 0');
	like($why, qr/neither confirmed present nor removed/, 'with a reason');

	my ($no_spec) = firewall(FakeRunner->new)->rule_present(undef);
	is($no_spec, undef, 'and no spec is undef too');
}

###############################################################################
# Version parsing -> -w support. `-w` did not exist before 1.4.20 and passing
# it to an older binary is a usage error that fails the mutation.
###############################################################################
{
	my @case = (
		["iptables v1.4.7\n",             'iptables-legacy', 0],
		["iptables v1.4.20\n",            'iptables-legacy', 1],
		["iptables v1.4.21\n",            'iptables-legacy', 1],
		["iptables v1.6.0\n",             'iptables-legacy', 1],
		["iptables v1.8.4 (legacy)\n",    'iptables-legacy', 1],
		["iptables v1.8.10 (nf_tables)\n",'iptables-nft',    1],
	);
	for my $case (@case) {
		my ($banner, $expected, $wait) = @$case;
		my $r = FakeRunner->new
			->on(qr{^/sbin/iptables --version\z}, { output => $banner })
			->on(qr{^/sbin/iptables -S INPUT\z},  { output => "-P INPUT ACCEPT\n" });
		my $d = firewall($r, iptables => '/sbin/iptables')->detect;
		chomp(my $label = $banner);
		is($d->{backend},   $expected, "$label -> $expected");
		is($d->{supports_w}, $wait,    "$label -> -w " . ($wait ? 'usable' : 'not usable'));
	}
}

###############################################################################
# GUARD: `unknown` DECLINES. Every mutating entry point, and - the part that
# matters - NOTHING is executed. A decline that has already run `iptables -I`
# is not a decline.
###############################################################################
{
	my $r = FakeRunner->new;
	my $fw = firewall($r);
	my $out = $fw->open_port(port => 8443, address => '203.0.113.5');
	is($out->{ok}, 0, 'unknown backend: open_port declines');
	is($out->{code}, 'E_BACKEND_UNKNOWN', 'with E_BACKEND_UNKNOWN');
	like($out->{reason}, qr/could not be identified with certainty/, 'and says why');
	is($r->ran(qr/-I |--add-rich-rule|insert/), 0,
		'and nothing that could add a rule was ever executed');

	# The backend gate runs BEFORE the port and address are even looked at.
	# That ordering is the guard itself, and it is what this asserts: with
	# arguments that are ALSO wrong, the answer is still the backend, because
	# the backend is the thing that actually stops this from working and the
	# operator should be told that rather than the first checkable thing.
	my $also_bad = $fw->open_port(port => 80, address => 'nonsense');
	is($also_bad->{code}, 'E_BACKEND_UNKNOWN',
		'an unknown backend is reported before the arguments are validated, not after');
}
{
	# Known-but-unwritable: a DIFFERENT refusal code from unknown, because
	# "we know what this is and will not write to it" is different
	# information from "we have no idea what this is".
	my $r = FakeRunner->new
		->on(qr{^/usr/sbin/nft --version\z},    { output => "nftables v1.0.6\n" })
		->on(qr{^/usr/sbin/nft list ruleset\z}, { output => "table inet filter {}\n" });
	my $fw = firewall($r, nft => '/usr/sbin/nft');
	my $out = $fw->open_port(port => 8443, address => '203.0.113.5');
	is($out->{ok}, 0, 'native nftables: open_port declines');
	is($out->{code}, 'E_NO_SAFE_RULE', 'with its own code, not E_BACKEND_UNKNOWN');
	is($r->ran(qr/add rule|add table/), 0, 'and no table or rule was created');

	my $also_bad = $fw->open_port(port => 80, address => 'nonsense');
	is($also_bad->{code}, 'E_NO_SAFE_RULE',
		'and that refusal too comes before argument validation - the backend is the reason');
}

###############################################################################
# GUARD: the rule is restricted to ONE address, or there is no rule.
###############################################################################
{
	my $r = FakeRunner->new
		->on(qr{^/sbin/iptables --version\z}, { output => "iptables v1.8.7 (nf_tables)\n" })
		->on(qr{^/sbin/iptables -S INPUT\z},  { output => "-P INPUT ACCEPT\n" });
	my $fw = firewall($r, iptables => '/sbin/iptables');

	my @case = (
		[undef,             'E_ADDRESS', qr/no operator address is known/,    'no address at all'],
		['',                'E_ADDRESS', qr/no operator address is known/,    'an empty address'],
		['203.0.113.0/24',  'E_ADDRESS', qr/single host, not a \/24/,         'a /24 network'],
		['0.0.0.0/0',       'E_ADDRESS', qr/whole Internet/,                   'the whole Internet'],
		['0.0.0.0',         'E_ADDRESS', qr/unspecified address/,             'the unspecified address'],
		# ip_info() rejects :: and ::1 before the unspecified/loopback checks
		# below them ever run - both fall inside its IPv4-mapped rule. The
		# refusal is what matters; which of the two layers produced it does
		# not, and asserting the wrong message here would be asserting a
		# message this code does not in fact produce.
		['::',              'E_ADDRESS', qr/IPv4-mapped or IPv4-compatible/,  'the v6 unspecified address'],
		['127.0.0.1',       'E_ADDRESS', qr/loopback/,                        'loopback'],
		['::1',             'E_ADDRESS', qr/IPv4-mapped or IPv4-compatible/,  'v6 loopback'],
		['not-an-address',  'E_ADDRESS', qr/not a valid IP address/,          'a hostname'],
		['203.0.113.5; rm -rf /', 'E_ADDRESS', qr/characters that cannot appear|not a valid IP/,
		                                                                      'a shell fragment'],
	);
	for my $case (@case) {
		my ($address, $code, $why, $label) = @$case;
		my $out = $fw->open_port(port => 8443, address => $address);
		is($out->{ok}, 0, "$label is refused");
		is($out->{code}, $code, "$label -> $code");
		like($out->{reason}, $why, "$label says why");
	}
	is($r->ran(qr/-I INPUT/), 0, 'and none of them reached an iptables mutation');

	# A full-length prefix IS a single host and is accepted - the rule is
	# "one address", not "no slash".
	my $ok = $fw->open_port(port => 8443, address => '203.0.113.5/32');
	isnt($ok->{code}, 'E_ADDRESS', '/32 is a single host, not a network');
}
{
	my $r = FakeRunner->new
		->on(qr{^/sbin/iptables --version\z}, { output => "iptables v1.8.7 (nf_tables)\n" })
		->on(qr{^/sbin/iptables -S INPUT\z},  { output => "-P INPUT ACCEPT\n" });
	my $fw = firewall($r, iptables => '/sbin/iptables');
	for my $port (undef, '', '80', '0', '65536', '08443', 'eighty', '1023') {
		my $out = $fw->open_port(port => $port, address => '203.0.113.5');
		is($out->{code}, 'E_PORT', 'port ' . (defined $port ? "\"$port\"" : 'undef') . ' is refused');
	}
}

###############################################################################
# THE CANONICAL SPEC ROUND TRIP (task-8-brief.md).
#
# The fixture models what iptables actually does: what comes back out of
# `-S INPUT` is NOT the command line that went in. `-s 203.0.113.5` becomes
# `-s 203.0.113.5/32`, an `-m tcp` appears that nobody typed, and the match
# modules come back in the kernel's order. A removal built from the port and
# address this code remembers would not match that line.
###############################################################################
sub iptables_fixture {
	my (%opt) = @_;
	my $installed = $opt{installed} || [];
	my $r = FakeRunner->new;
	$r->{state}{rules} = [@$installed];

	$r->on(qr{^/sbin/iptables --version\z}, { output => "iptables v1.8.7 (nf_tables)\n" });
	$r->on(qr{ -I INPUT 1 }, sub {
		my ($self, $argv) = @_;
		# The backend's own rendering, deliberately NOT the argv it was given.
		push @{ $self->{state}{rules} },
			'-A INPUT -s 203.0.113.5/32 -p tcp -m comment --comment csf-ui-setup -m tcp --dport 8443 -j ACCEPT';
		return { exit => 0, output => '' };
	});
	$r->on(qr{ -D INPUT }, sub {
		my ($self, $argv) = @_;
		my $spec = join(' ', @$argv[ (grep { $argv->[$_] eq '-D' } 0 .. $#$argv)[0] + 2 .. $#$argv ]);
		my $before = scalar @{ $self->{state}{rules} };
		@{ $self->{state}{rules} } = grep { $_ ne "-A INPUT $spec" } @{ $self->{state}{rules} };
		return { exit => (scalar(@{ $self->{state}{rules} }) < $before ? 0 : 1),
			output => (scalar(@{ $self->{state}{rules} }) < $before ? '' : "Bad rule (does a matching rule exist in that chain?).\n") };
	});
	$r->on(qr{ -S INPUT\z}, sub {
		my ($self) = @_;
		return { exit => 0, output => join("\n", '-P INPUT ACCEPT', @{ $self->{state}{rules} }) . "\n" };
	});
	return $r;
}

{
	my $r = iptables_fixture();
	my $fw = firewall($r, iptables => '/sbin/iptables');

	my $out = $fw->open_port(port => 8443, address => '203.0.113.5');
	is($out->{ok}, 1, 'the temporary port opens on a known iptables backend');
	is($out->{spec}{canonical},
		'-A INPUT -s 203.0.113.5/32 -p tcp -m comment --comment csf-ui-setup -m tcp --dport 8443 -j ACCEPT',
		"the stored spec is the BACKEND'S rendering, not the command line that was issued");
	is($out->{spec}{kind}, 'iptables', 'the spec names how to remove it');
	is($out->{spec}{address}, '203.0.113.5', 'and the canonical address');
	is($out->{spec}{port}, 8443, 'and the port');

	my ($insert) = grep { / -I INPUT 1 / } $r->log_lines;
	like($insert, qr/ -I INPUT 1 /, 'the rule was INSERTED at position 1, not appended after csf\'s own rules');
	like($insert, qr/--comment csf-ui-setup/, 'and stamped with a comment so it can be found again');
	unlike($insert, qr/["']/, 'and the comment carries no whitespace, so the canonical line stays splittable');

	my $closed = $fw->close_port($out->{spec});
	is($closed->{ok}, 1, 'and it closes again');
	is($closed->{removed}, 1, 'reporting that it actually removed something');

	my ($delete) = grep { / -D INPUT / } $r->log_lines;
	is($delete,
		'/sbin/iptables -w 5 -D INPUT -s 203.0.113.5/32 -p tcp -m comment --comment csf-ui-setup -m tcp --dport 8443 -j ACCEPT',
		'the deletion is the read-back line with -A turned into -D, argument for argument');

	my $again = $fw->close_port($out->{spec});
	is($again->{ok}, 1, 'closing twice is not an error');
	is($again->{removed}, 0, 'the second time removes nothing');
}

###############################################################################
# GUARD: REMOVAL IS DRIVEN BY THE READ-BACK, NOT BY MEMORY.
#
# This is the guard the whole module is shaped around, so it is tested by
# handing close_port() a spec whose remembered canonical text is exactly what
# a "rebuild it from the port and address" implementation would produce - the
# command line that went IN, which is not what the backend shows. Nothing is
# deleted, and the code says so.
###############################################################################
{
	my $r = iptables_fixture();
	my $fw = firewall($r, iptables => '/sbin/iptables');
	my $out = $fw->open_port(port => 8443, address => '203.0.113.5');
	is($out->{ok}, 1, 'a rule is installed');

	my %rebuilt = %{ $out->{spec} };
	# Exactly the string a from-memory rebuild produces: no /32, no -m tcp.
	$rebuilt{canonical} = '-A INPUT -s 203.0.113.5 -p tcp --dport 8443 -m comment --comment csf-ui-setup -j ACCEPT';

	my $closed = $fw->close_port(\%rebuilt);
	is($closed->{ok}, 1, 'a spec that does not match the backend is not an error...');
	is($closed->{removed}, 0, '...but removes nothing');
	is($r->ran(qr/ -D INPUT /), 0,
		'and no deletion was attempted at all - a -D that matches nothing is how a port stays open forever');

	# The real rule is still there, and the real spec still removes it.
	my $real = $fw->close_port($out->{spec});
	is($real->{removed}, 1, 'the spec that came from the read-back still works');
}
{
	# The other half of the same guard: a rule whose canonical rendering
	# contains a quote cannot be split into argv without implementing shell
	# quoting, so it is refused with the line printed rather than guessed at.
	my $r = FakeRunner->new
		->on(qr{ -S INPUT\z}, { output =>
			qq{-P INPUT ACCEPT\n-A INPUT -s 203.0.113.5/32 -m comment --comment "csf ui setup" -j ACCEPT\n} });
	my $fw = firewall($r, iptables => '/sbin/iptables');
	my $closed = $fw->close_port({
		kind => 'iptables', binary => '/sbin/iptables', chain => 'INPUT', wait => [],
		canonical => '-A INPUT -s 203.0.113.5/32 -m comment --comment "csf ui setup" -j ACCEPT',
	});
	is($closed->{ok}, 0, 'a quoted canonical line is refused');
	is($closed->{code}, 'E_UNREMOVABLE', 'with E_UNREMOVABLE');
	like($closed->{manual}, qr/csf ui setup/, 'and the operator is handed the line to act on');
	is($r->ran(qr/ -D /), 0, 'and nothing was deleted');
}
{
	# iptables says it removed the rule; the read-back says otherwise. The
	# read-back wins: "exited 0" and "the rule is gone" are different claims.
	my $r = FakeRunner->new
		->on(qr{ -D INPUT }, { exit => 0, output => '' })
		->on(qr{ -S INPUT\z}, { output => "-P INPUT ACCEPT\n-A INPUT -s 203.0.113.5/32 -j ACCEPT\n" });
	my $fw = firewall($r, iptables => '/sbin/iptables');
	my $closed = $fw->close_port({
		kind => 'iptables', binary => '/sbin/iptables', chain => 'INPUT', wait => [],
		canonical => '-A INPUT -s 203.0.113.5/32 -j ACCEPT',
	});
	is($closed->{ok}, 0, 'a successful-looking delete that did not delete is a failure');
	is($closed->{code}, 'E_REMOVE_FAILED', 'reported as E_REMOVE_FAILED');
	like($closed->{manual}, qr/-D INPUT/, 'with the command to run by hand');
}

###############################################################################
# Read-back failures at OPEN time. Something was added and cannot be seen:
# the operator is never told the port is open, and a best-effort undo is
# attempted so the hole does not simply stay there.
###############################################################################
{
	my $r = FakeRunner->new
		->on(qr{^/sbin/iptables --version\z}, { output => "iptables v1.8.7 (nf_tables)\n" })
		->on(qr{ -I INPUT 1 }, { exit => 0, output => '' })
		->on(qr{ -D INPUT },   { exit => 0, output => '' })
		->on(qr{ -S INPUT\z},  { output => "-P INPUT ACCEPT\n" });    # our rule is not there
	my $fw = firewall($r, iptables => '/sbin/iptables');
	my $out = $fw->open_port(port => 8443, address => '203.0.113.5');
	is($out->{ok}, 0, 'a rule that cannot be read back is not a successfully opened port');
	is($out->{code}, 'E_READBACK', 'reported as E_READBACK');
	is($r->ran(qr/ -D INPUT /), 1, 'and a best-effort undo was attempted');
	like($out->{reason}, qr/has been removed again/,
		'whose OUTCOME is reported - "took it back out" is a different situation from the next case');
}
{
	# The undo itself fails. Both refusals are refusals, but this one means
	# a rule is installed on the operator's machine that nothing is tracking
	# and nothing will ever remove - so it says so, with the command.
	my $r = FakeRunner->new
		->on(qr{^/sbin/iptables --version\z}, { output => "iptables v1.8.7 (nf_tables)\n" })
		->on(qr{ -I INPUT 1 }, { exit => 0, output => '' })
		->on(qr{ -D INPUT },   { exit => 1, output => "Bad rule\n" })
		->on(qr{ -S INPUT\z},  { output => "-P INPUT ACCEPT\n" });
	my $fw = firewall($r, iptables => '/sbin/iptables');
	my $out = $fw->open_port(port => 8443, address => '203.0.113.5');
	is($out->{ok}, 0, 'still a refusal');
	like($out->{reason}, qr/WORSE, it could not be removed again/,
		'but a LOUDER one - a rule nothing is tracking is the worst outcome this module has');
	like($out->{reason}, qr/-D INPUT/, 'and the operator is handed the command to run');
}
{
	# waitpid's own result. $? is a GLOBAL: if waitpid did not reap this
	# child, $? still holds whatever the last reaped child left there, and
	# reading it would mean reporting some other process's exit status as
	# this iptables mutation's.
	my $r = ConfigServer::UI::Firewall::_run_argv('/bin/true', 1);
	ok(!$r->{error}, 'the real runner reaps its own child and reports no error');
	is($r->{exit}, 0, 'and reads the exit status it actually waited for');

	# The hazard, reproduced: with SIGCHLD set to IGNORE the kernel reaps
	# children itself and waitpid returns -1 (ECHILD) having waited for
	# nothing. $? is then stale - here, deliberately poisoned with a
	# success - and a runner that read it would report exit 0 for a command
	# whose outcome it does not know.
	{
		local $SIG{CHLD} = 'IGNORE';

		# Whether this platform auto-reaps is established INDEPENDENTLY,
		# with a child of this test's own - not from the result under test.
		# Skipping on that result would make this block skip itself into a
		# pass the moment the guard it exists for was removed, which is
		# exactly the shape of test this project keeps finding.
		my $auto_reaps = do {
			my $pid = fork();
			if (defined $pid && !$pid) { POSIX::_exit(0) }
			if (defined $pid) {
				select(undef, undef, undef, 0.2);
				(waitpid($pid, 0) == -1) ? 1 : 0;
			}
			else { 0 }
		};

		SKIP: {
			skip 'this platform does not auto-reap under SIGCHLD=IGNORE', 2 unless $auto_reaps;
			$? = 0;   # the stale "success" a credulous reader would find
			my $orphan = ConfigServer::UI::Firewall::_run_argv('/bin/false', 2);
			like($orphan->{error}, qr/could not be reaped/,
				'a child that could not be reaped is an error, not an exit status');
			isnt($orphan->{exit}, 0, 'and never reports the stale success left in $?');
		}
	}
}
{
	my $r = FakeRunner->new
		->on(qr{^/sbin/iptables --version\z}, { output => "iptables v1.8.7 (nf_tables)\n" })
		->on(qr{ -I INPUT 1 }, { exit => 0, output => '' })
		->on(qr{ -S INPUT\z},  { output => join("\n",
			'-P INPUT ACCEPT',
			'-A INPUT -s 203.0.113.5/32 -p tcp -m comment --comment csf-ui-setup -m tcp --dport 8443 -j ACCEPT',
			'-A INPUT -s 198.51.100.9/32 -p tcp -m comment --comment csf-ui-setup -m tcp --dport 8443 -j ACCEPT') . "\n" });
	my $fw = firewall($r, iptables => '/sbin/iptables');
	my $out = $fw->open_port(port => 8443, address => '203.0.113.5');
	is($out->{ok}, 0, 'two rules with this session\'s comment on this port is a refusal');
	like($out->{reason}, qr/refusing to guess which one/, 'rather than a guess');
}
{
	my $r = FakeRunner->new
		->on(qr{^/sbin/iptables --version\z}, { output => "iptables v1.8.7 (nf_tables)\n" })
		->on(qr{^/sbin/iptables -w 5 -S INPUT\z}, { output => "-P INPUT ACCEPT\n" })
		->on(qr{^/sbin/iptables -S INPUT\z},  { output => "-P INPUT ACCEPT\n" })
		->on(qr{ -I INPUT 1 }, { exit => 2, output => "iptables: No chain/target/match by that name.\n" });
	my $fw = firewall($r, iptables => '/sbin/iptables');
	my $out = $fw->open_port(port => 8443, address => '203.0.113.5');
	is($out->{ok}, 0, 'an iptables that refuses the insert is a refusal here too');
	is($out->{code}, 'E_ADD_FAILED', 'reported as E_ADD_FAILED');
	like($out->{reason}, qr/No chain\/target\/match/, 'quoting what iptables said');
}
{
	# IPv6 operator address with no ip6tables to remove the rule with.
	my $r = FakeRunner->new
		->on(qr{^/sbin/iptables --version\z}, { output => "iptables v1.8.7 (nf_tables)\n" })
		->on(qr{ -S INPUT\z}, { output => "-P INPUT ACCEPT\n" });
	my $fw = firewall($r, iptables => '/sbin/iptables');
	my $out = $fw->open_port(port => 8443, address => '2001:db8::5');
	is($out->{ok}, 0, 'an IPv6 operator with no ip6tables is refused');
	like($out->{reason}, qr/ip6tables/, 'naming the missing binary');
	is($r->ran(qr/-I INPUT/), 0, 'and nothing was added');
}

###############################################################################
# firewalld: a RUNTIME rich rule, removed with the exact string firewalld
# itself printed, as ONE argv element.
###############################################################################
{
	my $r = FakeRunner->new;
	$r->{state}{rich} = [];
	$r->on(qr{^/usr/bin/firewall-cmd --state\z}, { output => "running\n" })
	  ->on(qr{^/usr/bin/firewall-cmd --add-rich-rule=}, sub {
			my ($self) = @_;
			# firewalld re-renders what it was given; the spacing is its own.
			push @{ $self->{state}{rich} },
				'rule family="ipv4" source address="203.0.113.5" port port="8443" protocol="tcp" accept';
			return { exit => 0, output => "success\n" };
		})
	  ->on(qr{^/usr/bin/firewall-cmd --remove-rich-rule=(.+)\z}, sub {
			my ($self, $argv) = @_;
			my ($rule) = $argv->[1] =~ /^--remove-rich-rule=(.*)\z/s;
			my $before = scalar @{ $self->{state}{rich} };
			@{ $self->{state}{rich} } = grep { $_ ne $rule } @{ $self->{state}{rich} };
			return { exit => (scalar(@{ $self->{state}{rich} }) < $before ? 0 : 1), output => '' };
		})
	  ->on(qr{^/usr/bin/firewall-cmd --list-rich-rules\z}, sub {
			my ($self) = @_;
			return { exit => 0, output => join("\n", @{ $self->{state}{rich} }) . "\n" };
		});

	my $fw = firewall($r, 'firewall-cmd' => '/usr/bin/firewall-cmd');
	my $out = $fw->open_port(port => 8443, address => '203.0.113.5');
	is($out->{ok}, 1, 'firewalld: the rich rule is added');
	is($out->{spec}{kind}, 'firewalld', 'and the spec knows how to remove it');
	is($r->ran(qr/--permanent/), 0,
		'and it is a RUNTIME rule - a reload or a reboot closes the hole by itself');

	my $closed = $fw->close_port($out->{spec});
	is($closed->{ok}, 1, 'firewalld: the rich rule is removed');
	is($closed->{removed}, 1, 'and something was actually removed');
	my ($remove) = grep { /--remove-rich-rule/ } $r->log_lines;
	like($remove, qr/\Q--remove-rich-rule=rule family="ipv4" source address="203.0.113.5" port port="8443" protocol="tcp" accept\E\z/,
		'removed with the exact string firewalld printed, in one argv element');
}

###############################################################################
# ufw: indices renumber, so the index used to delete comes from a listing
# read AT REMOVAL TIME, never from the one read when the rule was added.
###############################################################################
{
	my $r = FakeRunner->new;
	$r->{state}{numbered} = [];
	$r->on(qr{^/usr/sbin/ufw status\z}, { output => "Status: active\n" })
	  ->on(qr{^/usr/sbin/ufw insert 1 allow from }, sub {
			my ($self) = @_;
			$self->{state}{numbered} = ['8443/tcp ALLOW IN 203.0.113.5'];
			return { exit => 0, output => "Rule inserted\n" };
		})
	  ->on(qr{^/usr/sbin/ufw status numbered\z}, sub {
			my ($self) = @_;
			my $n = 0;
			my $text = "Status: active\n\n     To          Action      From\n     --          ------      ----\n";
			$text .= sprintf("[%2d] %s\n", ++$n, $_) for @{ $self->{state}{numbered} };
			return { exit => 0, output => $text };
		})
	  ->on(qr{^/usr/sbin/ufw --force delete ([0-9]+)\z}, sub {
			my ($self, $argv) = @_;
			my $index = $argv->[3];
			splice(@{ $self->{state}{numbered} }, $index - 1, 1);
			return { exit => 0, output => "Rule deleted\n" };
		});

	my $fw = firewall($r, ufw => '/usr/sbin/ufw');
	my $out = $fw->open_port(port => 8443, address => '203.0.113.5');
	is($out->{ok}, 1, 'ufw: the rule is added');
	is($out->{spec}{canonical}, '8443/tcp ALLOW IN 203.0.113.5',
		"the stored form is ufw's own rendering WITHOUT its index - indices renumber");

	# Somebody else adds two rules in front of ours before we clean up.
	unshift @{ $r->{state}{numbered} }, '22/tcp ALLOW IN Anywhere', '80/tcp ALLOW IN Anywhere';

	my $closed = $fw->close_port($out->{spec});
	is($closed->{ok}, 1, 'ufw: the rule is removed after a renumber');
	my ($delete) = grep { /--force delete/ } $r->log_lines;
	is($delete, '/usr/sbin/ufw --force delete 3',
		'deleted by the index it has NOW (3), not the index it had when it was added (1)');
	is(scalar @{ $r->{state}{numbered} }, 2, 'and the two other rules are untouched');
}
{
	# Two ufw rules that now render identically: refuse, do not guess.
	my $r = FakeRunner->new
		->on(qr{^/usr/sbin/ufw status numbered\z}, { output =>
			"Status: active\n\n[ 1] 8443/tcp ALLOW IN 203.0.113.5\n[ 2] 8443/tcp ALLOW IN 203.0.113.5\n" });
	my $fw = firewall($r, ufw => '/usr/sbin/ufw');
	my $closed = $fw->close_port({ kind => 'ufw', binary => '/usr/sbin/ufw',
		canonical => '8443/tcp ALLOW IN 203.0.113.5' });
	is($closed->{ok}, 0, 'two identical ufw rules is a refusal');
	is($closed->{code}, 'E_UNREMOVABLE', 'reported as E_UNREMOVABLE');
	is($r->ran(qr/--force delete/), 0, 'and neither was deleted');
}

###############################################################################
# close_port's own argument checking.
###############################################################################
{
	my $fw = firewall(FakeRunner->new);
	for my $case ([undef, 'nothing at all'], [{}, 'an empty spec'],
			[{ kind => 'iptables' }, 'a spec with no canonical text'],
			[{ canonical => '-A INPUT -j ACCEPT', kind => 'martian' }, 'an unknown backend kind']) {
		my ($spec, $label) = @$case;
		my $out = $fw->close_port($spec);
		is($out->{ok}, 0, "close_port refuses $label");
	}
	my $out = $fw->close_port({ kind => 'iptables', canonical => '-A INPUT -j ACCEPT' });
	is($out->{code}, 'E_SPEC', 'a spec with no binary is E_SPEC, not an exec of something else');
}

###############################################################################
# G2 - no shell, asserted about the source of all three new files, the same
# way t/11-helper-validate.t asserts it about the helper.
###############################################################################
{
	my @file = (
		"$FindBin::Bin/../ui-src/lib/ConfigServer/UI/Firewall.pm",
		"$FindBin::Bin/../ui-src/lib/ConfigServer/UI/Rollback.pm",
		"$FindBin::Bin/../ui-src/bin/csf-ui-setup",
	);
	for my $path (@file) {
		ok(-f $path, "$path exists");
		open(my $fh, '<', $path) or die "cannot read $path: $!";
		local $/;
		my $source = <$fh>;
		close $fh;
		my ($name) = $path =~ m{([^/]+)\z};
		unlike($source, qr/\x60/, "$name contains no backquote");
		unlike($source, qr/\bqx\s*[\{\(\[\/'"|!#]/, "$name contains no qx");
		unlike($source, qr/\bsystem\s*\(/, "$name never calls system");
		unlike($source, qr/\bopen\s*\([^;]*?['"][^'"\n]*\|/, "$name never opens a pipe to a command string");
		unlike($source, qr/^\s*exec\s+["']/m, "$name never execs a string");
	}

	open(my $fh, '<', "$FindBin::Bin/../ui-src/lib/ConfigServer/UI/Firewall.pm") or die;
	local $/;
	my $source = <$fh>;
	close $fh;
	like($source, qr/exec \{ \$argv\[0\] \} \@argv/,
		'the only exec is the block form, which cannot reach a shell even for a one-element list');
	my @exec = ($source =~ /^\s*exec\b/mg);
	is(scalar(@exec), 1, 'there is exactly one exec statement in Firewall.pm');
}

###############################################################################
# Binaries are resolved from a fixed list of directories, never from the
# inherited $PATH: this program runs as root and execs the firewall.
###############################################################################
{
	is_deeply(\@ConfigServer::UI::Firewall::SEARCH_DIRS,
		[qw(/sbin /usr/sbin /bin /usr/bin /usr/local/sbin /usr/local/bin)],
		'the search path is a fixed list in the source');

	open(my $fh, '<', "$FindBin::Bin/../ui-src/lib/ConfigServer/UI/Firewall.pm") or die;
	local $/;
	my $source = <$fh>;
	close $fh;
	unlike($source, qr/\$ENV\{PATH\}/, 'nothing in Firewall.pm reads $ENV{PATH}');

	# A name that could escape the search directories is not a name.
	for my $name ('../../bin/sh', '/bin/sh', 'ipt ables', '', undef) {
		is(ConfigServer::UI::Firewall::_locate($name), undef,
			'_locate refuses ' . (defined $name ? "\"$name\"" : 'undef'));
	}

	# And the default runner refuses a relative argv[0] outright, so even a
	# locate() that somehow returned one cannot become an exec of whatever
	# $PATH finds.
	my $result = ConfigServer::UI::Firewall::_run_argv('iptables', '-L', 1);
	is($result->{error}, 'argv[0] is not an absolute path',
		'the default runner refuses a relative argv[0]');
}

###############################################################################
# detect() caches, because the wizard asks more than once and each ask is a
# fork+exec.
###############################################################################
{
	my $r = FakeRunner->new
		->on(qr{^/sbin/iptables --version\z}, { output => "iptables v1.8.7 (legacy)\n" })
		->on(qr{^/sbin/iptables -S INPUT\z},  { output => "-P INPUT ACCEPT\n" });
	my $fw = firewall($r, iptables => '/sbin/iptables');
	$fw->detect for 1 .. 3;
	is($r->ran(qr/--version/), 1, 'detect() probes once and caches');
	$fw->detect(force => 1);
	is($r->ran(qr/--version/), 2, 'force => 1 re-probes');
}
