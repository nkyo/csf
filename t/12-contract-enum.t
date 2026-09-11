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
# docs/WEBUI-RPC.md section 3.5 is a closed enumeration of error codes. Twice now
# a task has added a trigger in one section and left that table stale - Task 1's
# round 2, then Task 2's - and both times it was caught by someone reading
# carefully. Nine tasks remain, each able to add a trigger, and a check that runs
# only when somebody remembers it is a check that will eventually be forgotten.
#
# WHAT THIS PROVES, exactly: every E_* token used anywhere in the document
# appears in the section 3.5 table.
#
# WHAT IT DOES NOT PROVE, and no one should read it as proving:
#
#   * that every enumerated code is still reachable in the code. A code deleted
#     from the helper but left in the table passes this test.
#   * that the table's *description* of a code is complete. A new reason for an
#     existing code - "the counter cannot be rewritten" under an E_UNAVAILABLE
#     that already existed - adds no new token, so this test stays green. That is
#     precisely the defect it was written after, and it is why the enumeration
#     still needs a human reading the diff. This test removes the cheaper half of
#     the job, not the job.
#   * anything about the helper's source. It reads one document.
###############################################################################
use strict;
use warnings;

use FindBin ();
use Test::More tests => 6;

my $CONTRACT = "$FindBin::Bin/../docs/WEBUI-RPC.md";

ok(-f $CONTRACT, 'the frozen contract is where every other task expects it');

open(my $fh, '<', $CONTRACT) or die "cannot read $CONTRACT: $!";
binmode($fh);
my @line = <$fh>;
close $fh;
chomp @line;

# --- the enumeration itself: the leading cell of each row of 3.5's table -----
my %enumerated;
my $in_table = 0;
for my $line (@line) {
	if ($line =~ /^#{2,4}\s/) {
		$in_table = ($line =~ /^###\s+3\.5\s/) ? 1 : 0;
		next;
	}
	next unless $in_table;
	next unless $line =~ /^\|\s*`(E_[A-Z_]+)`\s*\|/;
	$enumerated{$1} = 1;
}

cmp_ok(scalar(keys %enumerated), '>=', 10,
	'section 3.5 was found and parsed as a table of codes');

# --- every token the document uses, with where it was used ------------------
my %used;
my $section = '(before the first heading)';
for my $index (0 .. $#line) {
	my $line = $line[$index];
	if ($line =~ /^(#{1,4})\s+(.*)$/) {
		$section = $2;
		next;
	}
	for my $token ($line =~ /(E_[A-Z_]+)/g) {
		$used{$token} ||= { section => $section, line => $index + 1 };
	}
}

cmp_ok(scalar(keys %used), '>=', 10, 'the document uses error codes to check');

my @missing;
for my $token (sort keys %used) {
	next if $enumerated{$token};
	push @missing, sprintf('%s (first used at line %d, under "%s")',
		$token, $used{$token}{line}, $used{$token}{section});
}

is_deeply(\@missing, [],
	'every E_* token used in the contract is enumerated in the section 3.5 table')
	or diag(
		"These codes are used in docs/WEBUI-RPC.md but are not rows of the\n"
		. "section 3.5 table. Either add each one to that table - it is the closed\n"
		. "enumeration, and every other task reads it - or stop using it:\n\n  "
		. join("\n  ", @missing)
		. "\n\nThis check is one-directional: it finds tokens missing from the\n"
		. "enumeration. It cannot tell you that an enumerated code is still\n"
		. "reachable, and it cannot tell you that a row's description covers every\n"
		. "reason the code is now returned - a new trigger for an existing code\n"
		. "adds no new token. Read the diff for those.\n");

# --- and prove the check can fail, so a green run means something -----------
{
	my %pretend_enumerated = %enumerated;
	delete $pretend_enumerated{E_ARG};
	my @would_miss = grep { !$pretend_enumerated{$_} } sort keys %used;
	is_deeply(\@would_miss, ['E_ARG'],
		'with a row removed the same comparison names exactly the missing code');
}

# The helper carries one internal fault code that is deliberately absent from the
# contract, and that asymmetry is worth stating where the enumeration is checked
# rather than leaving it to be rediscovered as a discrepancy.
ok(!exists $used{E_TIMEOUT},
	'E_TIMEOUT is internal to the helper and never reaches the wire, so it is not a contract code');
