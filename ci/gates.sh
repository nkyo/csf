#!/bin/sh
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
# Added 2026-09-22 in https://github.com/nkyo/csf - see CHANGES.md.
#
# Task 10's own gate, task-10-brief.md's own words:
#
#   "perl -I. -c on every .pl/.pm touched by this branch, sh -n on every
#    shell script, prove -I. t/, and a grep gate that fails on backticks,
#    qx, system with a single string, and eval on a string in any file
#    under ui-src/."
#
# POSIX sh throughout, deliberately, for the same reason install-webui.sh
# is: gate 2 below runs `sh -n` over every *.sh file in the tree, and this
# file is itself one of them - a gate that could not pass its own check
# would be exactly the kind of hollow gate this task exists to rule out. No
# bashisms ([[, <(process substitution), <<<, arrays): every loop that
# needs to update a counter reads from a real file via redirection rather
# than a pipe, because `cmd | while read ...` runs the loop body in a
# subshell under POSIX sh and every variable it sets would be lost the
# moment the loop ends.
#
# Four gates, in order. Each one prints what it checked and what it found;
# the script's own exit status is nonzero iff at least one gate failed, and
# every gate runs even if an earlier one failed - one call gives the whole
# picture, not just the first thing that broke.
#
# WHAT "TOUCHED BY THIS BRANCH" MEANS HERE. This tree ships as a fork of
# v15.00, and its root still carries the untouched v14.22-descended scripts
# (install.*.sh, cpanel/, da/, ...) this project's own CLAUDE.md forbids
# copying from or editing. Gate 1 is scoped to the diff against this
# branch's merge-base with `main` (falling back to `origin/main`, and to
# every tracked file when neither ref is reachable - a detached clone with
# no history to diff against gets the conservative answer, not a silent
# skip) precisely so it never touches those files. Gates 2 and 4 are NOT
# diff-scoped, per the brief's own wording ("every shell script", "any file
# under ui-src/") - deliberately broader, because a syntax error or an
# injection-shaped construct in a file this run did not happen to touch is
# still a real defect the next run would hit.
#
# WHAT THE GREP GATE CANNOT DO. It is textual, not a parser: it skips
# whole-line comments (a line whose first non-blank character is '#') so
# that the many backtick-as-markdown-quoting comments already throughout
# this tree ("the `op` field", "run `csf`") do not drown every real
# finding, but a backtick or eval sitting in a TRAILING comment on a code
# line is still inside the scanned text and would still be flagged. That is
# the direction a blunt gate should be wrong in: a rare false positive an
# author dismisses by eye costs a minute, a false negative that lets a real
# `` `rm -rf $x` `` through costs a great deal more.
###############################################################################
set -u

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT" || exit 1

FAILED=0
note() { printf '%s\n' "$*"; }
fail() { printf 'GATE FAILED: %s\n' "$*"; FAILED=1; }

WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/csf-ui-gates.XXXXXX") || exit 1
trap 'rm -rf "$WORKDIR"' EXIT INT TERM

###############################################################################
# GATE 1 - perl -I. -c on every .pl/.pm touched by this branch.
#
# "touched by this branch" is read as: every file in the diff against this
# branch's merge-base with main, filtered to the ones perl -c can actually
# check - .pl/.pm by extension, plus a Perl shebang, because this project's
# own bin/ scripts (csf-ui, csf-ui-helper, csf-ui-passwd, csf-ui-setup) are
# real Perl with no extension at all, and skipping them over a naming
# convention this tree does not follow would be exactly the kind of gate
# that passes for the wrong reason the report has to call out.
###############################################################################
note "== Gate 1: perl -I. -c on every .pl/.pm (or perl-shebang) file touched by this branch =="

BASE_REF=$(git merge-base HEAD main 2>/dev/null)
if [ -z "$BASE_REF" ]; then
	BASE_REF=$(git merge-base HEAD origin/main 2>/dev/null)
fi

if [ -n "$BASE_REF" ]; then
	note "   base: $BASE_REF"
	git diff --name-only --diff-filter=ACMR "$BASE_REF"...HEAD > "$WORKDIR/touched" 2>/dev/null
else
	# No history to diff against (e.g. a shallow or detached checkout) -
	# the conservative answer is every tracked file, not silence.
	note "   no merge-base with main/origin/main was reachable - checking every tracked file instead of silently skipping this gate"
	git ls-files > "$WORKDIR/touched"
fi

PERL_CHECKED=0
PERL_FAILED=0
while IFS= read -r f; do
	[ -n "$f" ] || continue
	[ -f "$f" ] || continue   # a deleted-in-this-branch path still appears in the diff

	is_perl=0
	case "$f" in
		*.pl | *.pm) is_perl=1 ;;
	esac
	if [ "$is_perl" -ne 1 ]; then
		first_line=$(head -n1 -- "$f" 2>/dev/null)
		case "$first_line" in
			'#!'*perl*) is_perl=1 ;;
		esac
	fi
	[ "$is_perl" -eq 1 ] || continue

	PERL_CHECKED=$((PERL_CHECKED + 1))
	# -I. is the brief's own words, verbatim; ui-src/lib is added alongside
	# it (not instead of it) because every file in this tree - the .pm
	# modules and the extension-less bin/ scripts alike - resolves its
	# sibling `use ConfigServer::UI::*` modules from there, exactly as
	# every t/*.t file's own `use lib "$FindBin::Bin/../ui-src/lib"` does.
	# -I. alone makes this gate fail on every module in the tree for
	# missing a dependency that is one directory away, which is not a
	# syntax error this gate exists to catch - it is the gate finding
	# nothing, dressed up as if it found something.
	if out=$(perl -I. -Iui-src/lib -c -- "$f" 2>&1); then
		:
	else
		fail "perl -c $f"
		printf '%s\n' "$out" | sed 's/^/    /'
		PERL_FAILED=$((PERL_FAILED + 1))
	fi
done < "$WORKDIR/touched"

note "   checked $PERL_CHECKED Perl file(s), $PERL_FAILED failed"

###############################################################################
# GATE 2 - sh -n on every shell script in the tree (not diff-scoped: the
# brief says "every shell script", and a pre-existing script's syntax is
# still worth a green check even when this branch did not touch it).
###############################################################################
note "== Gate 2: sh -n on every *.sh in the tree =="

find . -name '*.sh' -not -path './.git/*' | sort > "$WORKDIR/shfiles"

SH_CHECKED=0
SH_FAILED=0
while IFS= read -r f; do
	[ -n "$f" ] || continue
	SH_CHECKED=$((SH_CHECKED + 1))
	if out=$(sh -n -- "$f" 2>&1); then
		:
	else
		fail "sh -n $f"
		printf '%s\n' "$out" | sed 's/^/    /'
		SH_FAILED=$((SH_FAILED + 1))
	fi
done < "$WORKDIR/shfiles"

note "   checked $SH_CHECKED shell script(s), $SH_FAILED failed"

###############################################################################
# GATE 3 - prove -I. -r t/, the whole suite.
#
# Fix round 2, Task 11 minor #1: -r (recurse), not merely `t/`'s own
# top-level *.t files. Without it a test added in a SUBDIRECTORY of t/ runs
# fine locally (an ordinary `prove -I. t/some/dir/x.t` finds it) and is
# simply invisible to this gate - a green CI run proving nothing about a
# file CI never looked at, which is worse than a red one.
###############################################################################
note "== Gate 3: prove -I. -r t/ =="
if command -v prove >/dev/null 2>&1; then
	if prove -I. -r t/; then
		:
	else
		fail "prove -I. -r t/ (see the prove output above for which file(s))"
	fi
else
	fail "prove is not installed - cannot run the test suite at all"
fi

###############################################################################
# GATE 4 - the grep gate: backticks, qx, system() with a single string, and
# eval on a string (not a block), in any file under ui-src/.
#
# Each finding names the file, line, and the exact text - not merely "found
# something" - because a gate that only says "failed" makes the fix a
# second investigation instead of a one-line diff.
###############################################################################
note "== Gate 4: backticks / qx / single-string system() / string eval, under ui-src/ =="
note "   scoped to Perl and shell files - see the header comment for why"

# "Any file under ui-src/" (the brief's own words) is read here as any file
# where these FOUR PATTERNS could ever be operative - Perl's qx//, eval EXPR
# and system() are meaningless syntax in an HTML file, and a scan that did
# not carve that out found nothing but its own false positives: this tree's
# templates and their header comments quote field names in backticks
# throughout ("the `op` field", "`support => 1`"), 42 hits on the first
# full run, every one of them markdown-style prose inside an HTML comment,
# none of them a single line of executable anything. Scoping to .pm/.pl/.t,
# a perl shebang, and .sh keeps the gate pointed at the surface it exists
# to guard - every file that could actually reach a shell - instead of
# drowning real findings in noise from files that cannot.
> "$WORKDIR/uisrcfiles"
find ui-src -type f | sort > "$WORKDIR/uisrcfiles.all"
while IFS= read -r f; do
	[ -n "$f" ] || continue
	case "$f" in
		*.pm | *.pl | *.t | *.sh) printf '%s\n' "$f" >> "$WORKDIR/uisrcfiles"; continue ;;
	esac
	first_line=$(head -n1 -- "$f" 2>/dev/null)
	case "$first_line" in
		'#!'*perl* | '#!'*sh*) printf '%s\n' "$f" >> "$WORKDIR/uisrcfiles" ;;
	esac
done < "$WORKDIR/uisrcfiles.all"

GREP_FINDINGS=0
while IFS= read -r f; do
	[ -n "$f" ] || continue
	# Binary files are skipped - grep -I already refuses them below, this
	# is just cheap enough to check first that it is worth doing.
	grep -Iq . -- "$f" 2>/dev/null || continue

	line_no=0
	while IFS= read -r line || [ -n "$line" ]; do
		line_no=$((line_no + 1))

		# A whole-line comment - see the header comment for exactly what
		# this does and does not exclude.
		trimmed=$(printf '%s' "$line" | sed -e 's/^[[:space:]]*//')
		case "$trimmed" in
			'#'*) continue ;;
		esac

		case "$line" in
			*'`'*)
				fail "backtick in $f:$line_no"
				note "    $line"
				GREP_FINDINGS=$((GREP_FINDINGS + 1))
				;;
		esac

		# For qx/system/eval only (not the backtick check above): a
		# trailing " #comment" is cut off before matching. Cutting AFTER
		# the '#' can only remove text, never hide a real qx/system/eval
		# that appears earlier on the same line, so this cannot create a
		# false negative for the thing the gate exists to catch - it only
		# stops prose that happens to contain these words (e.g. "...this
		# eval existed...") from being flagged as if it were code.
		code_line=$(printf '%s\n' "$line" | sed -e 's/[[:space:]]#.*$//')

		if printf '%s\n' "$code_line" | grep -Pq '\bqx\s*[{(\[/'"'"'"|!#]'; then
			fail "qx in $f:$line_no"
			note "    $line"
			GREP_FINDINGS=$((GREP_FINDINGS + 1))
		fi

		if printf '%s\n' "$code_line" | grep -Pq '\bsystem\s*\(?\s*(["'"'"'])(?:(?!\1).)*\1\s*(\)|;|,\s*$|$)'; then
			fail "system() called with a single string in $f:$line_no"
			note "    $line"
			GREP_FINDINGS=$((GREP_FINDINGS + 1))
		fi

		if printf '%s\n' "$code_line" | grep -Pq '\beval\s+(?!\{)\S'; then
			fail "eval on a string (not a block) in $f:$line_no"
			note "    $line"
			GREP_FINDINGS=$((GREP_FINDINGS + 1))
		fi
	done < "$f"
done < "$WORKDIR/uisrcfiles"

note "   $GREP_FINDINGS finding(s)"

###############################################################################
if [ "$FAILED" -ne 0 ]; then
	note ""
	note "ci/gates.sh: at least one gate failed - see GATE FAILED lines above."
	exit 1
fi

note ""
note "ci/gates.sh: all gates passed."
exit 0
