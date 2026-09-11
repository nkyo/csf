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
# ConfigServer::UI::Render - task-6-brief.md's own words: "the one
# genuinely dangerous thing in this task is escaping ... A missed escape
# is stored XSS in the administrative interface of a firewall". This file
# tests it like an adversary rather than a formality: a <script> payload
# in every position a template author could plausibly put a placeholder,
# quote-breakout payloads in both attribute-quoting styles, a value that
# is itself template syntax (proving substitution is single-pass and
# never re-expands what it just inserted), the raw marker requiring an
# explicit three-brace opt-in with the two-brace default never granting
# it, and a missing/undef/reference-typed var being a die() naming the
# key rather than a blank landing silently in the page.
#
# Every payload's expected output below was independently computed by
# hand from escape_html()'s documented order (& first, then < > " ', so
# the & introduced by the later four is never re-escaped) and cross-
# checked against a throwaway script run against this module before this
# file was written - not copied from whatever the implementation
# happened to print, which would make a bug and its test agree with each
# other for the wrong reason.
###############################################################################
use strict;
use warnings;

use FindBin ();
use lib "$FindBin::Bin/..", "$FindBin::Bin/../ui-src/lib";

use File::Find ();
use File::Temp qw(tempdir);
use Test::More tests => 115;

require_ok('ConfigServer::UI::Render');

# No Exporter anywhere in this codebase (ConfigServer::UI::Proto,
# ::Session, ... are all called fully qualified) - Render.pm follows the
# same convention, so every call below goes through the package name.
sub render      { return ConfigServer::UI::Render::render(@_) }
sub render_file { return ConfigServer::UI::Render::render_file(@_) }
sub esc         { return ConfigServer::UI::Render::escape_html(@_) }

###############################################################################
# escape_html() in isolation.
###############################################################################
is(esc('&'), '&amp;', 'escape_html: ampersand');
is(esc('<'), '&lt;',  'escape_html: less-than');
is(esc('>'), '&gt;',  'escape_html: greater-than');
is(esc('"'), '&quot;', 'escape_html: double-quote');
is(esc("'"), '&#39;', 'escape_html: single-quote');

# Order matters: & must run first, or the &amp;/&lt;/&gt;/&quot;/&#39;
# this call itself introduces would be mangled into &amp;amp; etc. One
# call proves all five in combination, in one pass.
is(esc(q{&<>"'}), '&amp;&lt;&gt;&quot;&#39;',
	'escape_html: all five together, in order, without double-escaping the & the others introduce');

is(esc('plain text, no specials'), 'plain text, no specials',
	'escape_html: text with none of the five characters passes through unchanged');
is(esc('0'), '0', 'escape_html: the string "0" (defined but false) is preserved, not blanked');
is(esc(''), '', 'escape_html: empty string is preserved, not treated as an error');
is(esc(42), '42', 'escape_html: a plain number is stringified correctly');

eval { esc(undef) };
like($@, qr/value is undef/, 'escape_html: undef dies, naming the problem');

eval { esc([1, 2]) };
like($@, qr/reference/, 'escape_html: an arrayref dies, naming it a reference');

eval { esc({ a => 1 }) };
ok($@, 'escape_html: a hashref dies');

eval { esc(sub { 1 }) };
ok($@, 'escape_html: a coderef dies');

###############################################################################
# render(): the default {{key}} form escapes a <script> payload in every
# position a template author could plausibly place one - start, middle,
# end, inside each attribute-quoting style, two placeholders back to
# back with no separator between them, and as the entire template.
# task-6-brief.md: "<script> in every substitution position".
###############################################################################
{
	my $payload  = '<script>alert(1)</script>';
	my $escaped  = '&lt;script&gt;alert(1)&lt;/script&gt;';
	my %vars     = (v => $payload);

	my %position = (
		'start of template'                 => ['{{v}}<p>end</p>',                       "$escaped<p>end</p>"],
		'middle of template'                => ['<p>before</p>{{v}}<p>after</p>',         "<p>before</p>$escaped<p>after</p>"],
		'end of template'                   => ['<p>start</p>{{v}}',                      "<p>start</p>$escaped"],
		'inside a double-quoted attribute'  => ['<a href="#" title="{{v}}">x</a>',         qq{<a href="#" title="$escaped">x</a>}],
		'inside a single-quoted attribute'  => [q{<a href='#' title='{{v}}'>x</a>},        qq{<a href='#' title='$escaped'>x</a>}],
		'two placeholders back to back'     => ['{{v}}{{v}}',                             "$escaped$escaped"],
		'the entire template'               => ['{{v}}',                                  $escaped],
	);

	for my $name (sort keys %position) {
		my ($template, $expect) = @{ $position{$name} };
		my $out = render($template, \%vars);
		unlike($out, qr/<script>/, "script payload not literal, $name");
		is($out, $expect, "script payload fully escaped, $name");
	}
}

###############################################################################
# Quote breakouts in attribute context - task-6-brief.md names this
# explicitly. Exact-string comparison, not merely "no longer contains a
# bare quote": a weaker regex check could pass while the attribute is
# still broken in a way the regex did not think to look for.
###############################################################################
{
	my $dq_payload = q{" onmouseover="alert(1)};
	my $dq_out = render(q{<input type="text" value="{{val}}">}, { val => $dq_payload });
	is($dq_out, q{<input type="text" value="&quot; onmouseover=&quot;alert(1)">},
		'attribute breakout: a double-quote in the value cannot end the double-quoted attribute early');

	my $sq_payload = q{' onmouseover='alert(1)};
	my $sq_out = render(q{<input type='text' value='{{val}}'>}, { val => $sq_payload });
	is($sq_out, q{<input type='text' value='&#39; onmouseover=&#39;alert(1)'>},
		'attribute breakout: a single-quote in the value cannot end the single-quoted attribute early');

	# Combines a quote breakout with a tag breakout in one payload: even
	# if the quote alone were mishandled, the < and > must still stop a
	# literal </script> or <script> from reappearing in the markup.
	my $combo_payload = q{"><script>alert(1)</script>};
	my $combo_out = render(q{<input type="text" value="{{val}}">}, { val => $combo_payload });
	is($combo_out, q{<input type="text" value="&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;">},
		'attribute breakout: a combined quote+tag payload is fully neutralised, not just the quote');
}

###############################################################################
# The raw marker requires an explicit, different marker to opt in -
# task-6-brief.md: "a raw insert requires an explicitly different marker
# so that forgetting is safe rather than dangerous".
###############################################################################
{
	my %vars = (v => '<b>bold</b>');

	is(render('{{v}}', \%vars), '&lt;b&gt;bold&lt;/b&gt;',
		'raw opt-in: the two-brace default form always escapes, even markup that looks harmless');
	unlike(render('{{v}}', \%vars), qr/<b>/,
		'raw opt-in: the two-brace default form never lets a literal tag through');

	is(render('{{{v}}}', \%vars), '<b>bold</b>',
		'raw opt-in: the three-brace form inserts the value unchanged, byte for byte');

	# The raw marker is a real bypass, not a filtered "mostly safe"
	# insert - it must not quietly sanitise a dangerous payload either,
	# because a caller that reaches for {{{ }}} is asserting the value
	# is already safe, not asking this module to make it so.
	is(render('{{{v}}}', { v => '<script>alert(1)</script>' }), '<script>alert(1)</script>',
		'raw opt-in: the three-brace form is a genuine bypass, not a second escaping path');
}

###############################################################################
# Malformed or mismatched brace counts are not magic: they simply do not
# match either marker and pass through as literal template text, even
# when a matching key exists in vars. This is what makes "forgetting is
# safe" true in the other direction too - there is no near-miss spelling
# that accidentally goes raw.
###############################################################################
{
	is(render('{v}} start', { v => 'X' }), '{v}} start',
		'malformed marker: a single leading brace is not a placeholder');
	is(render('{{v} end', { v => 'X' }), '{{v} end',
		'malformed marker: a single trailing brace is not a placeholder');
	is(render('{{ v }}', { v => 'X' }), '{{ v }}',
		'malformed marker: whitespace inside the braces is not a placeholder');
	is(render('{{1abc}}', { '1abc' => 'X' }), '{{1abc}}',
		'malformed marker: a key starting with a digit is not a placeholder');
}

###############################################################################
# A substituted value that is itself template syntax is never re-scanned
# for placeholders of its own - task-6-brief.md: "a value that is itself
# a {{key}}". Proven three ways: literal recursion on the SAME key would
# never terminate if it were tried; a raw-inserted value containing a
# placeholder for a key that plain does not exist in %vars must not die,
# because a recursive implementation is the only way that die could ever
# be reached; and a value that spells another real key's raw marker must
# never pull that other key's value in.
###############################################################################
{
	is(render('{{a}}', { a => 'prefix {{a}} suffix' }), 'prefix {{a}} suffix',
		'no re-expansion: a value containing its own placeholder text renders as inert literal text, not infinitely');

	my $out_b = eval { render('{{{a}}}', { a => 'prefix {{{b}}} suffix' }) };
	ok(!$@, 'no re-expansion: a raw value containing {{{b}}} does not die even though b is not in vars')
		or diag("died with: $@");
	is($out_b, 'prefix {{{b}}} suffix',
		'no re-expansion: that raw value is inserted exactly as written, not processed as a second template');

	my $out_c = render('{{a}}', { a => '{{{c}}}', c => 'evil-if-expanded' });
	is($out_c, '{{{c}}}',
		"no re-expansion: a value spelling another key's raw marker renders as inert text");
	unlike($out_c, qr/evil-if-expanded/,
		"no re-expansion: that other key's real value is never pulled in");
}

###############################################################################
# Fail closed: missing, undef or reference-typed variables are a die(),
# never a blank. task-6-brief.md: "A missing key must be an error, not a
# silently empty string".
###############################################################################
{
	eval { render('{{missing}}', {}) };
	ok($@, 'missing key (escaped marker): dies');
	like($@, qr/missing template variable 'missing'/, 'missing key (escaped marker): message names the key');

	eval { render('{{{missing}}}', {}) };
	ok($@, 'missing key (raw marker): dies');
	like($@, qr/missing template variable 'missing'/, 'missing key (raw marker): message names the key');

	eval { render('{{v}}', { v => undef }) };
	ok($@, 'present-but-undef value: dies');
	like($@, qr/is undef/, 'present-but-undef value: message distinguishes undef from missing');

	eval { render('{{v}}', { v => [1, 2] }) };
	ok($@, 'present-but-arrayref value: dies');

	eval { render('{{{v}}}', { v => { a => 1 } }) };
	ok($@, 'present-but-hashref value on the RAW marker also dies (the type check is not skipped for raw)');

	eval { render('x', undef) };
	ok($@, 'vars => undef: dies');
	eval { render('x', [1, 2]) };
	ok($@, 'vars => arrayref: dies');
	eval { render('x', 'not a ref') };
	ok($@, 'vars => plain scalar: dies');

	eval { render(undef, {}) };
	ok($@, 'template => undef: dies');
	eval { render(['x'], {}) };
	ok($@, 'template => reference: dies');

	my $result = eval { render('{{missing}}', {}) };
	ok(!defined $result, 'a dying render() never returns a partial or blank page to the caller');
}

###############################################################################
# Purity: render() has no state across calls and does not mutate its
# arguments.
###############################################################################
{
	my %vars = (v => 'x');
	my $first  = render('{{v}}-{{v}}', \%vars);
	my $second = render('{{v}}-{{v}}', \%vars);
	is($first, $second, 'purity: the same template and vars render identically on a second call');

	is_deeply(\%vars, { v => 'x' }, 'purity: the vars hashref is not mutated by render()');

	my $template = '{{v}}';
	render($template, \%vars);
	is($template, '{{v}}', 'purity: the template string argument is not mutated by render()');
}

###############################################################################
# render_file(): a thin wrapper over render() that reads the whole file
# as raw bytes. docs/WEBUI-RPC.md S14.2's byte-vs-character rule is
# reproduced here rather than only in the request path this module has
# nothing to do with - a value round-tripped through this module must
# never end up with Perl's internal UTF-8 flag set, because everything
# downstream of it (the HTTP response body) is sent as raw bytes
# verbatim.
###############################################################################
{
	my $dir = tempdir(CLEANUP => 1);

	my $path = "$dir/tmpl.html";
	open(my $fh, '>:raw', $path) or die "test setup: cannot write $path: $!";
	print { $fh } '<p>{{greeting}}, {{name}}!</p>';
	close $fh;

	is(render_file($path, { greeting => 'Hello', name => 'World' }), '<p>Hello, World!</p>',
		'render_file: reads the template from disk and substitutes correctly');

	# A multi-byte UTF-8 sequence (the two bytes of U+00E9, "e" with an
	# acute accent, 0xC3 0xA9) sitting in the LITERAL part of the
	# template, untouched by any placeholder.
	my $utf8_path = "$dir/utf8.html";
	open(my $ufh, '>:raw', $utf8_path) or die "test setup: cannot write $utf8_path: $!";
	print { $ufh } "caf\xC3\xA9 {{v}}";
	close $ufh;

	my $utf8_out = render_file($utf8_path, { v => 'ok' });
	is(length($utf8_out), length("caf\xC3\xA9 ok"),
		'render_file: a multi-byte UTF-8 sequence in the template is preserved byte for byte (length)');
	is($utf8_out, "caf\xC3\xA9 ok",
		'render_file: a multi-byte UTF-8 sequence in the template is preserved byte for byte (content)');
	ok(!utf8::is_utf8($utf8_out),
		q{render_file: Perl's internal UTF-8 flag is never set on the result (docs/WEBUI-RPC.md S14.2's rule)});

	# The same multi-byte sequence, this time arriving through a
	# SUBSTITUTED value that also needs escaping, proving escape_html's
	# byte-level scan for &<>"' never corrupts a multi-byte character -
	# every UTF-8 continuation/lead byte is >= 0x80, so none of those
	# five ASCII bytes can ever occur inside one.
	my $mixed_out = render('{{note}}', { note => "caf\xC3\xA9 <script>" });
	is($mixed_out, "caf\xC3\xA9 &lt;script&gt;",
		'render: a multi-byte UTF-8 byte sequence survives escaping unchanged while adjacent ASCII is escaped');

	eval { render_file("$dir/does-not-exist.html", {}) };
	ok($@, 'render_file: a nonexistent path dies');
	like($@, qr/does-not-exist\.html/, 'render_file: the die message names the path');

	eval { render_file(undef, {}) };
	ok($@, 'render_file: an undef path dies');
}

###############################################################################
# R38 (fix round 1, spec review): the boundary between where {{ }} is safe
# and where it is not - documented in Render.pm's and layout.html's own
# header comments as element content and quoted attributes only, NEVER a
# <script>/<style> body, an event-handler attribute, or a URL-bearing
# attribute - was, until this round, enforced by nothing but that comment.
# Task 7 adds five screens directly on top of this file with nothing
# stopping any of them from writing {{value}} inside an onclick or an href.
# The reviewer also punctured the fallback comfort of "tag/quote entities
# survive inside <script> anyway": a value ending in an unescaped backslash
# still corrupts a JS string literal there, escaped or not, so the boundary
# is not merely undefended, it is not as forgiving as it looks when crossed
# either. This section turns the boundary into a test - the third landmine
# of this exact shape in the project (an unbound @ROUTES table, a read sized
# by a literal that happened to equal its cap, now an undefended escaping
# context boundary), each time ruled into enforcement rather than left as
# description.
#
# _find_unsafe_placeholders() is a text scan, not an HTML parser: <script>/
# <style> bodies, on*=/href=/src=/action= attribute values, and (R40,
# below) ANY unquoted attribute value are located with regexes, and each
# is checked only for the literal substring "{{" - deliberately not
# distinguishing the escaped {{key}} marker from the raw {{{key}}} one,
# because neither is safe in any of these positions and a value that only
# ever needs the raw marker should not have been attacker-reachable text
# to begin with. This can be fooled by sufficiently contrived markup the
# way any regex-based scan can (a <script> tag split by an HTML comment,
# for instance); it is a trip-wire for the ordinary way this gets broken -
# a screen author reaching for the nearest placeholder while wiring up an
# onclick - not a proof that the rule can never be violated. Said here
# plainly rather than left for a re-review to notice: this test's
# advertised scope is "the ordinary mistake", not "every mistake".
#
# R40 (fix round 2, live-verified by the reviewer): the on*/href/src/action
# check above only matches a QUOTED value ((["'])(.*?)\2) - an unquoted
# attribute, legal HTML5 (<a href={{evil}}>), bypassed detection entirely.
# This is not merely a scanner gap: escape_html() does not escape spaces,
# so an unquoted value containing one does not just break out of the
# value, it injects a whole new attribute - onmouseover is one space away.
# Enumerating "the dangerous attributes" is the wrong shape for the
# unquoted case, because without quotes EVERY attribute is injectable, not
# only on*/href/src/action - so the fix below flags {{ in an unquoted
# value regardless of the attribute's name, as an addition alongside the
# quoted checks above, not a replacement for them.
#
# Other evasion candidates raised in the round 2 review, checked
# individually rather than assumed (see the positive/negative controls
# below this sub, and task-6-report.md for the input/scanner/render()
# table on each):
#   - single-quoted attributes: already handled - (["'])(.*?)\2 matches
#     either quote character via backreference, not only ".
#   - uppercase ONCLICK/HREF: already handled - every while loop below
#     carries /i.
#   - <script> carrying attributes or a type: already handled -
#     <script\b[^>]*> consumes any attributes before the opening tag's >.
#   - whitespace around an attribute's =: already handled - \s*=\s*
#     already allows it on both sides.
#   - {{ split across a line inside a script body: already handled for
#     the ordinary case (dotall /s lets (.*?) cross the newline) - but see
#     the "split across a literal {{" negative control below for the one
#     sub-case that is NOT live, and why.
#
# R41 (fix round 3, live-verified): a placeholder used AS THE ATTRIBUTE
# NAME, not its value - <div {{attr}}="{{val}}"> lets the substituted
# value choose which attribute exists at all (onclick, onerror, ...).
# render() was confirmed to actually do this: with vars (attr=>'onclick',
# val=>'alert(1)') that template becomes a live
# <div onclick="alert(1)">. escape_html() only ever escapes a VALUE;
# nothing it does touches a NAME, so a name position is dangerous
# regardless of which marker is used or how the value is quoted - the
# check below fires on the placeholder syntax appearing immediately
# before '=', before any of the value-position checks run.
#
# R43 (fix round 3, live-verified): the round-2 unquoted-attribute check
# (R40) matched against the WHOLE document text, with no requirement
# that it actually be inside a tag - so "<p>Max attempts = {{max}}</p>",
# ordinary element content with no attribute anywhere in it, was
# misread as an unquoted attribute named "attempts". That is exactly
# the shape Task 7's Overview screen was going to write
# ("<div class=\"stat\">Blocked count = {{count}}</div>"), and a guard
# that blocks correct work is a guard someone disables - at which point
# R40 and R41 stop being theoretical again. Fixed by requiring REAL TAG
# CONTEXT: every attribute-level check (R41's name check, on*, href/
# src/action, and R40's unquoted-any) now runs only against the region
# TAG_RE captures between a tag's name and its closing '>', never
# against text that sits between tags. "<p>" contributes an empty
# region; the prose after it is never handed to any attribute check at
# all, because nothing in it is preceded by an actual '<tagname'.
###############################################################################
sub _find_unsafe_placeholders {
	my ($html) = @_;
	my @findings;

	while ($html =~ m{<script\b[^>]*>(.*?)</script>}gis) {
		push @findings, '<script> block' if index($1, '{{') >= 0;
	}
	while ($html =~ m{<style\b[^>]*>(.*?)</style>}gis) {
		# Beyond what R38 asked for, added for consistency with the SCOPE
		# OF THE ESCAPING paragraph in Render.pm's own header comment,
		# which names <style>/CSS alongside <script> as unsafe - leaving
		# it out here would mean this module documents a fourth unsafe
		# context and enforces only three of them.
		push @findings, '<style> block' if index($1, '{{') >= 0;
	}

	# R43: every check in this loop body sees only $region - the text
	# between a tag's name and its own closing '>' - never the whole
	# document, so element content between tags can never be mistaken
	# for an attribute.
	while ($html =~ m{<[a-zA-Z][a-zA-Z0-9-]*([^>]*)>}gis) {
		my $region = $1;

		# R41: checked first, before any value-position check, because
		# a placeholder in name position is dangerous on its own,
		# independent of whatever the value turns out to be.
		while ($region =~ m{(\{\{\{?[A-Za-z_][A-Za-z0-9_]*\}\}\}?)\s*=}gs) {
			push @findings, "placeholder used as an attribute name ('$1')";
		}

		while ($region =~ m{\s(on[a-zA-Z]+)\s*=\s*(["'])(.*?)\2}gis) {
			push @findings, "event-handler attribute '$1'" if index($3, '{{') >= 0;
		}
		while ($region =~ m{\s(href|src|action)\s*=\s*(["'])(.*?)\2}gis) {
			push @findings, "URL-bearing attribute '$1'" if index($3, '{{') >= 0;
		}
		# R40: any attribute at all, unquoted. The negative lookahead
		# (?!["']) is what keeps this from double-counting the quoted
		# cases already caught above - it only matches when the
		# character right after = (and any whitespace) is neither
		# quote, i.e. genuinely unquoted. The value itself is captured
		# up to the next whitespace or '>' (which R43's $region never
		# contains, having already been trimmed to it by TAG_RE), which
		# is where HTML5 ends an unquoted attribute value.
		while ($region =~ m{\s([a-zA-Z][a-zA-Z0-9:_-]*)\s*=\s*(?!["'])([^\s>]+)}gis) {
			push @findings, "unquoted attribute '$1'" if index($2, '{{') >= 0;
		}
	}

	return @findings;
}

###############################################################################
# R42 (fix round 3, live-verified): DO NOT try to enumerate every unsafe
# CONTEXT for the raw marker - that set is unbounded, and this round is
# the proof. {{{v}}} placed after a </script> that itself sits inside a
# JS string renders as live, unescaped markup
# (<img src=x onerror=alert(1)> for real): the browser's HTML tokenizer
# ends a <script> element at the literal byte sequence "</script>"
# regardless of JS string-quoting context, so everything after it -
# including a {{{v}}} the template author may have believed was still
# "inside the script" - is parsed as ordinary HTML. Nothing about that
# position LOOKS unsafe to a context-based scanner: by the time the raw
# marker is reached, it is sitting in perfectly ordinary element
# content, which is the raw marker's own legitimate use case. A
# context-based blocklist cannot tell those two apart, because they are
# not different in shape, only in which key is being substituted - and
# that is exactly why R41 and this both belong to the same underlying
# lesson: value-position checks (R38/R40/R41 above) cannot be the whole
# answer for a mechanism whose entire point is "insert this without any
# check at all."
#
# Checked and confirmed NOT the same danger for the escaped marker: the
# same position with {{v}} (not {{{v}}}) renders as harmless escaped
# text, because escape_html() already makes a value safe as ordinary
# element content - which is exactly what it becomes here. The finding
# is specifically about the raw marker.
#
# So: an ALLOWLIST of where the raw marker is legitimately used, not a
# blocklist of where it is dangerous. That set is small and already
# known - today, exactly layout.html's {{{nav}}} and {{{content}}}
# slots (documented at the top of layout.html itself, Task 6's own
# contract with Task 7). Every {{{key}}} anywhere under ui-src/web/
# that is not on this list is flagged, regardless of what surrounds it,
# regardless of whether the surrounding context looks safe.
###############################################################################
our %RAW_MARKER_ALLOWLIST = (
	'ui-src/web/layout.html' => { nav => 1, content => 1 },
);

sub _find_unauthorized_raw_markers {
	my ($html, $rel_path) = @_;
	my @findings;
	my $allowed = $RAW_MARKER_ALLOWLIST{$rel_path} || {};

	while ($html =~ m{\{\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}\}}gs) {
		my $key = $1;
		push @findings, "unauthorized raw marker '{{{$key}}}' (not on the allowlist for $rel_path)"
			unless $allowed->{$key};
	}

	return @findings;
}

###############################################################################
# R44 (fix round 3): the file walk below used to match "\.html\z" with
# no /i, so a screen saved as SCREEN.HTML (or any other case) was never
# scanned at all - a silent skip in the one guard standing between
# Task 7 and this whole class of mistake. Factored out so the R44
# regression has something concrete to call directly against a
# synthetic directory, rather than only exercising it indirectly
# through the real ui-src/web walk below.
###############################################################################
sub _html_files_under {
	my ($dir) = @_;
	my @files;
	File::Find::find({
		wanted   => sub { push @files, $File::Find::name if /\.html\z/i },
		no_chdir => 1,
	}, $dir);
	return sort @files;
}

# Positive controls: prove the scanner actually catches each of the four
# danger categories, using synthetic markup rather than trusting the regex
# by inspection alone.
{
	my @f;

	@f = _find_unsafe_placeholders('<script>var x = "{{v}}";</script>');
	ok((grep { /script/ } @f), 'context scan: {{ inside a <script> block is flagged');

	@f = _find_unsafe_placeholders('<style>.x { color: {{v}}; }</style>');
	ok((grep { /style/ } @f), 'context scan: {{ inside a <style> block is flagged');

	@f = _find_unsafe_placeholders(q{<button onclick="go('{{v}}')">Go</button>});
	ok((grep { /onclick/ } @f), 'context scan: {{ inside an onclick attribute is flagged');

	@f = _find_unsafe_placeholders('<a href="{{path}}">x</a>');
	ok((grep { /href/ } @f), 'context scan: {{ inside an href attribute is flagged');

	@f = _find_unsafe_placeholders('<img src="{{img}}">');
	ok((grep { /src/ } @f), 'context scan: {{ inside a src attribute is flagged');

	@f = _find_unsafe_placeholders('<form action="{{target}}">');
	ok((grep { /action/ } @f), 'context scan: {{ inside an action attribute is flagged');
}

# R40 positive controls: the unquoted case the reviewer found live
# (<a href={{evil}}>), an unquoted attribute with a name outside the
# on*/href/src/action enumeration entirely (proving the fix really is
# "any attribute", not a fifth name added to the list), and the other
# evasion candidates the same review raised - single vs. double quotes,
# case, a <script> tag carrying its own attributes, a script body split
# across lines, and whitespace around =.
{
	my %case = (
		'the exact R40 example: unquoted href'
			=> ['<a href={{evil}}>x</a>',                                qr/unquoted attribute 'href'/],
		'unquoted attribute outside the href/src/action/on* enumeration'
			=> ['<div data-id={{v}}>x</div>',                            qr/unquoted attribute 'data-id'/],
		'single-quoted href (not only double-quoted)'
			=> [q{<a href='{{evil}}'>x</a>},                             qr/URL-bearing attribute 'href'/],
		"single-quoted onclick (not only double-quoted)"
			=> [q{<button onclick='alert({{v}})'>go</button>},           qr/event-handler attribute 'onclick'/],
		'uppercase HREF'
			=> ['<A HREF="{{evil}}">x</A>',                              qr/URL-bearing attribute 'HREF'/],
		'uppercase ONCLICK'
			=> ['<BUTTON ONCLICK="{{v}}">go</BUTTON>',                   qr/event-handler attribute 'ONCLICK'/],
		'a <script> tag carrying its own attributes (type=)'
			=> ['<script type="text/javascript">var x = "{{v}}";</script>', qr/script/],
		'a <script> body split across multiple lines'
			=> ["<script>\nvar x = \"{{v}}\";\n</script>",               qr/script/],
		'whitespace around = on a quoted attribute'
			=> ['<a href = "{{evil}}">x</a>',                            qr/URL-bearing attribute 'href'/],
		'whitespace around = on an unquoted attribute'
			=> ['<a href = {{evil}}>x</a>',                              qr/unquoted attribute 'href'/],
	);

	for my $name (sort keys %case) {
		my ($html, $expect) = @{ $case{$name} };
		my @f = _find_unsafe_placeholders($html);
		ok((grep { $_ =~ $expect } @f), "context scan: $name is flagged");
	}
}

# R41 positive controls: a placeholder used AS the attribute name -
# live-verified against the real render() first (see task-6-report.md
# for the exact input/output), which is why these check the actual
# render() output too, not only the scanner.
{
	for my $case (
		['<div {{attr}}="{{val}}">x</div>',  { attr => 'onclick', val => 'alert(1)' }, 'quoted value'],
		['<div {{attr}}={{val}}>x</div>',    { attr => 'onclick', val => 'alert(1)' }, 'unquoted value'],
		['<div {{{attr}}}="{{val}}">x</div>', { attr => 'onclick', val => 'alert(1)' }, 'raw marker as the name'],
	) {
		my ($tmpl, $vars, $label) = @$case;
		my @f = _find_unsafe_placeholders($tmpl);
		ok((grep { /attribute name/ } @f), "context scan: placeholder as an attribute name ($label) is flagged");

		my $out = render($tmpl, $vars);
		like($out, qr/\bonclick\s*=/i,
			"render() confirms the attribute-name danger is real ($label): the template author's onclick actually appears");
	}

	# Negative: an ordinary attribute is never mistaken for "placeholder
	# as a name" just because its VALUE is a placeholder - the name
	# check only fires when the {{...}} sits immediately before '=',
	# never when it sits after one.
	my @ordinary = _find_unsafe_placeholders('<a href="{{v}}">x</a>');
	ok(!(grep { /attribute name/ } @ordinary),
		q{context scan: an ordinary href="{{v}}" is not mistaken for a placeholder-as-name});
}

# Negative controls: prove the scanner does not flag the ordinary safe
# usage this codebase actually writes, attribute names that merely
# contain "on"/"action" as a substring rather than being one, an unquoted
# attribute with no {{ at all, a quoted attribute not double-counted by
# the new unquoted check, and the one evasion candidate that turned out
# not to be reachable.
{
	is_deeply([ _find_unsafe_placeholders('<h1>{{title}}</h1>') ], [],
		'context scan: {{ as plain element content is not flagged');
	is_deeply([ _find_unsafe_placeholders('<main>{{{content}}}</main>') ], [],
		'context scan: {{{ as plain element content is not flagged');
	is_deeply([ _find_unsafe_placeholders('<a href="/static/path">x</a>') ], [],
		'context scan: an href with no {{ at all is not flagged');
	is_deeply([ _find_unsafe_placeholders('<div data-action="{{v}}" data-onload="{{v}}">x</div>') ], [],
		q{context scan: "data-action"/"data-onload" are not "action"/"onload" - no attribute-name boundary, not flagged});
	is_deeply([ _find_unsafe_placeholders('<input type=text>') ], [],
		'context scan: an unquoted attribute with no {{ at all is not flagged');

	my @dup_check = _find_unsafe_placeholders('<a href="{{evil}}">x</a>');
	is(scalar(@dup_check), 1,
		'context scan: a quoted attribute is reported once, not double-counted by the new unquoted-attribute check');

	# R43 (fix round 3), the reviewer's own two examples, live-verified
	# against the round-2 scanner first: both used to be misread as an
	# unquoted attribute ("attempts", "count") purely because ordinary
	# prose contained "word = {{value}}" with no tag anywhere near it -
	# precisely the shape Task 7's Overview screen needs to write.
	is_deeply([ _find_unsafe_placeholders('<p>Max attempts = {{max}}</p>') ], [],
		'context scan: R43 example 1 - "<p>Max attempts = {{max}}</p>" is not flagged (no tag involved)');
	is_deeply([ _find_unsafe_placeholders('<div class="stat">Blocked count = {{count}}</div>') ], [],
		'context scan: R43 example 2 - a stat card with "Blocked count = {{count}}" as element content is not flagged');

	# NOT reachable, and here is the independent proof rather than a bare
	# assertion: a { and a { separated by a newline is not "{{" to
	# Render.pm's own $PLACEHOLDER_RE either (it requires the two braces
	# strictly adjacent), so this template substitutes nothing and dies
	# on nothing - it is exactly as inert to render() as to this scanner.
	# Flagging it would be reporting a danger that cannot occur through
	# the only code path that ever processes these files. Re-checked in
	# fix round 3 against the amended scanner, not merely carried over
	# from round 2 unexamined - a change to the matcher can make a
	# previously-unreachable pattern reachable, and the only way to know
	# it didn't is to run it again.
	my $split_brace_html = "<a href=\"{\n{v}}\">x</a>";
	is_deeply([ _find_unsafe_placeholders($split_brace_html) ], [],
		'context scan: a { and a { separated by a newline (not literal "{{") is not flagged');
	my $split_brace_out = eval { render($split_brace_html, {}) };
	ok(!$@, 'that same split-brace template renders through the REAL Render.pm without dying (proving it is inert, not merely unflagged)')
		or diag("died with: $@");
	is($split_brace_out, $split_brace_html,
		'and comes back byte-identical - Render.pm never treated the split braces as a placeholder either');
}

# R42: the raw-marker allowlist, tested directly against
# _find_unauthorized_raw_markers() rather than only through real files,
# plus the exact embedded-</script> scenario that motivated it, run
# through both the scanner and the real render() as the reviewer's
# method requires.
{
	my @evil = _find_unauthorized_raw_markers('{{{evil}}}', 'ui-src/web/layout.html');
	ok((grep { /evil/ } @evil), 'raw-marker allowlist: an unlisted key on layout.html is flagged');

	my @wrong_file = _find_unauthorized_raw_markers('{{{content}}}', 'ui-src/web/screens/overview.html');
	ok((grep { /content/ } @wrong_file),
		q{raw-marker allowlist: "content" is allowed on layout.html, not on every file - a hypothetical screen using it is still flagged});

	is_deeply([ _find_unauthorized_raw_markers('{{{nav}}}', 'ui-src/web/layout.html') ], [],
		'raw-marker allowlist: layout.html/{{{nav}}} is on the allowlist');
	is_deeply([ _find_unauthorized_raw_markers('{{{content}}}', 'ui-src/web/layout.html') ], [],
		'raw-marker allowlist: layout.html/{{{content}}} is on the allowlist');
	is_deeply([ _find_unauthorized_raw_markers('{{nav}}', 'ui-src/web/layout.html') ], [],
		'raw-marker allowlist: {{nav}} (two braces, not raw) is out of scope for this check entirely');

	# The exact R42 scenario: a JS string containing a literal
	# "</script>" ends the <script> element from the BROWSER's point of
	# view regardless of JS syntax, so a {{{v}}} placed after it is not
	# "inside script" to anything that actually parses the page - it is
	# ordinary element content, the raw marker's own legitimate shape,
	# which is exactly why no CONTEXT check could ever have caught this.
	my $r42_tmpl = qq{<script>var s = "</script>";\n</script>\n{{{v}}}\n};
	my @r42_scan = _find_unauthorized_raw_markers($r42_tmpl, 'ui-src/web/layout.html');
	ok((grep { /\{\{\{v\}\}\}/ } @r42_scan),
		'raw-marker allowlist: the embedded-</script> scenario is caught (key "v" is not on the layout.html allowlist)');

	my $r42_out = render($r42_tmpl, { v => '<img src=x onerror=alert(1)>' });
	like($r42_out, qr/<img src=x onerror=alert\(1\)>/,
		'render() confirms the R42 danger is real: the raw marker after the embedded </script> renders live, unescaped markup');

	# And the escaped form in the identical position is confirmed
	# harmless, not merely assumed to be - it is still just escaped
	# text, which is exactly what element content is supposed to hold.
	my $r42_escaped_tmpl = qq{<script>var s = "</script>";\n</script>\n{{v}}\n};
	my $r42_escaped_out = render($r42_escaped_tmpl, { v => '<img src=x onerror=alert(1)>' });
	unlike($r42_escaped_out, qr/<img src=x onerror=alert\(1\)>/,
		'render() confirms the escaped marker in the identical position stays inert text, unlike the raw one');
}

# R44: the traversal itself, isolated from the enforcement test below -
# a file saved as SCREEN.HTML (any case) must still be found. Built in
# a tempdir rather than relying on a coincidence of what currently
# exists under ui-src/web (none of it is uppercase today, which is
# exactly how this went unnoticed the first time).
{
	my $dir = tempdir(CLEANUP => 1);
	open(my $fh, '>:raw', "$dir/SCREEN.HTML") or die "test setup: $!\n";
	print { $fh } '<p>hello</p>';
	close $fh;

	my @found = _html_files_under($dir);
	is(scalar(@found), 1, 'context scan: file traversal is case-insensitive - SCREEN.HTML is found')
		or diag("found: @found");
}

# The real enforcement: every .html file under ui-src/web, walked
# recursively (case-insensitively, R44) so ui-src/web/screens/*.html
# (Task 7, not yet created) is covered automatically with no second
# place to remember to add it. Checks both _find_unsafe_placeholders()
# (context) and _find_unauthorized_raw_markers() (R42's allowlist) on
# every file.
{
	my @html_files = _html_files_under("$FindBin::Bin/../ui-src/web");

	# Guards against the next test passing vacuously because the path
	# above was wrong and nothing was actually scanned - exactly the
	# "test passing for the wrong reason" this project has hit before.
	ok(scalar(@html_files) > 0,
		'context scan: found at least one .html file under ui-src/web to check (not a vacuous pass)');

	my @all_findings;
	for my $path (@html_files) {
		open(my $fh, '<:raw', $path) or die "test: cannot open $path: $!\n";
		local $/;
		my $html = <$fh>;
		close $fh;

		my $rel = $path;
		$rel =~ s{^\Q$FindBin::Bin\E/\.\./}{};
		push @all_findings, map { "$rel: $_" } _find_unsafe_placeholders($html);
		push @all_findings, map { "$rel: $_" } _find_unauthorized_raw_markers($html, $rel);
	}

	is_deeply(\@all_findings, [],
		'context scan: no ui-src/web/*.html file has {{ in an unsafe context, an unauthorised raw marker, or a placeholder as an attribute name')
		or diag("Found a problem:\n  " . join("\n  ", @all_findings) . "\n\n"
			. "Fix: move the value out of that position, don't reach for the raw {{{ }}} marker instead - "
			. "neither marker is safe there. A URL should be a literal this codebase wrote, not a substituted "
			. "value; server-rendered HTML should not have inline event-handler attributes at all; a placeholder "
			. "must never be the NAME of an attribute, only (sometimes) its value; the raw {{{ }}} marker is only "
			. "authorised for layout.html's own nav/content slots - if a screen genuinely needs to insert raw HTML "
			. "it built itself, add it to \%RAW_MARKER_ALLOWLIST in this file and say why in the same commit; and "
			. "dynamic data a <script> needs should be placed OUTSIDE the <script> tag (a data-* attribute the "
			. "script reads) rather than interpolated into its source text.");
}
