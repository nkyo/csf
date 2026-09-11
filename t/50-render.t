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
use Test::More tests => 202;

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
# THE CONTEXT SCANNER - and why it is no longer built out of regexes.
#
# R38 (fix round 1, spec review): the boundary between where {{ }} is safe
# and where it is not - documented in Render.pm's and layout.html's own
# header comments as element content and quoted attributes only, NEVER a
# <script>/<style> body, an event-handler attribute, or a URL-bearing
# attribute - was, until that round, enforced by nothing but that comment.
# Task 7 adds five screens directly on top of this file with nothing
# stopping any of them from writing {{value}} inside an onclick or an
# href. The reviewer also punctured the fallback comfort of "tag/quote
# entities survive inside <script> anyway": a value ending in an
# unescaped backslash still corrupts a JS string literal there, escaped
# or not, so the boundary is not merely undefended, it is not as
# forgiving as it looks when crossed either.
#
# Rounds 1-3 enforced that boundary with a growing set of regexes, and
# each round's bypass lived inside the previous round's fix:
#
#   round 1  on*/href/src/action, quoted values only
#            -> R40: <a href={{evil}}> (unquoted) was invisible.
#   round 2  + "any unquoted attribute", matched against the whole
#            document
#            -> R43: "<p>Max attempts = {{max}}</p>" - ordinary prose
#               with no tag in it - was misread as an unquoted attribute
#               named "attempts", which is exactly the shape a stats
#               screen writes, and a guard that blocks correct work is a
#               guard someone switches off;
#            -> R41: a placeholder in attribute-NAME position;
#            -> R42: the raw marker after an embedded </script>.
#   round 3  + scope every attribute check to <tag ...> regions captured
#            by <[a-zA-Z][a-zA-Z0-9-]*([^>]*)>
#            -> R45: [^>]* stops at the FIRST '>' anywhere in the tag,
#               including one inside an earlier QUOTED attribute value,
#               so <div title="Count > 5" onclick="{{v}}"> handed the
#               checks a region of just ' title="Count ' and the onclick
#               went unseen. Confirmed live: not flagged, and render()
#               emits a real onclick="alert(1)".
#   round 4  regexes replaced by the scan below
#            -> R47: the last regex-era artifact, the href/src/action
#               ENUMERATION, left formaction=, style=, srcdoc= and every
#               URL attribute nobody had listed unguarded;
#            -> R48: <script>'s escaped and double-escaped states were
#               not modelled, so "</script>" was believed to end a body
#               that a browser keeps open.
#   round 5  attribute rule inverted to an allowlist (R47); the three
#            script-data states modelled (R48); the RCDATA note
#            corrected to describe what it actually does (R49).
#
# That is not three careless rounds. HTML is not a regular language, so
# "where am I in this document" is not a question a regular expression
# can answer; a regex can only approximate it, and every approximation
# has a next counterexample. There is no patch sequence that converges -
# the recommended round-4 patch (alternate "[^>]*" with
# '"[^"]*"|\x27[^\x27]*\x27|[^>]' so an in-value '>' cannot terminate the
# region) is itself only the next approximation: it still cannot tell a
# comment from markup, still cannot see that a '<' inside an attribute
# value is not a new tag, and still has to be re-argued from scratch
# against every construction nobody has thought of yet.
#
# So this round replaces the regexes with an explicit single-pass scan
# that tracks which context it is in: element content, inside a tag,
# inside a quoted or unquoted attribute value, inside a comment or other
# markup declaration, or inside a <script>/<style> raw-text body. It
# follows the HTML5 tokenizer's own state transitions for the subset
# that decides those boundaries, so the questions the regexes were
# failing one at a time (the truncating '>', the comment that looks like
# markup, the '<' inside an attribute value, the tag spanning lines, the
# missing whitespace between two attributes) are all answered by the
# same mechanism rather than by five more patterns. It is ~120 lines,
# bounded, and every branch below names the HTML5 state it mirrors, so
# it can be checked against the spec rather than against intuition.
#
# What it reports, and why each is unsafe (escape_html() escapes
# & < > " ' - enough for element content and for a QUOTED attribute
# value, and nothing else):
#
#   <script>/<style> body   neither JS nor CSS treats any of those five
#                           characters as special, and an HTML tokenizer
#                           ends a <script> at the byte sequence
#                           "</script" without decoding entities first.
#   attribute NAME          escape_html() only ever escapes a VALUE;
#                           nothing it does touches a name, so a
#                           placeholder here chooses which attribute
#                           exists at all - onclick is one substitution
#                           away (R41).
#   tag-NAME position       "<{{v}}", "</{{v}}" or "<d{{v}}" - the
#                           template supplied the '<' itself, and
#                           escape_html() escapes neither space nor '='
#                           nor '/', so the value supplies a tag name
#                           and every attribute after it. Found in this
#                           round while probing the new scan, confirmed
#                           live: "<p>5 <{{v}}> 6</p>" with
#                           v = "img src=x onerror=alert(1)" renders
#                           exactly that img (R46). Missed by every
#                           earlier round, because the question it asks
#                           is about the OUTPUT's structure, not the
#                           template's.
#   unquoted value          there is no boundary to defend: escape_html()
#                           does not escape SPACE, so a value containing
#                           one does not widen this attribute, it injects
#                           a new one - onmouseover is one space away
#                           (R40). Any attribute, not only the enumerated
#                           ones - without quotes they are all injectable.
#   quoted value, any       R47: inverted. A quoted value holding {{ is
#   attribute NOT on the    reported unless the attribute's name is on
#   inert allowlist         %INERT_ATTRIBUTES below, because the set of
#                           dangerous attributes cannot be enumerated -
#                           on*= is JavaScript, href/src/action= is a URL
#                           and "javascript:" is one, style= is CSS,
#                           srcdoc= is a whole nested document, and
#                           formaction/xlink:href/poster/srcset/ping/
#                           <object data> are URLs nobody had listed. on*
#                           and href/src/action keep their own finding
#                           text for the diagnostic, not for the
#                           decision.
#   a <script> body in ANY  R48: <script>, unlike <style>, has three
#   of its three states     tokenizer states, and "</script>" ends the
#                           element in only two of them. See
#                           _scan_script_data().
#
# Deliberately NOT reported, each with its reason:
#
#   comment content         inert to the browser, and an escaped value
#                           cannot break out: every way HTML5 ends a
#                           comment ("-->", "--!>", the abrupt "<!-->"
#                           and "<!--->" forms, EOF) needs a literal '>',
#                           escape_html() turns '>' into "&gt;", and
#                           entities are not decoded inside a comment.
#                           This also clears the round-3 false positive
#                           on a commented-out <button onclick=...>. It
#                           does NOT extend to the raw marker, which is
#                           why _find_unauthorized_raw_markers() below
#                           checks every {{{key}}} context-free, comments
#                           included.
#   end-tag attributes      </div onclick="{{v}}"> - an end tag's
#                           attributes are discarded by the HTML parser
#                           and can never become live. Parsed with the
#                           same quoting rules anyway, so a '>' inside
#                           one of them cannot desynchronise the scan.
#                           An end tag's NAME is still reported (R46).
#   quoted value on an      escape_html() covers it and the name is on
#   INERT attribute         %INERT_ATTRIBUTES: that is the whole point of
#                           the escaping, and flagging it would block
#                           correct work (R43's lesson). Any OTHER
#                           quoted attribute is now reported - see R47
#                           below.
#
# Known and accepted, stated here rather than left for a re-review:
#   - RCDATA elements (<title>, <textarea>) are scanned as ordinary
#     markup, while a browser treats their content as text that ends at
#     the first matching end tag, wherever it falls. R49: this was
#     previously described here as an over-report that "fails closed".
#     That was wrong, and a comment that misdescribes its own guard is
#     worse than no comment - it is the fourth time this project has hit
#     one. The disagreement runs in BOTH directions:
#
#       over-reports  <textarea><button onclick="{{v}}"></textarea> is
#                     flagged though a browser renders it as text.
#       under-reports <textarea><div title="</textarea><button
#                     onclick='{{v}}'>">x</div></textarea> is NOT
#                     flagged. A browser ends the textarea at the
#                     </textarea> inside that quoted value - RCDATA has
#                     no notion of attributes - so the <button> after it
#                     is real markup and the onclick is live. The
#                     scanner is inside a quoted attribute value at that
#                     point and sees only an inert title=. Verified
#                     against the real render(), which emits
#                     onclick='alert(1)'.
#
#     Left as behaviour by the round-5 brief's explicit instruction
#     ("fix the sentence, not the code"), and no template in this tree
#     writes markup inside an RCDATA element. Modelling RCDATA is a
#     contained follow-on - two element names handled the way <style>
#     already is - and it would close both directions at once.
#   - a tag with no closing '>' at all is still reported, though a
#     browser discards it. Over-reporting again, and such a template is
#     visibly broken anyway.
#   - (was: "the URL-bearing set is an enumeration and therefore
#     incomplete by construction". R47 removed that limitation by
#     inverting the rule - see %INERT_ATTRIBUTES.)
###############################################################################

# _find_unsafe_placeholders($html) -> @findings
#
# The DATA state: ordinary element content, which is the one place the
# escaped marker is unconditionally safe. Everything interesting starts
# at a '<', so this loop's only job is to classify each '<' and hand off
# to the routine for that context.
sub _find_unsafe_placeholders {
	my ($html) = @_;
	my @findings;
	my $len = length $html;
	my $pos = 0;

	while ($pos < $len) {
		my $lt = index($html, '<', $pos);
		last if $lt < 0;                      # DATA through to EOF
		my $c = substr($html, $lt + 1, 1);

		# R46: TAG-NAME POSITION. A '<' the TEMPLATE wrote, immediately
		# followed by a placeholder, is markup structure the escaping
		# cannot reach: escape_html() escapes '<' and '>' in a VALUE, so
		# a value can never invent a tag on its own - but here the
		# template has already supplied the '<', and escape_html()
		# escapes neither SPACE nor '=' nor '/', so the value supplies
		# the tag name and as many attributes as it likes. Confirmed
		# live: "<p>5 <{{v}}> 6</p>" with v = "img src=x
		# onerror=alert(1)" renders exactly that img. Note "< {{v}}"
		# (whitespace between) is NOT this - an HTML tokenizer emits
		# that '<' as text, and the escaped value beside it is ordinary
		# element content.
		if (substr($html, $lt, 4) =~ m{\A<[/]?\{\{}) {
			push @findings, 'placeholder in tag-name position (immediately after the template\'s own "<")';
		}

		# MARKUP DECLARATION OPEN: <!-- comment -->, <!DOCTYPE ...>,
		# <![CDATA[...]]> (a bogus comment in an HTML document).
		if ($c eq '!') {
			$pos = _skip_declaration($html, $lt, $len);
			next;
		}

		# '<?' is a bogus comment to an HTML parser, ended by '>'.
		if ($c eq '?') {
			$pos = _skip_to_gt($html, $lt + 2, $len);
			next;
		}

		# END TAG OPEN.
		if ($c eq '/') {
			my $d = substr($html, $lt + 2, 1);
			if ($d =~ /\A[A-Za-z]\z/) {
				# Parsed with the same quoting rules as a start tag so a
				# '>' inside one of its (browser-ignored) attribute
				# values cannot desynchronise the scan. The $end_tag
				# flag suppresses the ATTRIBUTE findings - an end tag's
				# attributes are discarded by the HTML parser - but not
				# the tag-NAME one, so "</d{{v}}>" is reported exactly
				# as "</{{v}}>" is.
				(undef, $pos) = _scan_tag($html, $lt + 2, $len, \@findings, 1);
			}
			elsif ($d eq '>') {
				$pos = $lt + 3;               # "</>" is discarded
			}
			else {
				$pos = _skip_to_gt($html, $lt + 2, $len);
			}
			next;
		}

		# TAG OPEN: only an ASCII letter starts a tag.
		if ($c =~ /\A[A-Za-z]\z/) {
			my ($name, $after) = _scan_tag($html, $lt + 1, $len, \@findings, 0);
			$pos = $after;

			# RAW TEXT: a <script>/<style> body is not markup and not
			# text - it is program source, where none of the five
			# characters escape_html() handles means anything at all.
			if ($name eq 'script') {
				# SCRIPT DATA, with the escaped and double-escaped
				# states a <script> body can enter (R48).
				my ($body, $next) = _scan_script_data($html, $pos, $len);
				push @findings, '<script> block' if index($body, '{{') >= 0;
				$pos = $next;
			}
			elsif ($name eq 'style') {
				# RAWTEXT, which has no escape states at all: </style>
				# always ends a style element.
				my ($body, $next) = _scan_raw_text($html, $pos, $len, 'style');
				push @findings, '<style> block' if index($body, '{{') >= 0;
				$pos = $next;
			}
			next;
		}

		# A '<' followed by anything else is literal text to an HTML
		# tokenizer ("5 < 6", "<{{v}}>"), not the start of a tag - the
		# single most common source of false positives in a regex scan.
		$pos = $lt + 1;
	}

	return @findings;
}

# _scan_tag($html, $p, $len, $findings, $end_tag) -> ($lc_name, $pos_after)
#
# $p points at the first character of the tag NAME. Mirrors HTML5's tag
# name / before-attribute-name / attribute-name / after-attribute-name /
# before-attribute-value / attribute-value(double|single|unquoted)
# states. The whole point of walking these states rather than matching
# them is that a '>' inside a quoted attribute value is an ordinary
# character here (R45), and so is a '<'.
sub _scan_tag {
	my ($html, $p, $len, $findings, $end_tag) = @_;

	# An end tag's attributes never become live, so they are parsed for
	# position and not reported; its NAME still is.
	my $attr_findings = $end_tag ? undef : $findings;

	my $name_at = $p;
	$p++ while $p < $len && substr($html, $p, 1) !~ m{[\s/>]};
	my $raw_name = substr($html, $name_at, $p - $name_at);
	my $name = lc $raw_name;

	# R46 again, the in-tag half: "<d{{v}}>" with v = "iv onclick=..."
	# is a live <div onclick=...>. Reported for end tags too, not
	# because a substituted end-tag name can carry an attribute (it
	# cannot - they are discarded) but so that "</{{v}}>" and
	# "</d{{v}}>" cannot differ: an asymmetry there is the shape a
	# future bypass grows in.
	push @$findings, "placeholder in tag-name position ('<$raw_name')"
		if index($raw_name, '{{') >= 0;

	while ($p < $len) {
		my $ch = substr($html, $p, 1);

		# BEFORE ATTRIBUTE NAME. A stray '/' is skipped here, which is
		# also how the solidus of a self-closing tag is consumed - and
		# note that <div/onclick="{{v}}"> really does give the browser
		# an onclick, with no whitespace anywhere before it.
		if ($ch =~ /\s/ || $ch eq '/') { $p++; next; }
		if ($ch eq '>')               { $p++; last; }

		# ATTRIBUTE NAME: ends at whitespace, '/', '>' or '='. The first
		# character is consumed unconditionally because an '=' in that
		# position is part of the name per HTML5
		# (unexpected-equals-sign-before-attribute-name), not a value
		# separator.
		my $name_start = $p;
		$p++;
		$p++ while $p < $len && substr($html, $p, 1) !~ m{[\s/>=]};
		my $attr = substr($html, $name_start, $p - $name_start);

		# AFTER ATTRIBUTE NAME / BEFORE ATTRIBUTE VALUE: whitespace is
		# allowed on both sides of '=', including newlines.
		my $q = $p;
		$q++ while $q < $len && substr($html, $q, 1) =~ /\s/;
		if ($q >= $len || substr($html, $q, 1) ne '=') {
			_report_attribute($attr_findings, $attr, undef, 0);
			next;                             # valueless attribute
		}
		$q++;
		$q++ while $q < $len && substr($html, $q, 1) =~ /\s/;

		my $quote = $q < $len ? substr($html, $q, 1) : '';
		if ($quote eq '"' || $quote eq q{'}) {
			# ATTRIBUTE VALUE (DOUBLE|SINGLE QUOTED): ends at the
			# matching quote and at nothing else. '>' and '<' inside are
			# data.
			my $end = index($html, $quote, $q + 1);
			if ($end < 0) {
				_report_attribute($attr_findings, $attr, substr($html, $q + 1), 1);
				return ($name, $len);         # eof-in-tag
			}
			_report_attribute($attr_findings, $attr, substr($html, $q + 1, $end - $q - 1), 1);
			$p = $end + 1;
		}
		else {
			# ATTRIBUTE VALUE (UNQUOTED): ends at whitespace or '>'.
			# NOT at '/' - <img src={{x}}/> has the value "{{x}}/".
			my $value_at = $q;
			$q++ while $q < $len && substr($html, $q, 1) !~ m{[\s>]};
			_report_attribute($attr_findings, $attr, substr($html, $value_at, $q - $value_at), 0);
			$p = $q;
		}
	}

	return ($name, $p);
}

# _report_attribute($findings, $name, $value, $quoted)
#
# The only place a judgement about safety is made. $value is undef for a
# valueless attribute. $findings is undef when the caller is parsing for
# position only (an end tag).
sub _report_attribute {
	my ($findings, $attr, $value, $quoted) = @_;
	return unless defined $findings;

	push @$findings, "placeholder used as an attribute name ('$attr')"
		if index($attr, '{{') >= 0;

	return unless defined $value;
	return unless index($value, '{{') >= 0;

	if (!$quoted) {
		push @$findings, "unquoted attribute '$attr'";
	}
	elsif ($attr =~ /\Aon[A-Za-z]+\z/i) {
		# Kept ahead of the allowlist test purely for the diagnostic:
		# "event-handler attribute" tells a screen author what is wrong
		# far better than "not on the allowlist" does. The allowlist
		# below would catch these anyway.
		push @$findings, "event-handler attribute '$attr'";
	}
	elsif ($attr =~ /\A(?:href|src|action)\z/i) {
		push @$findings, "URL-bearing attribute '$attr'";
	}
	elsif (!_attribute_is_inert($attr)) {
		# R47: everything that is not provably inert. See
		# %INERT_ATTRIBUTES above for why this is an allowlist.
		push @$findings, "attribute '$attr' is not on the inert-attribute allowlist";
	}
}

###############################################################################
# R47 (fix round 5, live-verified): the URL-bearing set used to be the
# enumeration href/src/action, and rounds 1-4 all left it that way
# because widening it is a guess. The re-review showed the gap is
# reachable by ORDINARY markup rather than a contrived case:
#
#     <button formaction="/api/unblock?ip={{id}}">
#
# is simply how the Block/Unblock screen's two-submit form gets written,
# and action= two lines above it IS guarded - which teaches exactly the
# wrong lesson to whoever writes that screen. Widening the list invites
# the next omission: xlink:href, <object data>, poster, srcset are all
# already known, style= is forbidden by Render.pm's own header comment
# yet went unflagged, and srcdoc is worse than all of them
# (<iframe srcdoc="{{v}}"> is script execution from a value the escaping
# handled perfectly, because the escaped markup is DECODED again when
# the srcdoc document is parsed).
#
# So the rule is inverted, exactly as R42 inverted the raw marker: a
# blocklist of dangerous things can never be finished, an allowlist of
# safe ones can. A quoted attribute value holding {{ is reported unless
# the attribute's name is on the list below.
#
# What earns a place on this list: the value must never be interpreted
# as a URL, as CSS, as JavaScript, or as markup - in ANY element, not
# merely in the element a screen happens to use it on today. That last
# clause is what keeps "data" (a URL on <object>) off the list while
# "data-*" is on it, and it is the question to ask of any future
# addition.
#
#   class, id, for, name   identifiers and IDREFs. Not fetched, not
#                          evaluated, not parsed as markup.
#   title, alt, label,     human-readable text. The browser renders
#   placeholder            them as characters and nothing else.
#   value                  form-control data, and the documented home of
#                          the CSRF nonce
#                          (<input type="hidden" value="{{csrf}}"> - see
#                          "How a template obtains the CSRF nonce" in
#                          task-6-report.md). Caveat stated rather than
#                          hidden: <param value> on an <object> can be a
#                          URL in the Flash-era plugin model. Nothing in
#                          this tree uses <param>, and a screen that
#                          ever did would be doing something this UI has
#                          no reason to do.
#   aria-*                 accessibility strings and IDREFs.
#   data-*                 author data. Inert to the HTML parser by
#                          definition; it would take a script reading
#                          and evaluating one to make it dangerous, and
#                          this UI ships no scripts at all. NOTE the
#                          hyphen is required - bare "data" is a URL
#                          attribute on <object> and is NOT on this list.
#
# Adding a name here is a one-line change, and it must arrive WITH the
# screen that needs it and a justification against the paragraph above,
# in the same commit - the same discipline %RAW_MARKER_ALLOWLIST is held
# to.
###############################################################################
our %INERT_ATTRIBUTES = map { $_ => 1 } qw(
	alt class for id label name placeholder title value
);
our @INERT_ATTRIBUTE_PREFIXES = qw( aria- data- );

sub _attribute_is_inert {
	my ($attr) = @_;
	my $lc = lc $attr;

	return 1 if $INERT_ATTRIBUTES{$lc};
	for my $prefix (@INERT_ATTRIBUTE_PREFIXES) {
		return 1 if length($lc) > length($prefix)
			&& index($lc, $prefix) == 0;
	}
	return 0;
}

# _scan_raw_text($html, $p, $len, $name) -> ($body, $pos_of_end_tag)
#
# HTML5 leaves a script/style raw-text element only at "</name" followed
# by whitespace, '/' or '>' (or EOF). "</scriptx" is still script source
# to a browser, so ending the body there would hand the rest of a live
# script to the element-content rules, which consider it safe. The
# returned position is the '<' of the end tag, so the caller's main loop
# re-reads it as an end tag and parses it with the ordinary quoting
# rules.
sub _scan_raw_text {
	my ($html, $p, $len, $name) = @_;

	pos($html) = $p;
	while ($html =~ m{</\Q$name\E}gi) {
		my $hit  = $-[0];
		my $next = pos($html);
		my $after = $next < $len ? substr($html, $next, 1) : '';
		next unless $after eq '' || $after =~ m{[\s/>]};
		return (substr($html, $p, $hit - $p), $hit);
	}
	return (substr($html, $p), $len);
}

# _appropriate_end_tag($html, $lt, $len, $name) -> 1 | undef
#
# Is the '<' at $lt the start of an end tag that closes $name? HTML5
# requires the tag name to match and to be followed by whitespace, '/'
# or '>' - "</scriptx" is still script source to a browser.
sub _appropriate_end_tag {
	my ($html, $lt, $len, $name) = @_;

	return undef unless substr($html, $lt, 2) eq '</';
	return undef unless lc(substr($html, $lt + 2, length $name)) eq $name;
	my $at = $lt + 2 + length $name;
	return 1 if $at >= $len;
	return substr($html, $at, 1) =~ m{[\s/>]} ? 1 : undef;
}

# _script_tag_name_at($html, $p, $len) -> $pos_after | undef
#
# The temporary-buffer comparison HTML5's script-data double escape
# start/end states perform: read the run of ASCII letters at $p and
# answer only if it is exactly "script" and is followed by whitespace,
# '/' or '>'.
sub _script_tag_name_at {
	my ($html, $p, $len) = @_;

	my $at = $p;
	$at++ while $at < $len && substr($html, $at, 1) =~ /\A[A-Za-z]\z/;
	return undef unless lc(substr($html, $p, $at - $p)) eq 'script';
	return undef unless $at < $len && substr($html, $at, 1) =~ m{[\s/>]};
	return $at;
}

# _scan_script_data($html, $p, $len) -> ($body, $pos_of_end_tag)
#
# R48 (fix round 5, live-verified): a <script> body is not one state, it
# is three, and only the first of them ends at "</script>".
#
#     <script><!--<script>x</script>{{v}}</script>
#
# leaves {{v}} as live JavaScript source. Walk it: "<!--" in SCRIPT DATA
# moves to SCRIPT DATA ESCAPED; a "<script" there moves to SCRIPT DATA
# DOUBLE ESCAPED; and in THAT state "</script>" does not end the element
# at all - it only drops back to ESCAPED. The element ends at the second
# "</script>". Confirmed against the real render(): the value lands
# inside the script element, where none of the five characters
# escape_html() handles means anything. The document.write("<!--<script")
# form is the same machine reached a different way.
#
# This is a missing tokenizer STATE, not a missing name in a list, which
# is why R47's inversion does not reach it - no attribute is involved.
# It is also the reason a scan that tracks context can be finished while
# a set of patterns cannot: the states are enumerated by the HTML5 spec,
# and there are exactly these three.
#
# Only <script> has them. <style> is RAWTEXT, which has no escape states,
# so _scan_raw_text() still serves it.
sub _scan_script_data {
	my ($html, $p, $len) = @_;

	my $state = 0;          # 0 = script data, 1 = escaped, 2 = double escaped
	my $i     = $p;

	# Cached position of the next "-->" (any run of two or more dashes
	# then '>'), which is what returns states 1 and 2 to state 0. Cached
	# rather than re-searched per iteration so a body full of '<' cannot
	# make this quadratic; $i only ever moves forward, so the cache is
	# refreshed at most once per match.
	my ($dash_at, $dash_end) = (-1, -1);

	while ($i < $len) {
		if ($state == 0) {
			my $lt = index($html, '<', $i);
			last if $lt < 0;
			if (substr($html, $lt, 4) eq '<!--') { $state = 1; $i = $lt + 4; next; }
			return (substr($html, $p, $lt - $p), $lt)
				if _appropriate_end_tag($html, $lt, $len, 'script');
			$i = $lt + 1;
			next;
		}

		if ($dash_at < $i) {
			pos($html) = $i;
			if ($html =~ m{-{2,}>}g) { ($dash_at, $dash_end) = ($-[0], pos($html)) }
			else                     { ($dash_at, $dash_end) = ($len + 1, $len + 1) }
		}

		my $lt = index($html, '<', $i);
		if ($lt < 0 || $dash_at < $lt) {
			last if $dash_at > $len;        # neither: the rest is script
			$state = 0;                     # "-->" leaves the escaped states
			$i     = $dash_end;
			next;
		}

		my $c = substr($html, $lt + 1, 1);
		if ($state == 1) {
			# ESCAPED: a matching </script> DOES end the element here.
			return (substr($html, $p, $lt - $p), $lt)
				if $c eq '/' && _appropriate_end_tag($html, $lt, $len, 'script');
			if ($c =~ /\A[A-Za-z]\z/) {
				my $after = _script_tag_name_at($html, $lt + 1, $len);
				if (defined $after) { $state = 2; $i = $after; next; }
			}
			$i = $lt + 1;
			next;
		}

		# DOUBLE ESCAPED: </script> only drops back to ESCAPED.
		if ($c eq '/') {
			my $after = _script_tag_name_at($html, $lt + 2, $len);
			if (defined $after) { $state = 1; $i = $after; next; }
		}
		$i = $lt + 1;
	}

	return (substr($html, $p), $len);
}

# _skip_declaration($html, $lt, $len) -> $pos_after
#
# COMMENT and everything else introduced by "<!". Comment content is
# skipped, not scanned - see the "Deliberately NOT reported" note above
# for why that is sound for the escaped marker and why it does not
# extend to the raw one.
sub _skip_declaration {
	my ($html, $lt, $len) = @_;

	if (substr($html, $lt, 4) eq '<!--') {
		my $p = $lt + 4;
		return $p + 1 if substr($html, $p, 1) eq '>';    # <!-->
		return $p + 2 if substr($html, $p, 2) eq '->';   # <!--->
		pos($html) = $p;
		return pos($html) if $html =~ m{--!?>}g;         # --> and --!>
		return $len;                                     # eof-in-comment
	}

	# <!DOCTYPE ...> and any other markup declaration: to an HTML parser
	# this is a bogus comment, ended by the first '>'.
	return _skip_to_gt($html, $lt + 2, $len);
}

sub _skip_to_gt {
	my ($html, $p, $len) = @_;
	my $gt = index($html, '>', $p);
	return $gt < 0 ? $len : $gt + 1;
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

###############################################################################
# R45 (fix round 4) and the rest of the context-tracking corpus.
#
# R45 is the finding that retired the regexes: round 3 scoped every
# attribute check to a tag region captured by <[a-zA-Z][a-zA-Z0-9-]*([^>]*)>,
# and [^>]* stops at the FIRST '>' in the tag - including one sitting
# inside an earlier QUOTED attribute value, which is ordinary business
# text ("Attempts > 5") next to a dynamic handler in the same tag. The
# reviewer confirmed it live: no findings, and render() emitting a real
# onclick. Every case below was run through BOTH the scanner and the
# real render() before being written down (see task-6-report.md for the
# full input/scanner/render() table), because "the scanner doesn't flag
# it" and "render() cannot produce it" are different facts and only the
# second one makes a gap safe.
###############################################################################
{
	# Positive: things the scanner MUST catch, each one reachable -
	# render() really does emit the live construct named.
	my %must_flag = (
		'R45: a > inside an earlier quoted value no longer truncates the tag'
			=> ['<div title="Count > 5" onclick="{{v}}">x</div>',        qr/event-handler attribute 'onclick'/],
		'R45: the reviewer\'s own stat-button shape'
			=> [q{<button title="Attempts > {{max}}" onclick="retry('{{id}}')">go</button>}, qr/event-handler attribute 'onclick'/],
		'R45: a > inside an earlier SINGLE-quoted value'
			=> [q{<div title='a > b' onclick="{{v}}">x</div>},           qr/event-handler attribute 'onclick'/],
		'R45: a > in an earlier value with an UNQUOTED dangerous attribute after it'
			=> ['<a title="a > b" href={{evil}}>x</a>',                  qr/unquoted attribute 'href'/],
		'a < inside an earlier quoted value is data, not a new tag'
			=> ['<div title="a < b" onclick="{{v}}">x</div>',            qr/event-handler attribute 'onclick'/],
		'an earlier quoted value containing a whole fake <script> tag'
			=> ['<div title="<script>" onclick="{{v}}">x</div>',         qr/event-handler attribute 'onclick'/],
		'no whitespace at all between two attributes'
			=> ['<a href="{{evil}}"onclick="{{v}}">x</a>',               qr/event-handler attribute 'onclick'/],
		'a stray solidus where the whitespace before an attribute would be'
			=> ['<div/onclick="{{v}}">x</div>',                          qr/event-handler attribute 'onclick'/],
		'an unquoted value ends at whitespace or >, never at the / of a self-closing tag'
			=> ['<img src={{x}}/>',                                      qr/unquoted attribute 'src'/],
		'"</scriptx" does not end a script body, so the {{ after it is still in script'
			=> [q{<script>var a='</scriptx'; var b="{{v}}";</script>},   qr/script/],
		'a DOCTYPE before the violation does not swallow it'
			=> ['<!DOCTYPE html><a href="{{evil}}">x</a>',               qr/URL-bearing attribute 'href'/],
		'a tag with no closing > at all is still reported (over-reports rather than under-reports)'
			=> ['<div onclick="{{v}}"',                                  qr/event-handler attribute 'onclick'/],
		'R46: a placeholder immediately after a < the template itself wrote'
			=> ['<p>5 <{{v}}> 6</p>',                                    qr/tag-name position/],
		'R46: a placeholder inside a tag NAME'
			=> ['<d{{d}} title="x">y</d>',                               qr/tag-name position/],
		'R46: a placeholder immediately after a </'
			=> ['</{{d}}>',                                              qr/tag-name position/],
		'R46: a placeholder inside an END-tag name, reported symmetrically'
			=> ['</d{{d}}>',                                             qr/tag-name position/],
		'R46: the raw marker in the same position'
			=> ['<p><{{{v}}}></p>',                                      qr/tag-name position/],
	);

	for my $name (sort keys %must_flag) {
		my ($html, $expect) = @{ $must_flag{$name} };
		my @f = _find_unsafe_placeholders($html);
		ok((grep { $_ =~ $expect } @f), "context scan: $name")
			or diag("findings: " . (@f ? join('; ', @f) : '(none)'));
	}

	# The R45 case is reachable, not theoretical - the same proof the
	# reviewer used: render() puts a live handler on the page.
	my $r45 = render('<div title="Count > 5" onclick="{{v}}">x</div>', { v => 'alert(1)' });
	like($r45, qr/onclick="alert\(1\)"/,
		'render() confirms the R45 danger is real: the onclick after the in-value > is a live attribute');

	# R46 is reachable too, and by the same mechanism as R41: the
	# escaping never touches structure the TEMPLATE supplied.
	# escape_html() escapes '<' and '>' inside a value - so a value can
	# never invent a tag - but it escapes neither space nor '=' nor '/',
	# so once the template has written the '<' itself the value supplies
	# the tag name and every attribute after it.
	my $r46 = render('<p>5 <{{v}}> 6</p>', { v => 'img src=x onerror=alert(1)' });
	like($r46, qr/<img src=x onerror=alert\(1\)>/,
		'render() confirms the R46 danger is real: a placeholder after the template\'s own < becomes a live tag');

	# And the whitespace case beside it is genuinely safe, not merely
	# unflagged: an HTML tokenizer emits a '<' followed by anything
	# other than a letter, '!', '/' or '?' as a character token, so the
	# escaped value next to it stays ordinary element content.
	my $r46_safe = render('<p>a < b and {{v}}</p>', { v => 'img src=x onerror=alert(1)' });
	like($r46_safe, qr/a < b and img src=x onerror=alert\(1\)</,
		'and "< {{v}}" with whitespace between is text to a tokenizer, which is why it is not flagged');

	# Negative: ordinary things a stats screen writes, plus every
	# construct the tokenizer now understands well enough NOT to flag.
	# Each of these was round-tripped through render() too; none can
	# produce a live handler or URL from a substituted value.
	my %must_not_flag = (
		'a commented-out handler is inert markup (the round-3 false positive)'
			=> '<!-- <button onclick="{{oldVal}}">Old</button> -->',
		'a commented-out <script> is inert too'
			=> '<!-- <script>{{v}}</script> -->',
		'a downlevel-revealed conditional comment is just a comment'
			=> '<!--[if IE]><script>{{v}}</script><![endif]-->',
		'a < in prose is text, not a tag'
			=> '<p>a < b and {{v}} too</p>',
		'a stat line whose prose contains a > comparison'
			=> '<p>Blocked > {{max}} attempts</p>',
		'a placeholder in a table cell'
			=> '<td>{{value}}</td>',
		'an = inside a <pre>'
			=> '<pre>key = {{value}}</pre>',
		'prose that happens to contain src='
			=> '<p>Try src="{{url}}" in config</p>',
		'an ordinary quoted attribute that is neither a handler nor a URL'
			=> '<div class="{{value}}">x</div>',
		'an aria-label carrying a value'
			=> '<button aria-label="Unblock {{id}}">x</button>',
		'a placeholder in a <title>'
			=> '<title>{{title}} - CSF</title>',
		'an end tag\'s attributes are discarded by the HTML parser'
			=> '</div onclick="{{v}}">',
		'a > inside an UNQUOTED value ends the tag, exactly as a browser ends it'
			=> '<div title=a>b onclick="{{v}}">x</div>',
		'"<!--" inside a tag is an attribute NAME, and the --> closes the tag'
			=> '<div <!-- -->onclick="{{v}}">x</div>',
		'a < followed by a digit starts nothing'
			=> '<1div onclick="{{v}}">',
	);

	for my $name (sort keys %must_not_flag) {
		my @f = _find_unsafe_placeholders($must_not_flag{$name});
		is_deeply(\@f, [], "context scan: not flagged - $name")
			or diag("unexpected findings: " . join('; ', @f));
	}

	# Why skipping comment content is sound rather than merely
	# convenient, proved against the real escape_html() rather than
	# asserted: EVERY way HTML5 ends a comment ("-->", "--!>", the
	# abrupt "<!-->"/"<!--->" forms) needs a literal '>', escape_html()
	# turns '>' into "&gt;", and entities are not decoded inside a
	# comment - so a substituted value cannot close the comment it sits
	# in and reach live markup.
	my $comment_out = render('<!-- {{v}} -->', { v => '--> <img src=x onerror=alert(1)>' });
	like($comment_out, qr/--&gt; &lt;img src=x onerror=alert\(1\)&gt;/,
		'comment safety: an escaped value carrying "-->" comes out with its > escaped');
	my $terminators = () = $comment_out =~ m{--!?>}g;
	is($terminators, 1,
		'comment safety: the rendered comment still has exactly one terminator - the template\'s own, not one the value supplied');

	# And the argument above covers the ESCAPED marker only. The raw
	# marker escapes nothing, so comment position must not exempt it -
	# _find_unauthorized_raw_markers() is context-free for exactly this
	# reason, and here is the proof it reaches inside a comment.
	my @raw_in_comment = _find_unauthorized_raw_markers('<!-- {{{v}}} -->', 'ui-src/web/layout.html');
	ok((grep { /\{\{\{v\}\}\}/ } @raw_in_comment),
		'comment safety does NOT extend to the raw marker: {{{v}}} inside a comment is still flagged');
}
###############################################################################
# R47, R48, R49 (fix round 5).
#
# R47 inverts the attribute rule: the href/src/action enumeration was the
# last regex-era artifact in this file, and the re-review showed its gap
# is reachable by ORDINARY markup - <button formaction="...{{id}}"> is
# just how the Block/Unblock screen's two-submit form gets written, with
# a guarded action= two lines above it teaching the wrong lesson. The
# fix is the one R42 already established for the raw marker: a blocklist
# of dangerous things can never be finished, an allowlist of safe ones
# can.
#
# R48 models <script>'s escaped and double-escaped states, which is a
# missing tokenizer STATE rather than a missing name in a list - R47
# cannot reach it, because no attribute is involved.
#
# R49 is a comment fix, not a code fix, per the round-5 brief. The
# under-report it now describes is pinned below so the description and
# the behaviour cannot drift apart again - which is exactly how the
# sentence came to be wrong in the first place.
###############################################################################
{
	# R47 positives. Every one of these is a quoted value that
	# escape_html() handles perfectly and that is dangerous anyway,
	# because the value is read as a URL, as CSS, or as a document.
	my %must_flag = (
		'R47: formaction (the re-review\'s own example - ordinary form markup)'
			=> ['<button formaction="/api/unblock?ip={{id}}">Unblock</button>', qr/formaction/],
		'R47: style, which Render.pm\'s header comment forbids and no earlier round flagged'
			=> ['<div style="width:{{max}}%"></div>',                  qr/'style'/],
		'R47: srcdoc, where the escaping is undone by the nested parse'
			=> ['<iframe srcdoc="{{v}}"></iframe>',                    qr/srcdoc/],
		'R47: xlink:href'
			=> ['<use xlink:href="{{evil}}"/>',                        qr/xlink:href/],
		'R47: bare "data" is a URL on <object> and is NOT covered by the data-* prefix'
			=> ['<object data="{{evil}}"></object>',                   qr/'data'/],
		'R47: poster'   => ['<video poster="{{evil}}"></video>',        qr/poster/],
		'R47: srcset'   => ['<img srcset="{{evil}} 2x">',               qr/srcset/],
		'R47: ping'     => ['<a ping="{{evil}}" href="/x">x</a>',       qr/ping/],
		'R47: background' => ['<table background="{{evil}}"></table>',  qr/background/],
		'R48: the re-review\'s example - </script> does not end a double-escaped body'
			=> ['<script><!--<script>x</script>{{v}}</script>',        qr/script/],
		'R48: the document.write("<!--<script") form reaches the same state'
			=> ['<script>document.write("<!--<script>");{{v}}</script>', qr/script/],
		'R48: an escaped body that never double-escapes is still a script body'
			=> ['<script><!-- x -->{{v}}</script>',                    qr/script/],
		'R48: double escaped, then --> returns to script data, still inside the element'
			=> ['<script><!--<script>a-->{{v}}</script>',              qr/script/],
	);

	for my $name (sort keys %must_flag) {
		my ($html, $expect) = @{ $must_flag{$name} };
		my @f = _find_unsafe_placeholders($html);
		ok((grep { $_ =~ $expect } @f), "context scan: $name")
			or diag("findings: " . (@f ? join('; ', @f) : '(none)'));
	}

	# The two that motivated R47 and R48 are reachable, not theoretical -
	# the same proof method as every round before this one.
	my $r47 = render('<button formaction="/api/unblock?ip={{id}}">Unblock</button>', { id => '1.2.3.4' });
	like($r47, qr{formaction="/api/unblock\?ip=1\.2\.3\.4"},
		'render() confirms R47 is reachable: formaction really is fed from the value');
	my $r47_style = render('<div style="width:{{pct}}%"></div>', { pct => '50' });
	like($r47_style, qr/style="width:50%"/,
		'render() confirms style= is a live CSS context fed from a value, which Render.pm:83 forbids');
	my $r48 = render('<script><!--<script>x</script>{{v}}</script>', { v => 'alert(1)' });
	like($r48, qr{<!--<script>x</script>alert\(1\)</script>},
		'render() confirms R48 is reachable: the value lands after a </script> that does not close the element');

	# R47 negatives: the ordinary Task 7 shapes, checked again because a
	# broad change to matching behaviour is exactly where the false
	# positives that got this guard disabled would come back.
	my %must_not_flag = (
		'title= carrying a value'          => '<td title="{{id}}">x</td>',
		'aria-label= carrying a value'     => '<button aria-label="Unblock {{id}}">x</button>',
		'aria-describedby= IDREF'          => '<input aria-describedby="help-{{id}}">',
		'data-* carrying values'           => '<tr data-ip="{{id}}" data-state="{{value}}">x</tr>',
		'the documented CSRF hidden field' => '<input type="hidden" name="_csrf" value="{{value}}">',
		'label/for/id pairing with a placeholder'
			=> '<label for="ip-{{id}}">IP</label><input id="ip-{{id}}" placeholder="{{url}}">',
		'class carrying a status modifier' => '<span class="badge badge-{{value}}">x</span>',
		'alt text'                         => '<img src="/static/i.png" alt="{{title}}">',
		'option value and label'           => '<option value="{{id}}">{{title}}</option>',
		'R48: <style> has no escape states, so </style> still ends it'
			=> '<style><!--<style>x</style>{{v}}</style>',
		'R48: in the escaped state a matching </script> DOES still end the element'
			=> '<script><!-- x </script>{{v}}',
	);

	for my $name (sort keys %must_not_flag) {
		my @f = _find_unsafe_placeholders($must_not_flag{$name});
		is_deeply(\@f, [], "context scan: not flagged - $name")
			or diag("unexpected findings: " . join('; ', @f));
	}

	# The allowlist is a list, so it is tested as one rather than only
	# through the markup above: every name on it, and the two shapes
	# that must NOT be mistaken for a prefix match.
	ok(_attribute_is_inert($_), "inert allowlist: '$_' is on it")
		for qw(alt class for id label name placeholder title value ARIA-LABEL data-ip);
	ok(!_attribute_is_inert($_), "inert allowlist: '$_' is NOT on it")
		for qw(data srcdoc style formaction href onclick datafoo ariafoo);

	# R49: the RCDATA under-report the header comment now describes.
	# Pinned so the sentence and the behaviour cannot drift apart again -
	# drift is precisely how that sentence came to claim "fails closed"
	# for something that also fails open.
	my $rcdata = q{<textarea><div title="</textarea><button onclick='{{v}}'>">x</div></textarea>};
	is_deeply([ _find_unsafe_placeholders($rcdata) ], [],
		'R49: the RCDATA under-report is real - the scanner sees an inert title=, not the button');
	my $rcdata_out = render($rcdata, { v => 'alert(1)' });
	like($rcdata_out, qr/<button onclick='alert\(1\)'>/,
		q{R49: ... and render() produces the live handler a browser sees, because RCDATA ends at that </textarea>});

	# The other direction of the same blindness, also now described
	# rather than claimed to be the only one.
	ok((grep { /onclick/ } _find_unsafe_placeholders('<textarea><button onclick="{{v}}"></textarea>')),
		'R49: the over-report direction is real too - inert markup inside a textarea is still flagged');
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
			. "must never be the NAME of an attribute nor any part of a TAG name, only the value of an attribute on the inert allowlist in this file; the raw {{{ }}} marker is only "
			. "authorised for layout.html's own nav/content slots - if a screen genuinely needs to insert raw HTML "
			. "it built itself, add it to \%RAW_MARKER_ALLOWLIST in this file and say why in the same commit; and "
			. "dynamic data a <script> needs should be placed OUTSIDE the <script> tag (a data-* attribute the "
			. "script reads) rather than interpolated into its source text.");
}
