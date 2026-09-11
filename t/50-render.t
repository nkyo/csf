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

use File::Temp qw(tempdir);
use Test::More tests => 70;

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
