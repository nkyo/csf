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
# A tiny, single-purpose template substitutor for the web tier's rendering
# layer (docs/WEBUI-PLAN.md S8, task-6-brief.md). It knows nothing about HTTP,
# sessions, routes or files on disk beyond reading one path in render_file();
# ui-src/bin/csf-ui (Task 4/7) is the only caller and decides which template
# goes with which request.
#
# THE ONE RULE THIS MODULE EXISTS TO ENFORCE: every value that reaches the
# HTML this produces went through escape_html() unless the template author
# wrote the three-brace marker on purpose. Everything that flows into a
# screen - IP addresses out of log lines, block comments out of csf.deny
# entries that themselves originated in log data, usernames out of failed-
# login records - is attacker-shaped text by the time it reaches here, so
# the safe outcome has to be the one that requires no one to remember
# anything:
#
#   {{key}}    HTML-escaped.   The default. Forgetting to escape is
#              impossible - there is no way to ask for unescaped output
#              with this spelling.
#   {{{key}}}  Inserted raw, byte for byte. Requires typing an extra
#              brace on each side; used ONLY for a value the calling code
#              built itself out of already-escaped pieces (the canonical
#              case: a screen handler calls render() once per row of a
#              table, HTML-escaping each cell through the {{}} form, joins
#              the rows into one string, and hands that whole string to
#              the page template as a {{{content}}} or {{{rows}}} var).
#              A raw var must never be attacker text end to end - if it
#              is, something upstream of this module already made the
#              escaping decision, not this call.
#
# A key absent from the vars hashref, or present with an undef or reference
# value, is a die(), not a blank. A template that silently renders an empty
# string where a value belongs is exactly the failure mode this exists to
# rule out (task-6-brief.md: "A missing key must be an error, not a
# silently empty string - a blank where a value should be is how a broken
# template ships unnoticed"). render() never returns a partially-filled
# page; it either returns the whole thing or dies before producing any
# output. Callers that want a request to survive a template bug still can -
# ui-src/bin/csf-ui's dispatch() already wraps every route in an eval and
# turns any die into a generic 500 (see its header comment) - but that is
# the caller's choice to make, not something silently absorbed here.
#
# SINGLE PASS, NOT RECURSIVE. Substitution runs as one s///ge over the
# template text; Perl's /g resumes scanning immediately after the text a
# match was replaced with, not from the start of that replacement, so
# nothing this module inserts is ever re-scanned for placeholders of its
# own. A value that is itself the literal text "{{key}}" (an attacker
# typing template syntax at a form field, or a legitimate note that
# happens to contain double braces) is HTML-escaped like any other value
# and appears on the page as inert text, never expanded, never able to
# smuggle a raw marker into existence. This is verified in t/50-render.t
# rather than only asserted here.
#
# SCOPE OF THE ESCAPING, READ THIS BEFORE ADDING A TEMPLATE. escape_html()
# escapes the five characters HTML needs escaped to stay inert as element
# content AND as the value of a QUOTED attribute (single or double):
# & < > " '. That one function covers both contexts because every
# attribute in every template this module ever renders is quoted - an
# unquoted attribute value is not, and must never be, produced by any
# template in this tree, because " and ' are exactly what keep a quoted
# value from being broken out of and an unquoted one has no such boundary
# at all (a bare space in the escaped output would end it early). It does
# NOT make a value safe to place inside a <script> block, an inline event
# handler (onclick="..."), a "javascript:" URL, or a <style> block/CSS
# value - an HTML tokenizer looks for a literal "</script" byte sequence
# to end a script element without decoding entities first, so an escaped
# "<" does not stop it, and none of "&<>\"'" is what JavaScript or CSS
# syntax needs escaped anyway. No template in this tree may put a {{}} or
# {{{}}} substitution inside <script>, <style>, an on* attribute, or a
# URL-typed attribute (href/src/action) fed from a var - if a future
# screen needs one of those, it needs a different escaping function, not
# a misuse of this one.
###############################################################################
package ConfigServer::UI::Render;

use strict;
use warnings;

our $VERSION = '1.00';

# A key is a bare identifier: a letter or underscore, then letters, digits
# or underscores. No spaces inside the braces, no dots, no brackets - keys
# name one scalar in the vars hashref and nothing more structured than
# that. A template that misspells a marker (extra space, wrong case used
# consistently as a different literal key, ...) simply does not match this
# pattern and passes through as literal text, which is a visible bug in
# the rendered page rather than a silent one - the template author sees
# "{{ key }}" sitting on the screen and fixes it, not something that
# needed a test to notice at all.
my $KEY_RE = qr/[A-Za-z_][A-Za-z0-9_]*/;

# Alternation order matters: the three-brace form is tried first at every
# position, so "{{{key}}}" is never seen as "{" followed by a two-brace
# match starting one character in. Only one of the two capture groups is
# ever defined for a given match; _substitute() below uses that to tell
# raw from escaped.
my $PLACEHOLDER_RE = qr/\{\{\{($KEY_RE)\}\}\}|\{\{($KEY_RE)\}\}/;

###############################################################################
# escape_html($value) -> $text
#
# The five characters HTML gives meaning to that plain data must not:
# & (entity introducer) < > (tag delimiters) " ' (attribute-value
# delimiters, either quote style). Order matters - & is escaped first, so
# the & introduced by escaping < > " ' is never itself re-escaped into
# &amp;amp;.
#
# $value must be defined and must not be a reference: a reference
# stringifies to something like "HASH(0x55a1b2c3d4e5)", which is not a
# value any template meant to show and which a caller would have no way
# to notice went wrong (G3 - failing to die here would be exactly the
# "silently empty [or silently wrong]" outcome the brief rules out for
# render() itself; the same standard applies to the primitive it is built
# from).
###############################################################################
sub escape_html {
	my ($value) = @_;
	die "escape_html: value is undef, not a string\n" unless defined $value;
	die "escape_html: value is a reference (@{[ref $value]}), not a plain scalar\n" if ref $value;

	my $text = "$value";
	$text =~ s/&/&amp;/g;
	$text =~ s/</&lt;/g;
	$text =~ s/>/&gt;/g;
	$text =~ s/"/&quot;/g;
	$text =~ s/'/&#39;/g;
	return $text;
}

###############################################################################
# render($template, \%vars) -> $html
#
# $template is a plain string, byte-for-byte - this module never decodes it
# as UTF-8 characters and never sets Perl's internal UTF-8 flag on its
# output, the same "raw bytes in, raw bytes out, verbatim to the wire"
# convention docs/WEBUI-RPC.md S14.2 states for the request/response
# structures csf-ui builds around this (that document's own words: a value
# "produces a raw byte string (no UTF-8 flag), even when the decoded bytes
# are a valid multi-byte UTF-8 sequence" - S1053 names this module by task
# number as the layer that does the escaping such bytes still need). This
# is safe for the five ASCII characters escape_html() looks for: every byte
# of a multi-byte UTF-8 sequence's continuation and lead bytes is >= 0x80,
# so none of "&<>\"'" (all < 0x80) can ever appear as part of one, and
# scanning byte-by-byte for them can never misfire partway through a
# multi-byte character or corrupt one.
#
# Every {{key}} / {{{key}}} in $template is replaced in one pass (see the
# module header for why one pass matters). A key not present in %vars, or
# present with an undef or reference value, is a die() naming the key -
# never a blank. The key names embedded in die() messages come from the
# TEMPLATE text (trusted, written by this codebase), never from a
# substituted value, so there is nothing here that could turn attacker
# data into a log/error-message injection the way an escaped value's
# content would if this module ever put IT in a die() - it doesn't.
###############################################################################
sub render {
	my ($template, $vars) = @_;
	die "render: template is undef, not a string\n" unless defined $template;
	die "render: template is a reference, not a plain scalar\n" if ref $template;
	die "render: vars must be a hashref\n" unless ref($vars) eq 'HASH';

	my $out = "$template";
	$out =~ s/$PLACEHOLDER_RE/ _substitute($1, $2, $vars) /ge;
	return $out;
}

# One match's worth of work: exactly one of $raw_key/$escaped_key is
# defined, per $PLACEHOLDER_RE's two alternatives.
sub _substitute {
	my ($raw_key, $escaped_key, $vars) = @_;
	return _lookup($raw_key, $vars) if defined $raw_key;
	return escape_html(_lookup($escaped_key, $vars));
}

sub _lookup {
	my ($key, $vars) = @_;
	die "render: missing template variable '$key'\n" unless exists $vars->{$key};

	my $value = $vars->{$key};
	die "render: template variable '$key' is undef, not a string\n" unless defined $value;
	die "render: template variable '$key' is a reference (@{[ref $value]}), not a plain scalar\n" if ref $value;

	return "$value";
}

###############################################################################
# render_file($path, \%vars) -> $html
#
# A thin convenience wrapper: read the whole file at $path as raw bytes -
# no ":encoding" layer, so Perl's UTF-8 flag is never set on what render()
# then sees, the same byte-safety render()'s own header comment explains -
# and hand it to render(). Any I/O failure (missing file, permission
# denied, ...) is a die() naming $path and the OS error; this function
# never returns a partial read or a default page in place of one, which
# would be the same "unnoticed brokenness" the brief rules out for a
# missing template key, just one layer earlier.
###############################################################################
sub render_file {
	my ($path, $vars) = @_;
	die "render_file: path is undef\n" unless defined $path;

	open(my $fh, '<:raw', $path) or die "render_file: cannot open '$path': $!\n";
	local $/;
	my $template = <$fh>;
	close $fh;
	die "render_file: '$path' is empty or unreadable\n" unless defined $template;

	return render($template, $vars);
}

1;
