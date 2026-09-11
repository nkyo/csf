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
# Task 7's five server-rendered screens (task-7-brief.md: "each screen
# renders with fixture data; a support session is refused every mutating
# route with 403; CSRF missing or wrong -> 403; pagination bounds"). t/33-
# app.t already proves _gate()'s own mechanics (session/role/CSRF) against
# the /api/* tier in isolation; this file does not re-derive those
# mechanics, it proves the NEW /ui/* rows in @ROUTES are wired to the SAME
# _gate() with the RIGHT flags, and that each screen's own handler renders
# sensible HTML from fixture RPC responses without dying.
#
# The RPC client is the same scripted fake t/33-app.t uses - t/32-client.t
# already proves the real Client's wire behaviour, so this file only needs
# to prove the screen handlers call it correctly and render correctly from
# what comes back.
###############################################################################
use strict;
use warnings;

use FindBin ();
use lib "$FindBin::Bin/..", "$FindBin::Bin/../ui-src/lib";

use File::Temp qw(tempdir);
use JSON::Tiny ();
use Test::More tests => 120;

my $APP_PATH = "$FindBin::Bin/../ui-src/bin/csf-ui";
ok(-f $APP_PATH, 'csf-ui is where the brief says it is');
require $APP_PATH;
my $A = 'ConfigServer::UI::App';
my $WEB_ROOT = "$FindBin::Bin/../ui-src/web";
ok(-f "$WEB_ROOT/layout.html", 'the real ui-src/web tree is reachable from this test (not a vacuous pass)');

###############################################################################
# Same scripted RPC client as t/33-app.t - records every call, answers from
# a queue of canned responses keyed by operation.
###############################################################################
package FakeClient;

sub new {
	my ($class, %opt) = @_;
	return bless { responses => $opt{responses} || {}, calls => [], n => 0 }, $class;
}

sub generate_id {
	my ($self) = @_;
	return 'fake-id-' . (++$self->{n});
}

sub call {
	my ($self, $op, $args, %opt) = @_;
	push @{ $self->{calls} }, { op => $op, args => $args, id => $opt{id} };
	my $queue = $self->{responses}{$op};
	my $canned = ($queue && @$queue) ? shift @$queue : undef;
	return $canned if $canned;
	return { id => $opt{id}, ok => 1, data => {} };
}

package main;

###############################################################################
# Fixture data, shaped exactly per docs/WEBUI-RPC.md's own examples.
###############################################################################
my $ID_ORPHAN = 'a' x 32;
my $ID_GHOST  = 'b' x 32;

sub _status_ok {
	return { ok => 1, data => { enabled => 1, rules_loaded => 1, testing => 0, ipv6 => 0,
		lfd_running => 1, version => '15.00', start_error => undef, ipset_mode => 0, generated => 1_757_548_800 } };
}
sub _counts_ok {
	return { ok => 1, data => { deny => 412, allow => 37, temp_deny => 19, temp_allow => 2,
		deny_includes => 0, allow_includes => 1, generated => 1_757_548_800 } };
}
sub _reconcile_empty {
	return { ok => 1, data => { totals => { orphan => 0, ghost => 0, dup => 0 },
		returned => 0, truncated => \0, generated => 1_757_548_800, entries => [] } };
}
sub _reconcile_with_findings {
	return { ok => 1, data => { totals => { orphan => 1, ghost => 1, dup => 0 },
		returned => 2, truncated => \0, generated => 1_757_548_800,
		entries => [
			{ id => $ID_ORPHAN, kind => 'ORPHAN', family => 4, chain => 'DENYIN',
				ip => '198.51.100.7', spec => '-s 198.51.100.7/32 -j DROP', fixable => \1, reason => undef },
			{ id => $ID_GHOST, kind => 'GHOST', family => 4, chain => 'DENYIN',
				ip => '198.51.100.8', spec => '-s 198.51.100.8/32 -j DROP', fixable => \0, reason => 'restart required' },
		] } };
}
sub _list_one_row {
	my (%opt) = @_;
	return { ok => 1, data => { which => $opt{which} || 'deny', total => $opt{total} || 1, offset => $opt{offset} || 0,
		returned => 1, next_offset => $opt{next_offset}, truncated => \0, includes => 0,
		rows => [ { ip => '192.0.2.10', note => $opt{note} || 'abuse ticket 4471', protected => \0, line => 37 } ] } };
}

###############################################################################
# Fixture builder - same shape as t/33-app.t's _build(), plus web_root
# pointed at the real ui-src/web tree so every screen renders through its
# actual template files, not a stub.
###############################################################################
sub _build {
	my (%opt) = @_;
	my $base = tempdir(CLEANUP => 1);
	my $now  = $opt{now} || 1_000_000;
	my $client = FakeClient->new(responses => $opt{responses} || {});
	my $sessions  = ConfigServer::UI::Session->new(dir => "$base/sessions", now => sub { $now });
	my $ratelimit = ConfigServer::UI::RateLimit->new(dir => "$base/rl", now => sub { $now });
	my $app = $A->new(
		client     => $client,
		sessions   => $sessions,
		ratelimit  => $ratelimit,
		access_log => "$base/access.log",
		web_root   => $WEB_ROOT,
		now        => sub { $now },
	);
	return ($app, $client, $sessions, $ratelimit);
}

sub _location {
	my ($response) = @_;
	my ($loc) = grep { $_->[0] eq 'Location' } @{ $response->{headers} };
	return $loc ? $loc->[1] : undef;
}

sub _query_of {
	my ($url) = @_;
	my (undef, $qs) = split(/\?/, $url, 2);
	return {} unless defined $qs && length $qs;
	my %q;
	for my $pair (split /&/, $qs) {
		my ($k, $v) = split /=/, $pair, 2;
		$k = _pct_decode($k);
		$v = defined $v ? _pct_decode($v) : '';
		$q{$k} = $v;
	}
	return \%q;
}

sub _pct_decode {
	my ($t) = @_;
	$t =~ tr/+/ /;
	$t =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/ge;
	return $t;
}

###############################################################################
# Every screen renders 200 with fixture data (task-7-brief.md's own words).
###############################################################################
{
	my ($app, undef, $sessions) = _build(responses => {
		status    => [ _status_ok() ],
		counts    => [ _counts_ok() ],
		reconcile => [ _reconcile_empty() ],
	});
	my $sess = $sessions->create(user => 'alice', role => 'admin');
	my $cookie = "csfui_sid=$sess->{id}";

	my $r = $app->dispatch({ method => 'GET', path => '/ui/overview', headers => { cookie => $cookie }, peer => '203.0.113.1' });
	is($r->{status}, 200, 'GET /ui/overview renders (fixture data)');
	like($r->{body}, qr/Enabled/, 'Overview shows the enabled badge text');
	like($r->{body}, qr/412/, 'Overview shows the deny count from fixture data');
	unlike($r->{body}, qr/render: missing template variable/, 'Overview never leaks a Render.pm die() into the page');
}

{
	my ($app, undef, $sessions) = _build();
	my $sess = $sessions->create(user => 'alice', role => 'admin');
	my $r = $app->dispatch({ method => 'GET', path => '/ui/block', headers => { cookie => "csfui_sid=$sess->{id}" }, peer => '203.0.113.1' });
	is($r->{status}, 200, 'GET /ui/block renders');
	like($r->{body}, qr/action="\/ui\/block\/deny"/, 'Block screen has a deny form');
	like($r->{body}, qr/action="\/ui\/block\/tempdeny"/, 'Block screen has a tempdeny form');
	like($r->{body}, qr/action="\/ui\/block\/allow"/, 'Block screen has an allow form');
	like($r->{body}, qr/action="\/ui\/block\/undeny"/, 'Block screen has an undeny form');
}

{
	my ($app, undef, $sessions) = _build(responses => { list => [ _list_one_row(which => 'deny') ] });
	my $sess = $sessions->create(user => 'alice', role => 'admin');
	my $r = $app->dispatch({ method => 'GET', path => '/ui/lists', query => {}, headers => { cookie => "csfui_sid=$sess->{id}" }, peer => '203.0.113.1' });
	is($r->{status}, 200, 'GET /ui/lists renders');
	like($r->{body}, qr/192\.0\.2\.10/, 'Lists shows the fixture row');
	like($r->{body}, qr/action="\/ui\/lists\/undeny"/, 'admin sees the undeny form on a which=deny row');
}

{
	my ($app, undef, $sessions) = _build();
	my $sess = $sessions->create(user => 'alice', role => 'admin');
	my $r = $app->dispatch({ method => 'GET', path => '/ui/lookup', query => {}, headers => { cookie => "csfui_sid=$sess->{id}" }, peer => '203.0.113.1' });
	is($r->{status}, 200, 'GET /ui/lookup renders with no query yet');

	my ($app2, undef, $sessions2) = _build(responses => {
		grep => [ { ok => 1, data => { ip => '192.0.2.10', lines => ['filter DENYIN  all  --  192.0.2.10'], count => 1, truncated => \0 } } ],
	});
	my $sess2 = $sessions2->create(user => 'alice', role => 'admin');
	my $r2 = $app2->dispatch({ method => 'GET', path => '/ui/lookup', query => { ip => '192.0.2.10' },
		headers => { cookie => "csfui_sid=$sess2->{id}" }, peer => '203.0.113.1' });
	is($r2->{status}, 200, 'GET /ui/lookup?ip=... renders a result');
	like($r2->{body}, qr/filter DENYIN/, 'lookup result shows the grep output line');
	my $call = $app2->{client}->{calls}[-1];
	is($call->{op}, 'grep', 'a lookup query calls the grep operation');
	is($call->{args}{ip}, '192.0.2.10', 'with the submitted ip');
}

{
	my ($app, undef, $sessions) = _build(responses => { reconcile => [ _reconcile_with_findings() ] });
	my $sess = $sessions->create(user => 'alice', role => 'admin');
	my $r = $app->dispatch({ method => 'GET', path => '/ui/health', headers => { cookie => "csfui_sid=$sess->{id}" }, peer => '203.0.113.1' });
	is($r->{status}, 200, 'GET /ui/health renders');
	like($r->{body}, qr/ORPHAN/, 'Health shows the ORPHAN finding');
	like($r->{body}, qr/GHOST/, 'Health shows the GHOST finding');
	like($r->{body}, qr/name="fix_id_0"/, 'the fixable finding has a checkbox');
	unlike($r->{body}, qr/name="fix_id_1"/, 'the unfixable (GHOST) finding has no checkbox at all');
	like($r->{body}, qr/Not fixable: restart required/, 'the unfixable finding shows its reason');

	# The "no one-click cleanup" guarantee itself (docs/WEBUI-RPC.md S5.12),
	# checked against the actual rendered markup rather than only against
	# the route table: the ONLY form on this page posts to /ui/health/review
	# (never mutating), and it never posts straight to /ui/health/apply
	# (the only route that calls reconcile_fix) - see the guard-removal
	# verification in task-7-report.md, which proves this exact assertion
	# is what catches that specific regression.
	like($r->{body}, qr/action="\/ui\/health\/review"/, 'the findings form posts to the review step, not straight to a mutation');
	unlike($r->{body}, qr/action="\/ui\/health\/apply"/, 'GET /ui/health never renders a form that posts directly to /ui/health/apply');
}

{
	my ($app) = _build();
	my $r = $app->dispatch({ method => 'GET', path => '/ui/login', headers => {}, peer => '203.0.113.1' });
	is($r->{status}, 200, 'GET /ui/login renders with no session at all');
	like($r->{body}, qr/action="\/ui\/login"/, 'login screen posts to /ui/login');
	unlike($r->{body}, qr/csfui_sid/, 'the login screen carries no session cookie value anywhere in its body');
}

{
	my ($app) = _build();
	my $r = $app->dispatch({ method => 'GET', path => '/app.css', headers => {}, peer => '203.0.113.1' });
	is($r->{status}, 200, 'GET /app.css is served with no session');
	my ($ct) = grep { $_->[0] eq 'Content-Type' } @{ $r->{headers} };
	like($ct->[1], qr{text/css}, 'app.css is served with a CSS content type');
	like($r->{body}, qr/site-nav/, 'app.css body looks like the real stylesheet');
}

###############################################################################
# Escaping, end to end: a note carrying markup renders inert, through the
# REAL render() and REAL templates - t/50-render.t already proves the
# static templates are safe in the abstract; this proves a concrete
# attacker-shaped value survives a real request/response round trip
# without becoming live markup.
###############################################################################
{
	my ($app, undef, $sessions) = _build(responses => {
		list => [ _list_one_row(note => '<script>alert(1)</script>" onmouseover="alert(2)') ],
	});
	my $sess = $sessions->create(user => 'alice', role => 'admin');
	my $r = $app->dispatch({ method => 'GET', path => '/ui/lists', query => {}, headers => { cookie => "csfui_sid=$sess->{id}" }, peer => '203.0.113.1' });
	unlike($r->{body}, qr/<script>alert\(1\)<\/script>/, 'a malicious note never appears as a live <script> tag');
	unlike($r->{body}, qr/onmouseover="alert\(2\)"/, 'a malicious note never breaks out into a live attribute');
	like($r->{body}, qr/&lt;script&gt;alert\(1\)&lt;\/script&gt;/, 'the note is present, but HTML-escaped');
}

###############################################################################
# Pagination bounds (task-7-brief.md's own words).
###############################################################################
{
	my ($app, undef, $sessions) = _build(responses => { list => [ _list_one_row(offset => 0, next_offset => undef) ] });
	my $sess = $sessions->create(user => 'alice', role => 'admin');
	my $r = $app->dispatch({ method => 'GET', path => '/ui/lists', query => { which => 'deny', offset => '0' },
		headers => { cookie => "csfui_sid=$sess->{id}" }, peer => '203.0.113.1' });
	unlike($r->{body}, qr/>Previous</, 'offset 0: no Previous control');
	unlike($r->{body}, qr/>Next</, 'next_offset null: no Next control');
}
{
	my ($app, undef, $sessions) = _build(responses => { list => [ _list_one_row(offset => 25, next_offset => 50) ] });
	my $sess = $sessions->create(user => 'alice', role => 'admin');
	my $r = $app->dispatch({ method => 'GET', path => '/ui/lists', query => { which => 'deny', offset => '25' },
		headers => { cookie => "csfui_sid=$sess->{id}" }, peer => '203.0.113.1' });
	like($r->{body}, qr/>Previous</, 'offset 25: a Previous control is present');
	like($r->{body}, qr/>Next</, 'next_offset 50: a Next control is present');
	like($r->{body}, qr/name="offset" value="0"/, 'Previous carries offset back to 0 (25 - limit 25), never negative');
	like($r->{body}, qr/name="offset" value="50"/, 'Next carries next_offset (50) verbatim, never offset + limit computed locally');
}

###############################################################################
# Role enforcement: a support session is refused every admin-only /ui/*
# route with 403 - the page-level GET routes AND every mutating POST.
# task-7-brief.md: "support sees only IP lookup and read-only Lists ... not
# Overview, not Health; the server enforces this per request".
###############################################################################
{
	my @admin_only_get = (
		['/ui/overview', 'Overview'],
		['/ui/block',    'Block'],
		['/ui/health',   'Health'],
	);
	for my $case (@admin_only_get) {
		my ($path, $label) = @$case;
		my ($app, undef, $sessions) = _build();
		my $sess = $sessions->create(user => 'trent', role => 'support');
		my $r = $app->dispatch({ method => 'GET', path => $path, headers => { cookie => "csfui_sid=$sess->{id}" }, peer => '1.2.3.4' });
		is($r->{status}, 403, "support cannot reach $label ($path)");
	}

	my ($app_ok, undef, $sessions_ok) = _build(responses => { list => [ _list_one_row() ] });
	my $sess_ok = $sessions_ok->create(user => 'trent', role => 'support');
	for my $path (qw(/ui/lists /ui/lookup)) {
		my $r = $app_ok->dispatch({ method => 'GET', path => $path, query => {}, headers => { cookie => "csfui_sid=$sess_ok->{id}" }, peer => '1.2.3.4' });
		is($r->{status}, 200, "support CAN reach $path");
	}
}

# Every mutating /ui/* route, enumerated straight from @ROUTES (the same
# R27-style mechanical technique t/33-app.t uses for /api/*, so a future
# route that forgets to restrict itself to admin fails THIS test rather
# than shipping reachable-by-support).
my @UI_MUTATING;
{
	no warnings 'once'; # @ConfigServer::UI::App::ROUTES is touched exactly once in this file
	@UI_MUTATING = sort { $a->{path} cmp $b->{path} }
		grep { $_->{path} =~ m{^/ui/} && $_->{mutates} && !$_->{anonymous} } @ConfigServer::UI::App::ROUTES;
}
is(scalar(@UI_MUTATING), 11, 'sanity: this checks all eleven mutating /ui/* routes (10 admin-only + logout)');

{
	for my $route (@UI_MUTATING) {
		next if $route->{any_role};   # /ui/logout: both roles may end their own session
		my ($app, undef, $sessions) = _build();
		my $sess = $sessions->create(user => 'trent', role => 'support');
		my $r = $app->dispatch({ method => uc($route->{method}), path => $route->{path},
			headers => { cookie => "csfui_sid=$sess->{id}", 'x-csrf-token' => $sess->{csrf} },
			body => '', peer => '1.2.3.4' });
		is($r->{status}, 403, "support cannot reach $route->{path}, even with a valid CSRF token");
		my $body = eval { JSON::Tiny::decode_json($r->{body}) } || {};
		is($body->{error}, 'WEB_FORBIDDEN', "...and the refusal is the role check, not the CSRF check, for $route->{path}");
	}
}

###############################################################################
# CSRF missing or wrong -> 403, for every mutating /ui/* route (task-7-
# brief.md's own words) - the same mechanical enumeration, this time with
# an admin session (so role can never be the reason for the refusal) and
# no field values at all, since _gate() refuses before the handler ever
# looks at the body.
###############################################################################
{
	for my $route (@UI_MUTATING) {
		my ($app, undef, $sessions) = _build();
		my $sess = $sessions->create(user => 'adele', role => 'admin');
		my $cookie = "csfui_sid=$sess->{id}";

		my $r1 = $app->dispatch({ method => uc($route->{method}), path => $route->{path},
			headers => { cookie => $cookie }, body => '', peer => '1.2.3.4' });
		is($r1->{status}, 403, "$route->{path}: no CSRF token at all is refused");

		my $r2 = $app->dispatch({ method => uc($route->{method}), path => $route->{path},
			headers => { cookie => $cookie, 'x-csrf-token' => 'totally-wrong' }, body => '', peer => '1.2.3.4' });
		is($r2->{status}, 403, "$route->{path}: a wrong CSRF token is refused");
	}
}

###############################################################################
# Health's destructive flow: review, then apply - docs/WEBUI-RPC.md S5.12's
# "a diff shown and a separate confirmation", proved end to end.
###############################################################################
{
	my ($app, $client, $sessions) = _build(responses => {
		reconcile => [ _reconcile_with_findings(), _reconcile_with_findings() ],
	});
	my $sess = $sessions->create(user => 'alice', role => 'admin');
	my $cookie = "csfui_sid=$sess->{id}";

	# Step 1: the operator selects the fixable finding (fix_id_0) and
	# leaves the unfixable one alone (it never had a checkbox to submit).
	my $r1 = $app->dispatch({ method => 'POST', path => '/ui/health/review',
		headers => { cookie => $cookie, 'x-csrf-token' => $sess->{csrf} },
		body => "fix_id_0=$ID_ORPHAN", peer => '1.2.3.4' });
	is($r1->{status}, 200, 'POST /ui/health/review (fresh reconcile ok) renders a confirmation page');
	like($r1->{body}, qr/rule\(s\) will be deleted/, 'the review page states what will be deleted');
	like($r1->{body}, qr/198\.51\.100\.7/, 'the review page shows the surviving finding');
	unlike($r1->{body}, qr/198\.51\.100\.8/, 'the review page does not show the GHOST finding, which was never selectable');
	like($r1->{body}, qr/name="apply_id_0"\s+value="$ID_ORPHAN"/, 'the review page carries the id forward as a hidden field');
	is(scalar(grep { $_->{op} eq 'reconcile' } @{ $client->{calls} }), 1,
		'reviewing runs its own FRESH reconcile scan rather than trusting the page just shown');

	# Step 2: apply - the only route that ever calls reconcile_fix.
	my ($app2, $client2, $sessions2) = _build(responses => {
		reconcile_fix => [ { ok => 1, data => { fixed => 1, stale => 0, unfixable => 0,
			results => [ { id => $ID_ORPHAN, outcome => 'deleted' } ] } } ],
	});
	my $sess2 = $sessions2->create(user => 'alice', role => 'admin');
	my $r2 = $app2->dispatch({ method => 'POST', path => '/ui/health/apply',
		headers => { cookie => "csfui_sid=$sess2->{id}", 'x-csrf-token' => $sess2->{csrf} },
		body => "apply_id_0=$ID_ORPHAN", peer => '1.2.3.4' });
	is($r2->{status}, 303, 'POST /ui/health/apply redirects back to Health');
	is(_location($r2), '/ui/health?msg=1%20fixed%2C%200%20stale%2C%200%20unfixable.', 'with an outcome summary in the flash');
	my $fix_call = $client2->{calls}[-1];
	is($fix_call->{op}, 'reconcile_fix', 'apply calls reconcile_fix');
	is_deeply($fix_call->{args}{ids}, [$ID_ORPHAN], 'with exactly the id carried forward from the review page, as a real array');

	# Nothing was selected at all: apply must never call reconcile_fix with
	# an empty ids array (docs/WEBUI-RPC.md S4.8: 1-500 strings, not 0).
	my ($app3, $client3, $sessions3) = _build();
	my $sess3 = $sessions3->create(user => 'alice', role => 'admin');
	my $r3 = $app3->dispatch({ method => 'POST', path => '/ui/health/apply',
		headers => { cookie => "csfui_sid=$sess3->{id}", 'x-csrf-token' => $sess3->{csrf} },
		body => '', peer => '1.2.3.4' });
	is($r3->{status}, 303, 'apply with nothing selected still redirects, not a crash');
	is(scalar(grep { $_->{op} eq 'reconcile_fix' } @{ $client3->{calls} }), 0,
		'and reconcile_fix is never called with an empty ids array');
}

{
	# A selected id that is no longer in the fresh scan (S5.12's own
	# "stale" case) - the review page must say so, not silently drop it or
	# silently proceed as if it were fine.
	my $stale_id = 'c' x 32;
	my ($app, undef, $sessions) = _build(responses => { reconcile => [ _reconcile_with_findings() ] });
	my $sess = $sessions->create(user => 'alice', role => 'admin');
	my $r = $app->dispatch({ method => 'POST', path => '/ui/health/review',
		headers => { cookie => "csfui_sid=$sess->{id}", 'x-csrf-token' => $sess->{csrf} },
		body => "fix_id_0=$stale_id", peer => '1.2.3.4' });
	is($r->{status}, 200, 'reviewing a since-vanished id still renders (no crash)');
	like($r->{body}, qr/no longer present or no longer fixable/, 'the page says the selection is stale');
	like($r->{body}, qr/nothing to apply|None of the selected findings/, 'and offers no Yes-delete form when nothing survived');
}

###############################################################################
# Login: success mints a session and redirects by role; failure re-renders
# the form with an error, never a raw JSON body.
###############################################################################
{
	my ($app, $client) = _build(responses => { authenticate => [ { ok => 1, data => { ok => 1, role => 'admin' } } ] });
	my $r = $app->dispatch({ method => 'POST', path => '/ui/login', headers => {}, body => 'user=alice&pass=correct+horse', peer => '5.5.5.5' });
	is($r->{status}, 303, 'a successful admin login redirects');
	is(_location($r), '/ui/overview', 'admin lands on Overview');
	my ($set_cookie) = grep { $_->[0] eq 'Set-Cookie' } @{ $r->{headers} };
	like($set_cookie->[1], qr/\Acsfui_sid=/, 'and a session cookie is set');
	is($client->{calls}[-1]{args}{pass}, 'correct horse', 'the password is forwarded to authenticate');
}
{
	my ($app) = _build(responses => { authenticate => [ { ok => 1, data => { ok => 1, role => 'support' } } ] });
	my $r = $app->dispatch({ method => 'POST', path => '/ui/login', headers => {}, body => 'user=bob&pass=x', peer => '5.5.5.5' });
	is(_location($r), '/ui/lookup', 'support lands on IP lookup, the one screen it can use');
}
{
	my ($app) = _build(responses => { authenticate => [ { ok => 1, data => { ok => 0, role => undef, locked => 0, retry_after => 0 } } ] });
	my $r = $app->dispatch({ method => 'POST', path => '/ui/login', headers => {}, body => 'user=carol&pass=wrong', peer => '6.6.6.6' });
	is($r->{status}, 200, 'a wrong password re-renders the login page, not a redirect');
	like($r->{body}, qr/Wrong username or password/, 'with a visible error message');
	unlike($r->{body}, qr/^\{"ok"/, 'and never a raw JSON body for a screen request');
}
{
	my ($app) = _build(responses => { authenticate => [ { ok => 1, data => { ok => 0, role => undef, locked => 1, retry_after => 42 } } ] });
	my $r = $app->dispatch({ method => 'POST', path => '/ui/login', headers => {}, body => 'user=dave&pass=x', peer => '7.7.7.7' });
	is($r->{status}, 200, 'a locked account also re-renders the login page (200), not the API 429');
	like($r->{body}, qr/temporarily locked/, 'with the lockout stated in the page');
}
{
	my ($app, $client, undef, $ratelimit) = _build(responses => { authenticate => [ { ok => 1, data => { ok => 0, role => undef, locked => 0, retry_after => 0 } } ] });
	$ratelimit->record_failure('8.8.8.8', 'erin') for 1 .. 10;
	my $r = $app->dispatch({ method => 'POST', path => '/ui/login', headers => {}, body => 'user=erin&pass=x', peer => '8.8.8.8' });
	is($r->{status}, 200, "the web tier's own rate limiter also re-renders the login page rather than a 429");
	is(scalar(@{ $client->{calls} }), 0, 'and never reaches the helper once already over the cap');
}

###############################################################################
# Logout: a real session is actually destroyed, and redirects to the login
# screen - not merely a cleared cookie the browser is trusted to honour.
###############################################################################
{
	my ($app, undef, $sessions) = _build();
	my $sess = $sessions->create(user => 'frank', role => 'admin');
	my $cookie = "csfui_sid=$sess->{id}";
	my $r = $app->dispatch({ method => 'POST', path => '/ui/logout', headers => { cookie => $cookie, 'x-csrf-token' => $sess->{csrf} }, peer => '1.1.1.1' });
	is($r->{status}, 303, 'logout redirects');
	is(_location($r), '/ui/login', 'to the login screen');

	my $r2 = $app->dispatch({ method => 'GET', path => '/ui/overview', headers => { cookie => $cookie }, peer => '1.1.1.1' });
	is($r2->{status}, 401, 'the session is actually gone after logout, not just the cookie cleared client-side (same _gate() as /api/*)');
}
