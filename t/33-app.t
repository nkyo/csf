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
# ConfigServer::UI::App (ui-src/bin/csf-ui) - the request handler's routing,
# session, role and CSRF enforcement. Task 4's brief calls for exactly these
# router-level behaviours ("router returns 405 for unknown method, 404 for
# unknown path, 403 without CSRF") in its Tests paragraph without naming a
# file for them; this is that file; t/30-32 cover the three modules the
# router is built from in isolation, and this file covers what they do
# wired together, the way Task 5 will actually call this module.
#
# The RPC client is a fake with scripted responses, not a real socket:
# t/32-client.t already proves Client.pm's wire behaviour, so this file only
# needs to prove that ConfigServer::UI::App calls it with the right
# arguments and reacts correctly to what comes back.
###############################################################################
use strict;
use warnings;

use FindBin ();
use lib "$FindBin::Bin/..", "$FindBin::Bin/../ui-src/lib";

use File::Temp qw(tempdir);
use JSON::Tiny ();
use Test::More tests => 137;

my $APP_PATH = "$FindBin::Bin/../ui-src/bin/csf-ui";
ok(-f $APP_PATH, 'csf-ui is where the brief says it is');
require $APP_PATH;
my $A = 'ConfigServer::UI::App';

###############################################################################
# A scripted stand-in for ConfigServer::UI::Client. Records every call it
# receives and answers from a queue of canned responses keyed by operation -
# t/32-client.t already proves the real Client's wire behaviour, so this
# file only has to prove App calls it correctly and reacts correctly to what
# comes back.
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
# Test fixture: one App instance per test block, with its own temp
# directories so nothing here ever touches /var/lib/csf-ui or
# /var/log/csf-ui-access.log.
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
		now        => sub { $now },
	);
	return ($app, $client, $sessions, $ratelimit, "$base/access.log");
}

sub _last_access_line {
	my ($path) = @_;
	open(my $fh, '<', $path) or return undef;
	my @lines = <$fh>;
	close $fh;
	return undef unless @lines;
	chomp(my $last = $lines[-1]);
	return eval { JSON::Tiny::decode_json($last) };
}

###############################################################################
# 404, 405 - path and method
###############################################################################
{
	my ($app) = _build();

	my $r = $app->dispatch({ method => 'GET', path => '/api/does-not-exist', headers => {}, peer => '203.0.113.1' });
	is($r->{status}, 404, 'an unregistered path is 404');

	$r = $app->dispatch({ method => 'DELETE', path => '/api/status', headers => {}, peer => '203.0.113.1' });
	is($r->{status}, 405, 'a registered path with the wrong method is 405');
	my ($allow) = grep { $_->[0] eq 'Allow' } @{ $r->{headers} };
	is($allow->[1], 'GET', 'the 405 response names the one method the path accepts');

	$r = $app->dispatch("not a hashref");
	is($r->{status}, 400, 'a malformed request (not even a hashref) is refused, not a crash');
}

###############################################################################
# Important 3 in the review: a missing or empty peer address must fail
# closed, loudly, before anything else runs - never silently degrade
# RateLimit.pm's per-address cap or blank the access log's record of who
# asked. Checked against a route that would otherwise succeed cleanly, so
# there is no other reason a 400 could appear here.
###############################################################################
{
	my ($app, $client, $sessions) = _build();
	my $sess = $sessions->create(user => 'nadia', role => 'admin');
	my $cookie = "csfui_sid=$sess->{id}";

	my $r = $app->dispatch({ method => 'GET', path => '/api/status', headers => { cookie => $cookie } });
	is($r->{status}, 400, 'a request with no peer key at all is refused before routing proceeds');
	is(scalar(@{ $client->{calls} }), 0, 'and the helper is never reached');

	$r = $app->dispatch({ method => 'GET', path => '/api/status', headers => { cookie => $cookie }, peer => '' });
	is($r->{status}, 400, 'a request with an empty-string peer is refused the same way');

	$r = $app->dispatch({ method => 'GET', path => '/api/status', headers => { cookie => $cookie }, peer => '203.0.113.1' });
	is($r->{status}, 200, 'and the same request with a real peer address succeeds, confirming peer was the only thing missing');
}

###############################################################################
# docs/WEBUI-RPC.md S14.1: a body over the documented 65536-byte cap is
# refused by csf-ui itself, before any parsing is attempted - a defensive
# backstop for a producer that forgets its own limit, not a replacement for
# Task 5 imposing one earlier.
###############################################################################
{
	no warnings 'once'; # ConfigServer::UI::App::MAX_BODY_BYTES is touched exactly once in this file
	my ($app, undef, $sessions) = _build();
	my $sess = $sessions->create(user => 'oscar', role => 'admin');

	my $huge = 'x' x ($ConfigServer::UI::App::MAX_BODY_BYTES + 1);
	my $r = $app->dispatch({ method => 'POST', path => '/api/deny',
		headers => { cookie => "csfui_sid=$sess->{id}", 'x-csrf-token' => $sess->{csrf} },
		body => "ip=192.0.2.1&note=$huge", peer => '1.2.3.4' });
	is($r->{status}, 400, 'a body over the documented cap is refused outright');

	my $body = eval { JSON::Tiny::decode_json($r->{body}) } || {};
	is($body->{error}, 'WEB_BAD_REQUEST', 'with the bad-request code, not a crash or a helper call');

	$r = $app->dispatch({ method => 'POST', path => '/api/deny',
		headers => { cookie => "csfui_sid=$sess->{id}", 'x-csrf-token' => $sess->{csrf} },
		body => "ip=192.0.2.1&note=x&_csrf=$sess->{csrf}", peer => '1.2.3.4' });
	is($r->{status}, 200, 'and a normal-sized body for the same route is unaffected');
}

###############################################################################
# 401 - no session at all
###############################################################################
{
	my ($app) = _build();
	my $r = $app->dispatch({ method => 'GET', path => '/api/status', headers => {}, peer => '203.0.113.1' });
	is($r->{status}, 401, 'a protected route with no cookie at all is 401');

	$r = $app->dispatch({ method => 'GET', path => '/api/status',
		headers => { cookie => 'csfui_sid=not-a-real-session-id' }, peer => '203.0.113.1' });
	is($r->{status}, 401, 'a protected route with a bogus cookie is 401, not a crash');
}

###############################################################################
# 403 - role enforcement: support may reach grep/list only
###############################################################################
{
	my ($app, $client, $sessions) = _build();
	my $sess = $sessions->create(user => 'trent', role => 'support');
	my $cookie = "csfui_sid=$sess->{id}";

	my $r = $app->dispatch({ method => 'GET', path => '/api/status', headers => { cookie => $cookie }, peer => '1.2.3.4' });
	is($r->{status}, 403, 'support cannot reach status');

	# A valid CSRF token is supplied here on purpose: without one, a
	# support-role request to a mutating route would be refused by the CSRF
	# check regardless of role, which would make this assertion pass even if
	# role enforcement were broken. Supplying the correct token isolates the
	# property this test is actually for.
	$r = $app->dispatch({ method => 'POST', path => '/api/restart',
		headers => { cookie => $cookie, 'x-csrf-token' => $sess->{csrf} }, peer => '1.2.3.4' });
	is($r->{status}, 403, 'support cannot reach restart, even with a valid CSRF token');
	my $body = eval { JSON::Tiny::decode_json($r->{body}) } || {};
	is($body->{error}, 'WEB_FORBIDDEN', 'the refusal is specifically the role check, not the CSRF check');

	$r = $app->dispatch({ method => 'GET', path => '/api/list', query => { which => 'deny' },
		headers => { cookie => $cookie }, peer => '1.2.3.4' });
	is($r->{status}, 200, 'support CAN reach list');

	$r = $app->dispatch({ method => 'GET', path => '/api/grep', query => { ip => '192.0.2.1' },
		headers => { cookie => $cookie }, peer => '1.2.3.4' });
	is($r->{status}, 200, 'support CAN reach grep');
}

{
	my ($app, $client, $sessions) = _build();
	my $sess = $sessions->create(user => 'adele', role => 'admin');
	my $cookie = "csfui_sid=$sess->{id}";
	my $r = $app->dispatch({ method => 'GET', path => '/api/status', headers => { cookie => $cookie }, peer => '1.2.3.4' });
	is($r->{status}, 200, 'admin can reach every route, including read-only ones support cannot');
}

###############################################################################
# 403 - CSRF required on every mutating route, and accepted when correct
###############################################################################
{
	my ($app, $client, $sessions) = _build();
	my $sess = $sessions->create(user => 'admin1', role => 'admin');
	my $cookie = "csfui_sid=$sess->{id}";

	my $r = $app->dispatch({ method => 'POST', path => '/api/deny', headers => { cookie => $cookie },
		body => 'ip=192.0.2.1&note=abuse', peer => '1.2.3.4' });
	is($r->{status}, 403, 'a mutating route with no CSRF token at all is refused');

	$r = $app->dispatch({ method => 'POST', path => '/api/deny', headers => { cookie => $cookie },
		body => 'ip=192.0.2.1&note=abuse&_csrf=totally-wrong', peer => '1.2.3.4' });
	is($r->{status}, 403, 'a mutating route with the wrong CSRF token is refused');

	$r = $app->dispatch({ method => 'POST', path => '/api/deny', headers => { cookie => $cookie },
		body => "ip=192.0.2.1&note=abuse&_csrf=$sess->{csrf}", peer => '1.2.3.4' });
	is($r->{status}, 200, 'a mutating route with the correct CSRF token (form field) succeeds');

	$r = $app->dispatch({ method => 'POST', path => '/api/allow',
		headers => { cookie => $cookie, 'x-csrf-token' => $sess->{csrf} },
		body => 'ip=192.0.2.1&note=abuse', peer => '1.2.3.4' });
	is($r->{status}, 200, 'the CSRF token is also accepted from the X-CSRF-Token header');

	# Read-only mutating=0 routes never even ask for one.
	$r = $app->dispatch({ method => 'GET', path => '/api/status', headers => { cookie => $cookie }, peer => '1.2.3.4' });
	is($r->{status}, 200, 'a read-only route needs no CSRF token');
}

###############################################################################
# Arguments: query string for GET, form-urlencoded body for POST, and the
# CSRF field is stripped before the arguments reach the RPC client.
###############################################################################
{
	my ($app, $client, $sessions) = _build();
	my $sess = $sessions->create(user => 'opal', role => 'admin');
	my $cookie = "csfui_sid=$sess->{id}";

	$app->dispatch({ method => 'GET', path => '/api/list', query => { which => 'deny', limit => '10' },
		headers => { cookie => $cookie }, peer => '1.2.3.4' });
	my $call = $client->{calls}[-1];
	is($call->{op}, 'list', 'GET /api/list forwards the list operation');
	is($call->{args}{which}, 'deny', 'GET args come from the query string');
	is($call->{args}{limit}, '10', 'every query key is forwarded');

	$app->dispatch({ method => 'POST', path => '/api/deny',
		headers => { cookie => $cookie, 'x-csrf-token' => $sess->{csrf} },
		body => 'ip=192.0.2.9&note=blocked+by+ops', peer => '1.2.3.4' });
	$call = $client->{calls}[-1];
	is($call->{op}, 'deny', 'POST /api/deny forwards the deny operation');
	is($call->{args}{ip}, '192.0.2.9', 'form-urlencoded args are decoded');
	is($call->{args}{note}, 'blocked by ops', 'a + in a form body decodes to a space');
	ok(!exists $call->{args}{_csrf}, 'the _csrf field never reaches the RPC client');
}

###############################################################################
# The request id used for the RPC call is echoed to the access log, so an
# incident can be correlated with the helper's own audit log by that id
# (docs/WEBUI-RPC.md S8).
###############################################################################
{
	my ($app, $client, $sessions, undef, $access_log) = _build();
	my $sess = $sessions->create(user => 'quinn', role => 'admin');
	$app->dispatch({ method => 'GET', path => '/api/status',
		headers => { cookie => "csfui_sid=$sess->{id}" }, peer => '9.9.9.9' });

	my $call = $client->{calls}[-1];
	my $entry = _last_access_line($access_log);
	ok(defined $entry, 'a line was written to the access log');
	is($entry->{id}, $call->{id}, "the access log's id matches the id sent to the helper");
	is($entry->{user}, 'quinn', 'the access log records the authenticated user');
	is($entry->{role}, 'admin', 'the access log records the role');
	is($entry->{addr}, '9.9.9.9', 'the access log records the peer address');
	is($entry->{method}, 'GET', 'the access log records the method');
	is($entry->{path}, '/api/status', 'the access log records the path');
	is($entry->{status}, 200, 'the access log records the response status');
}

###############################################################################
# Login: success mints a session and a Set-Cookie header
###############################################################################
{
	my ($app, $client, $sessions) = _build(
		responses => { authenticate => [ { ok => 1, data => { ok => 1, role => 'admin' } } ] },
	);

	my $r = $app->dispatch({ method => 'POST', path => '/api/login', headers => {},
		body => 'user=alice&pass=correct+horse', peer => '5.5.5.5' });
	is($r->{status}, 200, 'a successful login is 200');

	my ($set_cookie) = grep { $_->[0] eq 'Set-Cookie' } @{ $r->{headers} };
	ok($set_cookie, 'a successful login sets a cookie');
	like($set_cookie->[1], qr/\Acsfui_sid=/, 'the cookie carries a session id under the fixed name');

	my $call = $client->{calls}[-1];
	is($call->{op}, 'authenticate', '/api/login calls the authenticate operation');
	is($call->{args}{pass}, 'correct horse', 'the submitted password is forwarded to the helper');

	# And the freshly minted cookie actually works on a follow-up request.
	my ($cookie_value) = $set_cookie->[1] =~ /\Acsfui_sid=([^;]+)/;
	my $r2 = $app->dispatch({ method => 'GET', path => '/api/status',
		headers => { cookie => "csfui_sid=$cookie_value" }, peer => '5.5.5.5' });
	is($r2->{status}, 200, 'the session minted by login is immediately usable');
}

###############################################################################
# Login: wrong password
###############################################################################
{
	my ($app, $client, undef, $ratelimit) = _build(
		responses => { authenticate => [ { ok => 1, data => { ok => 0, role => undef, locked => 0, retry_after => 0 } } ] },
	);

	my $r = $app->dispatch({ method => 'POST', path => '/api/login', headers => {},
		body => 'user=bob&pass=wrong', peer => '6.6.6.6' });
	is($r->{status}, 401, 'a wrong password is 401');
	is($r->{headers}[0][0], 'Content-Type', 'even an error response carries a Content-Type header');

	ok($ratelimit->blocked_user('bob') == 0, 'one failure alone does not yet trip the web tier\'s own limiter');
}

###############################################################################
# Login: the helper reports the account locked
###############################################################################
{
	my ($app) = _build(
		responses => { authenticate => [ { ok => 1, data => { ok => 0, role => undef, locked => 1, retry_after => 42 } } ] },
	);
	my $r = $app->dispatch({ method => 'POST', path => '/api/login', headers => {},
		body => 'user=carol&pass=whatever', peer => '7.7.7.7' });
	is($r->{status}, 429, "the helper's own lockout answers 429");
	my ($retry) = grep { $_->[0] eq 'Retry-After' } @{ $r->{headers} };
	is($retry->[1], 42, 'the retry-after value from the helper is relayed');
}

###############################################################################
# Login: the web tier's OWN rate limiter blocks before the helper is ever
# asked, once it is already tripped.
###############################################################################
{
	my ($app, $client, undef, $ratelimit) = _build(
		responses => { authenticate => [ { ok => 1, data => { ok => 0, role => undef, locked => 0, retry_after => 0 } } ] },
	);
	$ratelimit->record_failure('8.8.8.8', 'dave') for 1 .. 10; # trips the 10-per-window username cap

	my $r = $app->dispatch({ method => 'POST', path => '/api/login', headers => {},
		body => 'user=dave&pass=whatever', peer => '8.8.8.8' });
	is($r->{status}, 429, 'a caller already over the web tier\'s own cap is refused');
	is(scalar(@{ $client->{calls} }), 0, 'the helper is never even asked once the web tier\'s own limiter is tripped');
}

###############################################################################
# Logout
###############################################################################
{
	my ($app, undef, $sessions) = _build();
	my $sess = $sessions->create(user => 'erin', role => 'admin');
	my $cookie = "csfui_sid=$sess->{id}";

	my $r = $app->dispatch({ method => 'POST', path => '/api/logout', headers => { cookie => $cookie },
		body => "_csrf=$sess->{csrf}", peer => '1.1.1.1' });
	is($r->{status}, 200, 'logout with the correct CSRF token succeeds');
	my ($clear) = grep { $_->[0] eq 'Set-Cookie' } @{ $r->{headers} };
	like($clear->[1], qr/Max-Age=0/, 'logout clears the cookie');

	my $r2 = $app->dispatch({ method => 'GET', path => '/api/status', headers => { cookie => $cookie }, peer => '1.1.1.1' });
	is($r2->{status}, 401, 'the session is actually gone after logout, not just the cookie cleared client-side');
}

{
	my ($app, undef, $sessions) = _build();
	my $sess = $sessions->create(user => 'frank', role => 'admin');
	my $cookie = "csfui_sid=$sess->{id}";
	my $r = $app->dispatch({ method => 'POST', path => '/api/logout', headers => { cookie => $cookie },
		body => '_csrf=wrong', peer => '1.1.1.1' });
	is($r->{status}, 403, 'logout also requires the correct CSRF token, not just a session');
}

###############################################################################
# Wire error codes are mapped to HTTP status per docs/WEBUI-RPC.md S3.5
###############################################################################
{
	my ($app, undef, $sessions) = _build(
		responses => {
			deny => [
				{ id => 'x', ok => 0, error => 'E_ARG', message => 'ip: is required' },
			],
			restart => [
				{ id => 'x', ok => 0, error => 'E_BUSY', message => 'too soon' },
			],
		},
	);
	my $sess = $sessions->create(user => 'grace', role => 'admin');
	my $cookie = "csfui_sid=$sess->{id}";

	my $r = $app->dispatch({ method => 'POST', path => '/api/deny', headers => { cookie => $cookie },
		body => "ip=x&note=x&_csrf=$sess->{csrf}", peer => '1.1.1.1' });
	is($r->{status}, 400, 'E_ARG maps to 400');

	$r = $app->dispatch({ method => 'POST', path => '/api/restart', headers => { cookie => $cookie },
		body => "_csrf=$sess->{csrf}", peer => '1.1.1.1' });
	is($r->{status}, 503, 'E_BUSY maps to 503');
	my ($retry) = grep { $_->[0] eq 'Retry-After' } @{ $r->{headers} };
	ok($retry, 'an E_BUSY response carries a Retry-After header');
}

###############################################################################
# G9: the password never appears in the access log, whatever happens to the
# request. This is the property the whole design exists to protect, so it is
# checked directly against the log file's bytes, not just against the
# structured fields this module happens to populate.
###############################################################################
{
	my ($app, undef, undef, undef, $access_log) = _build(
		responses => { authenticate => [ { ok => 1, data => { ok => 0, role => undef, locked => 0, retry_after => 0 } } ] },
	);
	$app->dispatch({ method => 'POST', path => '/api/login', headers => {},
		body => 'user=henry&pass=hunter2-super-secret', peer => '2.2.2.2' });

	open(my $fh, '<', $access_log) or die "cannot read $access_log: $!";
	local $/;
	my $contents = <$fh>;
	close $fh;
	unlike($contents, qr/hunter2/, 'the submitted password never appears anywhere in the access log');
	like($contents, qr/"user":"henry"/, 'the username, which is not a secret, does appear');
}

###############################################################################
# R27: @ROUTES is bound to section 5's Mutates and role columns by a
# mechanical test, not by inspection or memory - the same reasoning
# t/12-contract-enum.t already applies to the error enumeration. A future
# row that forgets `mutates => 1`, or wrongly sets `support => 1`, fails
# THIS test rather than silently shipping without CSRF or with a widened
# role.
###############################################################################
{
	# docs/WEBUI-RPC.md S5's Mutates and role columns, as data. authenticate
	# is excluded on purpose: S5.14 makes it pre-session, and its route
	# (/api/login) is `anonymous`, which has no mutates/support pair to
	# check in the first place - checked separately below instead.
	my %SPEC = (
		status        => { mutates => 0, support => 0 },
		counts        => { mutates => 0, support => 0 },
		deny          => { mutates => 1, support => 0 },
		undeny        => { mutates => 1, support => 0 },
		allow         => { mutates => 1, support => 0 },
		unallow       => { mutates => 1, support => 0 },
		tempdeny      => { mutates => 1, support => 0 },
		temprm        => { mutates => 1, support => 0 },
		list          => { mutates => 0, support => 1 },
		'grep'        => { mutates => 0, support => 1 },
		reconcile     => { mutates => 0, support => 0 },
		reconcile_fix => { mutates => 1, support => 0 },
		restart       => { mutates => 1, support => 0 },
	);
	is(scalar(keys %SPEC), 13, 'sanity: this checks all thirteen non-authenticate operations');

	for my $op (sort keys %SPEC) {
		my ($route) = grep { defined $_->{op} && $_->{op} eq $op } @ConfigServer::UI::App::ROUTES;
		ok($route, "a route exists forwarding the '$op' operation");
		next unless $route;
		is(!!$route->{mutates}, !!$SPEC{$op}{mutates},
			"'$op' route's mutates flag matches section 5's Mutates column");
		is(!!$route->{support}, !!$SPEC{$op}{support},
			"'$op' route's support flag matches section 5's role mapping");
		next unless $SPEC{$op}{mutates};
		isnt(uc($route->{method}), 'GET', "'$op' mutates and so must not be reachable by GET");
	}

	# Converse: every route that names an `op` names one of the thirteen
	# real operations, and the only anonymous route is the one that has to
	# be (S5.14).
	for my $route (@ConfigServer::UI::App::ROUTES) {
		if (defined $route->{op}) {
			ok(exists $SPEC{ $route->{op} }, "route op '$route->{op}' is a real section 5 operation");
		}
		if ($route->{anonymous}) {
			is($route->{path}, '/api/login', "the only anonymous route is /api/login, not '$route->{path}'");
		}
	}
}

###############################################################################
# R27: a `handler` row gets the SAME gate as an `op` row, automatically -
# proven by pushing a synthetic mutating handler route onto @ROUTES (scoped
# to this block with `local`, so it cannot leak into any other test) and
# confirming it behaves exactly like a real mutating operation would: no
# session refuses it before the handler ever runs, a session with no CSRF
# token also refuses it before the handler ever runs, and only a session
# plus the correct token lets the handler's own body execute. This is
# exactly the property Important 5 found missing in the review; if _gate()
# is ever skipped again for handler rows, this fails before Task 7's own
# screens would be the ones to find out.
###############################################################################
{
	my ($app, undef, $sessions) = _build();
	my $ran = 0;
	local @ConfigServer::UI::App::ROUTES = (
		@ConfigServer::UI::App::ROUTES,
		{ method => 'POST', path => '/api/_test-synthetic-mutating-handler', mutates => 1,
			handler => sub {
				my ($self, $req, $sess, $args) = @_;
				$ran++;
				return (ConfigServer::UI::App::_json_response(200, { ok => \1, data => {} }),
					$sess->{user}, $sess->{role}, undef);
			} },
	);

	my $r = $app->dispatch({ method => 'POST', path => '/api/_test-synthetic-mutating-handler',
		headers => {}, peer => '1.2.3.4' });
	is($r->{status}, 401, 'a synthetic handler route with no session at all is refused before the handler runs');
	is($ran, 0, 'and the handler body itself never ran');

	my $sess = $sessions->create(user => 'zola', role => 'admin');
	$r = $app->dispatch({ method => 'POST', path => '/api/_test-synthetic-mutating-handler',
		headers => { cookie => "csfui_sid=$sess->{id}" }, peer => '1.2.3.4' });
	is($r->{status}, 403, 'the same route with a session but no CSRF token is refused before the handler runs');
	is($ran, 0, 'and the handler body still never ran');

	$r = $app->dispatch({ method => 'POST', path => '/api/_test-synthetic-mutating-handler',
		headers => { cookie => "csfui_sid=$sess->{id}", 'x-csrf-token' => $sess->{csrf} }, peer => '1.2.3.4' });
	is($r->{status}, 200, 'with a session and the correct CSRF token, the handler finally runs');
	is($ran, 1, 'exactly once');
}

###############################################################################
# Minor 9 in the review: the CSRF nonce is now delivered to a client two
# ways - in the login response body, and via /api/session on any later page
# load that did not itself just log in. A server-rendered template has a
# third path that needs no route at all: _gate() hands every non-anonymous
# handler its $session directly, and $session->{csrf} is that page's copy.
###############################################################################
{
	my ($app, undef, $sessions) = _build();

	my $r = $app->dispatch({ method => 'GET', path => '/api/session', headers => {}, peer => '1.2.3.4' });
	is($r->{status}, 401, '/api/session with no session at all is refused');

	my $sess = $sessions->create(user => 'yara', role => 'support');
	$r = $app->dispatch({ method => 'GET', path => '/api/session',
		headers => { cookie => "csfui_sid=$sess->{id}" }, peer => '1.2.3.4' });
	is($r->{status}, 200, '/api/session works for the support role too (any_role, not admin-only)');
	my $body = eval { JSON::Tiny::decode_json($r->{body}) } || {};
	is($body->{data}{user}, 'yara', 'and returns the username');
	is($body->{data}{role}, 'support', 'and the role');
	is($body->{data}{csrf}, $sess->{csrf}, "and the session's own CSRF nonce");
}

{
	my ($app) = _build(
		responses => { authenticate => [ { ok => 1, data => { ok => 1, role => 'admin' } } ] },
	);
	my $r = $app->dispatch({ method => 'POST', path => '/api/login', headers => {},
		body => 'user=zach&pass=whatever', peer => '1.2.3.4' });
	my $body = eval { JSON::Tiny::decode_json($r->{body}) } || {};
	ok(defined $body->{data}{csrf} && length($body->{data}{csrf}),
		"a successful login also returns the session's CSRF nonce in the response body, not only in the cookie");
}

###############################################################################
# R27 side effect: /api/logout is now routed through the same shared gate,
# so a request with no session at all is refused rather than silently
# answered 200 - this was Minor 4 in the review ("the no-session branch is
# the one place a state-changing-looking route answers 200 with no check at
# all"), closed as a consequence of removing the special case rather than
# by a change aimed at it directly.
###############################################################################
{
	my ($app) = _build();
	my $r = $app->dispatch({ method => 'POST', path => '/api/logout', headers => {}, peer => '1.2.3.4' });
	is($r->{status}, 401, 'logout with no session at all is refused, not silently answered 200');
}
