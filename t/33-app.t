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
use Test::More tests => 55;

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
