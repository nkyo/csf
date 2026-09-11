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
# ConfigServer::UI::Session (docs/WEBUI-RPC.md's brief for Task 4, section
# "Sessions are server-side"). Runs without root and without a network: every
# store used here is a temp directory this process owns.
###############################################################################
use strict;
use warnings;

use FindBin ();
use lib "$FindBin::Bin/..", "$FindBin::Bin/../ui-src/lib";

use File::Temp qw(tempdir);
use Test::More tests => 69;

require_ok('ConfigServer::UI::Session');
my $S = 'ConfigServer::UI::Session';

my $dir = tempdir(CLEANUP => 1);

###############################################################################
# create() - shape and storage
###############################################################################
{
	my $now = 1_000_000;
	my $store = $S->new(dir => $dir, idle => 1800, max => 43200, now => sub { $now });

	my $sess = $store->create(user => 'alice', role => 'admin');
	ok($sess, 'create() returns a session record');
	like($sess->{id}, qr/\A[A-Za-z0-9_-]{43}\z/, 'the id is 43 characters of the base64url alphabet');
	is($sess->{user}, 'alice', 'create() records the username');
	is($sess->{role}, 'admin', 'create() records the role');
	ok(defined $sess->{csrf} && length($sess->{csrf}), 'create() mints a CSRF nonce');
	is($sess->{created}, $now, 'created is the current time');
	is($sess->{last_use}, $now, 'last_use starts equal to created');

	my $path = "$dir/$sess->{id}";
	ok(-f $path, 'the session file exists on disk');
	my @stat = stat($path);
	is($stat[2] & 07777, 0600, 'the session file is mode 0600');

	my $second = $store->create(user => 'bob', role => 'support');
	isnt($second->{id}, $sess->{id}, 'two sessions never share an id');
	is($second->{role}, 'support', "create() accepts the 'support' role");

	eval { $store->create(user => 'x', role => 'root') };
	like($@, qr/role/, 'create() refuses a role that is neither admin nor support');
	eval { $store->create(role => 'admin') };
	like($@, qr/user/, 'create() refuses a missing user');
}

###############################################################################
# load() - round trip, and the idle timer sliding forward on every load
###############################################################################
{
	my $now = 1_000_000;
	my $store = $S->new(dir => $dir, idle => 100, max => 100000, now => sub { $now });
	my $sess = $store->create(user => 'carol', role => 'admin');

	my $loaded = $store->load($sess->{id});
	ok($loaded, 'load() finds a freshly created session');
	is($loaded->{user}, 'carol', 'load() returns the same user');
	is($loaded->{role}, 'admin', 'load() returns the same role');
	is($loaded->{csrf}, $sess->{csrf}, 'load() returns the same CSRF nonce');

	# Advance close to, but not past, the idle window, and load again: a
	# session that is used right at the edge of its idle window must not
	# expire, because load() is supposed to slide the window forward.
	$now += 90;
	ok($store->load($sess->{id}), 'a session used just inside its idle window is still valid');

	$now += 90; # 90 more since the last load - inside 100s of THAT load, even
	            # though 180s have passed since creation
	my $reloaded = $store->load($sess->{id});
	ok($reloaded, 'load() slides the idle window forward on every successful load');
	is($reloaded->{last_use}, $now, 'last_use is refreshed to the load time');
}

###############################################################################
# Idle expiry
###############################################################################
{
	my $now = 2_000_000;
	my $store = $S->new(dir => $dir, idle => 100, max => 100000, now => sub { $now });
	my $sess = $store->create(user => 'dave', role => 'admin');

	$now += 101;
	is($store->load($sess->{id}), undef, 'a session past its idle timeout is refused');
	ok(!-e "$dir/$sess->{id}", 'an idle-expired session file is removed');
}

###############################################################################
# Absolute expiry - reached even though the session is used continuously and
# never sits idle
###############################################################################
{
	my $now = 3_000_000;
	my $store = $S->new(dir => $dir, idle => 1000, max => 500, now => sub { $now });
	my $sess = $store->create(user => 'erin', role => 'admin');

	for (1 .. 4) {
		$now += 100; # well inside the 1000s idle window every time
		ok($store->load($sess->{id}), "still valid after ${\ ($_ * 100)}s of continuous use");
	}
	$now += 150; # total age now 550s, past the 500s absolute cap
	is($store->load($sess->{id}), undef,
		'a session past its absolute lifetime is refused even though it was never idle');
	ok(!-e "$dir/$sess->{id}", 'an absolute-expired session file is removed');
}

###############################################################################
# Tampered or unknown identifiers - refused identically, with nothing to
# distinguish "never existed" from "malformed" from "wrong shape"
###############################################################################
{
	my $store = $S->new(dir => $dir, now => sub { 4_000_000 });
	my $sess = $store->create(user => 'frank', role => 'admin');

	opendir(my $before_dh, $dir) or die $!;
	my @before = sort readdir($before_dh);
	closedir $before_dh;

	is($store->load('not-a-session-id'), undef, 'a short, malformed id is refused');
	is($store->load('x' x 43), undef, 'a well-shaped but never-issued id is refused');
	is($store->load($sess->{id} . 'x'), undef, 'a one-character-longer id is refused');
	is($store->load(substr($sess->{id}, 0, 42)), undef, 'a one-character-shorter id is refused');
	is($store->load('../../etc/passwd'), undef, 'a path-traversal-shaped value is refused');
	is($store->load(undef), undef, 'an undef id is refused');
	is($store->load(''), undef, 'an empty id is refused');

	# None of the rejected lookups above - including the traversal-shaped one
	# - ever reach _path()'s filename construction with an unvalidated value,
	# so none of them can have created, touched or removed any file: the
	# directory listing is byte-for-byte the same set of names as before.
	opendir(my $after_dh, $dir) or die $!;
	my @after = sort readdir($after_dh);
	closedir $after_dh;
	is_deeply(\@after, \@before,
		'none of the rejected lookups, including the traversal-shaped one, touched the filesystem');

	ok($store->load($sess->{id}), 'the real session is unaffected by all of the above');
}

###############################################################################
# The id grammar guard is load-bearing, not incidentally correct. The
# '../../etc/passwd' case above is refused today, but only because that
# file's content happens not to split into exactly five ':'-delimited
# fields - an accident of what is on the machine running this test, not a
# property this module guarantees. Prove the real property directly: a
# decoy file placed one directory above the session store, containing
# something that WOULD parse as a perfectly valid session record, must
# still never be reached by a traversal-shaped id.
###############################################################################
{
	my $parent = tempdir(CLEANUP => 1);
	my $sessions_subdir = "$parent/sessions";
	mkdir($sessions_subdir, 0700) or die "cannot mkdir $sessions_subdir: $!";

	my $decoy_path = "$parent/decoy";
	open(my $fh, '>', $decoy_path) or die "cannot write $decoy_path: $!";
	print { $fh } join(':', 'root', 'admin', ('A' x 43), 4_000_000, 4_000_000);
	close $fh;

	my $store = $S->new(dir => $sessions_subdir, now => sub { 4_000_000 });
	is($store->load('../decoy'), undef,
		'a traversal-shaped id is refused even when it would reach a file that parses as a valid session');
}

###############################################################################
# destroy()
###############################################################################
{
	my $store = $S->new(dir => $dir, now => sub { 5_000_000 });
	my $sess = $store->create(user => 'grace', role => 'admin');

	is($store->destroy($sess->{id}), 1, 'destroy() succeeds on an existing session');
	ok(!-e "$dir/$sess->{id}", 'destroy() removes the session file');
	is($store->load($sess->{id}), undef, 'a destroyed session no longer loads');
	is($store->destroy($sess->{id}), 1, 'destroy() on an already-gone session still reports success');
	is($store->destroy('not-a-session-id'), 0, 'destroy() on a malformed id reports failure, not success');
}

###############################################################################
# csrf_ok() - constant-time-in-content compare
###############################################################################
{
	my $store = $S->new(dir => $dir, now => sub { 6_000_000 });
	my $sess = $store->create(user => 'heidi', role => 'admin');

	ok($store->csrf_ok($sess, $sess->{csrf}), 'the session\'s own CSRF nonce is accepted');
	ok(!$store->csrf_ok($sess, 'x' x length($sess->{csrf})), 'a same-length wrong nonce is rejected');
	ok(!$store->csrf_ok($sess, substr($sess->{csrf}, 0, -1)), 'a shorter wrong-length nonce is rejected');
	ok(!$store->csrf_ok($sess, $sess->{csrf} . 'x'), 'a longer wrong-length nonce is rejected');
	ok(!$store->csrf_ok($sess, undef), 'an undef submitted token is rejected');
	ok(!$store->csrf_ok($sess, ''), 'an empty submitted token is rejected');
	ok(!$store->csrf_ok({}, $sess->{csrf}), 'a session with no csrf field never matches');
	ok(!$store->csrf_ok(undef, $sess->{csrf}), 'a missing session never matches');

	# Prove the loop really does visit every byte rather than returning at
	# the first difference: flipping the LAST byte must be caught exactly
	# like flipping the first.
	my $last_flip = $sess->{csrf};
	substr($last_flip, -1, 1) = (substr($last_flip, -1, 1) eq 'A') ? 'B' : 'A';
	ok(!$store->csrf_ok($sess, $last_flip), 'a difference in the last byte is still caught');

	# The assertion above alone does not prove constant time: a short-
	# circuiting `eq` would also correctly reject a same-length,
	# last-byte-different value - it would just do it faster than a
	# same-length, first-byte-different one, which is exactly the timing
	# signal this function exists to not leak. $COMPARE_VISITS proves the
	# loop itself never short-circuits, by counting how many byte positions
	# it actually visited rather than by measuring wall-clock time (which
	# would make this test flaky under load, the same reasoning Auth.pm's
	# own constant_time_equal() test uses for the identical property).
	my $first_flip = $sess->{csrf};
	substr($first_flip, 0, 1) = (substr($first_flip, 0, 1) eq 'A') ? 'B' : 'A';
	$store->csrf_ok($sess, $first_flip);
	is($ConfigServer::UI::Session::COMPARE_VISITS, length($sess->{csrf}),
		'a first-byte difference still visits every byte of the nonce, not just the first');

	$store->csrf_ok($sess, $last_flip);
	is($ConfigServer::UI::Session::COMPARE_VISITS, length($sess->{csrf}),
		'a last-byte difference visits exactly the same number of bytes as a first-byte one');

	$store->csrf_ok($sess, $sess->{csrf});
	is($ConfigServer::UI::Session::COMPARE_VISITS, length($sess->{csrf}),
		'a full match visits every byte too - there is nothing for the loop to skip in any case');
}

###############################################################################
# Cookie plumbing
###############################################################################
{
	my $store = $S->new(dir => $dir, now => sub { 7_000_000 });
	my $sess = $store->create(user => 'ivan', role => 'admin');

	my $set = $store->set_cookie_header($sess->{id});
	like($set, qr/\A\Q$ConfigServer::UI::Session::COOKIE_NAME\E=\Q$sess->{id}\E;/, 'set_cookie_header carries the id under the fixed cookie name');
	like($set, qr/HttpOnly/,          'set_cookie_header sets HttpOnly');
	like($set, qr/Secure/,            'set_cookie_header sets Secure');
	like($set, qr/SameSite=Strict/,   'set_cookie_header sets SameSite=Strict');
	like($set, qr{Path=/},            'set_cookie_header sets Path=/');

	my $clear = $store->clear_cookie_header;
	like($clear, qr/Max-Age=0/, 'clear_cookie_header expires the cookie immediately');
	like($clear, qr/\A\Q$ConfigServer::UI::Session::COOKIE_NAME\E=;/, 'clear_cookie_header empties the value');

	is($store->id_from_cookie_header("$ConfigServer::UI::Session::COOKIE_NAME=$sess->{id}"),
		$sess->{id}, 'id_from_cookie_header parses a single cookie');
	is($store->id_from_cookie_header("foo=bar; $ConfigServer::UI::Session::COOKIE_NAME=$sess->{id}; baz=qux"),
		$sess->{id}, 'id_from_cookie_header finds the right cookie among several');
	is($store->id_from_cookie_header('foo=bar; baz=qux'), undef,
		'id_from_cookie_header returns undef when the cookie is absent');
	is($store->id_from_cookie_header(undef), undef, 'id_from_cookie_header handles an undef header');
	is($store->id_from_cookie_header("$ConfigServer::UI::Session::COOKIE_NAME=not-valid-shape"), undef,
		'id_from_cookie_header refuses a value of the wrong shape');

	# The class-method spelling works identically - neither method touches $self.
	is(ConfigServer::UI::Session->id_from_cookie_header("$ConfigServer::UI::Session::COOKIE_NAME=$sess->{id}"),
		$sess->{id}, 'id_from_cookie_header also works as a class method');
}
