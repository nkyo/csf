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
# ConfigServer::UI::Auth (docs/WEBUI-RPC.md S5.14, S10, S11.8) and the
# csf-ui-passwd CLI built on it. Runs without root and without a network: every
# store used here is a temp file this process owns, which is exactly the
# ownership csf-ui-helper's own precondition on /etc/csf-ui/users checks for
# (S9's uid-0 rule reads as "owned by the process that runs this", and in
# production that process is root).
###############################################################################
use strict;
use warnings;

use FindBin ();
use lib "$FindBin::Bin/..", "$FindBin::Bin/../ui-src/lib";

use File::Temp qw(tempdir);
use Fcntl qw(:DEFAULT);
use POSIX ();
use Test::More tests => 177;

require_ok('ConfigServer::UI::Auth');
my $A = 'ConfigServer::UI::Auth';

my $CLI_PATH = "$FindBin::Bin/../ui-src/bin/csf-ui-passwd";
ok(-f $CLI_PATH, 'csf-ui-passwd is where the brief says it is');
require $CLI_PATH;
my $C = 'ConfigServer::UI::PasswdCLI';
ok($C->can('run'), 'the CLI loads as a module without touching /etc/csf-ui');

###############################################################################
# Username and role grammar (docs/WEBUI-RPC.md S4.9) - the same shape the
# wire protocol enforces, so nothing can be written here that could not also
# have been submitted to `authenticate`.
###############################################################################
{
	for my $good (qw(a alice a-1 a_1), 'a' x 32, 'admin', 'support-2') {
		ok($A->can('validate_username')->($good), "username '$good' is accepted");
	}
	for my $bad ('', 'Alice', 'a b', 'a.b', 'a/b', 'a' x 33, "alice\n", undef, '../../etc/shadow') {
		my $label = defined $bad ? "'$bad'" : 'undef';
		ok(!$A->can('validate_username')->($bad), "username $label is rejected");
	}

	ok($A->can('validate_role')->('admin'), "role 'admin' is accepted");
	ok($A->can('validate_role')->('support'), "role 'support' is accepted");
	for my $bad ('Admin', 'root', 'superadmin', '', undef) {
		my $label = defined $bad ? "'$bad'" : 'undef';
		ok(!$A->can('validate_role')->($bad), "role $label is rejected");
	}
}

###############################################################################
# Hashing and verification round trip
###############################################################################
{
	my $hash = $A->can('hash_password')->('correct horse battery staple', 5000);
	like($hash, qr/^\$6\$rounds=5000\$/, 'hash_password produces a $6$ hash at the requested rounds');
	ok($A->can('verify')->($hash, 'correct horse battery staple'), 'verify accepts the password it was hashed with');
	ok(!$A->can('verify')->($hash, 'wrong'), 'verify rejects a wrong password');
	ok(!$A->can('verify')->($hash, 'correct horse battery staplf'), 'verify rejects a near-miss password');
	ok(!$A->can('verify')->($hash, ''), 'verify rejects an empty password against a real hash');

	# The 16-byte salt is drawn fresh from /dev/urandom each time, so hashing
	# the same password twice must not produce the same hash.
	my $again = $A->can('hash_password')->('correct horse battery staple', 5000);
	isnt($hash, $again, 'two hashes of the same password use different salts');
	ok($A->can('verify')->($again, 'correct horse battery staple'), 'the second hash verifies its own password');

	# Default rounds, used when none is given.
	my $default_hash = $A->can('hash_password')->('x');
	like($default_hash, qr/^\$6\$rounds=100000\$/, 'hash_password defaults to 100000 rounds');
}

###############################################################################
# Important 1 (review round 1): a non-ASCII password must authenticate.
#
# docs/WEBUI-RPC.md S4.10 - "normalisation: none. The bytes are compared as
# sent" - but the two places a password enters this module disagree about
# what "the bytes" are. csf-ui-passwd hashes raw BYTES straight off stdin/a
# prompt, with no utf8 flag. Proto::validate_pass (Task 2) decodes the wire's
# UTF-8 and hands the helper - and so verify() - a utf8-flagged CHARACTER
# string for anything outside ASCII. crypt() croaks on that flag rather than
# hashing the bytes underneath it, so before this fix a genuinely correct
# non-ASCII password would crypt()-croak inside verify()'s eval, come back
# as an ordinary wrong-password 0, and burn the S5.14 lockout counter on
# every attempt - a live denial of service triggered by the *right*
# password. Both call shapes must converge on the same octets.
###############################################################################
{
	my $password_chars = "correct \x{1F512} battery staple"; # padlock emoji: multi-byte UTF-8
	ok(utf8::is_utf8($password_chars), 'the test password is genuinely a wide-character string');

	my $password_bytes = $password_chars;
	utf8::encode($password_bytes); # what csf-ui-passwd actually hashes: raw bytes read from stdin

	isnt($password_chars, $password_bytes, 'sanity: the character and byte forms are not the same scalar bytes');

	my $hash = $A->can('hash_password')->($password_bytes, 5000);
	ok($A->can('verify')->($hash, $password_chars),
		'verify accepts the utf8-flagged character-string form the helper receives from JSON');
	ok($A->can('verify')->($hash, $password_bytes),
		'and the raw byte-string form csf-ui-passwd itself hashed');
	ok(!$A->can('verify')->($hash, "$password_chars!"), 'and still rejects a genuinely wrong non-ASCII password');

	# hash_password() must also accept a utf8-flagged string directly, in
	# case a future caller passes one instead of bytes, and produce a hash
	# that verifies against EITHER form afterwards - not croak, and not
	# silently hash something other than what was asked for.
	my $hash_from_chars = $A->can('hash_password')->($password_chars, 5000);
	ok($A->can('verify')->($hash_from_chars, $password_bytes),
		'hash_password given the character-string form still produces a hash the byte form verifies against');
	ok($A->can('verify')->($hash_from_chars, $password_chars),
		'and the character form verifies against it too');
}

###############################################################################
# verify() never dies - a die here is read by csf-ui-helper's auth_verify()
# seam as "the verifier could not run" (E_BACKEND), which must never be how an
# ordinary wrong guess or a corrupt record is answered, or the S5.14 failure
# counter it feeds stops counting.
###############################################################################
{
	ok(defined eval { $A->can('verify')->(undef, 'x') }, 'verify does not die on an undef hash');
	is($A->can('verify')->(undef, 'x'), 0, 'and answers false');
	ok(defined eval { $A->can('verify')->('not-a-crypt-hash-at-all', 'x') },
		'verify does not die on a hash that is not a $6$ record');
	is($A->can('verify')->('not-a-crypt-hash-at-all', 'x'), 0, 'and answers false');
	ok(defined eval { $A->can('verify')->('$6$rounds=5000$salt$garbage', undef) },
		'verify does not die on an undef password');
	is($A->can('verify')->('$6$rounds=5000$salt$garbage', undef), 0, 'and answers false');
}

###############################################################################
# hash_password refuses an out-of-range round count (docs/WEBUI-RPC.md S10:
# UI_CRYPT_ROUNDS is 5000..2000000) rather than silently clamping it - a
# silently clamped value is a round count nobody chose and the config would
# disagree with the file.
###############################################################################
{
	ok(!eval { $A->can('hash_password')->('x', 4999); 1 }, 'hash_password refuses below the 5000 floor');
	ok(!eval { $A->can('hash_password')->('x', 2000001); 1 }, 'hash_password refuses above the 2000000 ceiling');
	ok(!eval { $A->can('hash_password')->('x', 'lots'); 1 }, 'hash_password refuses a non-integer round count');
	ok(eval { $A->can('hash_password')->('x', 5000); 1 }, 'hash_password accepts the floor itself');
	ok(eval { $A->can('hash_password')->('x', 2000000); 1 }, 'hash_password accepts the ceiling itself');
}

###############################################################################
# Constant-time comparison does not short-circuit.
#
# A timing assertion would be flaky, so this instead proves the structural
# property the brief asks for: constant_time_equal() reduces both operands to
# a digest through an overridable seam, and the byte-comparison loop visits
# every position of that digest - not stopping at the first difference -
# whichever position (first, middle, last, or none) actually differs. The
# mocked digest below skips real hashing so the test controls the exact bytes
# compared and their length.
###############################################################################
{
	# $A holds a string, so overriding the package variable it names needs a
	# symbolic reference - "identity" here means the mocked digest is just the
	# input itself, so this test controls the exact bytes compared and their
	# length instead of trusting SHA-256 to produce a particular pattern.
	no strict 'refs';
	local ${"${A}::DIGESTER"} = sub { return defined $_[0] ? $_[0] : '' };
	use strict 'refs';

	my $reference = 'A' x 40;

	my %case = (
		'identical inputs'          => 'A' x 40,
		'differ at the first byte'  => ('B' . ('A' x 39)),
		'differ in the middle'      => (('A' x 20) . 'B' . ('A' x 19)),
		'differ at the last byte'   => (('A' x 39) . 'B'),
	);
	for my $label (sort keys %case) {
		no strict 'refs';
		${"${A}::COMPARE_VISITS"} = -1;
		my $result = $A->can('constant_time_equal')->($reference, $case{$label});
		is(${"${A}::COMPARE_VISITS"}, 40,
			"constant_time_equal visits all 40 bytes when inputs $label");
		use strict 'refs';
		if ($label eq 'identical inputs') {
			ok($result, 'and reports a match for identical digests');
		}
		else {
			ok(!$result, "and reports a mismatch when inputs $label");
		}
	}

	# Different-length "digests" are still both walked in full (padded with a
	# zero byte past the shorter one), not rejected early on a length check.
	{
		no strict 'refs';
		${"${A}::COMPARE_VISITS"} = -1;
		my $result = $A->can('constant_time_equal')->('A' x 40, 'A' x 30);
		is(${"${A}::COMPARE_VISITS"}, 40, 'a length mismatch still visits the longer operand in full');
		ok(!$result, 'and is reported as a mismatch');
		use strict 'refs';
	}
}

###############################################################################
# Minor 12 / R25: everything above proves constant_time_equal() itself never
# short-circuits, but nothing yet proved verify() actually calls it rather
# than, say, `return $computed eq $hash ? 1 : 0` - a change every other
# assertion in this file would still pass. $COMPARE_VISITS is set by
# constant_time_equal() alone, so seeing it move off a sentinel after a
# verify() call is a direct, falsifiable check that the comparison already
# proved safe above is the one actually reached from the seam.
###############################################################################
{
	no strict 'refs';
	${"${A}::COMPARE_VISITS"} = -1;
	use strict 'refs';

	my $hash = $A->can('hash_password')->('routing check', 5000);
	$A->can('verify')->($hash, 'routing check');

	no strict 'refs';
	isnt(${"${A}::COMPARE_VISITS"}, -1,
		'verify() actually routes its comparison through constant_time_equal (COMPARE_VISITS moved)');
	use strict 'refs';
}

###############################################################################
# Record format (docs/WEBUI-RPC.md S5.14: username:algo:hash:role:created)
###############################################################################
{
	my $line = $A->can('format_record')->(
		user => 'alice', algo => '6', hash => '$6$rounds=5000$salt$hash', role => 'admin', created => 1757548800);
	is($line, 'alice:6:$6$rounds=5000$salt$hash:admin:1757548800', 'format_record produces the frozen five-field shape');

	my $parsed = $A->can('parse_record')->($line);
	is($parsed->{user}, 'alice', 'parse_record recovers the username');
	is($parsed->{algo}, '6', 'and the algo');
	is($parsed->{hash}, '$6$rounds=5000$salt$hash', 'and the hash');
	is($parsed->{role}, 'admin', 'and the role');
	is($parsed->{created}, 1757548800, 'and the created epoch, numified');

	# parse_record strips a trailing line ending itself, so it behaves the same
	# whether a caller hands it an already-chomped line (as read_store does) or
	# a raw one straight from <$fh> - this is a deliberate convenience, not a
	# gap: a real line from a file can never contain a newline anywhere but at
	# its very end.
	my $with_crlf = $A->can('parse_record')->("$line\r\n");
	is($with_crlf->{user}, 'alice', 'parse_record also accepts a line with its trailing CRLF still attached');

	ok(!eval { $A->can('format_record')->(user => 'Alice', algo => '6', hash => 'h', role => 'admin', created => 1); 1 },
		'format_record refuses a username outside the grammar');
	ok(!eval { $A->can('format_record')->(user => 'alice', algo => '6', hash => 'h', role => 'root', created => 1); 1 },
		'format_record refuses a role that is not admin or support');
	ok(!eval { $A->can('format_record')->(user => 'alice', algo => '2', hash => 'h', role => 'admin', created => 1); 1 },
		'format_record refuses an algo other than 6 (R13: $6$ is the only implemented algorithm)');
	ok(!eval { $A->can('format_record')->(user => 'alice', algo => '6', hash => 'h:h', role => 'admin', created => 1); 1 },
		'format_record refuses a hash containing a colon, which would corrupt the field split');
	ok(!eval { $A->can('format_record')->(user => 'alice', algo => '6', hash => '', role => 'admin', created => 1); 1 },
		'format_record refuses an empty hash');
	ok(!eval { $A->can('format_record')->(user => 'alice', algo => '6', hash => 'h', role => 'admin', created => 'now'); 1 },
		'format_record refuses a non-numeric created field');

	for my $bad (
		'',
		'#a comment',
		'alice',
		'alice:6',
		'alice:6:hash',
		'alice:6:hash:admin',
		'alice:6:hash:admin:soon',
		'Alice:6:hash:admin:1',
		'alice:6:hash:root:1',
		'alice:6::admin:1',
		'alice:6:hash:admin:1:extra',
	) {
		is($A->can('parse_record')->($bad), undef, "parse_record rejects malformed line '$bad'");
	}

	# An algo this module did not write still parses, so a caller can name the
	# user and the unverifiable algorithm rather than lose the row entirely -
	# only verify() and the write path treat "not 6" as fatal.
	my $foreign = $A->can('parse_record')->('bob:2:somehash:support:1757548800');
	ok($foreign, 'parse_record accepts a record with a foreign algo rather than discarding it');
	is($foreign->{algo}, '2', 'and reports the algo it could not write itself');
}

###############################################################################
# Reading and writing the store
###############################################################################
my $dir = tempdir(CLEANUP => 1);
my $path = "$dir/users";

{
	my ($store, $error) = $A->can('read_store')->($path);
	ok($store, 'a store that does not exist yet reads as empty, not as an error');
	is(scalar(@{ $store->{order} }), 0, 'with no records');
	ok(!$error, 'and no error, because "no admin yet" is the normal pre-bootstrap state');
}

{
	my ($ok, $error) = $A->can('add_user')->($path, 'alice', 'admin', 'hunter2');
	ok($ok, 'add_user creates the first account') or diag($error);

	my @stat = stat($path);
	is($stat[2] & 07777, 0600, 'the store is created at mode 0600');

	my ($store, $read_error) = $A->can('read_store')->($path);
	ok($store, 'the store now reads back cleanly') or diag($read_error);
	ok(exists $store->{records}{alice}, 'with the account just added');
	is($store->{records}{alice}{role}, 'admin', 'carrying the role it was given');
	ok($A->can('verify')->($store->{records}{alice}{hash}, 'hunter2'), 'and a hash that verifies the password given');
}

{
	my ($ok, $error) = $A->can('add_user')->($path, 'alice', 'admin', 'x');
	ok(!$ok, 'add_user refuses to overwrite an existing account');
	like($error, qr/already exists/, 'and says why');
}

{
	my ($ok, $error) = $A->can('add_user')->($path, 'Alice', 'admin', 'x');
	ok(!$ok, 'add_user refuses a username outside the grammar');
	my ($ok2, $error2) = $A->can('add_user')->($path, 'carol', 'root', 'x');
	ok(!$ok2, 'add_user refuses a role that is not admin or support');
}

{
	my ($rows, $error) = $A->can('list_users')->($path);
	ok($rows, 'list_users reads the store') or diag($error);
	is(scalar(@$rows), 1, 'with one account so far');
	is($rows->[0]{user}, 'alice', 'named alice');
}

{
	my ($old_before) = $A->can('read_store')->($path);
	my $old_hash = $old_before->{records}{alice}{hash};

	my ($ok, $error) = $A->can('set_password')->($path, 'alice', 'newpass');
	ok($ok, 'set_password changes an existing account') or diag($error);

	my ($after) = $A->can('read_store')->($path);
	isnt($after->{records}{alice}{hash}, $old_hash, 'the stored hash actually changed');
	ok($A->can('verify')->($after->{records}{alice}{hash}, 'newpass'), 'and verifies the new password');
	ok(!$A->can('verify')->($after->{records}{alice}{hash}, 'hunter2'), 'and no longer verifies the old one');

	my ($bad_ok, $bad_error) = $A->can('set_password')->($path, 'nosuchuser', 'x');
	ok(!$bad_ok, 'set_password refuses an unknown username');
}

{
	my ($ok, $error) = $A->can('add_user')->($path, 'bob', 'support', 'y');
	ok($ok, 'a second account can be added') or diag($error);
	my ($rows) = $A->can('list_users')->($path);
	is(scalar(@$rows), 2, 'both accounts are listed');

	my ($del_ok, $del_error) = $A->can('delete_user')->($path, 'alice');
	ok($del_ok, 'delete_user removes an account') or diag($del_error);
	my ($rows_after) = $A->can('list_users')->($path);
	is(scalar(@$rows_after), 1, 'leaving the other one in place');
	is($rows_after->[0]{user}, 'bob', 'namely bob');

	my ($del_bad_ok, $del_bad_error) = $A->can('delete_user')->($path, 'alice');
	ok(!$del_bad_ok, 'deleting an already-deleted account is refused, not a silent no-op');
}

###############################################################################
# Important 2 (review round 1): a line this module cannot parse must not be
# silently dropped on the next write.
#
# read_store() collects unparsable line numbers into `malformed` and leaves
# them out of `records`/`order` - correctly, since it cannot guess what a
# broken line meant. But write_store() serialises exactly `records`/`order`,
# so without a check, the very next add/passwd/delete would silently rewrite
# the file minus every line it could not parse - including a comment, and
# including a record the HELPER's own looser reader (csf-ui-helper's
# _auth_store, which only requires user/algo/hash/role - not five colon
# fields) would still authenticate. Every write-side operation must refuse
# instead, before touching the file, and say why; `list`, being read-only,
# is safe to show what it can and warn about what it cannot.
###############################################################################
{
	my $malformed_dir = tempdir(CLEANUP => 1);
	my $malformed_path = "$malformed_dir/users";
	my $original = "# admin accounts, do not hand-edit lightly\n"
		. "alice:6:\$6\$rounds=5000\$abc\$def:admin\n"                       # 4 fields: no created_epoch
		. "bob:6:\$6\$rounds=5000\$abc\$ghi:support:1757548800\n";
	open(my $fh, '>', $malformed_path) or die $!;
	print $fh $original;
	close $fh;
	chmod 0600, $malformed_path;

	my ($store, $store_error) = $A->can('read_store')->($malformed_path);
	ok($store, 'read_store still succeeds when some lines cannot be parsed') or diag($store_error);
	is_deeply($store->{malformed}, [2], 'and reports which line it could not parse (the comment is not malformed, just skipped)');
	ok(exists $store->{records}{bob}, 'the parseable record is still readable');
	ok(!exists $store->{records}{alice}, 'the unparsable one is absent from records, as documented');

	for my $case (
		['add_user',      sub { $A->can('add_user')->($malformed_path, 'carol', 'support', 'x') }],
		['set_password',  sub { $A->can('set_password')->($malformed_path, 'bob', 'x') }],
		['delete_user',   sub { $A->can('delete_user')->($malformed_path, 'bob') }],
	) {
		my ($name, $code) = @$case;
		my ($ok, $error) = $code->();
		ok(!$ok, "$name refuses to run while the store has an unparsable line");
		like($error, qr/cannot parse/, "$name says why");
		like($error, qr/\b2\b/, "$name names the line number");
		is(_slurp($malformed_path), $original, "$name left the file byte-for-byte untouched");
	}

	my ($rows, $list_error, $malformed) = $A->can('list_users')->($malformed_path);
	ok($rows, 'list_users still succeeds') or diag($list_error);
	is(scalar(@$rows), 1, 'and lists only what it could parse');
	is_deeply($malformed, [2], 'reporting the malformed line number as its third return value');
}

###############################################################################
# Important 3 (review round 1): a foreign-algo record must not brick every
# other write.
#
# parse_record() deliberately admits algo != 6 on read (R13/S5.14) so a
# caller can still name a row it cannot verify. But format_record() -
# correctly - refuses to MINT a new record claiming any algo but 6, and
# write_store() used to run every record in the snapshot through it, so a
# single foreign-algo row anywhere in the file made every unrelated add,
# passwd or delete die uncaught (exit 255) trying to re-serialise it - even
# though the contract's own documented remedy for that row
# ("csf-ui-passwd passwd <user>") requires this CLI to keep working.
###############################################################################
{
	my $foreign_dir = tempdir(CLEANUP => 1);
	my $foreign_path = "$foreign_dir/users";
	$A->can('add_user')->($foreign_path, 'bob', 'support', 'hunter2');
	# Splice in a foreign-algo row the way a store copied from a machine that
	# had something else would carry one - parse_record() admits it; nothing
	# in this module can mint it.
	open(my $fh, '>>', $foreign_path) or die $!;
	print $fh "carol:2:somehash:admin:1757548800\n";
	close $fh;

	my ($store) = $A->can('read_store')->($foreign_path);
	ok(exists $store->{records}{carol}, 'the foreign-algo record parses on read');
	is($store->{records}{carol}{algo}, '2', 'carrying the algo this module cannot verify');

	{
		my ($ok, $error) = $A->can('set_password')->($foreign_path, 'bob', 'newpass');
		ok($ok, 'set_password on an unrelated user succeeds despite a foreign-algo record elsewhere') or diag($error);
	}
	{
		my ($after) = $A->can('read_store')->($foreign_path);
		is($after->{records}{carol}{algo}, '2', "the foreign row survives verbatim, unchanged, in someone else's write");
		is($after->{records}{carol}{hash}, 'somehash', 'byte-for-byte, not re-hashed or altered');
	}
	{
		my ($ok, $error) = $A->can('delete_user')->($foreign_path, 'bob');
		ok($ok, 'delete_user on an unrelated user also succeeds') or diag($error);
	}
	{
		# The documented remedy itself: fixing the offending row must work,
		# which is the scenario a blanket refusal would have broken.
		my ($ok, $error) = $A->can('set_password')->($foreign_path, 'carol', 'fixedpass');
		ok($ok, "the contract's own remedy - passwd on the foreign-algo user - succeeds") or diag($error);
		my ($after) = $A->can('read_store')->($foreign_path);
		is($after->{records}{carol}{algo}, '6', 'and carol is now algo 6, mintable and verifiable normally');
		ok($A->can('verify')->($after->{records}{carol}{hash}, 'fixedpass'), 'with a hash that verifies the new password');
	}
}

###############################################################################
# Atomic replace leaves no partial file
###############################################################################
{
	my $atomic_dir = tempdir(CLEANUP => 1);
	my $atomic_path = "$atomic_dir/users";
	$A->can('add_user')->($atomic_path, 'alice', 'admin', 'hunter2');
	my $original = _slurp($atomic_path);

	# Force the write to fail after the temp file is created but before the
	# rename, by pre-creating the exact temp name write_store() will pick
	# (O_EXCL then refuses to clobber it) - the same failure mode a crashed
	# prior run or a disk that fills mid-write leaves behind.
	my $pid_temp = "$atomic_path.tmp.$$";
	sysopen(my $blocker, $pid_temp, O_WRONLY | O_CREAT, 0600) or die "test setup: $!";
	print $blocker "stale\n";
	close $blocker;

	my ($ok, $error) = $A->can('write_store')->($atomic_path, { records => {}, order => [] });
	ok(!$ok, 'write_store refuses when its temp name is already taken');
	like($error, qr/cannot create/, 'and says so');

	my $after = _slurp($atomic_path);
	is($after, $original, 'the target file is untouched by the failed write');
	is(_slurp($pid_temp), "stale\n", 'and the pre-existing temp file was not touched either');
	unlink $pid_temp;

	my @leftover = glob("$atomic_dir/*.tmp.*");
	is(scalar(@leftover), 0, 'no temp file is left behind after a successful write elsewhere in this test');
}

###############################################################################
# Symlink and ownership refusals (docs/WEBUI-RPC.md S5.14, S9, S11.1: the
# store is 0600, opened only by the helper and by csf-ui-passwd, and never
# operated on through a symlink).
###############################################################################
{
	my $sym_dir = tempdir(CLEANUP => 1);
	my $target = "$sym_dir/elsewhere";
	open(my $fh, '>', $target) or die $!;
	print $fh "not the users file\n";
	close $fh;
	my $link = "$sym_dir/users";
	symlink($target, $link) or die "cannot create test symlink: $!";

	my ($store, $error) = $A->can('read_store')->($link);
	ok(!$store, 'read_store refuses a symlink target');
	like($error, qr/symlink/, 'and says why');

	my ($ok, $write_error) = $A->can('write_store')->($link, { records => {}, order => [] });
	ok(!$ok, 'write_store refuses to write through a symlink');
	like($write_error, qr/symlink/, 'and says why');

	is(_slurp($target), "not the users file\n",
		'the symlink target was never touched by either refusal');

	my ($add_ok, $add_error) = $A->can('add_user')->($link, 'alice', 'admin', 'x');
	ok(!$add_ok, 'add_user refuses a symlinked store end to end');
}

{
	my $mode_dir = tempdir(CLEANUP => 1);
	my $mode_path = "$mode_dir/users";
	$A->can('add_user')->($mode_path, 'alice', 'admin', 'hunter2');
	chmod 0644, $mode_path;

	my ($store, $error) = $A->can('read_store')->($mode_path);
	ok(!$store, 'read_store refuses a store readable by group or other');
	like($error, qr/0600/, 'and names the mode it requires');
}

SKIP: {
	skip 'cannot create a file owned by a different uid without root', 1 unless $> == 0;
	# Only reachable as root: create the store, re-own it to a non-root uid,
	# and confirm read_store refuses it exactly as it refuses any other file
	# this process does not own - the "owned by uid 0" rule the brief states,
	# checked from the other side.
	my $own_dir = tempdir(CLEANUP => 1);
	my $own_path = "$own_dir/users";
	$A->can('add_user')->($own_path, 'alice', 'admin', 'x');
	chown(65534, -1, $own_path); # nobody, or close enough on any Linux box
	my ($store, $error) = $A->can('read_store')->($own_path);
	ok(!$store, 'read_store refuses a store this process does not own');
}

###############################################################################
# Minor 9 / R25: if echo cannot be turned off, refuse rather than read the
# password anyway with it silently still on - the one place a password
# becomes visible, to shoulder-surfing, a terminal log, or tmux scrollback.
# G3 says refuse, not degrade. A real captured tty is not available under
# `prove`, so POSIX::Termios::getattr is made to fail instead - done in a
# forked child so the monkey-patch and the STDIN redirection are confined to
# one throwaway process rather than this test file's own.
###############################################################################
{
	my ($result_read, $result_write);
	pipe($result_read, $result_write) or die $!;
	my ($in_read, $in_write);
	pipe($in_read, $in_write) or die $!;

	my $pid = fork();
	die "fork failed: $!" unless defined $pid;
	if (!$pid) {
		close $in_write;
		close $result_read;
		open(STDIN, '<&', $in_read) or POSIX::_exit(126);
		no warnings 'redefine';
		local *POSIX::Termios::getattr = sub { die "simulated termios failure\n" };
		my $line = ConfigServer::UI::PasswdCLI::_read_line_no_echo();
		print $result_write (defined $line ? "DEFINED:$line" : 'UNDEF');
		close $result_write;
		POSIX::_exit(0);
	}
	close $in_read;
	print $in_write "should-not-be-read\n";
	close $in_write;
	close $result_write;
	local $/;
	my $result = <$result_read>;
	close $result_read;
	waitpid($pid, 0);
	is($result, 'UNDEF', '_read_line_no_echo refuses instead of reading with echo on when it cannot disable echo');
}

###############################################################################
# The CLI: no default account, and each command's happy and unhappy paths.
# STDIN here is never a tty under `prove`, so this exercises the
# read-from-stdin branch of read_new_password(). The interactive branch's
# happy path (successfully disabling echo, then reading) needs a real
# terminal and is not reachable from an automated suite, for the same
# reason G5 lets a root-only test skip rather than fake root; its refusal
# path when echo cannot be disabled is tested directly just above.
###############################################################################
{
	# $C holds a string too, so its two path variables are also reached by
	# symbolic reference - the CLI's own USERS_PATH/UI_CONF_PATH exist
	# precisely so a test can point them at a temp file instead of the real,
	# root-owned /etc/csf-ui paths.
	no strict 'refs';
	local ${"${C}::USERS_PATH"}   = "$dir/cli-users";
	local ${"${C}::UI_CONF_PATH"} = "$dir/cli-ui.conf";
	use strict 'refs';

	my ($rc, $out, $err) = _run_cli(['list'], '');
	is($rc, 0, 'list on a store that does not exist yet succeeds');
	like($out, qr/no accounts exist yet/, 'and says there is no way in yet - no default account');

	($rc, $out, $err) = _run_cli(['add', 'alice', 'admin'], "hunter2\n");
	is($rc, 0, 'add succeeds reading a password from stdin');
	like($out, qr/added 'alice' as admin/, 'and confirms what it did');

	($rc, $out, $err) = _run_cli(['add', 'alice', 'admin'], "hunter2\n");
	isnt($rc, 0, 'adding the same user twice fails');
	like($err, qr/already exists/, 'with a clear reason on stderr');

	($rc, $out, $err) = _run_cli(['add', 'Alice', 'admin'], "hunter2\n");
	isnt($rc, 0, 'add refuses a username outside the grammar before ever touching the store');

	($rc, $out, $err) = _run_cli(['add', 'carol', 'root'], "hunter2\n");
	isnt($rc, 0, 'add refuses an invalid role before ever touching the store');

	($rc, $out, $err) = _run_cli(['add', 'dave', 'admin'], '');
	isnt($rc, 0, 'add refuses an empty password');

	($rc, $out, $err) = _run_cli(['passwd', 'alice'], "newpass\n");
	is($rc, 0, 'passwd changes an existing account from stdin');

	($rc, $out, $err) = _run_cli(['passwd', 'nosuchuser'], "x\n");
	isnt($rc, 0, 'passwd refuses an unknown user');

	($rc, $out, $err) = _run_cli(['list'], '');
	is($rc, 0, 'list succeeds after accounts exist');
	like($out, qr/alice\s+admin/, 'and shows the account and its role');

	($rc, $out, $err) = _run_cli(['delete', 'alice'], '');
	is($rc, 0, 'delete removes an account');

	($rc, $out, $err) = _run_cli(['list'], '');
	unlike($out, qr/alice/, 'and it is gone from the listing');

	($rc, $out, $err) = _run_cli([], '');
	isnt($rc, 0, 'no command prints usage and a non-zero exit rather than guessing');
	like($err, qr/usage:/, 'to stderr');

	($rc, $out, $err) = _run_cli(['bogus'], '');
	isnt($rc, 0, 'an unrecognised command is also usage, not a crash');
}

# Runs one CLI invocation in a child process with STDIN fed from a string and
# stdout/stderr captured, so this test never touches the real terminal and
# never depends on one existing.
sub _run_cli {
	my ($args, $stdin) = @_;
	my ($read_out, $write_out);
	my ($read_err, $write_err);
	pipe($read_out, $write_out) or die $!;
	pipe($read_err, $write_err) or die $!;
	my ($read_in, $write_in);
	pipe($read_in, $write_in) or die $!;

	my $pid = fork();
	die "fork failed: $!" unless defined $pid;

	if (!$pid) {
		close $read_out; close $read_err; close $write_in;
		open(STDIN,  '<&', $read_in)  or POSIX::_exit(126);
		open(STDOUT, '>&', $write_out) or POSIX::_exit(126);
		open(STDERR, '>&', $write_err) or POSIX::_exit(126);
		my $rc = eval { ConfigServer::UI::PasswdCLI::run(@$args) };
		$rc = 255 unless defined $rc;
		POSIX::_exit($rc);
	}

	close $read_in;
	print $write_in $stdin;
	close $write_in;
	close $write_out;
	close $write_err;

	local $/;
	my $out = <$read_out>;
	my $err = <$read_err>;
	close $read_out;
	close $read_err;
	waitpid($pid, 0);
	my $rc = $? >> 8;
	return ($rc, (defined $out ? $out : ''), (defined $err ? $err : ''));
}

sub _slurp {
	my ($path) = @_;
	open(my $fh, '<', $path) or return undef;
	local $/;
	my $data = <$fh>;
	close $fh;
	return defined $data ? $data : '';
}
