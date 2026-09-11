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
# The credential store for the replacement WebUI: hashing, constant-time
# verification, the on-disk record format, and atomic reads/writes of
# /etc/csf-ui/users. This is what replaces lfd.pl:9788's
# `$FORM{csfpassword} eq $config{UI_PASS}` - a plaintext password kept in
# csf.conf, compared with `eq`, which returns on the first differing byte and
# is a plain string anyone with a copy of csf.conf can read.
#
# Ruling R6 (docs/WEBUI-RPC.md S11.1): this module runs INSIDE the root
# helper, never in the web tier. csf-ui does not require this file and never
# opens /etc/csf-ui/users; it calls the helper's `authenticate` operation and
# gets back a verdict, never a hash. That is the whole point of the boundary:
# a compromise of the web tier yields no hash file to carry away and grind
# through offline. verify() below is called by csf-ui-helper's auth_verify()
# seam, in the helper's own process, as root.
#
# Two things bind everywhere in this file:
#
#   G1/R13  $6$ SHA-512 crypt() is the only implemented algorithm.
#           Crypt::Argon2 is neither core nor vendored in this tree, so it
#           cannot be a dependency, and an optional branch nobody can exercise
#           would advertise a strength the deployment does not have. The
#           `algo` field is kept in every record so a future migration has
#           somewhere to go; only `6` is accepted, on read and on write.
#   G3      Fail closed. hash_password() and the store writer refuse rather
#           than guess whenever an input is out of range or the target file
#           is not what it is supposed to be. verify() never dies on a wrong
#           password or a malformed hash - a die from here is read by the
#           helper as "the verifier could not run" (E_BACKEND, counter
#           untouched), which must never be how an ordinary wrong guess is
#           answered, or the failure counter it feeds would stop counting.
###############################################################################
package ConfigServer::UI::Auth;

use strict;
use warnings;

use Digest::SHA ();
use Encode ();
use Fcntl qw(:DEFAULT :flock :mode);
use IO::Handle ();

our $VERSION = '1.00';

###############################################################################
# Frozen values (docs/WEBUI-RPC.md S10, S11.8)
###############################################################################
our $MIN_ROUNDS     = 5000;
our $DEFAULT_ROUNDS = 100000;
our $MAX_ROUNDS     = 2000000;

# \A...\z, not ^...$: "$" matches just before a trailing newline as well as at
# the true end of the string, which would let "alice\n" through as a username.
my $USERNAME_RE = qr/\A[a-z0-9_-]{1,32}\z/;
my %VALID_ROLE  = (admin => 1, support => 1);
my @SALT_CHARS  = ('.', '/', 0 .. 9, 'A' .. 'Z', 'a' .. 'z'); # crypt's 64-char alphabet

###############################################################################
# Username and role grammar - the same shape docs/WEBUI-RPC.md S4.9 enforces
# on the RPC argument, so that a username this module would refuse to write
# is also a username the wire protocol refuses to accept.
###############################################################################
sub validate_username {
	my ($user) = @_;
	return 0 unless defined $user && !ref($user);
	return $user =~ $USERNAME_RE ? 1 : 0;
}

sub validate_role {
	my ($role) = @_;
	return 0 unless defined $role && !ref($role);
	return $VALID_ROLE{$role} ? 1 : 0;
}

# R24. docs/WEBUI-RPC.md S4.10: "normalisation: none. The bytes are compared
# as sent." Proto::validate_pass (Task 2, ui-src/lib/ConfigServer/UI/Proto.pm)
# decodes the wire's UTF-8 and hands the helper a utf8-flagged CHARACTER
# string for any password outside ASCII - the same normalisation Proto.pm
# applies to everything else it handles. csf-ui-passwd, on the other hand,
# hashes whatever raw BYTES it read from a prompt or stdin, with no such
# flag. crypt() croaks on a utf8-flagged argument rather than hashing the
# bytes underneath it, so without this the two paths mint and check two
# different strings for what is, on the wire, one password: a correct
# non-ASCII password would crypt()-croak at verify time, be swallowed by
# verify()'s eval, come back as a plain wrong-password 0, and burn the
# S5.14 lockout counter on every attempt - a live denial of service
# triggered by the *right* password. Encoding both sides to the same UTF-8
# octets here, once, is what makes "the bytes are compared as sent" true
# regardless of which of the two calling conventions handed this module the
# password.
sub _pass_octets {
	my ($pass) = @_;
	return $pass unless defined $pass;
	return utf8::is_utf8($pass) ? Encode::encode('UTF-8', $pass) : $pass;
}

###############################################################################
# Hashing
###############################################################################
sub _random_bytes {
	my ($count) = @_;
	open(my $fh, '<', '/dev/urandom') or die "cannot open /dev/urandom: $!\n";
	binmode($fh);
	my $data = '';
	while (length($data) < $count) {
		my $chunk;
		my $read = sysread($fh, $chunk, $count - length($data));
		unless (defined $read && $read > 0) {
			close $fh;
			die "short read from /dev/urandom\n";
		}
		$data .= $chunk;
	}
	close $fh;
	return $data;
}

# 16 random salt bytes from /dev/urandom, mapped onto crypt's 64-character
# salt alphabet. 256 is an exact multiple of 64, so masking each byte to its
# low 6 bits is uniform over the alphabet - no modulo bias.
sub _random_salt {
	my $salt = '';
	$salt .= $SALT_CHARS[ $_ & 0x3f ] for unpack('C*', _random_bytes(16));
	return $salt;
}

# Never store plaintext, never anything but $6$: hash_password() is the only
# place a new hash is minted, and it refuses outright rather than produce one
# outside ui.conf's UI_CRYPT_ROUNDS range (docs/WEBUI-RPC.md S10) or one that
# is not actually $6$, which would otherwise be stored and then be silently
# unverifiable the next time someone logs in.
sub hash_password {
	my ($pass, $rounds) = @_;
	die "password must be defined\n" unless defined $pass;
	$pass = _pass_octets($pass);
	$rounds = $DEFAULT_ROUNDS unless defined $rounds;
	die "UI_CRYPT_ROUNDS must be an integer between $MIN_ROUNDS and $MAX_ROUNDS\n"
		unless $rounds =~ /\A[0-9]+\z/ && $rounds >= $MIN_ROUNDS && $rounds <= $MAX_ROUNDS;

	my $setting = '$6$rounds=' . $rounds . '$' . _random_salt();
	my $hash = crypt($pass, $setting);
	die "crypt() on this system did not produce a \$6\$ hash\n"
		unless defined $hash && $hash =~ /^\$6\$/ && length($hash) > length($setting);
	return $hash;
}

###############################################################################
# Constant-time verification - the seam csf-ui-helper's auth_verify() calls
# as ConfigServer::UI::Auth::verify($hash, $pass). Matches that call exactly:
# two positional scalars in, a plain true/false verdict out, never a die for
# an ordinary wrong password or a malformed stored hash.
#
# $DIGESTER exists only so t/20-auth.t can prove the comparison below does
# not stop at the first differing byte - production code never overrides it.
# Because both sides are always reduced to a digest of the SAME fixed length
# first, the comparison loop's length never depends on where two inputs
# differ, or on whether they differ at all: there is nothing here for a timing
# assertion to notice, which is why the test instead counts how many digest
# bytes the loop actually visited.
###############################################################################
our $DIGESTER = \&_sha256_digest;

sub _sha256_digest {
	my ($value) = @_;
	return Digest::SHA::sha256(defined $value ? $value : '');
}

# Test-only introspection: constant_time_equal() resets this to 0 and then
# increments it once per byte position visited in the comparison loop, so a
# test can assert the loop ran to completion - to the full digest length -
# whether the inputs matched, differed at the first byte, or differed at the
# last. Production code never reads it.
our $COMPARE_VISITS = 0;

sub constant_time_equal {
	my ($left, $right) = @_;
	my $left_digest  = $DIGESTER->($left);
	my $right_digest = $DIGESTER->($right);
	my $left_len  = length($left_digest);
	my $right_len = length($right_digest);
	my $len = $left_len > $right_len ? $left_len : $right_len;

	$COMPARE_VISITS = 0;
	my $diff = $left_len ^ $right_len;
	for my $i (0 .. $len - 1) {
		$COMPARE_VISITS++;
		my $l = $i < $left_len  ? ord(substr($left_digest,  $i, 1)) : 0;
		my $r = $i < $right_len ? ord(substr($right_digest, $i, 1)) : 0;
		$diff |= ($l ^ $r);
	}
	return $diff == 0 ? 1 : 0;
}

sub verify {
	my ($hash, $pass) = @_;
	return 0 unless defined $hash && length($hash) && defined $pass;
	$pass = _pass_octets($pass);

	# crypt() does not die on a malformed salt/setting string on any platform
	# this ships for; it returns something that will not match. The eval is
	# defensive, not load-bearing - and either way this returns a plain 0
	# rather than propagating a die, because a die here is read by the caller
	# as "the verifier could not run", which must never be how an ordinary
	# wrong guess or a corrupt hash is answered (G3: that path leaves the
	# per-username failure counter untouched, and an unmetered guess is the
	# one thing S5.14's counter exists to prevent).
	my $computed = eval { crypt($pass, $hash) };
	$computed = '' unless defined $computed;
	return constant_time_equal($computed, $hash);
}

###############################################################################
# Record format (docs/WEBUI-RPC.md S5.14, S11.8):
#   username:algo:hash:role:created_epoch
# `algo` is kept for a future migration. format_record() is the gate this
# module mints a record through - add_user() and set_password() always pass
# algo => '6', and this refuses to serialise anything else, so this module
# can never ORIGINATE a record claiming an algorithm it does not itself
# implement. parse_record() below deliberately admits a foreign `algo` on
# READ, so a caller can still name a row it cannot verify rather than lose
# it - see _verbatim_record() for how such a row survives being written back
# out unminted.
###############################################################################
sub format_record {
	my (%rec) = @_;
	for my $field (qw(user algo hash role created)) {
		die "format_record: $field is required\n" unless defined $rec{$field};
	}
	die "format_record: invalid username\n" unless validate_username($rec{user});
	die "format_record: invalid role\n" unless validate_role($rec{role});
	die "format_record: only algo 6 can be written\n" unless $rec{algo} eq '6';
	die "format_record: created must be a non-negative integer epoch\n"
		unless $rec{created} =~ /\A[0-9]+\z/;
	die "format_record: hash must not contain ':' or a newline\n"
		if $rec{hash} =~ /[:\n]/;
	die "format_record: hash must not be empty\n" unless length($rec{hash});
	return join(':', $rec{user}, $rec{algo}, $rec{hash}, $rec{role}, $rec{created});
}

# format_record()'s "only algo 6" rule is a mint-time gate: it stops this
# module ORIGINATING a new record it cannot itself verify. It must not also
# apply to a foreign-algo row parse_record() already admitted from an
# existing store (R13/S5.14) - refusing to re-serialise that row on every
# unrelated write would make the contract's own advertised remedy for it
# ("the record for this user carries an algo this helper cannot verify...
# reset it with csf-ui-passwd passwd <user>", csf-ui-helper's E_UNAVAILABLE
# message) unreachable: the offending row would still be sitting there,
# byte-identical, blocking the very next write - including the `passwd`
# call meant to fix it. So a foreign-algo row is carried through verbatim,
# unchanged, by whichever write touches OTHER users; only the row actually
# being added or reset is ever required to be algo 6 (Important 3).
sub _verbatim_record {
	my (%rec) = @_;
	for my $field (qw(user algo hash role created)) {
		die "cannot write a record missing '$field'\n" unless defined $rec{$field};
	}
	die "cannot write a record with an invalid username\n" unless validate_username($rec{user});
	die "cannot write a record with an invalid role\n" unless validate_role($rec{role});
	die "cannot write a record whose created field is not a non-negative integer epoch\n"
		unless $rec{created} =~ /\A[0-9]+\z/;
	die "cannot write a record whose hash contains ':' or a newline\n"
		if $rec{hash} =~ /[:\n]/;
	die "cannot write a record with an empty hash\n" unless length($rec{hash});
	return join(':', $rec{user}, $rec{algo}, $rec{hash}, $rec{role}, $rec{created});
}

# Returns undef for anything that is not exactly five well-formed fields.
# Malformed lines are the caller's problem to count and report, not this
# function's to guess at - a users file is hand-editable root config and a
# best-effort parse of a broken line is how a locked-out admin becomes a
# silently-wrong one instead.
sub parse_record {
	my ($line) = @_;
	return undef unless defined $line;
	my $text = $line;
	$text =~ s/[\r\n]+\z//;
	return undef if $text eq '' || $text =~ /^\s*#/;

	my @field = split(/:/, $text, -1);
	return undef unless @field == 5;
	my ($user, $algo, $hash, $role, $created) = @field;
	return undef unless validate_username($user);
	return undef unless defined $algo && $algo =~ /\A[0-9]+\z/;
	return undef unless defined $hash && length($hash);
	return undef unless validate_role($role);
	return undef unless defined $created && $created =~ /\A[0-9]+\z/;
	# R13/G1: an algo this module did not write is unverifiable, not
	# malformed - the record parses so a caller (the helper's own store
	# reader, or `list`) can still name the user and the algorithm it cannot
	# check; only `verify()` and the write path treat "not 6" as fatal.
	return {
		user    => $user,
		algo    => $algo,
		hash    => $hash,
		role    => $role,
		created => $created + 0,
	};
}

# The brief and docs/WEBUI-RPC.md's S9/S11.1 both say the store must be
# "owned by uid 0" - a literal statement about production, where this process
# always is root. Checking that literally would refuse every fixture in
# t/20-auth.t outright, since nothing under `prove` runs as uid 0, which is
# exactly what G5 rules out. Root's own euid IS 0, so "owned by $>" and
# "owned by uid 0" are the same check whenever this process actually is root;
# the fallback below only ever relaxes anything when it is not, which is
# precisely the unprivileged test harness this module must keep working
# without root (Minor 6).
sub _owned_correctly {
	my (@stat) = @_;
	return $> == 0 ? $stat[4] == 0 : $stat[4] == $>;
}

sub _not_owned_message {
	my ($path) = @_;
	return $> == 0
		? "$path is not owned by uid 0; refusing to operate on it"
		: "$path is not owned by this process; refusing to operate on it";
}

###############################################################################
# Reading the store.
#
# A file that does not exist yet is not an error: G3's "no default account"
# means the very first `csf-ui-passwd add` runs against a store that is not
# there. Everything else - a symlink, wrong owner, wrong mode, wrong type -
# is refused rather than read around, matching the same checks
# csf-ui-helper's own _auth_store() makes on this file for `authenticate`.
###############################################################################
sub read_store {
	my ($path) = @_;
	return ({ records => {}, order => [], malformed => [] }, undef)
		unless -e $path || -l $path;
	return (undef, "$path is a symlink; refusing to operate on it") if -l $path;

	my @stat = stat($path);
	return (undef, "$path could not be stat'd: $!") unless @stat;
	return (undef, "$path is not a regular file; refusing to operate on it")
		unless S_ISREG($stat[2]);
	return (undef, _not_owned_message($path)) unless _owned_correctly(@stat);
	return (undef, "$path is readable or writable by group or other; it must be mode 0600")
		if ($stat[2] & 0077);

	open(my $fh, '<', $path) or return (undef, "cannot open $path: $!");
	my (%records, @order, @malformed);
	my $line_no = 0;
	while (my $line = <$fh>) {
		$line_no++;
		my $trimmed = $line;
		$trimmed =~ s/[\r\n]+\z//;
		next if $trimmed eq '' || $trimmed =~ /^\s*#/;
		my $rec = parse_record($trimmed);
		if (!$rec) {
			push @malformed, $line_no;
			next;
		}
		push @order, $rec->{user} unless exists $records{ $rec->{user} };
		$records{ $rec->{user} } = $rec;
	}
	close $fh;
	return ({ records => \%records, order => \@order, malformed => \@malformed }, undef);
}

###############################################################################
# Writing the store, atomically.
#
# Refuses up front if the target is a symlink or (when it already exists) is
# not a plain file owned by this process - the same refusal read_store()
# makes, so a store this module would not trust to read it will also not
# overwrite. The actual replace is a temp file created O_EXCL in the same
# directory at mode 0600, fsync'd, then renamed over the target: rename(2)
# replaces whatever directory entry is there in one atomic step without ever
# following it as a symlink, so the TOCTOU window that matters is the one
# before this function is called, not the one inside it.
###############################################################################
sub write_store {
	my ($path, $snapshot) = @_;

	return (0, "$path is a symlink; refusing to write through it") if -l $path;
	if (-e $path) {
		my @stat = stat($path);
		return (0, "$path could not be stat'd: $!") unless @stat;
		return (0, "$path is not a regular file; refusing to overwrite it")
			unless S_ISREG($stat[2]);
		return (0, _not_owned_message($path)) unless _owned_correctly(@stat);
	}

	my $body = '';
	for my $user (@{ $snapshot->{order} }) {
		my $rec = $snapshot->{records}{$user} or next;
		# Important 3: a foreign-algo row (parse_record admitted one; see
		# above) must not go through format_record()'s mint-time "algo must
		# be 6" gate, or every unrelated write dies uncaught the moment such
		# a row exists anywhere in the store. Wrapped in eval regardless, so
		# any other malformed-in-memory record is a clean (0, $error) refusal
		# rather than an uncaught die with an exit code nothing here chose.
		my $line = eval {
			(defined $rec->{algo} && $rec->{algo} eq '6')
				? format_record(%$rec)
				: _verbatim_record(%$rec);
		};
		if ($@) {
			(my $reason = $@) =~ s/\s+\z//;
			return (0, "cannot write the record for '$user': $reason");
		}
		$body .= "$line\n";
	}

	my $temp = "$path.tmp.$$";
	sysopen(my $fh, $temp, O_WRONLY | O_CREAT | O_EXCL, 0600)
		or return (0, "cannot create $temp: $! "
			. "(a stale temp file from a previous failure may need removing)");

	my $wrote = eval {
		local $\ = '';
		print { $fh } $body or die "write failed: $!\n";
		1;
	};
	unless ($wrote) {
		my $error = $@ || 'unknown error';
		close $fh;
		unlink $temp;
		return (0, "could not write $temp: $error");
	}
	unless ($fh->flush) {
		close $fh;
		unlink $temp;
		return (0, "could not flush $temp: $!");
	}
	unless (eval { $fh->sync }) {
		my $error = $@ || $! || 'unknown error';
		close $fh;
		unlink $temp;
		return (0, "could not fsync $temp: $error");
	}
	close $fh;

	unless (rename($temp, $path)) {
		my $error = $!;
		unlink $temp;
		return (0, "could not rename $temp to $path: $error");
	}
	return (1, undef);
}

###############################################################################
# Serialises concurrent csf-ui-passwd invocations against each other. A
# separate lock file rather than locking $path itself, because write_store()
# replaces $path's inode by rename - a lock held on the old inode would stop
# guarding the name the moment the rename that finishes our own operation
# happens, let alone a second one.
###############################################################################
sub _with_lock {
	my ($path, $code) = @_;
	my $lock_path = "$path.lock";
	sysopen(my $lock_fh, $lock_path, O_RDWR | O_CREAT, 0600)
		or return (0, "cannot open $lock_path: $!");
	unless (flock($lock_fh, LOCK_EX)) {
		close $lock_fh;
		return (0, "cannot lock $lock_path: $!");
	}
	my @result = $code->();
	close $lock_fh;
	return @result;
}

# Important 2: read_store() collects the line numbers it could not parse
# into `malformed` and drops them from `records`/`order` - correctly, since
# it cannot guess what a broken line meant. But `records`/`order` is exactly
# what write_store() serialises, so the naive read -> mutate -> write cycle
# silently deletes every such line, and every comment, the next time ANYONE
# runs add/passwd/delete - including a line the *helper's own*, looser
# reader still authenticates against (csf-ui-helper's _auth_store() requires
# only user/algo/hash/role, not a five-field split). Data loss that reports
# ok=1 is the worst shape this could take, so every write-side operation
# refuses outright, before touching the file, when the store it just read
# has anything it could not parse - the same "fix or remove it by hand"
# recovery the module already asks for elsewhere in this file, and the only
# one that exists for a line with no field this module can even guess at.
sub _malformed_error {
	my ($store) = @_;
	my @lines = @{ $store->{malformed} || [] };
	return undef unless @lines;
	return "the store has " . scalar(@lines) . " line(s) this module cannot parse (line"
		. (@lines == 1 ? '' : 's') . ' ' . join(', ', @lines)
		. "); refusing to rewrite it until they are fixed or removed by hand - "
		. "a write here would silently delete them";
}

###############################################################################
# The four operations csf-ui-passwd needs. Each is lock -> read -> mutate ->
# write, so two invocations racing each other cannot interleave into a
# corrupt or half-applied store.
###############################################################################
sub add_user {
	my ($path, $user, $role, $pass, %option) = @_;
	return (0, "invalid username: must be 1 to 32 characters of a-z, 0-9, underscore or hyphen")
		unless validate_username($user);
	return (0, "invalid role: must be 'admin' or 'support'") unless validate_role($role);
	return (0, "password must not be empty") unless defined $pass && length($pass);

	return _with_lock($path, sub {
		my ($store, $error) = read_store($path);
		return (0, $error) unless $store;
		if (my $malformed_error = _malformed_error($store)) { return (0, $malformed_error) }
		return (0, "user '$user' already exists; use 'passwd' to change the password")
			if exists $store->{records}{$user};

		my $hash = eval { hash_password($pass, $option{rounds}) };
		return (0, "could not hash password: $@") if $@;

		$store->{records}{$user} = {
			user => $user, algo => '6', hash => $hash, role => $role, created => time(),
		};
		push @{ $store->{order} }, $user;
		my ($ok, $write_error) = write_store($path, $store);
		return (0, $write_error) unless $ok;
		return (1, undef);
	});
}

sub set_password {
	my ($path, $user, $pass, %option) = @_;
	return (0, "password must not be empty") unless defined $pass && length($pass);

	return _with_lock($path, sub {
		my ($store, $error) = read_store($path);
		return (0, $error) unless $store;
		if (my $malformed_error = _malformed_error($store)) { return (0, $malformed_error) }
		return (0, "no such user: $user") unless exists $store->{records}{$user};

		my $hash = eval { hash_password($pass, $option{rounds}) };
		return (0, "could not hash password: $@") if $@;

		$store->{records}{$user}{hash} = $hash;
		$store->{records}{$user}{algo} = '6';
		my ($ok, $write_error) = write_store($path, $store);
		return (0, $write_error) unless $ok;
		return (1, undef);
	});
}

sub delete_user {
	my ($path, $user) = @_;

	return _with_lock($path, sub {
		my ($store, $error) = read_store($path);
		return (0, $error) unless $store;
		if (my $malformed_error = _malformed_error($store)) { return (0, $malformed_error) }
		return (0, "no such user: $user") unless exists $store->{records}{$user};

		delete $store->{records}{$user};
		$store->{order} = [ grep { $_ ne $user } @{ $store->{order} } ];
		my ($ok, $write_error) = write_store($path, $store);
		return (0, $write_error) unless $ok;
		return (1, undef);
	});
}


# Third return value: the line numbers read_store() could not parse (never
# undef; empty when there are none), so the CLI's `list` - read-only, and so
# in no danger of destroying them - can at least say they exist instead of
# presenting a store that looks complete when it is not.
sub list_users {
	my ($path) = @_;
	my ($store, $error) = read_store($path);
	return (undef, $error) unless $store;
	my @rows = map {
		my $rec = $store->{records}{$_};
		{ user => $rec->{user}, role => $rec->{role}, algo => $rec->{algo}, created => $rec->{created} };
	} @{ $store->{order} };
	return (\@rows, undef, $store->{malformed});
}

1;
