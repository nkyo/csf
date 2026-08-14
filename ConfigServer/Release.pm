###############################################################################
# Copyright (C) 2006-2025 Jonathan Michaelson
#
# Added 2026-08-14 in https://github.com/nkyo/csf — not part of the original
# CSF v15.00 release. See CHANGES.md.
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
# Where releases come from, and how they are verified.
#
# The original update path fetched a tarball over the network and ran
# `sh install.sh` from it as root with NO integrity check of any kind. Anyone
# able to answer for the download host — or to sit in the middle, since the
# code fell back to plain http:// when TLS was unavailable — got remote root on
# every server that auto-updated.
#
# Everything here fails CLOSED. If gpg is missing, if the key is missing, if
# the fingerprint does not match, if anything at all is uncertain: no upgrade.
# Refusing to update is a bad day. Installing an unverified root-privileged
# tarball is a much worse one.
###############################################################################
package ConfigServer::Release;

use strict;
use warnings;
use Exporter qw(import);

our $VERSION   = 1.00;
our @ISA       = qw(Exporter);
our @EXPORT_OK = qw();

# Where this fork lives.
our $REPO = "nkyo/csf";

# Release signing key, shipped with the source and installed by the same
# `cp -avf ConfigServer /usr/local/csf/lib/` that installs these modules.
our $KEYFILE = "/usr/local/csf/lib/ConfigServer/release-key.asc";

# Fingerprint of the signing key, 40 hex characters, no spaces.
#
# PINNED ON PURPOSE. Without this, verification only proves "signed by whoever
# release-key.asc happens to contain", which a tampered upgrade could simply
# replace. With it, the trusted key is fixed in code that has been reviewed.
#
# Empty means signing has not been set up yet — in that state upgrades are
# refused rather than performed unverified. Fill it in with
# tools/setup-signing-key.sh.
our $FINGERPRINT = "";

sub repo { return $REPO }

sub version_url {
	return "https://raw.githubusercontent.com/$REPO/main/version.txt";
}

sub tarball_url {
	my $version = shift;
	return "https://github.com/$REPO/releases/download/v$version/csf.tgz";
}

sub signature_url {
	my $version = shift;
	return tarball_url($version).".asc";
}

sub changelog_url {
	return "https://github.com/$REPO/blob/main/CHANGES.md";
}

# Is release signing configured on this installation?
sub configured {
	return 0 unless (defined $FINGERPRINT and $FINGERPRINT =~ /^[0-9A-Fa-f]{40}$/);
	return 0 unless (-s $KEYFILE);
	return 1;
}

sub gpg_binary {
	foreach my $path ("/usr/bin/gpg", "/bin/gpg", "/usr/local/bin/gpg", "/usr/bin/gpg2") {
		if (-x $path) {return $path}
	}
	return "";
}

# verify($file, $sigfile) -> (1, "") on success, (0, "reason") on failure.
#
# Uses a throwaway GNUPGHOME so root's own keyring is neither read nor written:
# a key trusted for something else must not become a key trusted to ship code
# to these servers.
sub verify {
	my $file    = shift;
	my $sigfile = shift;

	unless (&configured) {
		return (0, "release signing is not configured on this installation ".
		           "(ConfigServer::Release::\$FINGERPRINT is unset, or $KEYFILE is missing)");
	}
	unless (defined $file and -s $file)       {return (0, "package is missing or empty")}
	unless (defined $sigfile and -s $sigfile) {return (0, "signature is missing or empty")}

	my $gpg = &gpg_binary;
	unless ($gpg) {
		return (0, "gpg was not found, so the package cannot be verified. ".
		           "Install gnupg, or upgrade manually after checking the signature yourself");
	}

	my $home = "/var/lib/csf/relverify.$$";
	system("rm", "-rf", $home);
	unless (mkdir($home, 0700)) {return (0, "cannot create temporary keyring directory $home: $!")}

	my @gpgcmd = ($gpg, "--homedir", $home, "--batch", "--quiet", "--no-tty",
	              "--no-options", "--no-default-keyring", "--trust-model", "always");

	my ($ok, $why) = (0, "");

	if (system(@gpgcmd, "--import", $KEYFILE) != 0) {
		$why = "cannot import the release key from $KEYFILE";
	} else {
		my $statusfile = "$home/status";
		system(@gpgcmd, "--status-file", $statusfile, "--verify", $sigfile, $file);

		my $status = "";
		if (open(my $STATUS, "<", $statusfile)) {
			local $/ = undef;
			$status = <$STATUS>;
			close($STATUS);
		}
		$status = "" unless defined $status;

		if ($status =~ /^\[GNUPG:\]\s+(REVKEYSIG|EXPKEYSIG|BADSIG|ERRSIG)\b/m) {
			$why = "signature is not usable ($1)";
		} elsif ($status !~ /^\[GNUPG:\]\s+GOODSIG\b/m) {
			$why = "no good signature on the package";
		} else {
			# VALIDSIG <fpr> ... [<primary-key-fpr>] — accept either, so that
			# signing with a subkey of the pinned primary key still verifies.
			my $matched = 0;
			foreach my $line (split(/\n/, $status)) {
				next unless ($line =~ /^\[GNUPG:\]\s+VALIDSIG\s+(.*)$/);
				foreach my $field (split(/\s+/, $1)) {
					if (uc($field) eq uc($FINGERPRINT)) {$matched = 1; last}
				}
				last if $matched;
			}
			if ($matched) {
				$ok = 1;
			} else {
				$why = "package is signed, but not by the pinned release key ($FINGERPRINT)";
			}
		}
	}

	system("rm", "-rf", $home);
	return $ok ? (1, "") : (0, $why);
}

1;
