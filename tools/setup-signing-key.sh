#!/bin/bash
# =============================================================================
# Set up the release signing key.
#
#   ./tools/setup-signing-key.sh --generate            create a new key
#   ./tools/setup-signing-key.sh --use <fingerprint>   use a key you already have
#
# Writes two things into the source tree:
#   ConfigServer/release-key.asc   the PUBLIC key, shipped to every install
#   ConfigServer/Release.pm        $FINGERPRINT, pinned in code
#
# WHERE THE PRIVATE KEY LIVES MATTERS MORE THAN ANY OF THIS CODE.
# Anyone holding it can publish a release that every server running this will
# install and execute as root. Keep it off shared machines, off CI, and off
# GitHub. A hardware token or an offline machine is the right home for it.
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RELEASE_PM="$REPO_ROOT/ConfigServer/Release.pm"
KEYFILE="$REPO_ROOT/ConfigServer/release-key.asc"

die() { echo "error: $*" >&2; exit 1; }

command -v gpg >/dev/null || die "gpg not found — install gnupg first"
[ -f "$RELEASE_PM" ] || die "cannot find $RELEASE_PM — run this from the repository"

MODE="${1:-}"
case "$MODE" in
  --generate)
    NAME="${2:-csf release signing key}"
    EMAIL="${3:-}"
    [ -n "$EMAIL" ] || die "usage: $0 --generate \"<name>\" <email>"

    echo "==> generating an ed25519 signing key for <$EMAIL>"
    echo "    you will be asked for a passphrase — use one, and do not lose it"
    gpg --quick-generate-key "$NAME <$EMAIL>" ed25519 sign never
    FPR="$(gpg --list-keys --with-colons "$EMAIL" | awk -F: '/^fpr:/{print $10; exit}')"
    ;;
  --use)
    FPR="${2:-}"
    [ -n "$FPR" ] || die "usage: $0 --use <fingerprint>"
    FPR="$(printf '%s' "$FPR" | tr -d ' ' | tr 'a-f' 'A-F')"
    gpg --list-keys "$FPR" >/dev/null 2>&1 || die "no key in your keyring matches $FPR"
    # Signing needs the secret half, so check for it now rather than at release time.
    gpg --list-secret-keys "$FPR" >/dev/null 2>&1 \
      || die "the SECRET key for $FPR is not in this keyring — you cannot sign with it here"
    ;;
  *)
    sed -n '2,17p' "$0"
    exit 1
    ;;
esac

[ -n "${FPR:-}" ] || die "could not determine the key fingerprint"
echo "$FPR" | grep -qE '^[0-9A-F]{40}$' || die "unexpected fingerprint format: $FPR"

echo "==> fingerprint: $FPR"

echo "==> exporting the public key to ConfigServer/release-key.asc"
gpg --armor --export "$FPR" > "$KEYFILE"
[ -s "$KEYFILE" ] || die "the exported public key is empty"

echo "==> pinning the fingerprint in ConfigServer/Release.pm"
perl -i -pe 'BEGIN{$f=shift} s/^our \$FINGERPRINT = ".*";$/our \$FINGERPRINT = "$f";/' "$FPR" "$RELEASE_PM"
grep -q "our \$FINGERPRINT = \"$FPR\";" "$RELEASE_PM" || die "failed to write the fingerprint into Release.pm"

cat <<EOF

Done.

  ConfigServer/release-key.asc   public key   ($(wc -c < "$KEYFILE") bytes)
  ConfigServer/Release.pm        pinned       $FPR

Commit both. They must ship together: the pinned fingerprint is what stops a
tampered release-key.asc from being believed.

Back up the private key now, somewhere that is not this machine:

  gpg --export-secret-keys --armor $FPR > /path/to/offline/backup.asc

Losing it means no server can be upgraded again without a manual reinstall.
EOF
