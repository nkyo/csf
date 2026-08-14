#!/bin/bash
# =============================================================================
# Build, sign and publish a release.
#
#   ./tools/release.sh            build + sign + verify, stop before publishing
#   ./tools/release.sh --publish  also create the GitHub release and upload
#
# The version comes from version.txt, and the tag is v<version> — the same URL
# ConfigServer::Release builds when a server asks for an upgrade. If those two
# disagree, servers download a 404.
#
# The tarball is built with `git archive` from the tag and gzipped with -n, so
# it is REPRODUCIBLE: anyone can rebuild it from the tag and get a byte-identical
# file. That is what makes "you can check for yourself" true rather than a claim.
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

PUBLISH=0
[ "${1:-}" = "--publish" ] && PUBLISH=1

die() { echo "error: $*" >&2; exit 1; }

command -v git >/dev/null || die "git not found"
command -v gpg >/dev/null || die "gpg not found"

[ -z "$(git status --porcelain)" ] || die "working tree is dirty — commit first"

VERSION="$(tr -d '[:space:]' < version.txt)"
echo "$VERSION" | grep -qE '^[0-9]+\.[0-9]+$' || die "version.txt does not look like a version: '$VERSION'"
TAG="v$VERSION"

FPR="$(perl -ne 'print $1 if /^our \$FINGERPRINT = "([0-9A-Fa-f]{40})";/' ConfigServer/Release.pm)"
[ -n "$FPR" ] || die "no release key pinned in ConfigServer/Release.pm — run tools/setup-signing-key.sh"
[ -s ConfigServer/release-key.asc ] || die "ConfigServer/release-key.asc is missing"
gpg --list-secret-keys "$FPR" >/dev/null 2>&1 || die "the secret key for $FPR is not in this keyring"

echo "==> version $VERSION   tag $TAG   key $FPR"

# The tag must exist and must point at what is checked out, or the tarball will
# not match the code that was reviewed.
if git rev-parse "$TAG" >/dev/null 2>&1; then
	[ "$(git rev-parse "$TAG^{commit}")" = "$(git rev-parse HEAD)" ] \
		|| die "tag $TAG exists but does not point at HEAD"
else
	echo "==> creating tag $TAG"
	git tag -a "$TAG" -m "csf $VERSION"
fi

OUT="$REPO_ROOT/dist"
rm -rf "$OUT"; mkdir -p "$OUT"

echo "==> building csf.tgz from $TAG (reproducible)"
# --prefix=csf/ keeps the historic layout: `tar -xzf csf.tgz; cd csf`.
# gzip -n drops the timestamp and filename from the header, which are the only
# non-deterministic parts.
git archive --format=tar --prefix=csf/ "$TAG" | gzip -n -9 > "$OUT/csf.tgz"

( cd "$OUT" && sha256sum csf.tgz > csf.tgz.sha256 )
echo "    $(cut -d' ' -f1 < "$OUT/csf.tgz.sha256")  ($(stat -c%s "$OUT/csf.tgz") bytes)"

echo "==> signing"
gpg --batch --yes --local-user "$FPR" --detach-sign --armor -o "$OUT/csf.tgz.asc" "$OUT/csf.tgz"

# Verify the way a server will, against the shipped public key and the pinned
# fingerprint — not against whatever else happens to be in this keyring.
echo "==> verifying the way a server will"
VHOME="$(mktemp -d)"
chmod 700 "$VHOME"
gpg --homedir "$VHOME" --batch --quiet --no-options --import ConfigServer/release-key.asc
gpg --homedir "$VHOME" --batch --quiet --no-options --trust-model always \
    --status-file "$VHOME/status" --verify "$OUT/csf.tgz.asc" "$OUT/csf.tgz" >/dev/null 2>&1 || true
grep -q "^\[GNUPG:\] GOODSIG" "$VHOME/status" || { rm -rf "$VHOME"; die "signature did not verify"; }
grep "^\[GNUPG:\] VALIDSIG" "$VHOME/status" | grep -qi "$FPR" \
	|| { rm -rf "$VHOME"; die "signature is not from the pinned key $FPR"; }
rm -rf "$VHOME"
echo "    good signature from $FPR"

# Reproducibility check: build it a second time and compare.
echo "==> checking the build is reproducible"
git archive --format=tar --prefix=csf/ "$TAG" | gzip -n -9 > "$OUT/csf-again.tgz"
cmp -s "$OUT/csf.tgz" "$OUT/csf-again.tgz" || die "two builds of the same tag differ — not reproducible"
rm -f "$OUT/csf-again.tgz"
echo "    identical on rebuild"

if [ "$PUBLISH" -eq 0 ]; then
	cat <<EOF

Built but NOT published. Artefacts in dist/:

  csf.tgz  csf.tgz.asc  csf.tgz.sha256

To publish:  git push origin $TAG && ./tools/release.sh --publish
EOF
	exit 0
fi

command -v gh >/dev/null || die "gh not found — needed to publish"
gh auth status >/dev/null 2>&1 || die "not logged in — run: gh auth login"

echo "==> pushing tag"
git push origin "$TAG"

echo "==> creating the GitHub release"
NOTES="$(mktemp)"
cat > "$NOTES" <<EOF
csf $VERSION

Verify before installing:

    gpg --import ConfigServer/release-key.asc      # or from this repository
    gpg --verify csf.tgz.asc csf.tgz
    sha256sum -c csf.tgz.sha256

Signed with $FPR.

csf.tgz is built reproducibly from tag $TAG. To confirm nothing was added to it:

    git archive --format=tar --prefix=csf/ $TAG | gzip -n -9 | sha256sum

Changes are listed in CHANGES.md.
EOF

gh release create "$TAG" \
	"$OUT/csf.tgz" "$OUT/csf.tgz.asc" "$OUT/csf.tgz.sha256" \
	--title "csf $VERSION" --notes-file "$NOTES"
rm -f "$NOTES"

echo
echo "Published: https://github.com/$(gh repo view --json nameWithOwner --jq .nameWithOwner)/releases/tag/$TAG"
