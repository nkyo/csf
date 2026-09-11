#!/bin/sh
###############################################################################
# Copyright (C) 2006-2025 Jonathan Michaelson
#
# Added 2026-09-11 in https://github.com/nkyo/csf — not part of the original
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
# Give this host its own certificate for the csf WebUI.
#
# Up to and including v15.00, a private key was SHIPPED IN THE TARBALL as
# ui/server.key, and every installer copied it to /etc/csf/ui/. Every server
# that enabled the built-in UI therefore served https with a key that anyone
# who downloaded csf already had, so the traffic could be read or altered by
# anyone able to see it. The certificate had also expired on 2020-07-17, which
# trained administrators to click past the browser warning — the same warning a
# real interception would raise.
#
# That key and certificate have been removed from the source. This script
# replaces them with a key generated on, and never leaving, this host.
#
#   sh ui-cert.sh            generate if missing, expired, or the shipped one
#   sh ui-cert.sh --force    replace whatever is there (rotate)
#
# Installed as /usr/local/csf/bin/csf-ui-cert.sh so it can be re-run later.
###############################################################################

UIDIR="${CSF_UI_DIR:-/etc/csf/ui}"
KEY="$UIDIR/server.key"
CRT="$UIDIR/server.crt"
DAYS="${CSF_UI_CERT_DAYS:-3650}"

# SHA-256 fingerprint of the certificate shipped up to v15.00. Any host still
# serving this one is using a private key that is public.
LEAKED="2EAB8C4A2DDE5A7D284E4652339843F4F0F26AC24AECC0D8FC4F1D6C119BB29A"

FORCE=0
[ "$1" = "--force" ] && FORCE=1

OPENSSL="$(command -v openssl 2>/dev/null)"
if [ -z "$OPENSSL" ]; then
	echo "csf: openssl not found, cannot create a certificate for the WebUI."
	echo "csf: install openssl and run: sh /usr/local/csf/bin/csf-ui-cert.sh"
	echo "csf: until then do not enable UI = \"1\" in /etc/csf/csf.conf"
	exit 0
fi

mkdir -p "$UIDIR" 2>/dev/null

fingerprint() {
	"$OPENSSL" x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null \
		| sed 's/.*=//; s/://g' | tr 'a-f' 'A-F'
}

REASON=""
if [ "$FORCE" -eq 1 ]; then
	REASON="asked to rotate"
elif [ ! -s "$KEY" ] || [ ! -s "$CRT" ]; then
	REASON="no certificate yet"
elif [ "$(fingerprint "$CRT")" = "$LEAKED" ]; then
	REASON="replacing the certificate that shipped with csf, whose private key is public"
elif ! "$OPENSSL" x509 -in "$CRT" -noout -checkend 0 >/dev/null 2>&1; then
	REASON="the certificate has expired"
else
	# Key and certificate must still belong together, or lfd will not start.
	k="$("$OPENSSL" pkey -in "$KEY" -pubout 2>/dev/null | "$OPENSSL" sha256 2>/dev/null)"
	c="$("$OPENSSL" x509 -in "$CRT" -pubkey -noout 2>/dev/null | "$OPENSSL" sha256 2>/dev/null)"
	if [ -z "$k" ] || [ "$k" != "$c" ]; then
		REASON="the key and certificate do not match"
	fi
fi

if [ -z "$REASON" ]; then
	exit 0
fi

HOST="$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo localhost)"
[ -n "$HOST" ] || HOST=localhost

echo "csf: generating a WebUI certificate for this host ($REASON)"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/csf-ui-cert.XXXXXX")" || exit 0
trap 'rm -rf "$TMP"' EXIT INT TERM

# Written as a config file rather than -addext so this works on the older
# openssl still shipped by several supported distributions.
{
	echo "[req]"
	echo "distinguished_name = dn"
	echo "x509_extensions = ext"
	echo "prompt = no"
	echo "[dn]"
	echo "CN = $HOST"
	echo "[ext]"
	echo "basicConstraints = CA:FALSE"
	echo "keyUsage = digitalSignature, keyEncipherment"
	echo "extendedKeyUsage = serverAuth"
	echo "subjectAltName = @alt"
	echo "[alt]"
	echo "DNS.1 = $HOST"
	n=2
	[ "$HOST" != "localhost" ] && { echo "DNS.$n = localhost"; n=$((n+1)); }
	echo "IP.1 = 127.0.0.1"
	i=2
	# Browsers ignore CN and match SAN only, so the addresses an administrator
	# is likely to type belong in here.
	for ip in $(hostname -I 2>/dev/null); do
		case "$ip" in
			*:*) echo "IP.$i = $ip"; i=$((i+1)) ;;
			[0-9]*) echo "IP.$i = $ip"; i=$((i+1)) ;;
		esac
	done
} > "$TMP/cfg"

umask 077
if ! "$OPENSSL" req -new -x509 -nodes -newkey rsa:2048 -sha256 \
	-days "$DAYS" -config "$TMP/cfg" -extensions ext \
	-keyout "$TMP/server.key" -out "$TMP/server.crt" >/dev/null 2>&1; then
	echo "csf: *Error* openssl could not create the certificate."
	echo "csf: the WebUI will not start until this succeeds; do not enable UI = \"1\""
	exit 0
fi

# Move into place only once both halves exist, so a failure here never leaves
# lfd with a key that does not match its certificate.
cp -f "$TMP/server.key" "$KEY" && cp -f "$TMP/server.crt" "$CRT" || {
	echo "csf: *Error* could not write to $UIDIR"
	exit 0
}
chmod 0600 "$KEY"
chmod 0644 "$CRT"

echo "csf: WebUI certificate written to $CRT (valid $DAYS days, this host only)"
echo "csf: fingerprint $(fingerprint "$CRT" | sed 's/../&:/g; s/:$//')"
echo "csf: it is self-signed, so browsers will warn once. Check the fingerprint above."
exit 0
