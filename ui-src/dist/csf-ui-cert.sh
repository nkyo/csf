#!/bin/sh
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
# Added 2026-09-12 in https://github.com/nkyo/csf - see CHANGES.md.
#
# Give the REPLACEMENT WebUI its own certificate, at the path Ruling R29
# (.superpowers/sdd/webui-implementation/progress.md) and
# ConfigServer::UI::Server ($TLS_CERT_FILE/$TLS_KEY_FILE) both name:
# /etc/csf-ui/ssl/{cert,key}.pem.
#
# THIS IS NOT ui-cert.sh. That script, already on main, provisions
# /etc/csf/ui/server.{key,crt} for the OLD built-in webmin-era UI and is
# left exactly as it is until Task 11 retires that UI - R29's whole point
# was that the two must never share a path, so this script is a sibling,
# not an edit. The generation logic below is deliberately the same shape
# (self-signed, host-only, SAN not CN, config-file form for older openssl)
# because that reasoning does not change with the path.
#
#   sh csf-ui-cert.sh            generate if missing, expired, or mismatched
#   sh csf-ui-cert.sh --force    replace whatever is there (rotate)
#
# Installed as /usr/local/csf-ui/bin/../../etc convention note: this file
# itself is NOT one of the four binaries docs/WEBUI-RPC.md S2.3 names under
# /usr/local/csf-ui/bin (t/71-rollback.t enforces that list is exactly
# those four) - it is installer plumbing, called once from
# ui-src/dist/install-webui.sh and not left behind as a re-runnable command
# the way ui-cert.sh is; re-running the installer re-runs this instead.
###############################################################################

SSLDIR="${CSF_UI_SSL_DIR:-/etc/csf-ui/ssl}"
KEY="$SSLDIR/key.pem"
CRT="$SSLDIR/cert.pem"
DAYS="${CSF_UI_CERT_DAYS:-3650}"
UIGROUP="${CSF_UI_GROUP:-csfui}"

FORCE=0
[ "$1" = "--force" ] && FORCE=1

OPENSSL="$(command -v openssl 2>/dev/null)"
if [ -z "$OPENSSL" ]; then
	echo "csf-ui: openssl not found, cannot create a certificate for the WebUI."
	echo "csf-ui: install openssl and re-run: sh ui-src/dist/csf-ui-cert.sh"
	echo "csf-ui: until then, do not set UI_MODE = \"b\" in /etc/csf-ui/ui.conf"
	exit 0
fi

mkdir -p "$SSLDIR" 2>/dev/null

fingerprint() {
	"$OPENSSL" x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null \
		| sed 's/.*=//; s/://g' | tr 'a-f' 'A-F'
}

REASON=""
if [ "$FORCE" -eq 1 ]; then
	REASON="asked to rotate"
elif [ ! -s "$KEY" ] || [ ! -s "$CRT" ]; then
	REASON="no certificate yet"
elif ! "$OPENSSL" x509 -in "$CRT" -noout -checkend 0 >/dev/null 2>&1; then
	REASON="the certificate has expired"
else
	# Key and certificate must still belong together, or Server.pm's TLS
	# wrap fails every connection with no useful error at the socket layer.
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

echo "csf-ui: generating a WebUI certificate for this host ($REASON)"

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
	# Browsers ignore CN and match SAN only, so the addresses an operator is
	# likely to type belong in here.
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
	-keyout "$TMP/key.pem" -out "$TMP/cert.pem" >/dev/null 2>&1; then
	echo "csf-ui: *Error* openssl could not create the certificate."
	echo "csf-ui: the WebUI will not start until this succeeds."
	exit 0
fi

# Move into place only once both halves exist, so a failure here never
# leaves Server.pm with a key that does not match its certificate.
cp -f "$TMP/key.pem" "$KEY" && cp -f "$TMP/cert.pem" "$CRT" || {
	echo "csf-ui: *Error* could not write to $SSLDIR"
	exit 0
}

# docs/WEBUI-RPC.md S2.3's own pattern: the directory is traversable, the
# contents are not, except the certificate itself (public by definition).
# csfui reads KEY directly in mode B (Server.pm terminates TLS itself); in
# mode A a front web server's own worker user reads both - install-webui.sh
# adds that user to the csfui group for exactly this file, rather than
# widening the mode past group-read.
chmod 0750 "$SSLDIR" 2>/dev/null
chmod 0640 "$KEY"
chmod 0644 "$CRT"
if getent group "$UIGROUP" >/dev/null 2>&1; then
	chgrp "$UIGROUP" "$SSLDIR" "$KEY" "$CRT" 2>/dev/null
fi

echo "csf-ui: WebUI certificate written to $CRT (valid $DAYS days, this host only)"
echo "csf-ui: fingerprint $(fingerprint "$CRT" | sed 's/../&:/g; s/:$//')"
echo "csf-ui: it is self-signed, so browsers will warn once. Check the fingerprint above."
exit 0
