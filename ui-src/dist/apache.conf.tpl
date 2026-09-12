##############################################################################
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
##############################################################################
# Added 2026-09-12 in https://github.com/nkyo/csf - see CHANGES.md.
#
# csf WebUI - Mode A front end (Apache httpd 2.4.7+ - fix round 1,
# task-9-review.md I6: the unix:PATH|URL ProxyPass syntax below needs
# 2.4.7, not merely "2.4" - with mod_ssl, mod_proxy, mod_proxy_http and
# mod_authz_core, all part of a standard Apache build).
# Same role as nginx.conf.tpl in this directory: Apache terminates TLS and
# parses HTTP so csf-ui never has to. Rendered by
# ui-src/dist/render-template.sh at install time; every placeholder token is
# resolved then or the render is refused.
#
# Placeholders: @@UI_PORT@@ @@UI_SOCK@@ @@UI_ALLOW_INCLUDE@@
##############################################################################

# Fix round 1 (task-9-review.md Important): an unknown directive, or an
# unknown protocol keyword, is a FATAL Apache config error - not a
# skipped feature, a config Apache refuses to load AT ALL, taking down
# every other site it serves. mod_ssl and mod_proxy_http are load-bearing
# for this vhost (there is no useful way to run it without TLS or the
# proxy, so their own directives are not further guarded beyond this),
# but everything below, INCLUDING `Listen ... https` - the "https"
# protocol keyword is itself registered by mod_ssl - is wrapped so a host
# where either module is missing gets a clean no-op instead of a fatal
# parse error discovered at the operator's next `apachectl -t`.
<IfModule mod_ssl.c>
<IfModule mod_proxy_http.c>
Listen @@UI_PORT@@ https

<VirtualHost *:@@UI_PORT@@>
	SSLEngine on
	SSLCertificateFile    /etc/csf-ui/ssl/cert.pem
	SSLCertificateKeyFile /etc/csf-ui/ssl/key.pem
	SSLProtocol -all +TLSv1.2 +TLSv1.3
	SSLHonorCipherOrder on

	ErrorLog  /var/log/csf-ui-apache-error.log
	CustomLog /var/log/csf-ui-apache-access.log combined

	# docs/WEBUI-RPC.md S3.1/S14.1: matches the 65536-byte wire/body cap on
	# the csf-ui side of the socket, so an oversized request is refused at
	# the edge rather than after Apache has already buffered it.
	# LimitRequestFields matches ConfigServer::UI::HTTP's own $MAX_HEADERS
	# (64) exactly, for the same reason the body figure matches the wire
	# cap - fix round 1 found this had drifted to 100.
	LimitRequestBody 65536
	LimitRequestFieldSize 8190
	LimitRequestFields 64
	TimeOut 30

	# docs/WEBUI-RPC.md S10: UI_ALLOW is enforced HERE in mode A, never by
	# csf-ui itself - wrapped in RequireAny so the generated, never-empty
	# list of "Require ip ..." lines is an explicit OR, not dependent on
	# Apache's own default merge behaviour for bare Require directives.
	# mod_authz_core (RequireAny/Require) is core Apache 2.4+, not guarded.
	<Location "/">
		<RequireAny>
			Include @@UI_ALLOW_INCLUDE@@
		</RequireAny>
	</Location>

	ProxyPreserveHost On
	ProxyPass        "/" "unix:@@UI_SOCK@@|http://csf-ui/" connectiontimeout=5 timeout=30
	ProxyPassReverse "/" "unix:@@UI_SOCK@@|http://csf-ui/"

	# The address ConfigServer::UI::RateLimit keys on and csf-ui's own
	# access log records (docs/WEBUI-RPC.md S14.1: "must be per-connecting-
	# client, never a constant"). Apache's %{REMOTE_ADDR}s is its own view
	# of the connecting peer, set unconditionally - a client-supplied
	# X-Real-IP is overwritten, never trusted through, for the same reason
	# S10 gives for UI_ALLOW and X-Forwarded-For.
	#
	# Fix round 1 (task-9-review.md Important): mod_headers is common but
	# NOT guaranteed enabled, and RequestHeader is exactly the kind of
	# unknown directive that is fatal to Apache's whole config, not just
	# this vhost - guarded so a host without it gets this one header
	# silently absent (RateLimit.pm then sees no X-Real-IP for this
	# request) rather than Apache refusing to start at all.
	<IfModule mod_headers.c>
		RequestHeader set X-Real-IP "%{REMOTE_ADDR}s"
	</IfModule>
</VirtualHost>
</IfModule>
</IfModule>
