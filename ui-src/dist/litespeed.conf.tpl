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
# csf WebUI - Mode A front end (LiteSpeed / OpenLiteSpeed, native config
# syntax - this is NOT an Apache-compatible vhost include). Same role as
# nginx.conf.tpl and apache.conf.tpl in this directory: LiteSpeed
# terminates TLS and parses HTTP so csf-ui never has to. Rendered by
# ui-src/dist/render-template.sh at install time; every placeholder token is
# resolved then or the render is refused.
#
# Meant to be dropped where the detected LiteSpeed/OpenLiteSpeed install
# reads extra vhost config from (commonly
# /usr/local/lsws/conf/vhosts/csf-ui/vhconf.conf, referenced by a `vhost`
# stanza in the main httpd_config.conf) - install-webui.sh writes it there
# and prints the one line of main-config wiring LiteSpeed's own admin
# console would otherwise ask for, rather than editing httpd_config.conf
# itself sight-unseen.
#
# Placeholders: @@UI_PORT@@ @@UI_SOCK@@ @@UI_ALLOW_INCLUDE@@
##############################################################################

docRoot                   /usr/local/lsws/Example/html
vhDomain                  *
adminEmails               root@localhost
enableGzip                0

extprocessor csfui {
	type                    proxy
	address                 UDS://@@UI_SOCK@@
	maxConns                35
	pcKeepAliveTimeout      15
	# initTimeout IS NOT A FREE CHOICE (fix round 2, R106) - it is
	# LiteSpeed's deadline on the first response from this external
	# application, the same deadline nginx spells proxy_read_timeout and
	# Apache spells ProxyPass timeout=. csf-ui arms a request budget of
	# its own over the same span - 75s: ConfigServer::UI::HTTP's header
	# (15) + body (15) + write (5) plus the dispatch term F1 added (4
	# helper calls x ConfigServer::UI::Client's 10s) - so at 30 this
	# number was SMALLER than the budget and a request csf-ui served
	# correctly at 44s would have been abandoned here, with the
	# administrator never seeing it. Measured on nginx and Apache, whose
	# equivalents both did exactly that (504 and 502 at 30.03s); this
	# server's own reproduction is not available in this workspace, which
	# is why the value is derived from the same authority rather than
	# tuned by observation here.
	#
	# Not maintained by hand:
	# ConfigServer::UI::Server::front_server_read_timeout() derives it, and
	# t/80-templates.t asserts this file, nginx.conf.tpl and
	# apache.conf.tpl all carry exactly that, so none of the numbers can
	# move on its own.
	initTimeout             80
	retryTimeout            0
	respBuffer              0
}

context / {
	type                    proxy
	handler                 csfui
	addDefaultCharset       off

	# The address ConfigServer::UI::RateLimit keys on and csf-ui's own
	# access log records (docs/WEBUI-RPC.md S14.1: "must be per-connecting-
	# client, never a constant"). LiteSpeed sets this from its own view of
	# the connecting peer - a client-supplied X-Real-IP is overwritten,
	# never trusted through, for the same reason S10 gives for UI_ALLOW
	# and X-Forwarded-For.
	extraHeaders            X-Real-IP %{REMOTE_ADDR}
}

# Fix round 1 (task-9-review.md C3): a bare top-level `include` of
# "allow ..." lines is not itself an ACL in LiteSpeed's native config -
# with no accessControl wrapper and no default deny, LiteSpeed simply had
# no restriction to apply, so the vhost shipped reachable from anywhere
# while this file's own (now former) comment described it as enforced.
# docs/WEBUI-RPC.md S10: UI_ALLOW is enforced HERE in mode A, never by
# csf-ui itself, and the generated file this includes is never empty - the
# installer refuses to render this vhost at all while UI_ALLOW is empty.
# `deny ALL` is the default-deny; LiteSpeed resolves an address that
# matches both an allow and a deny entry by longest-prefix match, so each
# specific `allow` line generated into the include below still wins over
# this catch-all.
accessControl  {
	include @@UI_ALLOW_INCLUDE@@
	deny                    ALL
}

vhssl {
	keyFile                 /etc/csf-ui/ssl/key.pem
	certFile                /etc/csf-ui/ssl/cert.pem
	sslProtocol             24
}

# docs/WEBUI-RPC.md S3.1/S14.1: matches the 65536-byte wire/body cap on
# the csf-ui side of the socket. LiteSpeed's own per-context body limit,
# maxReqBodySize, is NOT set by this file - it lives at the
# listener/vhost-map level in httpd_config.conf, which this vhost include
# does not control. install-webui.sh's printed instructions (fix round 1:
# this used to claim the note already did this, and it did not) tell the
# operator to set it there, next to the listener/map entry LiteSpeed's own
# admin console needs anyway.
