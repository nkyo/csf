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
# csf WebUI - Mode A front end (nginx). docs/WEBUI-PLAN.md S4: nginx
# terminates TLS and parses HTTP from the network so csf-ui never has to -
# that is the entire reason Mode A is the default where a web server is
# already present. Rendered by ui-src/dist/render-template.sh at install
# time (ui-src/dist/install-webui.sh); every placeholder token below is filled in
# then, and the installer refuses to leave one unresolved (render-
# template.sh exits 1 rather than write a config with a literal token in
# it).
#
# Placeholders: @@UI_PORT@@ @@UI_SOCK@@ @@UI_ALLOW_INCLUDE@@
##############################################################################

server {
	listen @@UI_PORT@@ ssl;
	listen [::]:@@UI_PORT@@ ssl;
	server_name _;

	ssl_certificate     /etc/csf-ui/ssl/cert.pem;
	ssl_certificate_key /etc/csf-ui/ssl/key.pem;
	ssl_protocols TLSv1.2 TLSv1.3;
	ssl_prefer_server_ciphers on;

	access_log /var/log/csf-ui-nginx-access.log;
	error_log  /var/log/csf-ui-nginx-error.log;

	# docs/WEBUI-RPC.md S10: UI_ALLOW is NOT enforced by csf-ui in mode A -
	# csf-ui's own listener sees only this front server as its peer, so the
	# allowlist has to be enforced here instead. The generated file this
	# includes is never empty: the installer refuses to render this vhost
	# at all while UI_ALLOW is empty, the same refusal ui.conf itself
	# applies (S10: "empty or missing, in both modes").
	include @@UI_ALLOW_INCLUDE@@;
	deny all;

	# docs/WEBUI-RPC.md S3.1/S14.1: 65536 bytes is the wire-line and body
	# cap on the csf-ui side of the socket too. Matched here, not derived
	# from it, so an oversized request is rejected at the edge instead of
	# after nginx has already buffered it for csf-ui to reject a second
	# time.
	client_max_body_size 64k;
	large_client_header_buffers 4 8k;

	# This tier implements no keep-alive at all past the proxied
	# connection itself (docs/WEBUI-RPC.md S13/S14.4) - short, fixed
	# timeouts rather than nginx's generous defaults.
	client_body_timeout 15s;
	client_header_timeout 15s;
	send_timeout 30s;

	location / {
		proxy_pass http://unix:@@UI_SOCK@@:;
		proxy_http_version 1.1;
		proxy_set_header Connection "";
		proxy_set_header Host $host;

		# The address ConfigServer::UI::RateLimit keys on and csf-ui's own
		# access log records (docs/WEBUI-RPC.md S14.1: "must be per-
		# connecting-client, never a constant"). nginx sets this
		# unconditionally, so a client-supplied X-Real-IP never reaches
		# csf-ui as if it were nginx's own - the same rule S10 already
		# gives for UI_ALLOW and X-Forwarded-For, applied here because the
		# adapter that fills in `peer` is the one place it actually
		# matters.
		proxy_set_header X-Real-IP $remote_addr;

		# proxy_read_timeout IS NOT A FREE CHOICE (fix round 2, R106). It
		# is the deadline on csf-ui's whole response, and csf-ui arms a
		# request budget of its own over exactly the same span - 75s:
		# ConfigServer::UI::HTTP's header (15) + body (15) + write (5)
		# plus the dispatch term F1 added (4 helper calls x
		# ConfigServer::UI::Client's 10s). At 30s this number was SMALLER
		# than that budget, so a request csf-ui served correctly at 44s
		# became a 504 here and the administrator never saw it - measured:
		# 504 Gateway Time-out at 30.03s against a dispatch of 44s, 200 OK
		# at 44.00s once this line read 80s.
		#
		# The rule is that CSF-UI's watchdog gives up first, never this
		# one: this deadline only knows nothing has arrived yet, while the
		# watchdog knows what it was bounding. So the value is csf-ui's
		# budget plus a small margin, and it is not maintained by hand -
		# ConfigServer::UI::Server::front_server_read_timeout() derives it,
		# and t/80-templates.t asserts this file, apache.conf.tpl and
		# litespeed.conf.tpl all carry exactly that, so none of the four
		# numbers can move on its own.
		#
		# Only the BACKEND read deadline moves. proxy_send_timeout is the
		# write of an already-buffered request into a local unix socket,
		# and the client-facing client_header_timeout/client_body_timeout/
		# send_timeout above bound a human's connection, not csf-ui's work.
		proxy_connect_timeout 5s;
		proxy_read_timeout 80s;
		proxy_send_timeout 30s;
	}
}
