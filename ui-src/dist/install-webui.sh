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
# install-webui.sh - packages and, optionally, configures the replacement
# WebUI (docs/WEBUI-RPC.md, docs/WEBUI-PLAN.md). Called once from the end
# of every install.*.sh, always as a SEPARATE `sh` process whose exit
# status the caller does not check:
#
#   sh ui-src/dist/install-webui.sh
#
# task-9-brief.md states two rules that shape every line below:
#
#   1. "A failure to set up the UI must not fail the install" - the
#      firewall matters more than its optional UI. Every hard problem
#      here is printed and this script still exits 0; the caller neither
#      checks nor should check its exit status.
#   2. "A non-interactive install enables neither mode." Account,
#      directory tree, binaries, TLS material and (on systemd hosts) the
#      unit files are always installed - that is packaging, not turning
#      anything on. Only writing /etc/csf-ui/ui.conf and enabling a unit
#      counts as "on", and both are skipped unless this is running at an
#      actual terminal (checked with [ -t 0 ]/[ -t 1 ], the same signal
#      every other "am I interactive" test in a POSIX shell uses - a
#      curl-pipe install, cron, CI, or an unattended provisioner all fail
#      this and get neither mode, exactly as required).
#
# Everything this script touches lives OUTSIDE /etc/csf, /var/lib/csf and
# /usr/local/csf on purpose (Ruling R11; docs/WEBUI-RPC.md S13): those
# three trees are reset to 0600 on every pass of lfd's main loop
# (lfd.pl:1173,1187-1201), forever, and a 0600 DIRECTORY is impassable
# even to its own owner (S13.2) - csfui is the one account that would
# ever be stopped by that, and it does not exist until this script runs.
###############################################################################

DIST_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd) || {
	echo "csf-ui: cannot resolve my own directory - skipping WebUI setup"
	exit 0
}
UI_SRC="$DIST_DIR/.."

###############################################################################
# create_account - the csfui system account (task-9-brief.md: "no login
# shell, no home"). Idempotent: re-running the installer on an upgrade
# must not fail because the account already exists.
#
# Fix round 2 (task-9-review.md R90): also creates csf-ui-sock, a SECOND,
# dedicated group with no relationship to csfui. csfui gates
# /etc/csf-ui/ui.conf, the TLS key and (via S2.3) /var/run/csf-ui/
# helper.sock - reusing it for anything a front-server worker account
# might join is exactly the R(I5) mistake fix round 1 already found and
# removed once. csf-ui-sock exists for exactly one purpose: letting a
# front server's worker traverse csf-ui.service's own RuntimeDirectory
# (see csf-ui.service and setup_mode_a(), below) to reach the Mode A
# socket ConfigServer::UI::Server binds inside it, and nothing else is
# ever gated by it. That group is ALSO what the listener derives its
# accepted-peer set from (Server.pm's unix_peer_uids(), which reads the
# membership of whichever group owns the socket): a worker account this
# function does not add is one the listener will refuse, so the grant
# below and that check are two halves of one decision.
###############################################################################
create_account() {
	if ! getent group csfui >/dev/null 2>&1; then
		groupadd -r csfui 2>/dev/null || groupadd csfui 2>/dev/null || {
			echo "csf-ui: could not create the 'csfui' group - skipping WebUI setup"
			return 1
		}
	fi

	if ! getent group csf-ui-sock >/dev/null 2>&1; then
		groupadd -r csf-ui-sock 2>/dev/null || groupadd csf-ui-sock 2>/dev/null || {
			echo "csf-ui: could not create the 'csf-ui-sock' group - skipping WebUI setup"
			return 1
		}
	fi

	if ! getent passwd csfui >/dev/null 2>&1; then
		nologin=""
		for candidate in /usr/sbin/nologin /sbin/nologin /bin/false; do
			[ -x "$candidate" ] && { nologin=$candidate; break; }
		done
		[ -n "$nologin" ] || nologin=/bin/false

		useradd -r -M -g csfui -G csf-ui-sock -d /nonexistent -s "$nologin" -c "csf WebUI" csfui 2>/dev/null || {
			echo "csf-ui: could not create the 'csfui' user - skipping WebUI setup"
			return 1
		}
	fi

	return 0
}

###############################################################################
# setup_directories - docs/WEBUI-RPC.md S2.3, verbatim, for every path this
# task owns. /etc/csf-ui/users is deliberately NOT created here - that
# file belongs to csf-ui-passwd (Task 3), and an installer that touched it
# could stomp an existing credential store on an upgrade.
###############################################################################
setup_directories() {
	install -d -m 0755 -o root  -g root  /usr/local/csf-ui
	install -d -m 0755 -o root  -g root  /usr/local/csf-ui/bin
	install -d -m 0755 -o root  -g root  /usr/local/csf-ui/lib
	install -d -m 0755 -o root  -g root  /usr/local/csf-ui/lib/ConfigServer
	install -d -m 0755 -o root  -g root  /usr/local/csf-ui/lib/ConfigServer/UI
	install -d -m 0755 -o root  -g root  /usr/local/csf-ui/web
	install -d -m 0755 -o root  -g root  /usr/local/csf-ui/web/screens

	install -d -m 0750 -o root  -g csfui /etc/csf-ui
	install -d -m 0750 -o root  -g csfui /etc/csf-ui/ssl

	install -d -m 0755 -o root  -g root  /var/lib/csf-ui
	install -d -m 0700 -o root  -g root  /var/lib/csf-ui/helper
	install -d -m 0700 -o csfui -g csfui /var/lib/csf-ui/sessions
	install -d -m 0700 -o csfui -g csfui /var/lib/csf-ui/rl

	# S2.3: "it must be traversable by csfui or the socket is unreachable".
	# The helper re-validates and, if necessary, recreates this on every
	# start (docs/WEBUI-RPC.md S2) - many distributions clear /var/run on
	# boot - so this is a convenience for the time between install and
	# first start, not the only thing standing it up.
	install -d -m 0755 -o root -g root /var/run/csf-ui

	[ -f /var/log/csf-ui-audit.log ] || : > /var/log/csf-ui-audit.log
	chown root:root /var/log/csf-ui-audit.log
	chmod 0640 /var/log/csf-ui-audit.log

	[ -f /var/log/csf-ui-access.log ] || : > /var/log/csf-ui-access.log
	chown csfui:csfui /var/log/csf-ui-access.log
	chmod 0640 /var/log/csf-ui-access.log
}

###############################################################################
# install_files - copies DIRECTORIES, never an enumerated file list
# (task-9-brief.md: "a hardcoded filename list would break" once Task 11
# retires assets), then sets the exact per-file modes docs/WEBUI-RPC.md
# S2.3 requires. The four binaries are named explicitly here only to set
# their mode tighter than the directory's - t/71-rollback.t is the
# guarantee that this list can never silently grow a fifth name.
###############################################################################
install_files() {
	cp -a "$UI_SRC/bin/." /usr/local/csf-ui/bin/
	cp -a "$UI_SRC/lib/ConfigServer/UI/." /usr/local/csf-ui/lib/ConfigServer/UI/
	cp -a "$UI_SRC/web/." /usr/local/csf-ui/web/

	chown -R root:root /usr/local/csf-ui
	find /usr/local/csf-ui -type d -exec chmod 0755 {} \;
	find /usr/local/csf-ui/lib -type f -exec chmod 0644 {} \;
	find /usr/local/csf-ui/web -type f -exec chmod 0644 {} \;
	find /usr/local/csf-ui/bin -type f -exec chmod 0644 {} \;

	for bin in csf-ui csf-ui-helper csf-ui-passwd csf-ui-setup; do
		if [ -f "/usr/local/csf-ui/bin/$bin" ]; then
			chown root:csfui "/usr/local/csf-ui/bin/$bin"
			chmod 0750 "/usr/local/csf-ui/bin/$bin"
		else
			echo "csf-ui: *Error* /usr/local/csf-ui/bin/$bin did not install - the WebUI will not run"
		fi
	done
}

###############################################################################
# install_units - copies the two systemd units into place and reloads the
# daemon. Never enables or starts either unit itself: that only happens
# once a mode has actually been configured (setup_mode_a/setup_mode_b,
# below), which an unattended run never reaches.
###############################################################################
install_units() {
	if [ "$(cat /proc/1/comm 2>/dev/null)" != "systemd" ]; then
		echo "csf-ui: this host is not running systemd - the WebUI units were not installed"
		echo "csf-ui: (the account, files and TLS material above are still in place)"
		return 1
	fi

	mkdir -p /usr/lib/systemd/system/ 2>/dev/null
	cp -avf "$DIST_DIR/csf-ui.service" /usr/lib/systemd/system/ >/dev/null
	cp -avf "$DIST_DIR/csf-ui-helper.service" /usr/lib/systemd/system/ >/dev/null
	chown root:root /usr/lib/systemd/system/csf-ui.service /usr/lib/systemd/system/csf-ui-helper.service
	chmod 0644 /usr/lib/systemd/system/csf-ui.service /usr/lib/systemd/system/csf-ui-helper.service
	systemctl daemon-reload 2>/dev/null
	return 0
}

###############################################################################
# detect_frontend - nginx, apache or litespeed, in that preference order,
# or nothing. docs/WEBUI-PLAN.md S4: Mode A is "the default when found".
#
# Fix round 2 (task-9-review.md, lower-priority findings): the `-d
# /etc/nginx`/`-d /etc/httpd`/`-d /etc/apache2` fallbacks are removed. A
# leftover config directory from an uninstalled package is not evidence
# the server is actually present - it would win Mode A over a correctly-
# detected other front end, or over no front end at all, and the vhost
# then lands in a directory nothing ever reads. The executable actually
# being findable (or, for LiteSpeed, its own control binary) is the
# strong signal; a config directory alone is not.
###############################################################################
detect_frontend() {
	if command -v nginx >/dev/null 2>&1; then
		echo nginx
	elif command -v httpd >/dev/null 2>&1 || command -v apache2 >/dev/null 2>&1; then
		echo apache
	elif [ -x /usr/local/lsws/bin/lswsctrl ] || [ -x /usr/local/lsws/bin/litespeed ]; then
		echo litespeed
	fi
}

###############################################################################
# guess_admin_ip - the same signal docs/WEBUI-PLAN.md S6 uses for the same
# reason: on THIS install run, it is the one address verifiably an
# operator's, not a guess, because it is where the current shell's own
# connection came from.
###############################################################################
guess_admin_ip() {
	raw=""
	if [ -n "$SSH_CLIENT" ]; then
		raw=$(echo "$SSH_CLIENT" | awk '{print $1}')
	elif [ -n "$SSH_CONNECTION" ]; then
		raw=$(echo "$SSH_CONNECTION" | awk '{print $1}')
	fi
	# Loose shape check only - docs/WEBUI-RPC.md S4.1's own
	# Socket::inet_pton gate is the real validator, applied when csf-ui
	# itself reads ui.conf; a value that fails it here is simply dropped
	# rather than written into a config guaranteed to then refuse to
	# start.
	case "$raw" in
		*:*|*.*.*.*) echo "$raw" ;;
		*) : ;;
	esac
}

###############################################################################
# apache_confd - where a config file this project drops actually gets
# read from, which differs by distribution family.
###############################################################################
apache_confd() {
	if [ -d /etc/apache2/conf-available ]; then
		echo /etc/apache2/conf-available
	else
		echo /etc/httpd/conf.d
	fi
}

# Fix round 1 (task-9-review.md Important): a grant_frontend_group()
# function used to live here, adding nginx/Apache/LiteSpeed's own worker
# account to group csfui "so it can read the TLS key". Removed outright,
# not narrowed, because the premise was wrong, not merely too broad: all
# three of these servers open ssl_certificate_key from their ROOT-run
# master/admin process at config-load time (nginx and Apache fork workers
# AFTER the master has already parsed the SSL context; LiteSpeed's own
# admin process does the equivalent) - the unprivileged WORKER account
# this function targeted never opens /etc/csf-ui/ssl/key.pem itself in
# the ordinary case, so there was nothing here for the grant to fix.
#
# What it actually did was worse than a no-op: group csfui is also the
# group /var/run/csf-ui/helper.sock is served at (docs/WEBUI-RPC.md
# S2.3 - the frozen table this project's own trust-boundary design
# (S1.2) depends on). Adding www-data (or any shared web-serving account -
# often the SAME account other, untrusted sites on the same host run as)
# to that group gives it socket-permission access to the ROOT-privileged
# helper - past the file mode, though NOT past the helper's own S2.2 peer
# check (SO_PEERCRED's uid compared against csfui's, `E_PEER` otherwise),
# which is a second, independent gate this grant did not open and closes
# the connection before a single byte is read. Fail-closed, so this was a
# standing widening bought for a benefit that never existed, not a
# working bypass of the split S1.2 describes - correcting the premise is
# still worth doing on its own, without overstating what was actually at
# risk.
#
# Fix round 2 (task-9-review.md R90) resolves the question the comment
# above left open: Mode A cannot work even once a listener exists if
# nothing can traverse csf-ui.service's own RuntimeDirectory
# (/run/csf-ui-web, 0750) to reach the socket inside it. The fix is NOT
# to reuse csfui (that is the exact mistake just removed above) - it is
# a second, dedicated group, csf-ui-sock, that gates ONLY this directory
# and nothing csfui also gates (not ui.conf, not the TLS key, not
# helper.sock). create_account() creates it; csf-ui.service's
# RuntimeDirectory is now owned by it (not csfui); this function grants
# it to the detected front server's own worker account.
###############################################################################
grant_socket_group() {
	front=$1
	case "$front" in
		nginx)     candidates="nginx www-data" ;;
		apache)    candidates="apache www-data" ;;
		litespeed) candidates="nobody lsadm" ;;
		*)         candidates="" ;;
	esac
	for u in $candidates; do
		if getent passwd "$u" >/dev/null 2>&1; then
			usermod -aG csf-ui-sock "$u" 2>/dev/null \
				&& echo "csf-ui: added '$u' to group csf-ui-sock (so $front can reach the Mode A socket ConfigServer::UI::Server binds there - this group gates nothing else)"
		fi
	done
}

###############################################################################
# write_allow_include - docs/WEBUI-RPC.md S10: "UI_ALLOW in mode A is not
# enforced by csf-ui... the value is what Task 9 renders into the
# nginx/Apache/LiteSpeed template, and it must still be non-empty so that
# no template is ever generated wide open." $2 is always non-empty by the
# time this is called - the callers below never invoke it otherwise.
###############################################################################
###############################################################################
# write_allow_include FRONT CSV DEST - fix round 2: DEST, not `out`, is
# deliberate. POSIX sh has no `local`; this function used to write
# `out=$3`, and setup_mode_a() ALSO uses a variable named `out` for the
# vhost path it renders to and tests - fix round 2 reordered that
# function's own calls (validate, then render, then test) and the two
# `out`s collided, silently overwriting the vhost's own destination with
# this function's, mid-run. Caught by actually running setup_mode_a() end
# to end (see the task report) rather than by inspection - a call-order
# assumption is not a contract, and every global name shared between a
# function and its caller is a latent version of this exact bug.
###############################################################################
write_allow_include() {
	front=$1
	allow_csv=$2
	dest=$3

	tmp="$dest.new.$$"
	{
		echo "# Generated by install-webui.sh from UI_ALLOW - docs/WEBUI-RPC.md S10."
		echo "# csf-ui does not enforce UI_ALLOW itself in Mode A; this front server"
		echo "# does. Regenerate with csf-ui-setup rather than hand-editing this file."
		old_ifs=$IFS
		IFS=,
		for entry in $allow_csv; do
			IFS=$old_ifs
			entry=$(printf '%s' "$entry" | sed 's/^[ \t]*//; s/[ \t]*$//')
			if [ -n "$entry" ]; then
				case "$front" in
					nginx)     echo "allow $entry;" ;;
					apache)    echo "Require ip $entry" ;;
					litespeed) echo "allow                   $entry" ;;
				esac
			fi
			IFS=,
		done
		IFS=$old_ifs
	} > "$tmp"
	chmod 0644 "$tmp"
	mv "$tmp" "$dest"
}

###############################################################################
# write_ui_conf - docs/WEBUI-RPC.md S10's grammar and key set, verbatim.
# UI_CRYPT_ROUNDS/UI_SESSION_IDLE/UI_SESSION_MAX are left unset
# deliberately: S10's own defaults (100000/1800/43200) apply to an absent
# key, and this installer has no better answer for any of the three than
# the ones already frozen there.
###############################################################################
write_ui_conf() {
	# Fix round 3 (task-9-review.md, sibling check on the write_allow_include
	# `out` collision fix round 2 found by actually running the code):
	# ui_mode, not `mode` - interactive_setup() (the only caller, alongside
	# setup_mode_a()/setup_mode_b() which pass a literal "a"/"b") has its
	# own global named `mode` for the a/b choice it read from the operator.
	# Both currently only ever get reassigned to a value already equal to
	# what they held, so this was inert, not a live bug like out=$3 was -
	# renamed anyway, on the same "every shared name is a latent version of
	# that bug" reasoning fix round 2 recorded.
	ui_mode=$1
	port=$2
	allow=$3

	tmp="/etc/csf-ui/.ui.conf.new.$$"
	{
		printf '# /etc/csf-ui/ui.conf - written by the csf installer, %s\n' "$(date '+%Y-%m-%d')"
		printf '# docs/WEBUI-RPC.md S10 is the frozen grammar and key list.\n'
		printf 'UI_MODE="%s"\n' "$ui_mode"
		printf 'UI_PORT="%s"\n' "$port"
		printf 'UI_ALLOW="%s"\n' "$allow"
	} > "$tmp"
	chown root:csfui "$tmp"
	chmod 0640 "$tmp"
	mv "$tmp" /etc/csf-ui/ui.conf
}

###############################################################################
# validate_ui_allow CSV - fix round 2 (task-9-review.md R87): "UI_ALLOW is
# still unvalidated and goes verbatim into the config. 'not-an-ip' breaks
# every site on the box. 0.0.0.0/0 produces exactly the wide-open template
# S10 forbids."
#
# Deliberately NOT a reimplementation of docs/WEBUI-RPC.md S4.1's full
# grammar (host-bit checks, IPv4-mapped rejection, the exact canonical
# form) - that validator already exists, in Perl, as the authority
# (ConfigServer::UI::Proto::ip_info, reached through Server::
# read_ui_conf), and reproducing it here in POSIX sh risks the two
# disagreeing with each other, silently, on some future edge case. What
# this catches, cheaply, before either a front server or csf-ui itself
# ever sees the value: an entry with no plausible address shape at all
# (review's "not-an-ip"), and a bare /0 mask - S10's own "prefix floor
# does not apply; /0 still rejected" - which is the one rule a syntax
# validator downstream would never object to, because /0 is perfectly
# valid CIDR syntax for "everyone".
#
# Prints nothing and returns 0 on success. On the first bad entry, prints
# why and returns 1 - every caller must refuse to render or write
# anything when this fails.
###############################################################################
validate_ui_allow() {
	allow_csv=$1

	if [ -z "$allow_csv" ]; then
		echo "csf-ui: UI_ALLOW is empty - refusing (docs/WEBUI-RPC.md S10: empty means \"nobody\", never \"everybody\")"
		return 1
	fi

	old_ifs=$IFS
	IFS=,
	for entry in $allow_csv; do
		IFS=$old_ifs
		entry=$(printf '%s' "$entry" | sed 's/^[ \t]*//; s/[ \t]*$//')
		if [ -z "$entry" ]; then
			IFS=,
			continue
		fi

		case "$entry" in
			*/0)
				echo "csf-ui: UI_ALLOW entry '$entry' is rejected - a /0 mask means \"the Internet\" (docs/WEBUI-RPC.md S10/S4.1), never an allowlist entry"
				IFS=$old_ifs
				return 1
				;;
		esac

		case "$entry" in
			[0-9]*.[0-9]*.[0-9]*.[0-9]*)
				: # plausible IPv4[/prefix] shape (Socket::inet_pton is the real judge)
				;;
			*:*)
				: # plausible IPv6[/prefix] shape (contains a colon)
				;;
			*)
				echo "csf-ui: UI_ALLOW entry '$entry' does not look like an IPv4 or IPv6 address/CIDR - refusing rather than writing it into a config a front server will parse"
				IFS=$old_ifs
				return 1
				;;
		esac
		IFS=,
	done
	IFS=$old_ifs
	return 0
}

###############################################################################
# apache_check_modules - fix round 2 (task-9-review.md R87/R88): "Stock
# Debian and Ubuntu ship mod_ssl, mod_proxy_http and mod_headers
# DISABLED... your <IfModule>-wrapped vhost is wholly inert" and "your
# <IfModule> fix turned a fatal error into a silent no-op". configtest
# alone cannot catch this - <IfModule> is specifically designed to make a
# missing module a clean parse, not an error - so the modules actually
# loaded have to be checked directly, not inferred from configtest's exit
# code.
#
# Fix round 3 (task-9-review.md R93): this used to also RUN `a2enmod`
# itself, silently, before checking - "unannounced, and never reverted".
# Enabling mod_ssl activates `Listen 443` through Debian's own
# ports.conf regardless of anything this vhost does - a firewall
# installer changing the operator's server exposure without asking is
# exactly backwards. This function is now a PURE CHECK with no side
# effects; enabling modules is a separate, explicit, asked-first step
# (apache_enable_modules(), below), called only from setup_mode_a()
# after the operator agrees.
#
# Fix round 5 (task-9-review.md R97): "give apache_check_modules() a
# third state: could not ask." `apache2ctl -M` (and its fallbacks) does
# not report "modules are unknown" when Apache's config fails to parse -
# it reports EVERY module as missing, indistinguishably from a host that
# genuinely has none of them enabled. That is exactly the condition the
# baseline in setup_mode_a() exists to tolerate (R94/R95), and until this
# round nothing here could tell "definitely missing" apart from "the
# instrument is blind right now" - review's own comparison:
# "the same defect as the firewall-cmd --state fallthrough one task
# over, where 'cannot reach the daemon' came back as a confident
# iptables-nft." A pre-existing, unrelated Apache config error therefore
# made this function claim ALL THREE modules were missing, forcing the
# consent path into a decision it had no real basis for and permanently
# blocking Apache's own self-heal - the two sub-findings review reproduced
# alongside R96.
#
# Exit 0: the check succeeded (Apache's config parses far enough for its
#         own module-listing command to run). Missing module names
#         (space-separated, possibly empty) are on stdout.
# Exit 1: COULD NOT ASK - the module-listing command itself failed, on
#         every candidate binary tried. Nothing is printed on stdout.
#         Callers MUST treat this as "unknown", never as "none missing"
#         (which would silently skip a genuinely-needed module) or as
#         "all missing" (which is what the blind instrument itself would
#         have guessed, and exactly the wrong answer this exists to
#         replace).
###############################################################################
apache_check_modules() {
	if command -v apache2ctl >/dev/null 2>&1; then
		loaded=$(apache2ctl -M 2>/dev/null)
		check_rc=$?
	elif command -v httpd >/dev/null 2>&1; then
		loaded=$(httpd -M 2>/dev/null)
		check_rc=$?
	elif command -v apachectl >/dev/null 2>&1; then
		loaded=$(apachectl -M 2>/dev/null)
		check_rc=$?
	else
		return 1
	fi

	if [ "$check_rc" -ne 0 ]; then
		return 1
	fi

	missing=""
	for mod in ssl_module proxy_http_module headers_module; do
		case "$loaded" in
			*"$mod"*) : ;;
			*) missing="$missing $mod" ;;
		esac
	done
	printf '%s' "$missing" | sed 's/^ //'
	return 0
}

###############################################################################
# apache_enable_modules NAMES - the one place a2enmod is ever invoked
# (fix round 3, R93). NAMES is a space-separated list of *_module names
# with the _module suffix already stripped (a2enmod's own naming) - the
# caller builds this from apache_check_modules()'s output and asks the
# operator before this function is ever reached.
#
# Fix round 5 (task-9-review.md R96): returns a2enmod's OWN exit status
# (the implicit return value of this function's last command) rather
# than leaving the caller to re-ask the same blind apache2ctl -M
# instrument this round's R97 fix exists to stop trusting. Round 4's
# version had the caller re-run apache_check_modules() after this to
# "confirm" it worked - on a host whose config does not parse for an
# unrelated reason, that re-check reported every module missing again,
# `enabled_now` never got set, and setup_mode_a() printed "not enabling
# Apache modules without confirmation" and returned - AFTER a2enmod had
# already run and changed the host's exposure. Trusting a2enmod's own
# exit code is both simpler and correct: it is not the blind instrument,
# it is the tool doing the enabling.
###############################################################################
apache_enable_modules() {
	names=$1
	command -v a2enmod >/dev/null 2>&1 || return 1
	a2enmod $names >/dev/null 2>&1
}

###############################################################################
# apache_disable_modules NAMES - fix round 4 (task-9-review.md R95): the
# other half apache_enable_modules() was missing. "Modules enabled by the
# new consent prompt are never reverted... A failed Mode A leaves Listen
# 443 active with nothing configured and nothing said." Called only from
# setup_mode_a()'s rollback path, and only with the exact names THIS RUN
# enabled (tracked in $modules_enabled_this_run, not re-derived from
# whatever apache_check_modules() reports at rollback time) - modules
# that were already enabled before this run touched anything are never
# named here and never disabled.
###############################################################################
apache_disable_modules() {
	names=$1
	command -v a2dismod >/dev/null 2>&1 || return 1
	a2dismod $names >/dev/null 2>&1
}

###############################################################################
# MODULES_RECORD - fix round 5 (task-9-review.md R98): "Everything up to
# the consent prompt is now reversible by doing nothing... but from
# a2enmod onward nothing ever reverts the enable, because the record is
# a shell variable that no later run can reconstruct. A crash, a SIGKILL
# or a Ctrl-C there leaves modules enabled forever with nothing knowing
# they were ours. Persist what this run enabled BEFORE enabling it."
#
# record_modules_enabled() is called before apache_enable_modules(), not
# after - the whole point is surviving a death between the two.
# clear_modules_enabled_record() is called once this run reaches a
# definite outcome of its own (success, or a rollback that already
# disabled what this run enabled) - the file is not a permanent audit
# log, only a dead-man's note for a run that never got to finish this
# sentence itself. verify_install() (below) checks for a leftover file
# from a run that died before clearing it.
###############################################################################
MODULES_RECORD=/var/lib/csf-ui/apache-modules-enabled-by-installer

record_modules_enabled() {
	names=$1
	tmp="$MODULES_RECORD.new.$$"
	{
		echo "# Written by install-webui.sh immediately before running a2enmod, so a"
		echo "# crash/SIGKILL/Ctrl-C between then and this run finishing has SOMETHING"
		echo "# that still knows these modules were enabled by this installer, not by"
		echo "# the operator or by anything else on this host."
		echo "# If this file still exists and no csf-ui install is currently running,"
		echo "# the run that wrote it died before reverting or confirming these -"
		echo "# check whether $names should stay enabled, then remove this file."
		echo "$names"
	} > "$tmp" 2>/dev/null && mv "$tmp" "$MODULES_RECORD" 2>/dev/null
}

clear_modules_enabled_record() {
	rm -f "$MODULES_RECORD" 2>/dev/null
}

###############################################################################
# front_configtest FRONT - runs FRONT's own configuration validator
# against the ACTIVE config (ours included, once written) and returns its
# exit status, with combined stdout+stderr already printed by the caller
# via command substitution. Returns 2, not 0 or 1, when no validator
# binary can be found for a platform EXPECTED to ship one - fix round 2
# (task-9-review.md R87): "when it is unavailable, say that rather than
# assuming success" - a caller must treat 2 as a refusal, the same as a
# real failure, never as a pass.
#
# Fix round 3 (task-9-review.md R92): that rule, applied uniformly,
# silently made Mode A impossible for LiteSpeed - it ships no
# configuration-test command at all, ever, on any host, so the generic
# "no validator found" fallthrough refused it every single time. R92:
# "a rule that is correct in general still needs a path for the
# platform that ships no validator... silently refusing a supported
# platform is not [fine]." LiteSpeed gets its own explicit arm: it says
# plainly that nothing here can verify the config, and returns 0 - not
# because anything was checked, but because "unavailable" is LiteSpeed's
# permanent, expected state rather than nginx/Apache's anomalous one,
# and refusing over a permanent condition is not a refusal a re-run can
# ever get past. setup_mode_a() prints the manual verification step this
# implies.
###############################################################################
front_configtest() {
	front=$1
	case "$front" in
		nginx)
			if command -v nginx >/dev/null 2>&1; then
				nginx -t 2>&1
				return $?
			fi
			;;
		apache)
			if command -v apache2ctl >/dev/null 2>&1; then
				apache2ctl configtest 2>&1
				return $?
			elif command -v httpd >/dev/null 2>&1; then
				httpd -t 2>&1
				return $?
			elif command -v apachectl >/dev/null 2>&1; then
				apachectl configtest 2>&1
				return $?
			fi
			;;
		litespeed)
			echo "csf-ui: LiteSpeed ships no configuration-test command - proceeding without automated verification"
			return 0
			;;
	esac
	echo "csf-ui: no configuration validator found for $front"
	return 2
}

###############################################################################
# front_disable_vhost FRONT OUT ALLOW_INCLUDE - the rollback half of
# setup_mode_a(): removes the vhost this run just wrote/enabled, so a
# failed validation never leaves a broken or inert config active.
# LiteSpeed has no enable/disable step to undo (install-webui.sh never
# touches its main httpd_config.conf - see setup_mode_a()'s own
# comment), so only the files are removed there.
#
# Fix round 5 (task-9-review.md R99): "':917'/':919' overclaim. They say
# 'nothing this run touched is still active' while
# /etc/csf-ui/allow-$front.conf, written at ':865', survives
# front_disable_vhost()." This used to remove only OUT (the vhost
# itself), leaving write_allow_include()'s own file behind - round 3's
# "removed the vhost" was true; round 4's stronger claim was not. Both
# files this run wrote are now removed together.
###############################################################################
front_disable_vhost() {
	front=$1
	out=$2
	allow_include=$3
	if [ "$front" = "apache" ] && command -v a2disconf >/dev/null 2>&1; then
		a2disconf csf-ui >/dev/null 2>&1
	fi
	rm -f "$out" "$allow_include"
}

###############################################################################
# _enable_now UNIT - enables and starts UNIT, then reports what actually
# happened rather than what was attempted (fix round 1, task-9-review.md
# Important: "'enabled and started' is printed without asking systemctl
# whether either happened"). `systemctl enable --now` can fail silently
# to a caller that only checks nothing crashed - a masked unit, a syntax
# error systemd itself rejects, or a unit file that failed to copy all
# return non-zero, or return zero while the service still fails its own
# startup checks (Server.pm's preflight() among them) - `is-enabled` and
# `is-active` are asked afterwards rather than inferred from the enable
# call's own exit status.
###############################################################################
_enable_now() {
	unit=$1
	systemctl enable --now "$unit" >/dev/null 2>&1

	enabled=$(systemctl is-enabled "$unit" 2>/dev/null)
	active=$(systemctl is-active "$unit" 2>/dev/null)
	[ -n "$enabled" ] || enabled=unknown
	[ -n "$active" ] || active=unknown

	echo "csf-ui: $unit: enabled=$enabled active=$active"
	if [ "$active" != "active" ]; then
		echo "csf-ui:   (not running - check 'systemctl status $unit' and 'journalctl -u $unit')"
	fi
}

###############################################################################
# setup_mode_b - standalone: csf-ui terminates TLS itself
# (ConfigServer::UI::Server, Task 5). Both units are meaningful here, so
# both are enabled.
###############################################################################
setup_mode_b() {
	port=$1
	allow=$2

	if ! validate_ui_allow "$allow"; then
		echo "csf-ui: leaving the WebUI unconfigured."
		return 1
	fi

	write_ui_conf b "$port" "$allow"
	echo "csf-ui: ui.conf written for Mode B (standalone) on port $port."
	echo "csf-ui: create an admin account before relying on it:"
	echo "csf-ui:   /usr/local/csf-ui/bin/csf-ui-passwd useradd <name> --role admin"

	if command -v systemctl >/dev/null 2>&1; then
		_enable_now csf-ui-helper.service
		_enable_now csf-ui.service
	else
		echo "csf-ui: no systemctl found - csf-ui-helper.service and csf-ui.service were not started"
	fi
}

###############################################################################
# setup_mode_a - behind a detected front web server. Renders that
# server's vhost template, but declares it configured ONLY once the
# front server's OWN validator (and, for Apache, an actual module check)
# says it is real - never on the strength of this script's own
# rendering having succeeded. Never enables csf-ui.service.
#
# WHY NOT ENABLE IT: this build's ConfigServer::UI::Server (Task 5) is,
# by its own header comment, "The Mode B listener" - it refuses to start
# at all for UI_MODE=a. Nothing anywhere in this tree yet listens on the
# unix socket these templates proxy to; there is no frozen path for it in
# docs/WEBUI-RPC.md S2.3 either. Enabling csf-ui.service here would start
# a process that immediately exits with that exact refusal, on a timer
# that keeps restarting it - a crash loop dressed up as "Mode A is on".
#
# WHY VALIDATE RATHER THAN TRUST OUR OWN RENDER (fix round 2,
# task-9-review.md R87): this task's whole failure signature is "nothing
# happens and nothing says so", and rendering a syntactically well-formed
# file is not the same claim as "the front server will actually load
# it". Three concrete ways they differ, all closed by the same fix:
#   - Apache ships mod_ssl/mod_proxy_http/mod_headers DISABLED by default
#     on Debian/Ubuntu - the vhost renders fine and is inert (R88).
#   - csf-ui-cert.sh can fail (no openssl, disk full) and exits 0 either
#     way (by design - a firewall install must not fail over it) - a
#     vhost referencing a certificate that was never written is fatal to
#     the ENTIRE front server, not just this one.
#   - UI_ALLOW's shape is checked by validate_ui_allow() above, but a
#     subtler malformed value (out-of-range octets, a mask past /32) is
#     still possible and is exactly what a real parser exists to catch.
# nginx and Apache both ship a validator whose only job is to answer this
# question (`nginx -t`, `apache2ctl configtest`/`httpd -t`) - it is used
# here rather than reproduced.
#
# THE SEQUENCE (fix round 4, task-9-review.md R95, replacing three
# separate patches with one ordering): validate input, determine the
# target path, BASELINE (measure - do not yet judge), check the
# certificate, ask CONSENT and ENABLE any missing Apache module, WRITE
# the vhost, VALIDATE the result, and only THEN decide - rolling back
# EVERYTHING this run changed (the vhost AND any module it enabled) if
# the final validation fails, and deriving every message from what the
# baseline and final results actually established rather than from
# which step happened to run last. R95 found three faces of the same
# ordering mistake in the previous round's separate baseline/consent/
# write steps:
#   1. the baseline ran before write_allow_include, so a MISSING FILE
#      THIS RUN WOULD HAVE RECREATED (e.g. our own allow-include lost
#      between runs) permanently blocked every future re-run instead of
#      being healed by it;
#   2. the baseline-failure branch printed only "leaving the WebUI
#      unconfigured", discarding $baseline_output - the one place in
#      this file that names the actual reason, in the round whose
#      entire subject was making refusals honest;
#   3. a module enabled by the R93 consent prompt was never reverted on
#      a later failure, and because enabling happened AFTER the
#      baseline, a failure the module-enable itself caused (activating
#      stale <IfModule>-guarded config elsewhere on the box) was
#      reported as "failed after adding this vhost (it passed before)"
#      - blaming the vhost for what the module-enable did, the exact
#      misattribution R94 exists to prevent, arriving through R93's own
#      fix instead.
# The fix below is not gating on the baseline result (except the one
# baseline outcome that WRITING can never change - no validator binary
# at all) - it is treated purely as a MEASUREMENT, carried forward to
# be compared against the result AFTER this run's own changes, so a
# baseline failure that this run's own write repairs succeeds instead
# of being blocked, and a baseline failure that persists is reported
# with both readings rather than one discarded.
###############################################################################
setup_mode_a() {
	front=$1
	port=$2
	allow=$3

	if ! validate_ui_allow "$allow"; then
		echo "csf-ui: leaving the WebUI unconfigured."
		return 1
	fi

	# /run/csf-ui-web is csf-ui.service's own RuntimeDirectory (fix round
	# 1, task-9-review.md Important): /var/run/csf-ui is 0755 root:root
	# (docs/WEBUI-RPC.md S2.3, frozen for csf-ui-helper's own root-owned
	# socket) and csfui - the user this unit runs as - cannot create a
	# file there at all. This path is the one csfui can actually bind() to
	# once a Mode A listener exists.
	sock=/run/csf-ui-web/csf-ui.sock
	allow_include="/etc/csf-ui/allow-$front.conf"

	case "$front" in
		nginx)
			tpl=nginx.conf.tpl
			out=/etc/nginx/conf.d/csf-ui.conf
			;;
		apache)
			tpl=apache.conf.tpl
			out="$(apache_confd)/csf-ui.conf"
			;;
		litespeed)
			tpl=litespeed.conf.tpl
			out=/usr/local/lsws/conf/vhosts/csf-ui/vhconf.conf
			;;
		*)
			echo "csf-ui: internal error: unknown front end '$front' - skipping Mode A"
			return 1
			;;
	esac

	# STEP 1 - BASELINE. Measured, not judged: LiteSpeed has no validator
	# to measure at all (front_configtest()'s own litespeed arm, R92),
	# so baseline_rc stays empty there and every comparison below treats
	# empty as "no baseline exists" rather than as pass or fail. A
	# missing-validator baseline (rc 2) IS still a same-outcome refusal
	# here, because it is the one baseline result nothing this run does
	# can ever change - there is no point asking for module consent or
	# writing a vhost this can never confirm. Every OTHER baseline
	# result, including a real failure, is carried forward instead of
	# acted on immediately (fix round 4's whole point): this run's own
	# write might repair exactly what the baseline found broken.
	baseline_rc=""
	baseline_output=""
	if [ "$front" != "litespeed" ]; then
		baseline_output=$(front_configtest "$front")
		baseline_rc=$?
		if [ "$baseline_rc" -eq 2 ]; then
			echo "$baseline_output" | sed 's/^/csf-ui:   /'
			echo "csf-ui: leaving the WebUI unconfigured."
			return 1
		fi
	fi

	if [ ! -s /etc/csf-ui/ssl/cert.pem ] || [ ! -s /etc/csf-ui/ssl/key.pem ]; then
		echo "csf-ui: /etc/csf-ui/ssl/cert.pem or key.pem is missing or empty"
		echo "csf-ui: (csf-ui-cert.sh could not create one - see its own output above)"
		echo "csf-ui: refusing to write a vhost that references a certificate that does not exist."
		return 1
	fi

	# STEP 2 - CONSENT, STEP 3 - ENABLE (Apache only). Fix round 3 (R93):
	# enabling a module is never silent or automatic - apache_check_modules()
	# is a pure check; apache_enable_modules() is the only place a2enmod
	# is invoked, and only after this asks. $modules_enabled_this_run
	# records EXACTLY what this run enabled (fix round 4, R95) - not
	# whatever apache_check_modules() reports at rollback time, which
	# would also catch modules that were already enabled before this run
	# touched anything and were never this run's to revert.
	#
	# Fix round 5 (task-9-review.md R97): apache_check_modules() can now
	# say "could not ask" (its own check_rc, not the missing-list). A host
	# whose Apache config does not parse for a reason this vhost has
	# nothing to do with used to make this look identical to "every module
	# is genuinely missing", forcing this consent prompt for the wrong
	# reason and permanently blocking Apache's own self-heal (the baseline
	# in STEP 1 exists precisely to tolerate that case). "Could not ask" now
	# skips consent and enabling entirely - proceeding to STEP 4/5 below,
	# where the real validator (not this blind instrument) has the final
	# word either way.
	modules_enabled_this_run=""
	if [ "$front" = "apache" ]; then
		still_missing=$(apache_check_modules)
		check_rc=$?
		if [ "$check_rc" -ne 0 ]; then
			echo "csf-ui: could not determine which Apache modules are enabled (apache2ctl -M"
			echo "csf-ui: and its fallbacks all failed) - this usually means Apache's own"
			echo "csf-ui: configuration does not already parse, for a reason unrelated to this"
			echo "csf-ui: vhost. Skipping the module check rather than guessing a wrong answer;"
			echo "csf-ui: the configuration test in the next step decides this either way."
			still_missing=""
		fi
		if [ -n "$still_missing" ]; then
			enable_names=$(printf '%s' "$still_missing" | sed 's/_module//g')
			echo "csf-ui: Apache module(s) not enabled: $still_missing"
			echo "csf-ui: the vhost would be syntactically valid but INERT without them"
			echo "csf-ui: (docs/WEBUI-RPC.md - a <IfModule> guard skips it rather than breaking"
			echo "csf-ui: your whole Apache config, per task-9-review.md I6)."
			echo "csf-ui: NOTE: enabling mod_ssl activates 'Listen 443' via Debian/Ubuntu's own"
			echo "csf-ui: ports.conf - a change to this host's network exposure, independent of"
			echo "csf-ui: anything this WebUI vhost does."
			enabled_now=0
			if command -v a2enmod >/dev/null 2>&1; then
				printf 'csf-ui: enable them now (a2enmod %s)? [y/N] ' "$enable_names"
				read -r reply
				case "$reply" in
					[Yy]*)
						# Fix round 5 (task-9-review.md R98): persist what this
						# run is ABOUT to enable BEFORE enabling it, so a crash
						# between the two leaves something on disk that still
						# knows these modules were this installer's doing.
						record_modules_enabled "$enable_names"
						# Fix round 5 (task-9-review.md R96): trust
						# apache_enable_modules()'s OWN exit status (a2enmod's
						# own exit status) rather than re-asking the same blind
						# apache_check_modules() instrument R97 exists to stop
						# trusting. The previous re-check reported every module
						# missing again whenever Apache's config did not parse
						# for an unrelated reason, so `enabled_now` never got
						# set even though a2enmod had already succeeded and
						# already changed the host's exposure - the code then
						# fell into "not enabling" below and returned WITHOUT
						# disabling what it had just enabled.
						if apache_enable_modules "$enable_names"; then
							modules_enabled_this_run=$enable_names
							enabled_now=1
						else
							clear_modules_enabled_record
							echo "csf-ui: a2enmod $enable_names failed - see its own output above"
						fi
						;;
				esac
			fi
			if [ "$enabled_now" -ne 1 ]; then
				echo "csf-ui: not enabling Apache modules without confirmation. Run this yourself"
				echo "csf-ui: when ready, then re-run this installer or run csf-ui-setup:"
				echo "csf-ui:   a2enmod $enable_names && systemctl reload apache2"
				return 1
			fi
		fi
	fi

	# STEP 4 - WRITE. Recreates $allow_include unconditionally - this is
	# what makes the baseline above a measurement rather than a gate: if
	# it was THIS file missing that failed the baseline, this line is
	# already the fix, and the validation below will say so by passing.
	write_allow_include "$front" "$allow" "$allow_include"

	mkdir -p "$(dirname "$out")" 2>/dev/null
	if ! sh "$DIST_DIR/render-template.sh" "$DIST_DIR/$tpl" "$out" \
		"UI_PORT=$port" "UI_SOCK=$sock" "UI_ALLOW_INCLUDE=$allow_include"; then
		echo "csf-ui: could not render the $front vhost - leaving the WebUI unconfigured"
		return 1
	fi

	if [ "$front" = "apache" ] && command -v a2enconf >/dev/null 2>&1; then
		a2enconf csf-ui >/dev/null 2>&1
	fi

	# STEP 5 - VALIDATE. front_configtest()'s own litespeed arm (R92)
	# always returns 0 here - not because anything was checked, but
	# because "no validator" is LiteSpeed's permanent, expected state
	# rather than nginx/Apache's anomalous one; the manual-verification
	# steps below are how that gap actually gets closed.
	test_output=$(front_configtest "$front")
	test_rc=$?

	if [ "$test_rc" -ne 0 ]; then
		# STEP 6 - ROLLBACK EVERYTHING THIS RUN CHANGED, then derive the
		# message from what the baseline and this result actually
		# established, rather than assuming the vhost is why.
		#
		# Fix round 5 (task-9-review.md R99): front_disable_vhost() now also
		# removes $allow_include (see its own comment) and
		# clear_modules_enabled_record() retires the R98 durability record
		# once apache_disable_modules() has actually reverted what it names -
		# both needed before "nothing this run touched is still active"
		# below is actually true.
		front_disable_vhost "$front" "$out" "$allow_include"
		if [ -n "$modules_enabled_this_run" ]; then
			apache_disable_modules "$modules_enabled_this_run"
			clear_modules_enabled_record
		fi

		what_changed="this vhost"
		[ -n "$modules_enabled_this_run" ] && what_changed="this vhost and enabling module(s) $modules_enabled_this_run"

		if [ -n "$baseline_rc" ] && [ "$baseline_rc" -ne 0 ]; then
			echo "csf-ui: $front's configuration ALREADY failed its own test before this run"
			echo "csf-ui: changed anything:"
			echo "$baseline_output" | sed 's/^/csf-ui:   /'
			echo "csf-ui: and STILL fails after adding $what_changed:"
			echo "$test_output" | sed 's/^/csf-ui:   /'
			echo "csf-ui: cannot tell whether this vhost is the cause of a problem that was"
			echo "csf-ui: already there - fix the pre-existing failure above, then re-run."
		else
			# Fix round 5 (task-9-review.md R99): baseline_rc is guaranteed
			# non-empty here - it is only ever empty for LiteSpeed, and
			# LiteSpeed's own front_configtest() arm (R92) always returns 0,
			# so this whole test_rc-!=0 branch can never be reached for
			# LiteSpeed; the old empty-baseline_rc arm below was dead code.
			# The old wording here also dangled - it said "it passed before,
			# see above" - but a PASSING baseline prints nothing, so there
			# was never anything shown above for it to point at.
			echo "csf-ui: $front's own configuration test failed after adding $what_changed"
			echo "csf-ui: (it passed before this run made any changes) - the WebUI vhost is NOT active:"
			echo "$test_output" | sed 's/^/csf-ui:   /'
		fi
		if [ -n "$modules_enabled_this_run" ]; then
			echo "csf-ui: removed the vhost, its allow-include file, and disabled the module(s)"
			echo "csf-ui: this run enabled ($modules_enabled_this_run) - nothing this run touched"
			echo "csf-ui: is still active."
		else
			echo "csf-ui: removed the vhost and its allow-include file - nothing this run"
			echo "csf-ui: touched is still active."
		fi
		echo "csf-ui: left the WebUI unconfigured. Fix the problem above and re-run."
		return 1
	fi

	if [ "$front" = "litespeed" ]; then
		verified_note="NOT automatically verified - see the manual step below"
	else
		verified_note="verified with its own configuration test"
	fi

	write_ui_conf a "$port" "$allow"
	grant_socket_group "$front"
	clear_modules_enabled_record

	echo "csf-ui: $front vhost written to $out and $verified_note."
	if [ "$front" = "litespeed" ]; then
		echo "csf-ui: LiteSpeed ships no configuration-test command this installer can call -"
		echo "csf-ui: MANUAL VERIFICATION IS REQUIRED before relying on this:"
		echo "csf-ui:   1. add a matching 'listener'/vhost-map entry in LiteSpeed's own"
		echo "csf-ui:      httpd_config.conf pointing at $out (its admin console can do this),"
		echo "csf-ui:      and set maxReqBodySize to 65536 on that same listener/map - it is"
		echo "csf-ui:      NOT set by $out itself (docs/WEBUI-RPC.md S3.1/S14.1's 65536-byte cap);"
		echo "csf-ui:   2. use the WebAdmin console's own 'Graceful Restart' (or"
		echo "csf-ui:      lswsctrl restart) and check its error log before trusting this -"
		echo "csf-ui:      nothing here has confirmed $out actually parses."
	fi

	# Fix round 1 (task-9-review.md Important): say what actually happens
	# on this host, not only what this script itself did not do. The vhost
	# file at $out is live configuration the moment $front next reads it -
	# which is $front's own timeline, not this script's, and this script
	# never reloads $front itself.
	echo "csf-ui: IMPORTANT - this build's csf-ui has no Mode A listener yet (no code"
	echo "csf-ui: anywhere in this release binds $sock; see the Task 9 report), so"
	echo "csf-ui: csf-ui.service is deliberately NOT enabled. But $out is otherwise"
	echo "csf-ui: ordinary, live $front configuration: the NEXT time $front reloads or"
	echo "csf-ui: restarts - for this or any unrelated reason - it WILL start accepting"
	echo "csf-ui: HTTPS on port $port and WILL return 502 for every request, because"
	echo "csf-ui: nothing listens on $sock yet. Do not reload $front expecting this to"
	echo "csf-ui: start working; remove $out first if you do not want a 502'ing port"
	echo "csf-ui: live before a Mode A listener ships."

	if command -v systemctl >/dev/null 2>&1; then
		_enable_now csf-ui-helper.service
	else
		echo "csf-ui: no systemctl found - csf-ui-helper.service was not started"
	fi
	return 0
}

###############################################################################
# interactive_setup - the only place this script asks anything. Reached
# only when stdin and stdout are both a real terminal (main(), below).
###############################################################################
interactive_setup() {
	front=$(detect_frontend)

	echo
	echo "csf-ui: the replacement WebUI (docs/WEBUI-PLAN.md) can be set up now."
	if [ -n "$front" ]; then
		echo "csf-ui: detected $front - Mode A (behind $front) is recommended."
	else
		echo "csf-ui: no supported front web server (nginx/Apache/LiteSpeed) detected."
	fi
	echo "csf-ui:   a = behind the detected web server"
	echo "csf-ui:   b = standalone (csf-ui serves TLS itself)"
	echo "csf-ui:   anything else = skip for now (run csf-ui-setup later)"
	printf 'csf-ui: set up the WebUI now? [a/b/N] '
	read -r answer

	case "$answer" in
		[Aa]) mode=a ;;
		[Bb]) mode=b ;;
		*)
			echo "csf-ui: skipping WebUI setup. Run csf-ui-setup at any time to finish it."
			return 0
			;;
	esac

	if [ "$mode" = "a" ] && [ -z "$front" ]; then
		echo "csf-ui: Mode A needs a detected web server; none found - using standalone (b) instead."
		mode=b
	fi

	allow=$(guess_admin_ip)
	if [ -z "$allow" ]; then
		echo "csf-ui: could not determine your address automatically (no \$SSH_CLIENT/\$SSH_CONNECTION)."
		printf 'csf-ui: enter an IP or CIDR to allow into the WebUI (blank to skip setup): '
		read -r allow
	fi
	if [ -z "$allow" ]; then
		echo "csf-ui: no address given - leaving the WebUI unconfigured. Run csf-ui-setup later."
		return 0
	fi

	port=8443
	printf 'csf-ui: WebUI port [%s]: ' "$port"
	read -r input_port
	# docs/WEBUI-RPC.md S10: UI_PORT must be 1024-65535 in EITHER mode -
	# fix round 1 (task-9-review.md Important) found any digit string was
	# accepted here, so a value ui.conf's own grammar refuses (e.g. "80",
	# "99999") would be written and only fail loudly later, at csf-ui
	# start time, instead of being caught where the operator can retype it.
	case "$input_port" in
		'') : ;;
		*[!0-9]*)
			echo "csf-ui: '$input_port' is not a number - keeping $port"
			;;
		*)
			if [ "$input_port" -ge 1024 ] 2>/dev/null && [ "$input_port" -le 65535 ] 2>/dev/null; then
				port=$input_port
			else
				echo "csf-ui: '$input_port' is out of range (must be 1024-65535, docs/WEBUI-RPC.md S10) - keeping $port"
			fi
			;;
	esac

	if [ "$mode" = "a" ]; then
		setup_mode_a "$front" "$port" "$allow"
	else
		setup_mode_b "$port" "$allow"
	fi
}

###############################################################################
# verify_install - task-9-brief.md item C: "nothing verifies S2.3 as
# installed". Checks every binary and directory the frozen table names,
# that csfui can actually read what was just written for it (S13.2's own
# demonstration, done here instead of only argued about), and that
# nothing here widened csf's own hardening (S13.5 assertion 2).
#
# S13.5's other assertion - re-checking csfui's read access "after one
# minute of lfd running" - is not repeated here on a timer: by
# construction (S13.4; item D above) none of this task's paths sit under
# /etc/csf, /var/lib/csf or /usr/local/csf, so lfd's sweep structurally
# cannot reach them, and re-reading the same mode 60 seconds later would
# reconfirm the same answer on a correct install, never a different one.
###############################################################################
###############################################################################
# _check_path PATH MODE OWNER GROUP LABEL
#
# Fix round 1 (task-9-review.md Important - "checks existence only, and
# test -x as root is close to vacuous... ownership and modes from S2.3
# are never checked in either direction"). `test -x` as root is true for
# almost anything, since root's execute check does not require ANY execute
# bit to be set for a regular file it owns in some implementations, and
# tells you nothing about whether a file is 0750 or 0777. This checks the
# exact mode and the exact owner/group `stat` reports - unlike
# t/71-rollback.t's own S2.3 check, which deliberately only checks the
# executable bit because a git checkout cannot carry a literal 0750 (its
# own comment explains why). This function runs against an actual
# INSTALL, where install_files()/setup_directories() just set every mode
# and owner explicitly, so there is no umask excuse for a mismatch here.
###############################################################################
_check_path() {
	path=$1
	want_mode=$2
	want_owner=$3
	want_group=$4
	label=$5

	if [ ! -e "$path" ]; then
		echo "csf-ui: *VERIFY FAILED* $label ($path) does not exist"
		return 1
	fi

	if ! command -v stat >/dev/null 2>&1; then
		echo "csf-ui: WebUI verify: 'stat' not found - cannot check $path's mode/owner"
		return 0
	fi

	got_mode=$(stat -c '%a' "$path" 2>/dev/null)
	got_owner=$(stat -c '%U' "$path" 2>/dev/null)
	got_group=$(stat -c '%G' "$path" 2>/dev/null)
	ok=1

	if [ "$got_mode" != "$want_mode" ]; then
		echo "csf-ui: *VERIFY FAILED* $label ($path) is mode $got_mode, expected $want_mode"
		ok=0
	fi
	if [ "$got_owner" != "$want_owner" ]; then
		echo "csf-ui: *VERIFY FAILED* $label ($path) is owned by $got_owner, expected $want_owner"
		ok=0
	fi
	if [ "$got_group" != "$want_group" ]; then
		echo "csf-ui: *VERIFY FAILED* $label ($path) has group $got_group, expected $want_group"
		ok=0
	fi
	[ "$ok" -eq 1 ]
}

verify_install() {
	problems=0

	# The four S2.3-frozen binaries: 0750 root:csfui, by name, so a
	# dropped exec bit (the exact defect that killed Task 8's rollback
	# timer while 2400 tests passed) is caught here rather than
	# discovered at start time.
	for bin in csf-ui csf-ui-helper csf-ui-passwd csf-ui-setup; do
		_check_path "/usr/local/csf-ui/bin/$bin" 750 root csfui "binary $bin" \
			|| problems=$((problems + 1))
	done

	# Fix round 1 (task-9-review.md M9): the report previously claimed
	# this function checks the installed bin/ holds ONLY those four names.
	# It did not - only their individual presence was checked, so a fifth
	# file (a stray copy, a leftover from Task 11 deleting assets, a
	# future mistake) would pass silently. t/71-rollback.t already proves
	# this for the SOURCE tree; this is the actual check for the
	# INSTALLED one.
	bin_dir=/usr/local/csf-ui/bin
	if [ -d "$bin_dir" ]; then
		for f in "$bin_dir"/*; do
			[ -f "$f" ] || continue
			name=$(basename "$f")
			case "$name" in
				csf-ui | csf-ui-helper | csf-ui-passwd | csf-ui-setup) : ;;
				*)
					echo "csf-ui: *VERIFY FAILED* $bin_dir/$name is not one of the four docs/WEBUI-RPC.md S2.3 names"
					problems=$((problems + 1))
					;;
			esac
		done
	fi

	# Directories and their contents, docs/WEBUI-RPC.md S2.3 verbatim
	# (plus /etc/csf-ui/ssl and /usr/local/csf-ui/{lib,web}'s own
	# subtrees, which S2.3 treats as part of the same pattern rather than
	# itemizing). "path:mode:owner:group:label" - colon-separated so a
	# single loop can walk it without a fifth positional array.
	for row in \
		"/usr/local/csf-ui:755:root:root:top-level install directory" \
		"/usr/local/csf-ui/bin:755:root:root:binary directory" \
		"/usr/local/csf-ui/lib:755:root:root:lib directory" \
		"/usr/local/csf-ui/lib/ConfigServer:755:root:root:lib/ConfigServer directory" \
		"/usr/local/csf-ui/lib/ConfigServer/UI:755:root:root:lib/ConfigServer/UI directory" \
		"/usr/local/csf-ui/web:755:root:root:web directory" \
		"/etc/csf-ui:750:root:csfui:/etc/csf-ui" \
		"/etc/csf-ui/ssl:750:root:csfui:TLS material directory" \
		"/var/lib/csf-ui:755:root:root:/var/lib/csf-ui" \
		"/var/lib/csf-ui/helper:700:root:root:helper state directory" \
		"/var/lib/csf-ui/sessions:700:csfui:csfui:session store" \
		"/var/lib/csf-ui/rl:700:csfui:csfui:rate-limit store" \
		"/var/run/csf-ui:755:root:root:/var/run/csf-ui" \
		"/var/log/csf-ui-audit.log:640:root:root:audit log" \
		"/var/log/csf-ui-access.log:640:csfui:csfui:access log" \
	; do
		path=${row%%:*}; rest=${row#*:}
		mode=${rest%%:*}; rest=${rest#*:}
		owner=${rest%%:*}; rest=${rest#*:}
		group=${rest%%:*}; label=${rest#*:}
		_check_path "$path" "$mode" "$owner" "$group" "$label" \
			|| problems=$((problems + 1))
	done

	if [ -f /etc/csf-ui/ssl/cert.pem ]; then
		_check_path /etc/csf-ui/ssl/cert.pem 644 root csfui "TLS certificate" \
			|| problems=$((problems + 1))
	fi
	if [ -f /etc/csf-ui/ssl/key.pem ]; then
		_check_path /etc/csf-ui/ssl/key.pem 640 root csfui "TLS private key" \
			|| problems=$((problems + 1))
	fi

	if getent passwd csfui >/dev/null 2>&1; then
		if [ -f /etc/csf-ui/ui.conf ]; then
			_check_path /etc/csf-ui/ui.conf 640 root csfui "ui.conf" \
				|| problems=$((problems + 1))
			if command -v su >/dev/null 2>&1 \
				&& ! su -s /bin/sh -c 'test -r /etc/csf-ui/ui.conf' csfui 2>/dev/null; then
				echo "csf-ui: *VERIFY FAILED* csfui cannot read /etc/csf-ui/ui.conf - the WebUI will refuse to start"
				problems=$((problems + 1))
			fi
		fi
	else
		echo "csf-ui: *VERIFY FAILED* system account 'csfui' does not exist"
		problems=$((problems + 1))
	fi

	# Fix round 5 (task-9-review.md R98): a leftover MODULES_RECORD means a
	# previous run died between recording what it was about to enable and
	# either confirming or reverting it (see record_modules_enabled()'s own
	# comment) - surfaced here rather than left for someone to discover by
	# accident.
	if [ -f "$MODULES_RECORD" ]; then
		echo "csf-ui: *VERIFY FAILED* $MODULES_RECORD exists - a previous WebUI install run"
		echo "csf-ui:   was interrupted after enabling Apache module(s) but before this run"
		echo "csf-ui:   confirmed or reverted them. Contents:"
		sed 's/^/csf-ui:     /' "$MODULES_RECORD" 2>/dev/null
		echo "csf-ui:   decide whether these modules should stay enabled, then remove this file."
		problems=$((problems + 1))
	fi

	for d in /etc/csf /var/lib/csf /usr/local/csf; do
		if [ -d "$d" ] && command -v stat >/dev/null 2>&1; then
			mode=$(stat -c '%a' "$d" 2>/dev/null)
			if [ -n "$mode" ] && [ "$mode" != "600" ]; then
				echo "csf-ui: *VERIFY FAILED* $d is mode $mode, expected 600 - something widened csf's own hardening"
				problems=$((problems + 1))
			fi
		fi
	done

	if [ "$problems" -gt 0 ]; then
		echo "csf-ui: WebUI install verification found $problems problem(s) - see above."
	else
		echo "csf-ui: WebUI install verified OK."
	fi
}

###############################################################################
main() {
	if [ "$(id -u)" != "0" ]; then
		echo "csf-ui: not running as root - skipping WebUI setup"
		return 0
	fi

	create_account || return 0
	setup_directories
	install_files
	sh "$DIST_DIR/csf-ui-cert.sh"
	install_units

	noninteractive=0
	for arg in "$@"; do
		[ "$arg" = "--yes" ] && noninteractive=1
	done
	if [ ! -t 0 ] || [ ! -t 1 ]; then
		noninteractive=1
	fi

	if [ "$noninteractive" -eq 1 ]; then
		echo "csf-ui: non-interactive install - the WebUI is installed but NOT enabled."
		echo "csf-ui: run 'csf-ui-setup' (or re-run this installer at a terminal) to turn it on."
	else
		interactive_setup
	fi

	verify_install
	return 0
}

main "$@"
exit 0
