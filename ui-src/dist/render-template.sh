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
# render-template.sh TEMPLATE OUTPUT [KEY=VALUE ...]
#
# Copies TEMPLATE to OUTPUT with every "@@KEY@@" token replaced by the
# matching VALUE. Refuses (exit 1) and leaves OUTPUT untouched if a
# placeholder survives the substitution - a template and its caller
# drifting apart (a renamed key, a token typo'd in the template) must be
# loud, not a vhost file nginx/Apache/LiteSpeed then loads with a literal
# "@@UI_PORT@@" in it, which is a config that is syntactically fine and
# semantically wrong in a way nothing downstream would ever complain about.
#
# Needs no root and no network, so t/80-templates.t runs this for real
# rather than only reading ui-src/dist/*.tpl as text.
###############################################################################

if [ $# -lt 2 ]; then
	echo "usage: render-template.sh TEMPLATE OUTPUT [KEY=VALUE ...]" >&2
	exit 2
fi

TEMPLATE=$1
OUTPUT=$2
shift 2

if [ ! -f "$TEMPLATE" ]; then
	echo "render-template.sh: no such template: $TEMPLATE" >&2
	exit 2
fi

TMP=$(mktemp "${TMPDIR:-/tmp}/csf-ui-render.XXXXXX") || exit 2
trap 'rm -f "$TMP" "$TMP.next"' EXIT INT TERM
cp "$TEMPLATE" "$TMP" || exit 2

for kv in "$@"; do
	case "$kv" in
		[A-Za-z_]*=*) : ;;
		*)
			echo "render-template.sh: bad KEY=VALUE argument: $kv" >&2
			exit 2
			;;
	esac
	key=${kv%%=*}
	val=${kv#*=}

	# '#' is this script's own sed delimiter (chosen so a value containing
	# '/' - every path this project passes - needs no escaping); '&' and
	# '\' are special to sed's replacement text. All three are escaped in
	# the VALUE, never rejected, so a real filesystem path is never a
	# reason for this script to refuse.
	escaped=$(printf '%s' "$val" | sed -e 's/[&#\]/\\&/g')

	sed "s#@@${key}@@#${escaped}#g" "$TMP" > "$TMP.next" || exit 2
	mv "$TMP.next" "$TMP" || exit 2
done

if grep -q '@@[A-Za-z_][A-Za-z0-9_]*@@' "$TMP"; then
	echo "render-template.sh: $TEMPLATE still has unresolved placeholder(s):" >&2
	grep -o '@@[A-Za-z_][A-Za-z0-9_]*@@' "$TMP" | sort -u >&2
	exit 1
fi

cp "$TMP" "$OUTPUT" && chmod 0644 "$OUTPUT"
