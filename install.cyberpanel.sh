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

umask 0177

# Added 2026-09-12 in https://github.com/nkyo/csf - see CHANGES.md.
#
# Captured before this script (or anything it calls) ever changes
# directory - kept consistent with the other six install.*.sh even though
# this one has no `cd` before its own WebUI packaging call today; a future
# `cd` added anywhere above must not be able to reintroduce fix round 1's
# silent-skip bug here too. Every reference to ui-src/dist/ below uses
# this instead of a path relative to the current directory.
CSF_SRC_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || CSF_SRC_ROOT=.

if [ -e "/usr/local/cpanel/version" ]; then
	echo "Running csf cPanel installer"
	echo
	sh install.cpanel.sh
	exit 0
elif [ -e "/usr/local/directadmin/directadmin" ]; then
	echo "Running csf DirectAdmin installer"
	echo
	sh install.directadmin.sh
	exit 0
fi

echo "Installing csf and lfd"
echo

echo "Check we're running as root"
if [ ! `id -u` = 0 ]; then
	echo
	echo "FAILED: You have to be logged in as root (UID:0) to install csf"
	exit
fi
echo

mkdir -v -m 0600 /etc/csf
cp -avf install.txt /etc/csf/

echo "Checking Perl modules..."
chmod 700 os.pl
RETURN=`./os.pl`
if [ "$RETURN" = 1 ]; then
	echo
	echo "FAILED: You MUST install the missing perl modules above before you can install csf. See /etc/csf/install.txt for installation details."
    echo
	exit
else
    echo "...Perl modules OK"
    echo
fi

mkdir -v -m 0600 /etc/csf
mkdir -v -m 0600 /var/lib/csf
mkdir -v -m 0600 /var/lib/csf/backup
mkdir -v -m 0600 /var/lib/csf/Geo
mkdir -v -m 0600 /var/lib/csf/stats
mkdir -v -m 0600 /var/lib/csf/lock
mkdir -v -m 0600 /var/lib/csf/webmin
mkdir -v -m 0600 /var/lib/csf/zone
mkdir -v -m 0600 /usr/local/csf
mkdir -v -m 0600 /usr/local/csf/bin
mkdir -v -m 0600 /usr/local/csf/lib
mkdir -v -m 0600 /usr/local/csf/tpl

if [ -e "/etc/csf/alert.txt" ]; then
	sh migratedata.sh
fi

if [ ! -e "/etc/csf/csf.conf" ]; then
	cp -avf csf.cyberpanel.conf /etc/csf/csf.conf
fi

if [ ! -d /var/lib/csf ]; then
	mkdir -v -p -m 0600 /var/lib/csf
fi
if [ ! -d /usr/local/csf/lib ]; then
	mkdir -v -p -m 0600 /usr/local/csf/lib
fi
if [ ! -d /usr/local/csf/bin ]; then
	mkdir -v -p -m 0600 /usr/local/csf/bin
fi
if [ ! -d /usr/local/csf/tpl ]; then
	mkdir -v -p -m 0600 /usr/local/csf/tpl
fi

if [ ! -e "/etc/csf/csf.allow" ]; then
	cp -avf csf.cyberpanel.allow /etc/csf/csf.allow
fi
if [ ! -e "/etc/csf/csf.deny" ]; then
	cp -avf csf.deny /etc/csf/.
fi
if [ ! -e "/etc/csf/csf.redirect" ]; then
	cp -avf csf.redirect /etc/csf/.
fi
if [ ! -e "/etc/csf/csf.resellers" ]; then
	cp -avf csf.resellers /etc/csf/.
fi
if [ ! -e "/etc/csf/csf.dirwatch" ]; then
	cp -avf csf.dirwatch /etc/csf/.
fi
if [ ! -e "/etc/csf/csf.syslogs" ]; then
	cp -avf csf.syslogs /etc/csf/.
fi
if [ ! -e "/etc/csf/csf.logfiles" ]; then
	cp -avf csf.logfiles /etc/csf/.
fi
if [ ! -e "/etc/csf/csf.logignore" ]; then
	cp -avf csf.logignore /etc/csf/.
fi
if [ ! -e "/etc/csf/csf.blocklists" ]; then
	cp -avf csf.blocklists /etc/csf/.
else
	cp -avf csf.blocklists /etc/csf/csf.blocklists.new
fi
if [ ! -e "/etc/csf/csf.ignore" ]; then
	cp -avf csf.cyberpanel.ignore /etc/csf/csf.ignore
fi
if [ ! -e "/etc/csf/csf.pignore" ]; then
	cp -avf csf.cyberpanel.pignore /etc/csf/csf.pignore
fi
if [ ! -e "/etc/csf/csf.rignore" ]; then
	cp -avf csf.rignore /etc/csf/.
fi
if [ ! -e "/etc/csf/csf.fignore" ]; then
	cp -avf csf.fignore /etc/csf/.
fi
if [ ! -e "/etc/csf/csf.signore" ]; then
	cp -avf csf.signore /etc/csf/.
fi
if [ ! -e "/etc/csf/csf.suignore" ]; then
	cp -avf csf.suignore /etc/csf/.
fi
if [ ! -e "/etc/csf/csf.uidignore" ]; then
	cp -avf csf.uidignore /etc/csf/.
fi
if [ ! -e "/etc/csf/csf.mignore" ]; then
	cp -avf csf.mignore /etc/csf/.
fi
if [ ! -e "/etc/csf/csf.sips" ]; then
	cp -avf csf.sips /etc/csf/.
fi
if [ ! -e "/etc/csf/csf.dyndns" ]; then
	cp -avf csf.dyndns /etc/csf/.
fi
if [ ! -e "/etc/csf/csf.syslogusers" ]; then
	cp -avf csf.syslogusers /etc/csf/.
fi
if [ ! -e "/etc/csf/csf.smtpauth" ]; then
	cp -avf csf.smtpauth /etc/csf/.
fi
if [ ! -e "/etc/csf/csf.rblconf" ]; then
	cp -avf csf.rblconf /etc/csf/.
fi
if [ ! -e "/etc/csf/csf.cloudflare" ]; then
	cp -avf csf.cloudflare /etc/csf/.
fi

if [ ! -e "/usr/local/csf/tpl/alert.txt" ]; then
	cp -avf alert.txt /usr/local/csf/tpl/.
fi
if [ ! -e "/usr/local/csf/tpl/reselleralert.txt" ]; then
	cp -avf reselleralert.txt /usr/local/csf/tpl/.
fi
if [ ! -e "/usr/local/csf/tpl/logalert.txt" ]; then
	cp -avf logalert.txt /usr/local/csf/tpl/.
fi
if [ ! -e "/usr/local/csf/tpl/logfloodalert.txt" ]; then
	cp -avf logfloodalert.txt /usr/local/csf/tpl/.
fi
if [ ! -e "/usr/local/csf/tpl/syslogalert.txt" ]; then
	cp -avf syslogalert.txt /usr/local/csf/tpl/.
fi
if [ ! -e "/usr/local/csf/tpl/integrityalert.txt" ]; then
	cp -avf integrityalert.txt /usr/local/csf/tpl/.
fi
if [ ! -e "/usr/local/csf/tpl/exploitalert.txt" ]; then
	cp -avf exploitalert.txt /usr/local/csf/tpl/.
fi
if [ ! -e "/usr/local/csf/tpl/queuealert.txt" ]; then
	cp -avf queuealert.txt /usr/local/csf/tpl/.
fi
if [ ! -e "/usr/local/csf/tpl/modsecipdbalert.txt" ]; then
	cp -avf modsecipdbalert.txt /usr/local/csf/tpl/.
fi
if [ ! -e "/usr/local/csf/tpl/tracking.txt" ]; then
	cp -avf tracking.txt /usr/local/csf/tpl/.
fi
if [ ! -e "/usr/local/csf/tpl/connectiontracking.txt" ]; then
	cp -avf connectiontracking.txt /usr/local/csf/tpl/.
fi
if [ ! -e "/usr/local/csf/tpl/processtracking.txt" ]; then
	cp -avf processtracking.txt /usr/local/csf/tpl/.
fi
if [ ! -e "/usr/local/csf/tpl/accounttracking.txt" ]; then
	cp -avf accounttracking.txt /usr/local/csf/tpl/.
fi
if [ ! -e "/usr/local/csf/tpl/usertracking.txt" ]; then
	cp -avf usertracking.txt /usr/local/csf/tpl/.
fi
if [ ! -e "/usr/local/csf/tpl/sshalert.txt" ]; then
	cp -avf sshalert.txt /usr/local/csf/tpl/.
fi
if [ ! -e "/usr/local/csf/tpl/webminalert.txt" ]; then
	cp -avf webminalert.txt /usr/local/csf/tpl/.
fi
if [ ! -e "/usr/local/csf/tpl/sualert.txt" ]; then
	cp -avf sualert.txt /usr/local/csf/tpl/.
fi
if [ ! -e "/usr/local/csf/tpl/sudoalert.txt" ]; then
	cp -avf sudoalert.txt /usr/local/csf/tpl/.
fi
if [ ! -e "/usr/local/csf/tpl/consolealert.txt" ]; then
	cp -avf consolealert.txt /usr/local/csf/tpl/.
fi
if [ ! -e "/usr/local/csf/tpl/cpanelalert.txt" ]; then
	cp -avf cpanelalert.txt /usr/local/csf/tpl/.
fi
if [ ! -e "/usr/local/csf/tpl/scriptalert.txt" ]; then
	cp -avf scriptalert.txt /usr/local/csf/tpl/.
fi
if [ ! -e "/usr/local/csf/tpl/relayalert.txt" ]; then
	cp -avf relayalert.txt /usr/local/csf/tpl/.
fi
if [ ! -e "/usr/local/csf/tpl/filealert.txt" ]; then
	cp -avf filealert.txt /usr/local/csf/tpl/.
fi
if [ ! -e "/usr/local/csf/tpl/watchalert.txt" ]; then
	cp -avf watchalert.txt /usr/local/csf/tpl/.
fi
if [ ! -e "/usr/local/csf/tpl/loadalert.txt" ]; then
	cp -avf loadalert.txt /usr/local/csf/tpl/.
else
	cp -avf loadalert.txt /usr/local/csf/tpl/loadalert.txt.new
fi
if [ ! -e "/usr/local/csf/tpl/resalert.txt" ]; then
	cp -avf resalert.txt /usr/local/csf/tpl/.
fi
if [ ! -e "/usr/local/csf/tpl/portscan.txt" ]; then
	cp -avf portscan.txt /usr/local/csf/tpl/.
fi
if [ ! -e "/usr/local/csf/tpl/uidscan.txt" ]; then
	cp -avf uidscan.txt /usr/local/csf/tpl/.
fi
if [ ! -e "/usr/local/csf/tpl/permblock.txt" ]; then
	cp -avf permblock.txt /usr/local/csf/tpl/.
fi
if [ ! -e "/usr/local/csf/tpl/netblock.txt" ]; then
	cp -avf netblock.txt /usr/local/csf/tpl/.
fi
if [ ! -e "/usr/local/csf/tpl/portknocking.txt" ]; then
	cp -avf portknocking.txt /usr/local/csf/tpl/.
fi
if [ ! -e "/usr/local/csf/tpl/forkbombalert.txt" ]; then
	cp -avf forkbombalert.txt /usr/local/csf/tpl/.
fi
if [ ! -e "/usr/local/csf/tpl/recaptcha.txt" ]; then
	cp -avf recaptcha.txt /usr/local/csf/tpl/.
fi
if [ ! -e "/usr/local/csf/tpl/apache.main.txt" ]; then
	cp -avf apache.main.txt /usr/local/csf/tpl/.
fi
if [ ! -e "/usr/local/csf/tpl/apache.http.txt" ]; then
	cp -avf apache.http.txt /usr/local/csf/tpl/.
fi
if [ ! -e "/usr/local/csf/tpl/apache.https.txt" ]; then
	cp -avf apache.https.txt /usr/local/csf/tpl/.
fi
if [ ! -e "/usr/local/csf/tpl/litespeed.main.txt" ]; then
	cp -avf litespeed.main.txt /usr/local/csf/tpl/.
fi
if [ ! -e "/usr/local/csf/tpl/litespeed.http.txt" ]; then
	cp -avf litespeed.http.txt /usr/local/csf/tpl/.
fi
if [ ! -e "/usr/local/csf/tpl/litespeed.https.txt" ]; then
	cp -avf litespeed.https.txt /usr/local/csf/tpl/.
fi
cp -avf x-arf.txt /usr/local/csf/tpl/.

if [ ! -e "/usr/local/csf/bin/regex.custom.pm" ]; then
	cp -avf regex.custom.pm /usr/local/csf/bin/.
fi
if [ ! -e "/usr/local/csf/bin/pt_deleted_action.pl" ]; then
	cp -avf pt_deleted_action.pl /usr/local/csf/bin/.
fi
if [ ! -e "/etc/csf/messenger" ]; then
	cp -avf messenger /etc/csf/.
fi
if [ ! -e "/etc/csf/messenger/index.recaptcha.html" ]; then
	cp -avf messenger/index.recaptcha.html /etc/csf/messenger/.
fi
if [ -e "/etc/cron.d/csfcron.sh" ]; then
	mv -fv /etc/cron.d/csfcron.sh /etc/cron.d/csf-cron
fi
if [ ! -e "/etc/cron.d/csf-cron" ]; then
	cp -avf csfcron.sh /etc/cron.d/csf-cron
fi
if [ -e "/etc/cron.d/lfdcron.sh" ]; then
	mv -fv /etc/cron.d/lfdcron.sh /etc/cron.d/lfd-cron
fi
if [ ! -e "/etc/cron.d/lfd-cron" ]; then
	cp -avf lfdcron.sh /etc/cron.d/lfd-cron
fi
sed -i "s%/etc/init.d/lfd restart%/usr/sbin/csf --lfd restart%" /etc/cron.d/lfd-cron
if [ -e "/usr/local/csf/bin/servercheck.pm" ]; then
	rm -f /usr/local/csf/bin/servercheck.pm
fi
if [ -e "/etc/csf/cseui.pl" ]; then
	rm -f /etc/csf/cseui.pl
fi
if [ -e "/etc/csf/csfui.pl" ]; then
	rm -f /etc/csf/csfui.pl
fi
if [ -e "/etc/csf/csfuir.pl" ]; then
	rm -f /etc/csf/csfuir.pl
fi
if [ -e "/usr/local/csf/bin/cseui.pl" ]; then
	rm -f /usr/local/csf/bin/cseui.pl
fi
if [ -e "/usr/local/csf/bin/csfui.pl" ]; then
	rm -f /usr/local/csf/bin/csfui.pl
fi
if [ -e "/usr/local/csf/bin/csfuir.pl" ]; then
	rm -f /usr/local/csf/bin/csfuir.pl
fi
if [ -e "/usr/local/csf/bin/regex.pm" ]; then
	rm -f /usr/local/csf/bin/regex.pm
fi

OLDVERSION=0
if [ -e "/etc/csf/version.txt" ]; then
    OLDVERSION=`head -n 1 /etc/csf/version.txt`
fi

rm -f /etc/csf/csf.pl /usr/sbin/csf /etc/csf/lfd.pl /usr/sbin/lfd
chmod 700 csf.pl lfd.pl
cp -avf csf.pl /usr/sbin/csf
cp -avf lfd.pl /usr/sbin/lfd
chmod 700 /usr/sbin/csf /usr/sbin/lfd
ln -svf /usr/sbin/csf /etc/csf/csf.pl
ln -svf /usr/sbin/lfd /etc/csf/lfd.pl
ln -svf /usr/local/csf/bin/csftest.pl /etc/csf/
ln -svf /usr/local/csf/bin/pt_deleted_action.pl /etc/csf/
ln -svf /usr/local/csf/bin/remove_apf_bfd.sh /etc/csf/
ln -svf /usr/local/csf/bin/uninstall.sh /etc/csf/
ln -svf /usr/local/csf/bin/regex.custom.pm /etc/csf/
ln -svf /usr/local/csf/lib/webmin /etc/csf/
if [ ! -e "/etc/csf/alerts" ]; then
    ln -svf /usr/local/csf/tpl /etc/csf/alerts
fi
chcon -h system_u:object_r:bin_t:s0 /usr/sbin/lfd
chcon -h system_u:object_r:bin_t:s0 /usr/sbin/csf

# The per-panel images/ directories are made here, from csf/, rather than
# shipped: they are install-time copies. Task 11 emptied csf/ down to the
# one file that still has a consumer - csf_small.png, the button icon that
# da/hooks/admin_img.html and da/hooks/reseller_img.html point at under
# /CMD_PLUGINS_ADMIN/csf/images/ - so only DirectAdmin's copy is still made.
# The ui/, webmin/csf/ and interworx/ copies held jQuery, Bootstrap, Chosen,
# configserver.css and the Fugue attribution file, and nothing reads any of
# them any more.
mkdir da/images

cp -avf csf/* da/images/

cp -avf messenger/*.php /etc/csf/messenger/
cp -avf uninstall.cyberpanel.sh /usr/local/csf/bin/uninstall.sh
cp -avf csftest.pl /usr/local/csf/bin/
cp -avf remove_apf_bfd.sh /usr/local/csf/bin/
cp -avf readme.txt /etc/csf/
cp -avf sanity.txt /usr/local/csf/lib/
cp -avf csf.rbls /usr/local/csf/lib/
cp -avf changelog.txt /etc/csf/
cp -avf downloadservers /etc/csf/
cp -avf install.txt /etc/csf/
cp -avf version.txt /etc/csf/
cp -avf license.txt /etc/csf/
cp -avf webmin /usr/local/csf/lib/
cp -avf ConfigServer /usr/local/csf/lib/
cp -avf Net /usr/local/csf/lib/
cp -avf Geo /usr/local/csf/lib/
cp -avf Crypt /usr/local/csf/lib/
cp -avf HTTP /usr/local/csf/lib/
cp -avf JSON /usr/local/csf/lib/
cp -avf version/* /usr/local/csf/lib/
cp -avf profiles /usr/local/csf/
cp -avf csf.conf /usr/local/csf/profiles/reset_to_defaults.conf
cp -avf lfd.logrotate /etc/logrotate.d/lfd
chcon --reference /etc/logrotate.d /etc/logrotate.d/lfd
cp -avf apf_stub.pl /etc/csf/

rm -fv /etc/csf/csf.spamhaus /etc/csf/csf.dshield /etc/csf/csf.tor /etc/csf/csf.bogon

###############################################################################
# Task 11 leftovers on an UPGRADED server.
#
# Added 2026-09-24. Every copy above is `cp -avf`, which overwrites and adds
# but never removes, so a server upgrading from an earlier release kept every
# file Task 11 deleted from the source tree. readme.txt and README.md
# document three of those leftovers as deliberately kept (/etc/csf/ui/,
# uialert.txt, ui-cert.sh - all operator-owned, all correctly left). The
# files below are NOT operator data: they are this package's own code and
# assets, they are inert at this release (nothing requires or references any
# of them), and leaving them made the branch's headline claim - "it was
# removed rather than patched", printed on nine panel pages - true of a
# fresh install and of the tarball but not of the server actually reading
# it. 4,218 lines of the Perl that used to render the root-run interface is
# the part of that which matters.
#
# migratedata.sh is not the place for this: it predates tpl/ and only
# touches /etc/csf/.
###############################################################################
rm -fv /usr/local/csf/lib/ConfigServer/DisplayUI.pm
rm -fv /usr/local/csf/lib/ConfigServer/cseUI.pm
rm -fv /usr/local/csf/lib/ConfigServer/DisplayResellerUI.pm
rm -fv /usr/local/csf/lib/csf.div
rm -fv /usr/local/csf/lib/restricted.txt
rm -fv /usr/local/csf/lib/csfajaxtail.js
rm -Rfv /var/lib/csf/ui

# The jQuery/Bootstrap/Chosen/Fugue tree, wherever an earlier release
# copied it. /etc/csf/ui/ ITSELF is left alone - it holds the operator's own
# ui.allow, ui.ban and TLS material, which readme.txt says are kept - but
# its images/ subdirectory was never anything but this package's copy of
# those libraries. csf_small.png is NOT in the list: it is still shipped and
# DirectAdmin's plugin buttons still point at it.
for d in \
    /etc/csf/ui/images \
    /etc/csf/webmin/csf/images \
    /usr/local/csf/lib/webmin/csf/images \
    /usr/local/CyberCP/configservercsf/static/configservercsf \
; do
    [ -d "$d" ] || continue
    rm -Rfv "$d/bootstrap"
    for a in LICENSE.txt admin_icon.svg reseller_icon.svg bootstrap-chosen.css \
        chosen-sprite.png "chosen-sprite@2x.png" chosen.min.css chosen.min.js \
        configserver.css csf-loader.gif csf.svg jquery.min.js loader.gif; do
        rm -fv "$d/$a"
    done
done

mkdir -p /usr/local/man/man1/
cp -avf csf.1.txt /usr/local/man/man1/csf.1
cp -avf csf.help /usr/local/csf/lib/
chmod 755 /usr/local/man/
chmod 755 /usr/local/man/man1/
chmod 644 /usr/local/man/man1/csf.1

chmod -R 600 /etc/csf
chmod -R 600 /var/lib/csf
chmod -R 600 /usr/local/csf/bin
chmod -R 600 /usr/local/csf/lib
chmod -R 600 /usr/local/csf/tpl
chmod -R 600 /usr/local/csf/profiles
chmod 600 /var/log/lfd.log*

chmod -v 700 /usr/local/csf/bin/*.pl /usr/local/csf/bin/*.sh /usr/local/csf/bin/*.pm
chmod -v 700 /etc/csf/*.pl /etc/csf/*.cgi /etc/csf/*.sh /etc/csf/*.php /etc/csf/*.py
chmod -v 700 /etc/csf/webmin/csf/index.cgi
chmod -v 644 /etc/cron.d/lfd-cron
chmod -v 644 /etc/cron.d/csf-cron

cp -avf csget.pl /etc/cron.daily/csget
chmod 700 /etc/cron.daily/csget
/etc/cron.daily/csget --nosleep

chmod -v 700 auto.cyberpanel.pl
./auto.cyberpanel.pl $OLDVERSION

if test `cat /proc/1/comm` = "systemd"
then
    if [ -e /etc/init.d/lfd ]; then
        if [ -f /etc/redhat-release ]; then
            /sbin/chkconfig csf off
            /sbin/chkconfig lfd off
            /sbin/chkconfig csf --del
            /sbin/chkconfig lfd --del
        elif [ -f /etc/debian_version ] || [ -f /etc/lsb-release ]; then
            update-rc.d -f lfd remove
            update-rc.d -f csf remove
        elif [ -f /etc/gentoo-release ]; then
            rc-update del lfd default
            rc-update del csf default
        elif [ -f /etc/slackware-version ]; then
            rm -vf /etc/rc.d/rc3.d/S80csf
            rm -vf /etc/rc.d/rc4.d/S80csf
            rm -vf /etc/rc.d/rc5.d/S80csf
            rm -vf /etc/rc.d/rc3.d/S85lfd
            rm -vf /etc/rc.d/rc4.d/S85lfd
            rm -vf /etc/rc.d/rc5.d/S85lfd
        else
            /sbin/chkconfig csf off
            /sbin/chkconfig lfd off
            /sbin/chkconfig csf --del
            /sbin/chkconfig lfd --del
        fi
        rm -fv /etc/init.d/csf
        rm -fv /etc/init.d/lfd
    fi

    mkdir -p /etc/systemd/system/
    mkdir -p /usr/lib/systemd/system/
    cp -avf lfd.service /usr/lib/systemd/system/
    cp -avf csf.service /usr/lib/systemd/system/

    chcon -h system_u:object_r:systemd_unit_file_t:s0 /usr/lib/systemd/system/lfd.service
    chcon -h system_u:object_r:systemd_unit_file_t:s0 /usr/lib/systemd/system/csf.service

    systemctl daemon-reload

    systemctl enable csf.service
    systemctl enable lfd.service

    systemctl disable firewalld
    systemctl stop firewalld
    systemctl mask firewalld
else
    cp -avf lfd.sh /etc/init.d/lfd
    cp -avf csf.sh /etc/init.d/csf
    chmod -v 755 /etc/init.d/lfd
    chmod -v 755 /etc/init.d/csf

    if [ -f /etc/redhat-release ]; then
        /sbin/chkconfig lfd on
        /sbin/chkconfig csf on
    elif [ -f /etc/debian_version ] || [ -f /etc/lsb-release ]; then
        update-rc.d -f lfd remove
        update-rc.d -f csf remove
        update-rc.d lfd defaults 80 20
        update-rc.d csf defaults 20 80
    elif [ -f /etc/gentoo-release ]; then
        rc-update add lfd default
        rc-update add csf default
    elif [ -f /etc/slackware-version ]; then
        ln -svf /etc/init.d/csf /etc/rc.d/rc3.d/S80csf
        ln -svf /etc/init.d/csf /etc/rc.d/rc4.d/S80csf
        ln -svf /etc/init.d/csf /etc/rc.d/rc5.d/S80csf
        ln -svf /etc/init.d/lfd /etc/rc.d/rc3.d/S85lfd
        ln -svf /etc/init.d/lfd /etc/rc.d/rc4.d/S85lfd
        ln -svf /etc/init.d/lfd /etc/rc.d/rc5.d/S85lfd
    else
        /sbin/chkconfig lfd on
        /sbin/chkconfig csf on
    fi
fi

chown -Rf root:root /etc/csf /var/lib/csf /usr/local/csf
chown -f root:root /usr/sbin/csf /usr/sbin/lfd /etc/logrotate.d/lfd /etc/cron.d/csf-cron /etc/cron.d/lfd-cron /usr/local/man/man1/csf.1 /usr/lib/systemd/system/lfd.service /usr/lib/systemd/system/csf.service /etc/init.d/lfd /etc/init.d/csf

mkdir -vp /usr/local/CyberCP/public/static/configservercsf/
cp -avf csf/* /usr/local/CyberCP/public/static/configservercsf/
cp -avf csf/* cyberpanel/configservercsf/static/configservercsf/
chmod 755 /usr/local/CyberCP/public/static/configservercsf/

cp cyberpanel/cyberpanel.pl /usr/local/csf/bin/
chmod 700 /usr/local/csf/bin/cyberpanel.pl
cp -avf cyberpanel/configservercsf /usr/local/CyberCP/

mkdir /home/cyberpanel/plugins
touch /home/cyberpanel/plugins/configservercsf

if ! cat /usr/local/CyberCP/CyberCP/settings.py | grep -q configservercsf; then
    sed -i "/pluginHolder/ i \ \ \ \ 'configservercsf'," /usr/local/CyberCP/CyberCP/settings.py
fi
if ! cat /usr/local/CyberCP/CyberCP/urls.py | grep -q configservercsf; then
    sed -i "/pluginHolder/ i \ \ \ \ url(r'^configservercsf/',include('configservercsf.urls'))," /usr/local/CyberCP/CyberCP/urls.py
fi
#if ! cat /usr/local/CyberCP/baseTemplate/templates/baseTemplate/index.html | grep -q configservercsf; then
#    sed -i "/url 'csf'/ i <li><a href='/configservercsf/' title='ConfigServer Security and Firewall'><span>ConfigServer Security \&amp; Firewall</span></a></li>" /usr/local/CyberCP/baseTemplate/templates/baseTemplate/index.html
#fi
if ! cat /usr/local/CyberCP/baseTemplate/templates/baseTemplate/index.html | grep -q configserver; then
    sed -i "/trans 'Plugins'/ i \{\% include \"/usr/local/CyberCP/configservercsf/templates/configservercsf/menu.html\" \%\}" /usr/local/CyberCP/baseTemplate/templates/baseTemplate/index.html
fi

service lscpd restart


# Added 2026-09-12 in https://github.com/nkyo/csf - see CHANGES.md.
#
# The replacement WebUI (docs/WEBUI-PLAN.md) - packaging only.
# task-9-brief.md: "A failure to set up the UI must not fail the install"
# (the firewall matters more than its optional UI) and "A non-interactive
# install enables neither mode" (an unattended run installs it disabled).
# Exit status is deliberately not checked here - see
# ui-src/dist/install-webui.sh's own header comment for why.
if [ -f "$CSF_SRC_ROOT/ui-src/dist/install-webui.sh" ]; then
	sh "$CSF_SRC_ROOT/ui-src/dist/install-webui.sh"
else
	echo "csf-ui: ui-src/dist/install-webui.sh not found under $CSF_SRC_ROOT - WebUI packaging was not run"
fi

echo
echo "Installation Completed"
echo
