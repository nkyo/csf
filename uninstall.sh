#!/bin/sh
echo "Uninstalling csf and lfd..."
echo

###############################################################################
# csf-ui (the replacement WebUI) - STOP FIRST.
#
# Added 2026-09-24. No uninstall script mentioned csf-ui at all, and
# ui-src/dist/install-webui.sh had no uninstall path, so `csf -u` left the
# entire WebUI installed, enabled and RUNNING: both units up, the front
# server still proxying to them, the csfui account still there, and the
# ROOT HELPER still listening on its unix socket - talking to a /usr/sbin/csf
# this script is about to delete. Every privileged operation it accepts
# would then fail in whatever way exec'ing a missing binary fails, on a
# server whose administrator believes csf is gone.
#
# The two units are stopped here, at the top, BEFORE /usr/sbin/csf is
# removed, rather than with the file removal at the foot of this script.
# Between those two points is exactly the window the paragraph above
# describes, and it costs nothing to close it.
###############################################################################
if test `cat /proc/1/comm` = "systemd"
then
    systemctl disable --now csf-ui.service 2>/dev/null
    systemctl disable --now csf-ui-helper.service 2>/dev/null
    # csf-ui-rollback.timer (Rollback.pm arm()) is a THIRD independent unit -
    # written to /etc/systemd/system, not /usr/lib/systemd/system where the
    # two units above live. Left armed, it survives everything below: with
    # OnBootSec=60 it re-fires on every subsequent boot, forever, once this
    # script deletes the snapshot and setup binary its ExecStart points at.
    # Disabled here, before /usr/sbin/csf is removed, same as the two above.
    systemctl disable --now csf-ui-rollback.timer 2>/dev/null
else
    # No systemd. Nothing enabled these, because install-webui.sh only
    # enables them through systemctl, but something may still have started
    # them by hand. Deliberately NOT killed by a name pattern: there is no
    # pattern for "csf-ui" narrow enough to be safe on a machine this
    # script has never seen, and killing the wrong process during an
    # uninstall is unrecoverable. Reported instead, with the exact paths.
    echo "csf-ui: no systemd here - if either of these is running, stop it by hand:"
    echo "csf-ui:   /usr/local/csf-ui/bin/csf-ui-helper   (root; the privileged half)"
    echo "csf-ui:   /usr/local/csf-ui/bin/csf-ui          (the csfui user)"
fi


/usr/sbin/csf -f

if test `cat /proc/1/comm` = "systemd"
then
    systemctl disable csf.service
    systemctl disable lfd.service
    systemctl stop csf.service
    systemctl stop lfd.service

    rm -fv /usr/lib/systemd/system/csf.service
    rm -fv /usr/lib/systemd/system/lfd.service
    systemctl daemon-reload
else
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

if [ -e "/usr/local/cpanel/bin/unregister_appconfig" ]; then
    cd /
	/usr/local/cpanel/bin/unregister_appconfig csf
fi

rm -fv /etc/chkserv.d/lfd
rm -fv /usr/sbin/csf
rm -fv /usr/sbin/lfd
rm -fv /etc/cron.d/csf_update
rm -fv /etc/cron.d/lfd-cron
rm -fv /etc/cron.d/csf-cron
rm -fv /etc/logrotate.d/lfd
rm -fv /usr/local/man/man1/csf.man.1

/bin/rm -fv /usr/local/cpanel/whostmgr/docroot/cgi/addon_csf.cgi
/bin/rm -Rfv /usr/local/cpanel/whostmgr/docroot/cgi/csf

/bin/rm -fv /usr/local/cpanel/whostmgr/docroot/cgi/configserver/csf.cgi
/bin/rm -Rfv /usr/local/cpanel/whostmgr/docroot/cgi/configserver/csf

/bin/rm -fv /usr/local/cpanel/Cpanel/Config/ConfigObj/Driver/ConfigServercsf.pm
/bin/rm -Rfv /usr/local/cpanel/Cpanel/Config/ConfigObj/Driver/ConfigServercsf
/bin/touch /usr/local/cpanel/Cpanel/Config/ConfigObj/Driver

rm -fv /var/run/chkservd/lfd
sed -i 's/lfd:1//' /etc/chkserv.d/chkservd.conf
/scripts/restartsrv_chkservd

rm -Rfv /etc/csf /usr/local/csf /var/lib/csf

###############################################################################
# csf-ui - REMOVE. See the "STOP FIRST" block at the head of this script.
#
# WHAT IS REMOVED AND WHY THE ACCOUNT HASHES AND TLS KEY ARE AMONG THEM.
# This script already does `rm -Rf /etc/csf`, which takes csf.conf, csf.allow
# and csf.deny - an operator's own configuration - so leaving /etc/csf-ui in
# place would not be consistency, it would be an exception. It would also
# leave a TLS PRIVATE KEY and a set of $6$ password hashes on a server that
# no longer has the software that uses them, which is worse than removing
# them: they are dead credentials nobody is watching any more. Everything
# removed is named in the output, so it is a statement rather than a
# surprise.
#
# NOT removed: /var/log/csf-ui-audit.log and /var/log/csf-ui-access.log.
# They are the record of what was done through the interface, this script
# does not remove /var/log/lfd.log either, and a log outliving its program
# is the normal and useful case.
###############################################################################
rm -fv /usr/lib/systemd/system/csf-ui.service
rm -fv /usr/lib/systemd/system/csf-ui-helper.service
# csf-ui-rollback.service/.timer (Rollback.pm arm()) live in
# /etc/systemd/system - a different directory from the two units above.
# Disabled already, up in the STOP FIRST block; removing the files here
# is what stops them surviving a reboot.
rm -fv /etc/systemd/system/csf-ui-rollback.timer
rm -fv /etc/systemd/system/csf-ui-rollback.service
if test `cat /proc/1/comm` = "systemd"
then
    systemctl daemon-reload 2>/dev/null
fi

# The front server's vhost, written by install-webui.sh's Mode A path. It
# is the reason an uninstalled WebUI can still answer on its port. Removing
# the file is not enough on its own - the front server holds its parsed
# configuration until it reloads - so this says so rather than implying the
# port is closed.
rm -fv /etc/nginx/conf.d/csf-ui.conf
rm -fv /etc/apache2/conf-available/csf-ui.conf
rm -fv /etc/apache2/conf-enabled/csf-ui.conf
rm -fv /etc/httpd/conf.d/csf-ui.conf
rm -Rfv /usr/local/lsws/conf/vhosts/csf-ui

# Captured before the rm below, because there is nothing left to test once
# it has run. Two things the closing message must not get wrong: whether
# /etc/csf-ui was here at all (a host that never had csf-ui, or a second
# run of this script, has nothing to claim was deleted), and whether it was
# a symlink - `rm -Rfv` removes a symlink itself, not whatever it points
# at, so the account hashes and TLS key living at the real target are
# untouched by this script even though the path is gone.
CSF_UI_ETC_LINK=0
test -L /etc/csf-ui && CSF_UI_ETC_LINK=1
CSF_UI_ETC_PRESENT=0
{ [ -e /etc/csf-ui ] || [ "$CSF_UI_ETC_LINK" = 1 ]; } && CSF_UI_ETC_PRESENT=1

rm -Rfv /usr/local/csf-ui /etc/csf-ui /var/lib/csf-ui /var/run/csf-ui /run/csf-ui-web

# The unprivileged account and the two groups the installer created. Not
# fatal if either refuses - a uid still owning something elsewhere is a
# reason to stop, not a reason to force.
userdel csfui 2>/dev/null
groupdel csfui 2>/dev/null
groupdel csf-ui-sock 2>/dev/null

echo
if [ "$CSF_UI_ETC_LINK" = 1 ]; then
    echo "csf-ui: /etc/csf-ui was a symlink - only the link was removed, not"
    echo "csf-ui: whatever it pointed at. If that target still holds account"
    echo "csf-ui: hashes or a TLS private key, remove it yourself."
elif [ "$CSF_UI_ETC_PRESENT" = 1 ]; then
    echo "csf-ui: removed. /etc/csf-ui is gone, including its account hashes"
    echo "csf-ui: and TLS private key."
else
    echo "csf-ui: nothing to remove - /etc/csf-ui was not present."
fi
if [ -f /var/log/csf-ui-audit.log ] || [ -f /var/log/csf-ui-access.log ]; then
    echo "csf-ui: The audit and/or access log was kept:"
    [ -f /var/log/csf-ui-audit.log ]  && echo "csf-ui:   /var/log/csf-ui-audit.log"
    [ -f /var/log/csf-ui-access.log ] && echo "csf-ui:   /var/log/csf-ui-access.log"
fi
echo "csf-ui: If a web server was proxying to it, reload that web server -"
echo "csf-ui: its configuration file is gone but it is still running the copy"
echo "csf-ui: it parsed at startup."

echo
echo "...Done"
