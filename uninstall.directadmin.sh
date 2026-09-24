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


sed -i 's/lfd=ON/lfd=OFF/' /usr/local/directadmin/data/admin/services.status

/usr/sbin/csf -f

if test `cat /proc/1/comm` = "systemd"
then
    systemctl disable csf.service
    systemctl disable lfd.service
    systemctl stop lfd.service
    systemctl stop csf.service

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

rm -fv /etc/chkserv.d/lfd
rm -fv /usr/sbin/csf
rm -fv /usr/sbin/lfd
rm -fv /etc/cron.d/csf_update
rm -fv /etc/cron.d/lfd-cron
rm -fv /etc/cron.d/csf-cron
rm -Rfv /usr/local/directadmin/plugins/csf
rm -fv /etc/logrotate.d/lfd
rm -fv /usr/local/man/man1/csf.man.1

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

rm -Rfv /usr/local/csf-ui /etc/csf-ui /var/lib/csf-ui /var/run/csf-ui /run/csf-ui-web

# The unprivileged account and the two groups the installer created. Not
# fatal if either refuses - a uid still owning something elsewhere is a
# reason to stop, not a reason to force.
userdel csfui 2>/dev/null
groupdel csfui 2>/dev/null
groupdel csf-ui-sock 2>/dev/null

echo
echo "csf-ui: removed. /etc/csf-ui is gone, including its account hashes and"
echo "csf-ui: TLS private key. The audit and access logs were kept:"
echo "csf-ui:   /var/log/csf-ui-audit.log"
echo "csf-ui:   /var/log/csf-ui-access.log"
echo "csf-ui: If a web server was proxying to it, reload that web server -"
echo "csf-ui: its configuration file is gone but it is still running the copy"
echo "csf-ui: it parsed at startup."

echo
echo "...Done"
