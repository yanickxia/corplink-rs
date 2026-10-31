#!/bin/sh
set -eu
[ -z "${IPKG_INSTROOT:-}" ] || exit 0
umask 077
# Preserve the previously installed executable; never stop a running tunnel.
if [ -x /usr/bin/corplink-rs-dev ]; then
    mkdir -p /usr/share/corplink-rs-dev
    backup_dir="$(mktemp -d /usr/share/corplink-rs-dev/backup-package-XXXXXX)"
    cp -p /usr/bin/corplink-rs-dev "$backup_dir/corplink-rs-dev"
    if [ -f /etc/init.d/corplink-rs-dev ]; then
        cp -p /etc/init.d/corplink-rs-dev "$backup_dir/init"
    fi
    if [ -f /usr/share/corplink-rs-dev/BUILD-INFO.json ]; then
        cp -p /usr/share/corplink-rs-dev/BUILD-INFO.json "$backup_dir/BUILD-INFO.json"
    fi
fi
