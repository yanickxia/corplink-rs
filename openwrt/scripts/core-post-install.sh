#!/bin/sh
set -eu
[ -z "${IPKG_INSTROOT:-}" ] || exit 0
umask 077
mkdir -p /etc/corplink-rs-dev
chmod 700 /etc/corplink-rs-dev
# APK protects files below /etc, including the previously hand-installed init.
# pre-install has already backed it up; apply the packaged service definition
# without calling procd or changing the saved configuration.
if [ -f /etc/init.d/corplink-rs-dev.apk-new ]; then
    chmod 755 /etc/init.d/corplink-rs-dev.apk-new
    mv /etc/init.d/corplink-rs-dev.apk-new /etc/init.d/corplink-rs-dev
fi
# Existing config, cookies, service state, and boot preference are preserved.
