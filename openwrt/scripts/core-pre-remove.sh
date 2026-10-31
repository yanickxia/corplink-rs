#!/bin/sh
[ -z "${IPKG_INSTROOT:-}" ] || exit 0
/usr/libexec/rpcd/luci.corplink shutdown >/dev/null 2>&1 || true
/etc/init.d/corplink-rs-dev stop >/dev/null 2>&1 || true
/etc/init.d/corplink-rs-dev disable >/dev/null 2>&1 || true
# Configuration and credential backups are intentionally retained.
exit 0
