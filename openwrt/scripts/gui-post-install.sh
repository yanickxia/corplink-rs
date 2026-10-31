#!/bin/sh
[ -z "${IPKG_INSTROOT:-}" ] || exit 0
rm -f /tmp/luci-indexcache
rm -f /tmp/luci-indexcache.*.json
rm -rf /tmp/luci-modulecache
/etc/init.d/rpcd reload >/dev/null 2>&1 || true
exit 0
