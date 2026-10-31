include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI support for the Corplink SOCKS5 proxy
LUCI_DEPENDS:=+corplink-rs-dev
LUCI_PKGARCH:=all
PKG_VERSION:=1.0.0
PKG_RELEASE:=2
PKG_LICENSE:=GPL-2.0-or-later

# Keep this repository's openwrt directory together under package/corplink.
LUCI_MK?=$(TOPDIR)/feeds/luci/luci.mk
include $(LUCI_MK)
