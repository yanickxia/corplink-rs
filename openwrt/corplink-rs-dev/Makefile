include $(TOPDIR)/rules.mk

PKG_NAME:=corplink-rs-dev
PKG_VERSION:=6.6.0
PKG_RELEASE:=2
PKG_LICENSE:=GPL-2.0-or-later
PKG_MAINTAINER:=Yanick

include $(INCLUDE_DIR)/package.mk

CORPLINK_SCRIPTS:=$(CURDIR)/../scripts

define Package/corplink-rs-dev
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Corplink userspace SOCKS5 proxy and LuCI login bridge
  DEPENDS:=+ca-bundle +jsonfilter +rpcd
endef

define Package/corplink-rs-dev/description
  Corplink dev with login-only JSON events and a local rpcd manager.
  Pure SOCKS5 mode; does not install routes or alter system DNS.
endef

# Supply the architecture-matched output of the locked Rust/Go build.
# No release download or moving submodule ref is silently substituted.
define Build/Prepare
	$(call Build/Prepare/Default)
	test -n "$(CORPLINK_PREBUILT_DIR)"
	test -x "$(CORPLINK_PREBUILT_DIR)/corplink-rs-dev"
	test -x "$(CORPLINK_PREBUILT_DIR)/luci.corplink"
endef

define Build/Compile
endef

define Package/corplink-rs-dev/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/usr/libexec/rpcd $(1)/usr/share/corplink-rs-dev
	$(INSTALL_BIN) $(CORPLINK_PREBUILT_DIR)/corplink-rs-dev $(1)/usr/bin/
	$(INSTALL_BIN) $(CORPLINK_PREBUILT_DIR)/luci.corplink $(1)/usr/libexec/rpcd/
	# Install the init template in postinst, so SDK default_postinst cannot
	# automatically enable/start the VPN while scanning package-owned init files.
	$(INSTALL_BIN) ./files/corplink-rs-dev.init $(1)/usr/share/corplink-rs-dev/service.init
	$(INSTALL_BIN) $(CORPLINK_SCRIPTS)/core-post-install.sh $(1)/usr/share/corplink-rs-dev/post-install
	$(INSTALL_BIN) $(CORPLINK_SCRIPTS)/core-pre-remove.sh $(1)/usr/share/corplink-rs-dev/pre-remove
	$(INSTALL_DATA) $(CORPLINK_PREBUILT_DIR)/BUILD-INFO.json $(1)/usr/share/corplink-rs-dev/
endef

define Package/corplink-rs-dev/preinst
#!/bin/sh
[ -z "$${IPKG_INSTROOT:-}" ] || exit 0
umask 077
if [ -x /usr/bin/corplink-rs-dev ]; then
  mkdir -p /usr/share/corplink-rs-dev
  backup_dir="$$(mktemp -d /usr/share/corplink-rs-dev/backup-package-XXXXXX)" || exit 1
  cp -p /usr/bin/corplink-rs-dev "$$backup_dir/corplink-rs-dev" || exit 1
  [ ! -f /etc/init.d/corplink-rs-dev ] || cp -p /etc/init.d/corplink-rs-dev "$$backup_dir/init" || exit 1
  [ ! -f /usr/share/corplink-rs-dev/BUILD-INFO.json ] || cp -p /usr/share/corplink-rs-dev/BUILD-INFO.json "$$backup_dir/BUILD-INFO.json" || exit 1
fi
endef

define Package/corplink-rs-dev/postinst
#!/bin/sh
[ -z "$${IPKG_INSTROOT:-}" ] || exit 0
/usr/share/corplink-rs-dev/post-install || exit 1
cp -p /usr/share/corplink-rs-dev/service.init /etc/init.d/corplink-rs-dev
endef

define Package/corplink-rs-dev/prerm
#!/bin/sh
[ -z "$${IPKG_INSTROOT:-}" ] || exit 0
/usr/share/corplink-rs-dev/pre-remove
endef

define Package/corplink-rs-dev/postrm
#!/bin/sh
[ -z "$${IPKG_INSTROOT:-}" ] || exit 0
rm -f /etc/init.d/corplink-rs-dev
endef

# User configuration and cookies are created at runtime, never packaged.
define Package/corplink-rs-dev/conffiles
/etc/corplink-rs-dev/
endef

$(eval $(call BuildPackage,corplink-rs-dev))
