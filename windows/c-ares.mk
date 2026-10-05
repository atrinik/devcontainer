# Atrinik c-ares MXE recipe. SPDX-License-Identifier: MIT
PKG             := c-ares
$(PKG)_WEBSITE  := https://c-ares.org/
$(PKG)_DESCR    := asynchronous DNS resolver
$(PKG)_VERSION  := 1.34.6
$(PKG)_CHECKSUM := 912dd7cc3b3e8a79c52fd7fb9c0f4ecf0aaa73e45efda880266a2d6e26b84ef5
$(PKG)_SUBDIR   := c-ares-$($(PKG)_VERSION)
$(PKG)_FILE     := c-ares-$($(PKG)_VERSION).tar.gz
$(PKG)_URL      := https://github.com/c-ares/c-ares/releases/download/v$($(PKG)_VERSION)/$($(PKG)_FILE)
$(PKG)_DEPS     := cc

define $(PKG)_BUILD
    cd '$(BUILD_DIR)' && $(SOURCE_DIR)/configure \
        $(MXE_CONFIGURE_OPTS) --disable-tests --disable-tools
    $(MAKE) -C '$(BUILD_DIR)' -j '$(JOBS)'
    $(MAKE) -C '$(BUILD_DIR)' -j 1 install
endef
