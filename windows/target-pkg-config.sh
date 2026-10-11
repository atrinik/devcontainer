#!/usr/bin/env sh
# Copyright 2026 The Atrinik Project
set -eu
export PKG_CONFIG_LIBDIR=/opt/atrinik-windows/lib/pkgconfig:/opt/atrinik-windows/share/pkgconfig
unset PKG_CONFIG_PATH
exec /usr/bin/pkg-config "$@"
