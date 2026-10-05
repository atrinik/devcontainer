#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
manifest=${1:?usage: build-classic-curl.sh MANIFEST [PREFIX] [JOBS]}
manifest=$(realpath "$manifest")
prefix=${2:-/usr/local}
jobs=${3:-2}
test "$(pkg-config --modversion openssl)" = "$(jq -r '.linux.openssl_version' "$manifest")"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
fetch() {
  curl --fail --location --silent --show-error "$1" --output "$2"
  printf '%s  %s\n' "$3" "$2" | sha256sum --check --status
}
fetch "$(jq -r '.cares.url' "$manifest")" "$work/cares.tar.gz" "$(jq -r '.cares.sha256' "$manifest")"
fetch "$(jq -r '.linux.curl_url' "$manifest")" "$work/curl.tar.xz" "$(jq -r '.linux.curl_sha256' "$manifest")"
tar --no-same-owner -xf "$work/cares.tar.gz" -C "$work"
tar --no-same-owner -xf "$work/curl.tar.xz" -C "$work"
cmake -S "$work/c-ares-$(jq -r '.cares.version' "$manifest")" -B "$work/cares-build" \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$prefix" -DCMAKE_INSTALL_LIBDIR=lib \
  -DCARES_STATIC=OFF -DCARES_SHARED=ON -DCARES_BUILD_TOOLS=OFF -DCARES_BUILD_TESTS=OFF
cmake --build "$work/cares-build" --parallel "$jobs"
cmake --install "$work/cares-build"
cd "$work/curl-$(jq -r '.linux.curl_version' "$manifest")"
PKG_CONFIG_PATH="$prefix/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}" \
  ./configure --prefix="$prefix" --libdir="$prefix/lib" --with-openssl \
  --enable-ares="$prefix" --disable-threaded-resolver --disable-static --enable-versioned-symbols \
  --with-ca-bundle="$(jq -r '.linux.ca_bundle' "$manifest")" \
  --with-ca-path=/etc/ssl/certs --disable-ldap --disable-ldaps --without-librtmp
# ASYNCHDNS and a non-null ares field alone also describe newer hybrid backends.
# Reject the macros that take precedence over USE_ARES in curl_setup.h.
grep -Eq '^#define USE_ARES 1$' lib/curl_config.h
if grep -Eq '^#define USE_THREADS_(POSIX|WIN32) 1$' lib/curl_config.h; then
  echo 'threaded resolver compiled into curl' >&2
  exit 1
fi
make --jobs="$jobs"
make install
install -d "$prefix/share/atrinik/curl"
cp lib/curl_config.h "$prefix/share/atrinik/curl/curl_config.h"
cp config.log "$prefix/share/atrinik/curl/config.log"
cp "$manifest" "$prefix/share/atrinik/classic-curl-toolchain.json"
install -d "$prefix/share/licenses/curl" "$prefix/share/licenses/c-ares"
cp COPYING "$prefix/share/licenses/curl/COPYING"
cp "$work/c-ares-$(jq -r '.cares.version' "$manifest")/LICENSE.md" "$prefix/share/licenses/c-ares/LICENSE.md"
ldconfig
"$prefix/bin/curl-config" --configure | grep -F -- --disable-threaded-resolver
