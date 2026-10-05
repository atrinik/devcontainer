#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
prefix=${1:-/usr/local}
config="$prefix/share/atrinik/curl/curl_config.h"
grep -Eq '^#define USE_ARES 1$' "$config"
if grep -Eq '^#define USE_THREADS_(POSIX|WIN32) 1$' "$config"; then
  echo 'curl has a threaded resolver backend' >&2
  exit 1
fi
"$prefix/bin/curl-config" --configure | grep -F -- --disable-threaded-resolver
"$prefix/bin/curl-config" --ssl-backends | grep -Fx OpenSSL
features=$("$prefix/bin/curl-config" --features)
protocols=$("$prefix/bin/curl-config" --protocols)
for feature in AsynchDNS HTTP2 IDN PSL SSL libz brotli zstd; do
  grep -Fx "$feature" <<< "$features"
done
for protocol in HTTP HTTPS WS WSS; do
  grep -Fx "$protocol" <<< "$protocols"
done
if grep -Eq '^(LDAP|LDAPS|RTMP|RTMPS|RTMPE|RTMPT|RTMPTE|RTMPTS)$' <<< "$protocols"; then
  echo 'excluded LDAP or RTMP protocol present' >&2
  exit 1
fi
if [[ $prefix == /usr/local ]]; then
  test "$(pkg-config --modversion libcurl)" = 8.18.0
  test "$(pkg-config --variable=prefix libcurl)" = "$prefix"
  test "$(pkg-config --modversion libcares)" = 1.34.6
  test "$(pkg-config --modversion openssl)" = 3.5.5
  "$prefix/bin/curl" --version | grep -F 'c-ares/1.34.6'
  "$prefix/bin/curl" --version | grep -F 'OpenSSL/3.5.5'
else
  pkg=/opt/mxe/usr/bin/x86_64-w64-mingw32.shared-pkg-config
  test "$($pkg --modversion libcurl)" = 8.21.0
  test "$($pkg --modversion libcares)" = 1.34.6
  test "$($pkg --modversion openssl)" = 3.5.5
  test -f "$prefix/bin/libcares-2.dll"
fi
