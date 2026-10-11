#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
manifest=${1:?usage: build-classic-curl.sh MANIFEST [PREFIX] [JOBS]}
manifest=$(realpath "$manifest")
prefix=${2:-/usr/local}
jobs=${3:-2}
: "${CC:?explicit LLVM C compiler required}"
: "${CXX:?explicit LLVM C++ compiler required}"
: "${AR:?explicit LLVM archiver required}"
: "${RANLIB:?explicit LLVM ranlib required}"
# Libtool discovers its linker separately from Clang's driver configuration.
# Select the cohort's linker by name when the caller has not exported LD.
export LD=${LD:-ld.lld}
"${CC}" --version | grep -F "clang version 23.1.3" >/dev/null
"${CXX}" --version | grep -F "clang version 23.1.3" >/dev/null
"${LD}" --version | grep -E '^LLD 23\.1\.3([[:space:]]|$)' >/dev/null
cmake_tool_path() {
  local executable
  executable=$(command -v "$1") || return 1
  realpath -s -- "${executable}"
}
# Resolve each tool before constructing CMake arguments, so a missing tool
# terminates this script instead of leaving an empty cache variable.
cmake_cc=$(cmake_tool_path "${CC}")
cmake_cxx=$(cmake_tool_path "${CXX}")
cmake_ar=$(cmake_tool_path "${AR}")
cmake_ranlib=$(cmake_tool_path "${RANLIB}")
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
# Portable callers retain their explicit release optimization; ordinary Linux
# callers keep CMake's existing Release defaults when these variables are absent.
cares_release_flags=()
if [[ -n ${ATRINIK_RELEASE_C_FLAGS:-} ]]; then
  cares_release_flags+=("-DCMAKE_C_FLAGS_RELEASE=${ATRINIK_RELEASE_C_FLAGS}")
fi
if [[ -n ${ATRINIK_RELEASE_CXX_FLAGS:-} ]]; then
  cares_release_flags+=("-DCMAKE_CXX_FLAGS_RELEASE=${ATRINIK_RELEASE_CXX_FLAGS}")
fi
cmake -S "$work/c-ares-$(jq -r '.cares.version' "$manifest")" -B "$work/cares-build" \
  -DCMAKE_C_COMPILER="${cmake_cc}" -DCMAKE_CXX_COMPILER="${cmake_cxx}" \
  -DCMAKE_AR="${cmake_ar}" -DCMAKE_RANLIB="${cmake_ranlib}" \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$prefix" -DCMAKE_INSTALL_LIBDIR=lib \
  -DCARES_STATIC=OFF -DCARES_SHARED=ON -DCARES_BUILD_TOOLS=OFF -DCARES_BUILD_TESTS=OFF \
  "${cares_release_flags[@]}"
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
