#!/usr/bin/env bash
set -euo pipefail
root=/opt/atrinik-portable
test "$(id -u)" != 0
test ! -d /usr/lib/x86_64-linux-gnu/dri
test ! -d /usr/lib/dri
test ! -e /usr/local/bin/dxc
test ! -e /usr/local/lib/libdxcompiler.so
test ! -e /usr/local/lib/libdxil.so
test "$(getconf GNU_LIBC_VERSION)" = 'glibc 2.36'
work=$(mktemp -d)
trap 'rm -rf -- "${work}"' EXIT
cd "${work}"
python3 "${root}/abi.py" --output abi.json
"${root}/audio/sdl3-mixer-probe" "${root}/audio/opus-probe.opus"
# pkg-config emits flags for the pinned build inputs; no user-provided shell code.
read -r -a media_flags <<< "$(pkg-config --cflags --libs sdl3-image sdl3-ttf)"
cc -O2 -march=x86-64 -mtune=generic "${root}/media-smoke.c" \
  -o media-smoke "${media_flags[@]}"
./media-smoke /usr/share/fonts/truetype/dejavu/DejaVuSans.ttf
openssl list -providers -provider default -provider legacy > providers.txt
grep -q 'OpenSSL Default Provider' providers.txt
grep -q 'OpenSSL Legacy Provider' providers.txt
python3 "${root}/abi.py" --output media-abi.json ./media-smoke
(cd "${root}/shaders" && sha256sum -c SHA256SUMS)
