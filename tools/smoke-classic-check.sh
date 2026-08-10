#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 IMAGE CLASSIC_CHECKOUT" >&2
  exit 2
fi

image=$1
classic_checkout=$(realpath "$2")
image_checkout=$(git rev-parse --show-toplevel)

if [[ ! -f ${classic_checkout}/client/tools/build-windows-package.sh ||
    ! -f ${classic_checkout}/tools/ci/stage_windows_runtime.py ]]; then
  echo "CLASSIC_CHECKOUT is not an Atrinik Classic checkout" >&2
  exit 1
fi
expected_classic_commit=$(jq -er '.consumer.validation_commit' \
  "${image_checkout}/windows/classic-check-toolchain.json")
actual_classic_commit=$(git -C "${classic_checkout}" rev-parse HEAD)
if [[ ${actual_classic_commit} != "${expected_classic_commit}" ]]; then
  echo "CLASSIC_CHECKOUT is at ${actual_classic_commit}, expected ${expected_classic_commit}" >&2
  exit 1
fi
if ! git -C "${classic_checkout}" diff --quiet || \
    ! git -C "${classic_checkout}" diff --cached --quiet; then
  echo "CLASSIC_CHECKOUT has tracked changes" >&2
  exit 1
fi

python3 "${classic_checkout}/client/tools/dependencies.py" sync
umask 077
mkdir -p "${classic_checkout}/build"
discord_test_file=$(mktemp \
  "${classic_checkout}/build/discord-test-application-id.XXXXXX")
trap 'rm -f -- "${discord_test_file}"' EXIT
printf '%s\n' '123456789012345678' > "${discord_test_file}"
discord_test_relative=${discord_test_file#"${classic_checkout}/"}

docker run --rm --user "$(id -u):$(id -g)" --network none \
  --env CCACHE_DIR=/tmp/atrinik-classic-check-ccache \
  --env CCACHE_TEMPDIR=/tmp/atrinik-classic-check-ccache-tmp \
  --env CCACHE_MAXSIZE=250M \
  --env ATRINIK_PACKAGE_VERSION=0.0.0 \
  --env ATRINIK_DISCORD_APPLICATION_ID_FILE="/workspace/${discord_test_relative}" \
  --volume "${classic_checkout}:/workspace" \
  --volume "${image_checkout}:/image-source:ro" \
  --workdir /workspace \
  "${image}" \
  bash -euo pipefail -c '
    test "$(command -v ccache)" = /opt/mxe/.ccache/bin/ccache
    test "$(command -v x86_64-w64-mingw32.shared-gcc)" = \
      /opt/mxe/usr/bin/x86_64-w64-mingw32.shared-gcc
    test -w "${CCACHE_DIR%/*}"
    ccache --zero-stats
    python3 -c "import hashlib, json, pathlib, shutil, subprocess, tarfile, urllib.request, zipfile"
    cmp /image-source/windows/classic-check-toolchain.json \
      /usr/local/share/atrinik/classic-check-toolchain.json
    cmp /image-source/audio-toolchain.json \
      /usr/local/share/atrinik/audio-toolchain.json
    cmp /image-source/audio-toolchain.spdx.json \
      /usr/local/share/atrinik/audio-toolchain.spdx.json
    test ! -e /opt/mxe/python-runtime
    test ! -e "${MXE_PREFIX}/include/python3.14"
    test ! -e "${MXE_PREFIX}/lib/libpython314.dll.a"

    x86_64-w64-mingw32.shared-cmake \
      -S libatrinik \
      -B libatrinik/build/windows-tests \
      -G Ninja \
      -DBUILD_TESTING=ON \
      -DCMAKE_BUILD_TYPE=Release \
      -DATRINIK_PROTOCOL_SOURCE_DIR=/workspace/protocol
    cmake --build libatrinik/build/windows-tests \
      --target libatrinik-path libatrinik-rendezvous \
        libatrinik-metaserver-publisher libatrinik-metaserver-url \
        libatrinik-stun \
      --parallel "$(nproc)"

    cd client
    bash tools/build-windows-package.sh build/windows-pr-package
    mapfile -t packages < <(find build/windows-pr-package -maxdepth 1 -type f \
      -name "atrinik-classic-client-*-windows-x86_64.zip" -print)
    test "${#packages[@]}" -eq 1
    package=${packages[0]}
    python3 /image-source/tools/verify-classic-check-package.py \
      "${package}" x86_64-w64-mingw32.shared-objdump
    cd ..

    stage=libatrinik/build/windows-test-bundle
    cmake -E remove_directory "${stage}"
    python3 tools/ci/stage_windows_runtime.py \
      --objdump x86_64-w64-mingw32.shared-objdump \
      --runtime-dir "${MXE_RUNTIME_DIR}" \
      --output-dir "${stage}" \
      libatrinik/build/windows-tests/libatrinik-path.exe \
      libatrinik/build/windows-tests/libatrinik-rendezvous.exe \
      libatrinik/build/windows-tests/libatrinik-metaserver-publisher.exe \
      libatrinik/build/windows-tests/libatrinik-metaserver-url.exe \
      libatrinik/build/windows-tests/libatrinik-stun.exe \
      client/build/windows-release/client-rich-presence-tests.exe
    cmake -E copy_directory libatrinik/tests/fixtures "${stage}/fixtures"
    ccache --show-stats
  '

test -f "${classic_checkout}/libatrinik/build/windows-test-bundle/libatrinik-path.exe"
