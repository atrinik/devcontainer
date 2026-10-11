#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 CLASSIC_SOURCE" >&2
  exit 2
fi

source_root=$(realpath "$1")
jobs=$(nproc)

export ATRINIK_LLVM_TOOLCHAIN=1
export CC=clang CXX=clang++ AR=llvm-ar RANLIB=llvm-ranlib
python3 /usr/local/bin/atrinik-validate-llvm-toolchain \
  --manifest /opt/llvm-23.1.3/share/atrinik/llvm-toolchain.json --prefix /opt/llvm-23.1.3
test -f "${source_root}/cmake/toolchains/llvm.cmake"
test -f "${source_root}/tools/ci/llvm_coverage.py"

mkdir -p "${HOME}"

export CCACHE_BASEDIR=${source_root}
export CCACHE_COMPILERCHECK=content
export CCACHE_DIR=${CCACHE_DIR:-/cache/ccache}
export CCACHE_NOHASHDIR=true

test -w "${CCACHE_DIR}"
test "$(stat --format='%a' "${CCACHE_DIR}")" = 1777

ccache_hits() {
  ccache --print-stats | awk -F '\t' '
    $1 == "direct_cache_hit" || $1 == "preprocessed_cache_hit" { hits += $2 }
    END { print hits + 0 }
  '
}

ccache --zero-stats >/dev/null

for component in server client; do
  pushd "${source_root}/${component}" >/dev/null
  python3 -m unittest discover -s tools/tests -p 'test_*.py'
  python3 tools/dependencies.py sync
  python3 tools/dependencies.py verify
  cmake --preset linux-coverage \
    -DCMAKE_TOOLCHAIN_FILE="${source_root}/cmake/toolchains/llvm.cmake" \
    -DCMAKE_C_COMPILER_LAUNCHER=ccache \
    -DFETCHCONTENT_SOURCE_DIR_ATRINIK_PROTOCOL="${source_root}/protocol" \
    -DFETCHCONTENT_SOURCE_DIR_LIBATRINIK="${source_root}/libatrinik"
  # Populate the dedicated cache deterministically even when the mounted source
  # checkout already contains build outputs from an earlier validation.
  cmake --build --preset linux-coverage --clean-first --parallel "${jobs}"
  python3 "${source_root}/tools/ci/llvm_coverage.py" prepare \
    --build-dir build/linux-coverage
  ctest --preset linux-coverage
  python3 "${source_root}/tools/ci/llvm_coverage.py" export \
    --build-dir build/linux-coverage --source-root "${source_root}" \
    --component "${component}" --output "${component}-coverage.lcov"
  test -s "${component}-coverage.lcov"
  # Force one identical rebuild against the mounted cache. A no-op incremental
  # build would not prove that consumer compiler outputs can be restored.
  warm_hits_before=$(ccache_hits)
  cmake --build --preset linux-coverage --clean-first --parallel "${jobs}"
  warm_hits_after=$(ccache_hits)
  if [[ ${warm_hits_after} -le ${warm_hits_before} ]]; then
    echo "Classic ${component} warm rebuild restored no compiler outputs from ccache" >&2
    exit 1
  fi
  popd >/dev/null
done

ccache --show-config
ccache --show-stats
