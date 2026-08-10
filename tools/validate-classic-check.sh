#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 CLASSIC_SOURCE" >&2
  exit 2
fi

source_root=$(realpath "$1")
jobs=$(nproc)

mkdir -p "${HOME}"

export CCACHE_BASEDIR=${source_root}
export CCACHE_COMPILERCHECK=content
export CCACHE_DIR=${CCACHE_DIR:-/cache/ccache}
export CCACHE_NOHASHDIR=true

ccache --zero-stats >/dev/null

for component in server client; do
  pushd "${source_root}/${component}" >/dev/null
  python3 -m unittest discover -s tools/tests -p 'test_*.py'
  python3 tools/dependencies.py sync
  python3 tools/dependencies.py verify
  cmake --preset linux-coverage \
    -DCMAKE_C_COMPILER_LAUNCHER=ccache \
    -DFETCHCONTENT_SOURCE_DIR_ATRINIK_PROTOCOL="${source_root}/protocol" \
    -DFETCHCONTENT_SOURCE_DIR_LIBATRINIK="${source_root}/libatrinik"
  cmake --build --preset linux-coverage --parallel "${jobs}"
  ctest --preset linux-coverage
  gcovr --root . --filter 'src/' --exclude 'src/tests/' \
    --print-summary --xml "${component}-coverage.xml"
  popd >/dev/null
done

cacheable_calls=$(ccache --print-stats | awk -F '\t' '
  $1 == "direct_cache_hit" || $1 == "preprocessed_cache_hit" \
      || $1 == "cache_miss" { calls += $2 }
  END { print calls + 0 }
')
if [[ ${cacheable_calls} -lt 1 ]]; then
  echo "Classic builds did not invoke ccache" >&2
  exit 1
fi

ccache --show-config
ccache --show-stats
