#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 5 ]]; then
  echo "usage: $0 PACKAGE_LOCK EXPECTED_INVENTORY INSTALLED_INVENTORY AUDIO_INVENTORY DOCKERFILE" >&2
  exit 2
fi

package_lock=$1
expected=$2
installed=$3
audio_inventory=$4
dockerfile=$5

cmp --silent "${expected}" "${installed}"

jq -e '
  .schema_version == 1
  and .platform == "linux/amd64"
  and .target == "classic-final"
  and .image == "ghcr.io/atrinik/classic-build"
  and (.base.digest | test("^sha256:[0-9a-f]{64}$"))
  and (.base.apt_snapshot | test("^[0-9]{8}T[0-9]{6}Z$"))
  and .ccache.directory == "/cache/ccache"
  and .ccache.default_user == "ubuntu"
  and .ccache.compiler_launcher_required == true
  and .consumer_validation.repository == "atrinik/classic"
  and (.consumer_validation.commit | test("^[0-9a-f]{40}$"))
' "${expected}" >/dev/null

test "linux/$(dpkg --print-architecture)" = "$(jq -r '.platform' "${expected}")"
expected_image=$(jq -r '.base.image' "${expected}")
expected_digest=$(jq -r '.base.digest' "${expected}")
expected_snapshot=$(jq -r '.base.apt_snapshot' "${expected}")
grep -Fqx "FROM ${expected_image}@${expected_digest} AS classic-ci" "${dockerfile}"
test "${UBUNTU_SNAPSHOT}" = "${expected_snapshot}"
grep -Fq "https://snapshot.ubuntu.com/ubuntu/${expected_snapshot}/" \
  /etc/apt/sources.list.d/ubuntu.sources
test "$(grep -Fxc 'Check-Valid-Until: no' \
  /etc/apt/sources.list.d/ubuntu.sources)" -eq 2
if grep -Eq 'https?://(archive|security)\.ubuntu\.com/ubuntu/' \
  /etc/apt/sources.list.d/ubuntu.sources; then
  echo "mutable Ubuntu source remains configured" >&2
  exit 1
fi

while IFS='=' read -r package version; do
  if [[ -z ${package} || -z ${version} ]]; then
    echo "invalid package lock entry" >&2
    exit 1
  fi
  test "$(dpkg-query --show --showformat='${Version}' "${package}")" = "${version}"
done < "${package_lock}"

test "$(ccache --version | sed -n '1s/^ccache version //p')" = \
  "$(jq -r '.tools.ccache' "${expected}")"
test "$(cmake --version | sed -n '1s/^cmake version //p')" = \
  "$(jq -r '.tools.cmake' "${expected}")"
test "$(gcc -dumpfullversion)" = "$(jq -r '.tools.gcc' "${expected}")"
test "$(gcovr --version | sed -n '1s/^gcovr //p')" = \
  "$(jq -r '.tools.gcovr' "${expected}")"
test "$(ninja --version)" = "$(jq -r '.tools.ninja' "${expected}")"
test "$(python3 --version | cut -d' ' -f2)" = \
  "$(jq -r '.tools.python' "${expected}")"

test "${CCACHE_DIR}" = "$(jq -r '.ccache.directory' "${expected}")"
test -w "${CCACHE_DIR}"
test "$(stat --format='%a' "${CCACHE_DIR}")" = 1777

while IFS= read -r module; do
  pkg-config --exists "${module}"
done < <(jq -r '.pkg_config[]' "${expected}")

test "$(pkg-config --modversion sdl3-mixer)" = \
  "$(jq -r '.sdl_mixer.version' "${audio_inventory}")"
atrinik-sdl3-mixer-probe /usr/local/share/atrinik/audio/opus-probe.opus

work=$(mktemp -d)
trap 'rm -rf -- "${work}"' EXIT
printf 'int answer(void) { return 42; }\n' > "${work}/cache-smoke.c"
ccache --zero-stats >/dev/null
ccache gcc -c "${work}/cache-smoke.c" -o "${work}/cache-smoke.o"
rm "${work}/cache-smoke.o"
ccache gcc -c "${work}/cache-smoke.c" -o "${work}/cache-smoke.o"
hits=$(ccache --print-stats | awk -F '\t' '
  $1 == "direct_cache_hit" || $1 == "preprocessed_cache_hit" { hits += $2 }
  END { print hits + 0 }
')
test "${hits}" -ge 1
ccache --clear >/dev/null
