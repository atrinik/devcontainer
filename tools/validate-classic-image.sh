#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 9 ]]; then
  echo "usage: $0 PACKAGE_LOCK EXPECTED_INVENTORY INSTALLED_INVENTORY AUDIO_INVENTORY DOCKERFILE SHADER_INVENTORY SHADER_INSTALLED SHADER_SPDX SHADER_SPDX_INSTALLED" >&2
  exit 2
fi

package_lock=$1
expected=$2
installed=$3
audio_inventory=$4
dockerfile=$5
shader_expected=$6
shader_installed=$7
shader_spdx_expected=$8
shader_spdx_installed=$9

cmp --silent "${expected}" "${installed}"
cmp --silent "${shader_expected}" "${shader_installed}"

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

jq -e '
  .schema_version == 1
  and .platform == "linux/amd64"
  and .target == "classic-final"
  and .image == "ghcr.io/atrinik/classic-build"
  and .dxc.repository == "microsoft/DirectXShaderCompiler"
  and .dxc.tag == "v1.9.2607"
  and .dxc.commit == "0d3ee6b551b8fa768fbf825300ebab81047ef6a8"
  and .dxc.url == "https://github.com/microsoft/DirectXShaderCompiler/releases/download/v1.9.2607/linux_dxc_2026_07_29.x86_x64.tar.gz"
  and .dxc.sha256 == "55665c87824051ed4774ff3280a79ccbbb7d39243b9736ca5e98222134112d54"
  and .dxc.archive_root == "linux_dxc_2026_07_29.x86_x64"
  and ([.dxc.files | to_entries[] | .key] | sort) == [
    "LICENCE-MIT.txt", "LICENSE-LLVM.txt", "LICENSE-MS.txt",
    "bin/dxc", "lib/libdxcompiler.so", "lib/libdxil.so"
  ]
  and .spirv_cross.repository == "KhronosGroup/SPIRV-Cross"
  and .spirv_cross.commit == "9c3c8e2cefdd8194b193bb8ed2fdff4d5527e382"
  and .spirv_cross.url == "https://codeload.github.com/KhronosGroup/SPIRV-Cross/tar.gz/9c3c8e2cefdd8194b193bb8ed2fdff4d5527e382"
  and .spirv_cross.sha256 == "78939435d588998e5174a7865ddd36b6d9d7cd05eafac42d42ef537ea770b40a"
  and .spirv_cross.license == "Apache-2.0"
  and .spirv_cross.license_path == "LICENSE"
  and .spirv_cross.license_sha256 == "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
  and .install.dxc.executable == "bin/dxc"
  and .install.dxc.libraries == ["lib/libdxcompiler.so", "lib/libdxil.so"]
  and .install.dxc.licenses == [
    {"archive_path":"LICENCE-MIT.txt", "destination":"share/licenses/dxc/LICENCE-MIT.txt"},
    {"archive_path":"LICENSE-LLVM.txt", "destination":"share/licenses/dxc/LICENSE-LLVM.txt"},
    {"archive_path":"LICENSE-MS.txt", "destination":"share/licenses/dxc/LICENSE-MS.txt"}
  ]
  and .install.spirv_cross == {
    "executable":"bin/spirv-cross",
    "license": {
      "archive_path":"LICENSE",
      "destination":"share/licenses/spirv-cross/LICENSE"
    }
  }
  and .runtime == {
    "vulkan_icd":"/usr/share/vulkan/icd.d/lvp_icd.json",
    "display_server":"Xvfb",
    "commands":["vulkaninfo", "Xvfb", "xvfb-run"]
  }
' "${shader_expected}" >/dev/null

jq -e --slurpfile inventory "${shader_expected}" '
  def manifest: $inventory[0];
  .spdxVersion == "SPDX-2.3"
  and .dataLicense == "CC0-1.0"
  and .SPDXID == "SPDXRef-DOCUMENT"
  and ([.packages[].name] | sort) == ["DirectXShaderCompiler", "SPIRV-Cross"]
  and ([.packages[].SPDXID] | unique | length) == 2
  and all(.packages[];
    .filesAnalyzed == false
    and (.checksums | length) == 1
    and .checksums[0].algorithm == "SHA256"
    and ((.name == "DirectXShaderCompiler"
        and .versionInfo == manifest.dxc.tag
        and .downloadLocation == manifest.dxc.url
        and .checksums[0].checksumValue == manifest.dxc.sha256
        and .licenseDeclared == "NOASSERTION")
      or
      (.name == "SPIRV-Cross"
        and .versionInfo == manifest.spirv_cross.commit
        and .downloadLocation == manifest.spirv_cross.url
        and .checksums[0].checksumValue == manifest.spirv_cross.sha256
        and .licenseDeclared == manifest.spirv_cross.license))
  )
  and .relationships == [
    {
      "spdxElementId":"SPDXRef-DOCUMENT",
      "relationshipType":"DESCRIBES",
      "relatedSpdxElement":"SPDXRef-Package-DirectXShaderCompiler"
    },
    {
      "spdxElementId":"SPDXRef-DOCUMENT",
      "relationshipType":"DESCRIBES",
      "relatedSpdxElement":"SPDXRef-Package-SPIRV-Cross"
    }
  ]
' "${shader_spdx_expected}" >/dev/null
cmp --silent "${shader_spdx_expected}" "${shader_spdx_installed}"

while IFS=$'\t' read -r relative digest; do
  case "${relative}" in
  bin/dxc|lib/libdxcompiler.so|lib/libdxil.so|LICENCE-MIT.txt|LICENSE-LLVM.txt|LICENSE-MS.txt) ;;
  *) echo "unexpected locked DXC member: ${relative}" >&2; exit 1 ;;
  esac
  installed_path="/usr/local/${relative}"
  test -f "${installed_path}"
  test "$(sha256sum "${installed_path}" | cut -d' ' -f1)" = "${digest}"
done < <(jq -r '.dxc.files | to_entries[]
  | select(.key == "bin/dxc" or (.key | startswith("lib/")))
  | [.key, .value] | @tsv' "${shader_expected}")

test -x /usr/local/bin/dxc
test -x /usr/local/bin/spirv-cross
dxc --version >/dev/null 2>&1
spirv-cross --help >/dev/null 2>&1

while IFS=$'\t' read -r command; do
  command -v "${command}" >/dev/null
done < <(jq -r '.runtime.commands[]' "${shader_expected}")
vulkan_icd=$(jq -er '.runtime.vulkan_icd' "${shader_expected}")
test -f "${vulkan_icd}"
VK_DRIVER_FILES="${vulkan_icd}" vulkaninfo --summary >/dev/null

while IFS=$'\t' read -r relative destination; do
  case "${relative}:${destination}" in
  LICENCE-MIT.txt:share/licenses/dxc/LICENCE-MIT.txt|\
  LICENSE-LLVM.txt:share/licenses/dxc/LICENSE-LLVM.txt|\
  LICENSE-MS.txt:share/licenses/dxc/LICENSE-MS.txt) ;;
  *) echo "unexpected DXC license destination: ${relative}:${destination}" >&2; exit 1 ;;
  esac
  test -f "/usr/local/${destination}"
  test "$(sha256sum "/usr/local/${destination}" | cut -d' ' -f1)" = \
    "$(jq -er --arg name "${relative}" '.dxc.files[$name]' "${shader_expected}")"
done < <(jq -r '.install.dxc.licenses[] | [.archive_path, .destination] | @tsv' "${shader_expected}")

spirv_license_destination=$(jq -er '.install.spirv_cross.license.destination' "${shader_expected}")
test -f "/usr/local/${spirv_license_destination}"
test "$(sha256sum "/usr/local/${spirv_license_destination}" | cut -d' ' -f1)" = \
  "$(jq -er '.spirv_cross.license_sha256' "${shader_expected}")"

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
