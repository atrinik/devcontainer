#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 4 && $# -ne 5 ]]; then
  echo "usage: $0 EXPECTED INSTALLED SPDX_EXPECTED SPDX_INSTALLED [PACKAGE_LOCK]" >&2
  exit 2
fi

expected=$1
installed=$2
spdx_expected=$3
spdx_installed=$4
package_lock=${5:-}

for command in cmp jq readelf sha256sum vulkaninfo xvfb-run; do
  command -v "${command}" >/dev/null || {
    echo "required command is unavailable: ${command}" >&2
    exit 1
  }
done

cmp --silent "${expected}" "${installed}"
cmp --silent "${spdx_expected}" "${spdx_installed}"

jq -e '
  .schema_version == 1
  and .platform == "linux/amd64"
  and .target == "classic-final"
  and .image == "ghcr.io/atrinik/classic-build"
  and .base == {
    "image": "ubuntu:26.04",
    "digest": "sha256:678c6550cc43645e08669028bc177f50be4e7c5b8cca677067b1914d4afc7a03",
    "apt_snapshot": "20260810T000000Z"
  }
  and .source.repository == "mesa/mesa"
  and .source.tag == "mesa-26.0.8"
  and .source.version == "26.0.8"
  and .source.commit == "60e95b787857afbc9a00b693b91c0d9c8923a430"
  and .source.url == "https://archive.mesa3d.org/mesa-26.0.8.tar.xz"
  and .source.sha256 == "caf1c0061a68e88dfa74967a7e780c0e85d65b6c4e334cd69095a5dc54ad78bc"
  and .source.archive_root == "mesa-26.0.8"
  and .build.system == "meson"
  and .build.version == "1.10.1"
  and .build.package_lock == "classic-vulkan-packages.lock"
  and .build.configure == {
    "buildtype": "release",
    "libdir": "lib/x86_64-linux-gnu",
    "prefix": "/usr",
    "wrap_mode": "nodownload"
  }
  and .build.options.platforms == ["wayland"]
  and .build.options["gallium-drivers"] == ["d3d12"]
  and .build.options["vulkan-drivers"] == ["microsoft-experimental"]
  and .build.options["gallium-d3d12-graphics"] == "enabled"
  and .build.options["gallium-d3d12-video"] == "disabled"
  and .build.options.opengl == false
  and .build.options.llvm == "disabled"
  and .build.options["spirv-tools"] == "disabled"
  and .build.options["vulkan-manifest-per-architecture"] == true
  and .install == {
    "library": "/usr/lib/x86_64-linux-gnu/libvulkan_dzn.so",
    "icd": "/usr/share/vulkan/icd.d/dzn_icd.x86_64.json",
    "icd_library": "libvulkan_dzn.so",
    "icd_api_version": "1.1.335"
  }
  and .runtime.packages == [
    {"name": "libdrm2", "version": "2.4.131-1"},
    {"name": "libudev1", "version": "259.5-0ubuntu3.3"},
    {"name": "libvulkan1", "version": "1.4.341.0-1"},
    {"name": "libwayland-client0", "version": "1.24.0-2"},
    {"name": "mesa-vulkan-drivers", "version": "26.0.3-1ubuntu1"},
    {"name": "vulkan-tools", "version": "1.4.341.0+dfsg1-1"},
    {"name": "zlib1g", "version": "1:1.3.dfsg+really1.3.1-1ubuntu3"}
  ]
  and .runtime.shared_library_sonames == [
    "libc.so.6", "libdrm.so.2", "libgcc_s.so.1", "libm.so.6",
    "libudev.so.1", "libwayland-client.so.0", "libz.so.1"
  ]
  and .runtime.headless == {
    "vulkan_icd": "/usr/share/vulkan/icd.d/lvp_icd.json",
    "display_server": "Xvfb",
    "commands": ["vulkaninfo", "Xvfb", "xvfb-run"]
  }
  and .runtime.wslg.vulkan_icd == .install.icd
  and .runtime.wslg.required_mounts == [
    "/dev/dxg", "/mnt/wslg/runtime-dir", "/usr/lib/wsl"
  ]
  and .runtime.wslg.required_host_libraries == [
    "/usr/lib/wsl/lib/libd3d12.so", "/usr/lib/wsl/lib/libdxcore.so"
  ]
  and .runtime.wslg.consumer_environment == ["MESA_D3D12_DEFAULT_ADAPTER_NAME"]
  and .runtime.wslg.probe == ["vulkaninfo", "--summary"]
' "${expected}" >/dev/null

jq -e --slurpfile manifest "${expected}" '
  .spdxVersion == "SPDX-2.3"
  and .dataLicense == "CC0-1.0"
  and .SPDXID == "SPDXRef-DOCUMENT"
  and ([.packages[].name] == ["Mesa"])
  and ([.packages[].SPDXID] | unique | length) == 1
  and .packages[0].filesAnalyzed == false
  and .packages[0].versionInfo == $manifest[0].source.version
  and .packages[0].downloadLocation == $manifest[0].source.url
  and .packages[0].checksums == [{
    "algorithm": "SHA256",
    "checksumValue": $manifest[0].source.sha256
  }]
  and .packages[0].licenseConcluded == "NOASSERTION"
  and .packages[0].licenseDeclared == "NOASSERTION"
  and .relationships == [{
    "spdxElementId": "SPDXRef-DOCUMENT",
    "relationshipType": "DESCRIBES",
    "relatedSpdxElement": "SPDXRef-Package-Mesa"
  }]
' "${spdx_expected}" >/dev/null

library=$(jq -er '.install.library' "${expected}")
icd=$(jq -er '.install.icd' "${expected}")
headless_icd=$(jq -er '.runtime.headless.vulkan_icd' "${expected}")
test -f "${library}"
test ! -L "${library}"
test -f "${icd}"
test -f "${headless_icd}"

jq -e --arg library "${library}" \
  --arg api_version "$(jq -er '.install.icd_api_version' "${expected}")" '
  .file_format_version == "1.0.1"
  and .ICD.api_version == $api_version
  and .ICD.library_arch == "64"
  and .ICD.library_path == $library
' "${icd}" >/dev/null

while IFS= read -r soname; do
  readelf -d "${library}" | grep -Fq "Shared library: [${soname}]"
done < <(jq -er '.runtime.shared_library_sonames[]' "${expected}")

while IFS=$'\t' read -r package version; do
  test "$(dpkg-query --show --showformat='${Version}' "${package}")" = "${version}"
done < <(jq -er '.runtime.packages[] | [.name, .version] | @tsv' "${expected}")

if [[ -n ${package_lock} ]]; then
  while IFS='=' read -r package version; do
    if [[ -z ${package} || -z ${version} ]]; then
      echo "invalid package lock entry" >&2
      exit 1
    fi
    test "$(dpkg-query --show --showformat='${Version}' "${package}")" = "${version}"
  done < "${package_lock}"
fi

while IFS= read -r command; do
  command -v "${command}" >/dev/null
done < <(jq -er '.runtime.headless.commands[]' "${expected}")

VK_DRIVER_FILES="${headless_icd}" xvfb-run -a vulkaninfo --summary >/dev/null

wslg_ready=true
while IFS= read -r path; do
  if [[ ! -e ${path} ]]; then
    wslg_ready=false
  fi
done < <(jq -er '.runtime.wslg.required_mounts[]' "${expected}")
while IFS= read -r path; do
  if [[ ! -e ${path} ]]; then
    wslg_ready=false
  fi
done < <(jq -er '.runtime.wslg.required_host_libraries[]' "${expected}")

if [[ ${wslg_ready} == true && -n ${MESA_D3D12_DEFAULT_ADAPTER_NAME:-} ]]; then
  display=$(jq -er '.runtime.wslg.fixed_environment.DISPLAY' "${expected}")
  wayland_display=$(jq -er '.runtime.wslg.fixed_environment.WAYLAND_DISPLAY' "${expected}")
  runtime_dir=$(jq -er '.runtime.wslg.fixed_environment.XDG_RUNTIME_DIR' "${expected}")
  library_path=$(jq -er '.runtime.wslg.fixed_environment.LD_LIBRARY_PATH' "${expected}")
  gallium_driver=$(jq -er '.runtime.wslg.fixed_environment.GALLIUM_DRIVER' "${expected}")
  wslg_icd=$(jq -er '.runtime.wslg.vulkan_icd' "${expected}")
  probe_output=$(mktemp)
  trap 'rm -f -- "${probe_output}"' EXIT
  DISPLAY="${display}" \
    WAYLAND_DISPLAY="${wayland_display}" \
    XDG_RUNTIME_DIR="${runtime_dir}" \
    LD_LIBRARY_PATH="${library_path}" \
    GALLIUM_DRIVER="${gallium_driver}" \
    MESA_D3D12_DEFAULT_ADAPTER_NAME="${MESA_D3D12_DEFAULT_ADAPTER_NAME}" \
    VK_DRIVER_FILES="${wslg_icd}" \
    vulkaninfo --summary | tee "${probe_output}"
  grep -Fq "Microsoft Direct3D12" "${probe_output}"
  grep -Fq "Mesa Dozen" "${probe_output}"
else
  echo "WSLg Dozen probe skipped: WSLg mounts/libraries or consumer adapter selection are unavailable" >&2
fi
