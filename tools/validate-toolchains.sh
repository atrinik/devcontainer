#!/usr/bin/env bash
set -euo pipefail

expected=${1:-toolchains.json}
installed=${2:-}
audio_expected=${3:-audio-toolchain.json}
audio_installed=${4:-}
audio_sbom_expected=${5:-audio-toolchain.spdx.json}
audio_sbom_installed=${6:-}
classic_check_expected=${7:-}
classic_check_installed=${8:-}

if [[ -n ${classic_check_expected} ]]; then
  jq -e '
  .schema_version == 1
  and .platform == "linux/amd64"
  and (.tools | keys == [
    "buf", "go", "node", "pnpm", "protoc", "protoc-gen-go",
    "protoc-gen-prost", "rust", "rustup", "syft", "trivy"
  ])
  and (.consumers | length == 7)
  and (.graphics.headless_validation == true)
  and (.graphics.virtual_display == "Xvfb")
' "${expected}" >/dev/null

if [[ -n ${installed} ]]; then
  cmp --silent "${expected}" "${installed}"

  test "$(go env GOVERSION)" = "go$(jq -r '.tools.go' "${expected}")"
  test "$(rustc --version | cut -d' ' -f2)" = \
    "$(jq -r '.tools.rust' "${expected}")"
  test "$(node --version)" = "v$(jq -r '.tools.node' "${expected}")"
  test "$(pnpm --version)" = "$(jq -r '.tools.pnpm' "${expected}")"
  test "$(protoc --version)" = \
    "libprotoc $(jq -r '.tools.protoc' "${expected}")"
  test "$(buf --version)" = "$(jq -r '.tools.buf' "${expected}")"
  test "$(protoc-gen-go --version)" = \
    "protoc-gen-go v$(jq -r '.tools["protoc-gen-go"]' "${expected}")"
  test "$(protoc-gen-prost --version)" = \
    "$(jq -r '.tools["protoc-gen-prost"]' "${expected}")"
  test "$(syft version -o json | jq -r '.version')" = \
    "$(jq -r '.tools.syft' "${expected}")"
  test "$(trivy --version | sed -n '1s/^Version: //p')" = \
    "$(jq -r '.tools.trivy' "${expected}")"
  command -v Xvfb >/dev/null
  command -v xvfb-run >/dev/null
fi

jq -e '
  .schema_version == 1
  and .sdl_mixer.name == "SDL3_mixer"
  and .sdl_mixer.version == "3.2.4"
  and .sdl_mixer.linkage == "shared"
  and .sdl_mixer.codec_linkage == "static"
  and .sdl_mixer.required_decoders == ["WAV", "STBVORBIS", "OPUS", "DRMP3"]
  and .sdl_mixer.forbidden_decoders == ["FLUIDSYNTH", "GME", "TIMIDITY", "XMP"]
  and ([.dependencies[].name] == ["libogg", "libopus", "libopusfile"])
  and all(.dependencies[];
    .license == "BSD-3-Clause"
    and .linkage == "static"
    and (.source.commit | test("^[0-9a-f]{40}$"))
    and (.source.sha256 | test("^[0-9a-f]{64}$")))
  and .fixture.license == "MIT"
  and (.fixture.sha256 | test("^[0-9a-f]{64}$"))
  and .windows.codec_runtime_dlls == []
  and .windows.support_runtime_dlls == ["libssp-0.dll"]
  and .windows.sdl_mixer_imports == [
    "KERNEL32.dll", "libssp-0.dll", "msvcrt.dll", "SDL3.dll"
  ]
  and .windows.support_runtime_imports == {
    "libssp-0.dll": ["ADVAPI32.dll", "KERNEL32.dll", "msvcrt.dll"]
  }
' "${audio_expected}" >/dev/null

if [[ -n ${audio_installed} ]]; then
  cmp --silent "${audio_expected}" "${audio_installed}"
fi

jq -e --slurpfile inventory "${audio_expected}" '
  ($inventory[0].dependencies + [$inventory[0].sdl_mixer]) as $expected
  |
  .spdxVersion == "SPDX-2.3"
  and .dataLicense == "CC0-1.0"
  and .SPDXID == "SPDXRef-DOCUMENT"
  and ([.packages[].name] ==
    ["SDL3_mixer", "libogg", "libopus", "libopusfile"])
  and ([.packages[].SPDXID] | unique | length) == 4
  and all(.packages[];
    . as $package
    | .filesAnalyzed == false
      and (.checksums | length) == 1
      and .checksums[0].algorithm == "SHA256"
      and .licenseConcluded == .licenseDeclared
    | any($expected[];
      .name == $package.name
        and .version == $package.versionInfo
        and .source.url == $package.downloadLocation
        and .source.sha256 == $package.checksums[0].checksumValue
        and .license == $package.licenseDeclared))
  and .relationships == [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-Package-SDL3-mixer"
    },
    {
      "spdxElementId": "SPDXRef-Package-SDL3-mixer",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-Package-libogg"
    },
    {
      "spdxElementId": "SPDXRef-Package-SDL3-mixer",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-Package-libopus"
    },
    {
      "spdxElementId": "SPDXRef-Package-SDL3-mixer",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-Package-libopusfile"
    }
  ]
' "${audio_sbom_expected}" >/dev/null

if [[ -n ${audio_sbom_installed} ]]; then
  cmp --silent "${audio_sbom_expected}" "${audio_sbom_installed}"
fi

jq -e '
  .schema_version == 1
  and .target == "classic-check"
  and .consumer.repository == "atrinik/classic"
  and (.consumer.validation_commit | test("^[0-9a-f]{40}$"))
  and .base.digest == "sha256:73d85a96694a2cadca1ba3fcb5721f2312a64f1d571dd86f6c77e10a708931dc"
  and .host_packages == [
    "ca-certificates", "cmake", "git", "ninja-build", "python3"
  ]
  and .mxe.commit == "8784776b145a8ddd350ce32aa0908ac10977060c"
  and .mxe.target == "x86_64-w64-mingw32.shared"
  and .mxe.ccache_path == "/opt/mxe/.ccache/bin/ccache"
  and .mxe.runtime_directory == "/opt/mxe/usr/x86_64-w64-mingw32.shared/bin"
  and (.mxe.packages | index("cc") != null)
  and (.mxe.packages | index("curl") != null)
  and (.mxe.packages | index("libidn2") != null)
  and (.mxe.packages | index("libxml2") != null)
  and (.mxe.packages | index("openssl") != null)
  and (.mxe.packages | index("sdl3") != null)
  and (.mxe.packages | index("sdl3_image") != null)
  and (.mxe.packages | index("sdl3_ttf") != null)
  and (.mxe.packages | index("zlib") != null)
  and (.mxe.additional_libraries | index("SDL3_mixer") != null)
  and .runtime_contract.inventory == "/usr/local/share/atrinik/audio-toolchain.json"
  and .runtime_contract.sbom == "/usr/local/share/atrinik/audio-toolchain.spdx.json"
  and (.excluded.paths | index("/opt/mxe/python-runtime") != null)
  and (.excluded.paths | index("/opt/mxe/.ccache/ccache") != null)
  and (.excluded.paths | index("/opt/mxe/usr/x86_64-pc-linux-gnu/icu4c") != null)
  and (.excluded.capabilities | index("native Linux worldmaker build") != null)
' "${classic_check_expected}" >/dev/null
fi

if [[ -n ${classic_check_installed} ]]; then
  cmp --silent "${classic_check_expected}" "${classic_check_installed}"
fi
