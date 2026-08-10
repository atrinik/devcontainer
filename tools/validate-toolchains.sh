#!/usr/bin/env bash
set -euo pipefail

expected=${1:-toolchains.json}
installed=${2:-}
audio_expected=${3:-audio-toolchain.json}
audio_installed=${4:-}
audio_sbom_expected=${5:-audio-toolchain.spdx.json}
audio_sbom_installed=${6:-}

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
  and ([.packages[].name] ==
    ["SDL3_mixer", "libogg", "libopus", "libopusfile"])
  and all(.packages[];
    . as $package
    | any($expected[];
      .name == $package.name
        and .version == $package.versionInfo
        and .source.url == $package.downloadLocation
        and .source.sha256 == $package.checksums[0].checksumValue
        and .license == $package.licenseDeclared))
' "${audio_sbom_expected}" >/dev/null

if [[ -n ${audio_sbom_installed} ]]; then
  cmp --silent "${audio_sbom_expected}" "${audio_sbom_installed}"
fi
