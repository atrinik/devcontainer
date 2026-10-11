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

jq -e '
  .schema_version == 1
  and .platform == "linux/amd64"
  and (.tools | keys == [
    "buf", "git-lfs", "go", "node", "pnpm", "protoc", "protoc-gen-go",
    "protoc-gen-prost", "rust", "rustup", "syft", "trivy"
  ])
  and (.consumers | length == 7)
  and (.graphics.headless_validation == true)
  and (.graphics.virtual_display == "Xvfb")
' "${expected}" >/dev/null

if [[ -n ${installed} ]]; then
  /usr/local/bin/atrinik-verify-classic-curl /usr/local
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
  test "$(git lfs version | sed -n '1s|^git-lfs/\([^ ]*\).*$|\1|p')" = \
    "$(jq -r '.tools["git-lfs"]' "${expected}")"
  command -v Xvfb >/dev/null
  command -v xvfb-run >/dev/null
  bash "$(dirname -- "${BASH_SOURCE[0]}")/smoke-git-lfs.sh"
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
  and .windows.support_runtime_dlls == []
  and .windows.support_runtime_imports == {}
  and (.windows.sdl_mixer_imports | length > 0)
  and all(.windows.sdl_mixer_imports[];
    (test("^(libgcc|libstdc|libssp|msvcrt)"; "i") | not))
  and any(.windows.sdl_mixer_imports[]; test("^(api-ms-win-crt-|ucrtbase)"; "i"))
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

if [[ -n ${classic_check_expected} ]]; then
  jq -e '
  keys == [
    "$schema", "base", "consumer", "curl_contract", "excluded", "host_packages", "llvm_mingw",
    "runtime_contract", "schema_version", "staging", "target", "verification"
  ]
  and .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and .schema_version == 1
  and .target == "classic-check"
  and (.consumer | keys == [
    "jobs", "lock_files", "repository", "validation_commit", "workflow"
  ])
  and .consumer.repository == "atrinik/classic"
  and (.consumer.validation_commit | test("^[0-9a-f]{40}$"))
  and .consumer.workflow == ".github/workflows/check.yml"
  and .consumer.jobs == [
    "Build native Windows tests", "Native Windows security tests"
  ]
  and .consumer.lock_files == [
    "client/dependencies.lock.json", "server/dependencies.lock.json"
  ]
  and .base == {
    "image": "mcr.microsoft.com/devcontainers/base:bookworm",
    "digest": "sha256:86165cfc170e9b2aa8df90b847127eea97b08eb9987021e6e6ec6c3a96545d7c"
  }
  and .host_packages == [
    "ca-certificates", "ccache", "cmake", "git", "ninja-build", "pkg-config", "python3"
  ]
  and (.llvm_mingw.repository == "mstorsjo/llvm-mingw")
  and .llvm_mingw.release == "20261006"
  and .llvm_mingw.llvm_version == "23.1.3"
  and .llvm_mingw.source_commit == "e1878a59f8bf3e1a73afe28f1b83168b1d029ed8"
  and .llvm_mingw.sha256 == "5f9c6ed95b2d4bdb2869a488c5fd5857fbdabcf288a0aa3eb1da43f6a08d8ab4"
  and .llvm_mingw.crt == "ucrt"
  and .llvm_mingw.runtime == "compiler-rt"
  and .llvm_mingw.target == "x86_64-w64-mingw32"
  and .llvm_mingw.prefix == "/opt/llvm-mingw"
  and .llvm_mingw.dependency_prefix == "/opt/atrinik-windows"
  and .llvm_mingw.toolchain_file == "/opt/atrinik-windows/share/cmake/llvm-mingw.cmake"
  and .llvm_mingw.runtime_directory == "/opt/atrinik-windows/bin"
  and .llvm_mingw.dependency_lock == "windows/dependencies.json"
  and .staging.commands == [
    "bash", "ccache", "cmake", "cpack", "git", "ninja", "python3",
    "x86_64-w64-mingw32-clang", "llvm-ar", "llvm-ranlib", "llvm-readobj",
    "llvm-dlltool", "x86_64-w64-mingw32-windres"
  ]
  and .staging.python_modules == [
    "hashlib", "json", "pathlib", "shutil", "subprocess", "tarfile",
    "urllib.request", "zipfile"
  ]
  and .runtime_contract == {
    "inventory": "/usr/local/share/atrinik/audio-toolchain.json",
    "sbom": "/usr/local/share/atrinik/audio-toolchain.spdx.json",
    "probe": "/opt/atrinik-windows/bin/atrinik-sdl3-mixer-probe.exe",
    "import_contract_source": "audio-toolchain.json#windows",
    "cares_license": {
      "source":"/opt/atrinik-windows/share/licenses/c-ares/LICENSE.md",
      "upstream":"https://github.com/c-ares/c-ares/blob/v1.34.6/LICENSE.md",
      "sha256":"460f5e768fda3752ca2169a95df062578a10fb126bfd65f3b9b1a1bed2f84807",
      "bundle_name":"c-ares-LICENSE.md"
    }
  }
  and (.verification | keys == ["native_tests", "public_ca"])
  and .verification.native_tests == [
    {"executable":"libatrinik-path.exe","build_target":"libatrinik-path","source":"libatrinik/build/windows-tests/libatrinik-path.exe","arguments":[]},
    {"executable":"libatrinik-rendezvous.exe","build_target":"libatrinik-rendezvous","source":"libatrinik/build/windows-tests/libatrinik-rendezvous.exe","arguments":[]},
    {"executable":"libatrinik-metaserver-publisher.exe","build_target":"libatrinik-metaserver-publisher","source":"libatrinik/build/windows-tests/libatrinik-metaserver-publisher.exe","arguments":["fixtures/metaserver-classic-publisher-v3.json"]},
    {"executable":"libatrinik-metaserver-url.exe","build_target":"libatrinik-metaserver-url","source":"libatrinik/build/windows-tests/libatrinik-metaserver-url.exe","arguments":[]},
    {"executable":"libatrinik-stun.exe","build_target":"libatrinik-stun","source":"libatrinik/build/windows-tests/libatrinik-stun.exe","arguments":[]},
    {"executable":"libatrinik-socket-quic.exe","build_target":"libatrinik-socket-quic","source":"libatrinik/build/windows-tests/libatrinik-socket-quic.exe","arguments":[]},
    {"executable":"atrinik-curl-cancellation-probe.exe","build_target":null,"source":"libatrinik/build/windows-curl-probe/atrinik-curl-cancellation-probe.exe","arguments":[]},
    {"executable":"client-rich-presence-tests.exe","build_target":null,"source":"client/build/windows-tests/client-rich-presence-tests.exe","arguments":[]}
  ]
  and .verification.public_ca == {
    "source":"client/ca-bundle.crt",
    "sha256":"a41b5d356aea97a529fe27e0f7316d2f9d946d75927476cf9cf1b90637d00505",
    "endpoint":"https://curl.se/"
  }
  and .excluded == {
    "paths": [
      "/opt/atrinik-windows/python-runtime",
      "/opt/atrinik-windows/include/python3.14",
      "/opt/atrinik-windows/lib/libpython314.dll.a",
      "/tmp/windows-dependencies"
    ],
    "capabilities": [
      "native Linux worldmaker build",
      "Windows server Python plugin SDK and runtime",
      "dependency source build caches"
    ],
    "reason": "Classic Check builds and stages only libatrinik and client native Windows tests; server packaging and worldmaker remain on the general-purpose image."
  }
' "${classic_check_expected}" >/dev/null

  if [[ -n ${classic_check_installed} ]]; then
    cmp --silent "${classic_check_expected}" "${classic_check_installed}"
  fi
elif [[ -n ${classic_check_installed} ]]; then
  echo "classic-check installed inventory requires an expected inventory" >&2
  exit 2
fi
