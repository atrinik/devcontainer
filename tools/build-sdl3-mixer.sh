#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 AUDIO_MANIFEST CMAKE_COMMAND INSTALL_PREFIX JOBS" >&2
  exit 2
fi

manifest=$1
cmake_command=$2
install_prefix=$3
jobs=$4

for command in jq sha256sum tar "${cmake_command}"; do
  if ! command -v "${command}" >/dev/null; then
    echo "required command is unavailable: ${command}" >&2
    exit 1
  fi
done

if [[ ! ${jobs} =~ ^[1-9][0-9]*$ ]]; then
  echo "JOBS must be a positive integer: ${jobs}" >&2
  exit 2
fi

work=$(mktemp -d)
trap 'rm -rf -- "${work}"' EXIT

download() {
  local url=$1
  local destination=$2

  if command -v curl >/dev/null; then
    curl --fail --location --silent --show-error "${url}" \
      --output "${destination}"
  elif command -v wget >/dev/null; then
    wget -q "${url}" -O "${destination}"
  else
    echo "curl or wget is required to download codec sources" >&2
    exit 1
  fi
}

extract_component() {
  local name=$1
  local url=$2
  local sha256=$3
  local destination=$4
  local archive="${work}/${name}.tar.gz"

  download "${url}" "${archive}"
  echo "${sha256}  ${archive}" | sha256sum -c -
  mkdir -p "${destination}"
  tar -xzf "${archive}" -C "${destination}" --strip-components=1
}

mixer_version=$(jq -er '.sdl_mixer.version' "${manifest}")
mixer_url=$(jq -er '.sdl_mixer.source.url' "${manifest}")
mixer_sha256=$(jq -er '.sdl_mixer.source.sha256' "${manifest}")
mixer_source="${work}/SDL3_mixer-${mixer_version}"

extract_component SDL3_mixer "${mixer_url}" "${mixer_sha256}" \
  "${mixer_source}"

for dependency in libogg libopus libopusfile; do
  url=$(jq -er --arg name "${dependency}" \
    '.dependencies[] | select(.name == $name) | .source.url' "${manifest}")
  sha256=$(jq -er --arg name "${dependency}" \
    '.dependencies[] | select(.name == $name) | .source.sha256' "${manifest}")
  destination=${dependency#lib}
  extract_component "${dependency}" "${url}" "${sha256}" \
    "${mixer_source}/external/${destination}"
done

"${cmake_command}" \
  -S "${mixer_source}" \
  -B "${work}/build" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="${install_prefix}" \
  -DBUILD_SHARED_LIBS=ON \
  -DSDLMIXER_DEPS_SHARED=OFF \
  -DSDLMIXER_EXAMPLES=OFF \
  -DSDLMIXER_FLAC=OFF \
  -DSDLMIXER_GME=OFF \
  -DSDLMIXER_INSTALL=ON \
  -DSDLMIXER_MIDI=OFF \
  -DSDLMIXER_MOD=OFF \
  -DSDLMIXER_MP3=ON \
  -DSDLMIXER_MP3_DRMP3=ON \
  -DSDLMIXER_MP3_MPG123=OFF \
  -DSDLMIXER_OPUS=ON \
  -DSDLMIXER_STRICT=ON \
  -DSDLMIXER_TESTS=OFF \
  -DSDLMIXER_VENDORED=ON \
  -DSDLMIXER_VORBIS_STB=ON \
  -DSDLMIXER_VORBIS_VORBISFILE=OFF \
  -DSDLMIXER_WAVPACK=OFF
"${cmake_command}" --build "${work}/build" --parallel "${jobs}"
"${cmake_command}" --install "${work}/build"
