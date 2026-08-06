#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 || ! $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "usage: $0 MAJOR.MINOR.PATCH" >&2
  exit 2
fi

version=$1
tag=v${version}
linux=false
windows=false

if [[ ${version} == 1.0.0 ]]; then
  linux=true
  windows=true
else
  previous_tag=$(git describe --tags --abbrev=0 "${tag}^" 2>/dev/null || true)
  if [[ -z ${previous_tag} ]]; then
    linux=true
    windows=true
  else
    while IFS= read -r path; do
      case ${path} in
      .dockerignore | linux/* | .github/workflows/publish-linux.yml)
        linux=true
        ;;
      esac
      case ${path} in
      .dockerignore | windows/* | .github/workflows/publish-windows.yml)
        windows=true
        ;;
      esac
    done < <(git diff --name-only "${previous_tag}" "${tag}")
  fi
fi

if [[ ${linux} == true ]]; then
  gh workflow run publish-linux.yml --repo "${GITHUB_REPOSITORY}" --ref "${tag}"
fi
if [[ ${windows} == true ]]; then
  gh workflow run publish-windows.yml --repo "${GITHUB_REPOSITORY}" --ref "${tag}"
fi
