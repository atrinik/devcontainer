#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 || ! $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "usage: $0 MAJOR.MINOR.PATCH" >&2
  exit 2
fi

version=$1
tag=v${version}
gh workflow run publish-linux.yml --repo "${GITHUB_REPOSITORY}" --ref "${tag}"
gh workflow run publish-windows.yml --repo "${GITHUB_REPOSITORY}" --ref "${tag}"
