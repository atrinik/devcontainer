#!/usr/bin/env bash
set -euo pipefail

expected=${1:-toolchains.json}
installed=${2:-}

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
