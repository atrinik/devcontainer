#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright 2026 The Atrinik Project
set -euo pipefail
image=${1:?usage: smoke-classic-curl.sh IMAGE CLASSIC_CHECKOUT}
classic=$(realpath "${2:?Classic checkout required}")
source=$(git rev-parse --show-toplevel)
expected=$(jq -er '.consumer_validation.commit' "$source/classic-toolchain.json")
test "$(git -C "$classic" rev-parse HEAD)" = "$expected"
git -C "$classic" diff --quiet HEAD --
ca_hash=$(jq -er '.verification.public_ca.sha256' "$source/windows/classic-check-toolchain.json")
test "$(sha256sum "$classic/client/ca-bundle.crt" | cut -d' ' -f1)" = "$ca_hash"
docker run --rm --init --read-only --cap-drop ALL --security-opt no-new-privileges \
  --cpus 4 --memory 6g --memory-swap 6g --pids-limit 512 \
  --label org.atrinik.task=classic-curl-qualification \
  --user "$(id -u):$(id -g)" --env HOME=/tmp/classic-curl-home \
  --env QUALIFICATION_COMMIT="$expected" \
  --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777 \
  --mount "type=bind,source=$source,target=/image-source,readonly" \
  --mount "type=bind,source=$classic,target=/workspace,readonly" \
  --workdir /workspace "$image" bash -euo pipefail -c '
    cmake -S /image-source/tools/curl-probe -B /tmp/curl-probe -G Ninja \
      -DATRINIK_CLASSIC_SOURCE_DIR=/workspace \
      -DATRINIK_CLASSIC_QUALIFICATION_COMMIT="$QUALIFICATION_COMMIT" \
      -DCMAKE_BUILD_TYPE=Release
    cmake --build /tmp/curl-probe --target atrinik-curl-cancellation-probe --parallel 4
    ctest --test-dir /tmp/curl-probe --output-on-failure --no-tests=error \
      -R "^atrinik-curl-cancellation-qualification$"
    /tmp/curl-probe/atrinik-curl-cancellation-probe \
      --public-ca /workspace/client/ca-bundle.crt https://curl.se/
  '
