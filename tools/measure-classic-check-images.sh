#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 BASELINE_IMAGE CANDIDATE_IMAGE OUTPUT_DIRECTORY" >&2
  exit 2
fi

baseline_image=$1
candidate_image=$2
output_directory=$3
registry_image=registry:2.8.3@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373
dind_image=docker:27.5.1-dind@sha256:aa3df78ecf320f5fafdce71c659f1629e96e9de0968305fe1de670e0ca9176ce
suffix=${GITHUB_RUN_ID:-$$}-${GITHUB_RUN_ATTEMPT:-1}
registry_name=classic-check-registry-${suffix}
baseline_daemon=classic-check-baseline-${suffix}
candidate_daemon=classic-check-candidate-${suffix}
registry_port=5000

cleanup() {
  docker rm --force "${baseline_daemon}" "${candidate_daemon}" \
    "${registry_name}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

mkdir -p "${output_directory}"

remote_start=$(date +%s%N)
docker pull "${baseline_image}"
remote_baseline_first_ms=$((($(date +%s%N) - remote_start) / 1000000))
remote_start=$(date +%s%N)
docker pull "${baseline_image}"
remote_baseline_warm_ms=$((($(date +%s%N) - remote_start) / 1000000))

docker run --detach --rm --name "${registry_name}" \
  --publish "${registry_port}:5000" "${registry_image}" >/dev/null
for _ in {1..30}; do
  if curl --fail --silent "http://localhost:${registry_port}/v2/" >/dev/null; then
    break
  fi
  sleep 1
done
curl --fail --silent "http://localhost:${registry_port}/v2/" >/dev/null

docker tag "${baseline_image}" localhost:${registry_port}/baseline:latest
docker tag "${candidate_image}" localhost:${registry_port}/candidate:latest
docker push localhost:${registry_port}/baseline:latest >/dev/null
docker push localhost:${registry_port}/candidate:latest >/dev/null

manifest_size() {
  local repository=$1
  python3 - "${registry_port}" "${repository}" <<'PY'
import json
import sys
import urllib.request


port, repository = sys.argv[1:]
accept = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)


def manifest(reference: str) -> dict[str, object]:
    request = urllib.request.Request(
        f"http://localhost:{port}/v2/{repository}/manifests/{reference}",
        headers={"Accept": accept},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


value = manifest("latest")
if "manifests" in value:
    descriptor = next(
        item
        for item in value["manifests"]
        if item.get("platform", {}).get("os") == "linux"
        and item.get("platform", {}).get("architecture") == "amd64"
    )
    value = manifest(descriptor["digest"])
print(sum(layer["size"] for layer in value["layers"]))
PY
}

baseline_compressed_bytes=$(manifest_size baseline)
candidate_compressed_bytes=$(manifest_size candidate)

start_daemon() {
  local name=$1
  docker run --detach --privileged --name "${name}" \
    --add-host registry.local:host-gateway \
    "${dind_image}" --insecure-registry registry.local:${registry_port} \
    --tls=false >/dev/null
  for _ in {1..60}; do
    if docker exec "${name}" docker info >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done
  echo "isolated Docker daemon ${name} did not start" >&2
  return 1
}

measure_image() {
  local name=$1
  local repository=$2
  local output_prefix=$3
  local image=registry.local:${registry_port}/${repository}:latest
  local start cold_ms warm_ms startup_total_ms uncompressed_bytes

  start_daemon "${name}"
  start=$(date +%s%N)
  docker exec "${name}" docker pull "${image}" >/dev/null
  cold_ms=$((($(date +%s%N) - start) / 1000000))
  start=$(date +%s%N)
  docker exec "${name}" docker pull "${image}" >/dev/null
  warm_ms=$((($(date +%s%N) - start) / 1000000))
  uncompressed_bytes=$(docker exec "${name}" docker image inspect \
    --format '{{.Size}}' "${image}")
  startup_total_ms=0
  for _ in {1..5}; do
    start=$(date +%s%N)
    docker exec "${name}" docker run --rm "${image}" true
    startup_total_ms=$((startup_total_ms + ($(date +%s%N) - start) / 1000000))
  done
  printf -v "${output_prefix}_cold_ms" '%s' "${cold_ms}"
  printf -v "${output_prefix}_warm_ms" '%s' "${warm_ms}"
  printf -v "${output_prefix}_startup_ms" '%s' "$((startup_total_ms / 5))"
  printf -v "${output_prefix}_uncompressed_bytes" '%s' "${uncompressed_bytes}"
}

measure_image "${baseline_daemon}" baseline baseline
measure_image "${candidate_daemon}" candidate candidate

export baseline_cold_ms baseline_warm_ms baseline_startup_ms \
  baseline_uncompressed_bytes candidate_cold_ms candidate_warm_ms \
  candidate_startup_ms candidate_uncompressed_bytes baseline_compressed_bytes \
  candidate_compressed_bytes remote_baseline_first_ms remote_baseline_warm_ms \
  baseline_image candidate_image
python3 - "${output_directory}/classic-check-image-measurements.json" \
  "${output_directory}/classic-check-image-measurements.md" <<'PY'
import json
import os
from pathlib import Path
import sys


def integer(name: str) -> int:
    return int(os.environ[name])


baseline = {
    "image": os.environ["baseline_image"],
    "compressed_bytes": integer("baseline_compressed_bytes"),
    "uncompressed_bytes": integer("baseline_uncompressed_bytes"),
    "isolated_cold_pull_ms": integer("baseline_cold_ms"),
    "isolated_warm_pull_ms": integer("baseline_warm_ms"),
    "startup_mean_ms": integer("baseline_startup_ms"),
    "ghcr_first_pull_ms": integer("remote_baseline_first_ms"),
    "ghcr_warm_pull_ms": integer("remote_baseline_warm_ms"),
}
candidate = {
    "image": os.environ["candidate_image"],
    "compressed_bytes": integer("candidate_compressed_bytes"),
    "uncompressed_bytes": integer("candidate_uncompressed_bytes"),
    "isolated_cold_pull_ms": integer("candidate_cold_ms"),
    "isolated_warm_pull_ms": integer("candidate_warm_ms"),
    "startup_mean_ms": integer("candidate_startup_ms"),
}
result = {
    "schema_version": 1,
    "method": {
        "runner": "GitHub-hosted ubuntu-26.04",
        "pulls": "separate clean Docker-in-Docker daemons via one local registry",
        "startup_samples": 5,
        "note": "The isolated comparison removes GHCR network variance; the baseline GHCR first and warm pulls are recorded separately.",
    },
    "baseline": baseline,
    "candidate": candidate,
    "reduction": {
        "compressed_percent": round(
            100 * (baseline["compressed_bytes"] - candidate["compressed_bytes"])
            / baseline["compressed_bytes"],
            2,
        ),
        "uncompressed_percent": round(
            100 * (baseline["uncompressed_bytes"] - candidate["uncompressed_bytes"])
            / baseline["uncompressed_bytes"],
            2,
        ),
    },
}
Path(sys.argv[1]).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
lines = [
    "# Classic Check image measurements",
    "",
    "GitHub-hosted `ubuntu-26.04`; isolated pulls use separate clean Docker-in-Docker daemons and one local registry.",
    "",
    "| Image | Compressed bytes | Uncompressed bytes | Cold pull | Warm pull | Mean startup |",
    "| --- | ---: | ---: | ---: | ---: | ---: |",
]
for label, value in (("Pinned baseline", baseline), ("Classic Check candidate", candidate)):
    lines.append(
        f"| {label} | {value['compressed_bytes']} | {value['uncompressed_bytes']} | "
        f"{value['isolated_cold_pull_ms']} ms | {value['isolated_warm_pull_ms']} ms | "
        f"{value['startup_mean_ms']} ms |"
    )
lines.extend(
    [
        "",
        f"Compressed-size reduction: **{result['reduction']['compressed_percent']}%**.",
        f"Uncompressed-size reduction: **{result['reduction']['uncompressed_percent']}%**.",
        "",
        f"Pinned GHCR baseline first/warm pulls: {baseline['ghcr_first_pull_ms']} ms / {baseline['ghcr_warm_pull_ms']} ms.",
    ]
)
Path(sys.argv[2]).write_text("\n".join(lines) + "\n", encoding="utf-8")
PY
