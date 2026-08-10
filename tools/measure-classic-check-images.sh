#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 BASELINE_IMAGE CANDIDATE_IMAGE OUTPUT_DIRECTORY" >&2
  exit 2
fi

baseline_image=$1
candidate_image=$2
output_directory=$3
if [[ ! ${baseline_image} =~ @sha256:[0-9a-f]{64}$ ]]; then
  echo "baseline image is not an immutable repository digest: ${baseline_image}" >&2
  exit 2
fi
if [[ ! ${candidate_image} =~ ^sha256:[0-9a-f]{64}$ &&
    ! ${candidate_image} =~ @sha256:[0-9a-f]{64}$ ]]; then
  echo "candidate image is not an immutable image ID or repository digest: ${candidate_image}" >&2
  exit 2
fi
registry_image=registry:2.8.3@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373
dind_image=docker:27.5.1-dind@sha256:aa3df78ecf320f5fafdce71c659f1629e96e9de0968305fe1de670e0ca9176ce
suffix=${GITHUB_RUN_ID:-$$}-${GITHUB_RUN_ATTEMPT:-1}
registry_name=classic-check-registry-${suffix}
network_name=classic-check-measurement-${suffix}
baseline_repository=baseline-${suffix}
candidate_repository=candidate-${suffix}
registry_port=
network_id=
baseline_local_tag=
candidate_local_tag=
baseline_tag_created=false
candidate_tag_created=false
measurement_trials=4
containers=()

cleanup() {
  if ((${#containers[@]})); then
    docker rm --force --volumes "${containers[@]}" >/dev/null 2>&1 || true
  fi
  if [[ ${baseline_tag_created} == true ]]; then
    docker image rm "${baseline_local_tag}" >/dev/null 2>&1 || true
  fi
  if [[ ${candidate_tag_created} == true ]]; then
    docker image rm "${candidate_local_tag}" >/dev/null 2>&1 || true
  fi
  if [[ -n ${network_id} ]]; then
    docker network rm "${network_id}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

mkdir -p "${output_directory}"

remote_start=$(date +%s%N)
docker pull "${baseline_image}"
remote_baseline_first_ms=$((($(date +%s%N) - remote_start) / 1000000))
remote_start=$(date +%s%N)
docker pull "${baseline_image}"
remote_baseline_warm_ms=$((($(date +%s%N) - remote_start) / 1000000))

network_id=$(docker network create "${network_name}")
registry_id=$(docker create --name "${registry_name}" \
  --network "${network_id}" --publish 127.0.0.1::5000 \
  "${registry_image}")
containers+=("${registry_id}")
docker start "${registry_id}" >/dev/null
registry_address=$(docker port "${registry_id}" 5000/tcp)
registry_port=${registry_address##*:}
if [[ ! ${registry_port} =~ ^[0-9]+$ ]]; then
  echo "cannot resolve temporary registry port: ${registry_address}" >&2
  exit 1
fi
for _ in {1..30}; do
  if curl --fail --silent "http://localhost:${registry_port}/v2/" >/dev/null; then
    break
  fi
  sleep 1
done
curl --fail --silent "http://localhost:${registry_port}/v2/" >/dev/null

baseline_local_tag=localhost:${registry_port}/${baseline_repository}:measurement
candidate_local_tag=localhost:${registry_port}/${candidate_repository}:measurement
if docker image inspect "${baseline_local_tag}" >/dev/null 2>&1 ||
    docker image inspect "${candidate_local_tag}" >/dev/null 2>&1; then
  echo "temporary measurement image tag already exists" >&2
  exit 1
fi
docker tag "${baseline_image}" "${baseline_local_tag}"
baseline_tag_created=true
docker tag "${candidate_image}" "${candidate_local_tag}"
candidate_tag_created=true
docker push "${baseline_local_tag}" >/dev/null
docker push "${candidate_local_tag}" >/dev/null

manifest_metadata() {
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


def manifest(reference: str) -> tuple[dict[str, object], str]:
    request = urllib.request.Request(
        f"http://localhost:{port}/v2/{repository}/manifests/{reference}",
        headers={"Accept": accept},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        digest = response.headers.get("Docker-Content-Digest", "")
        return json.load(response), digest


value, digest = manifest("measurement")
if "manifests" in value:
    descriptor = next(
        item
        for item in value["manifests"]
        if item.get("platform", {}).get("os") == "linux"
        and item.get("platform", {}).get("architecture") == "amd64"
    )
    value, digest = manifest(descriptor["digest"])
if not digest.startswith("sha256:") or len(digest) != 71:
    raise RuntimeError(f"registry did not return an immutable manifest digest: {digest}")
print(sum(layer["size"] for layer in value["layers"]), digest)
PY
}

read -r baseline_compressed_bytes baseline_registry_digest \
  < <(manifest_metadata "${baseline_repository}")
read -r candidate_compressed_bytes candidate_registry_digest \
  < <(manifest_metadata "${candidate_repository}")

start_daemon() {
  local name=$1
  local container_id
  container_id=$(docker create --privileged --name "${name}" \
    --network "${network_id}" \
    "${dind_image}" --insecure-registry "${registry_name}:5000" \
    --tls=false)
  containers+=("${container_id}")
  docker start "${container_id}" >/dev/null
  for _ in {1..60}; do
    if docker exec "${container_id}" docker info >/dev/null 2>&1; then
      measured_container_id=${container_id}
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
  local digest=$3
  local image=${registry_name}:5000/${repository}@${digest}
  local start cold_ms warm_ms startup_total_ms uncompressed_bytes

  start_daemon "${name}"
  start=$(date +%s%N)
  docker exec "${measured_container_id}" docker pull "${image}" >/dev/null
  cold_ms=$((($(date +%s%N) - start) / 1000000))
  start=$(date +%s%N)
  docker exec "${measured_container_id}" docker pull "${image}" >/dev/null
  warm_ms=$((($(date +%s%N) - start) / 1000000))
  uncompressed_bytes=$(docker exec "${measured_container_id}" docker image inspect \
    --format '{{.Size}}' "${image}")
  startup_total_ms=0
  for _ in {1..5}; do
    start=$(date +%s%N)
    docker exec "${measured_container_id}" docker run --rm "${image}" true
    startup_total_ms=$((startup_total_ms + ($(date +%s%N) - start) / 1000000))
  done
  measured_cold_ms=${cold_ms}
  measured_warm_ms=${warm_ms}
  measured_startup_ms=$((startup_total_ms / 5))
  measured_uncompressed_bytes=${uncompressed_bytes}
  docker rm --force --volumes "${measured_container_id}" >/dev/null
}

baseline_cold_samples=()
baseline_warm_samples=()
baseline_startup_samples=()
baseline_uncompressed_samples=()
candidate_cold_samples=()
candidate_warm_samples=()
candidate_startup_samples=()
candidate_uncompressed_samples=()

measure_trial() {
  local label=$1
  local trial=$2
  local repository digest daemon
  if [[ ${label} == baseline ]]; then
    repository=${baseline_repository}
    digest=${baseline_registry_digest}
  else
    repository=${candidate_repository}
    digest=${candidate_registry_digest}
  fi
  daemon=classic-check-${label}-${suffix}-${trial}
  measure_image "${daemon}" "${repository}" "${digest}"
  if [[ ${label} == baseline ]]; then
    baseline_cold_samples+=("${measured_cold_ms}")
    baseline_warm_samples+=("${measured_warm_ms}")
    baseline_startup_samples+=("${measured_startup_ms}")
    baseline_uncompressed_samples+=("${measured_uncompressed_bytes}")
  else
    candidate_cold_samples+=("${measured_cold_ms}")
    candidate_warm_samples+=("${measured_warm_ms}")
    candidate_startup_samples+=("${measured_startup_ms}")
    candidate_uncompressed_samples+=("${measured_uncompressed_bytes}")
  fi
}

for trial in $(seq 1 "${measurement_trials}"); do
  if ((trial % 2)); then
    measure_trial baseline "${trial}"
    measure_trial candidate "${trial}"
  else
    measure_trial candidate "${trial}"
    measure_trial baseline "${trial}"
  fi
done

baseline_cold_samples_csv=$(IFS=,; echo "${baseline_cold_samples[*]}")
baseline_warm_samples_csv=$(IFS=,; echo "${baseline_warm_samples[*]}")
baseline_startup_samples_csv=$(IFS=,; echo "${baseline_startup_samples[*]}")
baseline_uncompressed_samples_csv=$(IFS=,; echo "${baseline_uncompressed_samples[*]}")
candidate_cold_samples_csv=$(IFS=,; echo "${candidate_cold_samples[*]}")
candidate_warm_samples_csv=$(IFS=,; echo "${candidate_warm_samples[*]}")
candidate_startup_samples_csv=$(IFS=,; echo "${candidate_startup_samples[*]}")
candidate_uncompressed_samples_csv=$(IFS=,; echo "${candidate_uncompressed_samples[*]}")
measurement_docker_version=$(docker version --format '{{.Server.Version}}')
export baseline_cold_samples_csv baseline_warm_samples_csv \
  baseline_startup_samples_csv baseline_uncompressed_samples_csv \
  candidate_cold_samples_csv candidate_warm_samples_csv \
  candidate_startup_samples_csv candidate_uncompressed_samples_csv \
  baseline_compressed_bytes candidate_compressed_bytes \
  baseline_registry_digest candidate_registry_digest \
  remote_baseline_first_ms remote_baseline_warm_ms baseline_image \
  candidate_image measurement_trials measurement_docker_version
export measurement_source_sha=${MEASUREMENT_SOURCE_SHA:-${GITHUB_SHA:-unknown}} \
  measurement_head_sha=${MEASUREMENT_HEAD_SHA:-unknown} \
  measurement_base_sha=${MEASUREMENT_BASE_SHA:-unknown} \
  measurement_build_digest=${MEASUREMENT_BUILD_DIGEST:-unknown} \
  measurement_run_id=${GITHUB_RUN_ID:-local} \
  measurement_run_attempt=${GITHUB_RUN_ATTEMPT:-1}
if [[ ${GITHUB_ACTIONS:-false} == true ]]; then
  export measurement_runner='GitHub-hosted ubuntu-26.04'
else
  export measurement_runner=local
fi
python3 - "${output_directory}/classic-check-image-measurements.json" \
  "${output_directory}/classic-check-image-measurements.md" <<'PY'
import json
import os
from pathlib import Path
import statistics
import sys


def integer(name: str) -> int:
    return int(os.environ[name])


def samples(name: str) -> list[int]:
    return [int(value) for value in os.environ[name].split(",")]


def image_result(prefix: str) -> dict[str, object]:
    cold = samples(f"{prefix}_cold_samples_csv")
    warm = samples(f"{prefix}_warm_samples_csv")
    startup = samples(f"{prefix}_startup_samples_csv")
    uncompressed = samples(f"{prefix}_uncompressed_samples_csv")
    if len(set(uncompressed)) != 1:
        raise RuntimeError(f"{prefix} uncompressed size changed between trials")
    result: dict[str, object] = {
        "image": os.environ[f"{prefix}_image"],
        "local_registry_digest": os.environ[f"{prefix}_registry_digest"],
        "compressed_bytes": integer(f"{prefix}_compressed_bytes"),
        "uncompressed_bytes": uncompressed[0],
        "isolated_cold_pull_ms": int(statistics.median(cold)),
        "isolated_warm_pull_ms": int(statistics.median(warm)),
        "startup_mean_ms": int(statistics.median(startup)),
        "samples": {
            "isolated_cold_pull_ms": cold,
            "isolated_warm_pull_ms": warm,
            "startup_five_run_mean_ms": startup,
        },
    }
    return result


baseline = image_result("baseline")
baseline["ghcr_first_pull_ms"] = integer("remote_baseline_first_ms")
baseline["ghcr_warm_pull_ms"] = integer("remote_baseline_warm_ms")
candidate = image_result("candidate")
candidate["buildx_manifest_digest"] = os.environ["measurement_build_digest"]
trial_count = integer("measurement_trials")
result = {
    "schema_version": 1,
    "method": {
        "runner": os.environ["measurement_runner"],
        "checkout_sha": os.environ["measurement_source_sha"],
        "head_sha": os.environ["measurement_head_sha"],
        "base_sha": os.environ["measurement_base_sha"],
        "run_id": os.environ["measurement_run_id"],
        "run_attempt": os.environ["measurement_run_attempt"],
        "host_docker_version": os.environ["measurement_docker_version"],
        "dind_image": "docker:27.5.1-dind@sha256:aa3df78ecf320f5fafdce71c659f1629e96e9de0968305fe1de670e0ca9176ce",
        "pulls": "fresh Docker-in-Docker daemon per sample via one local registry",
        "pull_trials_per_image": trial_count,
        "order": "alternating baseline/candidate and candidate/baseline, two each",
        "startup_samples_per_trial": 5,
        "summary": f"median of {trial_count} pull trials and their five-run startup means",
        "note": "The isolated comparison removes GHCR network variance; local-registry digests identify the measured manifests, and baseline GHCR first/warm pulls are supplemental.",
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
    f"Runner: `{result['method']['runner']}`. {trial_count} counterbalanced isolated pull trials use a fresh Docker-in-Docker daemon per sample and one local registry. Values below are medians.",
    "",
    f"Checked-out revision: `{result['method']['checkout_sha']}`; PR head/base: `{result['method']['head_sha']}` / `{result['method']['base_sha']}`; workflow run: `{result['method']['run_id']}` attempt `{result['method']['run_attempt']}`.",
    "",
    "| Image | Immutable measurement digest | Compressed bytes | Uncompressed bytes | Cold pull | Warm pull | Mean startup |",
    "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
]
for label, value in (("Pinned baseline", baseline), ("Classic Check candidate", candidate)):
    lines.append(
        f"| {label} | `{value['local_registry_digest']}` | {value['compressed_bytes']} | {value['uncompressed_bytes']} | "
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
        "",
        f"Baseline cold samples: `{baseline['samples']['isolated_cold_pull_ms']}` ms; candidate: `{candidate['samples']['isolated_cold_pull_ms']}` ms.",
        f"Baseline warm samples: `{baseline['samples']['isolated_warm_pull_ms']}` ms; candidate: `{candidate['samples']['isolated_warm_pull_ms']}` ms.",
    ]
)
Path(sys.argv[2]).write_text("\n".join(lines) + "\n", encoding="utf-8")
PY
