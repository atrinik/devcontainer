# Classic CI image benchmark

This file is the durable measurement ledger for the slim Classic image. Local
measurements are useful implementation evidence, but they do not replace the
required equivalent-runner comparison between the existing apt-based Classic
job and the candidate image digest.

## Environment

- Measurement date: 2026-08-10 UTC
- Host: Linux 6.6.87.2-microsoft-standard-WSL2, x86_64, 32 logical CPUs
- Docker client/server: 29.7.1 / 29.7.1
- Devcontainer branch: `feat/classic-ci-image` (final head recorded in PR #28)
- Pinned Classic source: `2d3ecad2117733b1262f5195c0dd414fef4b45f3`
- Broad local comparison image: `sha256:c39ab7366fe92ef80e4c5d8b7bf9306a4d9df37d436d0da0efc3cff953c40b74`
- Slim local candidate image: `sha256:4e498aa55ada8bed181c3cd88153871588f92d855e92f476391b1e6c1c2c8c50`

The broad image is a local size/startup proxy, not the acceptance-test
apt-based consumer baseline.

## Local results

| Measurement | Broad image | Slim candidate | Result |
| --- | ---: | ---: | ---: |
| Docker content size | 1,215,965,963 B | 401,296,878 B | 67.0% smaller |
| sampled `docker image save \| gzip -1` | 1,207,055,637 B | 398,180,724 B | 67.0% smaller |
| five-run warm container startup mean | 0.985 s | 0.948 s | effectively unchanged |

The candidate ran the pinned server's 36 tests and client's 31 tests with
coverage as numeric UID/GID 1000. A clean repeated build restored all 330
server and 190 client compiler outputs as direct ccache hits.

Raw startup samples in seconds were `1.165, 0.921, 0.925, 0.952, 0.960` for
the broad image and `0.995, 0.850, 1.005, 0.933, 0.959` for the slim image.
The gzip figures are transfer-size proxies sampled from Docker's serialized
archive; repeated serialization can differ slightly and is not a content
digest.

Exact commands used:

```sh
docker image inspect atrinik-linux-build:issue-21 --format '{{.Id}} {{.Size}}'
docker image inspect atrinik-classic-build:issue-24 --format '{{.Id}} {{.Size}}'
docker image save atrinik-linux-build:issue-21 | gzip -1 | wc -c
docker image save atrinik-classic-build:issue-24 | gzip -1 | wc -c
TIMEFORMAT='%R'
for run in 1 2 3 4 5; do
  time docker run --rm atrinik-linux-build:issue-21 true >/dev/null
done
for run in 1 2 3 4 5; do
  time docker run --rm atrinik-classic-build:issue-24 true >/dev/null
done
```

The full workload command is the `docker run` recipe in `README.md`, using the
isolated Classic checkout at the pinned revision and a dedicated empty cache
directory for the first run. The validation script performs an intentional
clean rebuild so its reported hit count proves restoration from that mounted
cache rather than merely proving that ccache was invoked.

The empty-cache validation reported this raw summary after both intentional
warm rebuilds:

```text
Cacheable calls: 1040 / 1040 (100.0%)
Hits:             520 / 1040 (50.00%)
  Direct:         520 /  520 (100.0%)
Misses:           520 / 1040 (50.00%)
```

The validation snapshots hits immediately before each component's warm build
and requires a positive delta, so preexisting cache entries cannot satisfy the
assertion by themselves. Persistent consumers must use a stable numeric UID;
mode 1777 makes the root mount initially writable but does not make ccache's
owner-writable nested directories safe to reuse under a different UID.

## Hosted candidate-digest comparison

The candidate was published by
[devcontainer run 31427897129](https://github.com/atrinik/devcontainer/actions/runs/31427897129)
from reviewed source `b9a86c4f52205c927373caa7583d3a43989cfca7`.
The tag
`candidate-sha-b9a86c4f52205c927373caa7583d3a43989cfca7`
resolved to index digest
`sha256:e117b858d5aecdb8eb39dc56451378b6e6bd72dd5e042ab96fee5b6154000043`;
its amd64 manifest is
`sha256:cdba4bfd40f288e577842b3308e88ccfb7252623ac7b13d08074fc45cc305b8e`.

The linked [Classic review](https://github.com/atrinik/classic/pull/98) tested
source `934af663a1f0d5892026a366f12b907459f3cd50`. The apt baseline was
[run 31405779774](https://github.com/atrinik/classic/actions/runs/31405779774).
Candidate [run 31430896836](https://github.com/atrinik/classic/actions/runs/31430896836)
attempt 3 started without matching compiler caches; unchanged attempt 4 ran on
new hosted runners and restored all three caches. All three executions used
GitHub's `ubuntu-24.04` image version `20260720.247.2` and runner `2.336.0`.
The same runner image in
[final evidence run 31432805795](https://github.com/atrinik/classic/actions/runs/31432805795)
recorded the remaining hosted environment details:

- Runner OS / architecture / logical CPUs: `ubuntu24` / `X64` / `4`
- Kernel: `Linux 6.17.0-1020-azure x86_64 GNU/Linux`
- Docker client / server: `28.0.4` / `28.0.4`

Each candidate attempt removed the exact local image reference before its first
pull, immediately repeated the pull with local layers present, then measured
one cold and five warm `docker run --rm IMAGE true` invocations. Compressed
size is the sum of the registry manifest's amd64 layers, not a sampled Docker
archive.

| Measurement | Cold-cache attempt 3 | Restored-cache attempt 4 |
| --- | ---: | ---: |
| Compressed amd64 layers | 401,282,166 B | 401,282,166 B |
| Docker content size | 1,136,279,102 B | 1,136,279,102 B |
| First pull | 18,226 ms | 21,643 ms |
| Immediate repeat pull | 210 ms | 176 ms |
| Cold startup | 269 ms | 272 ms |
| Warm startup samples | 184, 173, 178, 171, 187 ms | 180, 193, 186, 189, 197 ms |
| Warm startup mean | 178.6 ms | 189.0 ms |

Job times are exact differences between GitHub's `started_at` and
`completed_at` timestamps. They are hosted samples, not performance
guarantees.

| Job | Apt baseline | Candidate cold | Candidate warm | Warm vs baseline |
| --- | ---: | ---: | ---: | ---: |
| Core validation | 206 s | 116 s | 84 s | -122 s (-59.2%) |
| Client validation | 84 s | 67 s | 40 s | -44 s (-52.4%) |
| Server validation | 202 s | 235 s | 141 s | -61 s (-30.2%) |

The baseline core dependency-install step took 28 seconds. Its complete client
and server validation steps took 67 and 185 seconds. The cold candidate paid
25 and 33 seconds for the client and server first pulls; its respective
validation steps took 19 and 181 seconds. With restored compiler caches those
steps took 9 and 100 seconds.

The complete uploaded `ccache --print-stats` outputs report:

| Component | Cold direct hits | Cold misses | Warm direct hits | Warm misses |
| --- | ---: | ---: | ---: | ---: |
| Core | 0 | 87 | 87 | 0 |
| Client | 0 | 193 | 193 | 0 |
| Server | 10 | 986 | 996 | 0 |

The ten cold server hits occurred within its repeated configurations. The new
warm runners restored 1,276 direct hits and recorded zero misses. GitHub stored
exactly three component-separated PR cache keys under `refs/pull/98/merge`; a
lookup for the trusted-main prefix returned no entry.

The Classic repository preserves the raw coordinates, commands, measurements,
cache evidence, invalidation tests, and reproduction procedure in
[`docs/CI-LINUX-IMAGE.md`](https://github.com/atrinik/classic/blob/perf/ci-linux-cache/docs/CI-LINUX-IMAGE.md).
The candidate digest is pre-merge evidence only. After this publisher change is
released, Classic must verify the versioned image's inventories and pin its
released digest before its consumer review becomes ready.
