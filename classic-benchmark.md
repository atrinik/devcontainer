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
- Slim local candidate image: `sha256:cf760df2b9ba0f825ffa568735d13e87580913edc4083931f0d5da70a780d609`

The broad image is a local size/startup proxy, not the acceptance-test
apt-based consumer baseline.

## Local results

| Measurement | Broad image | Slim candidate | Result |
| --- | ---: | ---: | ---: |
| Docker content size | 1,215,965,963 B | 401,297,171 B | 67.0% smaller |
| sampled `docker image save \| gzip -1` | 1,207,055,637 B | 398,194,006 B | 67.0% smaller |
| five-run warm container startup mean | 0.912 s | 0.871 s | effectively unchanged |

The candidate ran the pinned server's 36 tests and client's 31 tests with
coverage as numeric UID/GID 1000. A clean repeated build restored all 330
server and 190 client compiler outputs as direct ccache hits.

Raw startup samples in seconds were `0.928, 0.843, 0.865, 0.898, 1.027` for
the broad image and `0.823, 0.816, 0.917, 0.883, 0.916` for the slim image.
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

## Required candidate-digest comparison

Before issue closure, replace every pending cell below with raw measurements
from equivalent clean runners and link the associated devcontainer and Classic
reviews. Use the immutable digest resolved from the final reviewed
`candidate-sha-<commit>` tag.

| Measurement | Existing apt job | Candidate digest job | Status |
| --- | ---: | ---: | --- |
| Compressed transfer size | pending | pending | pending publication |
| Cold pull | n/a | pending | pending publication |
| Immediate repeat pull with local layers present | n/a | pending | pending publication |
| Cold container startup | n/a | pending | pending publication |
| Warm container startup | n/a | pending | pending publication |
| Dependency/setup time | pending | pending | pending consumer branch |
| Server build/test/coverage | pending | pending | pending consumer branch |
| Client build/test/coverage | pending | pending | pending consumer branch |
| End-to-end job time | pending | pending | pending consumer branch |
| Warm ccache hits/misses | pending | pending | pending consumer branch |

Record the runner image, CPU allocation, Docker version, commands, raw samples,
and both review URLs with the completed table. Do not compare timings collected
on materially different runners.
