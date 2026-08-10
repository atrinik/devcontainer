# Classic CI image benchmark

This file is the durable measurement ledger for the slim Classic image. Local
measurements are useful implementation evidence, but they do not replace the
required equivalent-runner comparison between the existing apt-based Classic
job and the candidate image digest.

## Environment

- Measurement date: 2026-08-10 UTC
- Host: Linux 6.6.87.2-microsoft-standard-WSL2, x86_64, 32 logical CPUs
- Docker client/server: 29.7.1 / 29.7.1
- Image-content checkpoint: `a19ce060e157b0cde4951bf478163aaa60432208`
- Pinned Classic source: `2d3ecad2117733b1262f5195c0dd414fef4b45f3`
- Broad local comparison image: `sha256:c39ab7366fe92ef80e4c5d8b7bf9306a4d9df37d436d0da0efc3cff953c40b74`
- Slim local candidate image: `sha256:78d3348df8b70df35f7f41fe86800b4740aa88925a69d62794a37cb8a75066b7`

The broad image is a local size/startup proxy, not the acceptance-test
apt-based consumer baseline.

## Local results

| Measurement | Broad image | Slim candidate | Result |
| --- | ---: | ---: | ---: |
| Docker content size | 1,215,965,963 B | 401,297,079 B | 67.0% smaller |
| `docker image save \| gzip -1` | 1,207,055,637 B | 398,170,129 B | 67.0% smaller |
| five-run warm container startup mean | 0.702 s | 0.626 s | effectively unchanged |

The candidate ran the pinned server's 36 tests and client's 31 tests with
coverage as numeric UID/GID 1000. A clean repeated build restored all 330
server and 190 client compiler outputs as direct ccache hits.

Commands used:

```sh
docker image inspect IMAGE --format '{{.Id}} {{.Size}}'
docker image save IMAGE | gzip -1 | wc -c
TIMEFORMAT='%R'
for run in 1 2 3 4 5; do
  time docker run --rm IMAGE true >/dev/null
done
```

The full workload command is the `docker run` recipe in `README.md`, using the
isolated Classic checkout at the pinned revision and a dedicated empty cache
directory for the first run. The validation script performs an intentional
clean rebuild so its reported hit count proves restoration from that mounted
cache rather than merely proving that ccache was invoked.

## Required candidate-digest comparison

Before issue closure, replace every pending cell below with raw measurements
from equivalent clean runners and link the associated devcontainer and Classic
reviews. Use the immutable digest resolved from the final reviewed
`candidate-sha-<commit>` tag.

| Measurement | Existing apt job | Candidate digest job | Status |
| --- | ---: | ---: | --- |
| Compressed transfer size | pending | pending | pending publication |
| Cold pull | n/a | pending | pending publication |
| Warm pull | n/a | pending | pending publication |
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
