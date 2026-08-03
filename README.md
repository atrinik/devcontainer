# Atrinik devcontainer images

This repository owns the reusable Linux and Windows build environments for
Atrinik. Keeping these images separate from the game repository means changes
to game code do not rebuild the toolchains.

Published images:

- `ghcr.io/atrinik/linux-build:ubuntu-26.04`
- `ghcr.io/atrinik/windows-build:mxe`

Every successful image publication updates `latest`, its rolling platform tag,
and a `sha-<commit>` tag. Publishing from an image-repository tag matching
`vX.Y.Z` also publishes the corresponding `X.Y.Z` image tag. Auto-tagging
detects Linux and Windows input changes independently, so changing one image
does not rebuild the other.

## Publishing

Merged pull requests are automatically tagged by incrementing the patch
component of the highest existing `vMAJOR.MINOR.PATCH` tag. A repository with
no tags starts at `v0.0.1`. The auto-tag workflow validates the squash-merge
commit on `master` and dispatches only the Linux and/or Windows publisher whose
inputs changed. Each dispatched workflow publishes the version tag together
with its rolling, `latest`, and commit tags.

Either publisher can also be started manually from the Actions page. To create
and publish an image version manually:

```sh
git tag -a v1.0.0 -m "Devcontainer images v1.0.0"
git push origin v1.0.0
```

Tags pushed outside the auto-tag workflow intentionally build both images,
providing matching immutable versions for a coordinated toolchain release.

## Local validation

```sh
docker build --check --file linux/Dockerfile .
docker build --check --file windows/Dockerfile .

docker build --file linux/Dockerfile --tag atrinik-linux-build .
docker build --file windows/Dockerfile \
  --build-arg MXE_BUILD_JOBS="$(nproc)" \
  --tag atrinik-windows-build .
```

The Windows image compiles MXE and its dependency stack and can take a long
time on a cold build. GitHub Actions uses separate BuildKit cache scopes for
the two images; cache export failures are non-fatal because publishing a usable
image is more important than preserving an optimization.
