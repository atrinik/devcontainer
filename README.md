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

docker run --rm atrinik-linux-build clang --version
docker run --rm atrinik-linux-build gh --version
docker run --rm atrinik-linux-build actionlint --version
docker run --rm atrinik-linux-build devcontainer --version
docker run --rm atrinik-windows-build \
  x86_64-w64-mingw32.shared-gcc --version
docker run --rm --user vscode atrinik-windows-build ssh -V
```

The Linux image includes GCC, Clang with compiler-rt, LLVM, clangd,
clang-tidy, actionlint, the GitHub CLI, the OpenSSH client, and the standalone
Dev Containers CLI. Its ccache directory defaults to writable container-local
storage under `/tmp`; CI can override `CCACHE_DIR` with a persistent cache. The
Windows image also includes the OpenSSH client and exports MXE's compiler-driver
directory in `PATH` for both interactive and non-interactive commands,
including Debian login shells for both `root` and `vscode`.

VS Code's Dev Containers extension automatically forwards a running host SSH
agent into either container. Add private keys to the host agent with `ssh-add`,
then use `ssh-add -l` in the opened container to confirm that its identities are
available. The images intentionally do not copy or mount the host's private key
files. SSH host configuration and `known_hosts` remain container-local.

The Windows image compiles MXE and its dependency stack and can take a long
time on a cold build. GitHub Actions uses separate BuildKit cache scopes for
the two images; cache export failures are non-fatal because publishing a usable
image is more important than preserving an optimization.

Pull requests build each image whose inputs changed. Linux validation also
runs actionlint over the repository workflows from inside the completed image;
Windows validation checks that the MXE compiler and CMake wrapper are directly
discoverable through the image's default `PATH`.
