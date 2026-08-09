# Atrinik devcontainer images

[![Validate build images](https://github.com/atrinik/devcontainer/actions/workflows/validate.yml/badge.svg)](https://github.com/atrinik/devcontainer/actions/workflows/validate.yml)
[![Publish Linux build image](https://github.com/atrinik/devcontainer/actions/workflows/publish-linux.yml/badge.svg)](https://github.com/atrinik/devcontainer/actions/workflows/publish-linux.yml)
[![Publish Windows build image](https://github.com/atrinik/devcontainer/actions/workflows/publish-windows.yml/badge.svg)](https://github.com/atrinik/devcontainer/actions/workflows/publish-windows.yml)

This repository owns the reusable Linux and Windows build environments for
Atrinik. Keeping these images separate from the game repository means changes
to game code do not rebuild the toolchains.

Published images:

- `ghcr.io/atrinik/linux-build:ubuntu-26.04`
- `ghcr.io/atrinik/windows-build:mxe`

Every successful image publication updates `latest`, its rolling platform tag,
and a `sha-<commit>` tag. Publishing from an image-repository tag matching
`vX.Y.Z` also publishes the corresponding `X.Y.Z` image tag. Release automation
publishes both Linux and Windows images for every version so consumers can pin
a matched toolchain release.

## Publishing

After a validated squash merge, semantic-release interprets its Conventional
Commits title. Fixes and performance changes advance the patch version,
features advance the minor version, and breaking changes advance the major
version. Every other conventional type advances at least the patch version, so
every squash merge creates a tag. Each new tag dispatches both image
publishers.

Either publisher can also be started manually from the Actions page for a
reviewed rebuild or recovery of an existing ref. Manual dispatch does not
create a Git tag or semantic release. Semantic-release alone creates new
`vX.Y.Z` tags; do not create or push a release tag manually. When recovering a
versioned release, dispatch both publishers against the same existing tag so
the Linux and Windows image versions remain matched.

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
docker run --rm atrinik-linux-build go version
docker run --rm atrinik-linux-build rustc --version
docker run --rm atrinik-linux-build buf --version
docker run --rm atrinik-linux-build protoc --version
docker run --rm atrinik-linux-build protoc-gen-go --version
docker run --rm atrinik-linux-build protoc-gen-prost --version
docker run --rm atrinik-linux-build node --version
docker run --rm atrinik-linux-build pnpm --version
docker run --rm atrinik-windows-build \
  x86_64-w64-mingw32.shared-gcc --version
docker run --rm --user vscode atrinik-windows-build ssh -V
```

The Linux image includes the pinned replacement toolchains recorded in
[`toolchains.json`](toolchains.json): Go, Rust/rustup, Protobuf/protoc, Buf,
Node.js, pnpm, Syft, and Trivy. It also includes GCC, Clang with compiler-rt,
LLVM, clangd, clang-tidy, actionlint, the GitHub CLI, the OpenSSH client, and
the standalone Dev Containers CLI. Standard `zip`/`unzip` archive tooling is
present for deterministic cross-platform release assembly. SDL3, SDL3_image,
SDL3_ttf, Vulkan
diagnostics, and a pinned source build of SDL3_mixer support Rust client,
editor, and renderer development. Mesa's software Vulkan implementation and
Xvfb provide repeatable offscreen and SDL window validation without a physical
GPU or display. Interactive windows still require display forwarding. Native Windows
D3D12 validation runs on Windows runners rather than pretending the MXE image
is a Windows runtime. The image's ccache directory
defaults to writable container-local storage under `/tmp`; CI can override
`CCACHE_DIR` with a persistent cache. The Windows image provides the same SDL3
family through MXE and the official SDL3_mixer MinGW SDK. It also includes the
OpenSSH client and exports MXE's compiler-driver directory in `PATH` for both
interactive and non-interactive commands, including Debian login shells for
both `root` and `vscode`.

VS Code's Dev Containers extension automatically forwards a running host SSH
agent into either container. Add private keys to the host agent with `ssh-add`,
then use `ssh-add -l` in the opened container to confirm that its identities are
available. The images intentionally do not copy or mount the host's private key
files. SSH host configuration and `known_hosts` remain container-local.

The Windows image compiles MXE and its dependency stack and can take a long
time on a genuinely cold build. Pull-request validation restores both the
published rolling image's inline BuildKit cache and the image-specific GitHub
Actions cache. It exports cache-only results instead of loading the completed
images into the runner's Docker daemon. Release builds publish inline cache
metadata for cross-ref reuse and also retain the max-mode Actions cache;
Actions-cache export failures are non-fatal because publishing a usable image
is more important than preserving an optimization.

Pull requests build each image whose inputs changed. Linux validation also
runs actionlint over the repository workflows in a dedicated validation stage;
Windows validation checks that the MXE compiler and CMake wrapper are directly
discoverable through the image's default `PATH`.

## License

The repository's original build configuration and automation are MIT licensed;
see [LICENSE](LICENSE). Software installed into the published images retains
its own upstream license.
