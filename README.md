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
- `ghcr.io/atrinik/windows-build:classic-check-mxe`

Every image publication creates an immutable `sha-<commit>` candidate. The
Windows publisher also creates a `classic-check-sha-<commit>` candidate in the
existing private `windows-build` package, preserving its governed Classic
Actions read access. It smokes that exact published digest and executes its six
staged tests on Windows before promoting `latest`, `mxe`, `classic-check`, and
`classic-check-mxe`. Publishing from an image-repository tag matching `vX.Y.Z`
also promotes the corresponding `X.Y.Z` and `classic-check-X.Y.Z` aliases.
Release automation publishes all three image variants for every version so
consumers can pin a matched, verified toolchain release.

GHCR cannot atomically move aliases for two different manifests. The Windows
promotion job therefore moves the Classic aliases first and the general aliases
last, after both immutable candidates and native tests pass. If the final
registry operation fails, rerun the failed promotion job in that same workflow
run. The job idempotently reapplies both alias sets from the preserved,
verified digest outputs; do not create a replacement release tag.

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
docker build --file windows/Dockerfile \
  --target classic-check \
  --build-arg MXE_BUILD_JOBS="$(nproc)" \
  --tag atrinik-windows-check .

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
docker run --rm atrinik-linux-build \
  atrinik-sdl3-mixer-probe \
  /usr/local/share/atrinik/audio/opus-probe.opus
docker run --rm atrinik-linux-build \
  syft dir:/ --override-default-catalogers sbom-cataloger -o table
docker run --rm atrinik-windows-build \
  x86_64-w64-mingw32.shared-gcc --version
docker run --rm --user vscode atrinik-windows-build ssh -V
docker run --rm --user vscode atrinik-windows-check \
  x86_64-w64-mingw32.shared-gcc --version
```

The Linux image includes the pinned replacement toolchains recorded in
[`toolchains.json`](toolchains.json): Go, Rust/rustup, Protobuf/protoc, Buf,
Node.js, pnpm, Syft, and Trivy. It also includes GCC, Clang with compiler-rt,
LLVM, clangd, clang-tidy, actionlint, the GitHub CLI, the OpenSSH client, and
the standalone Dev Containers CLI. Standard `zip`/`unzip` archive tooling is
present for deterministic cross-platform release assembly. SDL3, SDL3_image,
SDL3_ttf, Vulkan diagnostics, and a pinned source build of SDL3_mixer support
Rust client, editor, and renderer development. SDL3_mixer provides built-in
WAV, stb_vorbis, and dr_mp3 decoders plus Opus through statically linked,
checksum-pinned libogg, libopus, and libopusfile. MIDI and module decoders are
intentionally unavailable. Mesa's software Vulkan implementation and Xvfb
provide repeatable offscreen and SDL window validation without a physical GPU
or display. Interactive windows still require display forwarding. Native
Windows D3D12 validation runs on Windows runners rather than pretending the MXE
image is a Windows runtime. The image's ccache directory
defaults to writable container-local storage under `/tmp`; CI can override
`CCACHE_DIR` with a persistent cache. The Windows image provides the same SDL3
family and decoder contract through MXE and the same SDL3_mixer source build.
The codec libraries are linked into `SDL3_mixer.dll`, so packaged clients need
no `libogg`, `libopus`, or `libopusfile` DLLs. The exact additional runtime
closure is the MXE-provided `libssp-0.dll`, retained for Opus stack-protector
and fortified-source support; it imports only standard Windows libraries.
Cross-object inspection enforces both import lists. The image also
includes the OpenSSH client and exports MXE's compiler-driver directory in
`PATH` for both interactive and non-interactive commands, including Debian
login shells for both `root` and `vscode`.

[`audio-toolchain.json`](audio-toolchain.json) is the machine-readable codec
inventory. It records every version, immutable source revision or release URL,
SHA-256 checksum, license, linkage choice, decoder, fixture checksum, and the
exact Windows import contract. The matching
[`audio-toolchain.spdx.json`](audio-toolchain.spdx.json) records SDL3_mixer and
all three statically linked codec packages in SPDX 2.3 form, because a scanner
cannot infer static source dependencies from the resulting shared library.
Both images carry the inventory and SBOM under
`/usr/local/share/atrinik/`; Syft's nested-SBOM cataloger incorporates those
packages in whole-image SBOM output.

Both builds compile the same no-device decoder probe. Linux validation runs it
during the image build, enumerates the required `WAV`, `STBVORBIS`, `DRMP3`,
and `OPUS` decoders, rejects MIDI and module decoders, fully decodes the
bundled Opus fixture, and rejects empty PCM. The
Windows image puts `atrinik-sdl3-mixer-probe.exe` and the fixture under the MXE
prefix so a clean native Windows package test can copy and run the identical
contract without installing codecs separately. The MXE build cannot execute a
Windows binary, so its image validation instead compiles the probe and verifies
the exact imports of the self-contained `SDL3_mixer.dll`; native execution
belongs on a Windows runner.

VS Code's Dev Containers extension automatically forwards a running host SSH
agent into either container. Add private keys to the host agent with `ssh-add`,
then use `ssh-add -l` in the opened container to confirm that its identities are
available. The images intentionally do not copy or mount the host's private key
files. SSH host configuration and `known_hosts` remain container-local.

The general Windows image compiles MXE and its dependency stack and can take a
long time on a genuinely cold build. Its `classic-check` target starts again
from the pinned base and copies only the completed MXE compiler/sysroot,
ccache, client DLL closure, and host-side tools used by
Classic Check. It intentionally excludes MXE source/build caches, the embedded
Windows Python SDK/runtime, and native Linux worldmaker dependencies required
only by server packaging. The exact included and excluded contract is recorded
in [`windows/classic-check-toolchain.json`](windows/classic-check-toolchain.json),
while the audio inventory and SPDX document are present unchanged in both
images.

Pull-request validation restores both the
published rolling image's inline BuildKit cache and the image-specific GitHub
Actions cache. It exports cache-only results instead of loading the completed
general image into the runner's Docker daemon, then loads the Classic Check
target for its full smoke, cross-build, native Windows execution, and size/pull
measurements. Release builds first publish immutable general and Classic SHA
candidates with inline cache metadata, smoke the exact Classic repository
digest, and execute its staged bundle on `windows-2025`. Only then does a
separate promotion job move the rolling and version aliases, with the general
aliases promoted last. Max-mode Actions caches are also retained for both
targets; Actions-cache export failures are non-fatal because publishing usable
images is more important than preserving an optimization.

The performance check compares the currently pinned Classic image with the
immutable candidate digest on a GitHub-hosted Ubuntu runner. Compressed sizes
come from a local OCI registry. Three counterbalanced cold/warm pull trials per
image each use a fresh Docker-in-Docker daemon against that registry to remove
GHCR network variance and daemon-layer reuse; every trial averages five
container starts. The artifact records raw samples, checkout/head/base source
coordinates, manifest digests, runner metadata, and medians. The pinned image's
first and warm GHCR pulls are also recorded, and the JSON plus Markdown evidence
is retained as the
`classic-check-image-measurements` workflow artifact for 30 days.

Pull requests build each image whose inputs changed. Linux validation also
runs actionlint over the repository workflows in a dedicated validation stage.
Windows validation checks that ccache, the MXE compiler, and the CMake wrapper
are directly discoverable through the image's default `PATH`, cross-builds and
stages every native test in the pinned Classic Check contract without network
access, and executes the complete bundle on `windows-2025`.

## License

The repository's original build configuration and automation are MIT licensed;
see [LICENSE](LICENSE). Software installed into the published images retains
its own upstream license.
