# Atrinik devcontainer images

[![Validate build images](https://github.com/atrinik/devcontainer/actions/workflows/validate.yml/badge.svg)](https://github.com/atrinik/devcontainer/actions/workflows/validate.yml)
[![Publish Linux build image](https://github.com/atrinik/devcontainer/actions/workflows/publish-linux.yml/badge.svg)](https://github.com/atrinik/devcontainer/actions/workflows/publish-linux.yml)
[![Publish Windows build image](https://github.com/atrinik/devcontainer/actions/workflows/publish-windows.yml/badge.svg)](https://github.com/atrinik/devcontainer/actions/workflows/publish-windows.yml)

This repository owns the reusable Linux and Windows build environments for
Atrinik. Keeping these images separate from the game repository means changes
to game code do not rebuild the toolchains.

Published images:

- `ghcr.io/atrinik/linux-build:ubuntu-26.04`
- `ghcr.io/atrinik/classic-build:ubuntu-26.04`
- `ghcr.io/atrinik/windows-build:mxe`
- `ghcr.io/atrinik/windows-build:classic-check-mxe`

Every non-candidate Linux publication updates `latest`, `ubuntu-26.04`, and a
`sha-<commit>` tag for both Linux packages. A Windows publication first creates
immutable `sha-<commit>` and `classic-check-sha-<commit>` candidates in the
existing private `windows-build` package, preserving its governed Classic
Actions read access. It smokes the exact published Classic digest and executes
its six staged tests on Windows before promoting `latest`, `mxe`,
`classic-check`, and `classic-check-mxe`. Publishing from an image-repository
tag matching `vX.Y.Z` also promotes the corresponding `X.Y.Z` and
`classic-check-X.Y.Z` aliases.
Release automation publishes the broad Linux, slim Linux Classic, general
Windows, and task-focused Windows Classic variants for every version so
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

Either publisher workflow can also be started manually from the Actions page
for a reviewed rebuild or recovery of an existing ref. Manual dispatch does not
create a Git tag or semantic release. Semantic-release alone creates new
`vX.Y.Z` tags; do not create or push a release tag manually. The Linux
publisher produces both `linux-build` and `classic-build`. Its
`candidate_only` input skips the broad image and publishes Classic only as
`candidate-sha-<commit>` without moving any stable or version tag. When
recovering a versioned release, leave that input disabled and dispatch the
Linux and Windows publishers against the same existing tag so all three image
packages and all four variants remain matched.

## Local validation

The isolated `gh extension list` smoke requires `GH_TOKEN` to be exported from
an authenticated developer session; the token is passed only to that disposable
runtime container and is never supplied to the image build.

```sh
docker build --check --file linux/Dockerfile .
docker build --check --file windows/Dockerfile .

docker build --file linux/Dockerfile --tag atrinik-linux-build .
docker build --file linux/Dockerfile \
  --platform linux/amd64 \
  --target classic-validation \
  --tag atrinik-classic-validation .
docker build --file linux/Dockerfile \
  --platform linux/amd64 \
  --target classic-final \
  --tag atrinik-classic-build .
docker build --file windows/Dockerfile \
  --build-arg MXE_BUILD_JOBS="$(nproc)" \
  --tag atrinik-windows-build .
docker build --file windows/Dockerfile \
  --target classic-check \
  --build-arg MXE_BUILD_JOBS="$(nproc)" \
  --tag atrinik-windows-check .

docker run --rm atrinik-linux-build clang --version
docker run --rm --user ubuntu --env HOME=/home/ubuntu \
  atrinik-linux-build gh version
docker run --rm --user ubuntu --env HOME=/home/ubuntu \
  --env GH_TOKEN atrinik-linux-build gh extension list
docker run --rm --user ubuntu --env HOME=/home/ubuntu \
  atrinik-linux-build gh stack --version
docker run --rm --user ubuntu --env HOME=/home/ubuntu \
  atrinik-linux-build gh stack --help
docker run --rm --user ubuntu --env HOME=/home/ubuntu \
  atrinik-linux-build sha256sum \
  /home/ubuntu/.local/share/gh/extensions/gh-stack/gh-stack
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
docker run --rm atrinik-classic-build gcc --version
docker run --rm atrinik-classic-build cmake --version
docker run --rm atrinik-classic-build ccache --version
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

Run the pinned full Classic contract from this repository root, substituting
isolated absolute paths for the source checkout and cache:

```sh
classic_source=/absolute/path/to/atrinik-classic
classic_cache=/absolute/path/to/empty-classic-ccache
install -d -m 1777 "${classic_cache}"
docker run --rm \
  --user "$(id -u):$(id -g)" \
  --env CCACHE_DIR=/cache/ccache \
  --env HOME=/tmp/classic-home \
  --volume "$(pwd):/image-source:ro" \
  --volume "${classic_source}:/workspace" \
  --volume "${classic_cache}:/cache/ccache" \
  --workdir /workspace \
  atrinik-classic-build \
  /image-source/tools/validate-classic-check.sh /workspace
```

The `classic-final` target is a separate, amd64-only CI contract rather than a
trimmed development image. It starts from the same digest-pinned Ubuntu 26.04
base, bootstraps exact locked CA and TLS runtime packages, and resolves all
packages from the timestamp in
[`classic-toolchain.json`](classic-toolchain.json). Direct
package versions are locked in
[`classic-packages.lock`](classic-packages.lock). The image contains GCC,
CMake/Ninja, Python/gcovr, Check, ccache, and the union of native dependencies
needed by the Classic client and server. SDL3_mixer and its codec closure retain
the checksum-pinned source and nested SPDX inventory used by the development
image.

Classic runs as the unprivileged `ubuntu` user by default. `/cache/ccache` is a
mode-1777 mount contract so CI can run with its own numeric UID and persist the
directory without granting root. Consumers must still select ccache explicitly
with `-DCMAKE_C_COMPILER_LAUNCHER=ccache`; `CCACHE_DIR` alone does not activate
compiler caching. Persistent reuse must keep that numeric UID stable because
ccache's nested directories are owner-writable; if the runner UID changes,
discard or reinitialize the cache instead of sharing it across UIDs. The image
smoke target proves a repeated compilation hits the cache, validates every
locked direct package and tool version, checks the native
`pkg-config` surface, decodes the bundled Opus fixture, and inspects the image
plus nested dependency inventory in one SPDX 2.3 scan. The attached BuildKit
SBOM inventories discoverable image packages; the bundled
`/usr/local/share/atrinik/audio-toolchain.spdx.json` is the authoritative source
inventory for statically linked SDL3_mixer and codecs. Pull-request validation
then runs representative client and server configure-build-test-coverage
commands against the exact Classic revision recorded in the inventory as a
non-root runner UID.

Every non-candidate Classic publication updates `latest`, `ubuntu-26.04`, and
`sha-<commit>`. A semantic-release tag also publishes the matching `X.Y.Z` tag,
with BuildKit provenance and an attached SBOM. Consuming workflows should pin
the digest, never a rolling tag. To update that pin:

1. Update the matching Ubuntu base digest and snapshot value in both
   `linux/Dockerfile` and `classic-toolchain.json`, refresh the exact direct
   versions in `classic-packages.lock`, and update the tool versions and pinned
   Classic validation commit in `classic-toolchain.json`.
2. Build `classic-validation` and `classic-final`, run the repository checks,
   and compare compressed image size plus local client/server timings with the
   prior digest.
3. Before merge, dispatch `Publish Linux build image` on the reviewed head with
   `candidate_only` enabled. Resolve the immutable digest from
   `ghcr.io/atrinik/classic-build:candidate-sha-<commit>` and put that digest in
   the consuming review branch, including it in the ccache invalidation key.
4. On clean equivalent runners with the digest absent, time the first digest
   pull plus container startup. Without removing it, pull and start the same
   digest again to measure the warm local layer cache. Run the apt-based and
   image-based client/server jobs, record total and setup/build/test timings
   plus ccache statistics in
   [`classic-benchmark.md`](classic-benchmark.md), and attach the comparison to
   both reviews.
5. After the evidence passes review, merge through semantic-release and wait
   for both publisher workflows. Record the new versioned digest, rerun the
   image smoke against it, and compare its embedded tool inventories, package
   lock, and source checksums with the candidate before updating the consumer.
   The manifest digests themselves will differ because revision labels and
   provenance describe different builds. Only then remove superseded apt or
   prefix-cache setup.

The package snapshot is deliberately fail-closed: changing the snapshot or a
locked version requires a reviewed inventory update. The initial CA/TLS
bootstrap already uses the signed snapshot metadata and package hashes; only
TLS peer verification is temporarily disabled because the minimal base has no
CA bundle. After installing the exact locked TLS closure, a verified HTTPS
snapshot update must pass before any remaining package is installed. Snapshot
sources disable metadata expiry so the fixed timestamp remains rebuildable;
APT still verifies its signed metadata and package hashes.

The broad Linux image installs the official GitHub CLI 2.97.0 archive, pinned
by its published SHA-256, as the sole `gh` executable. It also installs the
official `github/gh-stack` extension v0.1.0 for the non-root `ubuntu` user with
`gh extension install github/gh-stack --pin v0.1.0`. The image validates the
extension's pinned manifest, ordinary `gh stack` dispatch, help output, and
the attested `linux-amd64` binary SHA-256
`358552dd7dce0a46ce153fe196270cec482b84f080947890aad4061a8d44bc0b`.
Both projects are MIT licensed; their pinned license texts are installed under
`/usr/local/share/licenses/`.

The upstream release attestation ties `github/gh-stack`'s
`.github/workflows/release.yml`, `refs/tags/v0.1.0`, and source commit
`a1b4a3d4d0bcde9ec3a78ab99b2d63af121857a9` to that asset digest. Pull-request
validation verifies those coordinates with `gh attestation verify` after the
image build, passing the workflow token only to the disposable validation
container at runtime. No GitHub credential enters the Dockerfile, build
arguments, image layers, or published image. Upgrades require reviewed version,
checksum, source, license, and attestation changes; do not run
`gh extension upgrade stack --force` as a runtime substitute.

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
All four image variants carry the inventory and SBOM under
`/usr/local/share/atrinik/`; Syft's nested-SBOM cataloger incorporates those
packages in whole-image SBOM output.

Both Dockerfiles compile the same no-device decoder probe for their image
variants. Linux validation runs it during the image build, enumerates the
required `WAV`, `STBVORBIS`, `DRMP3`, and `OPUS` decoders, rejects MIDI and
module decoders, fully decodes the bundled Opus fixture, and rejects empty PCM.
The Windows image puts `atrinik-sdl3-mixer-probe.exe` and the fixture under the
MXE prefix so a clean native Windows package test can copy and run the identical
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

Pull-request validation is deliberately private-package-free so fork-controlled
code never receives a GHCR read token or the private baseline image. It uses
image-specific GitHub Actions caches, exports the general image cache-only, and
loads the Classic Check target for its full smoke, cross-build, and native
Windows execution. A separate same-repository branch-push/dispatch workflow
authenticates to GHCR, restores the published inline cache, repeats the exact
candidate smoke and native tests, and publishes the size/pull measurements.
Release builds first publish immutable general and Classic SHA candidates with
inline cache metadata, smoke the exact Classic repository digest, and execute
its staged bundle on `windows-2025`. Only then does a separate promotion job
move the rolling and version aliases, with the general aliases promoted last.
Max-mode Actions caches are also retained for both targets; Actions-cache export
failures are non-fatal because publishing usable images is more important than
preserving an optimization.

The performance check compares the currently pinned Classic image with the
immutable candidate digest on a GitHub-hosted Ubuntu runner. Compressed sizes
come from a local OCI registry. Four counterbalanced cold/warm pull trials per
image alternate order evenly and each use a fresh Docker-in-Docker daemon
against that registry to remove GHCR network variance and daemon-layer reuse;
every trial averages five container starts. The artifact records raw samples,
checkout/head/base source coordinates, manifest digests, runner metadata, and
medians. The pinned image's first and warm GHCR pulls are also recorded, and
the JSON plus Markdown evidence is retained as the
`classic-check-image-measurements` workflow artifact for 30 days.

Pull requests build each image whose inputs changed. Linux validation also
runs actionlint over the repository workflows in a dedicated validation stage.
Windows validation checks that ccache, the MXE compiler, and the CMake wrapper
are directly discoverable through the image's default `PATH`, cross-builds and
stages every native test in the pinned Classic Check contract without network
access, and executes the complete bundle on `windows-2025`. Linux Classic
validation builds its smoke/SBOM target, loads the slim final target, and runs
the pinned Classic client and server checks as a non-root user.

## License

The repository's original build configuration and automation are MIT licensed;
see [LICENSE](LICENSE). Software installed into the published images retains
its own upstream license.
