# Atrinik devcontainer image repository guide

- This repository owns reusable Linux and Windows build-toolchain images. The
  workspace wrapper owns checkout composition and VS Code launch configuration;
  component repositories own their source builds.
- Keep Linux and MXE/Windows toolchains coherent for supported client/server
  releases. Pin base images and downloaded toolchains according to project
  policy, preserve non-root usage, and avoid embedding credentials or mutable
  workspace state.
- `toolchains.json` is the machine-readable replacement-stack compatibility
  contract. Keep its Go, Rust, Protobuf, Buf, Node, pnpm, SBOM, vulnerability,
  target, and graphics declarations synchronized with the Linux Dockerfile and
  smoke checks. Native Windows Rust/D3D12 validation belongs on Windows
  runners; the MXE image remains the explicit classic cross-build owner.
- Treat Dockerfile inputs, `.dockerignore`, cache scopes, build arguments,
  published tags, and workflow path filters as one contract. If a relevant file
  changes, the required aggregate validation must still run.
- `classic-final` is the slim Classic Check target. Keep its Ubuntu snapshot,
  direct package lock, tool inventory, non-root ccache mount, Classic validation
  revision, shader-toolchain inventory, GPU runtime, smoke/SBOM checks, and
  published tags synchronized. Do not make it inherit the broad
  replacement/development toolchain.
- The public Classic image's shader contract is defined by
  `classic-shader-toolchain.json`: retain the exact DXC/SPIRV-Cross archive and
  source checksums, upstream licenses, and `/usr/local/bin` tool paths. Its
  `classic-vulkan-toolchain.json` contract builds the pinned Mesa Dozen driver
  from `classic-vulkan-packages.lock`, carries only the dzn library and ICD
  into both Linux images, and records the WSLg host mounts/environment. Its
  pinned Lavapipe/Xvfb packages remain the fork-safe headless path; consumers
  still pin a released image digest and supply WSLg adapter selection.
- Keep a stable numeric runner UID when restoring a Classic ccache directory;
  the mode-1777 mount root supports non-root initialization but does not make
  ccache's owner-writable nested directories reusable across different UIDs.
- A Linux `candidate_only` dispatch is the pre-merge Classic review path. It
  must publish only `classic-build:candidate-sha-<commit>` after validation and
  must never move a rolling, platform, or version tag.
- Every semantic release publishes the broad Linux, slim Linux Classic,
  general Windows, and task-focused Windows Classic images with their
  supported tags. The Linux publisher owns `linux-build` and `classic-build`;
  the Windows publisher owns both `windows-build` variants. Keep the
  `classic-check` target branched from the expensive shared MXE foundation
  before general-image Python/worldmaker additions, preserve the general
  Windows image as the default Dockerfile result, validate immutable SHA
  candidates before promoting rolling/version aliases, and recover partial
  alias promotion by rerunning the failed job from the same workflow run. Do
  not create manual release tags as a substitute for semantic-release.
- Validate Dockerfiles with `docker build --check`. Build and smoke-test each
  affected image, including `classic-validation` before `classic-final` and the
  Windows `classic-check` target plus native bundle; note that a cold
  Windows/MXE build is expensive and may rely on CI cache for final
  verification.
- Workflow changes also require actionlint and Atrinik GitHub-governance review
  for permissions, pinned actions, check names, and ruleset compatibility.
  Never expose private-package permissions or images to `pull_request` code;
  authenticated measurements belong to the same-repository push/dispatch path.
- Commits and pull-request titles use Conventional Commits. Preserve unrelated
  work and finish with `git diff --check`.
- Update this `AGENTS.md` in the same change when major rework alters image
  ownership, toolchains, tags, workflow contracts, or validation.
