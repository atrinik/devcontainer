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
  revision, smoke/SBOM checks, and published tags synchronized. Do not make it
  inherit the broad replacement/development toolchain.
- Every semantic release publishes all three images and their supported tags.
  The Linux publisher owns both `linux-build` and `classic-build`; the Windows
  publisher owns `windows-build`. Do not create manual release tags as a
  substitute for semantic-release.
- Validate Dockerfiles with `docker build --check`. Build and smoke-test each
  affected image, including `classic-validation` before `classic-final`; note
  that a cold Windows/MXE build is expensive and may rely on CI cache for final
  verification.
- Workflow changes also require actionlint and Atrinik GitHub-governance review
  for permissions, pinned actions, check names, and ruleset compatibility.
- Commits and pull-request titles use Conventional Commits. Preserve unrelated
  work and finish with `git diff --check`.
- Update this `AGENTS.md` in the same change when major rework alters image
  ownership, toolchains, tags, workflow contracts, or validation.
