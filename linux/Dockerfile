# syntax=docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89

FROM ubuntu:26.04@sha256:678c6550cc43645e08669028bc177f50be4e7c5b8cca677067b1914d4afc7a03 AS toolchain

ENV DEBIAN_FRONTEND=noninteractive

RUN rm -f /etc/apt/apt.conf.d/docker-clean

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update \
    && apt-get install -y --no-install-recommends \
        alsa-utils \
        build-essential \
        ca-certificates \
        ccache \
        check \
        clang \
        clang-format \
        clang-tidy \
        clangd \
        cmake \
        cppcheck \
        cproto \
        curl \
        fd-find \
        file \
        flex \
        fzf \
        gdb \
        gh \
        git \
        iproute2 \
        jq \
        libasound2-plugins \
        libclang-rt-dev \
        libcurl4-openssl-dev \
        libgd-dev \
        libidn2-dev \
        libminiupnpc-dev \
        libreadline-dev \
        libsdl3-dev \
        libsdl3-image-dev \
        libsdl3-ttf-dev \
        libssl-dev \
        libsubunit-dev \
        libvulkan-dev \
        libxml2-dev \
        libxml2-utils \
        llvm \
        mesa-vulkan-drivers \
        ninja-build \
        openssh-client \
        patch \
        pkgconf \
        pulseaudio-utils \
        python3-dev \
        python3-pip \
        python3-venv \
        ripgrep \
        shellcheck \
        shfmt \
        sudo \
        timidity \
        tree \
        unzip \
        valgrind \
        vulkan-tools \
        xauth \
        xvfb \
        xz-utils \
        zip \
        zlib1g-dev

# Declare independently updatable downloaded tools after the distribution
# layer so a language/security tool bump can reuse the expensive native SDK.
ARG ACTIONLINT_VERSION=1.7.12
ARG ACTIONLINT_SHA256=8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8
ARG BUF_VERSION=1.72.0
ARG BUF_SHA256=8720830e26a733da55bb89bcd3cb44849c0965fc0c44fb5d691cccdc64dca5af
ARG DEVCONTAINER_CLI_VERSION=0.88.0
ARG GO_VERSION=1.26.5
ARG GO_SHA256=5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053
ARG NODE_VERSION=24.18.1
ARG NODE_SHA256=d6c664df3f3f61458e8c277585571328522d705166723a7c7823a9253a4d15a0
ARG PNPM_VERSION=11.20.0
ARG PROTOC_VERSION=35.0
ARG PROTOC_SHA256=a45cda0989c17dd950db55f6fbe1e5814c50fda08e87aa422980ac1f89dddbbc
ARG PROTOC_GEN_GO_VERSION=1.36.11
ARG PROTOC_GEN_PROST_VERSION=0.5.0
ARG RUST_VERSION=1.97.1
ARG RUSTUP_VERSION=1.29.0
ARG RUSTUP_SHA256=4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10
ARG SYFT_VERSION=1.50.0
ARG SYFT_SHA256=bf7b29ff57f06da30918266a0e1c2885a8f99784798d1bdb1628886aa015d788
ARG TRIVY_VERSION=0.73.0
ARG TRIVY_SHA256=2edd39da482bb4e9831962487b68f68e3928ec3137794757f54d00383d79547b

ENV CARGO_HOME=/opt/cargo \
    GOROOT=/usr/local/go \
    RUSTUP_HOME=/opt/rustup \
    PATH=/opt/node/bin:/usr/local/go/bin:/opt/cargo/bin:${PATH}

# Replacement-stack tools use immutable, checksum-pinned upstream archives.
# This image is intentionally amd64-only until publishing gains a reviewed
# multi-architecture contract.
RUN curl --fail --location --silent --show-error \
        "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
        --output /tmp/go.tar.gz \
    && echo "${GO_SHA256}  /tmp/go.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/go.tar.gz -C /usr/local \
    && curl --fail --location --silent --show-error \
        "https://nodejs.org/download/release/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz" \
        --output /tmp/node.tar.xz \
    && echo "${NODE_SHA256}  /tmp/node.tar.xz" | sha256sum -c - \
    && mkdir -p /opt/node \
    && tar -xJf /tmp/node.tar.xz -C /opt/node --strip-components=1 \
    && curl --fail --location --silent --show-error \
        "https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip" \
        --output /tmp/protoc.zip \
    && echo "${PROTOC_SHA256}  /tmp/protoc.zip" | sha256sum -c - \
    && unzip -q /tmp/protoc.zip -d /usr/local bin/protoc 'include/*' \
    && curl --fail --location --silent --show-error \
        "https://github.com/bufbuild/buf/releases/download/v${BUF_VERSION}/buf-Linux-x86_64" \
        --output /usr/local/bin/buf \
    && echo "${BUF_SHA256}  /usr/local/bin/buf" | sha256sum -c - \
    && chmod 0755 /usr/local/bin/buf \
    && curl --fail --location --silent --show-error \
        "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/x86_64-unknown-linux-gnu/rustup-init" \
        --output /tmp/rustup-init \
    && echo "${RUSTUP_SHA256}  /tmp/rustup-init" | sha256sum -c - \
    && chmod 0755 /tmp/rustup-init \
    && /tmp/rustup-init -y --no-modify-path --profile minimal \
        --default-toolchain "${RUST_VERSION}" \
        --component clippy,rustfmt \
    && rustup target add x86_64-pc-windows-gnu \
    && GOBIN=/usr/local/bin go install \
        "google.golang.org/protobuf/cmd/protoc-gen-go@v${PROTOC_GEN_GO_VERSION}" \
    && cargo install --locked --version "${PROTOC_GEN_PROST_VERSION}" \
        protoc-gen-prost \
    && npm install --global "pnpm@${PNPM_VERSION}" \
    && npm cache clean --force \
    && rm -rf /root/go /opt/cargo/registry /opt/cargo/git \
    && rm -f /tmp/go.tar.gz /tmp/node.tar.xz /tmp/protoc.zip /tmp/rustup-init

RUN curl --fail --location --silent --show-error \
        "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz" \
        --output /tmp/syft.tar.gz \
    && echo "${SYFT_SHA256}  /tmp/syft.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/syft.tar.gz -C /usr/local/bin syft \
    && curl --fail --location --silent --show-error \
        "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
        --output /tmp/trivy.tar.gz \
    && echo "${TRIVY_SHA256}  /tmp/trivy.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
    && rm -f /tmp/syft.tar.gz /tmp/trivy.tar.gz

# Ubuntu does not currently package SDL3_mixer. Build the checksum-pinned
# release with static libogg, libopus, and libopusfile inputs so OPUS, WAV,
# and built-in Vorbis remain available without host codec libraries.
COPY audio-toolchain.json /tmp/audio-toolchain.json
COPY tools/build-sdl3-mixer.sh /tmp/build-sdl3-mixer.sh
RUN /tmp/build-sdl3-mixer.sh \
        /tmp/audio-toolchain.json cmake /usr/local "$(nproc)" \
    && ldconfig \
    && test "$(pkg-config --modversion sdl3-mixer)" \
        = "$(jq -r '.sdl_mixer.version' /tmp/audio-toolchain.json)"

COPY tools/audio/opus-probe.opus /usr/local/share/atrinik/audio/opus-probe.opus
COPY tools/audio/sdl3-mixer-probe.c /tmp/sdl3-mixer-probe.c
RUN test "$(sha256sum /usr/local/share/atrinik/audio/opus-probe.opus \
        | cut -d' ' -f1)" \
        = "$(jq -r '.fixture.sha256' /tmp/audio-toolchain.json)" \
    && cc -std=c17 -Wall -Wextra -Werror \
        /tmp/sdl3-mixer-probe.c \
        -o /usr/local/bin/atrinik-sdl3-mixer-probe \
        $(pkg-config --cflags --libs sdl3-mixer) \
    && atrinik-sdl3-mixer-probe \
        /usr/local/share/atrinik/audio/opus-probe.opus \
    && rm /tmp/sdl3-mixer-probe.c

RUN curl --fail --location --silent --show-error \
        "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_amd64.tar.gz" \
        --output /tmp/actionlint.tar.gz \
    && echo "${ACTIONLINT_SHA256}  /tmp/actionlint.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/actionlint.tar.gz -C /usr/local/bin actionlint \
    && rm /tmp/actionlint.tar.gz \
    && actionlint --version | grep -Fx "${ACTIONLINT_VERSION}"

RUN npm install --global \
        "@devcontainers/cli@${DEVCONTAINER_CLI_VERSION}" \
    && npm cache clean --force \
    && test "$(devcontainer --version)" = "${DEVCONTAINER_CLI_VERSION}"

# The restricted agent sandbox exposes /tmp as writable even when the normal
# user cache directory is read-only. CI may override this with a persistent
# workspace cache.
ENV CCACHE_DIR=/tmp/atrinik-ccache
RUN install -d -m 1777 "${CCACHE_DIR}"

# Ubuntu packages fd as "fdfind" to avoid a naming conflict. Provide the
# conventional command name expected by editor integrations and CLI tooling.
RUN ln -s /usr/bin/fdfind /usr/local/bin/fd

COPY linux/asound.conf /etc/asound.conf

# Ubuntu 26.04 already provides this non-root account. Dev Containers updates
# its UID/GID to match the owner of the bind-mounted repository.
ARG USERNAME=ubuntu
RUN install -d -o "${USERNAME}" -g "${USERNAME}" "/home/${USERNAME}/.codex" \
    && printf '%s ALL=(ALL) NOPASSWD:ALL\n' "${USERNAME}" \
        > "/etc/sudoers.d/${USERNAME}" \
    && chmod 0440 "/etc/sudoers.d/${USERNAME}"

RUN clang --version \
    && test "$(go env GOVERSION)" = "go${GO_VERSION}" \
    && test "$(rustc --version | cut -d' ' -f2)" = "${RUST_VERSION}" \
    && test "$(node --version)" = "v${NODE_VERSION}" \
    && test "$(pnpm --version)" = "${PNPM_VERSION}" \
    && test "$(protoc --version)" = "libprotoc ${PROTOC_VERSION}" \
    && test "$(buf --version)" = "${BUF_VERSION}" \
    && test "$(protoc-gen-go --version)" \
        = "protoc-gen-go v${PROTOC_GEN_GO_VERSION}" \
    && test "$(protoc-gen-prost --version)" = "${PROTOC_GEN_PROST_VERSION}" \
    && gh --version \
    && llvm-config --version \
    && syft version \
    && trivy --version \
    && pkg-config --exists libidn2 \
    && pkg-config --exists vulkan \
    && command -v vulkaninfo \
    && command -v Xvfb \
    && command -v xvfb-run \
    && ssh -V \
    && zip -v >/dev/null \
    && unzip -v >/dev/null

COPY toolchains.json /usr/local/share/atrinik/toolchains.json
COPY audio-toolchain.json /usr/local/share/atrinik/audio-toolchain.json
COPY audio-toolchain.spdx.json /usr/local/share/atrinik/audio-toolchain.spdx.json

FROM toolchain AS validation

COPY .github/actionlint.yaml /workspace/.github/actionlint.yaml
COPY .github/workflows /workspace/.github/workflows
COPY toolchains.json /workspace/toolchains.json
COPY audio-toolchain.json /workspace/audio-toolchain.json
COPY audio-toolchain.spdx.json /workspace/audio-toolchain.spdx.json
COPY tools/validate-toolchains.sh /workspace/tools/validate-toolchains.sh

RUN actionlint \
    -config-file /workspace/.github/actionlint.yaml \
    /workspace/.github/workflows/*.yml \
    && /workspace/tools/validate-toolchains.sh \
        /workspace/toolchains.json /usr/local/share/atrinik/toolchains.json \
        /workspace/audio-toolchain.json \
        /usr/local/share/atrinik/audio-toolchain.json \
        /workspace/audio-toolchain.spdx.json \
        /usr/local/share/atrinik/audio-toolchain.spdx.json \
    && syft dir:/ --override-default-catalogers sbom-cataloger -o json \
        | jq -e --slurpfile inventory /workspace/audio-toolchain.json \
            '([.artifacts[] | [.name, .version]] | sort) == \
             (($inventory[0].dependencies + [$inventory[0].sdl_mixer]) \
              | map([.name, .version]) | sort)'

FROM toolchain AS final
