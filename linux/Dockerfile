# syntax=docker/dockerfile:1

FROM ubuntu:26.04 AS toolchain

ENV DEBIAN_FRONTEND=noninteractive

ARG ACTIONLINT_VERSION=1.7.12
ARG ACTIONLINT_SHA256=8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8
ARG DEVCONTAINER_CLI_VERSION=0.88.0
ARG SDL3_MIXER_VERSION=3.2.4
ARG SDL3_MIXER_SHA256=182a07c745375e113dc740d43964ff21b0be29f29f59876c4dbc4db3d32f6901

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
        libminiupnpc-dev \
        libreadline-dev \
        libsdl3-dev \
        libsdl3-image-dev \
        libsdl3-ttf-dev \
        libssl-dev \
        libsubunit-dev \
        libxml2-dev \
        libxml2-utils \
        llvm \
        ninja-build \
        nodejs \
        npm \
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
        zlib1g-dev

# Ubuntu does not currently package SDL3_mixer. Build the official release
# with its dependency-free Ogg Vorbis and MP3 decoders, matching the formats
# Atrinik ships while keeping the image small and reproducible.
RUN curl --fail --location --silent --show-error \
        "https://github.com/libsdl-org/SDL_mixer/releases/download/release-${SDL3_MIXER_VERSION}/SDL3_mixer-${SDL3_MIXER_VERSION}.tar.gz" \
        --output /tmp/SDL3_mixer.tar.gz \
    && echo "${SDL3_MIXER_SHA256}  /tmp/SDL3_mixer.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/SDL3_mixer.tar.gz -C /tmp \
    && cmake \
        -S "/tmp/SDL3_mixer-${SDL3_MIXER_VERSION}" \
        -B /tmp/SDL3_mixer-build \
        -DCMAKE_BUILD_TYPE=Release \
        -DSDLMIXER_DEPS_SHARED=OFF \
        -DSDLMIXER_EXAMPLES=OFF \
        -DSDLMIXER_FLAC=OFF \
        -DSDLMIXER_GME=OFF \
        -DSDLMIXER_INSTALL=ON \
        -DSDLMIXER_MIDI=OFF \
        -DSDLMIXER_MOD=OFF \
        -DSDLMIXER_MP3=ON \
        -DSDLMIXER_MP3_DRMP3=ON \
        -DSDLMIXER_MP3_MPG123=OFF \
        -DSDLMIXER_OPUS=OFF \
        -DSDLMIXER_TESTS=OFF \
        -DSDLMIXER_VORBIS_STB=ON \
        -DSDLMIXER_VORBIS_VORBISFILE=OFF \
        -DSDLMIXER_WAVPACK=OFF \
    && cmake --build /tmp/SDL3_mixer-build --parallel "$(nproc)" \
    && cmake --install /tmp/SDL3_mixer-build \
    && ldconfig \
    && rm -rf "/tmp/SDL3_mixer-${SDL3_MIXER_VERSION}" \
        /tmp/SDL3_mixer-build \
        /tmp/SDL3_mixer.tar.gz \
    && test "$(pkg-config --modversion sdl3-mixer)" = "${SDL3_MIXER_VERSION}"

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
    && gh --version \
    && llvm-config --version \
    && ssh -V \
    && unzip -v >/dev/null

FROM toolchain AS validation

COPY .github/actionlint.yaml /workspace/.github/actionlint.yaml
COPY .github/workflows /workspace/.github/workflows

RUN actionlint \
    -config-file /workspace/.github/actionlint.yaml \
    /workspace/.github/workflows/*.yml

FROM toolchain AS final
