# syntax=docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89

FROM mcr.microsoft.com/devcontainers/base:bookworm@sha256:73d85a96694a2cadca1ba3fcb5721f2312a64f1d571dd86f6c77e10a708931dc AS windows-shared

ENV DEBIAN_FRONTEND=noninteractive

RUN rm -f /etc/apt/apt.conf.d/docker-clean

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update \
    && apt-get install -y --no-install-recommends \
        autoconf \
        automake \
        autopoint \
        bison \
        bzip2 \
        ca-certificates \
        cmake \
        flex \
        g++ \
        g++-multilib \
        gettext \
        git \
        gperf \
        intltool \
        libc6-dev-i386 \
        libclang-dev \
        libgdk-pixbuf-2.0-dev \
        libgl-dev \
        libltdl-dev \
        libpcre2-dev \
        libssl-dev \
        libtool-bin \
        libxml-parser-perl \
        lzip \
        make \
        mingw-w64-tools \
        ninja-build \
        openssh-client \
        openssl \
        p7zip-full \
        patch \
        perl \
        python-is-python3 \
        python3 \
        python3-mako \
        python3-packaging \
        python3-pkg-resources \
        python3-setuptools \
        ruby \
        sqlite3 \
        unzip \
        wget \
        xz-utils \
        zip

ARG MXE_REF=8784776b145a8ddd350ce32aa0908ac10977060c
ARG MXE_BUILD_JOBS=2
ARG MINIUPNPC_COMMIT=bf4215a7574f88aa55859db9db00e3ae58cf42d6
ARG PYTHON_VERSION=3.14.6
ARG PYTHON_EMBED_SHA256=df901e84a896ff1ee720ad03377e0c8d8c2244fda79808aeeaff6316df1cb75c
ARG PYTHON_SOURCE_SHA256=143b1dddefaec3bd2e21e3b839b34a2b7fb9842272883c576420d605e9f30c63
RUN git clone --filter=blob:none https://github.com/mxe/mxe.git /opt/mxe \
    && git -C /opt/mxe checkout "${MXE_REF}"

COPY windows/curl-openssl.patch /tmp/curl-openssl.patch
RUN git -C /opt/mxe apply /tmp/curl-openssl.patch \
    && chown -R vscode:vscode /opt/mxe

ENV MXE_ROOT=/opt/mxe \
    MXE_TARGET=x86_64-w64-mingw32.shared \
    MXE_PREFIX=/opt/mxe/usr/x86_64-w64-mingw32.shared \
    MXE_TOOLCHAIN_FILE=/opt/mxe/usr/x86_64-w64-mingw32.shared/share/cmake/mxe-conf.cmake \
    MXE_RUNTIME_DIR=/opt/mxe/usr/x86_64-w64-mingw32.shared/bin \
    ATRINIK_WINDOWS_PYTHON_INCLUDE_DIR=/opt/mxe/usr/x86_64-w64-mingw32.shared/include/python3.14 \
    ATRINIK_WINDOWS_PYTHON_LIBRARY=/opt/mxe/usr/x86_64-w64-mingw32.shared/lib/libpython314.dll.a \
    ATRINIK_WINDOWS_PYTHON_RUNTIME_DIR=/opt/mxe/python-runtime \
    PATH=/opt/mxe/usr/bin:${PATH}

USER vscode
RUN make -C /opt/mxe --jobs="${MXE_BUILD_JOBS}" JOBS="${MXE_BUILD_JOBS}" \
        MXE_TARGETS=x86_64-w64-mingw32.shared \
        openssl
RUN make -C /opt/mxe --jobs="${MXE_BUILD_JOBS}" JOBS="${MXE_BUILD_JOBS}" \
        MXE_TARGETS=x86_64-w64-mingw32.shared \
        cc cmake curl openssl zlib libxml2 sdl3
COPY --chown=vscode:vscode windows/sdl3-image-disable-tiff.patch \
        /tmp/sdl3-image-disable-tiff.patch
RUN git -C /opt/mxe apply /tmp/sdl3-image-disable-tiff.patch \
    && make -C /opt/mxe --jobs="${MXE_BUILD_JOBS}" JOBS="${MXE_BUILD_JOBS}" \
        MXE_TARGETS=x86_64-w64-mingw32.shared \
        sdl3_image \
    || { \
        cat /opt/mxe/log/sdl3_image_x86_64-w64-mingw32.shared; \
        exit 1; \
    }
RUN make -C /opt/mxe --jobs="${MXE_BUILD_JOBS}" JOBS="${MXE_BUILD_JOBS}" \
        MXE_TARGETS=x86_64-w64-mingw32.shared \
        sdl3_ttf
RUN test "$(/opt/mxe/usr/x86_64-w64-mingw32.shared/bin/curl-config --ssl-backends)" \
        = "OpenSSL"

# Install the audio manifest reader after the expensive MXE foundation so this
# small dependency does not invalidate the established cross-toolchain cache.
USER root
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update \
    && apt-get install -y --no-install-recommends jq
USER vscode

# MXE does not yet package SDL3_mixer. Cross-build the checksum-pinned release
# with static libogg, libopus, and libopusfile inputs. This keeps the shared
# SDL3_mixer DLL self-contained instead of creating an easy-to-miss codec DLL
# closure for packaged clients.
COPY --chown=vscode:vscode audio-toolchain.json /tmp/audio-toolchain.json
COPY --chown=vscode:vscode tools/build-sdl3-mixer.sh /tmp/build-sdl3-mixer.sh
RUN /tmp/build-sdl3-mixer.sh \
        /tmp/audio-toolchain.json \
        x86_64-w64-mingw32.shared-cmake \
        "${MXE_PREFIX}" "${MXE_BUILD_JOBS}" \
    && test "$(x86_64-w64-mingw32.shared-pkg-config --modversion sdl3-mixer)" \
        = "$(jq -r '.sdl_mixer.version' /tmp/audio-toolchain.json)"

COPY --chown=vscode:vscode tools/audio/opus-probe.opus \
        ${MXE_PREFIX}/share/atrinik/audio/opus-probe.opus
COPY --chown=vscode:vscode tools/audio/sdl3-mixer-probe.c \
        /tmp/sdl3-mixer-probe.c
COPY --chown=vscode:vscode tools/verify-pe-imports.sh \
        /tmp/verify-pe-imports.sh
RUN test "$(sha256sum "${MXE_PREFIX}/share/atrinik/audio/opus-probe.opus" \
        | cut -d' ' -f1)" \
        = "$(jq -r '.fixture.sha256' /tmp/audio-toolchain.json)" \
    && x86_64-w64-mingw32.shared-gcc \
        -std=c17 -Wall -Wextra -Werror \
        /tmp/sdl3-mixer-probe.c \
        -o "${MXE_RUNTIME_DIR}/atrinik-sdl3-mixer-probe.exe" \
        $(x86_64-w64-mingw32.shared-pkg-config \
            --cflags --libs sdl3-mixer) \
    && jq -r '.windows.sdl_mixer_imports[]' \
        /tmp/audio-toolchain.json \
        | xargs /tmp/verify-pe-imports.sh \
            x86_64-w64-mingw32.shared-objdump \
            "${MXE_RUNTIME_DIR}/SDL3_mixer.dll" \
    && jq -r '.windows.support_runtime_imports["libssp-0.dll"][]' \
        /tmp/audio-toolchain.json \
        | xargs /tmp/verify-pe-imports.sh \
            x86_64-w64-mingw32.shared-objdump \
            "${MXE_RUNTIME_DIR}/libssp-0.dll" \
    && ! find "${MXE_RUNTIME_DIR}" -maxdepth 1 -type f \
        \( -iname '*opus*.dll' -o -iname 'libogg*.dll' \) \
        -print -quit | grep -q . \
    && rm /tmp/sdl3-mixer-probe.c

RUN git clone --filter=blob:none https://github.com/miniupnp/miniupnp.git /tmp/miniupnp \
    && git -C /tmp/miniupnp checkout "${MINIUPNPC_COMMIT}" \
    && x86_64-w64-mingw32.shared-cmake \
        -S /tmp/miniupnp/miniupnpc \
        -B /tmp/miniupnp-build \
        -DUPNPC_BUILD_STATIC=ON \
        -DUPNPC_BUILD_SHARED=OFF \
        -DUPNPC_BUILD_TESTS=OFF \
    && cmake --build /tmp/miniupnp-build --parallel "${MXE_BUILD_JOBS}" \
    && cmake --install /tmp/miniupnp-build \
    && rm -rf /tmp/miniupnp /tmp/miniupnp-build

FROM windows-shared AS windows-build

RUN mkdir -p "${ATRINIK_WINDOWS_PYTHON_RUNTIME_DIR}" /tmp/python-sdk \
    && wget -q \
        "https://www.python.org/ftp/python/${PYTHON_VERSION}/python-${PYTHON_VERSION}-embed-amd64.zip" \
        -O /tmp/python-sdk/python-embed.zip \
    && echo "${PYTHON_EMBED_SHA256}  /tmp/python-sdk/python-embed.zip" \
        | sha256sum -c - \
    && wget -q \
        "https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tar.xz" \
        -O /tmp/python-sdk/python-source.tar.xz \
    && echo "${PYTHON_SOURCE_SHA256}  /tmp/python-sdk/python-source.tar.xz" \
        | sha256sum -c - \
    && unzip -q /tmp/python-sdk/python-embed.zip \
        -d "${ATRINIK_WINDOWS_PYTHON_RUNTIME_DIR}" \
    && tar -xf /tmp/python-sdk/python-source.tar.xz -C /tmp/python-sdk \
    && mkdir -p "${ATRINIK_WINDOWS_PYTHON_INCLUDE_DIR}" \
    && cp -R "/tmp/python-sdk/Python-${PYTHON_VERSION}/Include/." \
        "${ATRINIK_WINDOWS_PYTHON_INCLUDE_DIR}/" \
    && cp "/tmp/python-sdk/Python-${PYTHON_VERSION}/PC/pyconfig.h" \
        "${ATRINIK_WINDOWS_PYTHON_INCLUDE_DIR}/pyconfig.h" \
    && cd /tmp/python-sdk \
    && gendef "${ATRINIK_WINDOWS_PYTHON_RUNTIME_DIR}/python314.dll" \
    && x86_64-w64-mingw32.shared-dlltool \
        -d python314.def \
        -D python314.dll \
        -l "${ATRINIK_WINDOWS_PYTHON_LIBRARY}" \
    && rm -rf /tmp/python-sdk

USER root

# Native build dependencies used by Atrinik's build-windows.sh to run the Linux
# world maker before cross-compiling and packaging the Windows server.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update \
    && apt-get install -y --no-install-recommends \
        libcurl4-openssl-dev \
        libgd-dev \
        libidn2-dev \
        libminiupnpc-dev \
        python3-dev \
        zlib1g-dev

COPY windows/mxe-path.sh /etc/profile.d/mxe-path.sh
COPY audio-toolchain.json /usr/local/share/atrinik/audio-toolchain.json
COPY audio-toolchain.spdx.json /usr/local/share/atrinik/audio-toolchain.spdx.json

RUN command -v x86_64-w64-mingw32.shared-gcc \
    && command -v x86_64-w64-mingw32.shared-cmake \
    && bash -lc 'command -v x86_64-w64-mingw32.shared-gcc' \
    && bash -lc 'command -v x86_64-w64-mingw32.shared-cmake' \
    && su --login vscode --command \
        'command -v x86_64-w64-mingw32.shared-gcc' \
    && su --login vscode --command \
        'command -v x86_64-w64-mingw32.shared-cmake' \
    && x86_64-w64-mingw32.shared-gcc --version \
    && /opt/mxe/usr/x86_64-pc-linux-gnu/bin/cmake --version \
    && test -f "${MXE_RUNTIME_DIR}/SDL3.dll" \
    && test -f "${MXE_RUNTIME_DIR}/SDL3_image.dll" \
    && test -f "${MXE_RUNTIME_DIR}/SDL3_mixer.dll" \
    && test -f "${MXE_RUNTIME_DIR}/atrinik-sdl3-mixer-probe.exe" \
    && test -f "${MXE_RUNTIME_DIR}/SDL3_ttf.dll" \
    && pkg-config --exists libidn2 \
    && ssh -V

# The Classic pull-request Check only needs the completed cross-toolchain and
# staging utilities. Start again from the pinned base so MXE sources, logs,
# package caches, the Windows Python SDK/runtime, and native worldmaker
# dependencies do not become layers in this task-focused image. This stage is
# deliberately branches from the shared toolchain before general-image Python
# and worldmaker additions, so changes to those additions cannot invalidate it.
FROM windows-shared AS classic-check-export

USER root
RUN mkdir -p /opt/classic-check/mxe \
    && tar -C /opt/mxe \
        --exclude='usr/x86_64-w64-mingw32.shared/include/python3.14' \
        --exclude='usr/x86_64-w64-mingw32.shared/lib/libpython314.dll.a' \
        -cf - \
        usr/bin \
        usr/include \
        usr/installed \
        usr/lib \
        usr/libexec \
        usr/share \
        usr/x86_64-w64-mingw32.shared \
        .ccache/bin \
        .ccache/etc \
        | tar -C /opt/classic-check/mxe -xf - \
    && mkdir -p \
        /opt/classic-check/mxe/usr/x86_64-pc-linux-gnu/bin \
        /opt/classic-check/mxe/usr/x86_64-pc-linux-gnu/share \
    && cp -a \
        /opt/mxe/usr/x86_64-pc-linux-gnu/bin/cmake \
        /opt/mxe/usr/x86_64-pc-linux-gnu/bin/cpack \
        /opt/mxe/usr/x86_64-pc-linux-gnu/bin/ctest \
        /opt/mxe/usr/x86_64-pc-linux-gnu/bin/pkgconf \
        /opt/mxe/usr/x86_64-pc-linux-gnu/bin/x86_64-w64-mingw32.shared-g++ \
        /opt/mxe/usr/x86_64-pc-linux-gnu/bin/x86_64-w64-mingw32.shared-gcc \
        /opt/classic-check/mxe/usr/x86_64-pc-linux-gnu/bin/ \
    && cp -a /opt/mxe/usr/x86_64-pc-linux-gnu/share/cmake-3.31 \
        /opt/classic-check/mxe/usr/x86_64-pc-linux-gnu/share/

FROM mcr.microsoft.com/devcontainers/base:bookworm@sha256:73d85a96694a2cadca1ba3fcb5721f2312a64f1d571dd86f6c77e10a708931dc AS classic-check

ENV DEBIAN_FRONTEND=noninteractive

RUN rm -f /etc/apt/apt.conf.d/docker-clean

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        cmake \
        git \
        ninja-build \
        python3

COPY --from=classic-check-export --chown=vscode:vscode \
    /opt/classic-check/mxe/ /opt/mxe/

ENV MXE_ROOT=/opt/mxe \
    MXE_TARGET=x86_64-w64-mingw32.shared \
    MXE_PREFIX=/opt/mxe/usr/x86_64-w64-mingw32.shared \
    MXE_TOOLCHAIN_FILE=/opt/mxe/usr/x86_64-w64-mingw32.shared/share/cmake/mxe-conf.cmake \
    MXE_RUNTIME_DIR=/opt/mxe/usr/x86_64-w64-mingw32.shared/bin \
    PATH=/opt/mxe/.ccache/bin:/opt/mxe/usr/bin:${PATH}

COPY windows/mxe-path.sh /etc/profile.d/mxe-path.sh
COPY windows/classic-check-toolchain.json \
    /usr/local/share/atrinik/classic-check-toolchain.json
COPY audio-toolchain.json /usr/local/share/atrinik/audio-toolchain.json
COPY audio-toolchain.spdx.json \
    /usr/local/share/atrinik/audio-toolchain.spdx.json

RUN test "$(command -v ccache)" = /opt/mxe/.ccache/bin/ccache \
    && test "$(command -v x86_64-w64-mingw32.shared-gcc)" \
        = /opt/mxe/usr/bin/x86_64-w64-mingw32.shared-gcc \
    && test "$(readlink /opt/mxe/usr/x86_64-pc-linux-gnu/bin/x86_64-w64-mingw32.shared-gcc)" \
        = /opt/mxe/.ccache/bin/ccache \
    && command -v x86_64-w64-mingw32.shared-cmake \
    && command -v x86_64-w64-mingw32.shared-objdump \
    && command -v x86_64-w64-mingw32.shared-pkg-config \
    && command -v cmake \
    && command -v cpack \
    && command -v git \
    && command -v ninja \
    && command -v python3 \
    && for package in \
        libcurl libidn2 libxml-2.0 miniupnpc openssl \
        sdl3 sdl3-image sdl3-mixer sdl3-ttf; do \
        x86_64-w64-mingw32.shared-pkg-config --exists "${package}"; \
    done \
    && test -f "${MXE_TOOLCHAIN_FILE}" \
    && test -f "${MXE_RUNTIME_DIR}/SDL3.dll" \
    && test -f "${MXE_RUNTIME_DIR}/SDL3_image.dll" \
    && test -f "${MXE_RUNTIME_DIR}/SDL3_mixer.dll" \
    && test -f "${MXE_RUNTIME_DIR}/SDL3_ttf.dll" \
    && test -f "${MXE_RUNTIME_DIR}/atrinik-sdl3-mixer-probe.exe" \
    && test ! -e /opt/mxe/python-runtime \
    && test ! -e /opt/mxe/.ccache/ccache \
    && test ! -e /opt/mxe/usr/x86_64-pc-linux-gnu/icu4c \
    && test ! -e "${MXE_PREFIX}/include/python3.14" \
    && test ! -e "${MXE_PREFIX}/lib/libpython314.dll.a" \
    && su --login vscode --command \
        'test "$(command -v ccache)" = /opt/mxe/.ccache/bin/ccache' \
    && su --login vscode --command \
        'test "$(command -v x86_64-w64-mingw32.shared-gcc)" = /opt/mxe/usr/bin/x86_64-w64-mingw32.shared-gcc'

# Preserve the historical default build result for the general-purpose image.
FROM windows-build AS windows
