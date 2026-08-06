# syntax=docker/dockerfile:1

FROM mcr.microsoft.com/devcontainers/base:bookworm

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
ARG SDL3_MIXER_VERSION=3.2.4
ARG SDL3_MIXER_MINGW_SHA256=2ff5f59be4683e0afb4339c4fa73c6228651e52d37b040ecf80da08edb3cecd6
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
        cc cmake curl openssl zlib libxml2 sdl3 sdl3_image sdl3_ttf
RUN test "$(/opt/mxe/usr/x86_64-w64-mingw32.shared/bin/curl-config --ssl-backends)" \
        = "OpenSSL"

# MXE does not yet package SDL3_mixer. Install the official, checksum-pinned
# x86_64 MinGW SDK into the MXE prefix; its DLL has no non-system dependency
# beyond the SDL3 DLL built above.
RUN wget -q \
        "https://github.com/libsdl-org/SDL_mixer/releases/download/release-${SDL3_MIXER_VERSION}/SDL3_mixer-devel-${SDL3_MIXER_VERSION}-mingw.tar.gz" \
        -O /tmp/SDL3_mixer-mingw.tar.gz \
    && echo "${SDL3_MIXER_MINGW_SHA256}  /tmp/SDL3_mixer-mingw.tar.gz" \
        | sha256sum -c - \
    && mkdir -p /tmp/SDL3_mixer-mingw \
    && tar -xzf /tmp/SDL3_mixer-mingw.tar.gz -C /tmp/SDL3_mixer-mingw \
    && cp -a \
        "/tmp/SDL3_mixer-mingw/SDL3_mixer-${SDL3_MIXER_VERSION}/x86_64-w64-mingw32/." \
        "${MXE_PREFIX}/" \
    && rm -rf /tmp/SDL3_mixer-mingw /tmp/SDL3_mixer-mingw.tar.gz \
    && test "$(x86_64-w64-mingw32.shared-pkg-config --modversion sdl3-mixer)" \
        = "${SDL3_MIXER_VERSION}"

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
        libminiupnpc-dev \
        python3-dev \
        zlib1g-dev

COPY windows/mxe-path.sh /etc/profile.d/mxe-path.sh

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
    && test -f "${MXE_RUNTIME_DIR}/SDL3_ttf.dll" \
    && ssh -V
