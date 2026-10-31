# syntax=docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89

# One Debian 12-built LLVM cohort serves Ubuntu and portable consumers. The
# bootstrap is build-only; every owned dependency uses the resulting Clang.
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS llvm-toolchain
ARG TARGETARCH
ARG LLVM_BUILD_JOBS=2
ENV DEBIAN_FRONTEND=noninteractive
COPY llvm-bootstrap-packages.lock /tmp/llvm-bootstrap-packages.lock
RUN test "${TARGETARCH}" = amd64 \
    && test "$(dpkg --print-architecture)" = amd64 \
    && rm /etc/apt/sources.list.d/debian.sources \
    && printf '%s\n' \
        'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20260901T000000Z bookworm main' \
        'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20260901T000000Z bookworm-updates main' \
        'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/20260901T000000Z bookworm-security main' \
        > /etc/apt/sources.list \
    && apt-get -o Acquire::Retries=5 -o APT::Update::Error-Mode=any update \
    && xargs apt-get -o Acquire::Retries=5 install -y --no-install-recommends \
        < /tmp/llvm-bootstrap-packages.lock \
    && while IFS='=' read -r package version; do \
        test "$(dpkg-query --show --showformat='${Version}' "${package}")" = "${version}"; \
       done < /tmp/llvm-bootstrap-packages.lock \
    && sed -i 's|http://snapshot.debian.org|https://snapshot.debian.org|g' /etc/apt/sources.list \
    && apt-get -o Acquire::Retries=5 -o APT::Update::Error-Mode=any update \
    && rm -rf /var/lib/apt/lists/*
COPY llvm-toolchain.json /tmp/llvm-toolchain.json
COPY tools/install_llvm_toolchain.py tools/validate_llvm_toolchain.py /tmp/
RUN python3 /tmp/install_llvm_toolchain.py --manifest /tmp/llvm-toolchain.json \
        --cache /tmp/llvm-downloads --prefix /opt/llvm-23.1.3 --jobs "${LLVM_BUILD_JOBS}" \
    && PATH="/opt/llvm-23.1.3/bin:${PATH}" python3 /tmp/validate_llvm_toolchain.py \
        --manifest /tmp/llvm-toolchain.json --prefix /opt/llvm-23.1.3 \
    && rm -rf /tmp/llvm-downloads


FROM mcr.microsoft.com/devcontainers/base:bookworm@sha256:99f5250dd2d5f8b11046d5662dd94c1e3c1dae56b560c7caad5ceb7edf349046 AS windows-shared
ENV DEBIAN_FRONTEND=noninteractive
RUN rm -f /etc/apt/apt.conf.d/docker-clean
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
        autoconf automake autopoint bison bzip2 ca-certificates ccache cmake \
        curl flex gettext git gperf libc6-dev libstdc++-12-dev libtool-bin lzip make ninja-build openssh-client \
        patch perl pkg-config python3 python3-mako python3-packaging python3-setuptools unzip wget xz-utils zip jq
ARG WINDOWS_BUILD_JOBS=2
ARG PYTHON_VERSION=3.14.6
ARG PYTHON_EMBED_SHA256=df901e84a896ff1ee720ad03377e0c8d8c2244fda79808aeeaff6316df1cb75c
ARG PYTHON_SOURCE_SHA256=143b1dddefaec3bd2e21e3b839b34a2b7fb9842272883c576420d605e9f30c63
COPY --from=llvm-toolchain /opt/llvm-23.1.3 /opt/llvm-23.1.3
COPY windows/classic-check-toolchain.json /tmp/classic-check-toolchain.json
RUN url=$(jq -er '.llvm_mingw.url' /tmp/classic-check-toolchain.json) \
    && hash=$(jq -er '.llvm_mingw.sha256' /tmp/classic-check-toolchain.json) \
    && curl --fail --location --show-error "$url" --output /tmp/llvm-mingw.tar.xz \
    && echo "$hash  /tmp/llvm-mingw.tar.xz" | sha256sum -c - \
    && mkdir -p /opt/llvm-mingw /opt/atrinik-windows/share/cmake \
    && tar -xf /tmp/llvm-mingw.tar.xz --strip-components=1 -C /opt/llvm-mingw \
    && rm /tmp/llvm-mingw.tar.xz \
    && mkdir -p /opt/atrinik-windows/share/licenses/llvm-mingw /opt/atrinik-windows/bin \
    && cp /opt/llvm-mingw/LICENSE.TXT /opt/atrinik-windows/share/licenses/llvm-mingw/LICENSE.TXT \
    && cp /opt/llvm-mingw/x86_64-w64-mingw32/share/mingw32/COPYING* /opt/atrinik-windows/share/licenses/llvm-mingw/ \
    && cp /opt/llvm-mingw/x86_64-w64-mingw32/bin/libc++.dll \
        /opt/llvm-mingw/x86_64-w64-mingw32/bin/libunwind.dll \
        /opt/llvm-mingw/x86_64-w64-mingw32/bin/libwinpthread-1.dll /opt/atrinik-windows/bin/ \
    && chown -R vscode:vscode /opt/atrinik-windows
ENV ATRINIK_WINDOWS_TOOLCHAIN_FILE=/opt/atrinik-windows/share/cmake/llvm-mingw.cmake \
    ATRINIK_WINDOWS_TARGET=x86_64-w64-mingw32 \
    ATRINIK_WINDOWS_RUNTIME_DIR=/opt/atrinik-windows/bin \
    ATRINIK_WINDOWS_PYTHON_INCLUDE_DIR=/opt/atrinik-windows/include/python3.14 \
    ATRINIK_WINDOWS_PYTHON_LIBRARY=/opt/atrinik-windows/lib/libpython314.dll.a \
    ATRINIK_WINDOWS_PYTHON_RUNTIME_DIR=/opt/atrinik-windows/python-runtime \
    PATH=/opt/llvm-23.1.3/bin:/opt/llvm-mingw/bin:/opt/atrinik-windows/bin:${PATH} \
    CC=clang CXX=clang++ AR=llvm-ar RANLIB=llvm-ranlib LD=ld.lld
COPY --chown=vscode:vscode windows/llvm-mingw-toolchain.cmake ${ATRINIK_WINDOWS_TOOLCHAIN_FILE}
COPY --chown=vscode:vscode windows/target-pkg-config.sh /opt/atrinik-windows/bin/x86_64-w64-mingw32-pkg-config
COPY --chown=vscode:vscode windows/build-dependencies.py windows/pe_tls.py windows/dependencies.json /tmp/windows-producer/
USER vscode
# Fresh target prefix: no binary or archive from the former GCC producer enters it.
RUN python3 /tmp/windows-producer/build-dependencies.py \
        --lock /tmp/windows-producer/dependencies.json --prefix /opt/atrinik-windows \
        --work-dir /tmp/windows-dependencies --jobs "${WINDOWS_BUILD_JOBS}" \
    && rm -rf /tmp/windows-dependencies
# Bind the native callback probe to the exact producer DLL's inspected symbols.
COPY --chown=vscode:vscode windows/glib-tls-probe.c windows/cairo-tls-probe.c /tmp/windows-producer/
RUN python3 /tmp/windows-producer/pe_tls.py \
        --dll /opt/atrinik-windows/bin/libglib-2.0-0.dll \
        --report /opt/atrinik-windows/share/atrinik/windows-dependencies/glib-tls.json \
        --header /tmp/windows-producer/glib-tls-rvas.h \
    && x86_64-w64-mingw32-clang -std=c17 -O2 -Wall -Wextra -Werror \
        /tmp/windows-producer/glib-tls-probe.c \
        $(x86_64-w64-mingw32-pkg-config --cflags glib-2.0) \
        -o /opt/atrinik-windows/bin/atrinik-glib-tls-probe.exe \
    && python3 /tmp/windows-producer/pe_tls.py \
        --dll /opt/atrinik-windows/bin/libglib-2.0-0.dll \
        --report /opt/atrinik-windows/share/atrinik/windows-dependencies/glib-tls.json \
        --probe /opt/atrinik-windows/bin/atrinik-glib-tls-probe.exe
RUN python3 /tmp/windows-producer/pe_tls.py --library cairo \
        --dll /opt/atrinik-windows/bin/libcairo-2.dll \
        --report /opt/atrinik-windows/share/atrinik/windows-dependencies/cairo-tls.json \
        --header /tmp/windows-producer/cairo-tls-rvas.h \
    && x86_64-w64-mingw32-clang -std=c17 -O2 -Wall -Wextra -Werror \
        /tmp/windows-producer/cairo-tls-probe.c \
        $(x86_64-w64-mingw32-pkg-config --cflags cairo) \
        -o /opt/atrinik-windows/bin/atrinik-cairo-tls-probe.exe \
    && python3 /tmp/windows-producer/pe_tls.py --library cairo \
        --dll /opt/atrinik-windows/bin/libcairo-2.dll \
        --report /opt/atrinik-windows/share/atrinik/windows-dependencies/cairo-tls.json \
        --probe /opt/atrinik-windows/bin/atrinik-cairo-tls-probe.exe
COPY --chown=vscode:vscode tools/verify-classic-curl.sh /tmp/verify-classic-curl.sh
RUN /tmp/verify-classic-curl.sh /opt/atrinik-windows \
    && test "$(x86_64-w64-mingw32-pkg-config --modversion openssl)" = 3.5.5 \
    && test "$(x86_64-w64-mingw32-pkg-config --modversion libcares)" = 1.34.6
COPY --chown=vscode:vscode audio-toolchain.json /tmp/audio-toolchain.json
COPY --chown=vscode:vscode tools/build-sdl3-mixer.sh /tmp/build-sdl3-mixer.sh
# The audio helper accepts a command; this small wrapper supplies our toolchain.
RUN printf '%s\n' '#!/bin/sh' 'case "${1:-}" in --build|--install) exec cmake "$@";; esac' 'exec cmake -DCMAKE_TOOLCHAIN_FILE="$ATRINIK_WINDOWS_TOOLCHAIN_FILE" "$@"' \
        > /opt/atrinik-windows/bin/atrinik-windows-cmake \
    && chmod +x /opt/atrinik-windows/bin/atrinik-windows-cmake \
    && /tmp/build-sdl3-mixer.sh /tmp/audio-toolchain.json \
        atrinik-windows-cmake /opt/atrinik-windows "${WINDOWS_BUILD_JOBS}" \
    && python3 /tmp/windows-producer/build-dependencies.py --register-audio \
        --audio-lock /tmp/audio-toolchain.json --lock /tmp/windows-producer/dependencies.json \
        --prefix /opt/atrinik-windows --work-dir /tmp/windows-audio-registration \
    && rm -rf /tmp/windows-audio-registration
COPY --chown=vscode:vscode tools/audio/opus-probe.opus /opt/atrinik-windows/share/atrinik/audio/opus-probe.opus
COPY --chown=vscode:vscode tools/audio/sdl3-mixer-probe.c /tmp/sdl3-mixer-probe.c
COPY --chown=vscode:vscode tools/verify-pe-imports.sh /tmp/verify-pe-imports.sh
RUN test "$(sha256sum /opt/atrinik-windows/share/atrinik/audio/opus-probe.opus | cut -d' ' -f1)" \
        = "$(jq -r '.fixture.sha256' /tmp/audio-toolchain.json)" \
    && x86_64-w64-mingw32-clang -std=c17 -Wall -Wextra -Werror \
        /tmp/sdl3-mixer-probe.c -o "${ATRINIK_WINDOWS_RUNTIME_DIR}/atrinik-sdl3-mixer-probe.exe" \
        $(x86_64-w64-mingw32-pkg-config --cflags --libs sdl3-mixer) \
    && jq -r '.windows.sdl_mixer_imports[]' /tmp/audio-toolchain.json \
        | xargs /tmp/verify-pe-imports.sh llvm-readobj "${ATRINIK_WINDOWS_RUNTIME_DIR}/SDL3_mixer.dll" \
    && python3 /tmp/windows-producer/build-dependencies.py \
        --lock /tmp/windows-producer/dependencies.json --prefix /opt/atrinik-windows \
        --work-dir /tmp/windows-dependencies --jobs "${WINDOWS_BUILD_JOBS}" --verify-only \
    && rm /tmp/sdl3-mixer-probe.c
COPY --chown=vscode:vscode windows/licenses/c-ares-1.34.6.LICENSE.md /opt/atrinik-windows/share/licenses/c-ares/LICENSE.md

FROM windows-shared AS windows-build
COPY --chown=vscode:vscode windows/python-import-library.py windows/python-runtime-inventory.py /tmp/
RUN mkdir -p "${ATRINIK_WINDOWS_PYTHON_RUNTIME_DIR}" /tmp/python-sdk \
    && wget -q "https://www.python.org/ftp/python/${PYTHON_VERSION}/python-${PYTHON_VERSION}-embed-amd64.zip" -O /tmp/python-sdk/python-embed.zip \
    && echo "${PYTHON_EMBED_SHA256}  /tmp/python-sdk/python-embed.zip" | sha256sum -c - \
    && wget -q "https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tar.xz" -O /tmp/python-sdk/python-source.tar.xz \
    && echo "${PYTHON_SOURCE_SHA256}  /tmp/python-sdk/python-source.tar.xz" | sha256sum -c - \
    && unzip -q /tmp/python-sdk/python-embed.zip -d "${ATRINIK_WINDOWS_PYTHON_RUNTIME_DIR}" \
    && tar -xf /tmp/python-sdk/python-source.tar.xz -C /tmp/python-sdk \
    && mkdir -p "${ATRINIK_WINDOWS_PYTHON_INCLUDE_DIR}" \
    && cp -R "/tmp/python-sdk/Python-${PYTHON_VERSION}/Include/." "${ATRINIK_WINDOWS_PYTHON_INCLUDE_DIR}/" \
    && cp "/tmp/python-sdk/Python-${PYTHON_VERSION}/PC/pyconfig.h" "${ATRINIK_WINDOWS_PYTHON_INCLUDE_DIR}/pyconfig.h" \
    && python3 /tmp/python-import-library.py "${ATRINIK_WINDOWS_PYTHON_RUNTIME_DIR}/python314.dll" /tmp/python-sdk/python314.def \
    && llvm-dlltool -m i386:x86-64 -d /tmp/python-sdk/python314.def -D python314.dll -l "${ATRINIK_WINDOWS_PYTHON_LIBRARY}" \
    && printf '%s\n' '#include <Python.h>' 'int main(void) { Py_Initialize(); PyErr_SetString(PyExc_RuntimeError, "probe"); Py_Finalize(); return 0; }' > /tmp/python-sdk/probe.c \
    && x86_64-w64-mingw32-clang -I"${ATRINIK_WINDOWS_PYTHON_INCLUDE_DIR}" /tmp/python-sdk/probe.c \
        "${ATRINIK_WINDOWS_PYTHON_LIBRARY}" -o /tmp/python-sdk/probe.exe \
    && llvm-readobj --coff-imports /tmp/python-sdk/probe.exe | grep -F 'Name: python314.dll' \
    && python3 /tmp/python-runtime-inventory.py "$ATRINIK_WINDOWS_PYTHON_RUNTIME_DIR" \
        /opt/atrinik-windows/share/atrinik/windows-dependencies/python-runtime.json \
    && rm -rf /tmp/python-sdk
USER root
# General-image worldmaker additions remain downstream of the shared producer.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
        libc6-dev libcurl4-openssl-dev libgd-dev libidn2-dev libminiupnpc-dev python3-dev zlib1g-dev
COPY windows/llvm-path.sh /etc/profile.d/llvm-path.sh
COPY windows/classic-check-toolchain.json classic-curl-toolchain.json audio-toolchain.json audio-toolchain.spdx.json /usr/local/share/atrinik/
RUN x86_64-w64-mingw32-clang --version | grep -F '23.1.3' \
    && clang --version | grep -F '23.1.3' \
    && command -v llvm-readobj && command -v llvm-dlltool \
    && bash -lc 'command -v x86_64-w64-mingw32-clang' \
    && su --login vscode --command 'command -v x86_64-w64-mingw32-clang' \
    && test -f "$ATRINIK_WINDOWS_TOOLCHAIN_FILE" \
    && test -f "$ATRINIK_WINDOWS_PYTHON_LIBRARY" \
    && test -f "$ATRINIK_WINDOWS_PYTHON_RUNTIME_DIR/python314.dll" \
    && x86_64-w64-mingw32-pkg-config --exists libcurl sdl3-mixer \
    && pkg-config --exists libidn2 && ssh -V

# Shared expensive dependency stage branches before Python/worldmaker additions.
FROM mcr.microsoft.com/devcontainers/base:bookworm@sha256:99f5250dd2d5f8b11046d5662dd94c1e3c1dae56b560c7caad5ceb7edf349046 AS classic-check
ENV DEBIAN_FRONTEND=noninteractive
RUN rm -f /etc/apt/apt.conf.d/docker-clean
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates ccache cmake git ninja-build pkg-config python3
COPY --from=windows-shared /opt/llvm-mingw /opt/llvm-mingw
COPY --from=windows-shared --chown=vscode:vscode /opt/atrinik-windows /opt/atrinik-windows
ENV ATRINIK_WINDOWS_TOOLCHAIN_FILE=/opt/atrinik-windows/share/cmake/llvm-mingw.cmake \
    ATRINIK_WINDOWS_TARGET=x86_64-w64-mingw32 \
    ATRINIK_WINDOWS_RUNTIME_DIR=/opt/atrinik-windows/bin \
    PATH=/opt/llvm-mingw/bin:/opt/atrinik-windows/bin:${PATH}
COPY windows/llvm-path.sh /etc/profile.d/llvm-path.sh
COPY windows/classic-check-toolchain.json classic-curl-toolchain.json audio-toolchain.json audio-toolchain.spdx.json /usr/local/share/atrinik/
RUN command -v ccache && x86_64-w64-mingw32-clang --version | grep -F '23.1.3' \
    && command -v llvm-readobj && command -v llvm-ar && command -v llvm-dlltool \
    && for package in libcurl libidn2 libxml-2.0 miniupnpc openssl sdl3 sdl3-image sdl3-mixer sdl3-ttf; do \
        x86_64-w64-mingw32-pkg-config --exists "$package"; done \
    && test -f "$ATRINIK_WINDOWS_TOOLCHAIN_FILE" \
    && test -f "$ATRINIK_WINDOWS_RUNTIME_DIR/SDL3_mixer.dll" \
    && test ! -e /opt/atrinik-windows/python-runtime \
    && test ! -e /opt/atrinik-windows/include/python3.14 \
    && test ! -e /opt/atrinik-windows/lib/libpython314.dll.a \
    && su --login vscode --command 'command -v x86_64-w64-mingw32-clang'
USER vscode
# Preserve the general-purpose image as the default Dockerfile result.
FROM windows-build AS windows
