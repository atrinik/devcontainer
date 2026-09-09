# syntax=docker/dockerfile:1
# Shader generators stay in the existing Ubuntu ABI; only verified data crosses.
FROM ubuntu:26.04@sha256:678c6550cc43645e08669028bc177f50be4e7c5b8cca677067b1914d4afc7a03 AS portable-shaders
ARG TARGETARCH
ENV DEBIAN_FRONTEND=noninteractive
COPY classic-packages.lock /tmp/classic-packages.lock
# Match the canonical signed-APT CA bootstrap; restore TLS verification immediately.
RUN test "${TARGETARCH}" = amd64 \
    && sed -i -e 's|http://archive.ubuntu.com/ubuntu/|https://snapshot.ubuntu.com/ubuntu/20260810T000000Z/|' \
        -e 's|http://security.ubuntu.com/ubuntu/|https://snapshot.ubuntu.com/ubuntu/20260810T000000Z/|' \
        /etc/apt/sources.list.d/ubuntu.sources \
    && sed -i '/^Signed-By:/a Check-Valid-Until: no' /etc/apt/sources.list.d/ubuntu.sources \
    && apt-get -o Acquire::Retries=5 -o APT::Update::Error-Mode=any -o Acquire::https::Verify-Peer=false update \
    && awk -F= '$1 == "ca-certificates" || $1 == "libssl3t64" || $1 == "openssl" || $1 == "openssl-provider-legacy" { print }' \
        /tmp/classic-packages.lock > /tmp/ca-bootstrap.lock \
    && xargs apt-get -o Acquire::Retries=5 -o Acquire::https::Verify-Peer=false \
        install -y --no-install-recommends < /tmp/ca-bootstrap.lock \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get -o Acquire::Retries=5 -o APT::Update::Error-Mode=any update \
    && xargs apt-get -o Acquire::Retries=5 install -y --no-install-recommends < /tmp/classic-packages.lock \
    && rm -rf /var/lib/apt/lists/*
COPY classic-shader-toolchain.json /opt/shader-toolchain.json
COPY tools/install_classic_shader_toolchain.py /opt/install-shaders.py
RUN python3 /opt/install-shaders.py --manifest /opt/shader-toolchain.json \
      --cache /tmp/shader-inputs --prefix /usr/local --jobs 2 \
    && ldconfig \
    && install -d -o ubuntu -g ubuntu /cohort
COPY portable/contract.json /opt/contract.json
USER ubuntu
RUN git init /cohort/source \
    && git -C /cohort/source remote add origin https://github.com/atrinik/classic.git \
    && commit=$(python3 -c 'import json; print(json.load(open("/opt/contract.json"))["consumer"]["commit"])') \
    && git -C /cohort/source fetch --depth 1 origin "${commit}" \
    && git -C /cohort/source checkout --detach FETCH_HEAD \
    && test "$(git -C /cohort/source rev-parse HEAD)" = "${commit}" \
    && /cohort/source/client/tools/generate_gpu_shaders.sh /usr/local/bin/dxc \
        /usr/local/bin/spirv-cross /cohort/shaders \
    && cd /cohort/shaders && sha256sum -c SHA256SUMS \
    && sha256sum -c /cohort/source/client/shaders/SHA256SUMS
COPY portable/shader-record.py /opt/shader-record.py
RUN python3 /opt/shader-record.py


FROM debian:bookworm-slim@sha256:5ae3c39ebd15e229dcedd5cee596b2497182493d41ff162e824ba13fc1b2b867 AS portable-build
ARG TARGETARCH
ENV DEBIAN_FRONTEND=noninteractive \
    CFLAGS="-O2 -march=x86-64 -mtune=generic" \
    CXXFLAGS="-O2 -march=x86-64 -mtune=generic" \
    PKG_CONFIG_PATH=/usr/local/lib/pkgconfig \
    OPENSSL_MODULES=/usr/local/lib/ossl-modules
COPY portable/packages.lock /tmp/portable-packages.lock
# Signed snapshot metadata and package hashes remain mandatory, including bootstrap.
RUN test "${TARGETARCH}" = amd64 \
    && test "$(dpkg --print-architecture)" = amd64 \
    && rm /etc/apt/sources.list.d/debian.sources \
    && printf '%s\n' \
      'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20260901T000000Z bookworm main' \
      'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20260901T000000Z bookworm-updates main' \
      'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/20260901T000000Z bookworm-security main' \
      > /etc/apt/sources.list \
    && apt-get -o Acquire::Retries=5 -o APT::Update::Error-Mode=any update \
    && xargs apt-get -o Acquire::Retries=5 install -y --no-install-recommends < /tmp/portable-packages.lock \
    && sed -i 's|http://snapshot.debian.org|https://snapshot.debian.org|g' /etc/apt/sources.list \
    && sed 's/^deb /deb-src /' /etc/apt/sources.list >> /etc/apt/sources.list.d/portable-source.list \
    && apt-get -o Acquire::Retries=5 -o APT::Update::Error-Mode=any update \
    && useradd --create-home --uid 1000 --shell /bin/bash ubuntu
COPY portable /opt/atrinik-portable
COPY audio-toolchain.json audio-toolchain.spdx.json classic-shader-toolchain.json classic-shader-toolchain.spdx.json /opt/atrinik-portable/
COPY tools/build-sdl3-mixer.sh tools/install_classic_shader_toolchain.py /opt/atrinik-portable/tools/
COPY tools/audio /opt/atrinik-portable/audio
RUN python3 /opt/atrinik-portable/build.py \
    && ldconfig \
    && python3 /opt/atrinik-portable/inventory.py \
    && python3 /opt/atrinik-portable/legal.py \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -m 1777 /cache/ccache
COPY --from=portable-shaders /cohort/shaders /opt/atrinik-portable/shaders
COPY --from=portable-shaders /cohort/input-sha256.txt /opt/atrinik-portable/shader-inputs.txt
COPY --from=portable-shaders /cohort/generation.json /opt/atrinik-portable/shader-generation.json
COPY --from=portable-shaders /cohort/corresponding-source /opt/atrinik-portable/sources/classic-shaders
# Build-time shader licenses/provenance accompany the generated cohort; no Ubuntu ELF.
COPY --from=portable-shaders /usr/local/share/licenses /opt/atrinik-portable/notices/shader-tools
USER ubuntu
WORKDIR /home/ubuntu

FROM portable-build AS portable-validation
RUN /opt/atrinik-portable/smoke.sh

FROM portable-build AS portable-final
LABEL org.opencontainers.image.title="Atrinik portable Classic build baseline" \
      org.opencontainers.image.description="Linux amd64 Debian 12/glibc 2.36 application ABI; sealed canonical shader cohort"
