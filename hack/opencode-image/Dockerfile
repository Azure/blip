# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Reusable opencode image for Blip chat pools. It bundles the opencode binary
# and the blipchat Code Mode plugin under /etc/opencode/plugins.
# Build from the repository root:
#   docker build -t localhost:5001/blip/opencode:dev hack/opencode-image
FROM ubuntu:24.04

ARG OPENCODE_VERSION=v2.4.1
ARG OPENCODE_SHA256_AMD64=9ddd18e3faf64eaeccf6a0fcbc96a5c7a14520ae5fd5b61e5be51d894f478b47
ARG OPENCODE_SHA256_ARM64=cb28cf94541aeb62a4b2ea5997a99b5dd6bae595a772f36fbe279299f2032a4f
ARG TARGETARCH

ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        wget \
        git \
        openssh-client \
        build-essential \
        pkg-config \
        python3 \
        python3-pip \
        python3-venv \
        nodejs \
        npm \
        jq \
        less \
        vim \
        procps \
        sudo \
        ripgrep \
        fd-find \
        fzf \
        unzip \
        zip \
        xz-utils \
        tar \
        gzip \
    && ln -s /usr/bin/fdfind /usr/local/bin/fd \
    && rm -rf /var/lib/apt/lists/*

# Ubuntu has no opencode package. Download the release for the image's own
# architecture and verify the published checksum.
RUN set -eux; \
    arch="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    case "$arch" in \
        amd64) \
            opencode_arch=x64; \
            opencode_sha256="$OPENCODE_SHA256_AMD64"; \
            ;; \
        arm64) \
            opencode_arch=arm64; \
            opencode_sha256="$OPENCODE_SHA256_ARM64"; \
            ;; \
        *) \
            echo "unsupported architecture: $arch" >&2; \
            exit 1; \
            ;; \
    esac; \
    curl -fsSLo /tmp/opencode.tar.gz \
        "https://github.com/anomalyco/opencode/releases/download/${OPENCODE_VERSION}/opencode-linux-${opencode_arch}.tar.gz"; \
    echo "${opencode_sha256}  /tmp/opencode.tar.gz" | sha256sum -c -; \
    mkdir -p /tmp/opencode-extract; \
    tar -xzf /tmp/opencode.tar.gz -C /tmp/opencode-extract; \
    install -m 0755 /tmp/opencode-extract/opencode /usr/local/bin/opencode; \
    rm -rf /tmp/opencode-extract /tmp/opencode.tar.gz

COPY config/plugins/blipchat-codemode /etc/opencode/plugins/blipchat-codemode

# Replace the image's default "ubuntu" user so dev gets UID 1000.
RUN userdel -r ubuntu 2>/dev/null || true \
    && useradd -m -u 1000 -s /bin/bash dev \
    && echo 'dev ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/dev \
    && chmod 0440 /etc/sudoers.d/dev

# Do not leak the noninteractive apt setting into the runtime environment.
ENV DEBIAN_FRONTEND=

USER dev
WORKDIR /home/dev
CMD ["/bin/bash", "-l"]
