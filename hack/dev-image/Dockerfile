# Development sandbox image for the local kind cluster. hack/kind-up.sh builds
# it and pushes it to the local registry as blip-registry:5000/blip/dev:latest.
# Build from the repository root after `make build`:
#   docker build -f hack/dev-image/Dockerfile .
FROM ubuntu:24.04

ARG KUBECTL_VERSION=v1.33.1

ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        git \
        less \
        procps \
        python3 \
        sudo \
        vim \
    && rm -rf /var/lib/apt/lists/*

# Ubuntu has no kubectl package. Install upstream for the image's own
# architecture and verify the published checksum.
RUN arch="$(dpkg --print-architecture)" \
    && curl -fsSLo /tmp/kubectl \
        "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${arch}/kubectl" \
    && curl -fsSLo /tmp/kubectl.sha256 \
        "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${arch}/kubectl.sha256" \
    && echo "$(cat /tmp/kubectl.sha256)  /tmp/kubectl" | sha256sum -c - \
    && install -m 0755 /tmp/kubectl /usr/local/bin/kubectl \
    && rm -f /tmp/kubectl /tmp/kubectl.sha256

# The CLI, also as `blip`. It is in /usr/local/bin, so `kubectl blip` finds
# it via PATH.
COPY bin/kubectl-blip /usr/local/bin/kubectl-blip
RUN ln -s kubectl-blip /usr/local/bin/blip

# Replace the image's default "ubuntu" user so dev gets UID 1000.
RUN userdel -r ubuntu \
    && useradd -m -u 1000 -s /bin/bash dev \
    && echo 'dev ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/dev \
    && chmod 0440 /etc/sudoers.d/dev

USER dev
WORKDIR /home/dev
CMD ["/bin/bash", "-l"]
