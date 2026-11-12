# Built by `make images` from the repo root after `make build`.
FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      lvm2 thin-provisioning-tools e2fsprogs ktls-utils kmod nvme-cli keyutils ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY images/blipd/lvm.conf /etc/lvm/lvm.conf
COPY images/blipd/tlshd.conf /etc/tlshd.conf
COPY bin/blipd /usr/local/bin/blipd
USER 0
ENTRYPOINT ["/usr/local/bin/blipd"]
