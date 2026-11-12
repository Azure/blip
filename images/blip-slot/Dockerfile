# Built by `make images` after `make build` and `make guest`.
FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      iproute2 libcap2-bin \
    && rm -rf /var/lib/apt/lists/*
COPY bin/blipd /usr/local/bin/blipd
COPY _output/guest/cloud-hypervisor /usr/local/bin/cloud-hypervisor
COPY _output/guest/vmlinuz /usr/share/blip/vmlinuz
COPY _output/guest/initramfs.cpio.gz /usr/share/blip/initramfs.cpio.gz
ENTRYPOINT ["/usr/local/bin/blipd"]
