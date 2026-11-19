# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Disposable environment for privileged storage/nvme/peer tests
# (hack/storage-test.sh). Test binaries are copied in at run time. Matches the
# node image's e2fsprogs and libarchive (mke2fs -d <tarball>).
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      dmsetup thin-provisioning-tools e2fsprogs libarchive13t64 util-linux mount \
      nftables iproute2 kmod ca-certificates \
    && rm -rf /var/lib/apt/lists/*
