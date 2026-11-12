#!/bin/sh
# Export an Alpine container into a rootfs directory for tests.
# Output: $BLIP_GUEST_DIR/rootfs-alpine (default /mnt/nvme2/blip/guest).
set -eu
dir=${BLIP_GUEST_DIR:-/mnt/nvme2/blip/guest}/rootfs-alpine
image=alpine:3.22
[ -f "$dir/etc/alpine-release" ] && { echo "$dir exists"; exit 0; }
timeout -s TERM 300 docker pull -q "$image" >/dev/null
cid=$(docker create "$image" /bin/true)
trap 'docker rm -f "$cid" >/dev/null' EXIT
rm -rf "$dir.tmp" && mkdir -p "$dir.tmp"
timeout -s TERM 300 docker export "$cid" | tar -x -C "$dir.tmp"
mv "$dir.tmp" "$dir"
echo "rootfs in $dir"
