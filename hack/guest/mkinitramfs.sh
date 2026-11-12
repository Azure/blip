#!/bin/sh
# Build blip-boot, blip-meta and _output/guest/initramfs.cpio.gz (/init = blip-boot).
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
out=$root/_output/guest
mkdir -p "$out"
cd "$root"
for c in blip-boot blip-meta; do
	CGO_ENABLED=0 timeout -s TERM 300 hack/go.sh build -trimpath -ldflags='-s -w' -o "$out/$c" ./cmd/$c
done
timeout -s TERM 120 hack/go.sh run ./hack/guest/mkinitramfs -init "$out/blip-boot" -o "$out/initramfs.cpio.gz"
echo "built $out/initramfs.cpio.gz"
