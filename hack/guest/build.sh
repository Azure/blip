#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Build the guest kernel and initramfs:
#   build/guest/vmlinuz       kernel image (KERNEL override; default is the
#                             host kernel)
#   build/guest/initramfs.gz  /init = blip-guest, plus the modules the guest
#                             needs for vsock, virtio disks, networking and
#                             the filesystems it mounts
#
# KVER overrides the kernel release (default: uname -r), KERNEL the kernel
# image (default: /boot/vmlinuz-$KVER), MODDIR the module tree (default:
# /lib/modules/$KVER), MODBASE the root directory modinfo searches for that
# tree (default: derived from MODDIR) and ARCH the target architecture
# (default: go env GOARCH).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$ROOT/build/guest"
KVER="${KVER:-$(uname -r)}"
KERNEL="${KERNEL:-/boot/vmlinuz-$KVER}"
ARCH="${ARCH:-$(go env GOARCH)}"
MODDIR="${MODDIR:-/lib/modules/$KVER}"
# modinfo -b expects the root that contains lib/modules/$KVER. For the default
# /lib/modules/$KVER this is /; for a package extracted below a staging
# directory it is three levels above the module directory.
MODBASE="${MODBASE:-$(dirname "$(dirname "$(dirname "$MODDIR")")")}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# The host kernel is often readable only by root. Copy it with sudo when
# possible so `make guest` works from an unprivileged dev shell.
if [[ ! -r "$KERNEL" ]] && sudo -n test -r "$KERNEL" 2>/dev/null; then
  sudo cp "$KERNEL" "$WORK/vmlinuz"
  sudo chmod 644 "$WORK/vmlinuz"
  KERNEL="$WORK/vmlinuz"
fi
if [[ ! -r "$KERNEL" ]]; then
  echo "error: kernel image $KERNEL is missing or unreadable; set KERNEL=/path/to/vmlinuz" >&2
  exit 1
fi
if [[ ! -d "$MODDIR" ]]; then
  echo "error: $MODDIR is missing; install the $KVER modules or set MODDIR" >&2
  exit 1
fi

mkdir -p "$OUT"
initrd="$WORK/initramfs"
mkdir -p "$initrd"/{dev,proc,sys,run,tmp,etc,mnt/root,lib/modules}

CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -C "$ROOT" -trimpath -ldflags "-s -w" \
  -o "$initrd/init" ./cmd/blip-guest

cp "$KERNEL" "$OUT/vmlinuz"

# modpath prints a module's file, "builtin" when it is compiled into the
# kernel, or nothing when the kernel does not provide it.
modpath() {
  local path
  path="$(modinfo -b "$MODBASE" -k "$KVER" -n "$1" 2>/dev/null || true)"
  case "$path" in
    ''|*'not found'*) ;;
    '(builtin)'|builtin) echo builtin ;;
    *) echo "$path" ;;
  esac
}

# Copy a module after its dependencies, decompressed. The numeric prefix is
# the load order (the guest loads /lib/modules/*.ko in lexical order).
declare -A seen
n=0
add_module() {
  local name="$1" file dst dep
  [[ -n "${seen[$name]:-}" ]] && return
  seen[$name]=1
  file="$(modpath "$name")"
  [[ -z "$file" || "$file" == builtin ]] && return
  for dep in $(modinfo -b "$MODBASE" -k "$KVER" -F depends "$name" 2>/dev/null | tr ',' ' '); do
    add_module "$dep"
  done
  dst="$initrd/lib/modules/$(printf '%03d' "$n")-$name.ko"
  n=$((n + 1))
  case "$file" in
    *.zst) zstd -q -d -c "$file" > "$dst" ;;
    *.xz) xz -d -c "$file" > "$dst" ;;
    *.gz) gzip -d -c "$file" > "$dst" ;;
    *) cp "$file" "$dst" ;;
  esac
}

# Drivers without which the guest cannot boot or claim its root: vsock carries
# the control port, virtio_pci/blk/ring bring up the disks, ext4/overlay/dm_*
# mount the root and volumes, virtio_net/nls_cp437/vfat cover networking and
# small filesystems. Each entry lists alternatives; the first one available as
# builtin or module is used.
critical=(
  virtio_pci
  virtio_ring
  virtio
  virtio_blk
  virtio_net
  'vmw_vsock_virtio_transport|vsock'
  ext4
  jbd2
  overlay
  dm_mod
  dm_thin_pool
  loop
  vfat
  nls_cp437
)
missing=()
for want in "${critical[@]}"; do
  found=""
  for alt in ${want//|/ }; do
    if [[ -n "$(modpath "$alt")" ]]; then
      found="$alt"
      add_module "$alt"
      break
    fi
  done
  [[ -z "$found" ]] && missing+=("$want")
done

if ((${#missing[@]} > 0)); then
  echo "error: $KVER provides none of these required drivers: ${missing[*]}" >&2
  echo "error: the guest would not boot; install the matching kernel modules" >&2
  exit 1
fi

(cd "$initrd" && find . -print0 | sort -z |
  cpio --null -o -H newc --owner=0:0 --quiet | gzip -9) > "$OUT/initramfs.gz"

ls -lh "$OUT/vmlinuz" "$OUT/initramfs.gz"
ls "$initrd/lib/modules"
