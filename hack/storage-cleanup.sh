#!/usr/bin/env bash
# Removes kernel objects created by blip storage/nvme/peer tests for the given
# node names, and nothing else: dm devices named blip-<sha256(node)[:8]>-*,
# nvmet subsystems nqn.2014-08.dev.blip:<hash>:*, their nvmet port (if left
# empty), connected NVMe controllers of those subsystems, and the host
# entries nqn.2014-08.dev.blip:host:<node> when unreferenced.
#
# Set BLIP_CLEANUP_LOOP_ROOT to also detach loop devices backed by files under
# that directory (kind nodes share the host kernel; the files live on the
# host). Loop devices created by the tests themselves use autoclear and go
# away with the pool.
#
# Run as root (inside a privileged container with -v /dev:/dev, or with sudo
# when cleaning up host kernel state after a kind cluster).
set -u
CFS=/sys/kernel/config
mountpoint -q "$CFS" || mount -t configfs none "$CFS" 2>/dev/null
NVMET=$CFS/nvmet

for node in "$@"; do
  h=$(printf %s "$node" | sha256sum | cut -c1-8)
  prefix="blip-$h-"
  hostnqn="nqn.2014-08.dev.blip:host:$node"

  # NVMe initiator controllers connected to this node's subsystems.
  for c in /sys/class/nvme/nvme*; do
    [ -e "$c/subsysnqn" ] || continue
    sub=$(cat "$c/subsysnqn")
    host=$(cat "$c/hostnqn" 2>/dev/null)
    case "$sub" in nqn.2014-08.dev.blip:$h:*) echo 1 > "$c/delete_controller" 2>/dev/null ;; esac
    case "$host" in "$hostnqn") echo 1 > "$c/delete_controller" 2>/dev/null ;; esac
  done

  # nvmet target objects.
  if [ -d $NVMET ]; then
    for p in $NVMET/ports/*; do
      [ -d "$p" ] || continue
      for l in "$p"/subsystems/nqn.2014-08.dev.blip:$h:*; do
        [ -L "$l" ] && rm -f "$l"
      done
    done
    for s in $NVMET/subsystems/nqn.2014-08.dev.blip:$h:*; do
      [ -d "$s" ] || continue
      for ns in "$s"/namespaces/*; do
        [ -d "$ns" ] || continue
        echo 0 > "$ns/enable" 2>/dev/null
        rmdir "$ns"
      done
      rm -f "$s"/allowed_hosts/* 2>/dev/null
      rmdir "$s"
    done
    port=$(( 0x${h:0:4} % 60000 + 1000 ))
    if [ -d $NVMET/ports/$port ] && [ -z "$(ls $NVMET/ports/$port/subsystems)" ]; then
      rmdir $NVMET/ports/$port
    fi
    host=$NVMET/hosts/$hostnqn
    if [ -d "$host" ] && ! ls -l $NVMET/subsystems/*/allowed_hosts/ 2>/dev/null | grep -q "host:$node\$"; then
      rmdir "$host"
    fi
  fi

  # Device-mapper devices, users before the pool.
  for pass in 1 2 3 4 5; do
    names=$(dmsetup ls 2>/dev/null | awk '{print $1}' | grep "^$prefix" | grep -v "^${prefix}pool$")
    [ -z "$names" ] && break
    for n in $names; do dmsetup --noudevsync remove --retry "$n" >/dev/null 2>&1; done
  done
  dmsetup ls 2>/dev/null | awk '{print $1}' | grep -q "^${prefix}pool$" && dmsetup --noudevsync remove --retry "${prefix}pool"
  left=$(dmsetup ls 2>/dev/null | awk '{print $1}' | grep "^$prefix")
  [ -n "$left" ] && echo "storage-cleanup: left: $left" >&2
done

# Loop devices backed by files under BLIP_CLEANUP_LOOP_ROOT, matched by device
# and inode (the kernel reports the backing path as the kind node saw it).
if [ -n "${BLIP_CLEANUP_LOOP_ROOT:-}" ] && [ -d "$BLIP_CLEANUP_LOOP_ROOT" ]; then
  files=$(find "$BLIP_CLEANUP_LOOP_ROOT" -xdev -type f -exec stat -c '%Hd:%Ld %i' {} +)
  losetup -l -n -O NAME,BACK-MAJ:MIN,BACK-INO | while read -r loop majmin ino; do
    printf '%s\n' "$files" | while IFS= read -r f; do
      if [ "$f" = "$majmin $ino" ]; then
        echo "detaching $loop"
        losetup -d "$loop"
      fi
    done
  done
fi
exit 0
