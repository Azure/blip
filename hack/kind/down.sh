#!/usr/bin/env bash
# Delete the Blip kind cluster and release the host devices up.sh created.
# Backing files are kept; remove $BLIP_DATA_DIR to free the space.
set -uo pipefail

CLUSTER=${KIND_CLUSTER:-blip}
DATA=${BLIP_DATA_DIR:-/mnt/nvme2/blip/kind}
WORKERS=(blip-worker blip-worker2 blip-worker3)

log() { echo "+ $*" >&2; }

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  log "deleting kind cluster $CLUSTER"
  timeout -s TERM 300 kind delete cluster --name "$CLUSTER"
fi

loops=()
for node in "${WORKERS[@]}"; do
  for f in "$DATA/storage-$node.img" "$DATA/compute-$node.img"; do
    [[ -f $f ]] || continue
    while read -r dev; do [[ -n $dev ]] && loops+=("$dev"); done < <(sudo losetup -j "$f" -O NAME -n)
  done
done

deactivate_vgs() {
  for node in "${WORKERS[@]}"; do
    f="$DATA/storage-$node.img"
    [[ -f $f ]] || continue
    dev=$(sudo losetup -j "$f" -O NAME -n | head -n1)
    [[ -n $dev ]] && sudo vgchange --devices "$dev" -an "blip-$node" >/dev/null 2>&1
  done
}
deactivate_vgs

# Remove device-mapper devices stacked on our loop devices, top first.
# Only devices whose dependency chain reaches our loops are touched.
ours=" ${loops[*]##*/} "
for pass in 1 2 3 4 5 6; do
  removed=0
  for dm in $(sudo dmsetup ls -o blkdevname 2>/dev/null | awk '{print $1}'); do
    [[ $dm == "No" ]] && continue
    deps=$(sudo dmsetup deps -o blkdevname "$dm" 2>/dev/null | sed 's/.*://; s/[()]//g')
    hit=0
    for d in $deps; do [[ $ours == *" $d "* ]] && hit=1; done
    [[ $hit == 1 ]] || continue
    kname=$(basename "$(readlink -f "/dev/mapper/$dm")")
    ours+="$kname "
    if [[ $(sudo dmsetup info -c --noheadings -o open "$dm") == 0 ]]; then
      log "removing dm device $dm"
      sudo dmsetup remove "$dm" && removed=1
    fi
  done
  [[ $removed == 1 ]] || break
done

deactivate_vgs

for dev in "${loops[@]}"; do
  log "detaching $dev"
  sudo losetup -d "$dev" || log "WARNING: could not detach $dev"
done
log "done"
