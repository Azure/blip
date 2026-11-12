#!/usr/bin/env bash
# Create the Blip kind cluster (docs/e2e.md, The kind cluster). Safe to run again.
set -euo pipefail

CLUSTER=${KIND_CLUSTER:-blip}
IMAGE=${KIND_NODE_IMAGE:-kindest/node:v1.33.1}
DATA=${BLIP_DATA_DIR:-/mnt/nvme2/blip/kind}
STORAGE_SIZE=${BLIP_STORAGE_SIZE:-6G}
COMPUTE_SIZE=${BLIP_COMPUTE_SIZE:-4G}
POOL_SIZE=${BLIP_POOL_SIZE:-4G}
SLOTS=${BLIP_SLOTS:-2}
WORKERS=(blip-worker blip-worker2 blip-worker3)

log() { echo "+ $*" >&2; }

log "loading kernel modules"
for m in nvmet nvmet-tcp nvme-tcp nvme-fabrics nvme-keyring tls dm-thin-pool dm-multipath loop sch_ingress cls_matchall act_mirred cls_flower act_gact; do
  sudo modprobe "$m"
done

# NVMe/TCP reconnects run in the host's initial network namespace, so
# their TLS handshakes go to a tlshd on the host, not to the sidecar in the
# kind node (docs/e2e.md, The kind cluster). The host side passes the key serial
# explicitly, so the stock config is enough.
log "checking host tlshd (ktls-utils)"
if ! command -v tlshd >/dev/null; then
  log "installing ktls-utils"
  sudo timeout -s TERM 300 apt-get install -y ktls-utils
fi
if ! systemctl is-active --quiet tlshd; then
  log "starting host tlshd"
  sudo systemctl enable --now tlshd
fi
systemctl is-active --quiet tlshd || { echo "host tlshd is not running; reconnects will fail" >&2; exit 1; }

if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  log "creating kind cluster $CLUSTER"
  cfg=$(mktemp)
  cat >"$cfg" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
- role: worker
- role: worker
- role: worker
EOF
  timeout -s TERM 600 kind create cluster --name "$CLUSTER" --image "$IMAGE" --config "$cfg" --wait 300s
  rm -f "$cfg"
fi

mkdir -p "$DATA"

# attach FILE SIZE: print the loop device for FILE, creating both if needed.
attach() {
  local file=$1 size=$2 dev
  [[ -f $file ]] || truncate -s "$size" "$file"
  dev=$(sudo losetup -j "$file" -O NAME -n | head -n1)
  if [[ -z $dev ]]; then
    dev=$(sudo losetup --find --show --direct-io=on "$file")
  fi
  echo "$dev"
}

# mknod_in NODE DEV: create the device node DEV inside the kind node.
mknod_in() {
  local node=$1 dev=$2 maj min
  maj=$((16#$(stat -c %t "$dev")))
  min=$((16#$(stat -c %T "$dev")))
  docker exec "$node" sh -c "
    if [ -b $dev ] && [ \"\$(stat -c '%t:%T' $dev)\" = \"$(stat -c '%t:%T' "$dev")\" ]; then exit 0; fi
    rm -f $dev && mknod $dev b $maj $min"
}

for node in "${WORKERS[@]}"; do
  vg="blip-$node"
  sdev=$(attach "$DATA/storage-$node.img" "$STORAGE_SIZE")
  cdev=$(attach "$DATA/compute-$node.img" "$COMPUTE_SIZE")
  log "$node: storage $sdev, compute $cdev"

  # Host LVM only looks at this one device.
  if ! sudo vgs --devices "$sdev" "$vg" >/dev/null 2>&1; then
    log "$node: creating VG $vg"
    sudo pvcreate --devices "$sdev" -y --metadatasize 64m "$sdev"
    sudo vgcreate --devices "$sdev" --setautoactivation n "$vg" "$sdev"
  fi
  if ! sudo lvs --devices "$sdev" "$vg/pool" >/dev/null 2>&1; then
    log "$node: creating thin pool $vg/pool"
    sudo lvcreate --devices "$sdev" -y --type thin-pool -L "$POOL_SIZE" --chunksize 64k \
      --poolmetadatasize 256m --zero n -n pool "$vg"
    sudo lvchange --devices "$sdev" -y --errorwhenfull y "$vg/pool"
    sudo vgchange --devices "$sdev" -an "$vg"
  fi

  mknod_in "$node" "$sdev"
  mknod_in "$node" "$cdev"

  ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$node")
  docker exec -i "$node" sh -c 'mkdir -p /etc/blip /run/blip && cat > /etc/blip/node.yaml' <<EOF
hypervisor: kvm
slots: $SLOTS
address: $ip
storage:
  vg: $vg
  maxLVs: 5000
  devices: [$sdev]
compute:
  device: $cdev
EOF
  docker exec "$node" test -c /dev/kvm || log "WARNING: /dev/kvm missing in $node"

  kubectl --context "kind-$CLUSTER" label node "$node" --overwrite \
    blip.example.com/storage=true blip.example.com/hypervisor=kvm >/dev/null
done

log "cluster $CLUSTER is ready"
