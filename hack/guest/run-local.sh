#!/usr/bin/env bash
# Boot real VMs with blip-runtime and blip-guest and drive them through the
# pod directory protocol. Needs /dev/kvm, cloud-hypervisor, docker and sudo.
# Everything lives under $WORK; VMs, the network namespace and TAPs are
# removed on exit.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="${WORK:-/tmp/blip-vmtest}"
NS=blipvmtest
mkdir -p "$WORK"

"$ROOT/hack/guest/build.sh"
CGO_ENABLED=0 go build -C "$ROOT" -o "$WORK/blip-runtime" ./cmd/blip-runtime
go build -C "$ROOT" -o "$WORK/vmtest" ./hack/guest/vmtest

if [[ ! -f "$WORK/base.ext4" ]]; then
  rm -rf "$WORK/rootdir"
  mkdir -p "$WORK/rootdir"
  cid="$(docker create debian:bookworm-slim)"
  docker export "$cid" | sudo tar -C "$WORK/rootdir" -x
  docker rm "$cid" >/dev/null
  sudo mke2fs -q -t ext4 -d "$WORK/rootdir" "$WORK/base.ext4" 1G
  sudo rm -rf "$WORK/rootdir"
fi

cleanup() {
  # Bracketed patterns keep pkill from matching its own sudo parent.
  sudo pkill -f "$WORK/[b]lip-runtime" 2>/dev/null || true
  sudo pkill -f "[c]loud-hypervisor --api-socket path=$WORK/" 2>/dev/null || true
  sudo ip netns del "$NS" 2>/dev/null || true
  sudo ip link del vt-host 2>/dev/null || true
  sudo rm -rf "/etc/netns/$NS"
}
trap cleanup EXIT
cleanup

# A fake pod network: eth0 10.99.0.2/24 in $NS, gateway 10.99.0.1 on the host.
sudo ip netns add "$NS"
sudo ip link add vt-host type veth peer name eth0 netns "$NS"
sudo ip addr add 10.99.0.1/24 dev vt-host
sudo ip link set vt-host up
sudo ip -n "$NS" addr add 10.99.0.2/24 dev eth0
sudo ip -n "$NS" link set eth0 up
sudo ip -n "$NS" link set lo up
sudo ip -n "$NS" route add default via 10.99.0.1
sudo mkdir -p "/etc/netns/$NS"
printf 'nameserver 10.99.0.1\nsearch blip.test\noptions ndots:5\n' | sudo tee "/etc/netns/$NS/resolv.conf" >/dev/null

sudo WORK="$WORK" NS="$NS" ASSETS="$ROOT/build/guest" "$WORK/vmtest" "$@"
