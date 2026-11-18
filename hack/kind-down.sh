#!/usr/bin/env bash
# Delete the kind cluster blip-dev and the host kernel state its blip nodes
# leave behind. kind nodes share the host kernel, so NVMe/TCP connections,
# nvmet exports, device-mapper devices and loop devices outlive the node
# containers. The cleanup itself lives in storage-cleanup.sh so the tests and
# this script cannot drift.
#
# Only resources of blip-dev nodes are touched: dm devices named
# blip-<first 8 hex of sha256(node name)>-*, nvmet and NVMe host entries with
# those nodes' host NQNs or devices, and loop devices backed by files under
# /var/tmp/blip-kind.
#
# Usage: hack/kind-down.sh [--purge]   (--purge also removes /var/tmp/blip-kind)
set -euo pipefail

CLUSTER=blip-dev
DATA=/var/tmp/blip-kind
HERE="$(cd "$(dirname "$0")" && pwd)"

purge=false
case "${1:-}" in
  --purge) purge=true ;;
  "") ;;
  *) echo "usage: $0 [--purge]" >&2; exit 2 ;;
esac

# Node names come from the cluster and from the data directories, so cleanup
# still works when the cluster is already gone.
mapfile -t nodes < <({
  kind get nodes --name "${CLUSTER}" 2>/dev/null || true
  [[ -d "${DATA}" ]] && ls -1 "${DATA}"
} | sort -u)

if kind get clusters 2>/dev/null | grep -qx "${CLUSTER}"; then
  kind delete cluster --name "${CLUSTER}"
fi

if [[ ${#nodes[@]} -gt 0 ]]; then
  sudo env BLIP_CLEANUP_LOOP_ROOT="${DATA}" "${HERE}/storage-cleanup.sh" "${nodes[@]}"
fi

if "${purge}"; then
  sudo rm -rf "${DATA}"
fi
