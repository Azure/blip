#!/usr/bin/env bash
# Delete the kind cluster blip-dev and the host kernel state its blip nodes
# leave behind. kind nodes share the host kernel, so NVMe/TCP connections,
# nvmet exports, device-mapper devices and loop devices outlive the node
# containers.
# Only resources of blip-dev nodes are touched: dm devices named
# blip-<first 8 hex of sha256(node name)>-*, nvmet and NVMe host entries with
# those nodes' host NQNs or devices, and loop devices backed by files under
# /var/tmp/blip-kind.
#
# Usage: hack/kind-down.sh [--purge]   (--purge also removes /var/tmp/blip-kind)
set -euo pipefail

CLUSTER=blip-dev
DATA=/var/tmp/blip-kind
NVMET=/sys/kernel/config/nvmet

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

# Naming used by internal/storage and internal/peer: dm names blip-<hash>-*,
# subsystem NQNs nqn.2014-08.dev.blip:<hash>:*, nvmet port ID derived from
# <hash>, host NQNs nqn.2014-08.dev.blip:host:<node>.
prefixes=() subnqns=() hostnqns=() ports=()
for node in "${nodes[@]}"; do
  h="$(printf %s "${node}" | sha256sum | cut -c1-8)"
  prefixes+=("blip-${h}-")
  subnqns+=("nqn.2014-08.dev.blip:${h}:")
  hostnqns+=("nqn.2014-08.dev.blip:host:${node}")
  ports+=("$(( 0x${h:0:4} % 60000 + 1000 ))")
done
ours_dm() {
  local p
  for p in "${prefixes[@]}"; do [[ "$1" == *"${p}"* ]] && return 0; done
  return 1
}
ours_nqn() {
  local n
  for n in "${hostnqns[@]}"; do [[ "$1" == "${n}" ]] && return 0; done
  for n in "${subnqns[@]}"; do [[ "$1" == "${n}"* ]] && return 0; done
  return 1
}
dm_name_of() { # device path -> dm name, or the path itself
  local base
  base="$(basename "$1")"
  if [[ "${base}" == dm-* && -r "/sys/block/${base}/dm/name" ]]; then
    cat "/sys/block/${base}/dm/name"
  else
    echo "$1"
  fi
}

# 1. NVMe/TCP host connections: fail outstanding I/O before removing the
#    dm-clone devices stacked on them.
for ctrl in /sys/class/nvme/nvme*; do
  [[ "$(cat "${ctrl}/transport" 2>/dev/null)" == tcp ]] || continue
  if ours_nqn "$(cat "${ctrl}/hostnqn")" || ours_nqn "$(cat "${ctrl}/subsysnqn")"; then
    echo "disconnecting ${ctrl##*/}"
    echo 1 | sudo tee "${ctrl}/delete_controller" >/dev/null
  fi
done

# 2. nvmet exports.
if [[ -d "${NVMET}/subsystems" ]]; then
  empty_ports=()
  for subsys in "${NVMET}"/subsystems/*; do
    [[ -d "${subsys}" ]] || continue
    ours=false
    ours_nqn "${subsys##*/}" && ours=true
    for ns in "${subsys}"/namespaces/*; do
      [[ -r "${ns}/device_path" ]] && ours_dm "$(dm_name_of "$(cat "${ns}/device_path")")" && ours=true
    done
    for host in "${subsys}"/allowed_hosts/*; do
      [[ -e "${host}" ]] && ours_nqn "${host##*/}" && ours=true
    done
    "${ours}" || continue
    name="${subsys##*/}"
    echo "removing nvmet subsystem ${name}"
    for port in "${NVMET}"/ports/*; do
      if [[ -L "${port}/subsystems/${name}" ]]; then
        sudo rm "${port}/subsystems/${name}"
        empty_ports+=("${port}")
      fi
    done
    for ns in "${subsys}"/namespaces/*; do
      [[ -d "${ns}" ]] || continue
      echo 0 | sudo tee "${ns}/enable" >/dev/null
      sudo rmdir "${ns}"
    done
    for host in "${subsys}"/allowed_hosts/*; do
      [[ -e "${host}" ]] && sudo rm "${host}"
    done
    sudo rmdir "${subsys}"
  done
  for port in "${ports[@]}"; do
    empty_ports+=("${NVMET}/ports/${port}")
  done
  for port in "${empty_ports[@]}"; do
    if [[ -d "${port}" && -z "$(ls -A "${port}/subsystems")" ]]; then
      echo "removing nvmet port ${port##*/}"
      sudo rmdir "${port}"
    fi
  done
  for host in "${NVMET}"/hosts/*; do
    [[ -d "${host}" ]] && ours_nqn "${host##*/}" && { sudo rmdir "${host}" 2>/dev/null || true; }
  done
fi

# 3. Device-mapper devices, top of the stack first: each pass removes the
#    devices nothing holds open.
for _ in $(seq 10); do
  mapfile -t devs < <(sudo dmsetup info -c --noheadings --separator ' ' -o name,open,suspended 2>/dev/null | while read -r name open state; do
    ours_dm "${name}" && echo "${name} ${open} ${state}"
  done)
  [[ ${#devs[@]} -gt 0 ]] || break
  for dev in "${devs[@]}"; do
    read -r name open state <<<"${dev}"
    if [[ "${state}" == Suspended ]]; then
      sudo timeout 30 dmsetup resume "${name}" || true
    fi
    if [[ "${open}" == 0 ]]; then
      echo "removing dm ${name}"
      sudo timeout 30 dmsetup remove "${name}" || true
    fi
  done
done
if [[ ${#devs[@]} -gt 0 ]]; then
  echo "warning: dm devices left: ${devs[*]%% *}" >&2
fi

# 4. Loop devices backed by files under ${DATA}, matched by device and inode
#    (the kernel reports the backing path as the kind node saw it).
if [[ -d "${DATA}" ]]; then
  mapfile -t files < <(sudo find "${DATA}" -xdev -type f -exec stat -c '%Hd:%Ld %i' {} +)
  sudo losetup -l -n -O NAME,BACK-MAJ:MIN,BACK-INO | while read -r loop majmin ino; do
    for f in "${files[@]}"; do
      if [[ "${f}" == "${majmin} ${ino}" ]]; then
        echo "detaching ${loop}"
        sudo losetup -d "${loop}"
      fi
    done
  done
fi

if "${purge}"; then
  sudo rm -rf "${DATA}"
fi
