#!/usr/bin/env bash
# Create or update the local kind cluster blip-dev and install Blip on it.
# Safe to rerun. Touches only the kind cluster blip-dev (always through the
# explicit context kind-blip-dev), the blip-registry container, and
# /var/tmp/blip-kind.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER=blip-dev
CTX=kind-blip-dev
REGISTRY=blip-registry
DATA=/var/tmp/blip-kind
WORKERS=(blip-dev-worker blip-dev-worker2 blip-dev-worker3)

k() { kubectl --context "${CTX}" "$@"; }

cd "${ROOT}"
# Non-login shells often omit the Go, snap, and sbin tool locations.
PATH="${PATH}:/usr/local/go/bin:${HOME}/go/bin:/snap/bin:/usr/sbin:/sbin"
export PATH
for tool in docker kind kubectl go make modinfo; do
  command -v "${tool}" >/dev/null || { echo "missing tool: ${tool}" >&2; exit 1; }
done

# Node data from before encrypted volumes has no disk key ID and the node agent
# refuses to open it. Fail before creating a cluster that cannot start.
for node in "${WORKERS[@]}"; do
  db="${DATA}/${node}/storage.db"
  if sudo test -s "${db}" && ! sudo grep -aq diskKeyID "${db}"; then
    echo "node data in ${DATA}/${node} predates encrypted volumes;" \
      "run hack/kind-down.sh --purge to discard it" >&2
    exit 1
  fi
done

# kind nodes share the host kernel, so the modules blip needs are loaded on the
# host.
sudo modprobe -a configfs loop tun nvmet nvmet_tcp nvme_tcp nvme_fabrics dm_thin_pool dm_clone dm_crypt

# load_images loads the given images into the workers. Old kind releases cannot
# detect the containerd 2.x snapshotter ("failed to detect containerd
# snapshotter"), so fall back to importing the archives directly with ctr.
load_images() {
  local images=("$@") tmp image archive node snapshotter detected
  if kind load docker-image --name "${CLUSTER}" \
    --nodes "$(IFS=,; echo "${WORKERS[*]}")" "${images[@]}"; then
    return
  fi
  echo "kind load failed; importing images directly into containerd" >&2
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/blip-images.XXXXXX")"
  trap 'rm -rf "${tmp}"' EXIT
  for image in "${images[@]}"; do
    archive="${tmp}/$(printf '%s' "${image}" | tr '/:' '__').tar"
    docker save "${image}" -o "${archive}"
    for node in "${WORKERS[@]}"; do
      # overlayfs is the kind default; use the node's configured snapshotter
      # when it can be detected.
      detected="$(docker exec "${node}" containerd config dump 2>/dev/null |
        sed -n "s/^[[:space:]]*snapshotter = ['\"]\([^'\"]*\)['\"].*/\1/p" | head -n1)"
      snapshotter="${detected:-overlayfs}"
      docker exec -i "${node}" ctr -n k8s.io images import \
        --all-platforms --digests --snapshotter="${snapshotter}" - <"${archive}" >/dev/null
    done
    rm -f "${archive}"
  done
  rm -rf "${tmp}"
  trap - EXIT
}

if kind get clusters 2>/dev/null | grep -qx "${CLUSTER}"; then
  if ! k get nodes >/dev/null 2>&1; then
    echo "kind cluster ${CLUSTER} exists but is not reachable; run hack/kind-down.sh first" >&2
    exit 1
  fi
else
  config="  - role: control-plane"
  for node in "${WORKERS[@]}"; do
    mkdir -p "${DATA}/${node}"
    config+="$(printf '\n  - role: worker\n    extraMounts:\n      - hostPath: %s\n        containerPath: /var/lib/blip' "${DATA}/${node}")"
  done
  # kind switches the kubeconfig's current context; put it back afterwards.
  prev="$(kubectl config current-context 2>/dev/null || true)"
  kind create cluster --name "${CLUSTER}" --wait 5m --config - <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  podSubnet: 10.244.0.0/16
nodes:
${config}
EOF
  if [[ -n "${prev}" ]]; then
    kubectl config use-context "${prev}" >/dev/null
  else
    kubectl config unset current-context >/dev/null
  fi
fi

# Plain HTTP registry: blip-registry:5000 on the kind network, localhost:5001
# from the host.
if ! docker container inspect "${REGISTRY}" >/dev/null 2>&1; then
  docker run -d --restart=always --name "${REGISTRY}" -p 127.0.0.1:5001:5000 registry:2 >/dev/null
elif [[ "$(docker container inspect -f '{{.State.Running}}' "${REGISTRY}")" != true ]]; then
  docker start "${REGISTRY}" >/dev/null
fi
if [[ "$(docker container inspect -f '{{json .NetworkSettings.Networks.kind}}' "${REGISTRY}")" == null ]]; then
  docker network connect kind "${REGISTRY}"
fi

for node in "${WORKERS[@]}"; do
  docker exec "${node}" sh -c 'mountpoint -q /sys/kernel/config || mount -t configfs configfs /sys/kernel/config'
  # Match deploy/kind/pools.yaml. The controller adds blip.dev/enrolled to
  # selected nodes and the node agent runs there.
  k label node "${node}" blip.dev/node-pool=default --overwrite >/dev/null
  # Remove the old manual opt-in label; it is inert now.
  k label node "${node}" blip.dev/node- >/dev/null 2>&1 || true
done

make build guest
hack/build-images.sh
# shellcheck source=/dev/null
source build/images.env
load_images "${CONTROLLER_IMAGE}" "${NODE_IMAGE}" "${RUNTIME_IMAGE}"

# The dev sandbox image (blip-registry:5000/blip/dev:latest inside the cluster),
# with bin/kubectl-blip from `make build` above.
docker build -q -t localhost:5001/blip/dev:latest -f hack/dev-image/Dockerfile . >/dev/null
docker push -q localhost:5001/blip/dev:latest >/dev/null

mkdir -p build/kind

cat > build/kind/kustomization.yaml <<EOF
# Generated by hack/kind-up.sh.
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - ../../deploy/kind
images:
  - name: ghcr.io/azure/blip-controller
    newName: ${CONTROLLER_IMAGE%:*}
    newTag: "${CONTROLLER_IMAGE##*:}"
  - name: ghcr.io/azure/blip-node
    newName: ${NODE_IMAGE%:*}
    newTag: "${NODE_IMAGE##*:}"
patches:
  - patch: |-
      apiVersion: apps/v1
      kind: Deployment
      metadata:
        name: blip-controller
        namespace: blip-system
      spec:
        template:
          spec:
            containers:
              - name: controller
                env:
                  - name: RUNTIME_IMAGE
                    value: ${RUNTIME_IMAGE}
EOF

k apply -k deploy/crd
# shellcheck disable=SC2046
k wait --for condition=Established --timeout 60s $(k get -k deploy/crd -o name)
k apply -k build/kind

k -n blip-system rollout status deployment/blip-controller --timeout 3m
k -n blip-system rollout status daemonset/blip-node --timeout 3m

cat <<EOF

blip-dev is ready. Always pass the context explicitly:

  bin/kubectl-blip --context ${CTX} pull dev-base ${REGISTRY}:5000/blip/dev:latest
  bin/kubectl-blip --context ${CTX} run hello --fork dev-base -- uname -a
  bin/kubectl-blip --context ${CTX} run sandbox --fork dev-base -- sh -c 'echo kept > ~/notes.txt'
  kubectl --context ${CTX} delete blip sandbox
  bin/kubectl-blip --context ${CTX} run resumed --state sandbox -- cat /home/dev/notes.txt
  kubectl --context ${CTX} get blippools,blips,blipstates -A

Root BlipState.spec.mounts and spec.runtime hold durable workspace configuration.
Delete BlipStates explicitly when their data is no longer needed.

Tear down with hack/kind-down.sh [--purge].
EOF
