#!/usr/bin/env bash
# hack/dev.sh — (re)deploy blip to a local kind cluster for development.
#
# Creates a kind cluster with KVM passthrough if one does not already exist,
# installs KubeVirt + CDI when needed, builds the blip image, loads it into
# kind, and applies the manifests.
#
# Usage:
#   ./hack/dev.sh              # full (re)deploy
#   POOL_REPLICAS=1 ./hack/dev.sh   # override pool size
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ---------------------------------------------------------------------------
# Configuration (override via environment)
# ---------------------------------------------------------------------------
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-kind}"
KUBEVIRT_VERSION="${KUBEVIRT_VERSION:-v1.8.1}"
CDI_VERSION="${CDI_VERSION:-v1.65.0}"
REGISTRY="${REGISTRY:-localhost/blip}"
BLIP_TAG="${BLIP_TAG:-dev}"
CONTAINER_ENGINE="${CONTAINER_ENGINE:-docker}"
POOL_REPLICAS="${POOL_REPLICAS:-}"  # empty = use pool.yaml default

IMAGE_NAME="${REGISTRY}/blip:${BLIP_TAG}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
info()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33mWARN:\033[0m %s\n' "$*" >&2; }
fatal() { printf '\033[1;31mFATAL:\033[0m %s\n' "$*" >&2; exit 1; }

require() {
    for cmd in "$@"; do
        command -v "$cmd" >/dev/null 2>&1 || fatal "required command not found: $cmd"
    done
}

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
require kind kubectl "$CONTAINER_ENGINE" envsubst

# ---------------------------------------------------------------------------
# 1. Ensure a kind cluster exists
# ---------------------------------------------------------------------------
if kind get clusters 2>/dev/null | grep -qx "$KIND_CLUSTER_NAME"; then
    info "Kind cluster '$KIND_CLUSTER_NAME' already exists"
else
    info "Creating kind cluster '$KIND_CLUSTER_NAME'..."
    cat > /tmp/blip-kind-config.yaml <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraMounts:
      - hostPath: /dev/kvm
        containerPath: /dev/kvm
EOF
    kind create cluster \
        --name "$KIND_CLUSTER_NAME" \
        --config /tmp/blip-kind-config.yaml \
        --wait 60s
    rm -f /tmp/blip-kind-config.yaml
fi

# Point kubectl at the kind cluster.
kubectl config use-context "kind-${KIND_CLUSTER_NAME}" >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# 2. Install KubeVirt (idempotent)
# ---------------------------------------------------------------------------
if kubectl get crd kubevirts.kubevirt.io >/dev/null 2>&1; then
    info "KubeVirt CRDs already present — skipping install"
else
    info "Installing KubeVirt ${KUBEVIRT_VERSION}..."
    kubectl apply -f "https://github.com/kubevirt/kubevirt/releases/download/${KUBEVIRT_VERSION}/kubevirt-operator.yaml"
    kubectl apply -f "https://github.com/kubevirt/kubevirt/releases/download/${KUBEVIRT_VERSION}/kubevirt-cr.yaml"
fi
info "Waiting for KubeVirt to become available..."
kubectl -n kubevirt wait kv kubevirt --for condition=Available --timeout=300s

# ---------------------------------------------------------------------------
# 3. Install CDI (idempotent)
# ---------------------------------------------------------------------------
if kubectl get crd cdis.cdi.kubevirt.io >/dev/null 2>&1; then
    info "CDI CRDs already present — skipping install"
else
    info "Installing CDI ${CDI_VERSION}..."
    kubectl apply -f "https://github.com/kubevirt/containerized-data-importer/releases/download/${CDI_VERSION}/cdi-operator.yaml"
    kubectl apply -f "https://github.com/kubevirt/containerized-data-importer/releases/download/${CDI_VERSION}/cdi-cr.yaml"
fi
info "Waiting for CDI to become available..."
kubectl -n cdi wait cdi cdi --for condition=Available --timeout=300s

# ---------------------------------------------------------------------------
# 4. Build the blip container image
# ---------------------------------------------------------------------------
info "Building image ${IMAGE_NAME}..."
"$CONTAINER_ENGINE" build -t "$IMAGE_NAME" -f "$REPO_ROOT/Dockerfile" "$REPO_ROOT"

# ---------------------------------------------------------------------------
# 5. Load image into kind
# ---------------------------------------------------------------------------
info "Loading image into kind cluster..."
kind load docker-image "$IMAGE_NAME" --name "$KIND_CLUSTER_NAME"

# ---------------------------------------------------------------------------
# 6. Render and apply manifests
# ---------------------------------------------------------------------------
info "Applying deploy.yaml..."
export REGISTRY BLIP_TAG
envsubst '${REGISTRY} ${BLIP_TAG}' < "$REPO_ROOT/deploy.yaml" | kubectl apply -f -

info "Applying pool.yaml..."
if [[ -n "$POOL_REPLICAS" ]]; then
    # Patch replica count on the fly.
    sed "s/replicas: [0-9]*/replicas: ${POOL_REPLICAS}/" "$REPO_ROOT/pool.yaml" \
        | kubectl apply -f -
else
    kubectl apply -f "$REPO_ROOT/pool.yaml"
fi

# ---------------------------------------------------------------------------
# 7. Restart deployments to pick up the new image
# ---------------------------------------------------------------------------
info "Restarting deployments..."
kubectl rollout restart deployment/blip-controller -n blip
kubectl rollout restart deployment/ssh-gateway -n blip

info "Waiting for rollouts to complete..."
kubectl rollout status deployment/blip-controller -n blip --timeout=120s
kubectl rollout status deployment/ssh-gateway -n blip --timeout=120s

# ---------------------------------------------------------------------------
# 8. Summary
# ---------------------------------------------------------------------------
echo ""
info "Blip deployed successfully!"
echo ""
kubectl get pods -n blip -o wide
echo ""
info "ssh-gateway service:"
kubectl get svc ssh-gateway -n blip
