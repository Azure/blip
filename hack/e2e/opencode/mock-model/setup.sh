#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Install the deterministic mock model used by the opencode browser E2E test.
# Local kind only: it replaces the real inference proxy in the same namespace.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
cd "$ROOT"

CONTEXT=${BLIP_CONTEXT:-kind-blip-dev}
EXPECTED_CONTEXT=kind-blip-dev
SCRIPT_DIR="$ROOT/hack/e2e/opencode/mock-model"
CA_DAYS=7
CERT_DAYS=7

log() { printf '\n==> %s\n' "$*" >&2; }
die() { echo "error: $*" >&2; exit 1; }

for tool in kubectl openssl; do
	command -v "$tool" >/dev/null || die "missing tool: $tool"
done

current=$(kubectl config current-context 2>/dev/null || true)
if [ -n "$current" ] && [ "$current" != "$EXPECTED_CONTEXT" ]; then
	die "refusing to run in context '$current'; expected '$EXPECTED_CONTEXT' (local kind only)"
fi
kubectl config get-contexts -o name | grep -qx "$EXPECTED_CONTEXT" || die \
	"missing kubectl context '$EXPECTED_CONTEXT' (local kind only)"
kubectl --context "$CONTEXT" -n blip-system get namespace blip-system >/dev/null

umask 077
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/blip-mock-model.XXXXXX")
cleanup() { rm -rf -- "$work_dir"; }
trap cleanup EXIT

ca_key="$work_dir/ca.key"
ca_crt="$work_dir/ca.crt"
server_key="$work_dir/tls.key"
server_csr="$work_dir/tls.csr"
server_crt="$work_dir/tls.crt"
server_ext="$work_dir/server.ext"

log "generating a short-lived local CA and server certificate"
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days "$CA_DAYS" \
	-keyout "$ca_key" -out "$ca_crt" \
	-subj "/CN=blip-mock-model-local-ca" \
	-addext "basicConstraints=critical,CA:TRUE" \
	-addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1

openssl req -new -newkey rsa:2048 -sha256 -nodes \
	-keyout "$server_key" -out "$server_csr" \
	-subj "/CN=unbounded-proxy.blip-system.svc.cluster.local" >/dev/null 2>&1

cat >"$server_ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:unbounded-proxy.blip-system.svc.cluster.local,DNS:unbounded-proxy.blip-system.svc,DNS:unbounded-proxy
EOF

openssl x509 -req -in "$server_csr" -CA "$ca_crt" -CAkey "$ca_key" \
	-CAcreateserial -out "$server_crt" -days "$CERT_DAYS" -sha256 \
	-extfile "$server_ext" >/dev/null 2>&1
openssl verify -CAfile "$ca_crt" "$server_crt" >/dev/null

log "applying the mock model TLS material"
kubectl --context "$CONTEXT" -n blip-system create secret tls unbounded-proxy-tls \
	--cert="$server_crt" --key="$server_key" \
	--dry-run=client -o yaml | kubectl --context "$CONTEXT" apply -f -
kubectl --context "$CONTEXT" -n default create configmap unbounded-proxy-ca \
	--from-file=ca.crt="$ca_crt" \
	--dry-run=client -o yaml | kubectl --context "$CONTEXT" apply -f -
kubectl --context "$CONTEXT" -n blip-system create configmap unbounded-proxy-script \
	--from-file=mock_model.py="$SCRIPT_DIR/mock_model.py" \
	--dry-run=client -o yaml | kubectl --context "$CONTEXT" apply -f -

log "applying the mock model Deployment and Service"
kubectl --context "$CONTEXT" apply -f "$SCRIPT_DIR/deployment.yaml"

log "restarting the mock model"
kubectl --context "$CONTEXT" -n blip-system rollout restart deployment/unbounded-proxy
kubectl --context "$CONTEXT" -n blip-system rollout status deployment/unbounded-proxy --timeout=180s
log "mock model is ready"
