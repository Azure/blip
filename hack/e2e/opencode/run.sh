#!/usr/bin/env bash
# Browser end-to-end test for the opencode ACP agent in a Blip.
#
# The tracked test harness knows only the logical endpoint named "unbounded".
# Its TLS gateway, bearer-token injection, and Azure credentials live in the
# ignored inference-proxy/ directory. Never run this against a remote cluster.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"

CONTEXT=${BLIP_CONTEXT:-kind-blip-dev}
EXPECTED_CONTEXT=kind-blip-dev
NS=${BLIP_E2E_NAMESPACE:-default}
POOL=${BLIP_E2E_POOL:-opencode}
BASE=${BLIP_E2E_BASE:-e2e-opencode-base}
PROFILE=${BLIP_E2E_PROFILE:-opencode}
HOST_IMAGE=${BLIP_E2E_OPENCODE_HOST_IMAGE:-localhost:5001/blip/opencode:e2e}
IMAGE=${BLIP_E2E_OPENCODE_IMAGE:-blip-registry:5000/blip/opencode:e2e}
CHAT_PORT=${BLIP_E2E_CHAT_PORT:-18080}
DIRECT_PORT=${BLIP_E2E_DIRECT_PORT:-18081}
T=${BLIP_E2E_TIMEOUT:-300}
SKIP_BUILD=${SKIP_BUILD:-0}
SKIP_BASE=${SKIP_BASE:-0}
SKIP_INFERENCE_PROXY=${SKIP_INFERENCE_PROXY:-0}
KEEP=${KEEP:-0}
REBUILD_BASE=${REBUILD_BASE:-0}
BASE_SIZE=${BLIP_E2E_BASE_SIZE:-2Gi}

RUN_ID=$(date +%Y%m%d-%H%M%S)
WORK=${BLIP_E2E_WORKDIR:-build/e2e-opencode/$RUN_ID}
ARTIFACTS=${BLIP_E2E_ARTIFACTS:-$WORK/artifacts}
RESULT=${BLIP_E2E_RESULT_FILE:-$WORK/result.json}
mkdir -p "$WORK" "$ARTIFACTS"

SESSION=
PF_PIDS=()
t0=$SECONDS

step() { printf '\n== [%3ds] %s\n' "$((SECONDS - t0))" "$*"; }
die() { echo "error: $*" >&2; exit 1; }
k() { kubectl --context "$CONTEXT" "$@"; }
blip() { bin/kubectl-blip --context "$CONTEXT" --namespace "$NS" "$@"; }

wait_for() {
	local timeout=$1 desc=$2 i
	shift 2
	for ((i = 0; i < timeout; i++)); do
		if "$@"; then
			return 0
		fi
		sleep 1
	done
	echo "timed out after ${timeout}s waiting for $desc" >&2
	return 1
}

wait_http() {
	local url=$1 timeout=${2:-60} i
	for ((i = 0; i < timeout; i++)); do
		curl -fsS --max-time 2 "$url" >/dev/null 2>&1 && return 0
		sleep 1
	done
	echo "timed out waiting for $url" >&2
	return 1
}

state_ready() {
	[ "$(k -n "$NS" get blipstate "$BASE" -o jsonpath='{.status.phase}' 2>/dev/null)" = Ready ]
}

pool_ready() {
	ready=$(k -n "$NS" get blippool "$POOL" -o jsonpath='{.status.ready}' 2>/dev/null || true)
	[ -n "$ready" ] && [ "$ready" -ge 1 ]
}

blip_exists() { k -n "$NS" get blip "$1" >/dev/null 2>&1; }

diagnose() {
	{
		echo "session=$SESSION"
		echo "result=$RESULT"
		k -n "$NS" get blipstate "$SESSION" -o yaml 2>&1 || true
		k -n "$NS" get blip -l "chat.blip.dev/session=$SESSION" -o yaml 2>&1 || true
		k -n "$NS" get pods -o wide 2>&1 || true
		k -n blip-system logs deploy/blipchat --tail=300 2>&1 || true
		k -n blip-system logs deploy/blipchat-auth --tail=200 2>&1 || true
		k -n blip-system logs deploy/unbounded-proxy --tail=200 2>&1 || true
		blip logs --state "$SESSION" 2>&1 | tail -300 || true
	} >"$WORK/diagnostics.txt" 2>&1
}

cleanup() {
	status=$?
	set +e
	if [ "${#PF_PIDS[@]}" -gt 0 ]; then
		for pid in "${PF_PIDS[@]}"; do
			kill "$pid" >/dev/null 2>&1 || true
			wait "$pid" >/dev/null 2>&1 || true
		done
	fi
	if [ "$status" -eq 0 ] && [ "$KEEP" != 1 ]; then
		if [ -n "$SESSION" ]; then
			k -n "$NS" delete blip -l "chat.blip.dev/session=$SESSION" \
				--ignore-not-found --wait=false >/dev/null 2>&1
			k -n "$NS" delete blipstate "$SESSION" \
				--ignore-not-found --wait=false >/dev/null 2>&1
		fi
		# Keep the result and browser artifacts; only the staged 211 MB
		# opencode build context is disposable.
		rm -rf "$WORK/image"
	fi
	echo "artifacts kept in $WORK" >&2
	exit "$status"
}
trap cleanup EXIT

cleanup_stale_sessions() {
	local states state
	states=$(k -n "$NS" get blipstates -o name 2>/dev/null \
		| sed 's|.*/||' | grep '^chat-opencode-e2e-' || true)
	[ -n "$states" ] || return 0
	for state in $states; do
		k -n "$NS" delete blip -l "chat.blip.dev/session=$state" \
			--ignore-not-found --wait=false >/dev/null 2>&1 || true
		k -n "$NS" delete blipstate "$state" \
			--ignore-not-found --wait=false >/dev/null 2>&1 || true
	done
}

on_error() {
	status=$?
	set +e
	echo "FAILED (exit $status); collecting diagnostics in $WORK" >&2
	diagnose
	exit "$status"
}
trap on_error ERR

step "checking local-only context"
current=$(kubectl config current-context 2>/dev/null || true)
[ "$current" = "$EXPECTED_CONTEXT" ] || die \
	"refusing to run in context '$current'; expected '$EXPECTED_CONTEXT' (local kind only)"
k get nodes >/dev/null
k -n blip-system get deployment/blipchat >/dev/null

if [ "$KEEP" != 1 ]; then
	cleanup_stale_sessions
fi

for tool in kubectl kind docker az openssl python3 node curl; do
	command -v "$tool" >/dev/null || die "missing tool: $tool"
done
command -v base64 >/dev/null || true

if [ ! -x bin/kubectl-blip ]; then
	step "building the blip CLI"
	make build
fi

OPENCODE_BIN=${OPENCODE_BIN:-$(command -v opencode || true)}
[ -n "$OPENCODE_BIN" ] && [ -x "$OPENCODE_BIN" ] || die \
	"opencode binary not found; set OPENCODE_BIN"

if [ -z "${NODE_PATH:-}" ]; then
	for dir in "$HOME/code/cade/node_modules" "$HOME/verify-cade/node_modules"; do
		if [ -d "$dir/playwright" ]; then
			export NODE_PATH="$dir"
			break
		fi
	done
fi
node -e "require('playwright')" >/dev/null 2>&1 || die \
	"playwright is not installed; run npm install in hack/e2e/opencode/browser or set NODE_PATH"

step "checking the local inference proxy"
# The inference proxy runs as a normal pod, so the kubelet needs the dev image
# in the node image store. kind-up pushes it; load it locally too.
proxy_image=blip-registry:5000/blip/dev:latest
if ! docker image inspect "$proxy_image" >/dev/null 2>&1; then
	docker pull localhost:5001/blip/dev:latest
	docker tag localhost:5001/blip/dev:latest "$proxy_image"
fi
kind load docker-image --name blip-dev "$proxy_image" >/dev/null 2>&1 || \
	echo "warning: could not load $proxy_image into kind" >&2

if [ "$SKIP_INFERENCE_PROXY" != 1 ]; then
	if [ -x inference-proxy/setup.sh ]; then
		inference-proxy/setup.sh
	elif k -n blip-system get service/unbounded-proxy >/dev/null 2>&1; then
		echo "using the existing unbounded-proxy service"
	else
		die "inference-proxy/setup.sh is missing and service/unbounded-proxy does not exist"
	fi
fi

if [ "$SKIP_BUILD" != 1 ]; then
	step "building the opencode VM image"
	imgctx="$WORK/image"
	mkdir -p "$imgctx"
	cp hack/e2e/opencode/image/Dockerfile "$imgctx/Dockerfile"
	cp "$OPENCODE_BIN" "$imgctx/opencode"
	chmod 0755 "$imgctx/opencode"
	docker build -t "$HOST_IMAGE" "$imgctx"
	docker push "$HOST_IMAGE"
fi

step "preparing base state $BASE"
if k -n "$NS" get blipstate "$BASE" >/dev/null 2>&1; then
	phase=$(k -n "$NS" get blipstate "$BASE" -o jsonpath='{.status.phase}' 2>/dev/null || true)
	if [ "$REBUILD_BASE" = 1 ] || [ "$phase" = Failed ]; then
		k -n "$NS" delete blipstate "$BASE" --ignore-not-found
	fi
fi
if ! k -n "$NS" get blipstate "$BASE" >/dev/null 2>&1; then
	[ "$SKIP_BASE" = 1 ] && die "base state $BASE does not exist and SKIP_BASE=1"
	blip pull "$BASE" "$IMAGE" --size "$BASE_SIZE"
fi
wait_for "$T" "state $BASE to become Ready" state_ready || {
	k -n "$NS" get blipstate "$BASE" -o yaml >&2 || true
	exit 1
}

step "applying pool and profile"
k apply -f hack/e2e/opencode/manifests/opencode-pool.yaml
profile_json=$(k create --dry-run=client -f hack/e2e/opencode/manifests/opencode-profile.yaml \
	-o jsonpath='{.data.opencode}')
if k -n blip-system get configmap/blip-chat-profiles >/dev/null 2>&1; then
	patch=$(python3 -c \
		'import json,sys; print(json.dumps({"data":{"opencode":sys.argv[1]}}))' \
		"$profile_json")
	k -n blip-system patch configmap/blip-chat-profiles --type merge -p "$patch"
else
	k apply -f hack/e2e/opencode/manifests/opencode-profile.yaml
fi

step "restarting blipchat for the new profile"
k -n blip-system rollout restart deployment/blipchat
k -n blip-system rollout status deployment/blipchat --timeout=3m

step "waiting for an opencode pool VM"
wait_for "$T" "pool $POOL to have a ready VM" pool_ready || {
	k -n "$NS" get blippool "$POOL" -o yaml >&2 || true
	k -n "$NS" get pods -o wide >&2 || true
	exit 1
}

step "starting the local auth shim"
if ! docker image inspect nginx:1.27-alpine >/dev/null 2>&1; then
	docker pull nginx:1.27-alpine
fi
kind load docker-image --name blip-dev nginx:1.27-alpine >/dev/null 2>&1 || \
	echo "warning: could not kind-load nginx; the deployment will pull it" >&2
k apply -f hack/e2e/opencode/manifests/blipchat-auth.yaml
k -n blip-system rollout status deployment/blipchat-auth --timeout=2m

k -n blip-system port-forward --address 127.0.0.1 svc/blipchat-auth "$CHAT_PORT":80 \
	>"$WORK/port-forward-auth.log" 2>&1 &
PF_PIDS+=("$!")
k -n blip-system port-forward --address 127.0.0.1 svc/blipchat "$DIRECT_PORT":80 \
	>"$WORK/port-forward-direct.log" 2>&1 &
PF_PIDS+=("$!")

wait_http "http://127.0.0.1:$CHAT_PORT/healthz" 60 || {
	cat "$WORK/port-forward-auth.log" >&2 || true
	exit 1
}
wait_http "http://127.0.0.1:$DIRECT_PORT/healthz" 60 || {
	cat "$WORK/port-forward-direct.log" >&2 || true
	exit 1
}

step "checking the auth boundary"
code=$(curl -sS --max-time 10 -o /dev/null -w '%{http_code}' \
	"http://127.0.0.1:$DIRECT_PORT/api/sessions?namespace=$NS")
[ "$code" = 401 ] || die "direct blipchat API returned $code, expected 401"
curl -fsS --max-time 30 "http://127.0.0.1:$CHAT_PORT/api/sessions?namespace=$NS" >/dev/null
curl -fsS --max-time 30 "http://127.0.0.1:$CHAT_PORT/api/profiles?namespace=$NS" \
	>"$WORK/profiles.json"
grep -q "\"$PROFILE\"" "$WORK/profiles.json" || {
	cat "$WORK/profiles.json" >&2
	die "profile $PROFILE is not visible to blipchat"
}

step "running the browser test"
BLIP_E2E_URL=${BLIP_E2E_URL:-http://127.0.0.1:$CHAT_PORT} \
BLIP_E2E_PROFILE="$PROFILE" \
BLIP_E2E_BASE="$BASE" \
BLIP_E2E_NAMESPACE="$NS" \
BLIP_E2E_ARTIFACTS="$ARTIFACTS" \
BLIP_E2E_RESULT_FILE="$RESULT" \
BLIP_E2E_TIMEOUT_MS=$((T * 1000)) \
	node hack/e2e/opencode/browser/run.js

[ -f "$RESULT" ] || die "browser test did not write $RESULT"
SESSION=$(python3 -c \
	'import json,sys; print(json.load(open(sys.argv[1]))["sessionName"])' "$RESULT")
ACP1=$(python3 -c \
	'import json,sys; print(json.load(open(sys.argv[1])).get("acpSessionId1", ""))' "$RESULT")
ACP2=$(python3 -c \
	'import json,sys; print(json.load(open(sys.argv[1])).get("acpSessionId2", ""))' "$RESULT")
GEN1=$(python3 -c \
	'import json,sys; print(json.load(open(sys.argv[1])).get("generation1", ""))' "$RESULT")
GEN2=$(python3 -c \
	'import json,sys; print(json.load(open(sys.argv[1])).get("generation2", ""))' "$RESULT")
[ -n "$SESSION" ] || die "browser test returned an empty session name"
[ -n "$ACP1" ] || die "first turn did not persist an ACP session id"
[ "$ACP1" = "$ACP2" ] || die "second turn changed the ACP session id ($ACP1 -> $ACP2)"
[ -n "$GEN1" ] && [ -n "$GEN2" ] && [ "$GEN2" -gt "$GEN1" ] || \
	die "expected a new generation for the second turn (got $GEN1 -> $GEN2)"

g1="$SESSION-g1"
g2="$SESSION-g2"
wait_for 60 "blip $g1" blip_exists "$g1" || die "missing first generation $g1"
wait_for 60 "blip $g2" blip_exists "$g2" || die "missing second generation $g2"

step "asserting the Blip generations"
[ "$(k -n "$NS" get blip "$g1" -o jsonpath='{.spec.pool}')" = "$POOL" ] || \
	die "$g1 did not run in pool $POOL"
[ "$(k -n "$NS" get blip "$g1" -o jsonpath='{.spec.command[0]}')" = /usr/local/bin/opencode ] || \
	die "$g1 did not run opencode"
[ "$(k -n "$NS" get blip "$g1" -o jsonpath='{.spec.command[1]}')" = acp ] || \
	die "$g1 did not run opencode acp"
[ "$(k -n "$NS" get blip "$g1" -o jsonpath='{.spec.state}')" = "$SESSION" ] || \
	die "$g1 did not use state $SESSION"

acp=$(k -n "$NS" get blipstate "$SESSION" -o jsonpath='{.metadata.annotations.chat\.blip\.dev/acp-session}')
[ -n "$acp" ] || die "state $SESSION has no ACP session id"
[ "$acp" = "$ACP1" ] || die "state ACP session $acp does not match the first turn ($ACP1)"
[ "$(k -n "$NS" get blip "$g2" -o jsonpath='{.spec.pool}')" = "$POOL" ] || \
	die "$g2 did not run in pool $POOL"
[ "$(k -n "$NS" get blip "$g2" -o jsonpath='{.spec.command[0]}')" = /usr/local/bin/opencode ] || \
	die "$g2 did not run opencode"

if k -n "$NS" get blip "$g1" -o json | grep -Eqi 'accessToken|unbounded-token|AZURE_CLIENT'; then
	die "inference credentials leaked into the Blip spec"
fi

echo
echo "PASSED in $((SECONDS - t0))s"
echo "session: $SESSION"
echo "ACP session: $acp"
echo "artifacts: $WORK"
