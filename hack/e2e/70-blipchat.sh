# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# shellcheck shell=bash
# blipchat smoke test: the deployment serves probes, rejects anonymous API
# calls, and lists team-scoped sessions through a port-forward. Agent turns are
# covered by unit tests; this scenario only checks the installed wire-up.

pf_pid_70=

cleanup_70() {
	if [ -n "${pf_pid_70:-}" ]; then
		kill "$pf_pid_70" >/dev/null 2>&1 || true
		wait "$pf_pid_70" >/dev/null 2>&1 || true
	fi
}

if ! k -n blip-system get deployment/blipchat >/dev/null 2>&1; then
	echo "SKIP 70-blipchat: deployment/blipchat is not installed in blip-system"
	return 0
fi
cleanup_register cleanup_70

step "port-forward blipchat"
chat_port_70=${BLIP_E2E_CHAT_PORT:-18080}
kubectl --context "$CONTEXT" -n blip-system port-forward \
	--address 127.0.0.1 svc/blipchat "$chat_port_70":80 >"$work/port-forward-70.log" 2>&1 &
pf_pid_70=$!
if ! wait_http "http://127.0.0.1:$chat_port_70/healthz" 120; then
	cat "$work/port-forward-70.log" >&2 || true
	exit 1
fi
curl -fsS --max-time 10 "http://127.0.0.1:$chat_port_70/readyz" >/dev/null

step "anonymous API requests are rejected"
code=$(curl -sS --max-time 10 -o /dev/null -w '%{http_code}' \
	"http://127.0.0.1:$chat_port_70/api/sessions?namespace=default")
[ "$code" = 401 ] || {
	echo "expected 401 without X-Forwarded-User, got $code" >&2
	exit 1
}

step "invalid namespaces are rejected"
code=$(curl -sS --max-time 10 -o /dev/null -w '%{http_code}' \
	-H 'X-Forwarded-User: e2e' \
	"http://127.0.0.1:$chat_port_70/api/sessions?namespace=Not_A_Namespace")
[ "$code" = 400 ] || {
	echo "expected 400 for an invalid namespace, got $code" >&2
	exit 1
}

step "authenticated session and profile listings"
curl -fsS --max-time 30 -H 'X-Forwarded-User: e2e' \
	"http://127.0.0.1:$chat_port_70/api/sessions?namespace=default" >"$work/sessions-70.json"
grep -q '^\[' "$work/sessions-70.json" || {
	echo "session listing is not a JSON array" >&2
	cat "$work/sessions-70.json" >&2
	exit 1
}
curl -fsS --max-time 30 -H 'X-Forwarded-User: e2e' \
	"http://127.0.0.1:$chat_port_70/api/profiles?namespace=default" >"$work/profiles-70.json"
grep -q '"default"' "$work/profiles-70.json" || {
	echo "profile listing has no default profile" >&2
	cat "$work/profiles-70.json" >&2
	exit 1
}
