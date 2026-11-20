# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# shellcheck shell=bash
# blipchat smoke test: the deployment serves probes, rejects anonymous API
# calls, and lists team-scoped sessions through a port-forward. Agent turns are
# covered by unit tests; this scenario only checks the installed wire-up.

pf_pid_70=
pf_mcp_pid_70=

cleanup_70() {
	if [ -n "${pf_mcp_pid_70:-}" ]; then
		kill "$pf_mcp_pid_70" >/dev/null 2>&1 || true
		wait "$pf_mcp_pid_70" >/dev/null 2>&1 || true
	fi
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

step "a stale namespace parameter is ignored"
code=$(curl -sS --max-time 10 -o /dev/null -w '%{http_code}' \
	-H 'X-Forwarded-User: e2e' \
	"http://127.0.0.1:$chat_port_70/api/sessions?namespace=Not_A_Namespace")
[ "$code" = 200 ] || {
	echo "expected 200 when a stale namespace is ignored, got $code" >&2
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

step "MCP endpoint rejects anonymous requests"
mcp_port_70=${BLIP_E2E_CHAT_MCP_PORT:-18443}
kubectl --context "$CONTEXT" -n blip-system port-forward \
	--address 127.0.0.1 svc/blipchat-mcp "$mcp_port_70":mcp >"$work/port-forward-70-mcp.log" 2>&1 &
pf_mcp_pid_70=$!
mcp_code_70=
for ((i = 0; i < 20; i++)); do
	if ! kill -0 "$pf_mcp_pid_70" 2>/dev/null; then
		break
	fi
	if mcp_code_70=$(curl -sS -k --max-time 2 -o /dev/null -w '%{http_code}' \
		-X POST "https://127.0.0.1:$mcp_port_70/mcp?namespace=default" 2>/dev/null); then
		break
	fi
	mcp_code_70=
	sleep 1
done
if [ -z "$mcp_code_70" ]; then
	# A cluster that does not provision the MCP TLS Secret serves no MCP port.
	echo "SKIP 70-blipchat: MCP is not configured in this cluster"
	cat "$work/port-forward-70-mcp.log" >&2 || true
else
	[ "$mcp_code_70" = 401 ] || {
		echo "expected 401 from MCP without a bearer token, got $mcp_code_70" >&2
		exit 1
	}
fi
