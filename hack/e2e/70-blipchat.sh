# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# shellcheck shell=bash
# shellcheck disable=SC2154
# blipchat API test through a port-forward, posing as the auth gateway with
# X-Forwarded-User: probes, identity, profile and session listing, the session
# lifecycle (create, get, SSE events, cancel/stop while idle, delete and its
# BlipState cleanup), private-chat isolation between users, and the sameOrigin
# guard. The deployed profiles need a real model, so agent turns and
# authenticated MCP calls (which need a VM's pod-bound service-account token)
# are covered by hack/e2e/opencode with a mock model instead.

pf_pid_70=
pf_mcp_pid_70=
sessions_70=()

cleanup_70() {
	local s
	for s in "${sessions_70[@]}"; do
		k -n default delete blipstate "$s" --ignore-not-found --wait=false >/dev/null 2>&1 || true
	done
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

# api_70 METHOD PATH [USER] [CURL ARGS...] writes the body to $work/api-70.json
# and prints the HTTP status.
api_70() {
	local method=$1 path=$2 user=${3:-e2e}
	shift 3 || shift $#
	curl -sS --max-time 30 -o "$work/api-70.json" -w '%{http_code}' -X "$method" \
		-H "X-Forwarded-User: $user" "$@" "http://127.0.0.1:$chat_port_70$path"
}

expect_code_70() { # WANT GOT WHAT
	[ "$2" = "$1" ] || {
		echo "$3: expected HTTP $1, got $2" >&2
		cat "$work/api-70.json" >&2 || true
		exit 1
	}
}

json_70() { # PYTHON-EXPR over j
	python3 -c "import json,sys; j=json.load(open(sys.argv[1])); print($1)" "$work/api-70.json"
}

step "GET /api/me returns the forwarded user"
code=$(api_70 GET /api/me e2e-me)
expect_code_70 200 "$code" "GET /api/me"
[ "$(json_70 'j["user"]')" = e2e-me ] || {
	echo "/api/me did not return the forwarded user" >&2
	cat "$work/api-70.json" >&2
	exit 1
}

step "create a private chat with the default profile"
code=$(api_70 POST /api/sessions e2e -H 'Content-Type: application/json' \
	--data '{"profile":"default","scope":"user","title":"e2e 70"}')
expect_code_70 201 "$code" "POST /api/sessions"
chat_70=$(json_70 'j["name"]')
sessions_70+=("$chat_70")
[ "$(json_70 'j["namespace"]')" = default ] || {
	echo "created chat is not in the chat namespace" >&2
	exit 1
}
[ "$(k -n default get blipstate "$chat_70" -o jsonpath='{.metadata.labels.chat\.blip\.dev/session}')" = true ] || {
	echo "chat $chat_70 has no BlipState with the session label" >&2
	exit 1
}

step "GET the chat and find it in the listing"
code=$(api_70 GET "/api/sessions/$chat_70")
expect_code_70 200 "$code" "GET /api/sessions/$chat_70"
[ "$(json_70 '"%s %s %s %s %s" % (j["name"], j["scope"], j["profile"], j["title"], j["running"])')" = \
	"$chat_70 user default e2e 70 False" ] || {
	echo "unexpected chat detail" >&2
	cat "$work/api-70.json" >&2
	exit 1
}
[ "$(json_70 'type(j["transcript"]).__name__')" = list ] || {
	echo "chat detail has no transcript list" >&2
	exit 1
}
code=$(api_70 GET /api/sessions)
expect_code_70 200 "$code" "GET /api/sessions"
[ "$(json_70 "sum(1 for s in j if s['name'] == '$chat_70')")" = 1 ] || {
	echo "chat $chat_70 is missing from the owner's listing" >&2
	exit 1
}

step "the event stream emits well-formed SSE"
curl -s -N --max-time 5 -H 'X-Forwarded-User: e2e' -D "$work/sse-70.hdr" \
	"http://127.0.0.1:$chat_port_70/api/sessions/$chat_70/events" >"$work/sse-70.txt" || true
grep -qi '^content-type: text/event-stream' "$work/sse-70.hdr" || {
	echo "event stream has the wrong content type" >&2
	cat "$work/sse-70.hdr" >&2
	exit 1
}
python3 - "$work/sse-70.txt" <<'PY'
import json, sys
text = open(sys.argv[1]).read()
assert text.startswith("retry: "), "stream does not start with a retry hint: %r" % text[:80]
frames = [f for f in text.split("\n\n") if f.strip()]
data = 0
for frame in frames:
    for line in frame.split("\n"):
        field, _, value = line.partition(":")
        assert field in ("retry", "id", "event", "data", ""), "bad SSE line %r" % line
        if field == "data":
            json.loads(value.strip())
            data += 1
assert data > 0, "no data frames in %r" % text[:200]
PY

step "another user cannot see or use the private chat"
code=$(api_70 GET /api/sessions e2e-other)
expect_code_70 200 "$code" "GET /api/sessions as another user"
[ "$(json_70 "sum(1 for s in j if s['name'] == '$chat_70')")" = 0 ] || {
	echo "private chat $chat_70 is visible to another user" >&2
	exit 1
}
for req in "GET /api/sessions/$chat_70" "GET /api/sessions/$chat_70/events" \
	"POST /api/sessions/$chat_70/stop" "POST /api/sessions/$chat_70/cancel" \
	"DELETE /api/sessions/$chat_70"; do
	read -r method path <<<"$req"
	code=$(api_70 "$method" "$path" e2e-other)
	expect_code_70 404 "$code" "$req as another user"
done
code=$(api_70 POST "/api/sessions/$chat_70/message" e2e-other \
	-H 'Content-Type: application/json' --data '{"text":"hi"}')
expect_code_70 404 "$code" "message as another user"

step "cross-site POSTs are rejected"
code=$(api_70 POST /api/sessions e2e -H 'Content-Type: application/json' \
	-H 'Origin: https://evil.example' --data '{"profile":"default"}')
expect_code_70 403 "$code" "POST /api/sessions with a foreign Origin"
code=$(api_70 POST "/api/sessions/$chat_70/stop" e2e -H 'Sec-Fetch-Site: cross-site')
expect_code_70 403 "$code" "stop with Sec-Fetch-Site: cross-site"
code=$(api_70 POST /api/sessions e2e -H 'Content-Type: text/plain' --data '{}')
expect_code_70 415 "$code" "POST /api/sessions without a JSON content type"

step "message validation, and cancel/stop on an idle chat"
code=$(api_70 POST "/api/sessions/$chat_70/message" e2e \
	-H 'Content-Type: application/json' --data '{"text":"   "}')
expect_code_70 400 "$code" "empty message"
code=$(api_70 POST "/api/sessions/$chat_70/cancel")
expect_code_70 202 "$code" "cancel on an idle chat"
code=$(api_70 POST "/api/sessions/$chat_70/stop")
expect_code_70 202 "$code" "stop on an idle chat"
if [ -n "$(k -n default get blip -l "chat.blip.dev/session=$chat_70" -o name 2>/dev/null)" ]; then
	echo "cancel/stop on an idle chat started a blip" >&2
	exit 1
fi

step "delete the chat"
code=$(api_70 DELETE "/api/sessions/$chat_70")
expect_code_70 200 "$code" "DELETE /api/sessions/$chat_70"
code=$(api_70 GET "/api/sessions/$chat_70")
expect_code_70 404 "$code" "GET after delete"
code=$(api_70 GET /api/sessions)
[ "$(json_70 "sum(1 for s in j if s['name'] == '$chat_70')")" = 0 ] || {
	echo "deleted chat $chat_70 is still listed" >&2
	exit 1
}
chat_gone_70() {
	! k -n default get blipstate "$1" >/dev/null 2>&1 &&
		[ -z "$(k -n default get blip -l "chat.blip.dev/session=$1" -o name 2>/dev/null)" ]
}
wait_for 120 "chat $chat_70 state and blips to be removed" chat_gone_70 "$chat_70"

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
