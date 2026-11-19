# shellcheck shell=bash
# shellcheck disable=SC2154
# Chat and coordinator: a deterministic fake LLM turns one chat message into a
# coordinator task, an agent blip, a report, and a closed task. The turn
# admission policy is exercised separately with a project service account.

here_70=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
pf_pid_70=

cleanup_70() {
	if [ -n "${pf_pid_70:-}" ]; then
		kill "$pf_pid_70" >/dev/null 2>&1 || true
		wait "$pf_pid_70" >/dev/null 2>&1 || true
	fi
	# Put blipchat back on its original LLM before removing the fake.
	if [ -s "$work/blipchat-args.json" ] &&
		k -n blip-system get deployment/blipchat >/dev/null 2>&1; then
		{
			printf '{"spec":{"template":{"spec":{"containers":[{"name":"blipchat","args":'
			cat "$work/blipchat-args.json"
			printf '}]}}}}'
		} >"$work/blipchat-restore.json"
		k -n blip-system patch deployment/blipchat --type=strategic \
			-p "$(cat "$work/blipchat-restore.json")" >/dev/null 2>&1 || true
		rm -f "$work/blipchat-args.json"
	fi
	k delete blip -n default -l "blip.dev/thread=$P-thread" \
		--ignore-not-found --wait=false >/dev/null 2>&1 || true
	k delete blipstate -n default -l "blip.dev/thread=$P-thread" \
		--ignore-not-found --wait=false >/dev/null 2>&1 || true
	local turns
	turns=$(k get blipturns -n default \
		-o jsonpath='{range .items[?(@.spec.thread=="'"$P-thread"'")]}{.metadata.name}{"\n"}{end}' 2>/dev/null || true)
	if [ -n "$turns" ]; then
		# shellcheck disable=SC2086
		k delete blipturn -n default --ignore-not-found --wait=false $turns \
			>/dev/null 2>&1 || true
	fi
	k delete blipthread "$P-thread" -n default \
		--ignore-not-found --wait=false >/dev/null 2>&1 || true
	k delete blipturn -n default --ignore-not-found --wait=false \
		"$P-turner-user" "$P-turner-wrong" "$P-turner-ok" >/dev/null 2>&1 || true
	k delete rolebinding "$P-turner" -n default --ignore-not-found >/dev/null 2>&1 || true
	k delete role "$P-turner" -n default --ignore-not-found >/dev/null 2>&1 || true
	k delete serviceaccount "$P-turner" -n default --ignore-not-found >/dev/null 2>&1 || true
	k delete deployment "$P-fake-llm" -n blip-system --ignore-not-found >/dev/null 2>&1 || true
	k delete service "$P-fake-llm" -n blip-system --ignore-not-found >/dev/null 2>&1 || true
	k delete configmap "$P-fake-llm" -n blip-system --ignore-not-found >/dev/null 2>&1 || true
}

if ! k -n blip-system get deployment/blipchat >/dev/null 2>&1; then
	echo "SKIP 70-blipchat: deployment/blipchat is not installed in blip-system"
	return 0
fi
cleanup_register cleanup_70

thread_exists_70() {
	[ -n "$(k -n default get blipthread "$P-thread" -o jsonpath='{.metadata.uid}' 2>/dev/null)" ]
}

consumed_70() {
	local n
	n=$(k -n default get blipthread "$P-thread" -o jsonpath='{.status.consumedSeq}' 2>/dev/null) || return 1
	[ -n "$n" ] && [ "$n" -ge 1 ]
}

task_state_70() {
	k -n default get blipthread "$P-thread" \
		-o jsonpath='{.status.tasks[?(@.id=="t1")].id}/{.status.tasks[?(@.id=="t1")].open}' 2>/dev/null
}

# ThreadTask.open is omitempty, so a closed task has no open field at all.
task_is_open_70() {
	[ "$(task_state_70)" = "t1/true" ]
}

task_is_closed_70() {
	local state
	state=$(task_state_70) || return 1
	[ "$state" = "t1/" ] || [ "$state" = "t1/false" ]
}

blip_finished_70() {
	k -n default get blips -l "blip.dev/thread=$P-thread" \
		-o jsonpath='{range .items[*]}{.status.phase}{"\n"}{end}' 2>/dev/null |
		grep -xE 'Succeeded|Failed' >/dev/null
}

topics_70() {
	k -n default get blipturns \
		-o jsonpath='{range .items[?(@.spec.thread=="'"$P-thread"'")]}{.spec.topic}{"\n"}{end}' 2>/dev/null
}

has_topic_70() {
	topics_70 | grep -x "$1" >/dev/null
}

chat_user_turn_70() {
	k -n default get blipturns \
		-o jsonpath='{range .items[?(@.spec.thread=="'"$P-thread"'")]}{.spec.topic}/{.spec.author.kind}{"\n"}{end}' 2>/dev/null |
		grep -x 'chat.propose/User' >/dev/null
}

turn_lines_70() {
	k -n default get blipturns \
		-o jsonpath='{range .items[?(@.spec.thread=="'"$P-thread"'")]}{.status.seq}{" "}{.spec.topic}{" "}{.spec.author.kind}{"\n"}{end}' 2>/dev/null
}

all_sequenced_70() {
	turn_lines_70 | awk '
		NF { if ($1 !~ /^[1-9][0-9]*$/) exit 1; n++ }
		END { if (n == 0) exit 1 }
	'
}

turner_70() {
	timeout "$T" kubectl --kubeconfig "$work/turner.kubeconfig" "$@"
}

step "deploy a deterministic fake LLM"
k -n blip-system create configmap "$P-fake-llm" \
	--from-file=fake-llm.py="$here_70/fake-llm.py" \
	--dry-run=client -o yaml | k apply -f -
k apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: $P-fake-llm
  namespace: blip-system
  labels:
    app.kubernetes.io/name: $P-fake-llm
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: $P-fake-llm
  template:
    metadata:
      labels:
        app.kubernetes.io/name: $P-fake-llm
    spec:
      containers:
        - name: fake-llm
          image: ${BLIP_E2E_FAKE_LLM_IMAGE:-python:3.12-slim}
          imagePullPolicy: IfNotPresent
          command: ["python3", "-u", "/scripts/fake-llm.py"]
          ports:
            - name: http
              containerPort: 8080
          readinessProbe:
            httpGet:
              path: /healthz
              port: 8080
          volumeMounts:
            - name: scripts
              mountPath: /scripts
              readOnly: true
      volumes:
        - name: scripts
          configMap:
            name: $P-fake-llm
---
apiVersion: v1
kind: Service
metadata:
  name: $P-fake-llm
  namespace: blip-system
  labels:
    app.kubernetes.io/name: $P-fake-llm
spec:
  selector:
    app.kubernetes.io/name: $P-fake-llm
  ports:
    - name: http
      port: 8080
      targetPort: 8080
EOF
k -n blip-system rollout status deployment/"$P-fake-llm" --timeout 2m

step "point blipchat at the fake LLM"
k -n blip-system get deployment/blipchat \
	-o jsonpath='{.spec.template.spec.containers[0].args}' >"$work/blipchat-args.json"
test -s "$work/blipchat-args.json"
cat >"$work/blipchat-patch.json" <<EOF
{"spec":{"template":{"spec":{"containers":[{"name":"blipchat","args":["--leader-elect","--listen=:8080","--llm-base-url=http://$P-fake-llm:8080/v1","--model=e2e","--debounce=1s","--heartbeat=30m","--agent-command=sh -c"]}]}}}}
EOF
k -n blip-system patch deployment/blipchat --type=strategic \
	-p "$(cat "$work/blipchat-patch.json")" >/dev/null
k -n blip-system rollout status deployment/blipchat --timeout 2m

step "create the coordinator thread"
k apply -f - <<EOF
apiVersion: blip.dev/v1alpha1
kind: BlipThread
metadata:
  name: $P-thread
  namespace: default
spec:
  pool: default
  base: $P-base
  maxRunning: 1
  charter: |
    Run the e2e agent when the engineer asks. One task at a time.
EOF
wait_for 60 "thread $P-thread to be accepted" thread_exists_70

step "exercise chat through a port-forward"
chat_port_70=${BLIP_E2E_CHAT_PORT:-18080}
kubectl --context "$CONTEXT" -n blip-system port-forward \
	--address 127.0.0.1 svc/blipchat "$chat_port_70":80 >"$work/port-forward.log" 2>&1 &
pf_pid_70=$!
if ! wait_http "http://127.0.0.1:$chat_port_70/healthz" 120; then
	cat "$work/port-forward.log" >&2 || true
	exit 1
fi

curl -fsS --max-time 60 -X POST \
	-H 'Content-Type: application/json' \
	-H 'X-Forwarded-User: e2e@example.com' \
	--data "{\"thread\":\"$P-thread\",\"message\":\"please start the e2e agent\"}" \
	"http://127.0.0.1:$chat_port_70/chat?namespace=default" >"$work/chat.json"
grep -Eq '^\{"reply":"[^"]+"\}$' "$work/chat.json"
grep -q '"reply":"I sent that to the coordinator."' "$work/chat.json"

step "wait for the coordinator, the agent, and its reports"
wait_for "$T" "chat turn consumed (consumedSeq >= 1)" consumed_70
wait_for 60 "task t1 to open" task_is_open_70
wait_for "$T" "a finished blip for thread $P-thread" blip_finished_70
wait_for "$T" "blip.report turn" has_topic_70 blip.report
wait_for "$T" "blip.finished turn" has_topic_70 blip.finished
wait_for "$T" "task t1 to close" task_is_closed_70
wait_for "$T" "coordinator.reply turn" has_topic_70 coordinator.reply
wait_for 60 "chat turn authored by User" chat_user_turn_70

step "assert turn order and the scripted report"
wait_for 60 "all turns to be sequenced" all_sequenced_70
turns=$(turn_lines_70)
test -n "$turns"
printf '%s\n' "$turns" | awk '
	NF < 2 { exit 1 }
	$1 !~ /^[0-9]+$/ || $1 + 0 < 1 { exit 1 }
	seen[$1]++ { exit 1 }
'
chat_seq=$(printf '%s\n' "$turns" | awk '$2 == "chat.propose" { print $1; exit }')
report_seq=$(printf '%s\n' "$turns" | awk '$2 == "blip.report" { print $1; exit }')
reply_seq=$(printf '%s\n' "$turns" | awk '$2 == "coordinator.reply" { print $1; exit }')
test -n "$chat_seq"
test -n "$report_seq"
test -n "$reply_seq"
test "$chat_seq" -lt "$report_seq"
test "$report_seq" -lt "$reply_seq"
k -n default get blips -l "blip.dev/thread=$P-thread" \
	-o jsonpath='{range .items[*]}{.status.report.text}{"\n"}{end}' |
	grep 'agent done' >/dev/null

step "exercise the turn admission policy with a project service account"
k apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: $P-turner
  namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: $P-turner
  namespace: default
rules:
  - apiGroups: ["blip.dev"]
    resources: ["blipturns"]
    verbs: ["create", "get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: $P-turner
  namespace: default
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: $P-turner
subjects:
  - kind: ServiceAccount
    name: $P-turner
    namespace: default
EOF
token=$(k -n default create token "$P-turner" --duration=1h)
server=$(kubectl --context "$CONTEXT" config view --minify --raw \
	-o jsonpath='{.clusters[0].cluster.server}')
ca=$(kubectl --context "$CONTEXT" config view --minify --raw \
	-o jsonpath='{.clusters[0].cluster.certificate-authority-data}')
test -n "$server"
{
	printf 'apiVersion: v1\nkind: Config\n'
	printf 'clusters:\n- name: e2e\n  cluster:\n    server: %s\n' "$server"
	if [ -n "$ca" ]; then
		printf '    certificate-authority-data: %s\n' "$ca"
	else
		printf '    insecure-skip-tls-verify: true\n'
	fi
	printf 'users:\n- name: turner\n  user:\n    token: %s\n' "$token"
	printf 'contexts:\n- name: e2e\n  context:\n    cluster: e2e\n    user: turner\n'
	printf 'current-context: e2e\n'
} >"$work/turner.kubeconfig"

# The policy is independent of blipchat, so these turns name a thread that
# need not exist.
cat >"$work/turn-user.yaml" <<EOF
apiVersion: blip.dev/v1alpha1
kind: BlipTurn
metadata:
  name: $P-turner-user
  namespace: default
spec:
  thread: $P-turn-policy
  author:
    kind: User
    name: e2e@example.com
  topic: chat.propose
  text: a User-authored turn must be rejected
  wake: Batch
EOF
cat >"$work/turn-wrong.yaml" <<EOF
apiVersion: blip.dev/v1alpha1
kind: BlipTurn
metadata:
  name: $P-turner-wrong
  namespace: default
spec:
  thread: $P-turn-policy
  author:
    kind: ServiceAccount
    name: "system:serviceaccount:default:not-$P-turner"
  topic: chat.propose
  text: another service account must be rejected
  wake: Batch
EOF
cat >"$work/turn-ok.yaml" <<EOF
apiVersion: blip.dev/v1alpha1
kind: BlipTurn
metadata:
  name: $P-turner-ok
  namespace: default
spec:
  thread: $P-turn-policy
  author:
    kind: ServiceAccount
    name: "system:serviceaccount:default:$P-turner"
  topic: chat.propose
  text: the turner may name itself
  wake: Batch
EOF

expect_fail_grep "a User-authored turn" \
	"turns must be created by blipchat" \
	turner_70 create -f "$work/turn-user.yaml"
expect_fail_grep "a turn naming another service account" \
	"turns must be created by blipchat" \
	turner_70 create -f "$work/turn-wrong.yaml"
expect_ok_grep "a turn naming its own service account" \
	"created" turner_70 create -f "$work/turn-ok.yaml"
test "$(k -n default get blipturn "$P-turner-ok" \
	-o jsonpath='{.spec.author.kind}/{.spec.author.name}')" = \
	"ServiceAccount/system:serviceaccount:default:$P-turner"
k -n default delete blipturn "$P-turner-ok" --ignore-not-found --wait=false >/dev/null
