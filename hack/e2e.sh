#!/usr/bin/env bash
# End-to-end tests against the kind cluster from hack/kind-up.sh. The Git
# fan-out runs the way users run it: from an SSH sandbox through the gateway,
# forking workers from the live sandbox and collecting their commits and files
# with `blip collect`. A second user checks that the ownership policy keeps
# the two apart.
set -euo pipefail
cd "$(dirname "$0")/.."

CONTEXT=${BLIP_CONTEXT:-kind-blip-dev}
IMG=${BLIP_IMAGE:-blip-registry:5000/blip/dev:latest}
P=${BLIP_E2E_PREFIX:-e2e}
FORK_MAX=${BLIP_E2E_FORK_MAX:-20}
# Limit for any single command or sandbox script, in seconds.
T=${BLIP_E2E_TIMEOUT:-180}
A=${P}a
B=${P}b
SSH_NS=blip-ssh
blip() { timeout "$T" bin/kubectl-blip --context "$CONTEXT" "$@"; }
k() { timeout "$T" kubectl --context "$CONTEXT" "$@"; }
t0=$SECONDS
step() { printf '\n== [%3ds] %s\n' "$((SECONDS - t0))" "$*"; }

tmp=$(mktemp -d "${TMPDIR:-/tmp}/blip-e2e.XXXXXX")
ip=$(k get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
# as USER [VAR=VALUE...] runs a bash script from stdin in USER's default
# sandbox, with the variables set.
as() {
	local user=$1
	shift
	{
		printf '%q ' export "$@" FORK_MAX="$FORK_MAX" SSH_NS="$SSH_NS"
		printf '\nset -euo pipefail\n'
		cat
	} | timeout "$T" ssh -i "$tmp/$user" -p 30022 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
		-o LogLevel=ERROR -o BatchMode=yes "default@$ip" bash -s
}

cleanup() {
	k delete blip --ignore-not-found "$P-hello" "$P-agent" >/dev/null 2>&1 || true
	k delete blipstate --ignore-not-found "$P-agent" >/dev/null 2>&1 || true
	for o in "$A" "$B"; do
		k -n "$SSH_NS" delete blip -l "blip.dev/owner=$o" --wait=false >/dev/null 2>&1 || true
		k -n "$SSH_NS" delete blipstate -l "blip.dev/owner=$o" --wait=false >/dev/null 2>&1 || true
	done
	k -n "$SSH_NS" patch configmap blip-ssh-users --type merge \
		-p "{\"data\":{\"$A\":null,\"$B\":null}}" >/dev/null 2>&1 || true
}
cleanup
k -n "$SSH_NS" wait --for=delete blip,blipstate -l "blip.dev/owner in ($A,$B)" --timeout "${T}s" >/dev/null 2>&1 || true
trap 'echo FAILED' ERR
trap 'kill $(jobs -p) 2>/dev/null || true; pkill -f "ssh -i $tmp/" || true; [ -n "${passed:-}" ] || tail -n 30 "$tmp"/*.log 2>/dev/null || true; cleanup; rm -rf "$tmp"' EXIT

# The host-side checks use the default namespace's pool; they run alongside
# the SSH flows below and their output is printed at the end.
host_checks() {
step "ephemeral command"
blip run "$P-hello" --image "$IMG" -- sh -c 'echo hello from $(hostname)'
k delete blip "$P-hello" >/dev/null

step "a durable root survives a restart"
blip create blipstate "$P-agent" --image "$IMG"
blip run "$P-agent" --state "$P-agent" -d
blip exec "$P-agent" -- sh -c 'mkdir -p ~/kept'
k patch blip "$P-agent" --type merge -p '{"spec":{"stop":true}}' >/dev/null
blip wait "$P-agent"
k delete blip "$P-agent" >/dev/null
blip run "$P-agent" --state "$P-agent" -- sh -c 'test -d ~/kept && echo root state kept'
echo "host checks passed"
}
host_checks >"$tmp/host.log" 2>&1 &
host=$!

step "register SSH users $A and $B"
for u in "$A" "$B"; do
	ssh-keygen -q -t ed25519 -N '' -C "$u" -f "$tmp/$u"
	k -n "$SSH_NS" patch configmap blip-ssh-users --type merge \
		-p "{\"data\":{\"$u\":\"$(cat "$tmp/$u.pub")\"}}" >/dev/null
done
# Both sandboxes start in parallel.
ready() {
	local i
	for i in $(seq 60); do
		as "$1" </dev/null >/dev/null 2>&1 && return
		sleep 2
	done
	echo "cannot ssh as $1"
	return 1
}
ready "$A" &
pa=$!
ready "$B"
wait "$pa"

step "$A: a repository with a 1GiB file, uncommitted work, and a running process"
as "$A" <<'EOF'
git config --global user.email a@example.com
git config --global user.name a
rm -rf ~/src && mkdir ~/src && cd ~/src && git init -q -b main
printf '#!/bin/sh\necho "task $1" >> tasks.txt\n' > task.sh && chmod +x task.sh
head -c 1G /dev/urandom > big.bin
git -c core.compression=0 add -A && git commit -qm init
echo uncommitted > notes.txt
setsid sleep 100000 </dev/null >/dev/null 2>&1 &
echo $! > ~/sleeper
EOF

step "$A: fork two workers from / and collect their branches and files"
as "$A" <<'EOF'
cd ~/src
pids=
for i in 1 2; do
	(
		start=$(date +%s%N)
		echo "$start" > ~/start.w$i
		# The commit message records when the command started inside the worker.
		blip run w$i --fork / -- sh -c "t=\$(date +%s%N) && test \"\$(cat notes.txt)\" = uncommitted && git switch -qc w$i && ./task.sh $i && git add tasks.txt && git commit -qm \$t"
		echo "w$i done after $((($(date +%s%N) - start) / 1000000))ms (including save)"
	) &
	pids="$pids $!"
done
for p in $pids; do wait "$p"; done
for i in 1 2; do
	blip collect w$i "git:$PWD:w$i"
	test "$(git show w$i:tasks.txt)" = "task $i"
	ms=$((($(git log -1 --format=%s w$i) - $(cat ~/start.w$i)) / 1000000))
	rm ~/start.w$i
	echo "fork w$i: command started after ${ms}ms"
	[ "$ms" -le $((FORK_MAX * 1000)) ] || { echo "fork w$i took longer than ${FORK_MAX}s"; exit 1; }
done
test ! -e tasks.txt
test "$(git status --porcelain)" = "?? notes.txt"
# Collect a file and a directory out of a worker's state.
blip collect w1 "$PWD/tasks.txt:./tasks.w1.txt"
test "$(cat tasks.w1.txt)" = "task 1"
mkdir -p collected
blip collect w1 "$PWD/task.sh:./collected/task.sh"
test -x collected/task.sh
rm -rf tasks.w1.txt collected
git log --oneline --all
kill -0 "$(cat ~/sleeper)"
touch ~/thawed && rm ~/thawed
if blip collect w9 "git:$PWD:w9" 2>/dev/null; then echo "collect from a missing worker succeeded"; exit 1; fi
EOF

b_checks() {
step "$B: cannot reach $A's blips"
apod=$(k -n "$SSH_NS" get blip "$A.default" -o jsonpath='{.status.pod}')
as "$B" "APOD=$apod" "A=$A" "B=$B" <<'EOF'
test ! -e /var/run/secrets/kubernetes.io/serviceaccount/token
test "$KUBECONFIG" = /run/blip/kubeconfig
test "$(cat /run/blip/namespace)" = "$SSH_NS"
api() {
	local method=$1 path=$2
	shift 2
	curl -sS -o /tmp/api.out -w '%{http_code}' -X "$method" \
		-H 'Content-Type: application/json' "http://127.0.0.1:8001$path" "$@"
}
denied() {
	local code
	code=$(api "$@")
	case $code in
	403) echo "denied: $1 $2" ;;
	*) echo "expected denial, got $code: $1 $2"; cat /tmp/api.out; exit 1 ;;
	esac
}
states=/apis/blip.dev/v1alpha1/namespaces/$SSH_NS/blipstates
denied POST "$states" -d "{\"apiVersion\":\"blip.dev/v1alpha1\",\"kind\":\"BlipState\",\"metadata\":{\"name\":\"$B.steal\",\"labels\":{\"blip.dev/owner\":\"$B\"}},\"spec\":{\"copyFrom\":\"$A.default\"}}"
denied POST "$states" -d "{\"apiVersion\":\"blip.dev/v1alpha1\",\"kind\":\"BlipState\",\"metadata\":{\"name\":\"$A.planted\",\"labels\":{\"blip.dev/owner\":\"$A\"}},\"spec\":{\"size\":\"1Gi\"}}"
denied DELETE "/apis/blip.dev/v1alpha1/namespaces/$SSH_NS/blips/$A.default"
denied POST "/api/v1/namespaces/$SSH_NS/pods/$APOD/exec?command=true&stdout=true"
if blip collect w1 "git:$PWD:w1" 2>/dev/null; then echo "$B collected $A's worker"; exit 1; fi
blip run bw --fork / -- true
EOF
echo "$B checks passed"
}
b_checks >"$tmp/b.log" 2>&1 &
bpid=$!

step "$A: create and fork a mounted state"
as "$A" <<'EOF'
blip create blipstate repo --size 2Gi
blip mount repo --path /work --write
sudo chown dev /work
mkdir /work/repo && cd /work/repo
git init -q && git config user.email a@example.com && git config user.name a
cp ~/src/task.sh . && git add task.sh && git commit -qm init
blip run w3 --fork /work -- sh -c 'git switch -qc w3 && ./task.sh 3 && git add tasks.txt && git commit -qm w3'
blip collect w3 git:/work/repo:w3
test "$(git show w3:tasks.txt)" = "task 3"
cd / && blip unmount repo
EOF

wait "$bpid" || { cat "$tmp/b.log"; exit 1; }
cat "$tmp/b.log"
k -n "$SSH_NS" get blip "$A.default" >/dev/null

step "deleting a worker deletes its forked state"
k -n "$SSH_NS" delete blip "$A.w1" >/dev/null
for i in $(seq 60); do
	k -n "$SSH_NS" get blipstate "$A.w1" >/dev/null 2>&1 || break
	[ "$i" = 60 ] && { echo "state $A.w1 was not deleted"; exit 1; }
	sleep 2
done

wait "$host" || { cat "$tmp/host.log"; exit 1; }
cat "$tmp/host.log"
echo "PASSED in $((SECONDS - t0))s"
passed=1
