#!/usr/bin/env bash
# End-to-end tests against the kind cluster from hack/kind-up.sh. The Git
# fan-out runs the way users run it: from an SSH sandbox through the gateway,
# forking workers from the live sandbox and collecting their commits and files
# with `blip collect`. Host checks delete an execution and restore the same
# durable workspace under another name. A second user checks that the ownership
# policy keeps the two apart.
# Guest commands intentionally expand variables inside the VM.
# shellcheck disable=SC2016
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
	k delete blip --ignore-not-found "$P-hello" "$P-agent" "$P-resumed" >/dev/null 2>&1 || true
	k delete blipstate --ignore-not-found "$P-base" "$P-hello" "$P-workspace" "$P-data" >/dev/null 2>&1 || true
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
step "pull a template and fork a command workspace"
blip pull "$P-base" "$IMG"
blip run "$P-hello" --fork "$P-base" -- sh -c 'echo hello from $(hostname)'
k delete blip "$P-hello" >/dev/null
test "$(k get blipstate "$P-hello" -o jsonpath='{.spec.copyFrom}')" = "$P-base"
test -z "$(k get blipstate "$P-hello" -o jsonpath='{.metadata.ownerReferences}')"

step "configure a durable root with writable and read-only mounts"
blip create blipstate "$P-workspace" --from "$P-base"
blip create blipstate "$P-data" --size 1Gi
k patch blipstate "$P-workspace" --type merge -p "{
  \"spec\": {
    \"mounts\": [
      {\"state\": \"$P-data\", \"path\": \"/work\", \"writable\": true},
      {\"state\": \"$P-base\", \"path\": \"/opt/base\", \"writable\": false}
    ],
    \"runtime\": {
      \"env\": [{\"name\": \"DURABLE_WORKSPACE\", \"value\": \"kept\"}],
      \"workingDir\": \"/work\",
      \"user\": \"0:0\",
      \"idleTimeout\": \"10m\",
      \"network\": {}
    }
  }
}" >/dev/null
local root_uid data_uid root_commit data_commit config
root_uid=$(k get blipstate "$P-workspace" -o jsonpath='{.metadata.uid}')
data_uid=$(k get blipstate "$P-data" -o jsonpath='{.metadata.uid}')
root_commit=$(k get blipstate "$P-workspace" -o jsonpath='{.status.committed.id}')
data_commit=$(k get blipstate "$P-data" -o jsonpath='{.status.committed.id}')
config=$(k get blipstate "$P-workspace" -o jsonpath='{.spec.mounts}{.spec.runtime}')
blip run "$P-agent" --state "$P-workspace" -d
blip exec "$P-agent" -- sh -ec '
  test "$DURABLE_WORKSPACE" = kept
  test "$PWD" = /work
  test "$(id -u):$(id -g)" = 0:0
  echo root-kept > /root/kept.txt
  echo rw-kept > /work/kept.txt
  test -x /opt/base/bin/sh
  sync
'

step "delete the live execution; its root and auxiliary states remain"
k delete blip "$P-agent" >/dev/null
test "$(k get blipstate "$P-workspace" -o jsonpath='{.metadata.uid}')" = "$root_uid"
test "$(k get blipstate "$P-data" -o jsonpath='{.metadata.uid}')" = "$data_uid"
test "$(k get blipstate "$P-workspace" -o jsonpath='{.status.phase}')" = Ready
test "$(k get blipstate "$P-data" -o jsonpath='{.status.phase}')" = Ready
test "$(k get blipstate "$P-workspace" -o jsonpath='{.status.committed.id}')" != "$root_commit"
test "$(k get blipstate "$P-data" -o jsonpath='{.status.committed.id}')" != "$data_commit"
test "$(k get blipstate "$P-workspace" -o jsonpath='{.spec.mounts}{.spec.runtime}')" = "$config"

step "a differently named execution restores files, topology, and runtime defaults"
blip run "$P-resumed" --state "$P-workspace" -d
blip exec "$P-resumed" -- sh -ec '
  test "$(cat /root/kept.txt)" = root-kept
  test "$(cat /work/kept.txt)" = rw-kept
  test "$DURABLE_WORKSPACE" = kept
  test "$PWD" = /work
  test "$(id -u):$(id -g)" = 0:0
  test -x /opt/base/bin/sh
  awk '\''$2 == "/work" && $4 ~ /(^|,)rw(,|$)/ { found=1 } END { exit !found }'\'' /proc/mounts
  awk '\''$2 == "/opt/base" && $4 ~ /(^|,)ro(,|$)/ { found=1 } END { exit !found }'\'' /proc/mounts
  echo "root, RW data, RO mount, and runtime defaults restored"
'
test "$(k get blip "$P-resumed" -o jsonpath='{.spec.state}')" = "$P-workspace"
test "$(k get blip "$P-resumed" -o jsonpath='{.status.mounts[?(@.path=="/work")].state}')" = "$P-data"
test "$(k get blip "$P-resumed" -o jsonpath='{.status.mounts[?(@.path=="/opt/base")].state}')" = "$P-base"
test "$(k get blipstate "$P-workspace" -o jsonpath='{.status.writer.blipName}')" = "$P-resumed"
test "$(k get blipstate "$P-data" -o jsonpath='{.status.writer.blipName}')" = "$P-resumed"
test -z "$(k get blipstate "$P-base" -o jsonpath='{.status.writer}')"
k delete blip "$P-resumed" >/dev/null
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
	for ((i = 0; i < 60; i++)); do
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

step "$A: fork two workers from the default root state and collect their branches and files"
as "$A" <<'EOF'
cd ~/src
pids=
for i in 1 2; do
	(
		start=$(date +%s%N)
		echo "$start" > ~/start.w$i
		# The commit message records when the command started inside the worker.
		blip run w$i --fork default -w "$PWD" -- sh -c "t=\$(date +%s%N) && test \"\$(cat notes.txt)\" = uncommitted && git switch -qc w$i && ./task.sh $i && git add tasks.txt && git commit -qm \$t"
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
blip run bw --fork default -- true
EOF
echo "$B checks passed"
}
b_checks >"$tmp/b.log" 2>&1 &
bpid=$!

step "$A: fork a root with a writable auxiliary state"
as "$A" <<'EOF'
blip create blipstate repo --size 2Gi
blip mount repo default --path /work --write
sudo chown dev /work
mkdir /work/repo && cd /work/repo
git init -q && git config user.email a@example.com && git config user.name a
cp ~/src/task.sh . && git add task.sh && git commit -qm init
blip run w3 --fork default -w "$PWD" -- sh -c 'git switch -qc w3 && ./task.sh 3 && git add tasks.txt && git commit -qm w3'
blip collect w3 git:/work/repo:w3
test "$(git show w3:tasks.txt)" = "task 3"
test ! -e tasks.txt
cd / && blip unmount repo default
EOF

wait "$bpid" || { cat "$tmp/b.log"; exit 1; }
cat "$tmp/b.log"
k -n "$SSH_NS" get blip "$A.default" >/dev/null

step "deleting a worker preserves its forked root and writable auxiliary state"
worker_uid=$(k -n "$SSH_NS" get blipstate "$A.w3" -o jsonpath='{.metadata.uid}')
worker_repo=$(k -n "$SSH_NS" get blipstate "$A.w3" -o jsonpath='{.spec.mounts[?(@.path=="/work")].state}')
test -n "$worker_repo" && test "$worker_repo" != "$A.repo"
test "$(k -n "$SSH_NS" get blipstate "$worker_repo" -o jsonpath='{.spec.copyFrom}')" = "$A.repo"
repo_uid=$(k -n "$SSH_NS" get blipstate "$worker_repo" -o jsonpath='{.metadata.uid}')
k -n "$SSH_NS" delete blip "$A.w3" >/dev/null
test "$(k -n "$SSH_NS" get blipstate "$A.w3" -o jsonpath='{.metadata.uid}')" = "$worker_uid"
test "$(k -n "$SSH_NS" get blipstate "$worker_repo" -o jsonpath='{.metadata.uid}')" = "$repo_uid"
test -z "$(k -n "$SSH_NS" get blipstate "$A.w3" -o jsonpath='{.metadata.ownerReferences}')"
test -z "$(k -n "$SSH_NS" get blipstate "$worker_repo" -o jsonpath='{.metadata.ownerReferences}')"
as "$A" <<'EOF'
blip run w3-reused --state w3 -w /work/repo -- sh -ec '
  test "$(cat tasks.txt)" = "task 3"
  test "$(cat /home/dev/src/notes.txt)" = uncommitted
'
EOF

wait "$host" || { cat "$tmp/host.log"; exit 1; }
cat "$tmp/host.log"
echo "PASSED in $((SECONDS - t0))s"
passed=1
