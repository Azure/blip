#!/usr/bin/env bash
# End-to-end tests against the kind cluster from hack/kind-up.sh. Everything
# runs from the host through the CLI in the default namespace: pull and fork, a
# plain command with exit-code propagation, a durable workspace whose files and
# mount topology survive deletion of its execution, and collection of commits
# and files from forked workers.
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
blip() { timeout "$T" bin/kubectl-blip --context "$CONTEXT" "$@"; }
k() { timeout "$T" kubectl --context "$CONTEXT" "$@"; }
t0=$SECONDS
step() { printf '\n== [%3ds] %s\n' "$((SECONDS - t0))" "$*"; }

# Background `blip run` processes. They stream the primary command, so an
# exec-style check starts a long-running command instead of detaching.
pids=()
pid=
cleanup() {
	local p
	for p in "${pids[@]:-}"; do
		[ -n "$p" ] || continue
		kill "$p" 2>/dev/null || true
		wait "$p" 2>/dev/null || true
	done
	k delete blip --ignore-not-found --timeout="${T}s" \
		"$P-hello" "$P-agent" "$P-resumed" "$P-collector" "$P-w1" "$P-w2" >/dev/null 2>&1 || true
	k delete blipstate --ignore-not-found --timeout="${T}s" \
		"$P-base" "$P-hello" "$P-workspace" "$P-data" "$P-collector" "$P-w1" "$P-w2" >/dev/null 2>&1 || true
}
stop_run() {
	[ -n "${pid:-}" ] || return 0
	kill "$pid" 2>/dev/null || true
	wait "$pid" 2>/dev/null || true
	pid=
}

cleanup
trap 'echo FAILED' ERR
trap 'stop_run; cleanup' EXIT

wait_running() {
	local name=$1 i
	for ((i = 0; i < 120; i++)); do
		if [ "$(k get blip "$name" -o jsonpath='{.status.phase}' 2>/dev/null)" = Running ] &&
			[ -n "$(k get blip "$name" -o jsonpath='{.status.pod}' 2>/dev/null)" ]; then
			return 0
		fi
		sleep 1
	done
	echo "blip $name did not start"
	k get blip "$name" -o yaml >&2 || true
	return 1
}

wait_state() {
	local name=$1 i
	for ((i = 0; i < 120; i++)); do
		[ "$(k get blipstate "$name" -o jsonpath='{.status.phase}' 2>/dev/null)" = Ready ] && return 0
		sleep 1
	done
	echo "state $name did not become Ready"
	k get blipstate "$name" -o yaml >&2 || true
	return 1
}

step "pull a template and fork it for a plain command"
blip pull "$P-base" "$IMG"
if out=$(blip run "$P-hello" --fork "$P-base" -- sh -c 'echo hello from $(hostname); exit 7' 2>&1); then
	echo "expected the command to fail"
	exit 1
else
	code=$?
fi
test "$code" -eq 7
grep -q '^hello from ' <<<"$out"
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
      \"network\": {}
    }
  }
}" >/dev/null
root_uid=$(k get blipstate "$P-workspace" -o jsonpath='{.metadata.uid}')
data_uid=$(k get blipstate "$P-data" -o jsonpath='{.metadata.uid}')
root_commit=$(k get blipstate "$P-workspace" -o jsonpath='{.status.committed.id}')
data_commit=$(k get blipstate "$P-data" -o jsonpath='{.status.committed.id}')
config=$(k get blipstate "$P-workspace" -o jsonpath='{.spec.mounts}{.spec.runtime}')
blip run "$P-agent" --state "$P-workspace" -- sleep infinity &
pid=$!
pids+=("$pid")
wait_running "$P-agent"
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
stop_run
wait_state "$P-workspace"
wait_state "$P-data"
test "$(k get blipstate "$P-workspace" -o jsonpath='{.metadata.uid}')" = "$root_uid"
test "$(k get blipstate "$P-data" -o jsonpath='{.metadata.uid}')" = "$data_uid"
test "$(k get blipstate "$P-workspace" -o jsonpath='{.status.committed.id}')" != "$root_commit"
test "$(k get blipstate "$P-data" -o jsonpath='{.status.committed.id}')" != "$data_commit"
test "$(k get blipstate "$P-workspace" -o jsonpath='{.spec.mounts}{.spec.runtime}')" = "$config"

step "a differently named execution restores files, topology, and runtime defaults"
blip run "$P-resumed" --state "$P-workspace" -- sleep infinity &
pid=$!
pids+=("$pid")
wait_running "$P-resumed"
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
stop_run
wait_state "$P-workspace"

step "fork workers from a long-running collector and collect their branches and files"
blip run "$P-collector" --fork "$P-base" -- sleep infinity &
pid=$!
pids+=("$pid")
wait_running "$P-collector"
blip exec "$P-collector" -e FORK_MAX="$FORK_MAX" -e W="$P" -- bash -ec '
  set -euo pipefail
  git config --global user.email a@example.com
  git config --global user.name a
  rm -rf ~/src && mkdir ~/src && cd ~/src && git init -q -b main
  printf "#!/bin/sh\necho \"task \$1\" >> tasks.txt\n" > task.sh && chmod +x task.sh
  head -c 1G /dev/urandom > big.bin
  git -c core.compression=0 add -A && git commit -qm init
  echo uncommitted > notes.txt
  setsid sleep 100000 </dev/null >/dev/null 2>&1 &
  echo $! > ~/sleeper
  workers=
  for i in 1 2; do
    (
      start=$(date +%s%N)
      echo "$start" > ~/start.w$i
      # The commit message records when the command started inside the worker.
      blip run "$W-w$i" --fork / -w "$PWD" -- sh -c "t=\$(date +%s%N) && test \"\$(cat notes.txt)\" = uncommitted && git switch -qc w$i && ./task.sh $i && git add tasks.txt && git commit -qm \$t"
      echo "$W-w$i done after $((($(date +%s%N) - start) / 1000000))ms (including save)"
    ) &
    workers="$workers $!"
  done
  for p in $workers; do wait "$p"; done
  for i in 1 2; do
    blip collect "$W-w$i" "git:$PWD:w$i"
    test "$(git show w$i:tasks.txt)" = "task $i"
    ms=$((($(git log -1 --format=%s w$i) - $(cat ~/start.w$i)) / 1000000))
    rm ~/start.w$i
    echo "fork $W-w$i: command started after ${ms}ms"
    [ "$ms" -le $((FORK_MAX * 1000)) ] || { echo "fork $W-w$i took longer than ${FORK_MAX}s"; exit 1; }
  done
  test ! -e tasks.txt
  test "$(git status --porcelain)" = "?? notes.txt"
  # Collect a file and a directory out of a worker state.
  blip collect "$W-w1" "$PWD/tasks.txt:./tasks.w1.txt"
  test "$(cat tasks.w1.txt)" = "task 1"
  mkdir -p collected
  blip collect "$W-w1" "$PWD/task.sh:./collected/task.sh"
  test -x collected/task.sh
  rm -rf tasks.w1.txt collected
  git log --oneline --all
  kill -0 "$(cat ~/sleeper)"
  if blip collect "$W-w9" "git:$PWD:w9" 2>/dev/null; then echo "collect from a missing worker succeeded"; exit 1; fi
'
k delete blip "$P-collector" >/dev/null
stop_run
# Finished executions are kept for their status and garbage-collected later.
k wait --for=jsonpath='{.status.phase}'=Succeeded --timeout "${T}s" blip "$P-w1" "$P-w2" >/dev/null

echo "PASSED in $((SECONDS - t0))s"
