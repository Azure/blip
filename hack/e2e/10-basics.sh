# shellcheck shell=bash
# shellcheck disable=SC2016,SC2154
# Core lifecycle: pull a base, run and gather a command, keep and resume a
# durable workspace, and fork concurrently from inside a blip.

cleanup_10() {
	k delete blip --ignore-not-found --wait=false \
		"$P-hello" "$P-agent" "$P-resumed" "$P-collector" \
		"$P-w1" "$P-w2" "$P-slow" "$P-stopped" >/dev/null 2>&1 || true
	# The driver owns the shared base and removes it after the last scenario.
	k delete blipstate --ignore-not-found --wait=false \
		"$P-hello" "$P-workspace" "$P-data" "$P-collector" \
		"$P-w1" "$P-w2" "$P-slow" "$P-stopped" >/dev/null 2>&1 || true
}
cleanup_register cleanup_10

step "use the shared template"
ensure_base

step "run a command, then gather its exit code and free its workspace"
out=$(blip run --name "$P-hello" --from "$P-base" -- sh -c 'echo hello from $(hostname); exit 7')
test "$out" = "$P-hello"
test "$(k get blipstate "$P-hello" -o jsonpath='{.metadata.ownerReferences[0].kind}')" = Blip
test "$(k get blipstate "$P-hello" -o jsonpath='{.status.committed.id}')" != ""
if blip gather "$P-hello" >"$work/gather.out" 2>&1; then
	echo "expected gather to report a failed command"
	exit 1
fi
grep -q 'Failed (exit 7)' "$work/gather.out"
# A failed command keeps its blip for inspection; release it before checking
# that its workspace is garbage collected.
k delete blip "$P-hello" >/dev/null
wait_blip_gone "$P-hello"
wait_state_gone "$P-hello"

step "create a durable workspace that outlives its execution"
test "$(blip run --name "$P-workspace" --from "$P-base" --keep -- sleep infinity)" = "$P-workspace"
k delete blip "$P-workspace" >/dev/null
wait_state "$P-workspace"
blip mount --new "$P-data:/work:rw" --size 1Gi --root "$P-workspace"
blip mount "$P-base:/opt/base:ro" --root "$P-workspace"
blip mount --root "$P-workspace" | grep -q "$P-data:/work (writable)"
k patch blipstate "$P-workspace" --type merge -p "{
  \"spec\": {
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

step "run the workspace, then delete the execution; its states remain"
blip run --name "$P-agent" --state "$P-workspace" -- sleep infinity
blip run --from "$P-agent" -- sh -ec '
  test "$DURABLE_WORKSPACE" = kept
  test "$PWD" = /work
  test "$(id -u):$(id -g)" = 0:0
  echo root-kept > /root/kept.txt
  echo rw-kept > /work/kept.txt
  test -x /opt/base/bin/sh
  sync
'
k delete blip "$P-agent" >/dev/null
wait_state "$P-workspace"
wait_state "$P-data"
test "$(k get blipstate "$P-workspace" -o jsonpath='{.metadata.uid}')" = "$root_uid"
test "$(k get blipstate "$P-data" -o jsonpath='{.metadata.uid}')" = "$data_uid"
test "$(k get blipstate "$P-workspace" -o jsonpath='{.status.committed.id}')" != "$root_commit"
test "$(k get blipstate "$P-data" -o jsonpath='{.status.committed.id}')" != "$data_commit"
test "$(k get blipstate "$P-workspace" -o jsonpath='{.spec.mounts}{.spec.runtime}')" = "$config"

step "a differently named execution restores files, topology, and runtime defaults"
blip run --name "$P-resumed" --state "$P-workspace" -- sleep infinity
blip run --from "$P-resumed" -- sh -ec '
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
test "$(blip_field "$P-resumed" '{.spec.state}')" = "$P-workspace"
test "$(blip_field "$P-resumed" '{.status.mounts[?(@.path=="/work")].state}')" = "$P-data"
test "$(blip_field "$P-resumed" '{.status.mounts[?(@.path=="/opt/base")].state}')" = "$P-base"
test "$(k get blipstate "$P-workspace" -o jsonpath='{.status.writer.blipName}')" = "$P-resumed"
test "$(k get blipstate "$P-data" -o jsonpath='{.status.writer.blipName}')" = "$P-resumed"
test -z "$(k get blipstate "$P-base" -o jsonpath='{.status.writer}')"
k delete blip "$P-resumed" >/dev/null
wait_state "$P-workspace"

step "fork concurrently inside a blip and gather branches, files, and logs"
blip run --name "$P-collector" --from "$P-base" -- sleep infinity
blip run --from "$P-collector" -e FORK_MAX="$FORK_MAX" -e W="$P" -- bash -ec '
  set -euo pipefail
  git config --global user.email a@example.com
  git config --global user.name a
  rm -rf ~/src && mkdir ~/src && cd ~/src && git init -q -b main
  printf "#!/bin/sh\necho \"task \$1\" >> tasks.txt\n" > task.sh && chmod +x task.sh
  head -c 1G /dev/urandom > big.bin
  git -c core.compression=0 add -A && git commit -qm init
  echo uncommitted > notes.txt
  # run returns once the fork is snapshotted; the command itself keeps going.
  declare -A start=()
  for i in 1 2; do
    start[$i]=$(date +%s%N)
    blip run --name "$W-w$i" --from / -w "$PWD" -- sh -c "t=\$(date +%s%N) && test \"\$(cat notes.txt)\" = uncommitted && git switch -qc w$i && ./task.sh $i && git add tasks.txt && git commit -qm \$t"
  done
  # A follower sees the output of a command that is still running.
  blip run --name "$W-slow" --from / -w "$PWD" -- sh -c "sleep 2; echo slow-output"
  blip gather "$W-slow" -f > slow.log
  grep -q "slow-output" slow.log
  # A server-side deadline stops a fork nobody waits for forever.
  blip run --name "$W-stopped" --timeout 2s --from / -w "$PWD" -- sh -c "git switch -qc stopped && sleep 100"
  blip gather "$W-stopped" --collect "git:$PWD:stopped" > stopped.out
  grep -q "DeadlineExceeded" stopped.out
  # Gather waits for the workers, fetches each branch, and deletes each blip
  # with its workspace.
  blip gather "$W-w1" --collect "git:$PWD:w1" --collect "$PWD/tasks.txt:./tasks.w1.txt" \
    --collect "$PWD/task.sh:./collected/task.sh"
  blip gather "$W-w2" --collect "git:$PWD:w2"
  for i in 1 2; do
    test "$(git show w$i:tasks.txt)" = "task $i"
    ms=$((($(git log -1 --format=%s w$i) - ${start[$i]}) / 1000000))
    echo "fork w$i: command started after ${ms}ms"
    [ "$ms" -le $((FORK_MAX * 1000)) ] || { echo "fork w$i took longer than ${FORK_MAX}s"; exit 1; }
  done
  test ! -e tasks.txt
  # Collect created its own untracked files here; assert the tracked tree is
  # clean and the one intended uncommitted file is still present.
  test -z "$(git status --porcelain --untracked-files=no)"
  test "$(git status --porcelain -- notes.txt)" = "?? notes.txt"
  test "$(cat tasks.w1.txt)" = "task 1"
  test -x collected/task.sh
  rm -rf tasks.w1.txt collected slow.log stopped.out
  git log --oneline --all
  if blip gather "$W-w9" --collect "git:$PWD:w9" 2>/dev/null; then echo "gather of a missing worker succeeded"; exit 1; fi
'
k delete blip "$P-collector" >/dev/null
# The workers were deleted by gather, and their owned states go with them.
for w in w1 w2 slow stopped; do
	wait_state_gone "$P-$w"
done
