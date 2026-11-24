# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# shellcheck shell=bash
# shellcheck disable=SC2016,SC2154
# CLI contracts: run labels and preflight, interrupted runs, stop by blip,
# list, and state, send with --eof and stdin, logs --offset/--state/-f, gather
# --wait expiry, pull --detach/--size/--image-pull-secret, and mount --new
# --replicas.

c15_blips=(label all1 all2 w eof pipe follow gwait int nopool off)
c15_states=("${c15_blips[@]}" st repl pd ps)

cleanup_15() {
	k delete blip --ignore-not-found --wait=false \
		"${c15_blips[@]/#/$P-cli-}" >/dev/null 2>&1 || true
	k delete blipstate --ignore-not-found --wait=false \
		"${c15_states[@]/#/$P-cli-}" >/dev/null 2>&1 || true
	k delete secret --ignore-not-found --wait=false "$P-cli-regcred" >/dev/null 2>&1 || true
}
cleanup_register cleanup_15

is_blip_stopped_15() {
	[ "$(blip_phase "$1")" = Succeeded ] &&
		[ "$(blip_field "$1" '{.status.reason}')" = Stopped ]
}

wait_blip_stopped_15() {
	wait_for "$T" "blip $1 to stop" is_blip_stopped_15 "$1" || {
		k get blip "$1" -o yaml >&2 || true
		return 1
	}
}

placements_15() { # STATE COUNT
	[ "$(k get blipstate "$1" -o jsonpath='{.status.placements[*]}' 2>/dev/null | wc -w)" -eq "$2" ]
}

state_or_blip_gone_15() {
	is_blip_gone "$1" && is_state_gone "$1"
}

step "run --label labels the blip and stop NAME stops it"
blip run --name "$P-cli-label" --from "$P-base" --label team=e2e-cli --label tier=t1 \
	-- sleep infinity >/dev/null
test "$(blip_field "$P-cli-label" '{.metadata.labels.team}')" = e2e-cli
test "$(blip_field "$P-cli-label" '{.metadata.labels.tier}')" = t1
wait_blip_phase "$P-cli-label" Running "$T"

step "gather --wait gives up while the blip is still running"
expect_fail_grep "gather --wait expiry" "still running" \
	blip gather "$P-cli-label" --wait 3s
test "$(blip_phase "$P-cli-label")" = Running

expect_ok_grep "stop by blip name" "blip/$P-cli-label stopped" blip stop "$P-cli-label"
test "$(blip_field "$P-cli-label" '{.spec.stop}')" = true
wait_blip_stopped_15 "$P-cli-label"
expect_fail_grep "stop a finished blip" "is not running" blip stop "$P-cli-label"

step "stop --all with names stops every listed blip"
# A bare --all stops every running blip in the namespace, which would hit
# other suites sharing the cluster, so this only checks --all with names.
blip run --name "$P-cli-all1" --from "$P-base" -- sleep infinity >/dev/null
blip run --name "$P-cli-all2" --from "$P-base" -- sleep infinity >/dev/null
wait_blip_phase "$P-cli-all1" Running "$T"
wait_blip_phase "$P-cli-all2" Running "$T"
blip stop --all "$P-cli-all1" "$P-cli-all2" >"$work/stop-all.out"
grep -q "blip/$P-cli-all1 stopped" "$work/stop-all.out"
grep -q "blip/$P-cli-all2 stopped" "$work/stop-all.out"
wait_blip_stopped_15 "$P-cli-all1"
wait_blip_stopped_15 "$P-cli-all2"

step "stop STATE stops the running blip of that state; logs --state reads it"
blip run --name "$P-cli-st" --from "$P-base" --keep -- true >/dev/null
wait_blip_phase "$P-cli-st" Succeeded "$T"
k delete blip "$P-cli-st" >/dev/null
wait_blip_gone "$P-cli-st" "$T"
wait_state "$P-cli-st" "$T"
blip run --name "$P-cli-w" --state "$P-cli-st" -- sh -c 'echo state-out; exec sleep infinity' >/dev/null
wait_blip_phase "$P-cli-w" Running "$T"
wait_for "$T" "state-out in $P-cli-st" \
	eval 'blip logs --state "default/$P-cli-st" --raw 2>/dev/null | grep -q state-out'
expect_ok_grep "stop by state" "blip/$P-cli-w stopped" blip stop "$P-cli-st"
wait_blip_stopped_15 "$P-cli-w"
expect_ok_grep "no running blip for the state" "no running blip for state" blip stop "$P-cli-st"
k delete blip "$P-cli-w" >/dev/null
wait_blip_gone "$P-cli-w" "$T"
wait_state "$P-cli-st" "$T"

step "send --eof closes stdin and send - copies local stdin"
blip run --name "$P-cli-eof" --from "$P-base" --interactive -- cat >/dev/null
wait_blip_phase "$P-cli-eof" Running "$T"
blip send "$P-cli-eof" --text $'eof-line\n'
wait_for "$T" "eof-line echoed" \
	eval 'blip logs "$P-cli-eof" --raw 2>/dev/null | grep -q eof-line'
test "$(blip_phase "$P-cli-eof")" = Running
blip send "$P-cli-eof" --eof
wait_blip_phase "$P-cli-eof" Succeeded "$T"
expect_ok_grep "eof blip output" "eof-line" blip logs "$P-cli-eof" --raw

blip run --name "$P-cli-pipe" --from "$P-base" --interactive -- cat >/dev/null
wait_blip_phase "$P-cli-pipe" Running "$T"
printf 'piped-1\npiped-2\n' | blip send "$P-cli-pipe" -
blip send "$P-cli-pipe" --eof
wait_blip_phase "$P-cli-pipe" Succeeded "$T"
expect_ok_grep "piped stdin" "piped-2" blip logs "$P-cli-pipe" --raw
grep -q piped-1 "$work/expect-ok.out"

step "logs -f follows until the blip exits"
blip run --name "$P-cli-follow" --from "$P-base" -- sh -c 'echo f1; sleep 5; echo f2; sleep 5; echo f3' >/dev/null
blip logs -f "$P-cli-follow" --raw >"$work/follow.out"
for line in f1 f2 f3; do
	grep -qx "$line" "$work/follow.out"
done
# -f returns at the command's end record; the blip finishes right after.
wait_blip_phase "$P-cli-follow" Succeeded "$T"

step "logs --offset starts at a record offset"
blip run --name "$P-cli-off" --from "$P-base" -- sh -c 'echo off-1; sleep 2; echo off-2 >&2' >/dev/null
wait_blip_phase "$P-cli-off" Succeeded "$T"
# Offsets are the record offsets the stream API reports; take the second
# record (the first after "start") and the stderr record.
k get --raw "/apis/stream.blip.dev/v1alpha1/namespaces/default/blipstreams/$P-cli-off/log" >"$work/off.ndjson"
c15_err_off=$(grep -m1 '"t":"err"' "$work/off.ndjson" | sed 's/.*"o":\([0-9]*\).*/\1/')
test -n "$c15_err_off"
blip logs "$P-cli-off" >"$work/off-all.out" 2>&1
grep -q off-1 "$work/off-all.out"
blip logs "$P-cli-off" --offset "$c15_err_off" >"$work/off.out" 2>&1
grep -q off-2 "$work/off.out"
if grep -q off-1 "$work/off.out"; then
	echo "logs --offset $c15_err_off still printed the first record" >&2
	exit 1
fi
expect_fail_grep "negative offset" "must not be negative" blip logs "$P-cli-off" --offset -1

step "run with a missing pool fails before creating anything"
expect_fail_grep "missing pool" "pool \"$P-cli-nopool\" not found" \
	blip run --name "$P-cli-nopool" --pool "$P-cli-nopool" --from "$P-base" -- true
is_blip_gone "$P-cli-nopool"
is_state_gone "$P-cli-nopool"

step "an interrupted run removes its blip and workspace"
bin/kubectl-blip --context "$CONTEXT" run --name "$P-cli-int" --from "$P-base" \
	-- sleep infinity >"$work/int.out" 2>&1 &
c15_pid=$!
wait_for "$T" "blip $P-cli-int to exist" eval '! is_blip_gone "$P-cli-int" || ! kill -0 $c15_pid 2>/dev/null'
kill -INT "$c15_pid" 2>/dev/null || true
c15_rc=0
wait "$c15_pid" || c15_rc=$?
if [ "$c15_rc" = 0 ]; then
	# run had already printed the name and returned; a returned run keeps
	# its blip by design, so there is nothing to check.
	echo "run returned before the interrupt; skipping cleanup check"
	k delete blip "$P-cli-int" --wait=false >/dev/null
else
	wait_for "$T" "interrupted blip and state to be removed" state_or_blip_gone_15 "$P-cli-int" || {
		cat "$work/int.out" >&2
		exit 1
	}
fi

step "pull --detach returns at once; --size is recorded"
expect_ok_grep "pull --detach" "blipstate/$P-cli-pd created" \
	blip pull --detach --size 3Gi "$P-cli-pd" "$IMG"
test "$(k get blipstate "$P-cli-pd" -o jsonpath='{.spec.size}')" = 3Gi
wait_state "$P-cli-pd" "$T"

step "pull --image-pull-secret records the secret and still imports"
k create secret docker-registry "$P-cli-regcred" \
	--docker-server=blip-registry:5000 --docker-username=e2e --docker-password=e2e >/dev/null
expect_ok_grep "pull with secret" "blipstate/$P-cli-ps Ready" \
	blip pull --image-pull-secret "$P-cli-regcred" "$P-cli-ps" "$IMG"
test "$(k get blipstate "$P-cli-ps" -o jsonpath='{.spec.imagePullSecrets[0].name}')" = "$P-cli-regcred"
expect_fail_grep "invalid secret name" "invalid --image-pull-secret" \
	blip pull --image-pull-secret Bad_Name "$P-cli-bad" "$IMG"

step "mount --new --replicas 2 places the new state on two nodes"
blip mount --new "$P-cli-repl:/repl:rw" --replicas 2 --root "$P-cli-st"
test "$(k get blipstate "$P-cli-repl" -o jsonpath='{.spec.replicas}')" = 2
wait_state "$P-cli-repl" "$T"
wait_for "$T" "two placements for $P-cli-repl" placements_15 "$P-cli-repl" 2 || {
	k get blipstate "$P-cli-repl" -o yaml >&2 || true
	exit 1
}
