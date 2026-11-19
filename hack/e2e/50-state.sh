# shellcheck shell=bash
# shellcheck disable=SC2154 # $work and the scenario environment come from hack/e2e.sh.
# Durable state semantics: single-writer serialization, writable mount
# conflicts, deletion finalizers, gather selection modes, TTL cleanup, and
# graceful stop.

cleanup_50() {
	k delete blip --ignore-not-found --wait=false \
		"$P-sw1" "$P-sw2" "$P-r1w" "$P-r2w" "$P-delw" \
		"$P-gfast" "$P-gslow" "$P-gkeep" "$P-gparent" "$P-gchild1" \
		"$P-gchild2" "$P-gfail" "$P-ttl" "$P-stopw" "$P-stopc" >/dev/null 2>&1 || true
	k delete blipstate --ignore-not-found --wait=false \
		"$P-sroot" "$P-r1" "$P-r2" "$P-shared" "$P-stop" \
		"$P-gfast" "$P-gslow" "$P-gkeep" "$P-gparent" "$P-gchild1" \
		"$P-gchild2" "$P-gfail" "$P-ttl" >/dev/null 2>&1 || true
	if [ "${created_base_50:-0}" = 1 ]; then
		k delete blipstate --ignore-not-found --wait=false "$P-base" >/dev/null 2>&1 || true
	fi
}
cleanup_register cleanup_50

# Set when this scenario had to pull the shared base itself, so it can remove
# it without deleting a base another scenario owns.
created_base_50=0

is_blip_busy_50() {
	[ "$(blip_phase "$1")" = Pending ] &&
		[ "$(blip_field "$1" '{.status.reason}')" = StateBusy ]
}

is_blip_finished_or_gone_50() {
	local name=$1 phase
	k get blip "$name" >/dev/null 2>&1 || return 0
	phase=$(blip_phase "$name" || true)
	[ "$phase" = Succeeded ] || [ "$phase" = Failed ]
}

is_state_writer_50() {
	[ "$(k get blipstate "$1" -o jsonpath='{.status.writer.blipName}' 2>/dev/null)" = "$2" ]
}

is_state_deleting_50() {
	[ -n "$(k get blipstate "$1" -o jsonpath='{.metadata.deletionTimestamp}' 2>/dev/null)" ]
}

is_state_message_50() {
	k get blipstate "$1" -o jsonpath='{.status.message}' 2>/dev/null | grep -q -- "$2"
}

wait_blip_busy_50() {
	wait_for 60 "blip $1 to be Pending/StateBusy" is_blip_busy_50 "$1" || {
		k get blip "$1" -o yaml >&2 || true
		return 1
	}
}

wait_state_writer_50() {
	local state=$1 owner=$2 timeout=${3:-120}
	wait_for "$timeout" "state $state writer $owner" is_state_writer_50 "$state" "$owner" || {
		k get blipstate "$state" -o yaml >&2 || true
		return 1
	}
}

# new_root_50 produces a durable, Ready root filesystem named $1 by forking
# the base and then deleting the execution that created it.
new_root_50() {
	local name=$1
	blip run --name "$name" --from "$P-base" --keep -- sleep infinity >/dev/null
	k delete blip "$name" >/dev/null
	wait_state "$name"
}

step "ensure a base image for state scenarios"
if k get blipstate "$P-base" >/dev/null 2>&1; then
	wait_state "$P-base"
else
	blip pull "$P-base" "$IMG"
	created_base_50=1
fi

step "serialize two writers of one durable root"
new_root_50 "$P-sroot"
out=$(blip run --name "$P-sw1" --state "$P-sroot" -- sleep 10)
test "$out" = "$P-sw1"
wait_blip_phase "$P-sw1" Running
wait_state_writer_50 "$P-sroot" "$P-sw1"
test "$(blip_field "$P-sw1" '{.spec.state}')" = "$P-sroot"

step "the second writer waits as StateBusy, then runs after the first saves"
out=$(blip run --name "$P-sw2" --state "$P-sroot" -- sh -c 'echo second')
test "$out" = "$P-sw2"
wait_blip_busy_50 "$P-sw2"
wait_blip_phase "$P-sw1" Succeeded 120
wait_blip_phase "$P-sw2" Succeeded 180
test "$(blip_field "$P-sw2" '{.status.exitCode}')" = 0
blip gather "$P-sw1" "$P-sw2"
wait_state "$P-sroot" 120

step "reject a writable mount held by another running root"
new_root_50 "$P-r1"
new_root_50 "$P-r2"
blip mount --new "$P-shared:/shared:rw" --size 1Gi --root "$P-r1"
expect_ok_grep "writable aux is listed" "$P-shared:/shared (writable)" blip mount --root "$P-r1"
blip run --name "$P-r1w" --state "$P-r1" -- sleep infinity
wait_blip_phase "$P-r1w" Running
wait_state_writer_50 "$P-r1" "$P-r1w"
wait_state_writer_50 "$P-shared" "$P-r1w"
blip run --name "$P-r2w" --state "$P-r2" -- sleep infinity
wait_blip_phase "$P-r2w" Running
expect_fail_grep "writable mount conflict" "in use by blip" \
	blip mount "$P-shared:/shared:rw" --root "$P-r2"
test "$(k get blipstate "$P-r2" -o jsonpath="{.spec.mounts[?(@.state==\"$P-shared\")].path}")" = /shared
test "$(k get blipstate "$P-r2" -o jsonpath="{.spec.mounts[?(@.state==\"$P-shared\")].writable}")" = true

step "stop the two roots and detach the rejected desired mount"
k delete blip "$P-r2w" >/dev/null
k delete blip "$P-r1w" >/dev/null
wait_blip_gone "$P-r2w" 60
wait_blip_gone "$P-r1w" 60
wait_state "$P-r2" 120
wait_state "$P-r1" 120
wait_state "$P-shared" 120
blip mount --rm "$P-shared" --root "$P-r2"
blip mount --rm "$P-shared" --root "$P-r1"

step "a deleted state waits for its writer, then disappears"
blip run --name "$P-delw" --state "$P-sroot" -- sleep 60
wait_blip_phase "$P-delw" Running
wait_state_writer_50 "$P-sroot" "$P-delw"
k delete blipstate "$P-sroot" --wait=false >/dev/null
wait_for 60 "state $P-sroot deletion timestamp" is_state_deleting_50 "$P-sroot" || {
	k get blipstate "$P-sroot" -o yaml >&2 || true
	false
}
test "$(k get blipstate "$P-sroot" -o jsonpath='{.status.writer.blipName}')" = "$P-delw"
wait_for 60 "deleting state to name its writer" is_state_message_50 "$P-sroot" "writer $P-delw" || {
	k get blipstate "$P-sroot" -o yaml >&2 || true
	false
}
k delete blip "$P-delw" >/dev/null
wait_state_gone "$P-sroot" 120
wait_blip_gone "$P-delw" 60
# The copy branch of the finalizer is not raced here: a copy of these test
# states commits in about the same time as a shell can observe it Pending and
# delete the source, so a failure would not distinguish a broken finalizer
# from losing the race. TestCopyCommitEnqueuesSource covers the copy-release
# path in the controller unit tests.

step "gather --any returns after one blip and leaves the other"
blip run --name "$P-gfast" --from "$P-base" --label "team=$P" -- true
blip run --name "$P-gslow" --from "$P-base" --label "team=$P" -- sleep 30
blip gather -l "team=$P" --any --wait 1m >"$work/gather-any.out"
grep -q "blip/$P-gfast Succeeded" "$work/gather-any.out"
k get blip "$P-gslow" >/dev/null
if is_blip_finished_or_gone_50 "$P-gslow"; then
	echo "gather --any returned only after the slow blip finished"
	k get blip "$P-gslow" -o yaml >&2 || true
	exit 1
fi
k delete blip "$P-gslow" >/dev/null
wait_blip_gone "$P-gfast" 60
wait_state_gone "$P-gfast" 60
wait_blip_gone "$P-gslow" 60
wait_state_gone "$P-gslow" 60

step "gather --keep retains a finished blip for inspection"
blip run --name "$P-gkeep" --from "$P-base" -- sh -c 'sleep 2; echo kept'
blip gather "$P-gkeep" --wait 1m --keep >"$work/gather-keep.out"
grep -q "blip/$P-gkeep Succeeded" "$work/gather-keep.out"
k get blip "$P-gkeep" >/dev/null
k delete blip "$P-gkeep" >/dev/null
wait_blip_gone "$P-gkeep" 60
wait_state_gone "$P-gkeep" 60

step "bare gather inside a blip gathers its own children"
blip run --name "$P-gparent" --from "$P-base" -- sleep infinity
wait_blip_phase "$P-gparent" Running
blip run --from "$P-gparent" -- blip run --name "$P-gchild1" --from / -- sh -c 'echo child1'
blip run --from "$P-gparent" -- blip run --name "$P-gchild2" --from / -- sh -c 'sleep 2; echo child2'
blip run --from "$P-gparent" -- blip gather >"$work/gather-children.out"
grep -q "blip/$P-gchild1 Succeeded" "$work/gather-children.out"
grep -q "blip/$P-gchild2 Succeeded" "$work/gather-children.out"
wait_blip_gone "$P-gchild1" 120
wait_blip_gone "$P-gchild2" 120
wait_state_gone "$P-gchild1" 120
wait_state_gone "$P-gchild2" 120
k delete blip "$P-gparent" >/dev/null
wait_blip_gone "$P-gparent" 60
wait_state_gone "$P-gparent" 60

step "gather keeps a failed blip for inspection"
blip run --name "$P-gfail" --from "$P-base" -- sh -c 'exit 3'
wait_blip_phase "$P-gfail" Failed 180
expect_fail_grep "gather reports the failed command" "Failed (exit 3)" blip gather "$P-gfail"
k get blip "$P-gfail" >/dev/null
k delete blip "$P-gfail" >/dev/null
wait_blip_gone "$P-gfail" 60
wait_state_gone "$P-gfail" 60

step "a finished blip with a TTL is deleted by the controller"
out=$(blip run --name "$P-ttl" --ttl 1s --from "$P-base" -- true)
test "$out" = "$P-ttl"
test "$(blip_field "$P-ttl" '{.spec.ttlSecondsAfterFinished}')" = 1
wait_for 120 "blip $P-ttl to finish or expire" is_blip_finished_or_gone_50 "$P-ttl" || {
	k get blip "$P-ttl" -o yaml >&2 || true
	false
}
wait_blip_gone "$P-ttl" 120
wait_state_gone "$P-ttl" 120

step "spec.stop finishes the blip, saves the root, and preserves files"
new_root_50 "$P-stop"
blip run --name "$P-stopw" --state "$P-stop" -- sleep infinity
wait_blip_phase "$P-stopw" Running
blip run --from "$P-stopw" -u 0:0 -- sh -ec 'echo persisted > /root/stop.txt; sync'
k patch blip "$P-stopw" --type merge -p '{"spec":{"stop":true}}' >/dev/null
wait_blip_phase "$P-stopw" Succeeded 180
wait_state "$P-stop" 120
k delete blip "$P-stopw" >/dev/null
wait_blip_gone "$P-stopw" 60
blip run --name "$P-stopc" --state "$P-stop" -- sleep infinity
wait_blip_phase "$P-stopc" Running
test "$(blip run --from "$P-stopc" -u 0:0 -- cat /root/stop.txt)" = persisted
k delete blip "$P-stopc" >/dev/null
wait_blip_gone "$P-stopc" 60
wait_state "$P-stop" 120
