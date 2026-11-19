# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# shellcheck shell=bash
# Mounts: durable roots, writable auxiliary mounts and their fork privacy,
# read-only mounts, --new/--from, removals, rejections, and collecting from a
# forked auxiliary mount.
#
# Guest commands intentionally expand variables inside the VM.
# shellcheck disable=SC2016

base_created=0

cleanup_40() {
	local b names
	k delete blip --ignore-not-found --wait=false \
		"$P-mparent" "$P-mchild" "$P-mout" >/dev/null 2>&1 || true
	# A fork's writable aux states have hashed names. Remove the states still
	# owned by this scenario's executions, then the durable states by name.
	for b in "$P-mparent" "$P-mchild" "$P-mout"; do
		names=$(k get blipstate -o jsonpath="{range .items[?(@.metadata.ownerReferences[0].name==\"$b\")]}{.metadata.name}{\"\n\"}{end}" 2>/dev/null || true)
		if [ -n "$names" ]; then
			# shellcheck disable=SC2086
			k delete blipstate --ignore-not-found --wait=false $names >/dev/null 2>&1 || true
		fi
	done
	k delete blipstate --ignore-not-found --wait=false \
		"$P-mroot" "$P-maux" "$P-inside" "$P-mcopy" "$P-mchild" "$P-mout" \
		>/dev/null 2>&1 || true
	if [ "$base_created" = 1 ]; then
		k delete blipstate --ignore-not-found --wait=false "$P-base" >/dev/null 2>&1 || true
	fi
}
cleanup_register cleanup_40

step "prepare an imported base and a durable root state from it"
if ! k get blipstate "$P-base" >/dev/null 2>&1; then
	base_created=1
	blip pull "$P-base" "$IMG"
fi
wait_state "$P-base"
blip run --name "$P-mroot" --from "$P-base" --keep -- sleep infinity
k delete blip "$P-mroot" >/dev/null
wait_state "$P-mroot"
test "$(k get blipstate "$P-mroot" -o jsonpath='{.spec.copyFrom}')" = "$P-base"
# The dev image runs as uid 1000. Empty auxiliary filesystems are root-owned,
# so run this root and its forks as root to write to their mount points.
k patch blipstate "$P-mroot" --type merge \
	-p '{"spec":{"runtime":{"user":"0:0"}}}' >/dev/null

step "create a writable auxiliary mount and a read-only base mount"
blip mount --new "$P-maux:/aux:rw" --root "$P-mroot"
blip mount "$P-base:/base:ro" --root "$P-mroot"
expect_ok_grep "writable aux is listed" "$P-maux:/aux (writable)" blip mount --root "$P-mroot"
expect_ok_grep "read-only base is listed" "$P-base:/base (read-only)" blip mount --root "$P-mroot"
test "$(k get blipstate "$P-mroot" -o jsonpath='{.spec.mounts[?(@.path=="/aux")].writable}')" = true
test -z "$(k get blipstate "$P-mroot" -o jsonpath='{.spec.mounts[?(@.path=="/base")].writable}')"

step "mount from inside a blip defaults --root to its own root state"
blip run --name "$P-mparent" --state "$P-mroot" -- sleep infinity
blip run --from "$P-mparent" -- blip mount --new "$P-inside:/inside:rw"
expect_ok_grep "inner mount is in the parent's listing" \
	"$P-inside:/inside (writable)" blip run --from "$P-mparent" -- blip mount
test "$(k get blipstate "$P-mroot" -o jsonpath='{.spec.mounts[?(@.path=="/inside")].state}')" = "$P-inside"
test "$(k get blipstate "$P-mroot" -o jsonpath='{.spec.mounts[?(@.path=="/inside")].writable}')" = true
test "$(blip_field "$P-mparent" '{.status.mounts[?(@.path=="/inside")].state}')" = "$P-inside"
test "$(blip_field "$P-mparent" '{.status.mounts[?(@.path=="/inside")].writable}')" = true

step "a writable auxiliary mount is private to a fork"
blip run --from "$P-mparent" -- sh -ec 'printf parent-data > /aux/parent.txt; sync'
child=$(blip run --from "$P-mparent" -- blip run --name "$P-mchild" --from / -- sleep infinity)
test "$child" = "$P-mchild"
blip run --from "$child" -- sh -ec '
	test "$(cat /aux/parent.txt)" = parent-data
	printf child-only > /aux/child-only
	sync
'
blip run --from "$P-mparent" -- test ! -e /aux/child-only
blip run --from "$child" -- sh -ec '
	test -x /base/bin/sh
	if ( printf blocked > /base/blocked ) 2>/dev/null; then
		echo "write to read-only /base succeeded" >&2
		exit 1
	fi
'
k delete blip "$child" >/dev/null
wait_blip_gone "$child"
wait_state_gone "$P-mchild"
blip run --from "$P-mparent" -- sh -ec '
	test "$(cat /aux/parent.txt)" = parent-data
	test ! -e /aux/child-only
'

# Collect while /aux is still mounted; the next step removes it from the root.
step "collect from a fork's aux mount with {name} substitution"
outchild=$(blip run --from "$P-mparent" -- blip run --name "$P-mout" --from / -- sh -ec 'printf collected-from-aux > /aux/out')
test "$outchild" = "$P-mout"
blip run --from "$P-mparent" -e CHILD="$P-mout" -- bash -ec '
	cd /root
	blip gather "$CHILD" --collect "/aux/out:./{name}.out"
	test "$(cat "./$CHILD.out")" = collected-from-aux
'
wait_blip_gone "$P-mout"
wait_state_gone "$P-mout"

step "remove the auxiliary mount and wait for its save"
aux_commit=$(k get blipstate "$P-maux" -o jsonpath='{.status.committed.id}')
blip mount --rm "$P-maux" --root "$P-mroot"
wait_state "$P-maux"
test "$(k get blipstate "$P-maux" -o jsonpath='{.status.committed.id}')" != "$aux_commit"
if blip mount --root "$P-mroot" | grep -q "$P-maux:/aux"; then
	echo "removed aux mount is still listed" >&2
	exit 1
fi

step "mount --new --from copies an imported base into an independent state"
blip mount --new "$P-mcopy:/copy:rw" --from "$P-base" --root "$P-mroot"
test "$(k get blipstate "$P-mcopy" -o jsonpath='{.spec.copyFrom}')" = "$P-base"
test "$(k get blipstate "$P-mcopy" -o jsonpath='{.metadata.uid}')" != \
	"$(k get blipstate "$P-base" -o jsonpath='{.metadata.uid}')"
blip run --from "$P-mparent" -- sh -ec '
	test -x /copy/bin/sh
	printf copy-only > /copy/mcopy-only
'
blip mount --rm "$P-mcopy" --root "$P-mroot"
wait_state "$P-mcopy"
blip mount "$P-mcopy:/copy-check:ro" --root "$P-mroot"
blip run --from "$P-mparent" -- sh -ec '
	test "$(cat /copy-check/mcopy-only)" = copy-only
	test ! -e /base/mcopy-only
'
blip mount --rm "$P-mcopy" --root "$P-mroot"
wait_state "$P-mcopy"

step "reject writable image mounts and direct execution of an imported base"
# The base is currently mounted read-only; free it so the writable-import
# check, not the duplicate-state check, is what rejects the attempt.
blip mount --rm "$P-base" --root "$P-mroot"
wait_state "$P-base"
expect_fail_grep "writable mount of an imported base" "imported base" \
	blip mount "$P-base:/bad:rw" --root "$P-mroot"
test -z "$(k get blipstate "$P-mroot" -o jsonpath='{.spec.mounts[?(@.path=="/bad")].state}')"
blip mount "$P-base:/base:ro" --root "$P-mroot"
expect_fail_grep "run in an imported base" "use --from" \
	blip run --state "$P-base" -- true

step "final mount listing and removing the guest-created mount"
inside_commit=$(k get blipstate "$P-inside" -o jsonpath='{.status.committed.id}')
blip mount --rm "$P-inside" --root "$P-mroot"
wait_state "$P-inside"
test "$(k get blipstate "$P-inside" -o jsonpath='{.status.committed.id}')" != "$inside_commit"
mounts=$(blip mount --root "$P-mroot")
printf '%s\n' "$mounts"
grep -q "^$P-base:/base (read-only)" <<<"$mounts"
if grep -q "$P-maux\|$P-inside\|$P-mcopy" <<<"$mounts"; then
	echo "mount listing still contains a removed mount" >&2
	exit 1
fi
k delete blip "$P-mparent" >/dev/null
wait_blip_gone "$P-mparent"
wait_state "$P-mroot"
