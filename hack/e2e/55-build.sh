# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# shellcheck shell=bash
# shellcheck disable=SC2154 # $work and the scenario environment come from hack/e2e.sh.
# Build recipes: a recipe produces owned, timestamped outputs; publishes its
# labels and annotations only on success; builds incrementally on a spec
# change; prunes outputs past historyLimit; and keeps a failed attempt
# unpublished. The git-cache contract is checked through labels and
# annotations only; profile-mount selection needs blipchat and is not covered.
# streamSize is copied to outputs but has no cheap observable effect here.
#
# Guest commands intentionally expand variables inside the VM.
# shellcheck disable=SC2016

cleanup_55() {
	k delete blip --ignore-not-found --wait=false "$P-build-check" >/dev/null 2>&1 || true
	# Outputs and build Blips are owned by the recipes; deleting a recipe
	# removes them, but delete them by label too so nothing outlives the run.
	k delete blipstate --ignore-not-found --wait=false "$P-build-ok" "$P-build-fail" >/dev/null 2>&1 || true
	k delete blip --ignore-not-found --wait=false -l "blip.dev/build in ($P-build-ok,$P-build-fail)" >/dev/null 2>&1 || true
	k delete blipstate --ignore-not-found --wait=false -l "blip.dev/build in ($P-build-ok,$P-build-fail)" >/dev/null 2>&1 || true
}
cleanup_register cleanup_55

state_field_55() {
	k get blipstate "$1" -o jsonpath="$2" 2>/dev/null
}

# is_build_latest_55 RECIPE NOT is true once the recipe's latest successful
# output is set and differs from NOT.
is_build_latest_55() {
	local latest
	latest=$(state_field_55 "$1" '{.status.build.latest}')
	[ -n "$latest" ] && [ "$latest" != "$2" ]
}

wait_build_latest_55() {
	wait_for "${3:-240}" "a new build output of $1" is_build_latest_55 "$1" "${2:-}" || {
		k get blipstate "$1" -o yaml >&2 || true
		k get blipstate,blip -l "blip.dev/build=$1" >&2 || true
		return 1
	}
}

is_build_failed_55() {
	local out
	out=$(state_field_55 "$1" '{.status.build.output}')
	[ -n "$out" ] && [ -n "$(state_field_55 "$1" '{.status.build.message}')" ] &&
		[ "$(state_field_55 "$out" '{.metadata.annotations.blip\.dev/build-status}')" = failed ]
}

# read_file_55 STATE PATH prints a file from a fork of STATE.
read_file_55() {
	blip_shell "$P-build-check" --from "$1" -u 0:0 >/dev/null
	blip_exec "$P-build-check" "cat $2"
	k delete blip "$P-build-check" >/dev/null
	wait_blip_gone "$P-build-check" 60
}

# The recipe carries the selector labels too; consumers pick Ready matches.
ready_cache_55() { # REPO
	k get blipstate -l "git.blip.dev/repo=$1" \
		-o jsonpath='{range .items[?(@.status.phase=="Ready")]}{.metadata.name}{"\n"}{end}'
}

recipe_55() { # MSG
	k apply -f - >/dev/null <<EOF
apiVersion: blip.dev/v1alpha1
kind: BlipState
metadata:
  name: $P-build-ok
  labels:
    blip.dev/shared: "true"
    git.blip.dev/repo: $P-build-repo
  annotations:
    git.blip.dev/url: https://example.invalid/$P.git
    git.blip.dev/branch: main
spec:
  historyLimit: 1
  build:
    from: $P-base
    incremental: true
    intervalSeconds: 3600
    user: "0"
    workingDir: /opt
    env:
    - name: MSG
      value: $1
    command: [sh, -ec, 'echo "\$MSG \$(id -u) \$(pwd)" >> /opt/build.txt']
EOF
}

step "a build recipe produces an owned, timestamped, published output"
ensure_base
recipe_55 one
wait_build_latest_55 "$P-build-ok"
out1=$(state_field_55 "$P-build-ok" '{.status.build.latest}')
[[ $out1 =~ ^$P-build-ok-[0-9]{8}t[0-9]{6}(-[0-9a-z]{4})?$ ]]
wait_state "$out1"
test "$(state_field_55 "$out1" '{.metadata.ownerReferences[0].name}')" = "$P-build-ok"
test "$(state_field_55 "$out1" '{.metadata.labels.blip\.dev/build}')" = "$P-build-ok"
test "$(state_field_55 "$out1" '{.metadata.annotations.blip\.dev/build-status}')" = succeeded
test "$(state_field_55 "$P-build-ok" '{.status.build.message}')" = ""
test "$(read_file_55 "$out1" /opt/build.txt)" = "one 0 /opt"

step "published outputs carry the git cache contract and are selectable"
test "$(state_field_55 "$out1" '{.metadata.labels.blip\.dev/shared}')" = true
test -z "$(state_field_55 "$out1" '{.metadata.labels.blip\.dev/owner}')"
test "$(state_field_55 "$out1" '{.metadata.annotations.git\.blip\.dev/url}')" = "https://example.invalid/$P.git"
test "$(state_field_55 "$out1" '{.metadata.annotations.git\.blip\.dev/branch}')" = main
test "$(ready_cache_55 "$P-build-repo")" = "$out1"

step "a spec change rebuilds incrementally and historyLimit prunes the old output"
recipe_55 two
wait_build_latest_55 "$P-build-ok" "$out1"
out2=$(state_field_55 "$P-build-ok" '{.status.build.latest}')
wait_state "$out2"
test "$(read_file_55 "$out2" /opt/build.txt)" = "one 0 /opt
two 0 /opt"
wait_state_gone "$out1" 120
test "$(ready_cache_55 "$P-build-repo")" = "$out2"

step "a failed build keeps an unpublished output and reports why"
k apply -f - >/dev/null <<EOF
apiVersion: blip.dev/v1alpha1
kind: BlipState
metadata:
  name: $P-build-fail
  labels:
    git.blip.dev/repo: $P-build-failrepo
spec:
  historyLimit: 1
  build:
    from: $P-base
    intervalSeconds: 3600
    command: [sh, -c, 'echo partial > /opt/build.txt; exit 3']
EOF
wait_for 240 "build $P-build-fail to fail" is_build_failed_55 "$P-build-fail" || {
	k get blipstate "$P-build-fail" -o yaml >&2 || true
	false
}
fout=$(state_field_55 "$P-build-fail" '{.status.build.output}')
test "$(state_field_55 "$P-build-fail" '{.status.build.latest}')" = ""
test -z "$(state_field_55 "$fout" '{.metadata.labels.git\.blip\.dev/repo}')"
test -z "$(ready_cache_55 "$P-build-failrepo")"

step "deleting a recipe deletes its outputs"
k delete blipstate "$P-build-ok" "$P-build-fail" >/dev/null
wait_state_gone "$out2" 120
wait_state_gone "$fout" 120
