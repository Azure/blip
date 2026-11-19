#!/usr/bin/env bash
# shellcheck disable=SC2154
# Shared helpers for the e2e scenarios. hack/e2e.sh sets the environment and
# sources this file before any scenario.

CLEANUP_FUNCS=()

# cleanup_register adds a function to run, in reverse order, when the suite
# exits. It is safe for a function to ignore missing objects.
cleanup_register() {
	CLEANUP_FUNCS+=("$1")
}

run_cleanup() {
	local i fn
	for ((i = ${#CLEANUP_FUNCS[@]} - 1; i >= 0; i--)); do
		fn=${CLEANUP_FUNCS[$i]}
		"$fn" || true
	done
}

# wait_for SECONDS DESCRIPTION PREDICATE [ARG...] polls a predicate.
wait_for() {
	local timeout=$1 desc=$2 i
	shift 2
	for ((i = 0; i < timeout; i++)); do
		if "$@"; then
			return 0
		fi
		sleep 1
	done
	echo "timed out after ${timeout}s waiting for $desc" >&2
	return 1
}

blip_phase() {
	k get blip "$1" -o jsonpath='{.status.phase}' 2>/dev/null
}

blip_pod() {
	k get blip "$1" -o jsonpath='{.status.pod}' 2>/dev/null
}

blip_field() {
	k get blip "$1" -o jsonpath="$2" 2>/dev/null
}

is_blip_phase() {
	[ "$(blip_phase "$1")" = "$2" ]
}

is_blip_gone() {
	! k get blip "$1" >/dev/null 2>&1
}

wait_blip_phase() {
	local name=$1 phase=$2 timeout=${3:-120}
	wait_for "$timeout" "blip $name phase $phase" is_blip_phase "$name" "$phase" || {
		k get blip "$name" -o yaml >&2 || true
		return 1
	}
}

wait_blip_gone() {
	local name=$1 timeout=${2:-120}
	wait_for "$timeout" "blip $name to be removed" is_blip_gone "$name" || {
		k get blip "$name" -o yaml >&2 || true
		return 1
	}
}

# is_state_phase and is_state_gone are predicates for wait_for.
is_state_phase() {
	[ "$(k get blipstate "$1" -o jsonpath='{.status.phase}' 2>/dev/null)" = "$2" ]
}

is_state_gone() {
	! k get blipstate "$1" >/dev/null 2>&1
}

wait_state() {
	local name=$1 timeout=${2:-120}
	wait_for "$timeout" "state $name to become Ready" is_state_phase "$name" Ready || {
		k get blipstate "$name" -o yaml >&2 || true
		return 1
	}
}

wait_state_gone() {
	local name=$1 timeout=${2:-120}
	wait_for "$timeout" "state $name to be removed" is_state_gone "$name" || {
		k get blipstate "$name" -o yaml >&2 || true
		return 1
	}
}

# expect_fail runs a command and succeeds only if it fails. The command's
# output is kept in $work/expect-fail.out for a following grep or debugging.
expect_fail() {
	local desc=$1
	shift
	if "$@" >"$work/expect-fail.out" 2>&1; then
		echo "expected failure: $desc" >&2
		cat "$work/expect-fail.out" >&2
		return 1
	fi
	return 0
}

expect_fail_grep() {
	local desc=$1 pattern=$2
	shift 2
	expect_fail "$desc" "$@" || return 1
	if ! grep -q -- "$pattern" "$work/expect-fail.out"; then
		echo "expected failure output for $desc to contain: $pattern" >&2
		cat "$work/expect-fail.out" >&2
		return 1
	fi
}

# expect_ok_grep greps successful command output, and leaves it in $work/expect-ok.out.
expect_ok_grep() {
	local desc=$1 pattern=$2
	shift 2
	if ! "$@" >"$work/expect-ok.out" 2>&1; then
		echo "command failed: $desc" >&2
		cat "$work/expect-ok.out" >&2
		return 1
	fi
	if ! grep -q -- "$pattern" "$work/expect-ok.out"; then
		echo "output for $desc did not contain: $pattern" >&2
		cat "$work/expect-ok.out" >&2
		return 1
	fi
}

# ensure_base makes the shared imported base available to any scenario, even
# when only a later scenario was selected.
ensure_base() {
	if k get blipstate "$P-base" >/dev/null 2>&1; then
		# A reused cluster may still be finishing (or repairing) the base.
		wait_state "$P-base" "${T:-120}"
		return
	fi
	blip pull "$P-base" "$IMG"
}

cleanup_base() {
	k delete blipstate --ignore-not-found --wait=false "$P-base" >/dev/null 2>&1 || true
}

# wait_http URL waits for a host-local HTTP endpoint, used by port-forwards.
wait_http() {
	local url=$1 timeout=${2:-60} i
	for ((i = 0; i < timeout; i++)); do
		curl -fsS --max-time 2 "$url" >/dev/null 2>&1 && return 0
		sleep 1
	done
	echo "timed out waiting for $url" >&2
	return 1
}
