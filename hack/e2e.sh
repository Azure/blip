#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# End-to-end tests against the kind cluster from hack/kind-up.sh. Scenarios
# live in hack/e2e/ and share the helpers in hack/e2e/lib.sh. Everything runs
# from the host through the CLI in the default namespace unless a scenario
# says otherwise.
# Guest commands intentionally expand variables inside the VM.
# shellcheck disable=SC2016,SC2034
set -euo pipefail
cd "$(dirname "$0")/.."

CONTEXT=${BLIP_CONTEXT:-kind-blip-dev}
IMG=${BLIP_IMAGE:-blip-registry:5000/blip/dev:latest}
P=${BLIP_E2E_PREFIX:-e2e}
FORK_MAX=${BLIP_E2E_FORK_MAX:-120}
# Limit for any single command or sandbox script, in seconds.
T=${BLIP_E2E_TIMEOUT:-180}
# limited CMD... runs CMD under the command limit and says so when it expires.
limited() {
	local rc=0
	timeout "$T" "$@" || rc=$?
	[ "$rc" -ne 124 ] || echo "timed out after ${T}s: ${*:1:5}" >&2
	return "$rc"
}
blip() { limited bin/kubectl-blip --context "$CONTEXT" "$@"; }
k() { limited kubectl --context "$CONTEXT" "$@"; }
t0=$SECONDS
step() { printf '\n== [%3ds] %s\n' "$((SECONDS - t0))" "$*"; }
work=$(mktemp -d)

# shellcheck source=hack/e2e/lib.sh
source hack/e2e/lib.sh

cleanup() {
	run_cleanup
	rm -rf "$work"
}
trap cleanup EXIT
cleanup_register cleanup_base
ensure_base

# Each scenario runs in its own subshell so a failure does not abort the
# others. Set BLIP_E2E_FAIL_FAST=1 to stop at the first failure.
results=()
failed=0
for scenario in hack/e2e/[0-9]*.sh; do
	name=$(basename "$scenario")
	if [ "$name" = "90-resilience.sh" ] && [ "${BLIP_E2E_RESILIENCE:-0}" != 1 ]; then
		continue
	fi
	if [ -n "${BLIP_E2E_SCENARIOS:-}" ]; then
		case " ${BLIP_E2E_SCENARIOS} " in
		*" ${name%%-*} "*) ;;
		*) continue ;;
		esac
	fi
	log="$work/scenario-${name%.sh}.log"
	start=$SECONDS
	set +e
	(
		set -e
		base_cleanups=${#CLEANUP_FUNCS[@]}
		# shellcheck disable=SC2317 # invoked by the EXIT trap
		scenario_exit() {
			local rc=$? i
			set +e
			# Free this scenario's states before the next one starts; the
			# shared base is owned by cleanup_base.
			for ((i = ${#CLEANUP_FUNCS[@]} - 1; i >= base_cleanups; i--)); do
				"${CLEANUP_FUNCS[$i]}" || true
			done
			local fn="cleanup_${name%%-*}"
			if declare -F "$fn" >/dev/null; then
				"$fn" || true
			fi
			if [ "$rc" -ne 0 ]; then
				echo "FAILED $name (exit $rc)"
				dump_cluster_diagnostics
			elif ! check_no_leaks "$P"; then
				rc=1
			fi
			exit "$rc"
		}
		trap scenario_exit EXIT
		trap 'echo "FAILED at line $LINENO: $BASH_COMMAND"' ERR
		# shellcheck disable=SC1090
		source "$scenario"
	) 2>&1 | tee "$log"
	rc=${PIPESTATUS[0]}
	set -e
	dur=$((SECONDS - start))
	if [ "$rc" -ne 0 ]; then
		result=fail
		failed=$((failed + 1))
	elif grep -q '^SKIP ' "$log"; then
		result=skip
	else
		result=pass
	fi
	results+=("$name $result $dur")
	if [ "$result" = fail ] && [ "${BLIP_E2E_FAIL_FAST:-0}" = 1 ]; then
		break
	fi
done

write_report() {
	local r n res d
	{
		echo '<?xml version="1.0" encoding="UTF-8"?>'
		printf '<testsuite name="blip-e2e" tests="%d" failures="%d" time="%d">\n' \
			"${#results[@]}" "$failed" "$((SECONDS - t0))"
		for r in "${results[@]}"; do
			read -r n res d <<<"$r"
			printf '  <testcase classname="e2e" name="%s" time="%d">\n' "${n%.sh}" "$d"
			case $res in
			fail)
				echo '    <failure message="scenario failed"><![CDATA['
				sed '/^--- cluster diagnostics$/,$d' "$work/scenario-${n%.sh}.log" | tail -50 | sed 's/]]>/]]]]><![CDATA[>/g' |
					tr -d '\000-\010\013\014\016-\037'
				echo ']]></failure>'
				;;
			skip) echo '    <skipped/>' ;;
			esac
			echo '  </testcase>'
		done
		echo '</testsuite>'
	} >"$BLIP_E2E_REPORT"
}

if [ -n "${BLIP_E2E_REPORT:-}" ]; then
	write_report
fi

printf '\n%-24s %-6s %s\n' SCENARIO RESULT SECONDS
for r in "${results[@]}"; do
	read -r n res d <<<"$r"
	printf '%-24s %-6s %s\n' "$n" "$res" "$d"
done
if [ "$failed" -ne 0 ]; then
	echo "FAILED: $failed scenario(s) in $((SECONDS - t0))s"
	exit 1
fi
echo "PASSED in $((SECONDS - t0))s"
