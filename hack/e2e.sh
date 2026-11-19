#!/usr/bin/env bash
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
blip() { timeout "$T" bin/kubectl-blip --context "$CONTEXT" "$@"; }
k() { timeout "$T" kubectl --context "$CONTEXT" "$@"; }
t0=$SECONDS
step() { printf '\n== [%3ds] %s\n' "$((SECONDS - t0))" "$*"; }
work=$(mktemp -d)

# shellcheck source=hack/e2e/lib.sh
source hack/e2e/lib.sh

cleanup() {
	run_cleanup
	rm -rf "$work"
}
trap 'echo FAILED' ERR
trap cleanup EXIT
cleanup_register cleanup_base
ensure_base

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
	# shellcheck disable=SC1090
	source "$scenario"
	# Free this scenario's states before the next one starts; the shared base
	# is owned by cleanup_base and the final cleanup repeats these calls.
	scenario_cleanup="cleanup_${name%%-*}"
	if declare -F "$scenario_cleanup" >/dev/null; then
		"$scenario_cleanup" || true
	fi
done

echo "PASSED in $((SECONDS - t0))s"
