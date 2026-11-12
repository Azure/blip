#!/usr/bin/env bash
# Wait until the deployed system is ready after `make deploy`: the
# controller Deployment and node DaemonSet rolled out, and the controller
# has a session with every node daemon (the last connect/disconnect line of
# each node in the current controller log is a connect).
set -euo pipefail
cluster=${KIND_CLUSTER:-blip}
T="timeout -s TERM"
K=(kubectl --context "kind-$cluster" -n blip-system)
$T 200 "${K[@]}" rollout status deploy/blip-controller --timeout=180s >/dev/null
$T 200 "${K[@]}" rollout status ds/blip-node --timeout=180s >/dev/null
nodes=$($T 30 "${K[@]}" get pods -l app.kubernetes.io/name=blip-node -o jsonpath='{.items[*].spec.nodeName}')
end=$((SECONDS + 120))
for n in $nodes; do
	until [[ $($T 30 "${K[@]}" logs deploy/blip-controller --tail=-1 2>/dev/null |
		grep -E "\"node (connected|disconnected)\",\"node\":\"$n\"" | tail -n 1) == *connected* &&
		$($T 30 "${K[@]}" logs deploy/blip-controller --tail=-1 2>/dev/null |
		grep -E "\"node (connected|disconnected)\",\"node\":\"$n\"" | tail -n 1) != *disconnected* ]]; do
		[[ $SECONDS -lt $end ]] || { echo "node $n has no controller session" >&2; exit 1; }
		sleep 1
	done
done
echo "controller and node daemons ready; sessions: $nodes"
