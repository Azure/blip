# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# shellcheck shell=bash
# Disruptive-but-graceful failure coverage: drain a worker that holds a state
# replica, restart one node agent, and churn a temporary pool at its maxCount.
# The cluster is disposable, but every drain is repaired here so later
# scenarios (and a reused cluster) still work.

# drained_nodes is a space-separated set of BlipNodes this scenario drained.
# cleanup_90 undrains them even when a subtest fails.
drained_nodes=""

cleanup_90() {
	local n
	for n in $drained_nodes; do
		k patch blipnode "$n" --type merge -p '{"spec":{"drain":false}}' >/dev/null 2>&1 || true
	done
	k delete blipstate --ignore-not-found --wait=false "$P-drain" >/dev/null 2>&1 || true
	k delete blippool --ignore-not-found --wait=false "$P-churn" >/dev/null 2>&1 || true
	k delete pod --ignore-not-found --wait=false \
		-l "blip.dev/pool=$P-churn" >/dev/null 2>&1 || true
}
cleanup_register cleanup_90

blipnode_field() {
	k get blipnode "$1" -o jsonpath="$2" 2>/dev/null
}

# remember_drain and drain_node make a drain reversible: the node is recorded
# before the patch, so cleanup can revert it even if the patch or a later wait
# fails.
remember_drain() {
	case " $drained_nodes " in
	*" $1 "*) ;;
	*) drained_nodes="$drained_nodes $1" ;;
	esac
}

drain_node() {
	remember_drain "$1"
	k patch blipnode "$1" --type merge -p '{"spec":{"drain":true}}' >/dev/null
}

is_safe_to_remove() {
	[ "$(blipnode_field "$1" '{.status.safeToRemove}')" = true ]
}

node_label() {
	k get node "$1" -o go-template="{{index .metadata.labels \"$2\"}}" 2>/dev/null
}

# is_undrained waits for the operator drain to clear and for enrollment to
# advertise the hypervisor again, so the node can take VM pods and replicas.
is_undrained() {
	[ "$(blipnode_field "$1" '{.spec.drain}')" != true ] &&
		[ "$(node_label "$1" blip.dev/hypervisor-kvm)" = true ]
}

undrain_node() {
	k patch blipnode "$1" --type merge -p '{"spec":{"drain":false}}' >/dev/null
	wait_for "$T" "node $1 to be usable again" is_undrained "$1"
}

state_placements() {
	k get blipstate "$1" -o jsonpath='{.status.placements[*]}' 2>/dev/null
}

state_has_placement() {
	case " $(state_placements "$1") " in
	*" $2 "*) return 0 ;;
	esac
	return 1
}

state_replica_count() {
	[ "$(state_placements "$1" | wc -w)" -ge "$2" ]
}

state_lacks_placement() {
	! state_has_placement "$1" "$2"
}

# node_agent_replaced finds a ready blip-node pod on node other than old,
# which is how the DaemonSet shows that it recreated a deleted agent.
node_agent_replaced() {
	local node=$1 old=$2 name
	for name in $(k get pods -n blip-system -l app.kubernetes.io/name=blip-node \
		--field-selector "spec.nodeName=$node" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
		[ "$name" = "$old" ] && continue
		[ "$(k get pod "$name" -n blip-system -o jsonpath='{.status.phase}' 2>/dev/null)" = Running ] || continue
		[ "$(k get pod "$name" -n blip-system \
			-o jsonpath='{.status.containerStatuses[?(@.name=="node")].ready}' 2>/dev/null)" = true ] || continue
		return 0
	done
	return 1
}

# node_agent_healthy requires a heartbeat newer than the one the old agent
# wrote, so a still-terminating pod or a stale BlipNode cannot stand in for the
# recreated agent.
node_agent_healthy() {
	local node=$1 old=$2 heartbeat
	heartbeat=$(blipnode_field "$node" '{.status.heartbeat}')
	[ "$(node_label "$node" blip.dev/hypervisor-kvm)" = true ] &&
		[ -n "$heartbeat" ] && [ "$heartbeat" != "$old" ] &&
		[ "$(blipnode_field "$node" '{.status.safeToRemove}')" != true ]
}

churn_ready() {
	[ "$(k get blippool "$P-churn" -o jsonpath='{.status.ready}' 2>/dev/null)" = 2 ]
}

churn_pods() {
	k get pods -l "blip.dev/pool=$P-churn" \
		-o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null
}

churn_gone() {
	[ -z "$(k get pods -l "blip.dev/pool=$P-churn" \
		-o jsonpath='{.items[*].metadata.name}' 2>/dev/null)" ]
}

step "drain a worker that holds a state replica"
k apply -f - >/dev/null <<EOF
apiVersion: blip.dev/v1alpha1
kind: BlipState
metadata:
  name: $P-drain
  namespace: default
spec:
  size: 1Gi
  replicas: 2
  nodeSelector:
    blip.dev/node-pool: default
EOF
wait_state "$P-drain" "$((T * 2))"
wait_for "$((T * 2))" "state $P-drain to hold two replicas" state_replica_count "$P-drain" 2
placements=$(state_placements "$P-drain")
drained=$(printf '%s' "$placements" | tr ' ' '\n' | sed -n '1p')
test -n "$drained"
survivors=$(printf '%s' "$placements" | tr ' ' '\n' | grep -vx "$drained" || true)
drain_node "$drained"
drain_timeout=$((T * 4))
wait_for "$drain_timeout" "node $drained to be safe to remove" is_safe_to_remove "$drained"
wait_for "$drain_timeout" "state $P-drain to move off $drained" state_lacks_placement "$P-drain" "$drained"
after=$(state_placements "$P-drain")
test -n "$after"
test "$(printf '%s' "$after" | wc -w)" -ge 2
for n in $survivors; do
	if ! state_has_placement "$P-drain" "$n"; then
		echo "state $P-drain lost surviving replica $n" >&2
		exit 1
	fi
done
test "$(k get blipstate "$P-drain" -o jsonpath='{.status.phase}')" = Ready
echo "replicas moved from [$placements] to [$after]"
undrain_node "$drained"

step "restart a node agent and wait for it to enroll again"
# Prefer a worker this scenario did not just drain, so the restart does not
# race with the enrollment and replica repair we triggered above.
agent_line=$(k get pods -n blip-system -l app.kubernetes.io/name=blip-node \
	-o jsonpath='{range .items[*]}{.metadata.name}{" "}{.spec.nodeName}{"\n"}{end}' |
	awk -v skip=" $drained_nodes " \
		'$2 ~ /worker/ && $1 != "" && index(skip, " " $2 " ") == 0 { print; exit }')
if [ -z "$agent_line" ]; then
	echo "no worker blip-node pod found" >&2
	exit 1
fi
read -r agent_pod agent_node <<<"$agent_line"
# The restarted pod must be the DaemonSet's node container, not another pod on
# the host that happens to share the label.
k get pod "$agent_pod" -n blip-system \
	-o jsonpath='{range .spec.containers[*]}{.name}{"\n"}{end}' | grep -qx node
old_heartbeat=$(blipnode_field "$agent_node" '{.status.heartbeat}')
test -n "$old_heartbeat"
echo "deleting $agent_pod on $agent_node"
k delete pod "$agent_pod" -n blip-system --wait=false >/dev/null
wait_for "$((T * 2))" "blip-node replacement on $agent_node" node_agent_replaced "$agent_node" "$agent_pod"
wait_for "$T" "node $agent_node to report healthy again" node_agent_healthy "$agent_node" "$old_heartbeat"
echo "node $agent_node enrolled through $agent_pod's replacement"

step "churn a temporary pool at its maxCount"
# Remove a pool left by a failed earlier run so the count below starts clean.
k delete blippool "$P-churn" --ignore-not-found >/dev/null 2>&1 || true
wait_for "$T" "stale $P-churn pods to disappear" churn_gone
k apply -f - >/dev/null <<EOF
apiVersion: blip.dev/v1alpha1
kind: BlipPool
metadata:
  name: $P-churn
  namespace: default
spec:
  serviceAccountName: blip-agent
  cpus: 1
  memory: 1Gi
  warmCount: 2
  maxCount: 2
  nodeSelector:
    blip.dev/node-pool: default
EOF
wait_for "$((T * 4))" "pool $P-churn to have two ready warm VMs" churn_ready
initial=$(churn_pods)
test "$(printf '%s\n' "$initial" | sed '/^$/d' | wc -l)" = 2
first_pod=$(printf '%s\n' "$initial" | sed -n '1p')
second_pod=$(printf '%s\n' "$initial" | sed -n '2p')
k delete pod "$first_pod" --wait=false >/dev/null
replacement=""
churn_timeout=$((T * 3))
for ((i = 0; i < churn_timeout; i++)); do
	names=$(churn_pods)
	count=$(printf '%s\n' "$names" | sed '/^$/d' | wc -l)
	if [ "$count" -gt 2 ]; then
		echo "pool $P-churn exceeded maxCount: $count pods" >&2
		printf '%s\n' "$names" >&2
		exit 1
	fi
	# A name that was not one of the two original warm pods means the deleted
	# VM was replaced. With count 2 and one such name the replacement is done.
	replacement=$(printf '%s\n' "$names" | sed '/^$/d' |
		grep -vxF -e "$first_pod" -e "$second_pod" || true)
	if [ "$count" -eq 2 ] && [ -n "$replacement" ]; then
		break
	fi
	sleep 1
done
if [ -z "$replacement" ]; then
	echo "timed out waiting for exactly one replacement warm VM" >&2
	churn_pods >&2 || true
	exit 1
fi
final=$(churn_pods)
test "$(printf '%s\n' "$final" | sed '/^$/d' | wc -l)" = 2
# grep exits 1 on no match, so count with wc instead of grep -c under -e.
# shellcheck disable=SC2126
new_count=$(printf '%s\n' "$final" | sed '/^$/d' |
	grep -vxF -e "$first_pod" -e "$second_pod" | wc -l)
test "$new_count" = 1
wait_for "$T" "pool $P-churn to be ready again" churn_ready
k delete blippool "$P-churn" >/dev/null
wait_for "$((T * 2))" "pool $P-churn pods to disappear" churn_gone
echo "replaced $first_pod with $replacement and removed the pool"

# Node loss (stopping a kind worker container) is intentionally omitted.
# That also stops the node's kubelet and every DaemonSet pod on it, and a
# stopped kind container can leave the node NotReady for minutes on a shared
# host. The controller-level drains above cover graceful removal; ungraceful
# loss is covered by the controller unit tests (deleted Node, lost
# incarnation, and unreachable placement).
