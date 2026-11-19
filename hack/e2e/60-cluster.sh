# shellcheck shell=bash
# shellcheck disable=SC2016
# Cluster integration: node registration, replicated state placement, warm
# pools, and the serial console log. Drain and node-loss coverage lives in
# 90-resilience.

# Set when this scenario had to create $P-base itself (normal runs reuse the
# base from 10-basics, which must not be deleted).
c60_created_base=false

cleanup_60() {
	k delete blip --ignore-not-found --wait=false \
		"$P-repl-run" "$P-console" >/dev/null 2>&1 || true
	k delete blipstate --ignore-not-found --wait=false \
		"$P-repl" "$P-console" >/dev/null 2>&1 || true
	if [ "$c60_created_base" = true ]; then
		k delete blipstate --ignore-not-found --wait=false "$P-base" >/dev/null 2>&1 || true
	fi
	k delete blippool --ignore-not-found --wait=false "$P-pool" >/dev/null 2>&1 || true
}
cleanup_register cleanup_60

c60_nodes() {
	k get blipnodes -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null |
		awk 'NF' | sort || true
}

c60_eligible_nodes() {
	k get nodes -l blip.dev/node-pool=default \
		-o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null |
		awk 'NF' | sort || true
}

# c60_registration_matches reports whether every eligible worker has exactly
# one BlipNode and no other BlipNode exists.
c60_registration_matches() {
	local -a eligible registered
	mapfile -t eligible < <(c60_eligible_nodes)
	mapfile -t registered < <(c60_nodes)
	[ "${#eligible[@]}" -gt 0 ] || return 1
	[ "${#eligible[@]}" -eq "${#registered[@]}" ] || return 1
	[ "$(printf '%s\n' "${eligible[@]}")" = "$(printf '%s\n' "${registered[@]}")" ]
}

# c60_pool_gone and c60_pool_pods_gone are predicates for wait_for.
c60_pool_gone() {
	! k get blippool "$P-pool" >/dev/null 2>&1
}

c60_pool_pods_gone() {
	local pods
	pods=$(k get pods -l "blip.dev/pool=$P-pool" \
		-o jsonpath='{.items[*].metadata.name}' 2>/dev/null) || return 1
	[ -z "$pods" ]
}

# c60_bn_ok checks the registration fields the scheduler and state replicator
# rely on, including a heartbeat no older than ten minutes.
c60_bn_ok() {
	local name=$1 endpoint hypervisors heartbeat incarnation now ts
	endpoint=$(k get blipnode "$name" -o jsonpath='{.status.endpoint}' 2>/dev/null) || return 1
	[ -n "$endpoint" ] || return 1
	hypervisors=$(k get blipnode "$name" -o jsonpath='{.status.hypervisors[*]}' 2>/dev/null) || return 1
	printf '%s\n' "$hypervisors" | grep -qw -- kvm || return 1
	heartbeat=$(k get blipnode "$name" -o jsonpath='{.status.heartbeat}' 2>/dev/null) || return 1
	[ -n "$heartbeat" ] || return 1
	ts=$(date -d "$heartbeat" +%s 2>/dev/null) || return 1
	now=$(date +%s)
	[ $((now - ts)) -le 600 ] || return 1
	incarnation=$(k get blipnode "$name" -o jsonpath='{.status.incarnation}' 2>/dev/null) || return 1
	[ -n "$incarnation" ]
}

step "assert one healthy BlipNode per eligible worker"
wait_for "$T" "one BlipNode per eligible worker" c60_registration_matches || exit 1
mapfile -t c60_eligible < <(c60_eligible_nodes)
mapfile -t c60_registered < <(c60_nodes)
if [ "${#c60_eligible[@]}" -ne 3 ]; then
	echo "expected 3 eligible kind workers, found ${#c60_eligible[@]}: ${c60_eligible[*]}" >&2
	exit 1
fi
for node in "${c60_eligible[@]}"; do
	if ! wait_for "$T" "BlipNode $node to register and heartbeat" c60_bn_ok "$node"; then
		k get blipnode "$node" -o yaml >&2 || true
		exit 1
	fi
done
printf 'registered BlipNodes: %s\n' "${c60_registered[*]}"

step "create a replicated workspace and check its placements"
k apply -f - >/dev/null <<EOF
apiVersion: blip.dev/v1alpha1
kind: BlipState
metadata:
  name: $P-repl
  namespace: default
spec:
  copyFrom: $P-base
  size: 10Gi
  replicas: 3
  nodeSelector:
    blip.dev/node-pool: default
EOF
wait_state "$P-repl" "$T" || exit 1
c60_repl_placed() {
	local count
	count=$(k get blipstate "$P-repl" -o jsonpath='{.status.placements[*]}' 2>/dev/null | wc -w)
	[ "$count" -eq 3 ]
}
wait_for "$T" "three placements for $P-repl" c60_repl_placed || {
	k get blipstate "$P-repl" -o yaml >&2 || true
	exit 1
}
mapfile -t c60_placements < <(
	# kubectl's range path does not expose scalar array items here; split the
	# space-separated jsonpath output instead.
	k get blipstate "$P-repl" -o jsonpath='{.status.placements[*]}' 2>/dev/null |
		tr ' ' '\n' | awk 'NF' | sort
)
if [ "${#c60_placements[@]}" -ne 3 ]; then
	echo "expected 3 placements for $P-repl, found ${#c60_placements[@]}: ${c60_placements[*]}" >&2
	k get blipstate "$P-repl" -o yaml >&2 || true
	exit 1
fi
if [ "$(printf '%s\n' "${c60_placements[@]}" | sort -u | wc -l)" -ne 3 ]; then
	echo "placements for $P-repl are not distinct: ${c60_placements[*]}" >&2
	exit 1
fi
for node in "${c60_placements[@]}"; do
	if ! printf '%s\n' "${c60_eligible[@]}" | grep -qx -- "$node"; then
		echo "placement $node is not an eligible worker" >&2
		exit 1
	fi
	if ! c60_bn_ok "$node"; then
		echo "placement $node does not have a healthy BlipNode" >&2
		k get blipnode "$node" -o yaml >&2 || true
		exit 1
	fi
done
printf 'placements: %s\n' "${c60_placements[*]}"

step "use the replicated state, then delete it"
repl_marker="repl-marker-$(date +%s)-$$"
c60_repl_out=$(blip run --name "$P-repl-run" --state "$P-repl" -e MARKER="$repl_marker" -- \
	sh -ec 'printf "%s\n" "$MARKER" > /tmp/repl.txt; test "$(cat /tmp/repl.txt)" = "$MARKER"')
test "$c60_repl_out" = "$P-repl-run"
blip gather "$P-repl-run" >/dev/null
wait_state "$P-repl" "$T" || exit 1
k delete blipstate "$P-repl" --wait=false >/dev/null
wait_state_gone "$P-repl" "$T" || exit 1

step "check the default pool's warm capacity"
warm_count=$(k get blippool default -o jsonpath='{.spec.warmCount}' 2>/dev/null) || exit 1
if [ -z "$warm_count" ] || [ "$warm_count" -lt 2 ]; then
	echo "default pool warmCount is $warm_count, want at least 2" >&2
	exit 1
fi
c60_default_ready() {
	local ready
	ready=$(k get blippool default -o jsonpath='{.status.ready}' 2>/dev/null) || return 1
	[ -n "$ready" ] && [ "$ready" -ge 1 ]
}
wait_for "$T" "default pool to report a ready warm VM" c60_default_ready || exit 1

c60_claimed_pods() {
	local out
	out=$(k get pods -l blip.dev/pool=default \
		-o jsonpath='{range .items[*]}{.metadata.labels.blip\.dev/blip-uid}{"\t"}{.status.phase}{"\n"}{end}' 2>/dev/null) || return 1
	printf '%s\n' "$out" |
		awk -F'\t' '$1 != "" && $2 != "Succeeded" && $2 != "Failed" { n++ } END { print n+0 }'
}

c60_default_claimed_consistent() {
	local claimed actual
	claimed=$(k get blippool default -o jsonpath='{.status.claimed}' 2>/dev/null) || return 1
	# claimed is omitted when zero.
	claimed=${claimed:-0}
	actual=$(c60_claimed_pods) || return 1
	[ "$claimed" = "$actual" ]
}
wait_for "$T" "default pool claimed count to match its pods" c60_default_claimed_consistent || exit 1
default_ready=$(k get blippool default -o jsonpath='{.status.ready}' 2>/dev/null) || exit 1
default_claimed=$(k get blippool default -o jsonpath='{.status.claimed}' 2>/dev/null) || exit 1
printf 'default pool: warm=%s ready=%s claimed=%s\n' "$warm_count" \
	"${default_ready:-0}" "${default_claimed:-0}"

step "create a temporary pool and verify its warm pod is replaced"
k apply -f - >/dev/null <<EOF
apiVersion: blip.dev/v1alpha1
kind: BlipPool
metadata:
  name: $P-pool
  namespace: default
spec:
  cpus: 1
  memory: 1Gi
  warmCount: 1
  serviceAccountName: blip-agent
  nodeSelector:
    blip.dev/node-pool: default
EOF
temp_warm=""
c60_temp_warm_ready() {
	local candidate
	candidate=$(k get pods -l "blip.dev/pool=$P-pool,blip.dev/warm=true" \
		-o jsonpath='{.items[0].metadata.name}' 2>/dev/null) || return 1
	[ -n "$candidate" ] || return 1
	[ "$(k get pod "$candidate" -o jsonpath='{.status.phase}' 2>/dev/null)" = Running ] || return 1
	temp_warm=$candidate
}
wait_for "$T" "temporary pool warm pod" c60_temp_warm_ready || {
	k get pods -l "blip.dev/pool=$P-pool" -o yaml >&2 || true
	exit 1
}
test "$(k get pod "$temp_warm" -o jsonpath='{.metadata.labels.blip\.dev/pool}')" = "$P-pool"
test "$(k get pod "$temp_warm" -o jsonpath='{.metadata.labels.blip\.dev/warm}')" = true
printf 'temporary pool warm pod: %s\n' "$temp_warm"

k delete pod "$temp_warm" --wait=false >/dev/null
replacement=""
c60_replacement_ready() {
	local candidate
	candidate=$(k get pods -l "blip.dev/pool=$P-pool,blip.dev/warm=true" \
		-o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null) || return 1
	candidate=$(printf '%s\n' "$candidate" |
		awk -v old="$temp_warm" 'NF && $0 != old { print; exit }')
	[ -n "$candidate" ] || return 1
	[ "$(k get pod "$candidate" -o jsonpath='{.status.phase}' 2>/dev/null)" = Running ] || return 1
	replacement=$candidate
}
wait_for "$T" "temporary pool replacement warm pod" c60_replacement_ready || {
	k get pods -l "blip.dev/pool=$P-pool" -o yaml >&2 || true
	exit 1
}
printf 'replacement warm pod: %s\n' "$replacement"

k delete blippool "$P-pool" --wait=false >/dev/null
wait_for "$T" "temporary pool to be removed" c60_pool_gone || {
	k get blippool "$P-pool" -o yaml >&2 || true
	exit 1
}
wait_for "$T" "temporary pool pods to be removed" c60_pool_pods_gone || {
	k get pods -l "blip.dev/pool=$P-pool" -o yaml >&2 || true
	exit 1
}

step "read a command's output from the VM serial console log"
if ! k get blipstate "$P-base" >/dev/null 2>&1; then
	blip pull "$P-base" "$IMG"
	c60_created_base=true
fi
wait_state "$P-base" "$T" || exit 1
console_marker="console-marker-$(date +%s)-$$"
c60_console_out=$(blip run --name "$P-console" --from "$P-base" -e MARKER="$console_marker" -- \
	sh -ec 'echo "$MARKER"; sleep 60')
test "$c60_console_out" = "$P-console"
wait_blip_phase "$P-console" Running "$T" || exit 1
console_pod=$(blip_pod "$P-console")
if [ -z "$console_pod" ]; then
	echo "blip $P-console is Running without a status.pod" >&2
	k get blip "$P-console" -o yaml >&2 || true
	exit 1
fi
c60_log_has_marker() {
	local pod=$1 marker=$2
	k logs "$pod" -c vm 2>/dev/null | grep -qF -- "$marker"
}
wait_for "$T" "serial console marker in the vm container log" \
	c60_log_has_marker "$console_pod" "$console_marker" || {
	k logs "$console_pod" -c vm --tail=50 >&2 || true
	exit 1
}
printf 'console marker found in pod/%s container vm\n' "$console_pod"
k delete blip "$P-console" --wait=false >/dev/null
wait_blip_gone "$P-console" "$T" || exit 1
wait_state_gone "$P-console" "$T" || exit 1
