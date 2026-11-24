# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# shellcheck shell=bash
# shellcheck disable=SC2016,SC2154
# Pool and placement fields: guest CPUs, memory, and DNS from the pool spec,
# tolerations and imagePullSecrets on the pool's pods, the idle timeout,
# status.locality, and a BlipState nodeSelector.

cleanup_25() {
	k delete blip --ignore-not-found --wait=false \
		"$P-shape25" "$P-idle25" "$P-sel25" >/dev/null 2>&1 || true
	k delete blipstate --ignore-not-found --wait=false \
		"$P-shape25" "$P-idle25" "$P-sel25" >/dev/null 2>&1 || true
	k delete blippool --ignore-not-found --wait=false "$P-pool25" >/dev/null 2>&1 || true
	k delete secret --ignore-not-found --wait=false "$P-pull25" >/dev/null 2>&1 || true
}
cleanup_register cleanup_25

has_pool_pod_25() {
	[ -n "$(k get pods -l "blip.dev/pool=$P-pool25" -o name 2>/dev/null)" ]
}

step "apply a temporary pool with a custom shape, DNS, toleration, and pull secret"
k create secret docker-registry "$P-pull25" --docker-server=e2e.invalid \
	--docker-username=e2e --docker-password=e2e >/dev/null
k apply -f - >/dev/null <<EOF
apiVersion: blip.dev/v1alpha1
kind: BlipPool
metadata:
  name: $P-pool25
  namespace: default
spec:
  serviceAccountName: blip-agent
  nodeSelector:
    blip.dev/node-pool: default
  warmCount: 1
  cpus: 2
  memory: 1536Mi
  dns:
    nameservers: ["9.9.9.9", "149.112.112.112"]
  tolerations:
    - key: e2e.blip.dev/$P-pool25
      operator: Exists
      effect: NoSchedule
  imagePullSecrets:
    - name: $P-pull25
EOF

step "the pool's pods carry its toleration and imagePullSecrets"
wait_for "$T" "a pod for pool $P-pool25" has_pool_pod_25
pod25=$(k get pods -l "blip.dev/pool=$P-pool25" -o name | awk 'NR == 1')
k get "$pod25" -o jsonpath='{.spec.tolerations[?(@.key=="e2e.blip.dev/'"$P-pool25"'")].effect}' |
	grep -qx NoSchedule
k get "$pod25" -o jsonpath='{.spec.imagePullSecrets[*].name}' | grep -qw "$P-pull25"

step "the guest sees the pool's CPUs, memory, and nameservers"
blip_shell "$P-shape25" --pool "$P-pool25" --from "$P-base"
expect_ok_grep "guest shape" "shape-ok" blip_exec "$P-shape25" '
	set -eu
	test "$(nproc)" = 2
	kb=$(awk "/^MemTotal:/ {print \$2}" /proc/meminfo)
	# 1536Mi is 1572864 KiB; the kernel reserves some of it.
	if [ "$kb" -gt 1572864 ] || [ "$kb" -lt 1300000 ]; then
		echo "MemTotal $kb KiB does not match 1536Mi"
		exit 1
	fi
	test "$(awk "/^nameserver/ {print \$2}" /etc/resolv.conf | paste -sd, -)" = 9.9.9.9,149.112.112.112
	echo shape-ok
'
k delete blip --wait=false "$P-shape25" >/dev/null
wait_blip_gone "$P-shape25" "$T"

step "a state nodeSelector keeps its replicas on matching nodes"
sel_node25=$(k get blipnodes -o jsonpath='{.items[0].metadata.name}')
test -n "$sel_node25"
k apply -f - >/dev/null <<EOF
apiVersion: blip.dev/v1alpha1
kind: BlipState
metadata:
  name: $P-sel25
  namespace: default
spec:
  copyFrom: $P-base
  replicas: 1
  nodeSelector:
    kubernetes.io/hostname: $sel_node25
EOF
wait_state "$P-sel25" "$T"
test "$(k get blipstate "$P-sel25" -o jsonpath='{.status.nodes[*].node}' | tr ' ' '\n' | sort -u)" = "$sel_node25"

step "a blip on that state records its locality and runs on the data node"
k apply -f - >/dev/null <<EOF
apiVersion: blip.dev/v1alpha1
kind: Blip
metadata:
  name: $P-sel25
  namespace: default
spec:
  pool: $P-pool25
  state: $P-sel25
  command: ["sleep", "600"]
EOF
wait_blip_phase "$P-sel25" Running "$T"
test "$(blip_field "$P-sel25" '{.status.locality.node}')" = "$sel_node25"
test "$(blip_field "$P-sel25" '{.status.locality.fallback}')" != true
test "$(k get pod "$(blip_pod "$P-sel25")" -o jsonpath='{.spec.nodeName}')" = "$sel_node25"
k delete blip --wait=false "$P-sel25" >/dev/null
wait_blip_gone "$P-sel25" "$T"
wait_state "$P-sel25" "$T"
test "$(k get blipstate "$P-sel25" -o jsonpath='{.status.nodes[*].node}' | tr ' ' '\n' | sort -u)" = "$sel_node25"

step "idleTimeoutSeconds stops a silent blip and saves its root"
k apply -f - >/dev/null <<EOF
apiVersion: blip.dev/v1alpha1
kind: BlipState
metadata:
  name: $P-idle25
  namespace: default
spec:
  copyFrom: $P-base
---
apiVersion: blip.dev/v1alpha1
kind: Blip
metadata:
  name: $P-idle25
  namespace: default
spec:
  pool: $P-pool25
  state: $P-idle25
  idleTimeoutSeconds: 10
  command: ["sleep", "600"]
EOF
wait_blip_phase "$P-idle25" Running "$T"
# The command sleeps for 600s, so finishing well before that means the idle
# stop ran.
wait_blip_phase "$P-idle25" Succeeded 180
test -z "$(blip_field "$P-idle25" '{.status.exitCode}')"
test "$(blip_field "$P-idle25" '{.status.reason}')" = Idle
