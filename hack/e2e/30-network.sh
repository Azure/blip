# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# shellcheck shell=bash
# shellcheck disable=SC2016
# Endpoint proxy, in-guest Kubernetes access with owner scoping, and the
# default egress policy.

cleanup_30() {
	k delete blip --ignore-not-found --wait=false \
		"$P-ep" "$P-netpol" "$P-top" "$P-owner.child" "$P-top.evil" >/dev/null 2>&1 || true
	k delete blipstate --ignore-not-found --wait=false \
		"$P-ep" "$P-netpol" "$P-top" "$P-owner.child" "$P-owner.evil" >/dev/null 2>&1 || true
	k delete blippool --ignore-not-found --wait=false \
		"$P-endpoint" >/dev/null 2>&1 || true
}
cleanup_register cleanup_30

is_30_pool_gone() {
	! k get blippool "$1" >/dev/null 2>&1
}

is_30_pool_pods_gone() {
	[ -z "$(k get pods -l "blip.dev/pool=$1" -o name 2>/dev/null || true)" ]
}

is_30_owner() {
	[ "$(k get configmap blip-vm-owners -o jsonpath="{.data['$1']}" 2>/dev/null)" = "$2" ]
}

is_30_identity() {
	# work is provided by hack/e2e.sh, which sources this scenario.
	# shellcheck disable=SC2154
	k get --raw "$identity_path?uid=$identity_pod_uid" >"$work/pod-identity.json" || return 1
	python3 - "$work/pod-identity.json" "$identity_pod" "$identity_pod_uid" \
		"$P-ep" "$identity_blip_uid" "$identity_state_uid" "$P-endpoint" <<'PY'
import json
import sys

path, pod, pod_uid, name, blip_uid, state_uid, pool = sys.argv[1:]
with open(path) as f:
    identity = json.load(f)
expected = {
    "metadata": {"name": pod, "uid": pod_uid},
    "blip": {
        "name": name, "uid": blip_uid, "phase": "Running", "pool": pool,
        "labels": {"e2e.blip.dev/identity": "blip"},
        "annotations": {"e2e.blip.dev/identity": "blip-metadata"},
    },
    "state": {
        "name": name, "uid": state_uid,
        "labels": {"e2e.blip.dev/identity": "state"},
        "annotations": {"e2e.blip.dev/identity": "state-metadata"},
    },
}
for section, fields in expected.items():
    for key, value in fields.items():
        actual = identity.get(section, {}).get(key)
        if isinstance(value, dict):
            if not isinstance(actual, dict) or any(actual.get(k) != v for k, v in value.items()):
                sys.exit(1)
        elif actual != value:
            sys.exit(1)
PY
}

step "apply a temporary pool with a Kubernetes API endpoint"
k apply -f - >/dev/null <<EOF
apiVersion: blip.dev/v1alpha1
kind: BlipPool
metadata:
  name: $P-endpoint
  namespace: default
spec:
  serviceAccountName: blip-agent
  nodeSelector:
    blip.dev/node-pool: default
  warmCount: 1
  cpus: 1
  memory: 1Gi
  endpoints:
    - name: e2e-api
      url: https://kubernetes.default.svc
      caConfigMap: kube-root-ca.crt
EOF

step "probe the endpoint proxy from inside a blip"
blip_shell "$P-ep" --pool "$P-endpoint" --from "$P-base"
expect_ok_grep "endpoint proxy" "endpoint-ok" blip_exec "$P-ep" '
	set -eu
	# The guest name resolves through 127.0.2.2; the sidecar adds the CA and
	# forwards /version to the unauthenticated API server route.
	version=$(curl -fsS --max-time 15 http://e2e-api/version)
	printf "%s" "$version" | grep -q gitVersion
	# Unknown hosts never reach an upstream.
	code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 -H "Host: no-such-endpoint" http://127.0.2.2/)
	test "$code" = 421
	# A CONNECT through the loopback listener is rejected before dialing.
	# curl reports the proxy status in its error, not as an HTTP code.
	err=$(curl -sS -o /dev/null --max-time 10 -x http://127.0.2.2:80 https://example.invalid/ 2>&1 || true)
	case "$err" in
	*"response 405"*) ;;
	*)
		echo "CONNECT was not rejected with 405: $err"
		exit 1
		;;
	esac
	echo endpoint-ok
'

step "resolve the endpoint pod's current identity and metadata"
k wait --for=condition=Available apiservice/v1alpha1.identity.blip.dev --timeout=120s
identity_pod=$(blip_pod "$P-ep")
test -n "$identity_pod"
identity_pod_uid=$(k get pod "$identity_pod" -o jsonpath='{.metadata.uid}')
identity_blip_uid=$(k get blip "$P-ep" -o jsonpath='{.metadata.uid}')
identity_state_uid=$(k get blipstate "$P-ep" -o jsonpath='{.metadata.uid}')
identity_path="/apis/identity.blip.dev/v1alpha1/namespaces/default/podidentities/$identity_pod"
k label blip "$P-ep" e2e.blip.dev/identity=blip >/dev/null
k annotate blip "$P-ep" e2e.blip.dev/identity=blip-metadata >/dev/null
k label blipstate "$P-ep" e2e.blip.dev/identity=state >/dev/null
k annotate blipstate "$P-ep" e2e.blip.dev/identity=state-metadata >/dev/null
wait_for 120 "current pod identity and propagated metadata" is_30_identity

step "reject a pod identity request with the wrong UID"
expect_fail_grep "pod identity UID mismatch" NotFound \
	k get --raw "$identity_path?uid=00000000-0000-0000-0000-000000000000"

step "deny pod identity access to the VM service account"
expect_ok_grep "VM cannot read pod identities" "identity-forbidden-ok" \
	blip_exec "$P-ep" "IDENTITY_PATH=$identity_path?uid=$identity_pod_uid
"'
	set -eu
	code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 15 "http://kube-apiserver$IDENTITY_PATH")
	test "$code" = 403
	echo identity-forbidden-ok
'

step "delete the endpoint blip and pool and verify cleanup"
k delete blip "$P-ep" --ignore-not-found --wait=false >/dev/null
wait_blip_gone "$P-ep"
wait_state_gone "$P-ep"
k delete blippool "$P-endpoint" --ignore-not-found --wait=false >/dev/null
wait_for 120 "pool $P-endpoint to be removed" is_30_pool_gone "$P-endpoint"
wait_for 120 "pool $P-endpoint pods to be removed" is_30_pool_pods_gone "$P-endpoint"

step "run a top-level blip and check unrestricted in-guest Kubernetes access"
blip_shell "$P-top" --from "$P-base"
expect_ok_grep "top-level blip lists blips" "$P-top" \
	blip_exec "$P-top" 'kubectl get blips -o name'

step "create a child inside the parent and give it a restricted owner"
# A top-level blip has no owner label, so a child started from it is
# unrestricted too. Name the child under an owner prefix and label both it
# and its root state after the fork has committed; the controller then
# records that owner for the child's VM token and keeps the state usable.
child=$(blip_exec "$P-top" "blip run --name '$P-owner.child' --interactive --from / -- bash")
test "$child" = "$P-owner.child"
wait_blip_phase "$child" Running
pod=$(blip_pod "$child")
test -n "$pod"
k patch blipstate "$child" --type merge -p "$(cat <<EOF
{"metadata":{"labels":{"blip.dev/owner":"$P-owner"}}}
EOF
)" >/dev/null
k patch blip "$child" --type merge -p "$(cat <<EOF
{"metadata":{"labels":{"blip.dev/owner":"$P-owner"}}}
EOF
)" >/dev/null
wait_for 120 "owner table entry for $pod" is_30_owner "$pod" "$P-owner"
# Let the admission policy's ConfigMap informer observe the same table entry.
sleep 2

step "verify the child's owner-scoped reads and writes"
expect_ok_grep "owner-scoped child" "child-scope-ok" blip_exec "$child" \
	"CHILD=$child BASE=$P-base ROOT=$P-top OWNER=$P-owner
"'
	set -eu
	ns=$(cat /run/blip/namespace)
	api=http://kube-apiserver
	# Own blip and the shared base are readable by name.
	code=$(curl -sS -o /dev/null -w "%{http_code}" "$api/apis/blip.dev/v1alpha1/namespaces/$ns/blips/$CHILD")
	test "$code" = 200
	code=$(curl -sS -o /dev/null -w "%{http_code}" "$api/apis/blip.dev/v1alpha1/namespaces/$ns/blipstates/$BASE")
	test "$code" = 200
	# The unlabelled parent is administrator-private and must look absent.
	code=$(curl -sS -o /dev/null -w "%{http_code}" "$api/apis/blip.dev/v1alpha1/namespaces/$ns/blips/$ROOT")
	test "$code" = 404
	# Admission must stop a name outside the owner prefix before it is stored.
	err=$(mktemp)
	if kubectl create -f - >"$err" 2>&1 <<-EOF
	apiVersion: blip.dev/v1alpha1
	kind: Blip
	metadata:
	  name: $ROOT.evil
	  labels:
	    blip.dev/owner: $OWNER
	spec:
	  pool: default
	  state: $OWNER.evil
	  command: ["true"]
	EOF
	then
		echo "creating $ROOT.evil was accepted"
		cat "$err"
		exit 1
	fi
	grep -q "may only write objects named $OWNER." "$err"
	echo child-scope-ok
'

step "delete the owner-scoped child and its parent"
k delete blip "$child" "$P-top" --ignore-not-found --wait=false >/dev/null
wait_blip_gone "$child"
wait_blip_gone "$P-top"
wait_state_gone "$child"
wait_state_gone "$P-top"

step "run a blip on the default pool and check its egress policy"
blip_shell "$P-netpol" --from "$P-base"
expect_ok_grep "default egress policy" "netpol-default-ok" blip_exec "$P-netpol" '
	set -eu
	# The default pool uses public resolvers, so public DNS is allowed while
	# cluster DNS, private ranges, and metadata are not. The public 443 probe
	# is the only outside dependency and is retried.
	timeout 15 getent ahostsv4 example.com >/dev/null
	code=$(timeout 8 curl -sS -o /dev/null -w "%{http_code}" --max-time 5 http://10.96.0.1/ 2>/dev/null || true)
	test "$code" = 000
	code=$(timeout 8 curl -sS -o /dev/null -w "%{http_code}" --max-time 5 http://169.254.169.254/ 2>/dev/null || true)
	test "$code" = 000
	i=0
	until curl -4 -fsS --max-time 15 -o /dev/null https://example.com; do
		i=$((i + 1))
		if [ "$i" -ge 5 ]; then
			echo "public egress failed under the default policy"
			exit 1
		fi
		sleep 1
	done
	echo netpol-default-ok
'

step "deny all egress on the running blip"
k patch blip "$P-netpol" --type merge -p '{"spec":{"network":{}}}' >/dev/null
expect_ok_grep "denied egress policy" "netpol-denied-ok" blip_exec "$P-netpol" '
	set -eu
	# The runtime applies the new policy to the running VM; poll until the
	# public request is denied, then check DNS and private ranges too.
	sleep 3
	i=0
	while [ "$i" -lt 30 ]; do
		if ! curl -4 -fsS --max-time 3 -o /dev/null https://example.com 2>/dev/null; then
			break
		fi
		i=$((i + 1))
		sleep 1
	done
	test "$i" -lt 30
	if timeout 10 getent ahostsv4 example.com >/dev/null 2>&1; then
		echo "public DNS still resolves after denial"
		exit 1
	fi
	code=$(timeout 8 curl -sS -o /dev/null -w "%{http_code}" --max-time 5 http://10.96.0.1/ 2>/dev/null || true)
	test "$code" = 000
	code=$(timeout 8 curl -sS -o /dev/null -w "%{http_code}" --max-time 5 http://169.254.169.254/ 2>/dev/null || true)
	test "$code" = 000
	echo netpol-denied-ok
'

step "delete the network policy blip"
k delete blip "$P-netpol" --ignore-not-found --wait=false >/dev/null
wait_blip_gone "$P-netpol"
wait_state_gone "$P-netpol"
