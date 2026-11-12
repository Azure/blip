#!/usr/bin/env bash
# Check CRD validation, defaults, admission policies and RBAC against the kind
# cluster. Needs CRDs, policies and RBAC applied (not the workloads).
set -uo pipefail

fail=0
ok() { echo "PASS: $*"; }
bad() { echo "FAIL: $*"; fail=1; }
# expect_deny DESC CMD...: CMD must fail.
expect_deny() { local d=$1; shift; if out=$("$@" 2>&1); then bad "$d (allowed)"; else ok "$d: $(echo "$out" | tail -1 | cut -c1-160)"; fi; }
expect_allow() { local d=$1; shift; if out=$("$@" 2>&1); then ok "$d"; else bad "$d: $out"; fi; }

# Pin the context: the current one may be a real cluster.
KC="kubectl --context kind-${KIND_CLUSTER:-blip}"
K="$KC"
for ns in blip-t1 blip-t2; do $K create ns $ns --dry-run=client -o yaml | $K apply -f - >/dev/null; done
$K -n blip-t1 delete blips,blipvols --all --timeout=60s >/dev/null 2>&1
$K -n blip-t2 delete rolebinding tenant-get-base --ignore-not-found >/dev/null
# Tenant SA with edit in blip-t1 only.
$K -n blip-t1 create sa tenant --dry-run=client -o yaml | $K apply -f - >/dev/null
$K -n blip-t1 create rolebinding tenant-edit --clusterrole=edit --serviceaccount=blip-t1:tenant --dry-run=client -o yaml | $K apply -f - >/dev/null
T="$KC --as=system:serviceaccount:blip-t1:tenant -n blip-t1"
C="$KC --as=system:serviceaccount:blip-system:blip-controller"

$K -n blip-t2 apply -f - >/dev/null <<EOF
apiVersion: blip.example.com/v1alpha1
kind: BlipVol
metadata: {name: base}
spec: {}
EOF

echo "== defaults"
$T apply -f - >/dev/null <<EOF
apiVersion: blip.example.com/v1alpha1
kind: Blip
metadata: {name: b1}
spec:
  rootVolume: root
  volumes: [{name: root, blipVolRef: {name: v1}}]
EOF
got=$($K -n blip-t1 get blip b1 -o jsonpath='{.spec.sku} {.spec.init} {.spec.serviceAccountName} {.spec.maxTTLSeconds} {.spec.ttlSecondsAfterFinished}')
[[ $got == 'default ["/sbin/init"] default 3600 300' ]] && ok "Blip defaults: $got" || bad "Blip defaults: $got"

echo "== CEL validation"
B() { echo '{"apiVersion":"blip.example.com/v1alpha1","kind":"Blip","metadata":{"name":"'"$1"'"},"spec":'"$2"'}'; }
expect_deny "empty init" $T create -f - <<<"$(B b2 '{"rootVolume":"root","volumes":[{"name":"root","blipVolRef":{"name":"v"}}],"init":[]}')"
expect_deny "relative init[0]" $T create -f - <<<"$(B b2 '{"rootVolume":"root","volumes":[{"name":"root","blipVolRef":{"name":"v"}}],"init":["sbin/init"]}')"
expect_deny "rootVolume not in volumes" $T create -f - <<<"$(B b2 '{"rootVolume":"other","volumes":[{"name":"root","blipVolRef":{"name":"v"}}]}')"
expect_deny "no volumes" $T create -f - <<<"$(B b2 '{"rootVolume":"root","volumes":[]}')"
v21=$(printf 'a%.0s' {1..21})
expect_deny "21-char volume name" $T create -f - <<<"$(B b2 '{"rootVolume":"'"$v21"'","volumes":[{"name":"'"$v21"'","blipVolRef":{"name":"v"}}]}')"
expect_deny "reserved volume name blip-meta" $T create -f - <<<"$(B b2 '{"rootVolume":"blip-meta","volumes":[{"name":"blip-meta","blipVolRef":{"name":"v"}}]}')"
expect_deny "maxTTLSeconds too large" $T create -f - <<<"$(B b2 '{"rootVolume":"root","volumes":[{"name":"root","blipVolRef":{"name":"v"}}],"maxTTLSeconds":604801}')"
expect_deny "maxTTLSeconds zero" $T create -f - <<<"$(B b2 '{"rootVolume":"root","volumes":[{"name":"root","blipVolRef":{"name":"v"}}],"maxTTLSeconds":0}')"
n58=$(printf 'a%.0s' {1..58})
expect_deny "58-char Blip name" $T create -f - <<<"$(B "$n58" '{"rootVolume":"root","volumes":[{"name":"root","blipVolRef":{"name":"v"}}]}')"
n57=$(printf 'a%.0s' {1..57})
expect_allow "57-char Blip name" $T create -f - <<<"$(B "$n57" '{"rootVolume":"root","volumes":[{"name":"root","blipVolRef":{"name":"v"}}]}')"
expect_deny "change spec.init" $T patch blip b1 --type=merge -p '{"spec":{"init":["/bin/false"]}}'
expect_deny "change spec.rootMountOptions" $T patch blip b1 --type=merge -p '{"spec":{"rootMountOptions":"ro"}}'
expect_deny "change spec.sku" $T patch blip b1 --type=merge -p '{"spec":{"sku":"big"}}'
expect_deny "remove root volume" $T patch blip b1 --type=json -p '[{"op":"replace","path":"/spec/volumes","value":[{"name":"data","blipVolRef":{"name":"v1"}}]}]'
expect_allow "add a volume" $T patch blip b1 --type=json -p '[{"op":"add","path":"/spec/volumes/-","value":{"name":"data","blipVolRef":{"name":"v1"}}}]'
expect_allow "change ttlSecondsAfterFinished" $T patch blip b1 --type=merge -p '{"spec":{"ttlSecondsAfterFinished":5}}'
expect_deny "tenant writes blips/status" $T patch blip b1 --subresource=status --type=merge -p '{"status":{"phase":"Running"}}'
expect_allow "controller writes blips/status" $C -n blip-t1 patch blip b1 --subresource=status --type=merge -p '{"status":{"phase":"Running","restartCount":2}}'

expect_deny "BlipVol image and parent" $T create -f - <<EOF
{"apiVersion":"blip.example.com/v1alpha1","kind":"BlipVol","metadata":{"name":"v2"},"spec":{"image":{"reference":"busybox"},"parent":{"name":"x"}}}
EOF
expect_deny "BlipVol size with parent" $T create -f - <<EOF
{"apiVersion":"blip.example.com/v1alpha1","kind":"BlipVol","metadata":{"name":"v2"},"spec":{"size":"1Gi","parent":{"name":"x"}}}
EOF
expect_allow "BlipVol image" $T create -f - <<EOF
{"apiVersion":"blip.example.com/v1alpha1","kind":"BlipVol","metadata":{"name":"v1"},"spec":{"image":{"reference":"busybox"},"size":"1Gi"}}
EOF
expect_deny "change BlipVol spec" $T patch blipvol v1 --type=merge -p '{"spec":{"size":"2Gi"}}'
expect_allow "change BlipVol snapshotPolicy" $T patch blipvol v1 --type=merge -p '{"spec":{"snapshotPolicy":{"limit":3,"interval":"10m"}}}'
expect_deny "BlipVol interval below 5m" $T patch blipvol v1 --type=merge -p '{"spec":{"snapshotPolicy":{"interval":"1m"}}}'

echo "== admission policies"
expect_deny "tenant creates with blip.example.com/ label" $T create -f - <<EOF
{"apiVersion":"blip.example.com/v1alpha1","kind":"BlipVol","metadata":{"name":"v3","labels":{"blip.example.com/lineage":"x"}},"spec":{}}
EOF
expect_deny "tenant adds blip.example.com/ label" $T label blipvol v1 blip.example.com/created-by=b1
expect_allow "tenant adds other label" $T label blipvol v1 team=a --overwrite
expect_allow "controller adds blip.example.com/ label" $C -n blip-t1 label blipvol v1 blip.example.com/lineage=abc --overwrite
expect_deny "tenant changes blip.example.com/ label" $T label blipvol v1 blip.example.com/lineage=zzz --overwrite
expect_deny "tenant removes blip.example.com/ label" $T label blipvol v1 blip.example.com/lineage-
expect_allow "controller creates with blip.example.com/ label" $C -n blip-t1 create -f - <<EOF
{"apiVersion":"blip.example.com/v1alpha1","kind":"BlipVol","metadata":{"name":"out1","labels":{"blip.example.com/lineage":"b1"}},"spec":{}}
EOF
expect_deny "cross-namespace parent without get" $T create -f - <<EOF
{"apiVersion":"blip.example.com/v1alpha1","kind":"BlipVol","metadata":{"name":"c1"},"spec":{"parent":{"namespace":"blip-t2","name":"base"}}}
EOF
$K -n blip-t2 create role get-base --verb=get --resource=blipvols.blip.example.com --resource-name=base --dry-run=client -o yaml | $K apply -f - >/dev/null
$K -n blip-t2 create rolebinding tenant-get-base --role=get-base --serviceaccount=blip-t1:tenant --dry-run=client -o yaml | $K apply -f - >/dev/null
sleep 2
expect_allow "cross-namespace parent with get" $T create -f - <<EOF
{"apiVersion":"blip.example.com/v1alpha1","kind":"BlipVol","metadata":{"name":"c1"},"spec":{"parent":{"namespace":"blip-t2","name":"base"}}}
EOF
expect_allow "same-namespace parent" $T create -f - <<EOF
{"apiVersion":"blip.example.com/v1alpha1","kind":"BlipVol","metadata":{"name":"c2"},"spec":{"parent":{"name":"v1"}}}
EOF

# Slot pods (policies 4, 5 and 7). The BlipPool only provides an owner for
# the test pods: their pool label names no BlipPool, so a running controller
# (which lists a pool's pods by that label) leaves them alone.
$K -n blip-t1 delete pods -l blip.example.com/slot --now --ignore-not-found >/dev/null
$K -n blip-t1 delete pod plain --now --ignore-not-found >/dev/null
$K -n blip-t1 apply -f - >/dev/null <<EOF
apiVersion: blip.example.com/v1alpha1
kind: BlipPool
metadata: {name: default}
spec: {cpus: 1, memory: 512Mi, minFree: 0, maxFree: 0}
EOF
puid=$($K -n blip-t1 get blippool default -o jsonpath='{.metadata.uid}')
# slotpod NAME [JQ]: a free slot pod shaped like the controller's, edited by JQ.
slotpod() {
  jq -n --arg name "$1" --arg uid "$puid" '{
    apiVersion: "v1", kind: "Pod",
    metadata: {name: $name,
      labels: {"blip.example.com/slot": "free", "blip.example.com/sku": "default", "blip.example.com/pool": "verify-api"},
      ownerReferences: [{apiVersion: "blip.example.com/v1alpha1", kind: "BlipPool", name: "default", uid: $uid, controller: true, blockOwnerDeletion: true}]},
    spec: {automountServiceAccountToken: false, enableServiceLinks: false, nodeSelector: {none: "none"},
      containers: [{name: "slot", image: "registry.k8s.io/pause:3.10",
        securityContext: {capabilities: {add: ["NET_ADMIN"]}, seccompProfile: {type: "RuntimeDefault"}}}]}
  }' | jq "${2:-.}"
}
expect_deny "tenant creates slot pod" $T create -f - <<<"$(slotpod s0)"
expect_deny "admin creates slot pod" $K -n blip-t1 create -f - <<<"$(slotpod s0)"
expect_deny "controller creates non-slot pod" $C -n blip-t1 create -f - <<<"$(slotpod s0 'del(.metadata.labels)')"
expect_deny "controller creates assigned slot pod" $C -n blip-t1 create -f - <<<"$(slotpod s0 '.metadata.labels["blip.example.com/slot"] = "assigned"')"
expect_deny "controller creates slot pod without pool label" $C -n blip-t1 create -f - <<<"$(slotpod s0 'del(.metadata.labels["blip.example.com/pool"])')"
expect_deny "controller creates slot pod without owner" $C -n blip-t1 create -f - <<<"$(slotpod s0 'del(.metadata.ownerReferences)')"
expect_deny "controller creates slot pod owned by a ReplicaSet" $C -n blip-t1 create -f - <<<"$(slotpod s0 '.metadata.ownerReferences[0] |= (.apiVersion = "apps/v1" | .kind = "ReplicaSet")')"
expect_deny "controller creates slot pod with a volume" $C -n blip-t1 create -f - <<<"$(slotpod s0 '.spec.volumes = [{name: "h", hostPath: {path: "/"}}]')"
expect_deny "controller creates slot pod with two containers" $C -n blip-t1 create -f - <<<"$(slotpod s0 '.spec.containers += [.spec.containers[0] | .name = "x"]')"
expect_deny "controller creates privileged slot pod" $C -n blip-t1 create -f - <<<"$(slotpod s0 '.spec.containers[0].securityContext.privileged = true')"
expect_deny "controller creates slot pod with SYS_ADMIN" $C -n blip-t1 create -f - <<<"$(slotpod s0 '.spec.containers[0].securityContext.capabilities.add += ["SYS_ADMIN"]')"
expect_deny "controller creates slot pod with hostNetwork" $C -n blip-t1 create -f - <<<"$(slotpod s0 '.spec.hostNetwork = true')"
expect_deny "controller creates slot pod with a token" $C -n blip-t1 create -f - <<<"$(slotpod s0 'del(.spec.automountServiceAccountToken)')"
expect_allow "controller creates slot pod a" $C -n blip-t1 create -f - <<<"$(slotpod slot-a)"
expect_allow "controller creates slot pod f" $C -n blip-t1 create -f - <<<"$(slotpod slot-f)"
expect_allow "tenant creates a plain pod" $T run plain --image=registry.k8s.io/pause:3.10 --restart=Never --overrides='{"spec":{"nodeSelector":{"none":"none"}}}'
expect_deny "tenant labels its pod as a slot" $T label pod plain blip.example.com/slot=free
expect_deny "tenant changes a slot label" $T label pod slot-a blip.example.com/slot=assigned --overwrite
# Claiming strips the pool owner reference.
expect_allow "controller claims slot a" $C -n blip-t1 patch pod slot-a --type=json -p '[{"op":"replace","path":"/metadata/labels/blip.example.com~1slot","value":"assigned"},{"op":"remove","path":"/metadata/ownerReferences"}]'
G="$KC --as=system:serviceaccount:kube-system:generic-garbage-collector --as-group=system:serviceaccounts -n blip-t1"
expect_deny "garbage collector deletes assigned slot" $G delete pod slot-a --wait=false
expect_allow "garbage collector deletes free slot" $G delete pod slot-f --wait=false
expect_allow "controller deletes assigned slot" $C -n blip-t1 delete pod slot-a --wait=false
$K -n blip-t1 delete pod plain --now --ignore-not-found >/dev/null

echo "== RBAC"
[[ $($T auth can-i create blips.blip.example.com 2>/dev/null) == yes ]] && ok "edit can create blips" || bad "edit create blips"
[[ $($T auth can-i patch blips.blip.example.com --subresource=status 2>/dev/null) == no ]] && ok "edit cannot patch blips/status" || bad "edit status"
[[ $($T auth can-i list pods -n blip-system 2>/dev/null) == no ]] && ok "tenant has no access to blip-system" || bad "tenant blip-system"
$K -n blip-t1 create rolebinding v --clusterrole=view --user=viewer --dry-run=client -o yaml | $K apply -f - >/dev/null
[[ $($K -n blip-t1 auth can-i list blipvols.blip.example.com --as=viewer) == yes && $($K -n blip-t1 auth can-i create blips.blip.example.com --as=viewer 2>/dev/null) == no ]] && ok "view can list but not create" || bad "view"
[[ $($K -n blip-t1 auth can-i list blippools.blip.example.com --as=viewer) == yes ]] && ok "view can list blippools" || bad "view blippools"
[[ $($T auth can-i create blippools.blip.example.com 2>/dev/null) == no && $($T auth can-i patch blippools.blip.example.com 2>/dev/null) == no ]] && ok "edit cannot write blippools" || bad "edit blippools"
[[ $($K auth can-i --list --as=system:serviceaccount:blip-system:blip-node -n blip-system | grep -c blip.example.com) == 0 ]] && ok "node SA has no Blip permissions" || bad "node SA"

echo "== printer columns"
$K -n blip-t1 get blips b1
$C -n blip-t1 get blipvols
$K -n blip-t1 get blippools

exit $fail
