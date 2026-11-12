#!/usr/bin/env bash
# End-to-end test of Blip on the kind cluster from hack/kind/up.sh, with the
# system deployed (make guest images kind-load deploy). Safe to run again: it
# deletes its namespaces before and after the run.
#
# Usage: hack/e2e/run.sh [check...]
#   E2E_ONLY=a,b    run only these checks (same as passing them as arguments)
#   E2E_KEEP=1      keep the namespaces after the run for debugging
#   E2E_FAILFAST=1  stop at the first failing check
#   E2E_PARALLEL=N  run up to N checks at a time (default 4; see docs/e2e.md)
#   E2E_LOG_DIR=d   per-check logs (default /tmp/opencode/blip-e2e-logs/<time>)
#   KIND_CLUSTER=n  kind cluster to test (default blip); the script writes
#                   its kubeconfig and exports KUBECONFIG, so the current
#                   kubectl context does not matter
#   E2E_KUBECONFIG=f use this kubeconfig as is instead
#   E2E_IMAGE=ref   root image; must be built from images/blip-e2e. By
#                   default the script builds bin/blip-meta and the image,
#                   pushes it to the local registry (hack/registry/up.sh)
#                   and uses it by digest
#   E2E_UBUNTU_IMAGE=ref  SSH guest image for the plugin check; must be built
#                   from images/blip-ubuntu. By default the script builds
#                   and pushes it like E2E_IMAGE
# See docs/e2e.md for the list of checks. With no selection, all run in order.
#
# Guests have no agent: every Blip boots images/blip-e2e with
# spec.init [/sbin/blip-e2e-init, MODE, ARGS...]. The init script brings up
# DHCP, credentials and a power button watcher, runs MODE, records the exit
# code with `blip-meta exit` and powers off.
set -uo pipefail

# Bash reads a script as it runs: run a private copy, so the script can be
# edited during a run.
if [[ -z ${E2E_SCRIPT_COPY:-} ]]; then
  mkdir -p /tmp/opencode
  E2E_SCRIPT_COPY=$(mktemp /tmp/opencode/blip-e2e-run.XXXXXX)
  cp "${BASH_SOURCE[0]}" "$E2E_SCRIPT_COPY"
  E2E_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
  export E2E_ROOT E2E_SCRIPT_COPY
  exec bash "$E2E_SCRIPT_COPY" "$@"
fi
rm -f "$E2E_SCRIPT_COPY"

NS=${E2E_NAMESPACE:-blip-e2e}
NSQ=$NS-quota
SYS=blip-system
ROOT=${E2E_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}
IMAGE=${E2E_IMAGE:-}
E2E_TAG=blip-e2e:dev
UBUNTU_IMAGE=${E2E_UBUNTU_IMAGE:-}
UBUNTU_TAG=blip-ubuntu:dev
DIAG=${E2E_DIAG_DIR:-/tmp/opencode/blip-e2e-diag}
T="timeout -s TERM"
GROUP=blip.example.com
SIZE=64Mi
# Go builds use the repository's private cache (see hack/go.sh).
GOB="$ROOT/hack/go.sh"

# Pin every kubectl call (including those in sh -c) to the kind cluster.
if [ -n "${E2E_KUBECONFIG:-}" ]; then
  export KUBECONFIG=$E2E_KUBECONFIG
else
  mkdir -p /tmp/opencode
  export KUBECONFIG=/tmp/opencode/e2e-${KIND_CLUSTER:-blip}.kubeconfig
  $T 60 kind get kubeconfig --name "${KIND_CLUSTER:-blip}" >"$KUBECONFIG" ||
    { echo "cannot get kubeconfig of kind cluster ${KIND_CLUSTER:-blip}" >&2; exit 1; }
fi

ALL=(health image chain net tls datavols hotplug forcedetach never ttl cancel poweroff reboot panic initexit move portfwd
  periodic exclusive delblock blankroot quota pool plugin nested resched derive compact nodeloss)

# ---------------------------------------------------------------- helpers

log() { echo "[$(date +%T)] + $*" >&2; }
ok() { echo "[$(date +%T)] PASS: ${CHECK:-}: $*"; }
die() {
  trap - ERR
  set +eE
  echo "[$(date +%T)] FAIL: ${CHECK:-}: $*" >&2
  dump_diag
  exit 1
}
k() { $T 60 kubectl "$@"; }
kn() { k -n "${BNS:-$NS}" "$@"; }

cleanup_ns() {
  $T 400 kubectl delete ns "$NS" "$NSQ" --ignore-not-found --wait=true --timeout=380s >/dev/null 2>&1 ||
    echo "WARNING: namespaces not deleted in time" >&2
}

# create_ns NS [MINFREE MAXFREE MAXSLOTS]: create a tenant namespace with its
# BlipPool (each namespace is its own pool; config/overlays/kind/slots/common),
# optionally resized. Kind has 6 hypervisor devices in total.
create_ns() {
  k create ns "$1" >/dev/null 2>&1 || true
  $T 60 kubectl kustomize "$ROOT/config/overlays/kind/slots/common" | k -n "$1" apply -f - >/dev/null || return 1
  [[ $# -lt 4 ]] || k -n "$1" patch blippool default --type=merge \
    -p "{\"spec\":{\"minFree\":$2,\"maxFree\":$3,\"maxSlots\":$4}}" >/dev/null
}

# pool_count STATE: status.STATE (free, booting, assigned) of blippool/default.
pool_count() { local n; n=$(field blippool/default "{.status.$1}"); echo "${n:-0}"; }

# dump_diag: write and print a diagnostics summary for the current check.
dump_diag() {
  mkdir -p "$DIAG"
  local f ns
  f="$DIAG/${CHECK:-run}-$(date +%H%M%S).txt"
  {
    for ns in "$NS" "$NSQ"; do
      echo "=== namespace $ns"
      $T 30 kubectl -n "$ns" get blips,blipvols,blippools -o wide --show-labels 2>&1
      $T 30 kubectl -n "$ns" get blips -l "e2e-check=${CHECK:-none}" -o yaml 2>&1
      $T 30 kubectl -n "$ns" describe blips 2>&1 | tail -n 200
      $T 30 kubectl -n "$ns" get blipvols -o json 2>&1 | jq -c '.items[]? | {name: .metadata.name, del: .metadata.deletionTimestamp,
          phase: .status.phase, current: .status.current, last: .status.lastSequence, origin: .status.origin, claim: .status.claim,
          holds: .status.holds, snapshots: [.status.snapshots[]? | {sequence, reason, state, base, writer: .writer.blipName,
          replicas: [.replicas[]? | .node + "=" + .state], message}],
          conditions: [.status.conditions[]? | {type, status, reason, message}]}' 2>&1 | head -n 200
    done
    echo "=== pods"
    $T 30 kubectl -n $SYS get pods -o wide 2>&1
    $T 30 kubectl get pods -A -l $GROUP/slot -o wide --show-labels 2>&1
    echo "=== controller log"
    $T 30 kubectl -n $SYS logs deploy/blip-controller --tail=300 2>&1
    local p
    for p in $($T 30 kubectl -n $SYS get pods -l app.kubernetes.io/name=blip-node -o name 2>/dev/null); do
      echo "=== $p"
      $T 30 kubectl -n $SYS logs "$p" --all-containers --tail=120 2>&1
    done
  } >"$f"
  echo "--- diagnostics written to $f; tail:" >&2
  grep -E 'level=(ERROR|WARN)|"level":"(error|warn)"' "$f" | tail -n 30 >&2 || true
}

# poll SECS DESC CMD...: run CMD every second until it succeeds.
poll() {
  local secs=$1 desc=$2 end=$((SECONDS + $1))
  shift 2
  until "$@" >/dev/null 2>&1; do
    [[ $SECONDS -lt $end ]] || die "timed out after ${secs}s waiting for $desc"
    sleep 1
  done
}

# wait_cond KIND/NAME CONDITION SECONDS
wait_cond() {
  $T $(($3 + 10)) kubectl -n "${BNS:-$NS}" wait "$1" --for=condition="$2" --timeout="$3s" >/dev/null 2>&1
}

json() { kn get "$1" -o json; }
field() { kn get "$1" -o jsonpath="$2"; }
reason() { field "blip/$1" "{.status.conditions[?(@.type==\"$2\")].reason}"; }

# vol NAME BLIPVOL: one spec.volumes entry.
vol() { jq -nc --arg n "$1" --arg r "$2" '{name: $n, blipVolRef: {name: $r}}'; }

# blip NAME TTL VOLUMES-JSON MODE [ARG...]: create a Blip with root "root"
# booting spec.init [/sbin/blip-e2e-init, MODE, ARG...] (see
# images/blip-e2e/blip-e2e-init; MODE sh runs a script with lib.sh, which
# has w, r, dev, waitdev, net_report and creds_check). VOLUMES-JSON is a
# JSON array of vol entries. BLIP_SPEC (JSON object) is merged into spec.
blip() {
  local name=$1 ttl=$2 vols=$3
  shift 3
  jq -n --arg name "$name" --arg ns "${BNS:-$NS}" --arg check "${CHECK:-}" \
    --argjson ttl "$ttl" --argjson vols "$vols" --argjson extra "${BLIP_SPEC:-"{}"}" \
    --argjson init "$(jq -nc '$ARGS.positional' --args /sbin/blip-e2e-init "$@")" '{
      apiVersion: "blip.example.com/v1alpha1", kind: "Blip",
      metadata: {name: $name, namespace: $ns, labels: {"e2e-check": $check}},
      spec: ({rootVolume: "root", volumes: $vols, init: $init,
              maxTTLSeconds: $ttl, ttlSecondsAfterFinished: 900} + $extra)}' |
    k create -f - >/dev/null || die "create blip $name"
  log "created blip $name ($(jq -c '[.[] | .name + "=" + .blipVolRef.name]' <<<"$vols")) init $1"
}

# blank NAME [SIZE [POLICY-JSON]]: create an empty (zero-filled raw) BlipVol
# with an optional spec.snapshotPolicy and wait Ready.
blank() {
  local pol=${3:-'{}'}
  kn create -f - >/dev/null <<EOF || die "create blipvol $1"
apiVersion: blip.example.com/v1alpha1
kind: BlipVol
metadata: {name: $1}
spec: {size: ${2:-$SIZE}, snapshotPolicy: $pol}
EOF
  wait_cond "blipvol/$1" Ready 180 || die "blank blipvol $1 not Ready: $(field "blipvol/$1" '{.status}')"
}

# clone NAME: clone the base image volume and wait Ready (own root per check,
# so checks never compete for the root volume's claim).
clone() {
  kn create -f - >/dev/null <<EOF || die "create clone $1"
apiVersion: blip.example.com/v1alpha1
kind: BlipVol
metadata: {name: $1}
spec: {parent: {namespace: $NS, name: base}}
EOF
  wait_cond "blipvol/$1" Ready 180 || die "clone $1 not Ready: $(field "blipvol/$1" '{.status}')"
}

# finish NAME [SECS]: wait for Finished; print "Complete" or the Failed reason.
finish() {
  wait_cond "blip/$1" Finished "${2:-300}" || die "blip $1 did not finish: $(field "blip/$1" '{.status}')"
  if [[ $(field "blip/$1" '{.status.conditions[?(@.type=="Complete")].status}') == True ]]; then
    echo Complete
  else
    reason "$1" Failed
  fi
}

# vstat BLIP ATTACHMENT JQ: query status.volumes[name==ATTACHMENT].
vstat() { json "blip/$1" | jq -r --arg n "$2" ".status.volumes[]? | select(.name == \$n) | $3"; }
vstate_is() { [[ $(vstat "$1" "$2" '.state') == "$3" ]]; }

# current VOL: status.current of a BlipVol (0 when unset).
current() { local n; n=$(field "blipvol/$1" '{.status.current}'); echo "${n:-0}"; }

# shutsnap BLIP ATTACHMENT REASON: check the shutdown snapshot of an
# attachment (Ready, release reason REASON, newer than the snapshot the
# attachment started from) and that it is its BlipVol's current snapshot,
# reason Shutdown, written by BLIP; prints the sequence.
shutsnap() {
  local b=$1 a=$2 want=$3 ss seq from v uid
  ss=$(vstat "$b" "$a" '.shutdownSnapshot // empty')
  [[ -n $ss ]] || die "$b/$a has no shutdownSnapshot"
  [[ $(jq -r .state <<<"$ss") == Ready ]] || die "$b/$a shutdownSnapshot $ss"
  [[ $(jq -r .reason <<<"$ss") == "$want" ]] || die "$b/$a shutdownSnapshot reason $(jq -r .reason <<<"$ss"), want $want"
  seq=$(jq -r '.sequence // 0' <<<"$ss")
  from=$(vstat "$b" "$a" '.snapshot // 0')
  [[ $seq -gt $from ]] || die "$b/$a shutdown snapshot $seq is not newer than the start snapshot $from"
  v=$(vstat "$b" "$a" '.blipVolRef.name')
  uid=$(field "blip/$b" '{.metadata.uid}')
  snapof "$v" "$seq" "$b" "$uid" Shutdown
  echo "$seq"
}

# snapof VOL SEQ BLIP UID REASON: VOL's current snapshot is SEQ, Ready with
# REASON and written by BLIP (UID).
snapof() {
  json "blipvol/$1" | jq -e --argjson s "$2" --arg b "$3" --arg u "$4" --arg r "$5" '
      .status.current == $s and .status.lastSequence >= $s and
      any(.status.snapshots[]; .sequence == $s and .state == "Ready" and .reason == $r and
          .writer.blipName == $b and .writer.blipUID == $u)' >/dev/null ||
    die "blipvol/$1: want current snapshot $2 ($5 by $3): $(json "blipvol/$1" | jq -c '{current: .status.current,
        snapshots: [.status.snapshots[]? | {sequence, reason, state, writer: .writer.blipName}]}')"
}

# shutdown_by_uid VOL UID: the sequence of the single Ready Shutdown
# snapshot written by Blip UID (for Blips that are already deleted); it
# must be VOL's current snapshot.
shutdown_by_uid() {
  local s
  s=$(json "blipvol/$1" | jq -r --arg u "$2" '[.status.snapshots[]? | select(.writer.blipUID == $u)] |
      if length == 1 and .[0].state == "Ready" and .[0].reason == "Shutdown" then .[0].sequence else empty end')
  [[ -n $s && $s == "$(current "$1")" ]] ||
    die "blipvol/$1: want one Ready Shutdown snapshot by $2 as current: $(json "blipvol/$1" | jq -c '{current: .status.current, snapshots: [.status.snapshots[]? | {sequence, reason, state, uid: .writer.blipUID}]}')"
  echo "$s"
}

pod_of() { field "blip/$1" '{.status.allocation.podName}'; }
# console BLIP: the guest console output (slot pod log).
console() { local p; p=$(pod_of "$1"); [[ -n $p ]] && kn logs "$p" 2>/dev/null; }
# wait_log BLIP REGEX SECS. The console has the init arguments ("E2E boot
# mode=sh args=SCRIPT"), so anchor REGEX to match the script's output, not
# its text.
wait_log() {
  local end=$((SECONDS + $3))
  until console "$1" | grep -aqE "$2"; do
    [[ $SECONDS -lt $end ]] || die "no '$2' in the console of $1 after $3s: $(console "$1" | tail -n 20)"
    sleep 1
  done
}

# remove_volume BLIP NAME: live detach by dropping the spec.volumes entry.
remove_volume() {
  local p
  p=$(json "blip/$1" | jq -c --arg n "$2" '{spec: {volumes: [.spec.volumes[] | select(.name != $n)]}}')
  kn patch blip "$1" --type=merge -p "$p" >/dev/null || die "remove volume $2 from $1"
  log "removed volume $2 from $1"
}
# add_volume BLIP VOL-JSON: live attach.
add_volume() {
  kn patch blip "$1" --type=json -p "[{\"op\":\"add\",\"path\":\"/spec/volumes/-\",\"value\":$2}]" >/dev/null ||
    die "add volume $2 to $1"
  log "added volume $(jq -r .name <<<"$2") to $1"
}

# restarts BLIP: status.restartCount (0 when unset).
restarts() { local n; n=$(field "blip/$1" '{.status.restartCount}'); echo "${n:-0}"; }

# registry_digest REPO:TAG: the manifest digest of an image in the local registry.
registry_digest() {
  $T 30 curl -fsS -o /dev/null -D - \
    -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' \
    -H 'Accept: application/vnd.oci.image.index.v1+json' \
    -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
    "http://127.0.0.1:5001/v2/${1%%:*}/manifests/${1##*:}" |
    tr -d '\r' | awk 'tolower($1) == "docker-content-digest:" {print $2}'
}

# push_image TAG DOCKERFILE: build DOCKERFILE (with bin/blip-meta), push it to
# the local registry and print its cluster reference by digest.
push_image() {
  local reg digest
  reg=$($T 300 "$ROOT/hack/registry/up.sh") || { echo "registry not available" >&2; return 1; }
  log "building $1"
  $T 900 docker build --provenance=false -q -t "localhost:5001/$1" -f "$ROOT/$2" "$ROOT" >/dev/null || return 1
  $T 300 docker push -q "localhost:5001/$1" >/dev/null || return 1
  digest=$(registry_digest "$1")
  [[ $digest == sha256:* ]] || { echo "no digest for $1 in the registry" >&2; return 1; }
  echo "$reg/${1%%:*}@$digest"
}

# build_image: build images/blip-e2e and set IMAGE to it (by digest).
build_image() { IMAGE=$(push_image "$E2E_TAG" images/blip-e2e/Dockerfile); }

# build_ubuntu_image: build images/blip-ubuntu (systemd, sshd,
# blip-ssh-bootstrap) and set UBUNTU_IMAGE to it (by digest).
build_ubuntu_image() { UBUNTU_IMAGE=$(push_image "$UBUNTU_TAG" images/blip-ubuntu/Dockerfile); }

# --------------------------------------------------------------- checks

check_health() {
  k -n $SYS rollout status deploy/blip-controller --timeout=50s >/dev/null || die "controller not ready"
  $T 200 kubectl -n $SYS rollout status ds/blip-node --timeout=180s >/dev/null || die "node daemon not ready"
  $T 200 kubectl -n "$NS" wait --for=condition=Ready blippool/default --timeout=180s >/dev/null || die "slot pool not ready"
  local n nodes
  for n in $(k get nodes -l $GROUP/hypervisor -o name); do
    # After a node daemon restart the device plugin re-registers and the
    # kubelet updates allocatable a few seconds later.
    poll 90 "$n to advertise slots" sh -c "[ \"\$(kubectl get $n -o jsonpath='{.status.allocatable.blip\\.example\\.com/hypervisor}')\" -gt 0 ]"
  done
  # A controller that just (re)started takes a few seconds to win the
  # leader lease and get the node sessions back.
  local end=$((SECONDS + 120))
  until nodes=$(k -n $SYS logs deploy/blip-controller --tail=-1 | grep -c '"node connected"' || true); [[ $nodes -ge 3 ]]; do
    [[ $SECONDS -lt $end ]] || die "only $nodes node sessions seen"
    sleep 1
  done
  local crd
  for crd in blips blipvols blippools; do
    k get crd "$crd.$GROUP" >/dev/null || die "CRD $crd.$GROUP missing"
  done
  [[ -z $(k get crd "blipsnapshotseries.$GROUP" -o name --ignore-not-found) ]] || die "the removed BlipSnapshotSeries CRD is installed"
  ok "controller, node DaemonSet, slot pool in $NS ($(pool_count free) free), device plugin, $nodes node sessions, CRDs (no BlipSnapshotSeries)"
}

ensure_base() {
  [[ -n $(k -n "$NS" get blipvol base -o name --ignore-not-found 2>/dev/null) ]] && return
  k -n "$NS" create -f - >/dev/null <<EOF || die "create base"
apiVersion: blip.example.com/v1alpha1
kind: BlipVol
metadata: {name: base}
spec:
  image: {reference: $IMAGE}
  size: 1Gi
EOF
  BNS=$NS wait_cond blipvol/base Ready 300 || die "image import: $(BNS=$NS field blipvol/base '{.status}')"
}

check_image() {
  ensure_base
  local reps
  json blipvol/base | jq -e '.status.current == 1 and .status.snapshots[0].sequence == 1 and
      .status.snapshots[0].reason == "Initial" and .status.snapshots[0].state == "Ready"' >/dev/null ||
    die "base history: $(json blipvol/base | jq -c '{current: .status.current, snapshots: [.status.snapshots[]? | {sequence, reason, state}]}')"
  reps=$(json blipvol/base | jq '[.status.snapshots[0].replicas[]? | select(.state == "Sealed")] | length')
  [[ $reps -ge 2 ]] || die "base snapshot 1 has $reps sealed replicas"
  ok "blipvol from $IMAGE is Ready ($(field blipvol/base '{.status.imageDigest}')), snapshot 1 (Initial) on $(field blipvol/base '{.status.snapshots[0].replicas[*].node}')"
}

# chain: one BlipVol advances across runs. Each run starts from the vol's
# current snapshot and appends a Shutdown snapshot; with skipShutdown the
# writes of a run are discarded.
check_chain() {
  clone chain-root
  local c0 s1 s2 last
  c0=$(current chain-root)
  blip write 300 "[$(vol root chain-root)]" sh 'echo e2e-$(cat /etc/alpine-release) > /e2e.txt; sync; echo wrote'
  [[ $(finish write) == Complete ]] || die "write: $(field blip/write '{.status}')"
  [[ $(vstat write root '.snapshot // 0') == "$c0" ]] || die "write started from snapshot $(vstat write root '.snapshot // 0'), want $c0"
  s1=$(shutsnap write root Completed)
  ok "write: Complete; shutdown snapshot $s1 (Completed, Ready) is chain-root's current (was $c0), reason Shutdown, writer write"

  blip read 300 "[$(vol root chain-root)]" sh 'grep -qx "e2e-$(cat /etc/alpine-release)" /e2e.txt && echo second >> /e2e.txt && sync'
  [[ $(finish read) == Complete ]] || die "read: $(field blip/read '{.status}') console: $(console read | tail)"
  [[ $(vstat read root '.snapshot // 0') == "$s1" ]] || die "read started from snapshot $(vstat read root '.snapshot // 0'), want $s1"
  s2=$(shutsnap read root Completed)
  ok "read: started from snapshot $s1, found the file, appended a line; chain-root advanced to $s2"

  kn patch blipvol chain-root --type=merge -p '{"spec":{"snapshotPolicy":{"skipShutdown":true}}}' >/dev/null || die "set skipShutdown"
  last=$(field blipvol/chain-root '{.status.lastSequence}')
  blip skip 300 "[$(vol root chain-root)]" sh 'echo discarded > /skip.txt; sync'
  [[ $(finish skip) == Complete ]] || die "skip: $(field blip/skip '{.status}')"
  [[ $(vstat skip root .shutdownSnapshot.state) == Skipped ]] || die "skip: shutdownSnapshot $(vstat skip root .shutdownSnapshot)"
  [[ $(current chain-root) == "$s2" && $(field blipvol/chain-root '{.status.lastSequence}') == "$last" ]] ||
    die "skipShutdown: current $(current chain-root) (want $s2), lastSequence $(field blipvol/chain-root '{.status.lastSequence}') (want $last)"
  blip skipread 300 "[$(vol root chain-root)]" sh 'test ! -e /skip.txt && grep -qx second /e2e.txt'
  [[ $(finish skipread) == Complete ]] || die "skipread: $(field blip/skipread '{.status}') console: $(console skipread | tail)"
  ok "skipShutdown: shutdownSnapshot Skipped, current stays $s2, the next run does not see the discarded write"
}

check_net() {
  # The guest owns the slot pod IP: the slot's DHCP server leases it (24h)
  # to the first Ethernet NIC; the pod keeps its MAC. The guest prints both,
  # resolves a cluster name through cluster DNS, and stays up 20s.
  clone net-root
  blip net 300 "[$(vol root net-root)]" sh 'net_report || exit 4; sleep 20; echo NET done'
  wait_cond blip/net Started 180 || die "net blip did not start: $(field blip/net '{.status}')"
  local pod podip mac line
  pod=$(pod_of net)
  podip=$(kn get pod "$pod" -o jsonpath='{.status.podIP}')
  mac=$(kn exec "$pod" -- cat /sys/class/net/eth0/address)
  wait_log net 'NET dns-ok' 90
  line=$(console net | grep -a '^NET ip=')
  log "slot pod $pod ip $podip mac $mac; console: $line"
  local gip gmac lease
  gip=$(sed -n 's/^NET ip=\([^ ]*\) mac=.*/\1/p' <<<"$line")
  gmac=$(sed -n 's/^NET ip=[^ ]* mac=\([^ ]*\).*/\1/p' <<<"$line")
  [[ -n $podip && $gip == "$podip" ]] || die "guest IP $gip, slot pod IP $podip"
  [[ -n $mac && ${gmac,,} == "${mac,,}" ]] || die "guest MAC $gmac, slot pod eth0 MAC $mac"
  lease=$(console net | sed -n '/E2E dhcp bound/{s/.* lease=\([0-9]*\).*/\1/p}' | head -n1)
  [[ $lease == 86400 ]] || die "DHCP lease '$lease', want 86400: $(console net | grep -a -E "E2E|NET|udhcpc" | tail -n 20)"
  [[ $(field blip/net '{.status.podIP}') == "$podip" ]] || die "status.podIP $(field blip/net '{.status.podIP}'), want $podip"
  [[ $(finish net) == Complete ]] || die "net: $(field blip/net '{.status}')"
  ok "DHCP leased the slot pod IP $podip for 24h to the guest NIC (MAC $mac), status.podIP matches, cluster DNS works, kubectl logs shows the console"
}

check_tls() {
  # Ports live in the shared kernel; every nvmet port must require TLS 1.3.
  local p n=0
  for p in /sys/kernel/config/nvmet/ports/*/; do
    [[ -d $p ]] || continue
    n=$((n + 1))
    [[ $(sudo cat "$p/addr_trtype") == tcp && $(sudo cat "$p/addr_tsas") == tls1.3 && $(sudo cat "$p/addr_treq") == required ]] ||
      die "port $p: trtype $(sudo cat "$p/addr_trtype") tsas $(sudo cat "$p/addr_tsas") treq $(sudo cat "$p/addr_treq")"
  done
  [[ $n -gt 0 ]] || die "no nvmet ports"
  ok "$n nvmet ports, all tcp with addr_tsas=tls1.3 addr_treq=required"

  # While a Blip runs, the read-only origin paths of its volumes are NVMe/TCP
  # controllers with a TLS key.
  clone tls-root
  blip tls 120 "[$(vol root tls-root)]" sleep 25
  wait_cond blip/tls Started 180 || die "tls blip did not start"
  local c found=0 tlsk
  for c in /sys/class/nvme/nvme*; do
    [[ $(cat "$c/transport" 2>/dev/null) == tcp && $(cat "$c/subsysnqn") == nqn.2026-01.com.example.blip:* ]] || continue
    tlsk=$(cat "$c/tls_key" 2>/dev/null || true)
    [[ -n $tlsk ]] || die "$(basename "$c") to $(cat "$c/address") has no TLS key"
    found=$((found + 1))
    log "$(basename "$c"): $(tr '\n' ' ' <"$c/address") tls_key=$tlsk"
  done
  [[ $found -ge 2 ]] || die "found $found Blip NVMe/TCP controllers, want at least 2 (one per replica)"
  ok "$found NVMe/TCP paths of the running Blip all use TLS keys"

  # A plain (no TLS) connection to a Blip port is refused.
  local addr svc nqn
  p=$(sudo sh -c 'ls -d /sys/kernel/config/nvmet/ports/*/' | head -n1)
  addr=$(sudo cat "$p/addr_traddr")
  svc=$(sudo cat "$p/addr_trsvcid")
  nqn=$(sudo ls "$p/subsystems" | head -n1)
  [[ -n $nqn ]] || nqn=nqn.2026-01.com.example.blip:none
  if sudo $T 30 nvme connect -t tcp -a "$addr" -s "$svc" -n "$nqn" \
    -q nqn.2026-01.com.example.blip:host:e2e-plain >/dev/null 2>&1; then
    sudo nvme disconnect -n "$nqn" >/dev/null 2>&1 || true
    die "plain NVMe/TCP connect to $addr:$svc succeeded"
  fi
  ok "plain NVMe/TCP connect to $addr:$svc is refused"

  local hs
  hs=$(k -n $SYS logs ds/blip-node -c tlshd --tail=-1 2>/dev/null | grep -ci handshake || true)
  hs=$((hs + $(sudo $T 30 journalctl -u tlshd --since "-1h" --no-pager 2>/dev/null | grep -ci handshake || true)))
  [[ $hs -gt 0 ]] || die "no tlshd handshake logs"
  ok "tlshd logged $hs handshakes"
  [[ $(finish tls) == Complete ]] || die "tls blip: $(field blip/tls '{.status}')"
}

# datavols: image root + two empty data volumes. The workload finds both at
# /dev/disk/by-id/virtio-<name> (virtio serial = volume name), formats one
# itself (vfat, busybox) and writes raw bytes to the other; the release
# snapshots carry the data into a second Blip.
check_datavols() {
  clone dv-root
  blank dv-a
  blank dv-b
  blip dv 300 "[$(vol root dv-root),$(vol a dv-a),$(vol b dv-b)]" sh '
    set -e
    waitdev a; waitdev b
    test "$(readlink -f "$(dev a)")" != "$(readlink -f "$(dev b)")"
    test -z "$(r "$(dev a)")"
    mkfs.vfat -n E2EA "$(dev a)" >/dev/null
    mkdir -p /mnt/a; mount -t vfat "$(dev a)" /mnt/a
    echo dv-data-a > /mnt/a/data.txt; umount /mnt/a
    w "$(dev b)" DV-RAW-B
    echo dv-root > /dv.txt; sync
    echo DV ok'
  [[ $(finish dv) == Complete ]] || die "dv: $(field blip/dv '{.status}') console: $(console dv | tail -n 20)"
  local dp
  dp=$(vstat dv a .devicePath)
  [[ $dp == /dev/disk/by-id/virtio-a ]] || die "status devicePath $dp"
  local oroot oa ob
  oroot=$(shutsnap dv root Completed)
  oa=$(shutsnap dv a Completed)
  ob=$(shutsnap dv b Completed)
  [[ $(json blipvol/dv-a | jq -r '.status.claim // empty') == "" ]] || die "dv-a still claimed"
  ok "devices at /dev/disk/by-id/virtio-<name> with serial <name>; shutdown snapshots root=$oroot a=$oa b=$ob (Completed, Ready, current)"

  blip dvread 300 "[$(vol root dv-root),$(vol a dv-a),$(vol b dv-b)]" sh '
    set -e; grep -qx dv-root /dv.txt; waitdev a; waitdev b
    mkdir -p /mnt/a; mount -t vfat -o ro "$(dev a)" /mnt/a; grep -qx dv-data-a /mnt/a/data.txt; umount /mnt/a
    test "$(r "$(dev b)")" = DV-RAW-B; echo DVREAD ok'
  [[ $(finish dvread) == Complete ]] || die "dvread: $(field blip/dvread '{.status}') console: $(console dvread | tail -n 20)"
  ok "a Blip on the same three BlipVols sees the root file, the workload-made vfat file and the raw bytes"
}

# hotplug: live attach a volume to a running Blip, write to it, live detach,
# check the Detach shutdown snapshot carries the data.
check_hotplug() {
  clone hp-root
  blank hp-x
  blip hp 600 "[$(vol root hp-root)]" sh '
    while :; do
      if [ ! -e /tmp/x ] && [ -b "$(dev x)" ]; then waitdev x 5 && w "$(dev x)" HOT-X && touch /tmp/x && echo HOT wrote; fi
      sleep 1
    done'
  wait_cond blip/hp Started 180 || die "hp did not start: $(field blip/hp '{.status}')"
  add_volume hp "$(vol x hp-x)"
  poll 120 "x Attached" vstate_is hp x Attached
  [[ $(json blipvol/hp-x | jq -r .status.claim.blipName) == hp ]] || die "hp-x claim $(field blipvol/hp-x '{.status.claim}')"
  wait_log hp '^HOT wrote' 60
  ok "live attach: x Attached, hp-x claimed by hp, the workload wrote to it"
  remove_volume hp x
  poll 180 "x Released" vstate_is hp x Released
  local out
  out=$(shutsnap hp x Detach)
  [[ -z $(json blipvol/hp-x | jq -r '.status.claim // empty') ]] || die "hp-x still claimed after detach"
  [[ $(field blip/hp '{.status.phase}') == Running ]] || die "hp not Running after detach"
  ok "live detach: x Released, claim gone, Blip still Running, shutdown snapshot $out (reason Detach) is hp-x's current"
  kn delete blip hp --wait=false >/dev/null

  clone hp-root2
  blip hpread 300 "[$(vol root hp-root2),$(vol x hp-x)]" sh 'waitdev x && echo "HPREAD x=$(r "$(dev x)")" && test "$(r "$(dev x)")" = HOT-X'
  [[ $(finish hpread) == Complete ]] || die "hpread: $(field blip/hpread '{.status}') console: $(console hpread | grep -aE 'HPREAD|E2E' | tail -n 5)"
  ok "the Detach snapshot has the bytes written while hot-attached"
}

# forcedetach: detach is forced (CH remove-device); a volume the guest has
# mounted is removed at once, the guest keeps running, and the snapshot has
# what the guest synced before.
check_forcedetach() {
  clone fd-root
  blank fd-y
  blip fd 600 "[$(vol root fd-root),$(vol y fd-y)]" sh '
    waitdev y || exit 5
    mkfs.vfat "$(dev y)" >/dev/null && mkdir -p /mnt/y && mount -t vfat "$(dev y)" /mnt/y || exit 5
    echo fd-y > /mnt/y/f.txt; sync; echo FD mounted
    while :; do sleep 5; echo FD alive; done'
  wait_cond blip/fd Started 180 || die "fd did not start: $(field blip/fd '{.status}')"
  wait_log fd '^FD mounted' 120
  remove_volume fd y
  poll 90 "y Released" vstate_is fd y Released
  local out
  out=$(shutsnap fd y Detach)
  [[ $(field blip/fd '{.status.phase}') == Running ]] || die "fd not Running after the forced detach"
  ok "detach of a mounted volume completes at once (Released, snapshot $out) and the Blip keeps running"
  kn delete blip fd --wait=false >/dev/null
  clone fd-root2
  blip fdread 300 "[$(vol root fd-root2),$(vol y fd-y)]" sh \
    'waitdev y && mkdir -p /mnt/y && mount -t vfat -o ro "$(dev y)" /mnt/y && grep -qx fd-y /mnt/y/f.txt'
  [[ $(finish fdread) == Complete ]] || die "fdread: $(field blip/fdread '{.status}')"
  ok "the snapshot of the forcibly detached volume has the synced file"
}

check_never() {
  clone never-root
  blank never-d
  blip never 120 "[$(vol root never-root),$(vol d never-d)]" sh \
    'waitdev d && w "$(dev d)" FAILED-RUN; echo before failing; exit 3'
  [[ $(finish never) == Error ]] || die "never: $(field blip/never '{.status}')"
  [[ $(field blip/never '{.status.lastExitCode}') == 3 ]] || die "never: exit code"
  [[ $(field blip/never '{.status.phase}') == Failed ]] || die "never: phase $(field blip/never '{.status.phase}')"
  grep -q 3 <<<"$(field blip/never '{.status.message}')" || die "never: message $(field blip/never '{.status.message}')"
  local oroot od
  oroot=$(shutsnap never root Failed)
  od=$(shutsnap never d Failed)
  ok "guest exit code 3 (blip-meta exit 3, poweroff): Failed/Error, message with the code, shutdown snapshots root=$oroot d=$od Ready (reason Failed)"
  blip neverread 300 "[$(vol root never-root),$(vol d never-d)]" sh 'waitdev d && test "$(r "$(dev d)")" = FAILED-RUN'
  [[ $(finish neverread) == Complete ]] || die "neverread: $(field blip/neverread '{.status}')"
  ok "the failed run's data snapshot has its bytes"
}

check_ttl() {
  clone ttl-root
  blip ttl 20 "[$(vol root ttl-root)]" sleep
  [[ $(finish ttl 180) == TTLExceeded ]] || die "ttl: $(field blip/ttl '{.status}')"
  local out
  out=$(shutsnap ttl root DeadlineExceeded)
  ok "maxTTLSeconds=20: Failed/TTLExceeded, shutdown snapshot $out (reason DeadlineExceeded)"
}

check_cancel() {
  clone cancel-root
  blip cancel 600 "[$(vol root cancel-root)]" sh 'echo cancelled-run > /c.txt; sync; sleep 600'
  wait_cond blip/cancel Started 180 || die "cancel blip did not start"
  sleep 3
  local pod uid
  pod=$(pod_of cancel)
  uid=$(field blip/cancel '{.metadata.uid}')
  $T 250 kubectl -n "$NS" delete blip cancel --timeout=240s >/dev/null || die "delete did not finish"
  $T 70 kubectl -n "$NS" wait "pod/$pod" --for=delete --timeout=60s >/dev/null 2>&1 || die "slot pod $pod not deleted"
  local out
  out=$(shutdown_by_uid cancel-root "$uid")
  [[ -z $(json blipvol/cancel-root | jq -r '.status.claim // empty') ]] || die "cancel-root still claimed"
  ok "deleting a running Blip stops it, deletes slot pod $pod, appends Ready snapshot $out to cancel-root, releases the claim"
  blip cancelread 300 "[$(vol root cancel-root)]" sh 'grep -qx cancelled-run /c.txt'
  [[ $(finish cancelread) == Complete ]] || die "cancelread: $(field blip/cancelread '{.status}')"
  ok "the Deleted snapshot has the file written before the delete"
}

# poweroff: deleting a running Blip stops it gracefully with the ACPI power
# button; the guest's handler writes /e2e-power.txt before it powers off,
# and the Deleted shutdown snapshot has it.
check_poweroff() {
  clone po-root
  blip po 600 "[$(vol root po-root)]" sleep
  wait_cond blip/po Started 180 || die "po did not start: $(field blip/po '{.status}')"
  wait_log po 'E2E boot mode=sleep' 120
  local uid t0 out
  uid=$(field blip/po '{.metadata.uid}')
  t0=$SECONDS
  $T 250 kubectl -n "$NS" delete blip po --timeout=240s >/dev/null || die "delete did not finish"
  log "delete took $((SECONDS - t0))s"
  out=$(shutdown_by_uid po-root "$uid")
  blip poread 300 "[$(vol root po-root)]" sh 'cat /e2e-power.txt; grep -q "^power-button " /e2e-power.txt'
  [[ $(finish poread) == Complete ]] || die "poread: $(field blip/poread '{.status}') console: $(console poread | tail)"
  ok "delete pressed the power button: the guest handler ran and powered off; snapshot $out has its marker"
}

# reboot: the guest reboots once (boot counter on its root), then exits 0.
check_reboot() {
  clone rb-root
  blip rb 300 "[$(vol root rb-root)]" reboot 2
  [[ $(finish rb) == Complete ]] || die "rb: $(field blip/rb '{.status}') console: $(console rb | tail)"
  [[ $(restarts rb) == 1 ]] || die "rb: restartCount $(restarts rb), want 1"
  ok "guest reboot -f: the same VM booted again from its root, Complete, status.restartCount 1"
}

# panic: a kernel panic (sysrq c) ends the Blip as Failed/GuestPanic.
check_panic() {
  clone pa-root
  blip pa 300 "[$(vol root pa-root)]" panic
  [[ $(finish pa) == GuestPanic ]] || die "pa: $(field blip/pa '{.status}') console: $(console pa | tail)"
  [[ $(field blip/pa '{.status.phase}') == Failed ]] || die "pa: phase $(field blip/pa '{.status.phase}')"
  local out
  out=$(shutsnap pa root Failed)
  ok "kernel panic: Failed/GuestPanic, shutdown snapshot $out (reason Failed)"
}

# initexit: PID 1 exits with code 7 (kernel "Attempted to kill init!").
check_initexit() {
  clone ie-root
  blip ie 300 "[$(vol root ie-root)]" initexit 7
  [[ $(finish ie) == InitExited ]] || die "ie: $(field blip/ie '{.status}') console: $(console ie | tail)"
  [[ $(field blip/ie '{.status.lastExitCode}') == 7 ]] || die "ie: lastExitCode $(field blip/ie '{.status.lastExitCode}')"
  ok "PID 1 exit 7: Failed/InitExited, lastExitCode 7"
}

# move: the same root BlipVol boots in one slot, is released, and boots again
# in another slot: the guest gets the new slot pod's IP by DHCP and new
# credentials, and cluster DNS works in both.
check_move() {
  clone mv-root
  local p1 ip1 p2 ip2 n
  for n in mv1 mv2; do
    blip "$n" 300 "[$(vol root mv-root)]" sh 'net_report || exit 4; creds_check || exit 5; sleep 10'
    wait_cond "blip/$n" Started 180 || die "$n did not start: $(field "blip/$n" '{.status}')"
    wait_log "$n" 'CREDS ok' 120
    [[ $n == mv1 ]] && { p1=$(pod_of mv1); ip1=$(kn get pod "$p1" -o jsonpath='{.status.podIP}'); }
    [[ $n == mv2 ]] && { p2=$(pod_of mv2); ip2=$(kn get pod "$p2" -o jsonpath='{.status.podIP}'); }
    console "$n" | grep -aq "^NET ip=$(kn get pod "$(pod_of "$n")" -o jsonpath='{.status.podIP}') " ||
      die "$n: guest IP is not the slot pod IP: $(console "$n" | grep -a '^NET ')"
    console "$n" | grep -aq "CREDS ok user=system:serviceaccount:$NS:default" || die "$n: $(console "$n" | grep -a CREDS)"
    [[ $(finish "$n") == Complete ]] || die "$n: $(field "blip/$n" '{.status}')"
    [[ -z $(json blipvol/mv-root | jq -r '.status.claim // empty') ]] || die "mv-root still claimed after $n"
  done
  [[ $p1 != "$p2" ]] || die "both Blips ran in slot pod $p1"
  ok "root mv-root booted in slot $p1 ($ip1), then in $p2 ($ip2): DHCP gave each its pod IP, credentials and DNS worked"
}

# portfwd: kubectl port-forward to the slot pod reaches a guest AF_VSOCK
# listener on the same port number.
check_portfwd() {
  clone pf-root
  BLIP_SPEC='{"ports":[{"port":8080,"name":"e2e"}]}' blip pf 600 "[$(vol root pf-root)]" vsock 8080
  wait_cond blip/pf Started 180 || die "pf did not start: $(field blip/pf '{.status}')"
  wait_log pf 'vsock listening on 8080' 120
  local pod lp=18080 pfpid got="" end
  pod=$(pod_of pf)
  $T 120 kubectl -n "$NS" port-forward "pod/$pod" "$lp:8080" >/dev/null 2>&1 &
  pfpid=$!
  end=$((SECONDS + 60))
  until [[ $got == PONG* ]]; do
    [[ $SECONDS -lt $end ]] || { kill "$pfpid" 2>/dev/null; die "no PONG through port-forward (got '$got')"; }
    sleep 1
    got=$($T 10 bash -c "exec 3<>/dev/tcp/127.0.0.1/$lp && head -n1 <&3" 2>/dev/null || true)
  done
  kill "$pfpid" 2>/dev/null
  wait "$pfpid" 2>/dev/null || true
  ok "port-forward to $pod:8080 reached the guest vsock listener: $got"
}

# periodic: BlipVol snapshotPolicy {interval: 5m, limit: 2} (the kind
# overlay scales intervals by 60: 5s) on two volumes; the workload writes
# counter N to a, then to b, every second.
check_periodic() {
  clone per-root
  local pol='{"interval":"5m","limit":2}'
  blank per-a "$SIZE" "$pol"
  blank per-b "$SIZE" "$pol"
  blip per 900 "[$(vol root per-root),$(vol a per-a),$(vol b per-b)]" sh '
    waitdev a && waitdev b || exit 5; A=$(dev a); B=$(dev b)
    i=0; while :; do i=$((i+1)); w "$A" "CNT $i"; w "$B" "CNT $i"; [ $((i % 10)) = 0 ] && echo CNT $i; sleep 1; done'
  wait_cond blip/per Started 180 || die "per did not start: $(field blip/per '{.status}')"
  local uid v last=() i=0
  uid=$(field blip/per '{.metadata.uid}')
  log "waiting for >= 4 Interval snapshots of per-a and per-b"
  for v in per-a per-b; do
    poll 420 "4 Interval snapshots of $v" sh -c "[ \"\$(kubectl -n $NS get blipvol $v -o jsonpath='{.status.lastSequence}')\" -ge 5 ]"
  done
  # Compaction keeps the newest 2 Ready snapshots plus those the claim
  # pins (the start snapshot and the incremental baseline).
  local kept='.status as $st | [$st.snapshots[] | select(.state == "Ready") | .sequence] as $r | ($r | sort | .[-2:]) as $keep |
      [$r[] | select(. as $q | ($keep | index($q)) == null and $q != $st.claim.snapshot and $q != $st.claim.baseline)] | length == 0'
  for v in per-a per-b; do
    poll 120 "compaction of $v to limit 2" sh -c "kubectl -n $NS get blipvol $v -o json | jq -e '$kept'"
    json "blipvol/$v" | jq -e --arg u "$uid" '[.status.snapshots[].sequence] as $s | $s == ($s | sort) and ($s | unique | length) == ($s | length) and
        all(.status.snapshots[]; .reason == "Initial" or (.reason == "Interval" and .writer.blipUID == $u)) and
        any(.status.snapshots[]; .reason == "Interval" and .state == "Ready") and .status.current >= 2' >/dev/null ||
      die "$v history: $(json "blipvol/$v" | jq -c '{current: .status.current, claim: .status.claim, snapshots: [.status.snapshots[] | {sequence, reason, state}]}')"
    last[i]=$(field "blipvol/$v" '{.status.lastSequence}')
    log "$v: lastSequence ${last[i]}, history $(json "blipvol/$v" | jq -c '[.status.snapshots[] | "\(.sequence):\(.reason):\(.state)"]')"
    i=$((i + 1))
  done
  ok "per-a and per-b took Interval snapshots (lastSequence ${last[*]}); compaction kept at most 2 Ready plus the claim's snapshot and baseline; sequences ascending"

  $T 250 kubectl -n "$NS" delete blip per --timeout=240s >/dev/null || die "delete per"
  i=0
  for v in per-a per-b; do
    [[ $(current "$v") -gt ${last[i]} ]] || die "$v did not advance past ${last[i]}: current $(current "$v")"
    json "blipvol/$v" | jq -e --arg u "$uid" '.status.current as $c | any(.status.snapshots[]; .sequence == $c and .state == "Ready" and
        .reason == "Shutdown" and .writer.blipUID == $u)' >/dev/null ||
      die "$v current is not a Shutdown snapshot of per: $(json "blipvol/$v" | jq -c '{current: .status.current, snapshots: [.status.snapshots[] | {sequence, reason, state}]}')"
    i=$((i + 1))
  done
  clone per-root2
  # The shutdown snapshots are taken after the VM stopped: a is b or b+1.
  blip restore 300 "[$(vol root per-root2),$(vol a per-a),$(vol b per-b)]" sh '
    waitdev a && waitdev b || exit 6
    a=$(r "$(dev a)"); b=$(r "$(dev b)"); echo "RESTORE a=\"$a\" b=\"$b\""
    case "$a $b" in "CNT "*" CNT "*) ;; *) exit 7;; esac
    na=${a#CNT }; nb=${b#CNT }
    [ "$nb" -ge 1 ] && { [ "$na" = "$nb" ] || [ "$na" = $((nb + 1)) ]; } || exit 8'
  wait_cond blip/restore Started 240 || die "restore did not start: $(field blip/restore '{.status}')"
  local res
  res=$(finish restore)
  log "restore console: $(console restore | grep -a RESTORE || true)"
  [[ $res == Complete ]] || die "restore: $res $(field blip/restore '{.status.message}')"
  ok "after deleting the Blip both vols have a Shutdown snapshot as current; a new Blip on them sees the counters"
}

# exclusive: two Blips on the same BlipVol; the second waits VolumeInUse.
check_exclusive() {
  clone ex-root1
  clone ex-root2
  blank ex-v
  blip ex1 300 "[$(vol root ex-root1),$(vol v ex-v)]" sh 'waitdev v && w "$(dev v)" EX1; sleep 30'
  wait_cond blip/ex1 Started 180 || die "ex1 did not start"
  blip ex2 300 "[$(vol root ex-root2),$(vol v ex-v)]" sh 'waitdev v && test "$(r "$(dev v)")" = EX1'
  poll 60 "ex2 VolumeInUse" sh -c "[ \"\$(kubectl -n $NS get blip ex2 -o jsonpath='{.status.conditions[?(@.type==\"Scheduled\")].reason}')\" = VolumeInUse ]"
  [[ $(field blip/ex2 '{.status.phase}') == Pending ]] || die "ex2 phase $(field blip/ex2 '{.status.phase}')"
  [[ $(json blipvol/ex-v | jq -r .status.claim.blipName) == ex1 ]] || die "ex-v claim: $(field blipvol/ex-v '{.status.claim}')"
  [[ $(field blip/ex1 '{.status.phase}') == Running ]] || die "ex1 not Running"
  ok "ex2 Pending with Scheduled=False/VolumeInUse while ex1 holds the claim"
  [[ $(finish ex1) == Complete ]] || die "ex1: $(field blip/ex1 '{.status}')"
  local s1
  s1=$(shutsnap ex1 v Completed)
  [[ $(finish ex2) == Complete ]] || die "ex2: $(field blip/ex2 '{.status}') console: $(console ex2 | tail)"
  [[ $(vstat ex2 v '.snapshot // 0') == "$s1" ]] || die "ex2 started from snapshot $(vstat ex2 v '.snapshot // 0'), want $s1"
  ok "ex2 ran after ex1 finished, started from ex1's shutdown snapshot $s1 and saw its bytes"
}

# delblock: deleting an attached BlipVol waits for the claim to go.
check_delblock() {
  clone del-root
  blank del-v
  blip del 300 "[$(vol root del-root),$(vol v del-v)]" sleep 30
  wait_cond blip/del Started 180 || die "del did not start"
  kn delete blipvol del-v --wait=false >/dev/null || die "delete del-v"
  poll 60 "DeletionBlocked" sh -c "[ \"\$(kubectl -n $NS get blipvol del-v -o jsonpath='{.status.conditions[?(@.type==\"Ready\")].reason}')\" = DeletionBlocked ]"
  [[ -n $(field blipvol/del-v '{.metadata.deletionTimestamp}') ]] || die "no deletionTimestamp"
  [[ $(field blip/del '{.status.phase}') == Running ]] || die "del not Running"
  ok "deleting an attached BlipVol: still present with deletionTimestamp, Ready reason DeletionBlocked, Blip still Running"
  [[ $(finish del) == Complete ]] || die "del: $(field blip/del '{.status}')"
  $T 190 kubectl -n "$NS" wait blipvol/del-v --for=delete --timeout=180s >/dev/null 2>&1 || die "del-v not deleted after the Blip finished"
  ok "the BlipVol is deleted after the Blip finished"
}

check_blankroot() {
  blank br-v
  blip br 120 "[$(vol root br-v)]" ok
  local r
  r=$(finish br 240)
  [[ $r == BootFailed ]] || die "blank root: reason $r: $(field blip/br '{.status}')"
  [[ $(field blip/br '{.status.message}') == *RootMountFailed* ]] || die "blank root: message $(field blip/br '{.status.message}')"
  [[ -z $(json blipvol/br-v | jq -r '.status.claim // empty') ]] || die "br-v still claimed"
  ok "a blank root volume fails with Failed/BootFailed ($(field blip/br '{.status.message}')), claim released"
}

check_quota() {
  create_ns "$NSQ" 1 1 1
  k annotate ns "$NSQ" --overwrite quota.blip.example.com/default=1 >/dev/null
  local v
  for v in q1-root q2-root; do
    BNS=$NSQ clone "$v"
  done
  BNS=$NSQ blip q1 300 "[$(vol root q1-root)]" sleep
  BNS=$NSQ wait_cond blip/q1 Started 180 || die "q1 did not start"
  [[ $(BNS=$NSQ field blip/q1 '{.status.phase}') == Running ]] || die "q1 not running"
  BNS=$NSQ blip q2 300 "[$(vol root q2-root)]" ok
  poll 60 "q2 QuotaExceeded" sh -c "[ \"\$(kubectl -n $NSQ get blip q2 -o jsonpath='{.status.conditions[?(@.type==\"Scheduled\")].reason}')\" = QuotaExceeded ]"
  [[ $(BNS=$NSQ field blip/q2 '{.status.phase}') == Pending ]] || die "q2 not Pending"
  ok "quota 1: second Blip Pending with QuotaExceeded"
  k -n "$NSQ" delete blip q1 --wait=false >/dev/null
  [[ $(BNS=$NSQ finish q2) == Complete ]] || die "q2 after quota freed: $(BNS=$NSQ field blip/q2 '{.status}')"
  ok "second Blip runs after the first is deleted"
}

# pool: a running Blip's slot pod leaves the pool (assigned, no owner
# reference) and the pool refills to minFree; deleting the Blip deletes the
# pod and the pool returns to minFree free slots.
check_pool() {
  local min pod
  min=$(field blippool/default '{.spec.minFree}')
  clone pool-root
  blip pool 300 "[$(vol root pool-root)]" sleep
  wait_cond blip/pool Started 180 || die "pool blip did not start"
  pod=$(pod_of pool)
  [[ -z $(field "pod/$pod" '{.metadata.ownerReferences}') ]] || die "claimed pod $pod still has an owner reference"
  [[ $(field "pod/$pod" "{.metadata.labels.blip\\.example\\.com/pool}") == default ]] || die "claimed pod $pod lost its pool label"
  poll 180 "pool to refill to $min free" sh -c "[ \"\$(kubectl -n $NS get blippool default -o jsonpath='{.status.free}')\" -ge $min ]"
  [[ $(pool_count assigned) -ge 1 ]] || die "pool reports $(pool_count assigned) assigned"
  ok "slot pod $pod left the pool on claim; the pool refilled to $(pool_count free) free"
  $T 250 kubectl -n "$NS" delete blip pool --timeout=240s >/dev/null || die "delete did not finish"
  $T 70 kubectl -n "$NS" wait "pod/$pod" --for=delete --timeout=60s >/dev/null 2>&1 || die "slot pod $pod not deleted"
  $T 200 kubectl -n "$NS" wait --for=condition=Ready blippool/default --timeout=180s >/dev/null || die "pool not Ready"
  ok "after the Blip is deleted the pool is Ready with $(pool_count free) free, $(pool_count assigned) assigned"
}

# plugin: kubectl blip (bin/kubectl-blip) with the ubuntu SSH image: setup,
# shell (creates the session from --image, runs a command, propagates the
# exit code, reuses the session), list, ssh-config with ssh through
# `kubectl blip proxy`, create --volume --wait, delete. Sessions have no
# e2e-check label, so the check deletes them itself.
check_plugin() {
  export PATH="$ROOT/bin:$PATH"
  [[ $(command -v kubectl-blip) == "$ROOT/bin/kubectl-blip" ]] || die "kubectl-blip on PATH is $(command -v kubectl-blip)"
  local home s=pl1 s2=pl2 vol root out rc uid pod t0=$SECONDS f
  home=$(mktemp -d /tmp/opencode/blip-home.XXXXXX)
  export BLIP_HOME=$home
  vol=img-$(printf %s "$UBUNTU_IMAGE" | sha256sum | cut -c1-12)
  # shellcheck disable=SC2064
  trap "$T 200 kubectl -n $NS delete blip $s $s2 pl-plain --ignore-not-found --timeout=180s >/dev/null 2>&1
        $T 200 kubectl -n $NS delete blipvol $vol --ignore-not-found --timeout=180s >/dev/null 2>&1; rm -rf $home" EXIT
  kb() { $T "${KB_TIMEOUT:-120}" kubectl blip -n "$NS" "$@" </dev/null; }

  out=$(kb setup 2>&1) || die "setup: $out"
  out=$(kb setup 2>&1) || die "setup again: $out"
  [[ $out == *"serviceaccount/blip-ssh unchanged"* ]] || die "setup not idempotent: $out"
  k -n "$NS" get sa/blip-ssh role/blip-ssh rolebinding/blip-ssh >/dev/null || die "setup objects missing"
  ok "setup created the blip-ssh ServiceAccount, Role and RoleBinding; a second run kept them"

  out=$(KB_TIMEOUT=900 kb shell "$s" --image "$UBUNTU_IMAGE" --ttl 15m --timeout 12m -- 'echo TOKEN-$((6*7)); cat /etc/os-release' 2>"$home/shell.err") ||
    die "shell: rc $? out: $out err: $(tail -n 20 "$home/shell.err")"
  [[ $out == *TOKEN-42* && $out == *Ubuntu* ]] || die "shell output: $out"
  [[ $(field "blipvol/$vol" '{.spec.image.reference}') == "$UBUNTU_IMAGE" ]] || die "blipvol $vol: $(field "blipvol/$vol" '{.spec}')"
  root=$(field "blip/$s" '{.spec.volumes[0].blipVolRef.name}')
  json "blipvol/$root" | jq -e --arg v "$vol" --arg s "$s" '.spec.parent.name == $v and
      any(.metadata.ownerReferences[]?; .kind == "Blip" and .name == $s)' >/dev/null ||
    die "root volume $root of $s is not a clone of $vol owned by $s: $(json "blipvol/$root" | jq -c '{spec, o: .metadata.ownerReferences}')"
  [[ $(field "blip/$s" '{.metadata.labels.blip\.example\.com/session}') == true ]] || die "$s has no session label"
  [[ $(field "blip/$s" '{.spec.maxTTLSeconds}') == 900 ]] || die "$s maxTTLSeconds $(field "blip/$s" '{.spec.maxTTLSeconds}')"
  for f in id_ed25519 known_hosts; do
    [[ $(stat -c %a "$home/$f") == 600 ]] || die "$f has mode $(stat -c %a "$home/$f")"
  done
  grep -q "^blip-$s ssh-" "$home/known_hosts" || die "known_hosts: $(cat "$home/known_hosts")"
  ok "shell --image created blipvol/$vol and session $s (root clone $root) and ran a remote command ($((SECONDS - t0))s)"

  uid=$(field "blip/$s" '{.metadata.uid}')
  pod=$(pod_of "$s")
  rc=0
  kb shell "$s" -- exit 7 >/dev/null 2>"$home/shell.err" || rc=$?
  [[ $rc == 7 ]] || die "exit code $rc, want 7: $(tail -n 5 "$home/shell.err")"
  out=$(kb shell "$s" -- hostname 2>"$home/shell.err") || die "second shell: $(tail -n 5 "$home/shell.err")"
  [[ -n $out ]] || die "second shell printed no hostname"
  if grep -qiE 'created|warning|authenticity' "$home/shell.err"; then die "second shell: $(cat "$home/shell.err")"; fi
  [[ $(field "blip/$s" '{.metadata.uid}') == "$uid" && $(pod_of "$s") == "$pod" ]] || die "session $s was replaced"
  [[ $(kn get blipvols -o name | grep -c '/img-') == 1 ]] || die "blipvols: $(kn get blipvols -o name)"
  ok "remote 'exit 7' gave rc 7; a second shell reused $s (pod $pod) without prompts"

  out=$(kb list) || die "list: $out"
  awk -v s="$s" '$1 == s && $2 == "Running" && $NF != "<unknown>" {f = 1} END {exit !f}' <<<"$out" || die "list: $out"
  ok "list: $(awk -v s="$s" '$1 == s' <<<"$out")"

  kb ssh-config >"$home/ssh_config" || die "ssh-config"
  grep -q "ProxyCommand kubectl blip proxy --namespace $NS %n" "$home/ssh_config" || die "ssh-config: $(cat "$home/ssh_config")"
  out=$($T 120 ssh -F "$home/ssh_config" -o BatchMode=yes "blip-$s" echo via-proxy </dev/null 2>"$home/ssh.err") ||
    die "ssh through the proxy: $(tail -n 20 "$home/ssh.err")"
  [[ $out == via-proxy ]] || die "ssh through the proxy printed: $out"
  grep -q "^blip-$s ssh-" "$home/known_hosts" || die "proxy did not record blip-$s: $(cat "$home/known_hosts")"
  ok "ssh -F <ssh-config> blip-$s connected through kubectl blip proxy"

  KB_TIMEOUT=400 kb create "$s2" --volume "$vol" --ttl 10m --wait 2>"$home/create.err" || die "create --wait: $(tail -n 20 "$home/create.err")"
  out=$(kb shell "$s2" -- echo second 2>"$home/shell.err") || die "shell $s2: $(tail -n 5 "$home/shell.err")"
  [[ $out == second ]] || die "shell $s2 printed: $out"
  grep -q "^blip-$s2 ssh-" "$home/known_hosts" || die "shell did not record the host key of $s2"
  ok "create $s2 --volume $vol --wait, then shell into it"

  # A finished session: shell refuses without a terminal, --recreate replaces it.
  uid=$(field "blip/$s2" '{.metadata.uid}')
  log "powering off $s2"
  kb shell "$s2" -- systemctl poweroff --no-block >/dev/null 2>&1 || true
  log "poweroff command returned"
  poll 180 "$s2 to finish after poweroff" sh -c "kubectl -n $NS get blip $s2 -o jsonpath='{.status.phase}' | grep -Eq '^(Succeeded|Failed)$'"
  local fin
  fin=$(field "blip/$s2" '{.status.phase}')
  log "$s2 is $fin"
  if out=$(kb shell "$s2" -- true 2>&1); then die "shell into a finished session succeeded: $out"; fi
  [[ $out == *--recreate* ]] || die "shell into a finished session: $out"
  out=$(KB_TIMEOUT=400 kb shell "$s2" --recreate --volume "$vol" -- echo again 2>"$home/shell.err") ||
    die "shell --recreate: $(tail -n 20 "$home/shell.err")"
  [[ $out == again && $(field "blip/$s2" '{.metadata.uid}') != "$uid" ]] || die "shell --recreate: $out, uid $(field "blip/$s2" '{.metadata.uid}')"
  ok "after poweroff $s2 was $fin; shell without a terminal refused it, shell --recreate replaced it"

  # A Blip without the session label; it never starts (no root BlipVol).
  kn create -f - >/dev/null <<EOF || die "create pl-plain"
apiVersion: blip.example.com/v1alpha1
kind: Blip
metadata: {name: pl-plain}
spec: {rootVolume: root, volumes: [{name: root, blipVolRef: {name: pl-missing}}], maxTTLSeconds: 300}
EOF
  if out=$(kb delete pl-plain 2>&1); then die "deleting a non-session Blip succeeded: $out"; fi
  [[ $out == *"not a session"* ]] || die "delete pl-plain: $out"
  KB_TIMEOUT=300 kb delete pl-plain --force --wait >/dev/null || die "delete --force pl-plain"
  ok "delete refused a non-session Blip without --force"

  KB_TIMEOUT=300 kb delete "$s" "$s2" --wait >/dev/null || die "delete --wait"
  [[ -z $(kn get blip "$s" "$s2" -o name --ignore-not-found) ]] || die "sessions still exist"
  out=$(kb list 2>&1) || die "list: $out"
  [[ $out == *"no sessions found"* ]] || die "list after delete: $out"
  poll 120 "root clones to be deleted with their sessions" sh -c "[ -z \"\$(kubectl -n $NS get blipvols -o json | jq -r '.items[] | select(any(.metadata.ownerReferences[]?; .kind == \"Blip\")) | .metadata.name')\" ]"
  $T 200 kubectl -n "$NS" delete blipvol "$vol" --timeout=180s >/dev/null || die "delete blipvol $vol"
  ok "delete --wait removed $s and $s2 and their root clones"
}

# nested: kubectl blip inside a session (images/blip-ubuntu ships kubectl
# and kubectl-blip, `setup --nested` grants the guests access). The parent
# derives a BlipVol from its own live root (a Derive capture), boots a task
# Blip from it, derives a BlipVol from the task's live root, mounts it,
# copies an artifact off it and deletes everything; it also starts a Blip
# from the image (not derived).
check_nested() {
  export PATH="$ROOT/bin:$PATH"
  local home p=pn1 task=pn-task fresh=pn-fresh vol out script t0=$SECONDS pkey snap proot res troot
  home=$(mktemp -d /tmp/opencode/blip-home.XXXXXX)
  export BLIP_HOME=$home
  vol=img-$(printf %s "$UBUNTU_IMAGE" | sha256sum | cut -c1-12)
  # shellcheck disable=SC2064
  trap "$T 200 kubectl -n $NS delete blip $p $task $fresh --ignore-not-found --timeout=180s >/dev/null 2>&1
        $T 100 kubectl -n $NS delete blipvol $vol --ignore-not-found --wait=false >/dev/null 2>&1; rm -rf $home" EXIT
  kb() { $T "${KB_TIMEOUT:-120}" kubectl blip -n "$NS" "$@" </dev/null; }

  out=$(kb setup --nested 2>&1) || die "setup --nested: $out"
  [[ $out == *"role/blip-ssh-nested created"* && $out == *"rolebinding/blip-ssh-nested created"* ]] || die "setup --nested: $out"
  out=$(kb setup --nested 2>&1) || die "setup --nested again: $out"
  [[ $out == *"rolebinding/blip-ssh-nested configured"* ]] || die "setup --nested not idempotent: $out"
  ok "setup --nested created the blip-ssh-nested Role and RoleBinding"

  KB_TIMEOUT=900 kb create "$p" --image "$UBUNTU_IMAGE" --ttl 20m --timeout 12m --wait 2>"$home/create.err" ||
    die "create $p: $(tail -n 20 "$home/create.err")"
  ok "session $p is running ($((SECONDS - t0))s)"

  # Runs in $p as root, without a kubeconfig: kubectl and kubectl blip use
  # the Blip's service account and namespace.
  script=$(cat <<EOS
set -euo pipefail
exec 2>&1
step() { echo "STEP \$*"; }
step whoami; kubectl auth whoami -o jsonpath='{.status.userInfo.username}'; echo
kubectl blip version
echo "COMPLETE=\$(kubectl __complete blip de 2>/dev/null | cut -f1 | grep -x derive)"
echo parent-data >/root/marker
step derive self; snap=\$(kubectl blip derive --volume root --wait); echo "SNAP=\$snap"
kubectl get blipvol "\$snap" -o name
step create derived; kubectl blip create $task --volume "\$snap" --ttl 10m --wait
step shell derived
kubectl blip shell $task -- 'echo "TASK_HOST=\$(hostname)"; echo "TASK_KEY=\$(cut -d" " -f2 /etc/ssh/ssh_host_ed25519_key.pub)"; echo "TASK_SAW=\$(cat /root/marker)"; echo "result-\$(cat /root/marker)" >/root/result; sync'
step derive task; troot=\$(kubectl get blip $task -o jsonpath='{.spec.volumes[0].blipVolRef.name}'); echo "TROOT=\$troot"
out=\$(kubectl blip derive "\$troot" --wait); echo "OUT=\$out"
kubectl get blipvol "\$out" -o jsonpath='ORIGIN={.status.origin.name}/{.status.origin.snapshot}{"\\n"}'
step delete task; kubectl blip delete $task --wait
step attach; dev=\$(kubectl blip attach "\$out" --name out --mount /mnt/out); echo "DEV=\$dev"
mountpoint -q /mnt/out
cp /mnt/out/root/result /root/artifact
echo "ARTIFACT=\$(cat /root/artifact)"
step detach; kubectl blip detach out --delete
if mountpoint -q /mnt/out; then echo "STILL MOUNTED"; exit 1; fi
if kubectl get blipvol "\$out" -o name 2>/dev/null; then echo "OUT STILL EXISTS"; exit 1; fi
step fresh; kubectl blip shell $fresh --image "$UBUNTU_IMAGE" --ttl 10m -- 'test ! -e /root/marker && echo FRESH_OK'
kubectl blip delete $fresh --wait
echo NESTED_DONE
EOS
)
  # Run it from a file: the nested `kubectl blip shell` (ssh) reads stdin.
  out=$(KB_TIMEOUT=1200 kb shell "$p" -- "echo $(base64 -w0 <<<"$script") | base64 -d >/root/nested.sh && bash /root/nested.sh" 2>"$home/shell.err") ||
    die "nested workflow failed: $out
$(tail -n 20 "$home/shell.err")"
  printf '%s\n' "$out" | sed 's/^/    | /' >&2
  [[ $out == *NESTED_DONE* ]] || die "nested workflow did not finish"
  [[ $out == *"system:serviceaccount:$NS:blip-ssh"* ]] || die "kubectl in $p did not use the blip-ssh service account"
  [[ $out == *COMPLETE=derive* ]] || die "kubectl in $p does not complete kubectl blip de to derive (kubectl_complete-blip)"
  [[ $out == *"TASK_HOST=$task"* && $out == *"TASK_SAW=parent-data"* ]] || die "$task did not boot from the snapshot of $p"
  [[ $out == *"DEV=/dev/disk/by-id/virtio-out"* && $out == *"ARTIFACT=result-parent-data"* ]] || die "artifact not copied off the snapshot of $task"
  [[ $out == *FRESH_OK* ]] || die "$fresh was not booted from the image"
  snap=$(sed -n 's/^SNAP=//p' <<<"$out")
  troot=$(sed -n 's/^TROOT=//p' <<<"$out")
  [[ -n $troot && $out == *"ORIGIN=$troot/"* ]] || die "derived result of $task: origin is not $troot"
  pkey=$(field "blip/$p" '{.metadata.annotations.blip\.example\.com/ssh-host-key}' | cut -d' ' -f2)
  [[ -n $pkey && $out == *TASK_KEY=* && $out != *"TASK_KEY=$pkey"* ]] || die "$task kept the host key of $p ($pkey)"
  ok "in $p: derive its live root, create $task from it, derive $task's live root, attach and mount it, copy the artifact, detach --delete ($((SECONDS - t0))s)"

  # The derived vol records its origin; the source got a Derive capture.
  proot=$(field "blip/$p" '{.spec.volumes[0].blipVolRef.name}')
  res=$(json "blipvol/$snap" | jq -c '{phase: .status.phase, origin: .status.origin, snapshots: [.status.snapshots[]? | {sequence, reason, state}]}')
  jq -e --arg n "$proot" --arg u "$(field "blipvol/$proot" '{.metadata.uid}')" '.phase == "Ready" and .origin.name == $n and
      .origin.uid == $u and .origin.snapshot >= 1 and .snapshots[0].sequence == 1 and .snapshots[0].reason == "Initial"' <<<"$res" >/dev/null ||
    die "derived $snap: $res"
  json "blipvol/$proot" | jq -e --argjson s "$(jq .origin.snapshot <<<"$res")" '
      any(.status.snapshots[]; .sequence == $s and .reason == "Derive" and .state == "Ready")' >/dev/null ||
    die "$proot has no Ready Derive snapshot $(jq .origin.snapshot <<<"$res"): $(json "blipvol/$proot" | jq -c '[.status.snapshots[]? | {sequence, reason, state}]')"
  ok "derived $snap: Ready, status.origin = $proot snapshot $(jq .origin.snapshot <<<"$res"), which is a Derive capture"

  [[ -z $(kn get blip "$task" "$fresh" -o name --ignore-not-found) ]] || die "child blips still exist"
  [[ $(field "blip/$p" '{.spec.volumes[*].name}') == root ]] || die "$p volumes: $(field "blip/$p" '{.spec.volumes[*].name}')"
  ok "the children and the attached result are gone; $p has only its root"

  out=$(kb shell "$p" -- 'cat /root/artifact' 2>"$home/shell.err") || die "shell $p: $(tail -n 5 "$home/shell.err")"
  [[ $out == result-parent-data ]] || die "artifact in $p: $out"
  KB_TIMEOUT=300 kb delete "$p" --wait >/dev/null || die "delete $p"
  $T 200 kubectl -n "$NS" delete blipvol "$snap" --timeout=180s >/dev/null || die "delete derived $snap"
  ok "the artifact stayed in $p; deleted $p and the derived $snap"
}

# kblip ARGS...: the kubectl plugin built at the start (bin/kubectl-blip).
kblip() { $T "${KB_TIMEOUT:-180}" "$ROOT/bin/kubectl-blip" -n "${BNS:-$NS}" "$@" </dev/null; }

# hist VOL: compact snapshot history "seq:reason:state ..." for messages.
hist() { json "blipvol/$1" | jq -r '[.status.snapshots[]? | "\(.sequence):\(.reason):\(.state)"] | join(" ")'; }

# snapwhere VOL JQ-FILTER: sequences of VOL's snapshots matching the filter.
snapwhere() { json "blipvol/$1" | jq -r "[.status.snapshots[]? | select($2) | .sequence] | join(\" \")"; }

# cond_reason KIND/NAME TYPE: reason of a condition.
cond_reason() { field "$1" "{.status.conditions[?(@.type==\"$2\")].reason}"; }

# resched: spec.reschedule with a connected node. The first attempt writes
# to two data volumes (one with skipShutdown) and panics; the failure
# saves every attached overlay as a Reschedule snapshot (also the
# skipShutdown one) and the second attempt starts from them and sees the
# bytes.
check_resched() {
  clone rs-root
  blank rs-d
  blank rs-s "$SIZE" '{"skipShutdown":true}'
  BLIP_SPEC='{"reschedule":{"limit":2,"initialBackoffSeconds":1,"maxBackoffSeconds":2}}' \
    blip rs 600 "[$(vol root rs-root),$(vol d rs-d),$(vol s rs-s)]" sh '
    waitdev d && waitdev s || exit 5
    if [ "$(r "$(dev d)")" = RS1 ]; then
      [ "$(r "$(dev s)")" = RS1 ] || { echo "RS second attempt: s=$(r "$(dev s)")"; exit 6; }
      grep -q RS1 /rs.txt || exit 7
      echo "RS resumed"; exit 0
    fi
    w "$(dev d)" RS1; w "$(dev s)" RS1; echo RS1 >/rs.txt; sync; echo "RS panic"; echo c >/proc/sysrq-trigger; sleep 60'
  [[ $(finish rs 400) == Complete ]] || die "rs: $(field blip/rs '{.status}') console: $(console rs | tail)"
  local b uid v seq
  b=$(json blip/rs)
  uid=$(jq -r .metadata.uid <<<"$b")
  jq -e '.status.rescheduleCount == 1 and .status.lastFailure.reason == "GuestPanic"' <<<"$b" >/dev/null ||
    die "rs: $(jq -c '{rescheduleCount: .status.rescheduleCount, lastFailure: .status.lastFailure}' <<<"$b")"
  [[ $(cond_reason blip/rs Rescheduling) == Rescheduled ]] || die "rs: Rescheduling reason $(cond_reason blip/rs Rescheduling)"
  for v in rs-root:root rs-d:d rs-s:s; do
    seq=$(snapwhere "${v%%:*}" ".reason == \"Reschedule\" and .state == \"Ready\" and .writer.blipUID == \"$uid\"")
    [[ $seq =~ ^[0-9]+$ ]] || die "${v%%:*}: want one Ready Reschedule snapshot by rs: $(hist "${v%%:*}")"
    [[ $(vstat rs "${v#*:}" '.snapshot // 0') == "$seq" ]] || die "rs/${v#*:} started from $(vstat rs "${v#*:}" '.snapshot // 0'), want $seq"
    [[ -z $(vstat rs "${v#*:}" '.resumedFrom // empty') ]] || die "rs/${v#*:} has resumedFrom"
  done
  [[ $(vstat rs s '.shutdownSnapshot.state') == Skipped ]] || die "rs/s shutdownSnapshot $(vstat rs s '.shutdownSnapshot')"
  [[ $(current rs-s) == "$(snapwhere rs-s '.reason == "Reschedule"')" ]] || die "rs-s current $(current rs-s): $(hist rs-s)"
  shutsnap rs d Completed >/dev/null
  ok "GuestPanic with spec.reschedule: Reschedule snapshots of root, d and skipShutdown s ($(hist rs-s)); attempt 2 started from them, saw the bytes and completed; s skipped its final snapshot"
}

# derive: kubectl blip derive from an idle BlipVol, from a historical
# snapshot (--snapshot N), from a BlipVol attached to a running Blip (a
# live Derive capture), and from a snapshot not taken yet.
check_derive() {
  clone de-root
  blank de-d
  local n s1 s2 lv uid seq out
  for n in 1 2; do
    blip "de-w$n" 300 "[$(vol root de-root),$(vol d de-d)]" sh "waitdev d && w \"\$(dev d)\" GEN$n"
    [[ $(finish "de-w$n") == Complete ]] || die "de-w$n: $(field "blip/de-w$n" '{.status}')"
  done
  s1=$(snapwhere de-d '.writer.blipName == "de-w1"')
  s2=$(current de-d)
  [[ $(kblip derive de-d --name de-idle --wait) == de-idle ]] || die "derive de-d"
  [[ $(field blipvol/de-idle '{.status.origin.snapshot}') == "$s2" ]] || die "de-idle origin $(field blipvol/de-idle '{.status.origin}'), want $s2"
  kblip derive de-d --snapshot "$s1" --name de-hist --wait >/dev/null || die "derive de-d --snapshot $s1"
  [[ $(field blipvol/de-hist '{.status.origin.snapshot}') == "$s1" ]] || die "de-hist origin $(field blipvol/de-hist '{.status.origin}'), want $s1"
  ok "derive de-d (idle) cloned the newest snapshot $s2; derive --snapshot $s1 cloned the older one"

  if out=$(kblip derive de-d --snapshot 99 --name de-future 2>&1); then die "derive --snapshot 99 succeeded: $out"; fi
  [[ $out == *"has no snapshot 99"* ]] || die "derive --snapshot 99: $out"
  kn create -f - >/dev/null <<EOF || die "create de-future"
apiVersion: blip.example.com/v1alpha1
kind: BlipVol
metadata: {name: de-future}
spec: {parent: {name: de-d, snapshot: 99}}
EOF
  poll 60 "de-future SnapshotNotYetTaken" sh -c "[ \"\$(kubectl -n $NS get blipvol de-future -o jsonpath='{.status.conditions[?(@.type==\"Ready\")].reason}')\" = SnapshotNotYetTaken ]"
  kn delete blipvol de-future --timeout=60s >/dev/null || die "delete de-future"
  ok "kubectl blip derive --snapshot 99 refuses a snapshot not taken yet; a BlipVol with parent.snapshot 99 waits with Ready=False/SnapshotNotYetTaken"

  blip de-live 600 "[$(vol root de-root),$(vol d de-d)]" sh 'waitdev d && w "$(dev d)" GEN3 && echo "DE wrote"; sleep 600'
  wait_cond blip/de-live Started 180 || die "de-live did not start"
  wait_log de-live '^DE wrote' 120
  uid=$(field blip/de-live '{.metadata.uid}')
  lv=$(kblip derive de-d --name de-live --wait) || die "derive de-d (live): $lv"
  seq=$(field blipvol/de-live '{.status.origin.snapshot}')
  json blipvol/de-d | jq -e --argjson s "${seq:-0}" --arg u "$uid" 'any(.status.snapshots[]; .sequence == $s and
      .reason == "Derive" and .state == "Ready" and .writer.blipUID == $u)' >/dev/null ||
    die "de-live origin ${seq:-none} is not a Ready Derive capture by de-live: $(hist de-d)"
  [[ $(field blip/de-live '{.status.phase}') == Running ]] || die "de-live not Running after the capture"
  out=$(kblip volumes de-d) || die "volumes de-d"
  [[ $out == *Derive* && $out == *de-live* && $out == *de-hist* ]] || die "volumes de-d: $out"
  ok "derive of attached de-d: Derive capture $seq by the running de-live; volumes de-d lists it and the pins"

  kn delete blip de-live --timeout=240s >/dev/null || die "delete de-live"
  clone de-root2
  blip de-r 300 "[$(vol root de-root2),$(vol a de-idle),$(vol b de-hist),$(vol c de-live)]" sh '
    waitdev a && waitdev b && waitdev c || exit 5
    echo "DE a=$(r "$(dev a)") b=$(r "$(dev b)") c=$(r "$(dev c)")"
    [ "$(r "$(dev a)")" = GEN2 ] && [ "$(r "$(dev b)")" = GEN1 ] && [ "$(r "$(dev c)")" = GEN3 ]'
  [[ $(finish de-r) == Complete ]] || die "de-r: $(console de-r | grep -a '^DE ')"
  kn delete blip de-r --timeout=120s >/dev/null
  kn delete blipvol de-idle de-hist de-live --timeout=120s >/dev/null || die "delete derived vols"
  ok "the derived vols have GEN2 (idle), GEN1 (--snapshot $s1) and GEN3 (live capture)"
}

# compact: snapshotPolicy {interval: 5m (5s scaled), limit: 2}. A derived
# BlipVol pins an old Interval snapshot beyond the limit
# (RetentionLimitExceeded=True/Pinned) while newer ones are compacted; once
# it is deleted, the pinned snapshot goes too.
check_compact() {
  clone cp-root
  blank cp-v "$SIZE" '{"interval":"5m","limit":2}'
  blip cp 900 "[$(vol root cp-root),$(vol v cp-v)]" sh '
    waitdev v || exit 5; i=0; while :; do i=$((i+1)); w "$(dev v)" "CNT $i"; sleep 1; done'
  wait_cond blip/cp Started 180 || die "cp did not start"
  local pin
  poll 180 "an Interval snapshot of cp-v" sh -c "kubectl -n $NS get blipvol cp-v -o json | jq -e 'any(.status.snapshots[]; .reason == \"Interval\" and .state == \"Ready\")'"
  pin=$(snapwhere cp-v '.reason == "Interval" and .state == "Ready"' | awk '{print $1}')
  kblip derive cp-v --snapshot "$pin" --name cp-pin --wait >/dev/null || die "derive cp-v --snapshot $pin"
  poll 300 "3 more snapshots of cp-v" sh -c "[ \"\$(kubectl -n $NS get blipvol cp-v -o jsonpath='{.status.lastSequence}')\" -ge $((pin + 4)) ]"
  poll 120 "RetentionLimitExceeded=Pinned on cp-v" sh -c "kubectl -n $NS get blipvol cp-v -o json | jq -e --argjson p $pin '
      ([.status.conditions[] | select(.type == \"RetentionLimitExceeded\" and .status == \"True\" and .reason == \"Pinned\")] | length == 1) and
      any(.status.snapshots[]; .sequence == \$p and .state == \"Ready\") and
      .status as \$st | ([\$st.snapshots[] | select(.sequence > \$p and .sequence < \$st.lastSequence - 1 and
          .sequence != \$st.claim.baseline)] | length == 0)'"
  ok "limit 2: Interval snapshot $pin pinned by cp-pin (RetentionLimitExceeded=True/Pinned), the snapshots after it were compacted: $(hist cp-v)"
  kn delete blipvol cp-pin --timeout=120s >/dev/null || die "delete cp-pin"
  poll 120 "snapshot $pin compacted" sh -c "kubectl -n $NS get blipvol cp-v -o json | jq -e --argjson p $pin '
      (any(.status.snapshots[]; .sequence == \$p) | not) and
      ([.status.conditions[] | select(.type == \"RetentionLimitExceeded\" and .status == \"True\" and .reason == \"Pinned\")] | length == 0)'"
  # Snapshot 1 is the claim's start snapshot: with it 3 Ready are kept,
  # so the condition stays True, now with reason Held.
  [[ $(cond_reason blipvol/cp-v RetentionLimitExceeded) == Held ]] || die "cp-v RetentionLimitExceeded: $(field blipvol/cp-v '{.status.conditions}')"
  ok "after deleting cp-pin, snapshot $pin was compacted; RetentionLimitExceeded is Held (the claim's start snapshot 1): $(hist cp-v)"
}

# nl_restore: unpause, start and untaint the kind nodes the nodeloss check took away.
nl_restore() {
  local n i
  for n in blip-worker blip-worker2 blip-worker3; do
    if [[ $($T 30 docker inspect -f '{{.State.Paused}}' "$n" 2>/dev/null) == true ]]; then
      log "unpausing $n"
      $T 60 docker unpause "$n" >/dev/null || true
    fi
    for i in 1 2 3 4 5; do
      [[ $($T 30 docker inspect -f '{{.State.Running}}' "$n" 2>/dev/null) == true ]] && break
      log "starting $n (try $i)"
      $T 120 docker start "$n" >/dev/null || sleep 10
    done
    $T 30 kubectl taint node "$n" "$OOS-" >/dev/null 2>&1 || true
    $T 30 kubectl uncordon "$n" >/dev/null 2>&1 || true
  done
  $T 200 kubectl wait node --all --for=condition=Ready --timeout=180s >/dev/null 2>&1 || echo "WARNING: nodes not Ready" >&2
  # After a restart kindnet sometimes does not program the routes to the
  # other nodes' pod CIDRs (no service network on the node); a new kindnet
  # pod does.
  local want have
  want=$(($(k get nodes -o name | wc -l) - 1))
  for n in blip-worker blip-worker2 blip-worker3; do
    for i in $(seq 90); do
      have=$($T 30 docker exec "$n" ip route 2>/dev/null | grep -c '^10\.244\..* via ' || true)
      [[ $have -ge $want ]] && break
      if [[ $((i % 30)) == 0 ]]; then
        log "$n has $have of $want pod routes; restarting its kindnet pod"
        k -n kube-system delete pod -l app=kindnet --field-selector "spec.nodeName=$n" --wait=false >/dev/null 2>&1 || true
      fi
      sleep 2
    done
  done
  $T 200 kubectl -n $SYS rollout status ds/blip-node --timeout=180s >/dev/null 2>&1 || echo "WARNING: node daemons not ready" >&2
  # Every node daemon must have a controller session again: its last
  # connect/disconnect line in the controller log is a connect.
  for n in blip-worker blip-worker2 blip-worker3; do
    for i in $(seq 300); do
      [[ $(k -n $SYS logs deploy/blip-controller --since=1h 2>/dev/null |
        grep -E "\"node (connected|disconnected)\",\"node\":\"$n\"" | tail -n 1) != *disconnected* ]] && break
      sleep 1
    done
  done
}
OOS=node.kubernetes.io/out-of-service

# nl_docker restart|pause NODE: restart or freeze a kind node container.
# Docker sometimes gives up killing a node whose processes are stuck in
# I/O ("did not receive an exit event"); try again a few times. A node is
# taken away with `docker pause` (all its processes frozen: the node
# daemon stops answering, the kubelet stops reporting) rather than
# `docker stop`, which hits that problem far more often.
nl_docker() {
  local started i
  started=$($T 30 docker inspect -f '{{.State.StartedAt}}' "$2")
  for i in 1 2 3; do
    $T 150 docker "$1" "$2" >/dev/null 2>&1
    case $1 in
      restart) [[ $($T 30 docker inspect -f '{{.State.Running}} {{.State.StartedAt}}' "$2") == "true "* &&
        $($T 30 docker inspect -f '{{.State.StartedAt}}' "$2") != "$started" ]] && return 0 ;;
      pause) [[ $($T 30 docker inspect -f '{{.State.Paused}}' "$2") == true ]] && return 0 ;;
    esac
    log "docker $1 $2 failed (try $i)"
    [[ $1 == restart && $($T 30 docker inspect -f '{{.State.Running}}' "$2") == false ]] && { $T 120 docker start "$2" >/dev/null 2>&1 && return 0; }
    sleep 5
  done
  return 1
}

# nl_off NODE: move the controller off NODE before the node is taken away
# (a paused node would freeze it too): cordon, delete the pod, wait for
# the new one, uncordon.
nl_off() {
  [[ $(k -n $SYS get pods -l app.kubernetes.io/name=blip-controller -o jsonpath='{.items[*].spec.nodeName}') == *"$1"* ]] || return 0
  log "moving the controller off $1"
  k cordon "$1" >/dev/null || die "cordon $1"
  k -n $SYS delete pods -l app.kubernetes.io/name=blip-controller --wait=false >/dev/null || die "delete controller pod"
  $T 200 kubectl -n $SYS rollout status deploy/blip-controller --timeout=180s >/dev/null || die "controller not back"
  k uncordon "$1" >/dev/null || die "uncordon $1"
}

# nl_blip NAME POLICY: a Blip on a fresh root, a blank volume k with
# interval snapshots and a blank volume d without. The first attempt
# writes KEEP to k (captured by the next Interval snapshot) and LOST to d
# (never snapshotted), then runs until its node goes away. A resumed
# attempt must see KEEP on k and a blank d.
nl_blip() {
  clone "$1-root"
  blank "$1-k" "$SIZE" '{"interval":"5m"}'
  blank "$1-d"
  BLIP_SPEC="{\"reschedule\":$(jq -c '. + {limit: 2, initialBackoffSeconds: 1, maxBackoffSeconds: 2}' <<<"$2")}" \
    blip "$1" 1200 "[$(vol root "$1-root"),$(vol k "$1-k"),$(vol d "$1-d")]" sh '
    waitdev k && waitdev d || exit 5; K=$(r "$(dev k)"); D=$(r "$(dev d)")
    if [ "$K" = KEEP ]; then echo "NL resumed k=$K d=$D"; [ -z "$D" ] || exit 9; exit 0; fi
    w "$(dev k)" KEEP; w "$(dev d)" LOST; echo "NL wrote"; while :; do sleep 1; done'
  wait_cond "blip/$1" Started 180 || die "$1 did not start: $(field "blip/$1" '{.status}')"
  wait_log "$1" '^NL wrote' 120
  # Two Interval snapshots: the second one surely has KEEP.
  poll 120 "2 Interval snapshots of $1-k" sh -c "kubectl -n $NS get blipvol $1-k -o json | jq -e '[.status.snapshots[] | select(.reason == \"Interval\" and .state == \"Ready\")] | length >= 2'"
}

# nl_resumed NAME FAILURE: the Blip completed in a second attempt (after
# lastFailure FAILURE) that resumed d from its Initial snapshot and k from
# its newest Interval snapshot.
nl_resumed() {
  local r b
  r=$(finish "$1" 600)
  [[ $r == Complete ]] || die "$1: $r $(field "blip/$1" '{.status}') console: $(console "$1" | tail -n 5)"
  b=$(json "blip/$1")
  jq -e --arg f "$2" '.status.rescheduleCount == 1 and .status.lastFailure.reason == $f and
      ([.status.conditions[] | select(.type == "Rescheduling" and .reason == "ResumedFromOlderSnapshot")] | length == 1) and
      (.status.volumes[] | select(.name == "d") | .resumedFrom.sequence == 1 and .snapshot == 1) and
      (.status.volumes[] | select(.name == "k") | .resumedFrom.sequence >= 2)' <<<"$b" >/dev/null ||
    die "$1: $(jq -c '{rescheduleCount: .status.rescheduleCount, lastFailure: .status.lastFailure,
        rescheduling: [.status.conditions[] | select(.type == "Rescheduling")], volumes: [.status.volumes[] | {name, snapshot, resumedFrom}]}' <<<"$b")"
  [[ $(snapwhere "$1-k" "(.sequence == $(jq '.status.volumes[] | select(.name == "k") | .resumedFrom.sequence' <<<"$b")) and .reason == \"Interval\"") != "" ]] ||
    die "$1-k resumed from a non-Interval snapshot: $(hist "$1-k")"
  [[ -z $(snapwhere "$1-d" '.reason == "Reschedule" and .state == "Ready"') ]] || die "$1-d has a Ready Reschedule snapshot: $(hist "$1-d")"
}

# nl_discarded NAME: wait for the OverlayDiscarded event of the Blip.
nl_discarded() {
  poll 240 "OverlayDiscarded event on $1" sh -c "kubectl -n $NS get events --field-selector involvedObject.name=$1,reason=OverlayDiscarded -o name | grep -q ."
}

# nodeloss: node loss under spec.reschedule (disruptive: pauses or restarts kind node
# containers; nl_restore restores them on exit).
#  reboot: `docker restart` of the node container is a reboot as the
#          controller sees it: /run (allocation records) is a tmpfs and
#          the VM is gone, so the node returns without the attachments.
#  fence:  `docker pause`; salvageTimeout 5s, nodeLoss Fence waits with
#          Rescheduling=False/NodeUnreachable until the out-of-service
#          taint is set.
#  abandon: `docker pause`; nodeLoss Abandon goes on after 5s; the
#          returning node gets an OverlayDiscarded event.
check_nodeloss() {
  trap nl_restore EXIT
  local node t0
  nl_blip nlr '{}'
  node=$(field blip/nlr '{.status.allocation.node}')
  nl_off "$node"
  log "restarting $node"
  nl_docker restart "$node" || die "docker restart $node"
  # The restarted node sometimes comes back without pod routes (no
  # cluster DNS, so its node daemon cannot reach the controller);
  # nl_restore repairs that.
  nl_restore
  nl_resumed nlr SlotLost
  ok "reboot of $node (docker restart): SlotLost (allocation missing after reconnect), overlays Unavailable, d resumed from 1, k from Interval $(vstat nlr k .resumedFrom.sequence), Rescheduling=ResumedFromOlderSnapshot, the second attempt saw KEEP and not LOST"
  nl_restore

  nl_blip nlf '{"salvageTimeout":"5s"}'
  node=$(field blip/nlf '{.status.allocation.node}')
  nl_off "$node"
  log "pausing $node"
  nl_docker pause "$node" || die "docker pause $node"
  t0=$SECONDS
  poll 300 "nlf Rescheduling=False/NodeUnreachable" sh -c "kubectl -n $NS get blip nlf -o json | jq -e 'any(.status.conditions[]; .type == \"Rescheduling\" and .status == \"False\" and .reason == \"NodeUnreachable\")'"
  log "Fence is waiting after $((SECONDS - t0))s; checking it keeps waiting (twice the salvage timeout)"
  sleep 10
  [[ $(field blip/nlf '{.status.phase}') == Saving ]] || die "nlf phase $(field blip/nlf '{.status.phase}') while Fence waits"
  k taint node "$node" "$OOS=nodeshutdown:NoExecute" >/dev/null || die "taint $node"
  nl_resumed nlf NodeLost
  ok "Fence: $node paused, Rescheduling=False/NodeUnreachable after $((SECONDS - t0))s until the out-of-service taint; then resumed from older snapshots"
  nl_restore
  nl_discarded nlf
  ok "Fence: $node returned (unpaused, taint removed) and got OverlayDiscarded"

  nl_blip nla '{"salvageTimeout":"5s","nodeLoss":"Abandon"}'
  node=$(field blip/nla '{.status.allocation.node}')
  nl_off "$node"
  log "pausing $node"
  nl_docker pause "$node" || die "docker pause $node"
  t0=$SECONDS
  nl_resumed nla NodeLost
  ok "Abandon: $node paused, rescheduled after $((SECONDS - t0))s without fencing, resumed from older snapshots"
  nl_restore
  nl_discarded nla
  ok "Abandon: $node returned (unpaused) and got OverlayDiscarded"
}

# cleanup_check NAME: delete the check's Blips so slots and claims are free.
cleanup_check() {
  local ns
  for ns in "$NS" "$NSQ"; do
    $T 320 kubectl -n "$ns" delete blips -l "e2e-check=$1" --ignore-not-found --wait=true --timeout=300s >/dev/null 2>&1 ||
      echo "WARNING: blips of $1 in $ns not deleted in time" >&2
  done
}

# ----------------------------------------------------------------- main

checks=("$@")
if [[ ${#checks[@]} -eq 0 && -n ${E2E_ONLY:-} ]]; then IFS=, read -ra checks <<<"$E2E_ONLY"; fi
[[ ${#checks[@]} -gt 0 ]] || checks=("${ALL[@]}")
for c in "${checks[@]}"; do
  case " ${ALL[*]} " in *" $c "*) ;; *) echo "unknown check $c (known: ${ALL[*]})" >&2; exit 2 ;; esac
done
selected() { [[ " ${checks[*]} " == *" $1 "* ]]; }

PAR=${E2E_PARALLEL:-4}
[[ $PAR =~ ^[1-9][0-9]*$ ]] || { echo "E2E_PARALLEL must be a positive number" >&2; exit 2; }
LOGDIR=${E2E_LOG_DIR:-/tmp/opencode/blip-e2e-logs/$(date +%Y%m%d-%H%M%S)}
mkdir -p "$LOGDIR" "$DIAG"

command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }
# One build of the host tools for every check (derive and compact run
# bin/kubectl-blip, plugin and nested put it on PATH).
(cd "$ROOT" && CGO_ENABLED=0 $T 300 "$GOB" build -trimpath -ldflags '-s -w' -o bin/ ./cmd/blip-meta ./cmd/kubectl-blip) ||
  { echo "cannot build bin/blip-meta and bin/kubectl-blip" >&2; exit 2; }
if [[ -z $IMAGE && " ${checks[*]} " != " health " ]]; then
  build_image || { echo "cannot build the e2e image (set E2E_IMAGE to skip)" >&2; exit 2; }
fi
log "guest image ${IMAGE:-none}"
if [[ -z $UBUNTU_IMAGE ]] && { selected plugin || selected nested; }; then
  build_ubuntu_image || { echo "cannot build the ubuntu image (set E2E_UBUNTU_IMAGE to skip)" >&2; exit 2; }
fi
log "ssh image ${UBUNTU_IMAGE:-none}"
if selected tls; then
  sudo -n true || { echo "passwordless sudo is required for the tls check" >&2; exit 2; }
fi
log "cleaning up namespaces from earlier runs"
cleanup_ns
[[ -n ${E2E_KEEP:-} ]] || trap cleanup_ns EXIT
create_ns "$NS" || { echo "cannot create namespace $NS" >&2; exit 1; }

# run_check NAME: run one check in a subshell (die() ends only that check),
# delete its Blips, and record "PASS|FAIL SECS" in $LOGDIR/NAME.result. The
# output goes to $LOGDIR/NAME.log and, prefixed with the name, to stdout.
run_check() {
  local c=$1 t0=$SECONDS rc
  (
    (
      set -eE
      CHECK=$c
      trap 'die "command failed (line $LINENO): $BASH_COMMAND"' ERR
      log "=== check $c"
      [[ $c == health ]] || ensure_base
      "check_$c"
    )
    rc=$?
    cleanup_check "$c"
    exit $rc
  ) 2>&1 | tee "$LOGDIR/$c.log" | sed -u "s/^/$(printf '%-11s' "$c")| /"
  rc=${PIPESTATUS[0]}
  if [[ $rc -eq 0 ]]; then echo "PASS $((SECONDS - t0))s"; else echo "FAIL $((SECONDS - t0))s"; fi >"$LOGDIR/$c.result"
  return "$rc"
}

# run_unit CHECK...: run checks one after another (stops at a failure with
# E2E_FAILFAST).
run_unit() {
  local c
  for c in "$@"; do
    run_check "$c" || [[ -z ${E2E_FAILFAST:-} ]] || return 1
  done
}

failed_any() { grep -qs ^FAIL "$LOGDIR"/*.result; }

# Scheduling. The checks share namespace $NS and its slot pool (at most 4
# slots), with unique Blip and BlipVol names and an e2e-check label each.
# Checks that need the whole cluster run alone: health and image first
# (health reads the pool and the node sessions; image imports the shared
# base), pool (asserts the pool's free count) and nodeloss (takes nodes
# away) last. The others run E2E_PARALLEL at a time, longest first.
# plugin and nested share the img-<hash> BlipVol, sessions and the
# blip-ssh RBAC objects, so they form one unit. plugin waits until the
# BlipVol is gone, so nested does not reuse a terminating one.
FIRST=(health image)
LAST=(pool nodeloss)
ORDER=("plugin nested" compact periodic derive tls exclusive move delblock net chain datavols ttl resched
  hotplug forcedetach never cancel poweroff reboot panic initexit portfwd blankroot quota)
in_list() { local x; for x in "${@:2}"; do [[ $x == "$1" ]] && return 0; done; return 1; }
units=()
for u in "${ORDER[@]}"; do
  sel=()
  for c in $u; do selected "$c" && sel+=("$c"); done
  [[ ${#sel[@]} -eq 0 ]] || units+=("${sel[*]}")
done
for c in "${checks[@]}"; do
  # shellcheck disable=SC2046
  in_list "$c" "${FIRST[@]}" "${LAST[@]}" $(printf '%s ' "${ORDER[@]}") || units+=("$c")
done

start=$SECONDS
for c in "${FIRST[@]}"; do
  selected "$c" || continue
  run_check "$c" || [[ -z ${E2E_FAILFAST:-} ]] || break
done
if ! { [[ -n ${E2E_FAILFAST:-} ]] && failed_any; } && [[ ${#units[@]} -gt 0 || " ${checks[*]} " == *" nodeloss "* || " ${checks[*]} " == *" pool "* ]]; then
  # Import the shared base once before the checks that clone it run.
  (CHECK=base; ensure_base) || { echo "cannot import the base BlipVol" >&2; exit 1; }
fi
t1=$SECONDS
log "=== ${#units[@]} unit(s), $PAR at a time; logs in $LOGDIR"
running=0
for u in "${units[@]}"; do
  [[ -n ${E2E_FAILFAST:-} ]] && failed_any && break
  if [[ $running -ge $PAR ]]; then wait -n; running=$((running - 1)); fi
  [[ -n ${E2E_FAILFAST:-} ]] && failed_any && break
  # shellcheck disable=SC2086
  run_unit $u &
  running=$((running + 1))
done
wait
t2=$SECONDS
for c in "${LAST[@]}"; do
  selected "$c" || continue
  [[ -n ${E2E_FAILFAST:-} ]] && failed_any && break
  run_check "$c"
done

echo
echo "e2e summary ($((SECONDS - start))s: exclusive first $((t1 - start))s, parallel x$PAR $((t2 - t1))s, exclusive last $((SECONDS - t2))s; logs in $LOGDIR):"
failed=0
for c in "${checks[@]}"; do
  r=$(cat "$LOGDIR/$c.result" 2>/dev/null || echo SKIPPED)
  [[ $r == PASS* ]] || failed=$((failed + 1))
  printf '  %-11s %s\n' "$c" "$r"
done
[[ $failed -eq 0 ]] || { echo "e2e: $failed check(s) failed or skipped; diagnostics in $DIAG" >&2; exit 1; }
echo "e2e: all ${#checks[@]} checks passed"
