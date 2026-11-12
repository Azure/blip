#!/usr/bin/env bash
# Load local images into every node of the kind cluster, in parallel.
# Uses ctr import directly, because `kind load` fails to detect the
# containerd snapshotter with recent Docker versions.
# An image is skipped when the same image ID was already loaded into the
# same node containers (stamps in _output/kind-loaded/); KIND_LOAD_FORCE=1
# loads anyway.
# Usage: hack/kind/load.sh image...
set -euo pipefail
cluster=${KIND_CLUSTER:-blip}
root=$(cd "$(dirname "$0")/../.." && pwd)
T="timeout -s TERM"
stamps=$root/_output/kind-loaded/$cluster
tmpdir=${BLIP_TMP:-/mnt/nvme2/blip/e2e}
mkdir -p "$stamps" "$tmpdir"
nodes=$($T 60 kind get nodes --name "$cluster")
ids=$(for n in $nodes; do $T 30 docker inspect -f '{{.Id}}' "$n"; done | sort | tr '\n' ' ')
todo=()
for img in "$@"; do
	want="$($T 30 docker image inspect -f '{{.Id}}' "$img") $ids"
	stamp=$stamps/$(tr '/:' '__' <<<"$img")
	if [[ -z ${KIND_LOAD_FORCE:-} && -f $stamp && $(cat "$stamp") == "$want" ]]; then
		echo "$img unchanged, not loading"
		continue
	fi
	todo+=("$img")
	rm -f "$stamp"
done
[[ ${#todo[@]} -gt 0 ]] || exit 0
tmp=$(mktemp "$tmpdir/images.XXXXXX.tar")
trap 'rm -f "$tmp"' EXIT
$T 300 docker save -o "$tmp" "${todo[@]}"
pids=()
for n in $nodes; do
	( $T 300 docker exec -i "$n" ctr -n k8s.io images import --all-platforms=false - <"$tmp" >/dev/null &&
		echo "loaded ${todo[*]} into $n" ) &
	pids+=($!)
done
rc=0
for p in "${pids[@]}"; do wait "$p" || rc=1; done
[[ $rc == 0 ]] || { echo "loading into some nodes failed" >&2; exit 1; }
for img in "${todo[@]}"; do
	echo "$($T 30 docker image inspect -f '{{.Id}}' "$img") $ids" >"$stamps/$(tr '/:' '__' <<<"$img")"
done
