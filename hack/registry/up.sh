#!/usr/bin/env bash
# Idempotently run a plain-HTTP registry:2 container on the kind docker
# network. Push from the host via localhost:5001; reference images from the
# cluster as <container-ip>:5000/... (storage nodes are hostNetwork kind nodes;
# go-containerregistry uses http for RFC1918 addresses). Prints <ip>:5000.
set -euo pipefail
NAME=${REGISTRY_NAME:-blip-registry}
NET=${KIND_NETWORK:-kind}
HOST_PORT=${REGISTRY_HOST_PORT:-5001}
T="timeout -s TERM 120"

if [[ $($T docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null || true) != true ]]; then
  $T docker rm -f "$NAME" >/dev/null 2>&1 || true
  $T docker run -d --restart=always --name "$NAME" --network "$NET" \
    -p "127.0.0.1:$HOST_PORT:5000" registry:2 >/dev/null
fi
ip=$($T docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$NAME")
[[ -n $ip ]] || { echo "registry $NAME has no IP on network $NET" >&2; exit 1; }
for _ in $(seq 30); do
  curl -fsS --max-time 2 "http://127.0.0.1:$HOST_PORT/v2/" >/dev/null 2>&1 && { echo "$ip:5000"; exit 0; }
  sleep 1
done
echo "registry $NAME not answering on 127.0.0.1:$HOST_PORT" >&2
exit 1
