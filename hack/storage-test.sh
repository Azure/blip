#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Runs the privileged storage, nvme, and peer tests in disposable privileged
# containers (they share the host kernel: dm, loop, nvmet, nvme-tcp), then
# removes every kernel object the run created. Never touches other devices.
#
#   hack/storage-test.sh [storage|nvme|peer|e2e]...   (default: all)
set -euo pipefail
cd "$(dirname "$0")/.."

RUN=${BLIP_TEST_RUN:-$(head -c3 /dev/urandom | od -An -tx1 | tr -d ' \n')}
OUT=$(mktemp -d)
IMAGE=blip-storage-test
NET=blipt-$RUN
suites=("$@")
[ ${#suites[@]} -eq 0 ] && suites=(storage nvme peer e2e)

nodes() { for i in $(seq 0 19); do echo blipt-$RUN-$i; done; echo blipt-$RUN-a blipt-$RUN-b; }

cleanup() {
  docker rm -f blipt-$RUN-a blipt-$RUN-b >/dev/null 2>&1 || true
  docker run --rm --privileged -v /dev:/dev -v "$PWD/hack:/hack:ro" $IMAGE \
    bash /hack/storage-cleanup.sh $(nodes) || true
  docker network rm $NET >/dev/null 2>&1 || true
  rm -rf "$OUT"
}
trap cleanup EXIT

docker build -q -t $IMAGE -f hack/storage-test.Dockerfile hack >/dev/null
for p in storage nvme peer; do
  CGO_ENABLED=0 go test -c -o "$OUT/$p.test" ./internal/$p
done

run() { # name binary args...
  local name=$1; shift
  docker run --rm --privileged --name "$name" -v /dev:/dev -v "$OUT:/t" \
    -e BLIP_PRIVILEGED_TESTS=1 -e BLIP_TEST_RUN=$RUN "$@"
}

status=0
for s in "${suites[@]}"; do
  case $s in
    storage|nvme|peer)
      echo "== $s"
      run blipt-$RUN-$s $IMAGE /t/$s.test -test.v -test.timeout 10m -test.run Privileged || status=1 ;;
    e2e)
      echo "== e2e (two nodes)"
      docker network create $NET >/dev/null
      mkdir -p "$OUT/shared"
      common=(--network $NET -e BLIP_E2E_SHARED=/t/shared $IMAGE /t/peer.test -test.v -test.timeout 10m -test.run TestE2ETwoNodes)
      run blipt-$RUN-b -e BLIP_E2E_ROLE=b "${common[@]}" > "$OUT/b.log" 2>&1 &
      bpid=$!
      run blipt-$RUN-a -e BLIP_E2E_ROLE=a "${common[@]}" || status=1
      wait $bpid || { status=1; }
      echo "-- node b log"; cat "$OUT/b.log" ;;
  esac
done
exit $status
