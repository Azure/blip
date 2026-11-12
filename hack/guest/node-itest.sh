#!/bin/sh
# Run the node daemon integration tests as root (real guest, fake storage).
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
make -s -f hack/guest/Makefile initramfs slotdev
CGO_ENABLED=0 timeout -s TERM 300 go test -c -o _output/guest/node.test ./internal/node
cd internal/node
sudo BLIP_ROOT_TESTS=1 timeout -s TERM 900 "$root/_output/guest/node.test" -test.v -test.timeout 14m -test.run "${1:-Integration}"
