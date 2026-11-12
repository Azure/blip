#!/bin/sh
# Run the guest integration tests as root. The test binary is built as the
# current user so no root-owned files end up in the Go cache.
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
make -s -f hack/guest/Makefile initramfs slotdev
CGO_ENABLED=0 timeout -s TERM 300 go test -c -o _output/guest/slot.test ./internal/slot
cd internal/slot
sudo BLIP_ROOT_TESTS=1 timeout -s TERM 900 "$root/_output/guest/slot.test" -test.v -test.timeout 14m -test.run "${1:-Integration}"
