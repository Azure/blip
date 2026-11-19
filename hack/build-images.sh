#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Build the blip-controller, blip-node, blip-runtime and blipchat images from
# prebuilt binaries (make build) and guest assets (make guest). Each image is
# tagged with its content hash, and the references are written to
# build/images.env.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="${IMAGE_REPO:-ghcr.io/azure}"
CH="${CLOUD_HYPERVISOR:-/usr/local/bin/cloud-hypervisor}"
cd "${ROOT}"

for f in bin/blip-controller bin/blip-node bin/blip-runtime bin/blipchat \
  build/guest/vmlinuz build/guest/initramfs.gz "${CH}"; do
  [[ -f "${f}" ]] || { echo "missing ${f} (run make build guest)" >&2; exit 1; }
done

mkdir -p build/images
install -m 0755 "${CH}" build/images/cloud-hypervisor

: > build/images.env.tmp
for c in controller node runtime blipchat; do
  docker build -q -f "deploy/images/Dockerfile.${c}" --iidfile "build/images/${c}.iid" . >/dev/null
  id="$(cat "build/images/${c}.iid")"
  ref="${REPO}/blip-${c}:${id:7:12}"
  docker tag "${id}" "${ref}"
  echo "${ref}"
  echo "${c^^}_IMAGE=${ref}" >> build/images.env.tmp
done
mv build/images.env.tmp build/images.env
