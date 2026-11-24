# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

BINARIES := blip-controller blip-node blip-runtime blipchat blip-guest kubectl-blip
CONTROLLER_GEN ?= $(shell go env GOPATH)/bin/controller-gen

.PHONY: build generate headers verify-headers verify-actions test test-sim test-ui guest images kind-up kind-down

build:
	CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o bin/ $(addprefix ./cmd/,$(BINARIES))

generate:
	$(CONTROLLER_GEN) object:headerFile=hack/boilerplate.go.txt paths=./api/...
	$(CONTROLLER_GEN) crd paths=./api/... output:crd:dir=deploy/crd
	python3 hack/headers.py fix api/v1alpha1/zz_generated.deepcopy.go deploy/crd

headers:
	python3 hack/headers.py fix

verify-headers:
	python3 hack/headers.py check

verify-actions:
	python3 hack/actions.py check

test:
	go test ./...

# Production simulations, component model checks, and their concurrent
# adapters. Ordinary `make test` also runs these tests; this target adds the
# race detector.
test-sim:
	go test -race -count=1 ./internal/sim ./internal/simtest ./internal/simlive ./internal/simapp ./internal/atomicfile ./internal/storage ./internal/peer ./internal/nvme ./internal/node ./internal/controller ./internal/runtime ./internal/guest ./internal/wire ./internal/podapi ./internal/stream ./internal/streamapi ./internal/workspace ./internal/blipchat

# Browser tests for the chat UI: real server and Chromium, in-memory backends.
# Needs node; run `npx playwright install chromium` once.
test-ui:
	test -d hack/e2e/blipchat-ui/node_modules || (cd hack/e2e/blipchat-ui && npm install --no-audit --no-fund)
	BLIP_BROWSER_TESTS=1 go test -v -count=1 -run TestBrowser ./internal/blipchat/

guest:
	hack/guest/build.sh

images: build guest
	hack/build-images.sh

kind-up:
	hack/kind-up.sh

kind-down:
	hack/kind-down.sh
