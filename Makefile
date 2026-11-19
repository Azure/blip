BINARIES := blip-controller blip-node blip-runtime blip-guest kubectl-blip
CONTROLLER_GEN ?= $(shell go env GOPATH)/bin/controller-gen

.PHONY: build generate test test-sim guest images kind-up kind-down

build:
	CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o bin/ $(addprefix ./cmd/,$(BINARIES))

generate:
	$(CONTROLLER_GEN) object:headerFile=hack/boilerplate.go.txt paths=./api/...
	$(CONTROLLER_GEN) crd paths=./api/... output:crd:dir=deploy/crd

test:
	go test ./...

# Production-machine simulations and their concurrent adapters. Ordinary
# `make test` also runs these tests; this target adds the race detector.
test-sim:
	go test -race ./internal/sim ./internal/simlive ./internal/simapp ./internal/atomicfile ./internal/storage ./internal/peer ./internal/nvme ./internal/node ./internal/controller ./internal/runtime ./internal/guest ./internal/session ./internal/wire ./internal/podapi

guest:
	hack/guest/build.sh

images: build guest
	hack/build-images.sh

kind-up:
	hack/kind-up.sh

kind-down:
	hack/kind-down.sh
