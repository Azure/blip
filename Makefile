SHELL := /bin/bash
GO ?= go
BIN := $(CURDIR)/bin
TOOLS := $(CURDIR)/bin/tools
CONTROLLER_GEN_VERSION := v0.18.0
PROTOC_GEN_GO_VERSION := v1.36.6
PROTOC_GEN_GO_GRPC_VERSION := v1.5.1
CONTROLLER_GEN := $(TOOLS)/controller-gen
PROTOC_GEN_GO := $(TOOLS)/protoc-gen-go
PROTOC_GEN_GO_GRPC := $(TOOLS)/protoc-gen-go-grpc
BLIPD_IMAGE ?= blip/blipd:dev
SLOT_IMAGE ?= blip/blip-slot:dev
KIND_CLUSTER ?= blip
T := timeout -s TERM
# A private Go build cache: other workloads on shared hosts clean
# ~/.cache/go-build during builds (see hack/go.sh, which also retries once).
BLIP_GOCACHE ?= $(CURDIR)/.cache/go-build
export GOCACHE := $(BLIP_GOCACHE)
export BLIP_GOCACHE
export GO
GOB := $(CURDIR)/hack/go.sh

.PHONY: redeploy blipd-images dst registry-up ubuntu-image e2e-image e2e build generate manifests proto test test-envtest images kind-up kind-down kind-load deploy tools guest

build:
	CGO_ENABLED=0 $(T) 600 $(GOB) build -trimpath -ldflags '-s -w' -o $(BIN)/ ./cmd/...

$(CONTROLLER_GEN):
	GOBIN=$(TOOLS) $(T) 600 $(GO) install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION)
$(PROTOC_GEN_GO):
	GOBIN=$(TOOLS) $(T) 600 $(GO) install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
$(PROTOC_GEN_GO_GRPC):
	GOBIN=$(TOOLS) $(T) 600 $(GO) install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GO_GRPC_VERSION)
tools: $(CONTROLLER_GEN) $(PROTOC_GEN_GO) $(PROTOC_GEN_GO_GRPC)

generate: $(CONTROLLER_GEN)
	$(T) 300 $(CONTROLLER_GEN) object paths=./internal/api/...

manifests: $(CONTROLLER_GEN)
	$(T) 300 $(CONTROLLER_GEN) crd paths=./internal/api/... output:crd:artifacts:config=config/base/crd

proto: $(PROTOC_GEN_GO) $(PROTOC_GEN_GO_GRPC)
	for f in $$(find internal/proto -name '*.proto'); do \
	  PATH=$(TOOLS):$$PATH $(T) 120 protoc -I . --go_out=paths=source_relative:. \
	    --go-grpc_out=paths=source_relative:. $$f || exit 1; done

test:
	$(T) 600 $(GO) test ./...

# dst runs TestStorageDST, a seeded random walk over storage operations on
# the real kernel with fault and crash injection, once per seed in
# DST_SEEDS, in parallel (each seed gets its own namespaces and names).
# Needs root (or passwordless sudo). Logs: bin/dst-<seed>.log. Replay a
# failure with DST_SEEDS=<seed>; see internal/storage/itest_dst_test.go.
DST_SEEDS ?= $(shell date +%s)
DST_STEPS ?= 150
DST_FAULTS ?= 0.15
DST_CRASHES ?= 0.05
SUDO ?= $(shell [ "$$(id -u)" = 0 ] || echo sudo)
dst:
	@mkdir -p $(BIN)
	$(T) 300 $(GO) test -c -o $(BIN)/storage.test ./internal/storage/
	@cd internal/storage && slot=0; pids=; for s in $(DST_SEEDS); do \
	  ( $(SUDO) $(T) 1800 env BLIP_ROOT_TESTS=1 PATH="$$PATH" BLIP_DST_SEED=$$s BLIP_DST_STEPS=$(DST_STEPS) \
	      BLIP_DST_FAULTS=$(DST_FAULTS) BLIP_DST_CRASHES=$(DST_CRASHES) BLIP_DST_SLOT=$$slot \
	      $(BIN)/storage.test -test.run 'TestStorageDST$$' -test.v -test.count=1 -test.timeout 1790s > $(BIN)/dst-$$s.log 2>&1 \
	    && echo "seed $$s: ok" || { echo "seed $$s: FAIL, see $(BIN)/dst-$$s.log"; exit 1; } ) & \
	  pids="$$pids $$!"; slot=$$((slot+1)); done; rc=0; for p in $$pids; do wait $$p || rc=1; done; exit $$rc

# envtest runs the controller integration tests against a real kube-apiserver.
ENVTEST_DIR ?= $(CURDIR)/bin/envtest
ENVTEST_K8S ?= 1.33.x
SETUP_ENVTEST := $(TOOLS)/setup-envtest
$(SETUP_ENVTEST):
	GOBIN=$(TOOLS) $(T) 600 $(GO) install sigs.k8s.io/controller-runtime/tools/setup-envtest@release-0.21
test-envtest: $(SETUP_ENVTEST)
	KUBEBUILDER_ASSETS="$$($(T) 300 $(SETUP_ENVTEST) use $(ENVTEST_K8S) --bin-dir $(ENVTEST_DIR) -p path)" \
	  $(T) 600 $(GO) test ./internal/controller/ -count=1

# The guest kernel, initramfs and cloud-hypervisor are built by the guest
# makefile target (hack/guest), which writes them to _output/guest/.
guest:
	$(MAKE) -f hack/guest/Makefile

images: blipd-images
	$(T) 600 docker build --provenance=false -q -t localhost:5001/$(E2E_IMAGE_TAG) -f images/blip-e2e/Dockerfile . >/dev/null

# The images with bin/blipd (controller, node daemon, slot pods).
blipd-images: build
	test -f _output/guest/vmlinuz || { echo "run 'make guest' first"; exit 1; }
	$(T) 1200 docker build --provenance=false -q -t $(BLIPD_IMAGE) -f images/blipd/Dockerfile . >/dev/null
	$(T) 600 docker build --provenance=false -q -t $(SLOT_IMAGE) -f images/blip-slot/Dockerfile . >/dev/null

kind-up:
	$(T) 900 hack/kind/up.sh

kind-down:
	$(T) 600 hack/kind/down.sh

# Skips images already loaded (KIND_LOAD_FORCE=1 loads anyway).
kind-load:
	KIND_CLUSTER=$(KIND_CLUSTER) $(T) 900 hack/kind/load.sh $(BLIPD_IMAGE) $(SLOT_IMAGE)

# Inner loop after editing Go code: rebuild bin/blipd and its images, load
# what changed, apply the manifests, restart and wait until the controller
# has a session with every node daemon. Needs `make guest` once.
redeploy: blipd-images kind-load deploy
	KIND_CLUSTER=$(KIND_CLUSTER) $(T) 400 hack/kind/ready.sh

# The images use fixed :dev tags, so applying unchanged manifests does not
# replace the pods; restart them to pick up images loaded by kind-load.
deploy:
	# CRDs first: the overlay has BlipPools.
	$(T) 120 kubectl --context kind-$(KIND_CLUSTER) apply --server-side --force-conflicts -k config/base/crd
	$(T) 60 kubectl --context kind-$(KIND_CLUSTER) wait --for=condition=Established crd --all --timeout=50s
	$(T) 300 kubectl --context kind-$(KIND_CLUSTER) apply --server-side --force-conflicts -k config/overlays/kind
	$(T) 60 kubectl --context kind-$(KIND_CLUSTER) -n blip-system rollout restart deploy/blip-controller ds/blip-node
	# The slot image tag does not change, so replace free slots to run the new
	# image; their pools create new ones.
	$(T) 60 kubectl --context kind-$(KIND_CLUSTER) delete pods -A -l blip.example.com/slot=free --wait=false

# End-to-end test against the kind cluster (see docs/e2e.md).
e2e:
	KIND_CLUSTER=$(KIND_CLUSTER) $(T) 3600 hack/e2e/run.sh

# Local plain-HTTP registry on the kind network (prints <ip>:5000).
UBUNTU_IMAGE_TAG ?= blip-ubuntu:dev
E2E_IMAGE_TAG ?= blip-e2e:dev
registry-up:
	$(T) 300 hack/registry/up.sh

# Build the ubuntu+sshd guest image and push it to the local registry.
ubuntu-image: registry-up build
	$(T) 900 docker build --provenance=false -t localhost:5001/$(UBUNTU_IMAGE_TAG) -f images/blip-ubuntu/Dockerfile .
	$(T) 300 docker push localhost:5001/$(UBUNTU_IMAGE_TAG)
	@echo "cluster reference: $$(hack/registry/up.sh)/$(UBUNTU_IMAGE_TAG)"

# Build the e2e guest image and push it to the local registry (hack/e2e/run.sh
# also does this unless E2E_IMAGE is set).
e2e-image: registry-up build
	$(T) 600 docker build --provenance=false -t localhost:5001/$(E2E_IMAGE_TAG) -f images/blip-e2e/Dockerfile .
	$(T) 300 docker push localhost:5001/$(E2E_IMAGE_TAG)
	@echo "cluster reference: $$(hack/registry/up.sh)/$(E2E_IMAGE_TAG)"
