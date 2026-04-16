REGISTRY ?= stargatetmedev.azurecr.io
BLIP_TAG ?= latest
RUNNER_VERSION ?= 2.321.0
CONTAINER_ENGINE ?= docker

export REGISTRY BLIP_TAG

.PHONY: all
all: manifest pool blip

.PHONY: blip
blip:
	$(CONTAINER_ENGINE) build -t $(REGISTRY)/blip:$(BLIP_TAG) -f Dockerfile .
	mkdir -p dist
	$(CONTAINER_ENGINE) save $(REGISTRY)/blip:$(BLIP_TAG) -o dist/image.tar.gz

.PHONY: base
base:
	$(CONTAINER_ENGINE) build \
		-t $(REGISTRY)/blip-base:$(BLIP_TAG) \
		-f images/base/Containerfile .
	mkdir -p dist
	$(CONTAINER_ENGINE) save $(REGISTRY)/blip-base:$(BLIP_TAG) -o dist/base.tar.gz

.PHONY: manifest
manifest:
	mkdir -p dist
	envsubst '$$REGISTRY $$BLIP_TAG' < manifests/deploy.yaml > dist/manifest.yaml

.PHONY: pool
pool:
	mkdir -p dist
	cp manifests/pool.yaml dist/pool.yaml
