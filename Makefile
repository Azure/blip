REGISTRY ?= stargatetmedev.azurecr.io
BLIP_TAG ?= latest
CONTAINER_ENGINE ?= docker

export REGISTRY BLIP_TAG

.PHONY: all
all: manifest pool blip

.PHONY: blip
blip:
	$(CONTAINER_ENGINE) build -t $(REGISTRY)/blip:$(BLIP_TAG) -f Dockerfile .
	mkdir -p dist
	$(CONTAINER_ENGINE) save $(REGISTRY)/blip:$(BLIP_TAG) -o dist/image.tar.gz

.PHONY: manifest
manifest:
	mkdir -p dist
	envsubst '$$REGISTRY $$BLIP_TAG' < deploy.yaml > dist/manifest.yaml

.PHONY: pool
pool:
	mkdir -p dist
	cp pool.yaml dist/pool.yaml
