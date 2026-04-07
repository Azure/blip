---
title: "Getting Started"
description: "Install KubeVirt and deploy Blip"
weight: 1
---

## Prerequisites

- Kubernetes cluster (v1.26+)
- `kubectl` configured with cluster admin access

## Install KubeVirt

```shell
export KUBEVIRT_VERSION=v1.8.1
kubectl apply -f "https://github.com/kubevirt/kubevirt/releases/download/${KUBEVIRT_VERSION}/kubevirt-operator.yaml"
kubectl apply -f "https://github.com/kubevirt/kubevirt/releases/download/${KUBEVIRT_VERSION}/kubevirt-cr.yaml"
```

## Install Blip

```shell
kubectl apply -f https://github.com/project-unbounded/blip/releases/latest/download/manifest.yaml
```

## Install the kubectl plugin

### With Krew (recommended)

```shell
kubectl krew install --manifest-url=https://github.com/project-unbounded/blip/releases/latest/download/blip.yaml
```

### Direct download

```shell
# Linux (amd64)
curl -fsSL https://github.com/project-unbounded/blip/releases/latest/download/kubectl-blip_linux_amd64.tar.gz | tar xz
sudo install kubectl-blip /usr/local/bin/kubectl-blip

# macOS (Apple Silicon)
curl -fsSL https://github.com/project-unbounded/blip/releases/latest/download/kubectl-blip_darwin_arm64.tar.gz | tar xz
sudo install kubectl-blip /usr/local/bin/kubectl-blip
```

## Next steps

- [Create a VM Pool]({{% relref "create-vm-pool" %}})
- [Sign SSH Keys]({{% relref "sign-ssh-keys" %}})
