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

## Create a VM Pool

```shell
kubectl apply -f https://github.com/project-unbounded/blip/releases/latest/download/pool.yaml
```

See [Create a VM Pool]({{% relref "create-vm-pool" %}}) for customization options and kustomize usage.

## Next steps

- [Create a VM Pool]({{% relref "create-vm-pool" %}})
- [Add SSH Key]({{% relref "sign-ssh-keys" %}})
