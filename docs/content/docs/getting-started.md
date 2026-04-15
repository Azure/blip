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

## Install CDI

VM pools require the [Containerized Data Importer](https://kubevirt.io/user-guide/storage/containerized_data_importer/) (CDI) for writable root disks:

```shell
export CDI_VERSION=$(curl -s -w '%{redirect_url}' https://github.com/kubevirt/containerized-data-importer/releases/latest | xargs basename)
kubectl apply -f "https://github.com/kubevirt/containerized-data-importer/releases/download/${CDI_VERSION}/cdi-operator.yaml"
kubectl apply -f "https://github.com/kubevirt/containerized-data-importer/releases/download/${CDI_VERSION}/cdi-cr.yaml"
```

## Install Blip

```shell
kubectl apply -f https://github.com/Azure/blip/releases/latest/download/manifest.yaml
```

## Create a VM Pool

```shell
kubectl apply -f https://github.com/Azure/blip/releases/latest/download/pool.yaml
```

## Next steps

- [Customize a VM Pool]({{% relref "create-vm-pool" %}})
- [Add SSH Key]({{% relref "sign-ssh-keys" %}})
