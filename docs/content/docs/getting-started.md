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

Required for writable root disks. See [CDI docs](https://kubevirt.io/user-guide/storage/containerized_data_importer/).

```shell
export CDI_VERSION=$(curl -s -w '%{redirect_url}' https://github.com/kubevirt/containerized-data-importer/releases/latest | xargs basename)
kubectl apply -f "https://github.com/kubevirt/containerized-data-importer/releases/download/${CDI_VERSION}/cdi-operator.yaml"
kubectl apply -f "https://github.com/kubevirt/containerized-data-importer/releases/download/${CDI_VERSION}/cdi-cr.yaml"
```

## Install Local Static Provisioner

Blip VM boot disks use the [local static provisioner](https://github.com/kubernetes-sigs/sig-storage-local-static-provisioner) to bind PVCs to pre-allocated local disks on each node. This gives VMs direct access to local storage for better I/O performance.

1. Prepare local disks on each node and mount them under a discovery directory (e.g. `/mnt/disks`). See the [provisioner operations guide](https://github.com/kubernetes-sigs/sig-storage-local-static-provisioner/blob/master/docs/operations.md) for details.

2. Create a `local-storage` StorageClass:

```shell
kubectl apply -f - <<'EOF'
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: local-storage
provisioner: kubernetes.io/no-provisioner
volumeBindingMode: WaitForFirstConsumer
EOF
```

3. Deploy the provisioner via Helm:

```shell
helm repo add sig-storage-local-static-provisioner https://kubernetes-sigs.github.io/sig-storage-local-static-provisioner
helm install local-static-provisioner sig-storage-local-static-provisioner/local-static-provisioner \
  --namespace local-static-provisioner --create-namespace \
  --set classes[0].name=local-storage \
  --set classes[0].hostDir=/mnt/disks \
  --set classes[0].volumeMode=Filesystem
```

The provisioner will automatically create PersistentVolumes for each disk found under `/mnt/disks`. You need at least as many local disks as your VM pool replica count.

## Install Blip

```shell
kubectl apply -f https://github.com/Azure/blip/releases/latest/download/manifest.yaml
```

## Next steps

- [Create a VM Pool]({{% relref "create-vm-pool" %}})
- [User Authentication]({{% relref "sign-ssh-keys" %}})
