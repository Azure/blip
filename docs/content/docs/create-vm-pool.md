---
title: "Create a VM Pool"
description: "Deploy a VM pool"
weight: 2
---

A VM pool is a set of pre-provisioned KubeVirt VMs. Idle VMs are allocated on SSH connection, destroyed on disconnect, and automatically replaced to maintain replica count. The gateway selects VMs by the `blip.io/pool` label.

## Deploy

Apply the pool manifest directly from the latest release:

```shell
kubectl apply -f https://github.com/Azure/blip/releases/latest/download/pool.yaml
```

Or pin to a specific version:

```shell
kubectl apply -f https://github.com/Azure/blip/releases/download/v0.1.0/pool.yaml
```

## Kustomize

Reference the release artifact as a remote resource in your `kustomization.yaml`:

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - https://github.com/Azure/blip/releases/latest/download/pool.yaml
patches:
  - target:
      kind: VirtualMachinePool
      name: blip
    patch: |
      - op: replace
        path: /spec/replicas
        value: 10
```

## Customization

Download the manifest and edit it before applying:

```shell
curl -fsSLO https://github.com/Azure/blip/releases/latest/download/pool.yaml
# edit pool.yaml
kubectl apply -f pool.yaml
```

### CPU and memory

`domain.resources.requests` controls pod-level resource requests:

```yaml
domain:
  cpu:
    cores: 4
    sockets: 1
    threads: 1
  memory:
    guest: 8Gi
  resources:
    requests:
      memory: 2Gi
      cpu: "1"
```

### Base image

Any cloud-init-compatible image with `sshd` installed:

```yaml
volumes:
  - name: rootdisk
    containerDisk:
      image: quay.io/containerdisks/fedora:40
```

## Next steps

- [Add SSH Key]({{% relref "sign-ssh-keys" %}})
