---
title: "Create a VM Pool"
description: "Deploy a VM pool"
weight: 2
---

A VM pool is a set of pre-provisioned KubeVirt VMs. Idle VMs are allocated on SSH connection, destroyed on disconnect, and automatically replaced to maintain replica count.

## Deploy

```shell
kubectl apply -f https://github.com/Azure/blip/releases/latest/download/pool.yaml
```

Pin a version by replacing `latest/download` with e.g. `download/v0.1.0`.

## Kustomize

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

```shell
curl -fsSLO https://github.com/Azure/blip/releases/latest/download/pool.yaml
```

### CPU and memory

```yaml
domain:
  cpu:
    cores: 4
  memory:
    guest: 8Gi
  resources:
    requests:
      memory: 2Gi
      cpu: "1"
```

### Base image

The root disk is served as a [containerDisk](https://kubevirt.io/user-guide/storage/disks_and_volumes/#containerdisk) — a regular container image containing the VM filesystem. No PVCs or CDI are required.

```yaml
volumes:
  - containerDisk:
      image: quay.io/containerdisks/fedora:40
    name: rootdisk
```

The image must be cloud-init-compatible with `sshd` installed.

## Next steps

- [User Authentication]({{% relref "sign-ssh-keys" %}})
