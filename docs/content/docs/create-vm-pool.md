---
title: "Create a VM Pool"
description: "Generate and deploy a VM pool"
weight: 2
---

A VM pool is a set of pre-provisioned KubeVirt VMs. Idle VMs are allocated on SSH connection, destroyed on disconnect, and automatically replaced to maintain replica count. The gateway selects VMs by the `blip.io/pool` label.

## Generate and deploy

```shell
kubectl blip generate-pool --name default --replicas 10 -n blip > pool.yaml
kubectl apply -f pool.yaml
```

## Customization

Edit `pool.yaml` before applying.

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
