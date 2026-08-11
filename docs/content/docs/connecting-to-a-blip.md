---
title: "Connecting to a Blip"
description: "Connect, retain, release, and nest Blips"
weight: 4
---

## Connect

```shell
GATEWAY=$(kubectl get svc ssh-gateway -n blip -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
ssh $GATEWAY
```

Registered SSH public keys connect immediately.

## Session lifecycle

Default max duration: 12 hours (`--max-session-duration`). VMs are destroyed on disconnect. Per-user quota: `--max-blips-per-user`.

- **`blip retain`**: keep the VM alive and print a reconnect session ID.
- **`blip release`**: destroy the VM now.

## Nested Blips

From a Blip, SSH back to the gateway:

```shell
ssh blip
```

Each VM gets a boot-generated client key and SSH config. Nested VMs are owned by the original user.

- Quotas count against the original user.
- `blip retain` returns a session ID the original user can reconnect to directly.
