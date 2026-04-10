---
title: "Nested Blips"
description: "Allocate VMs from inside an existing blip"
weight: 5
---

From inside an allocated VM you can SSH back to the gateway to get another VM. Each VM has a client key generated at boot and the gateway injects an SSH config pointing back to itself, so recursive allocation works out of the box.

## Connect

```shell
ssh blip
```

This uses the injected config at `~/.ssh/config` which points `blip` (and `blip-gateway`) back to the gateway with the VM's client key.

## Identity propagation

The gateway resolves the original user's identity through the VM client key. Nested VMs are owned by the original connecting user, not the intermediate VM. This means:

- Per-user quotas (`--max-blips-per-user`) count against the original user.
- `blip retain` on a nested VM produces a session ID the original user can reconnect to directly.

