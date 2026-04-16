---
title: "Nested Blips"
description: "Allocate VMs from inside an existing blip"
weight: 5
---

From inside an allocated VM you can SSH back to the gateway to get another VM. Each VM has a client key generated at boot and an injected SSH config pointing back to the gateway.

## Connect

```shell
ssh blip
```

## Identity propagation

The gateway resolves the original user's identity through the VM client key. Nested VMs are owned by the original user, not the intermediate VM:

- Per-user quotas (`--max-blips-per-user`) count against the original user.
- `blip retain` on a nested VM produces a session ID the original user can reconnect to directly.

## Next steps

- [GitHub Actions Runner]({{% relref "github-actions-runner" %}})
