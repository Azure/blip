---
title: "Add SSH Key"
description: "Add your SSH public key to the gateway allow-list"
weight: 3
---

Blip authenticates SSH connections using explicitly allowed public keys. The gateway trusts any key present in its allow-list.

## Generate an SSH key

```shell
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""
```

## Add your key

```shell
kubectl blip allow-key
```

Reads `~/.ssh/id_ed25519.pub` and adds it to the `ssh-gateway-auth` ConfigMap in the `blip` namespace. The gateway picks up changes in real time — no restart required.

Requires RBAC write access to the `ssh-gateway-auth` ConfigMap.

## Connect

```shell
GATEWAY=$(kubectl get svc ssh-gateway -n blip -o jsonpath='{.status.loadBalancer.ingress[0].ip}')

ssh $GATEWAY
```

## Session lifecycle

Default max session duration is 8 hours (configurable via `--max-session-duration`).

VMs are ephemeral by default — destroyed on disconnect.

- **`blip retain`** — keeps the VM alive, prints a session ID for reconnection.
- **`blip release`** — destroys the VM immediately.

## Security

- Each connection is logged with the key fingerprint and identity.
- Per-user quotas via `--max-blips-per-user`.

## Next steps

- [Github Actions Auth]({{% relref "github-actions-auth" %}})
