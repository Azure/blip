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

Add your public key to the `ssh-gateway-auth` ConfigMap in the `blip` namespace. One key per line, `authorized_keys` format.

```shell
kubectl edit configmap ssh-gateway-auth -n blip
```

Or patch it directly:

```shell
KEY=$(cat ~/.ssh/id_ed25519.pub)
kubectl patch configmap ssh-gateway-auth -n blip \
  --type merge -p "{\"data\":{\"allowed-pubkeys\":\"$KEY\n\"}}"
```

The gateway picks up changes in real time — no restart required.

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
