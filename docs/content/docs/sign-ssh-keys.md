---
title: "Add SSH Key"
description: "Add your SSH public key to the gateway allow-list"
weight: 3
---

Blip authenticates SSH connections using public keys in the gateway's allow-list.

## Add your key

Add your public key to the `ssh-gateway-auth` ConfigMap (`authorized_keys` format, one key per line):

```shell
kubectl edit configmap ssh-gateway-auth -n blip
```

Or patch it directly:

```shell
KEY=$(cat ~/.ssh/id_ed25519.pub)
kubectl patch configmap ssh-gateway-auth -n blip \
  --type merge -p "{\"data\":{\"allowed-pubkeys\":\"$KEY\n\"}}"
```

Changes take effect without a gateway restart.

## Connect

```shell
GATEWAY=$(kubectl get svc ssh-gateway -n blip -o jsonpath='{.status.loadBalancer.ingress[0].ip}')

ssh $GATEWAY
```

## Session lifecycle

Default max session duration is 8 hours (configurable via `--max-session-duration`). VMs are ephemeral — destroyed on disconnect. Per-user quotas via `--max-blips-per-user`.

- **`blip retain`** — keeps the VM alive, prints a session ID for reconnection.
- **`blip release`** — destroys the VM immediately.

## Next steps

- [OIDC Authentication]({{% relref "oidc-auth" %}})
