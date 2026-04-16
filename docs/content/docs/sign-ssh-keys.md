---
title: "Add SSH Key"
description: "Add your SSH public key to the gateway allow-list"
weight: 3
---

Blip authenticates SSH connections using public keys registered as ConfigMaps in the `blip` namespace.

## Add your key

Create a ConfigMap with the `blip.azure.com/user` label and your public key in the `pubkey` data key:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: alice-laptop
  namespace: blip
  labels:
    blip.azure.com/user: "alice"
data:
  pubkey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... alice@laptop"
```

Or create it directly from the command line:

```shell
KEY=$(cat ~/.ssh/id_ed25519.pub)
kubectl create configmap "$(whoami)-key" \
  -n blip \
  --from-literal=pubkey="$KEY"
kubectl label configmap "$(whoami)-key" \
  -n blip \
  blip.azure.com/user="$(whoami)"
```

The `blip.azure.com/user` label value is the user identity used for per-user quota tracking. It must be non-empty.

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

- [GitHub Actions Runner]({{% relref "github-actions-runner" %}})
