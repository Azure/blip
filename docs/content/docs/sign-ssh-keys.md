---
title: "Add SSH Key"
description: "Add your SSH public key to the gateway allow-list"
weight: 3
---

Blip authenticates SSH connections using public keys registered as BlipOwner CRs.

## Add your key

Create a BlipOwner CR with your public key:

```yaml
apiVersion: blip.io/v1alpha1
kind: BlipOwner
metadata:
  name: alice-laptop
  namespace: blip
spec:
  sshKey:
    publicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... alice@laptop"
```

Or create it directly from the command line:

```shell
KEY=$(cat ~/.ssh/id_ed25519.pub)
kubectl apply -f - <<EOF
apiVersion: blip.io/v1alpha1
kind: BlipOwner
metadata:
  name: $(whoami)-key
  namespace: blip
spec:
  sshKey:
    publicKey: "$KEY"
EOF
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
