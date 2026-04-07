---
title: "Sign SSH Keys"
description: "Sign your SSH public key with the cluster CA"
weight: 3
---

Blip uses SSH certificates, not raw public keys. The `blip-controller` generates a CA keypair on first startup and stores it as a Kubernetes Secret. The gateway trusts any certificate signed by this CA.

## Generate an SSH key

```shell
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""
```

## Sign your key

```shell
kubectl blip sign-identity
```

Reads `~/.ssh/id_ed25519.pub`, fetches the CA key from the `ssh-ca-keypair` Secret in the `blip` namespace, and writes the certificate to `~/.ssh/id_ed25519-cert.pub`.

Requires RBAC read access to the `ssh-ca-keypair` Secret.

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

- Certificates have a configurable TTL, defaulting to 30 days.
- Each certificate embeds the signer's identity (`KeyId`); all connections are logged.
- Per-user quotas via `--max-blips-per-user`.

## Next steps

- [Github Actions Auth]({{% relref "github-actions-auth" %}})
