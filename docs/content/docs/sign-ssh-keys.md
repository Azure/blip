---
title: "User Authentication"
description: "Authenticate with an SSH public key"
weight: 3
---

Blip authenticates users through trusted SSH public keys stored in Kubernetes ConfigMaps with the `blip.azure.com/user` label and a `pubkey` data key.

## Add an SSH public key

Create a ConfigMap with the `blip.azure.com/user` label and your public key in `pubkey`:

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

Or with `kubectl`:

```shell
KEY=$(cat ~/.ssh/id_ed25519.pub)
kubectl create configmap "$(whoami)-key" \
  -n blip \
  --from-literal=pubkey="$KEY"
kubectl label configmap "$(whoami)-key" \
  -n blip \
  blip.azure.com/user="$(whoami)"
```

The label value is the user identity for quotas. It must be non-empty.

## Next steps

- [Connecting to a Blip]({{% relref "connecting-to-a-blip" %}})
