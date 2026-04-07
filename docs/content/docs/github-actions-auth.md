---
title: "Github Actions Auth"
description: "Authenticate from GitHub Actions workflows"
weight: 4
---

Blip supports GitHub Actions authentication as an alternative to SSH certificates. The workflow requests a GitHub Actions token with audience `blip` and passes it as the SSH password. The gateway verifies the signature, audience, and repository against its allow-list.

## Configure the gateway

Allowed repositories are stored in the `ssh-gateway-auth` ConfigMap watched by the gateway. Changes take effect in real time — no restart required.

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: ssh-gateway-auth
  namespace: blip
data:
  allowed-repos: |
    my-org/my-repo
    my-org/another-repo
```

## Pin the gateway host key

The GitHub Actions token is sent during the SSH handshake — you **must** pin the host key. Never set `StrictHostKeyChecking` to `accept-new` or `no`.

Extract the public key:

```shell
kubectl -n blip get secret ssh-host-key -o jsonpath='{.data.host_key}' \
  | base64 -d \
  | ssh-keygen -y -f /dev/stdin
```

Store as a known hosts entry for your workflow (see example below):

```
ssh-gateway.example.com ssh-ed25519 AAAAC3Nza...
```

## Example Workflow

```yaml
name: CI
on: push

env:
  GATEWAY_HOST: ssh-gateway.example.com
  GATEWAY_HOST_KEY: ssh-gateway.example.com ssh-ed25519 AAAAC3Nza...

jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      id-token: write

    steps:
      - name: Get GitHub Actions Token
        id: token
        run: |
          TOKEN=$(curl -sS \
            -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=blip" \
            | jq -r '.value')
          echo "::add-mask::$TOKEN"
          echo "token=$TOKEN" >> "$GITHUB_OUTPUT"

      - name: SSH to Blip VM
        run: |
          mkdir -p ~/.ssh
          echo "$GATEWAY_HOST_KEY" > ~/.ssh/blip_known_hosts
          sshpass -p "${{ steps.token.outputs.token }}" \
            ssh -o StrictHostKeyChecking=yes \
                -o UserKnownHostsFile=~/.ssh/blip_known_hosts \
                runner@"$GATEWAY_HOST" \
                "echo 'Connected to Blip VM'; uname -a"
```

`permissions.id-token: write` is required. Audience must be `blip`. `::add-mask::` prevents token leakage in logs.

## Session behavior

- **Default TTL:** 30 minutes (vs 8 hours for certificate auth).
- **Identity:** `github-actions:<repository>:ref:refs/heads/<branch>`.
- **Ephemeral:** VMs destroyed on disconnect.
- Per-user quotas apply using the GitHub Actions identity.

## Security

- Tokens are short-lived (~5 min) and single-use.
- All GitHub Actions authentications are logged with the full subject claim.

