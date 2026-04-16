---
title: "User Authentication"
description: "How users authenticate to the Blip SSH gateway"
weight: 3
---

Two authentication methods, usable independently or together:

1. **Static public keys** — SSH public keys registered as Kubernetes ConfigMaps.
2. **Dynamic auth via authenticator service** — device-flow where unrecognized users authenticate via browser, provisioning their key automatically.

Both produce an SSH public key in a ConfigMap with the `blip.azure.com/user` label.

## Method 1: Static public keys

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

Or via CLI:

```shell
KEY=$(cat ~/.ssh/id_ed25519.pub)
kubectl create configmap "$(whoami)-key" \
  -n blip \
  --from-literal=pubkey="$KEY"
kubectl label configmap "$(whoami)-key" \
  -n blip \
  blip.azure.com/user="$(whoami)"
```

The `blip.azure.com/user` label value is the user identity for quota tracking. Must be non-empty.

## Method 2: Dynamic auth via authenticator service

When an authenticator service is configured, users with unrecognized SSH keys are prompted to authenticate via browser.

### How it works

1. User runs `ssh <gateway>` with an unrecognized key.
2. Gateway rejects the key but records the fingerprint and public key.
3. SSH falls back to keyboard-interactive. Gateway generates a signed JWT containing the SSH public key and presents a URL to the authenticator service.
4. User opens the URL, authenticates via identity provider.
5. Authenticator creates a Kubernetes Secret in `blip` namespace with:
   - Label: `blip.azure.com/auth-session: "true"`
   - Annotation: `blip.azure.com/fingerprint` — SSH key fingerprint
   - Annotation: `blip.azure.com/subject` — authenticated user identity
   - Data key `pubkey` — SSH public key
6. Gateway detects the Secret and completes the SSH connection as `device:<subject>`.

### Gateway configuration

Enable device-flow auth by setting `authenticator-url` in the OIDC ConfigMap. See [OIDC Authentication]({{% relref "oidc-auth" %}}) for full configuration.

### OIDC user endpoint

The gateway exposes `POST /auth/user` when OIDC is configured. This endpoint accepts an OIDC bearer token and a `pubkey` form value (a gateway-signed JWT from the device flow), verifies both, and creates a session ConfigMap with the user's SSH public key. See [OIDC Authentication]({{% relref "oidc-auth" %}}) for details.

### Configuring Entra ID with the Azure Function authenticator

The [`azure-auth`](https://github.com/Azure/blip/tree/main/azure-auth) cloud function uses Azure App Service Authentication (EasyAuth) to log users in via Entra ID. EasyAuth injects the user's token in `X-MS-TOKEN-AAD-ID-TOKEN`; the function forwards it to the gateway's `POST /auth/user` endpoint.

For ConfigMap configuration, see the [Azure Entra ID example]({{% relref "oidc-auth#azure-entra-id-example" %}}) in the OIDC docs.

### Auth session Secrets

Authenticator services must create Secrets conforming to this schema:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: auth-<unique-id>
  namespace: blip
  labels:
    blip.azure.com/auth-session: "true"
  annotations:
    blip.azure.com/fingerprint: "SHA256:..."
    blip.azure.com/subject: "user@example.com"
data:
  pubkey: <base64-encoded SSH public key>
```

## Connect

```shell
GATEWAY=$(kubectl get svc ssh-gateway -n blip -o jsonpath='{.status.loadBalancer.ingress[0].ip}')

ssh $GATEWAY
```

With static keys, authentication succeeds immediately. With device-flow, the terminal displays a URL; authenticate there, then the SSH session proceeds.

## Session lifecycle

Default max session duration: 12 hours (`--max-session-duration`). VMs are ephemeral — destroyed on disconnect. Per-user quotas via `--max-blips-per-user`.

- **`blip retain`** — keeps the VM alive, prints a session ID for reconnection.
- **`blip release`** — destroys the VM immediately.

## Next steps

- [OIDC Authentication]({{% relref "oidc-auth" %}})
- [Nested Blips]({{% relref "nested-blips" %}})
- [GitHub Actions Runner]({{% relref "github-actions-runner" %}})
