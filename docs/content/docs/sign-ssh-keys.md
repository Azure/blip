---
title: "User Authentication"
description: "How users authenticate to the Blip SSH gateway"
weight: 3
---

Blip supports two user authentication methods that can be used independently or together:

1. **Static public keys** — SSH public keys registered as Kubernetes ConfigMaps.
2. **Dynamic auth via an authenticator service** — a device-flow where unrecognized users are redirected to a browser-based login (e.g. an OIDC shim) that provisions their key automatically.

Both methods result in the same outcome: an SSH public key stored in a ConfigMap with the `blip.azure.com/user` label. The gateway watches these ConfigMaps and picks up changes without a restart.

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

## Method 2: Dynamic auth via authenticator service

When an authenticator service is configured, users with unrecognized SSH keys are prompted to authenticate via their browser instead of being rejected. This is useful for teams where managing individual ConfigMaps is impractical.

### How it works

1. A user runs `ssh <gateway>` with an SSH key that is not in any ConfigMap.
2. The gateway's pubkey callback rejects the key, but records the fingerprint and public key.
3. The SSH handshake falls back to keyboard-interactive auth. The gateway generates a signed JWT containing the user's SSH public key and fingerprint, and presents a URL pointing to the authenticator service.
4. The user opens the URL in their browser. The authenticator service (an OIDC shim or similar) authenticates the user via their identity provider.
5. On successful authentication, the authenticator creates a Kubernetes Secret in the `blip` namespace with:
   - Label: `blip.azure.com/auth-session: "true"`
   - Annotation: `blip.azure.com/fingerprint` — the user's SSH key fingerprint
   - Annotation: `blip.azure.com/subject` — the authenticated user identity
   - Data key `pubkey` — the user's SSH public key
6. The gateway detects the new Secret and completes the SSH connection, identifying the user as `device:<subject>`.

### Gateway configuration

Enable device-flow auth by setting these flags (or their environment variable equivalents):

| CLI flag | Environment variable | Description |
|----------|---------------------|-------------|
| `--authenticator-url` | `AUTHENTICATOR_URL` | URL of the authenticator web service. Enables device-flow auth when set. |

The authenticator URL is embedded in the JWT-signed link shown to the user during keyboard-interactive auth. The gateway's TLS signing key (from `--tls-secret-name`) is used to sign the JWT.

### OIDC user endpoint

When the HTTPS API server is enabled (`--oidc-issuer-url` and `--oidc-audience` are set), the gateway exposes a `POST /auth/user` endpoint. This endpoint accepts an OIDC bearer token and a `pubkey` form value (a gateway-signed JWT from the device flow), verifies both, and creates a ConfigMap (`user-<hash>`) with the user's SSH public key. The ConfigMap is labelled with `blip.azure.com/user` and is automatically picked up by the auth watcher — the user can SSH in immediately.

| CLI flag | Environment variable | Description |
|----------|---------------------|-------------|
| `--oidc-issuer-url` | `OIDC_ISSUER_URL` | Trusted OIDC issuer URL. Enables the HTTPS API server. |
| `--oidc-audience` | `OIDC_AUDIENCE` | Expected OIDC audience claim. |
| `--tls-secret-name` | `TLS_SECRET_NAME` | Kubernetes Secret with `tls.crt` and `tls.key` for the HTTPS server. |
| `--https-address` | `HTTPS_ADDRESS` | HTTPS listen address (default `:8443`). |

### Configuring Entra ID with the Azure Function authenticator

The [`azure-auth`](https://github.com/Azure/blip/tree/main/azure-auth) cloud function is a ready-made authenticator that uses Azure App Service Authentication (EasyAuth) to log users in via Microsoft Entra ID. EasyAuth handles the OIDC login at the platform level and injects the user's Entra ID token in the `X-MS-TOKEN-AAD-ID-TOKEN` header. The function forwards this token to the gateway's `POST /auth/user` endpoint.

To configure the gateway to accept these tokens, set `--oidc-issuer-url` and `--oidc-audience` to match the Entra ID App Registration used by EasyAuth on the Function App:

```
--oidc-issuer-url=https://login.microsoftonline.com/<tenant-id>/v2.0
--oidc-audience=<easyauth-app-registration-client-id>
--tls-secret-name=gateway-tls-key
--external-host=gateway.example.com
--authenticator-url=https://<function-app-name>.azurewebsites.net/api/auth
```

| Parameter | Value |
|-----------|-------|
| `--oidc-issuer-url` | `https://login.microsoftonline.com/<tenant-id>/v2.0` — the Entra ID v2.0 issuer for your tenant. The gateway fetches the OIDC discovery document at this URL to obtain signing keys for token verification. If your App Registration is configured for v1.0 tokens, use `https://sts.windows.net/<tenant-id>/` instead. |
| `--oidc-audience` | The **Application (client) ID** of the Entra ID App Registration configured as the EasyAuth identity provider on the Function App. This must match the `aud` claim in the ID tokens that EasyAuth issues. |
| `--authenticator-url` | The public URL of the Azure Function's `auth` HTTP trigger (e.g. `https://myapp.azurewebsites.net/api/auth`). This is shown to users during device-flow auth and used as the `aud` claim in the gateway-signed pubkey JWT. |
| `--external-host` | The gateway's public hostname. Used as the `iss` claim in the gateway-signed pubkey JWT. |

The Azure Function requires the `APISERVER_URL` environment variable set to the Kubernetes API server URL so it can fetch the gateway's TLS certificate from the `gateway-tls-certs` ConfigMap in `kube-public`.

### Auth session Secrets

The authenticator service is responsible for creating auth session Secrets. They must conform to this schema:

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

The gateway indexes these Secrets by fingerprint for fast lookups during SSH authentication.

## Connect

```shell
GATEWAY=$(kubectl get svc ssh-gateway -n blip -o jsonpath='{.status.loadBalancer.ingress[0].ip}')

ssh $GATEWAY
```

With static keys, authentication succeeds immediately. With device-flow auth, the terminal displays a URL to visit in your browser; after authenticating there, the SSH session proceeds.

## Session lifecycle

Default max session duration is 12 hours (configurable via `--max-session-duration`). VMs are ephemeral — destroyed on disconnect. Per-user quotas via `--max-blips-per-user`.

- **`blip retain`** — keeps the VM alive, prints a session ID for reconnection.
- **`blip release`** — destroys the VM immediately.

## Next steps

- [GitHub Actions Runner]({{% relref "github-actions-runner" %}})
