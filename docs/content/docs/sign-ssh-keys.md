---
title: "User Authentication"
description: "Static keys, device flow, and OIDC automation"
weight: 3
---

Blip authenticates users through trusted SSH public keys stored in Kubernetes ConfigMaps with the `blip.azure.com/user` label and a `pubkey` data key.

## Static public keys for tests

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

## Recommended: OAuth device flow

With an authenticator, unknown SSH keys trigger browser auth.

1. User runs `ssh <gateway>` with an unknown key.
2. Gateway records the SSH public key and returns a browser URL through keyboard-interactive auth.
3. User opens the URL and signs in with the identity provider.
4. The authenticator sends the identity token and gateway-signed pubkey token to `POST /auth/user`.
5. The gateway verifies both tokens and creates a trusted pubkey ConfigMap.
6. The waiting SSH connection resumes as `oidc:<subject>`.

The registered key works until the OIDC token expiry recorded on the ConfigMap. The controller removes expired dynamic key ConfigMaps.

## OIDC password auth for automation

SSH password auth can accept an OIDC token for non-interactive clients such as GitHub Actions.

Configure the gateway with the GitHub Actions issuer and workflow audience:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: ssh-gateway-oidc
  namespace: blip
data:
  oidc-issuer-url: "https://token.actions.githubusercontent.com"
  oidc-audience: "blip"
  tls-secret-name: "gateway-tls-key"
```

A workflow can then request an ID token for that audience and pass it as the SSH password:

```shell
sshpass -p "$ACTIONS_ID_TOKEN" ssh \
  -o PreferredAuthentications=password \
  -o PubkeyAuthentication=no \
  runner@<gateway-host>
```

Workflows need `permissions: id-token: write`.

The gateway maps the OIDC token `sub` to `oidc:<subject>` for quota tracking and retained-session reconnects.

## OIDC API key registration

For key registration instead of password auth, `POST /auth/user` registers a public key with an OIDC bearer token.

Request inputs:

| Input | Description |
|-------|-------------|
| `Authorization: Bearer <token>` | OIDC token from the configured provider. |
| `pubkey` form value | Either a raw SSH public key for automation or a gateway-signed pubkey JWT from device flow. |

Gateway config:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: ssh-gateway-oidc
  namespace: blip
data:
  oidc-issuer-url: "https://token.actions.githubusercontent.com"
  oidc-audience: "blip"
  tls-secret-name: "gateway-tls-key"
```

Post a job-scoped SSH public key:

```shell
curl -fsS -X POST "https://<gateway-host>/auth/user" \
  -H "Authorization: Bearer $ACTIONS_ID_TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "pubkey=$(cat ./id_ed25519.pub)"
```

The gateway stores a Kubernetes-safe form of the OIDC token `sub` in `blip.azure.com/user` and records the original subject in `blip.azure.com/subject`.

## Gateway configuration

The gateway reads OIDC and device-flow settings from the ConfigMap named by `--oidc-config` or `OIDC_CONFIG`.

| Field | Required | Description |
|-------|----------|-------------|
| `oidc-issuer-url` | yes | Trusted OIDC issuer URL for discovery. |
| `oidc-audience` | yes | Expected `aud` claim in the OIDC token. |
| `tls-secret-name` | yes | Kubernetes Secret with `tls.crt` and `tls.key` for the HTTPS API server and device-flow JWT signing. |
| `authenticator-url` | no | Web authenticator URL for browser device-flow SSH login. Omit this for OIDC automation-only setups. |

`oidc-issuer-url` and `oidc-audience` enable `POST /auth/user`. Device-flow SSH login also needs `authenticator-url`.

### Azure Entra ID device-flow example

With the [`azure-auth`](https://github.com/Azure/blip/tree/main/azure-auth) Function App authenticator:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: ssh-gateway-oidc
  namespace: blip
data:
  oidc-issuer-url: "https://login.microsoftonline.com/<tenant-id>/v2.0"
  oidc-audience: "<easyauth-app-registration-client-id>"
  tls-secret-name: "gateway-tls-key"
  authenticator-url: "https://<function-app-name>.azurewebsites.net/api/auth"
```

Set `--external-host` or `GATEWAY_EXTERNAL_HOST` to the gateway public hostname. The device-flow JWT uses it as `iss`.

The Azure Function needs `APISERVER_URL` set to the Kubernetes API server URL to fetch the gateway TLS certificate from `kube-public/gateway-tls-certs`.

## Runtime notes

- OIDC discovery runs asynchronously on issuer URL changes. Requests can return 503 briefly until the verifier is ready.
- Removing `authenticator-url` disables browser device flow but leaves OIDC API registration enabled.
- Removing `oidc-issuer-url` or `oidc-audience` disables OIDC API registration. Static pubkey ConfigMaps still work.

## Next steps

- [Connecting to a Blip]({{% relref "connecting-to-a-blip" %}})
