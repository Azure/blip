---
title: "User Authentication"
description: "OAuth device flow, OIDC automation tokens, and static test keys"
weight: 3
---

Blip has one user authentication backend: trusted SSH public keys stored in Kubernetes ConfigMaps with the `blip.azure.com/user` label and a `pubkey` data key.

Most users should not create those ConfigMaps by hand. They should connect with SSH, follow the OAuth device-flow URL, and let the authenticator register their key. Automation, especially GitHub Actions, can register a key directly with an OIDC bearer token. Static ConfigMaps are still useful as a simple fallback for tests and local development.

## Recommended: OAuth device flow

When an authenticator service is configured, users with unrecognized SSH keys are prompted to authenticate in a browser.

1. User runs `ssh <gateway>` with an unrecognized key.
2. Gateway records the SSH public key and shows a browser URL through keyboard-interactive auth.
3. User opens the URL and authenticates with the identity provider.
4. The authenticator forwards the identity token and gateway-signed pubkey token to `POST /auth/user`.
5. The gateway verifies both tokens and creates a trusted pubkey ConfigMap.
6. The waiting SSH connection continues as `oidc:<subject>`.

The same registered key is accepted immediately until the OIDC token expiry stored on the ConfigMap. Expired dynamic key ConfigMaps are deleted by the controller.

## OIDC API for automation

`POST /auth/user` registers a public key using an OIDC bearer token. This is intended mostly for non-interactive environments such as GitHub Actions.

The request must include:

| Input | Description |
|-------|-------------|
| `Authorization: Bearer <token>` | OIDC token issued by the configured provider. |
| `pubkey` form value | Either a raw SSH public key for automation or a gateway-signed pubkey JWT from device flow. |

For GitHub Actions, configure the gateway with the GitHub Actions issuer and the audience requested by your workflow:

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

Then a workflow can request an ID token for that audience and post a job-scoped SSH public key to the gateway:

```shell
curl -fsS -X POST "https://<gateway-host>/auth/user" \
  -H "Authorization: Bearer $ACTIONS_ID_TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "pubkey=$(cat ./id_ed25519.pub)"
```

Workflows must enable GitHub's OIDC token permission, for example `permissions: id-token: write`.

The gateway uses the OIDC token `sub` as the authenticated subject, stores a Kubernetes-safe form in `blip.azure.com/user`, and records the original subject in `blip.azure.com/subject`.

## Static public keys for tests

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

## Gateway configuration

The gateway reads OIDC and device-flow settings from the ConfigMap named by `--oidc-config` or `OIDC_CONFIG`.

| Field | Required | Description |
|-------|----------|-------------|
| `oidc-issuer-url` | yes | Trusted OIDC issuer URL. Used for OIDC discovery. |
| `oidc-audience` | yes | Expected `aud` claim in the OIDC token. |
| `tls-secret-name` | yes | Kubernetes Secret containing `tls.crt` and `tls.key` for the HTTPS API server and device-flow JWT signing. |
| `authenticator-url` | no | Web authenticator URL for browser device-flow SSH login. Omit this for OIDC automation-only setups. |

When `oidc-issuer-url` and `oidc-audience` are present, the gateway enables `POST /auth/user`. Device-flow SSH login additionally requires `authenticator-url`.

### Azure Entra ID device-flow example

Using the [`azure-auth`](https://github.com/Azure/blip/tree/main/azure-auth) Function App authenticator:

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

The `--external-host` flag or `GATEWAY_EXTERNAL_HOST` environment variable must be set to the gateway's public hostname. The device-flow JWT uses it as the `iss` claim.

The Azure Function requires `APISERVER_URL` set to the Kubernetes API server URL so it can fetch the gateway TLS certificate from the `gateway-tls-certs` ConfigMap in `kube-public`.

## Connect

```shell
GATEWAY=$(kubectl get svc ssh-gateway -n blip -o jsonpath='{.status.loadBalancer.ingress[0].ip}')

ssh $GATEWAY
```

With a registered static or OIDC key, authentication succeeds immediately. With device flow, the terminal displays a URL; authenticate there, then the SSH session proceeds.

## Session lifecycle

Default max session duration: 12 hours (`--max-session-duration`). VMs are ephemeral — destroyed on disconnect. Per-user quotas via `--max-blips-per-user`.

- **`blip retain`** — keeps the VM alive, prints a session ID for reconnection.
- **`blip release`** — destroys the VM immediately.

## Runtime notes

- OIDC discovery runs asynchronously on issuer URL changes. Requests can return 503 briefly until the verifier is ready.
- Removing `authenticator-url` disables browser device flow but keeps OIDC API registration enabled.
- Removing `oidc-issuer-url` or `oidc-audience` disables OIDC API registration. Static pubkey ConfigMaps continue to work.

## Next steps

- [Nested Blips]({{% relref "nested-blips" %}})
