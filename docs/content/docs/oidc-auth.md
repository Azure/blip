---
title: "OIDC Authentication"
description: "Configure OIDC auth via the ssh-gateway-oidc ConfigMap"
weight: 4
---

Blip supports OIDC authentication from any standards-compliant provider (Azure Entra, Google Cloud, etc.). OIDC configuration is managed entirely through the `ssh-gateway-oidc` ConfigMap, which the gateway watches at runtime — changes take effect immediately without a restart.

## ConfigMap reference

The gateway reads OIDC auth settings from a ConfigMap named by the `--oidc-config` flag (default: `ssh-gateway-oidc`, set via the `OIDC_CONFIG` environment variable). The default `deploy.yaml` includes an empty ConfigMap with this name.

| Field | Required | Description |
|-------|----------|-------------|
| `oidc-issuer-url` | yes | Trusted OIDC issuer URL (e.g. `https://login.microsoftonline.com/<tenant>/v2.0`). The gateway performs OIDC discovery against this URL. |
| `oidc-audience` | yes | Expected `aud` claim in the OIDC token (e.g. `api://blip` or an app client ID). |
| `tls-secret-name` | yes | Kubernetes Secret containing `tls.crt` and `tls.key` for the HTTPS API server. |
| `authenticator-url` | no | URL of the web authenticator for device-flow SSH login. Enables the device-flow keyboard-interactive fallback when set. |

When `oidc-issuer-url` and `oidc-audience` are both present, the gateway enables the HTTPS API server (`POST /auth/user`) and begins accepting OIDC bearer tokens. Removing either field disables OIDC auth.

## Enable OIDC auth

Populate the ConfigMap with your provider's settings:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: ssh-gateway-oidc
  namespace: blip
data:
  oidc-issuer-url: "https://login.microsoftonline.com/<tenant-id>/v2.0"
  oidc-audience: "<app-client-id>"
  tls-secret-name: "gateway-tls-key"
  authenticator-url: "https://<authenticator-host>/api/auth"
```

Apply the ConfigMap:

```shell
kubectl apply -f ssh-gateway-oidc.yaml
```

The gateway picks up changes immediately. Check the logs for confirmation:

```shell
kubectl logs -n blip -l app=ssh-gateway --tail=20 | grep "oidc config"
```

## Disable OIDC auth

Delete the data fields or the ConfigMap itself:

```shell
kubectl delete configmap ssh-gateway-oidc -n blip
```

The gateway reverts to SSH-key-only authentication. Active sessions are not interrupted.

## Azure Entra ID example

To use the [`azure-auth`](https://github.com/Azure/blip/tree/main/azure-auth) Function App authenticator with Azure Entra ID:

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

The `--external-host` flag (or `GATEWAY_EXTERNAL_HOST` env var) must also be set on the gateway deployment to the gateway's public hostname. This is used as the `iss` claim in gateway-signed JWTs.

See [User Authentication]({{% relref "sign-ssh-keys" %}}) for details on how the device-flow and OIDC user endpoint work.

## TLS certificate

The `tls-secret-name` field points to a Kubernetes Secret of type `kubernetes.io/tls` with `tls.crt` and `tls.key` keys. The gateway watches this Secret for rotations. If the Secret does not exist when the ConfigMap is first applied, HTTPS connections will fail until it is created.

## Runtime behavior

- **OIDC discovery** runs asynchronously when the issuer URL changes. There is a brief window after applying a new issuer where the verifier is not yet ready and requests return 503.
- **TLS certificate watcher** is created when `tls-secret-name` appears. Certificate rotations are picked up immediately.
- **Device-flow auth** activates when `authenticator-url` is set and deactivates when it is removed. The SSH server's keyboard-interactive callback checks the authenticator URL at connection time.

## Next steps

- [User Authentication]({{% relref "sign-ssh-keys" %}}) — static keys and device-flow details
- [GitHub Actions Runner]({{% relref "github-actions-runner" %}})
