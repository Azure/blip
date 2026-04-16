---
title: "OIDC Authentication"
description: "Configure OIDC auth via the ssh-gateway-oidc ConfigMap"
weight: 4
---

## ConfigMap reference

The gateway reads OIDC settings from a ConfigMap named by `--oidc-config` (default: `ssh-gateway-oidc`, env var `OIDC_CONFIG`).

| Field | Required | Description |
|-------|----------|-------------|
| `oidc-issuer-url` | yes | Trusted OIDC issuer URL (e.g. `https://login.microsoftonline.com/<tenant>/v2.0`). Used for OIDC discovery. |
| `oidc-audience` | yes | Expected `aud` claim in the OIDC token. |
| `tls-secret-name` | yes | Kubernetes Secret containing `tls.crt` and `tls.key` for the HTTPS API server. The gateway watches this Secret for rotations. |
| `authenticator-url` | no | URL of the web authenticator for device-flow SSH login. Enables keyboard-interactive fallback when set. |

When both `oidc-issuer-url` and `oidc-audience` are present, the gateway enables the HTTPS API server (`POST /auth/user`). Removing either field disables OIDC auth.

## Enable OIDC auth

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

```shell
kubectl apply -f ssh-gateway-oidc.yaml
```

Verify:

```shell
kubectl logs -n blip -l app=ssh-gateway --tail=20 | grep "oidc config"
```

## Disable OIDC auth

Delete the ConfigMap:

```shell
kubectl delete configmap ssh-gateway-oidc -n blip
```

The gateway reverts to SSH-key-only authentication. Active sessions are not interrupted.

## Azure Entra ID example

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

| Field | Value |
|-------|-------|
| `oidc-issuer-url` | Entra ID v2.0 issuer for your tenant. For v1.0 tokens, use `https://sts.windows.net/<tenant-id>/` instead. |
| `oidc-audience` | Application (client) ID of the Entra ID App Registration configured as the EasyAuth identity provider. Must match the `aud` claim in issued ID tokens. |
| `authenticator-url` | Public URL of the Azure Function's `auth` HTTP trigger. |

The `--external-host` flag (or `GATEWAY_EXTERNAL_HOST` env var) must be set to the gateway's public hostname (used as the `iss` claim in gateway-signed JWTs).

The Azure Function requires `APISERVER_URL` set to the Kubernetes API server URL to fetch the gateway's TLS certificate from the `gateway-tls-certs` ConfigMap in `kube-public`.

## Runtime notes

- **OIDC discovery** runs asynchronously on issuer URL change. Requests return 503 briefly until the verifier is ready.
- **Device-flow auth** activates/deactivates when `authenticator-url` is set/removed.

## Next steps

- [User Authentication]({{% relref "sign-ssh-keys" %}}) — static keys and device-flow details
- [Nested Blips]({{% relref "nested-blips" %}})
- [GitHub Actions Runner]({{% relref "github-actions-runner" %}})
