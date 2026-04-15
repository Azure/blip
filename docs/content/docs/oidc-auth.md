---
title: "OIDC Authentication"
description: "Authenticate using OIDC tokens or interactive device login"
weight: 4
---

Blip supports OIDC authentication from any standards-compliant provider (GitHub Actions, Azure Entra, Google Cloud, etc.). Two modes:

1. **Token mode** (default) — Client passes an OIDC token as the SSH password. Best for CI/CD.
2. **Device flow** — Gateway presents a login URL in the SSH terminal. Best for interactive use.

## Configure the gateway

Providers are configured in the `ssh-gateway-auth` ConfigMap. No restart required.

The `oidc-providers` key holds a YAML list:

| Field | Required | Description |
|-------|----------|-------------|
| `issuer` | yes | OIDC issuer URL |
| `audience` | yes | Expected `aud` claim |
| `identity-claim` | no | Claim used as user identity (default: `sub`) |
| `allowed-subjects` | no | Allowlist of subject patterns (glob: `*`) |
| `device-flow` | no | Enable device authorization grant (default: `false`) |
| `client-id` | device-flow | OAuth2 client ID (public client, no secret) |
| `device-auth-url` | device-flow | Device authorization endpoint |
| `token-url` | device-flow | Token endpoint |
| `scopes` | no | OAuth2 scopes for device flow |

Examples below show the `data` section of this ConfigMap.

### GitHub Actions

```yaml
data:
  oidc-providers: |
    - issuer: https://token.actions.githubusercontent.com
      audience: blip
      allowed-subjects:
        - "repo:my-org/my-repo:*"
```

### Azure Entra (AAD)

```yaml
data:
  oidc-providers: |
    - issuer: https://login.microsoftonline.com/<tenant-id>/v2.0
      audience: api://blip
      identity-claim: oid
      allowed-subjects:
        - "<user-or-service-principal-object-id>"
```

Multiple providers are supported; the gateway tries each in order and accepts the first match.

## Device flow

The gateway displays a login URL ([RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628)) and waits for browser authentication. After login, the user's SSH key is bound to their OIDC identity — subsequent connections use SSH key auth. Remove the key from `allowed-pubkeys` to revoke.

### GitHub

Requires a GitHub [OAuth App](https://github.com/settings/developers) (not GitHub App) with device flow enabled.

```yaml
data:
  oidc-providers: |
    - issuer: https://token.actions.githubusercontent.com
      audience: blip
      device-flow: true
      client-id: <your-github-oauth-app-client-id>
      device-auth-url: https://github.com/login/device/code
      token-url: https://github.com/login/oauth/access_token
      scopes:
        - read:user
```

### Azure Entra (AAD)

Requires a public client app with "Allow public client flows" enabled.

```yaml
data:
  oidc-providers: |
    - issuer: https://login.microsoftonline.com/<tenant-id>/v2.0
      audience: api://blip
      identity-claim: oid
      device-flow: true
      client-id: <your-app-client-id>
      device-auth-url: https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/devicecode
      token-url: https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token
      scopes:
        - api://blip/.default
```

## Pin the gateway host key

The OIDC token is sent during the SSH handshake — you **must** pin the host key (`StrictHostKeyChecking=yes`).

```shell
kubectl -n blip get secret ssh-host-key -o jsonpath='{.data.host_key}' \
  | base64 -d \
  | ssh-keygen -y -f /dev/stdin
```

Add to `known_hosts`:

```
ssh-gateway.example.com ssh-ed25519 AAAAC3Nza...
```

## Example: GitHub Actions

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
      - name: Get OIDC Token
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

`permissions.id-token: write` is required.

## Example: Azure Entra (AAD)

```shell
az login
TOKEN=$(az account get-access-token --resource api://blip --query accessToken -o tsv)
sshpass -p "$TOKEN" ssh \
  -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile=~/.ssh/blip_known_hosts \
  runner@ssh-gateway.example.com
```

## Go SDK

```go
// Using an explicit token
client, err := blip.NewClient("gateway.example.com",
    blip.WithOIDCToken(token),
)

// Or set BLIP_OIDC_TOKEN in the environment
client, err := blip.NewClient("gateway.example.com")
```

## Session behavior

- **TTL:** 30 min (OIDC) / 8 hours (SSH key). Device flow uses OIDC TTL until key binding, then SSH key TTL.
- **Identity:** `oidc:<subject-claim>` (or configured `identity-claim` value).
- Per-user quotas apply using the OIDC identity.

## Subject allowlists

Glob patterns with `*` (matches any character including `/` and `:`). Case-insensitive. Checked against `identity-claim` (default: `sub`).

```yaml
allowed-subjects:
  - "repo:my-org/my-repo:*"          # any ref in my-repo
  - "repo:my-org/*:*"                # any repo in my-org
  - "repo:my-org/my-repo:ref:refs/heads/main"  # only main branch
```

Empty `allowed-subjects` permits any valid token from the issuer.

## Security

- Tokens verified against the provider's JWKS endpoint (key rotation handled automatically).
- All OIDC authentications logged with full identity claim and issuer.
- **Device flow:** `allowed-subjects` is enforced after browser authentication. All device flow endpoints must use HTTPS.

## Next steps

- [Nested Blips]({{% relref "nested-blips" %}})
