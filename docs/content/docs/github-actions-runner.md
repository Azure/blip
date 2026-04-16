---
title: "GitHub Actions Runner"
description: "Use Blip VMs as just-in-time self-hosted GitHub Actions runners"
weight: 6
---

Blip can act as a GitHub Actions self-hosted runner backend. When a repository pushes a bootstrap token to the gateway, a per-repo polling loop starts that watches for queued workflow jobs. For each queued job, the gateway claims a VM from the pool, creates a JIT (just-in-time) runner configuration via the GitHub API, writes it to the VM's annotations, and releases the VM when the job completes.

## How it works

1. A GitHub Actions workflow obtains an OIDC token and POSTs it to the gateway's `/auth/github` endpoint.
2. The gateway verifies the token, checks the repository owner against the allowed orgs list, and stores it as a Kubernetes Secret (`gh-<hash>`) labelled with the repository name.
3. The actions runner backend watches for these secrets. When one appears, it starts a polling loop for that repository.
4. The polling loop uses a GitHub App installation token to list queued workflow jobs and match them against configured runner labels.
5. For each matched job, the gateway claims a VM, calls the GitHub API to generate a JIT runner config, and patches it onto the VM as the `blip.io/runner-jitconfig` annotation.
6. The in-VM runner agent polls for this annotation and starts with `./run.sh --jitconfig <config>`.
7. When the job completes, the VM is released immediately.

## Prerequisites

- A working Blip deployment ([Getting Started]({{% relref "getting-started" %}}))
- A VM pool whose image includes the GitHub Actions runner agent (see [VM image](#vm-image))
- The HTTPS API server enabled on the gateway (`--oidc-issuer-url` and related flags)

## Create and install a GitHub App

The integration authenticates to the GitHub API as a [GitHub App](https://docs.github.com/en/apps/creating-github-apps).

1. Create a new GitHub App (**Settings > Developer settings > GitHub Apps**) with:
   - **Webhook:** **Disabled** (Blip polls; no inbound webhook needed)
   - **Repository permissions:** Actions (read), Administration (read & write)
   - **Organization permissions** (org-level install only): Self-hosted runners (read & write)

2. Note the **App ID**, generate a **private key** (PEM), and download it.

3. Install the app on your target organization or repositories. Note the **installation ID** from the URL (`https://github.com/settings/installations/<install-id>`).

## Configure the gateway

Create a secret for the GitHub App private key:

```shell
kubectl create secret generic github-app-key \
  -n blip --from-file=private-key.pem=<path-to-pem-file>
```

Uncomment the GitHub Actions sections in `manifests/deploy.yaml` and fill in your values:

```yaml
- name: GITHUB_APP_ID
  value: "<app-id>"
- name: GITHUB_INSTALL_ID
  value: "<install-id>"
- name: RUNNER_LABELS
  value: "self-hosted,blip"
- name: ACTIONS_REPOS
  value: "my-org/my-repo"
- name: GITHUB_ALLOWED_ORGS
  value: "my-org"
```

Apply:

```shell
kubectl apply -f manifests/deploy.yaml
```

## Push the bootstrap token

The gateway's `/auth/github` endpoint accepts a GitHub Actions OIDC token with audience `blip`. The token must come from a repository whose owner is in `GITHUB_ALLOWED_ORGS`.

The gateway publishes its self-signed TLS certificate and hostname in a ConfigMap in `kube-public`, so any workflow with cluster access can retrieve it and connect with strong trust — no `--insecure` flags needed.

Below is a complete workflow that pushes the bootstrap token on a schedule. It assumes network connectivity from the runner to the Kubernetes API server.

```yaml
name: Push Blip Runner Token
on:
  schedule:
    - cron: "0 */6 * * *"    # every 6 hours
  workflow_dispatch: {}

permissions:
  id-token: write
  contents: read

env:
  # FQDN of the Kubernetes API server (e.g. apiserver.example.com:6443).
  # The runner must trust the API server's TLS certificate, or use
  # KUBE_CA_CERT to pass the cluster CA bundle.
  KUBE_APISERVER: apiserver.example.com:6443

jobs:
  push-token:
    runs-on: ubuntu-latest
    steps:
      - name: Retrieve gateway TLS cert and hostname from kube-public
        run: |
          # If your API server uses a private CA, set KUBE_CA_CERT to the
          # PEM-encoded CA bundle and add --cacert "$KUBE_CA_CERT" below.
          CM_URL="https://${KUBE_APISERVER}/api/v1/namespaces/kube-public/configmaps/gateway-tls-certs"
          CM=$(curl --silent --fail --show-error "$CM_URL")

          GATEWAY_HOST=$(echo "$CM" | jq -r '.data["hostname"]')
          echo "$CM" | jq -r '.data["active.crt"]' > /tmp/gateway.crt

          PREV=$(echo "$CM" | jq -r '.data["previous.crt"] // empty')
          if [ -n "$PREV" ]; then
            echo "$PREV" >> /tmp/gateway.crt
          fi

          echo "GATEWAY_HOST=${GATEWAY_HOST}" >> "$GITHUB_ENV"

      - name: Get GitHub Actions OIDC token
        uses: actions/github-script@v7
        id: oidc
        with:
          script: |
            const token = await core.getIDToken('blip');
            core.setOutput('token', token);

      - name: Push token to gateway
        run: |
          curl --silent --fail --show-error \
            --cacert /tmp/gateway.crt \
            -X POST \
            -d "token=${{ steps.oidc.outputs.token }}" \
            "https://${GATEWAY_HOST}:8443/auth/github"
```

The `kube-public` namespace is readable without authentication by default, so the first step needs no credentials. The `--cacert` flag pins trust to the gateway's self-signed certificate. Both the active and previous certificates are included in the trust bundle to handle rotation gracefully.

{{% callout type="info" %}}
The OIDC token is short-lived (valid for ~10 minutes). The gateway stores it as a Kubernetes Secret and uses it only to authorize the polling loop — actual runner authentication uses JIT configs issued by the GitHub App.
{{% /callout %}}

## Configuration reference

| Environment variable | CLI flag | Required | Description |
|---------------------|----------|----------|-------------|
| `GITHUB_APP_ID` | `--github-app-id` | yes | GitHub App ID |
| `GITHUB_INSTALL_ID` | `--github-install-id` | yes | GitHub App installation ID |
| `GITHUB_KEY_PATH` | `--github-key-path` | yes | Path to GitHub App PEM private key |
| `RUNNER_LABELS` | `--runner-labels` | yes | Comma-separated runner labels (e.g. `self-hosted,blip`) |
| `GITHUB_ALLOWED_ORGS` | `--github-allowed-orgs` | yes | Comma-separated list of GitHub orgs allowed to push tokens |
| `ACTIONS_REPOS` | `--actions-repos` | yes* | Comma-separated repos to poll (e.g. `my-org/my-repo`). Required when `--github-app-id` is set. |
| `ACTIONS_SESSION_DURATION` | `--actions-session-duration` | no | Max runner session TTL in seconds (default: `3600`). Note: the runner backend internally caps VM lifetime at 1800s (30 min). |
| `ACTIONS_POLL_INTERVAL` | `--actions-poll-interval` | no | How often to poll for queued jobs in seconds (default: `10`) |

Note: the runner backend discovers repositories dynamically from bootstrap token secrets pushed via `/auth/github`. `ACTIONS_REPOS` is validated at startup when the GitHub App is configured but the actual per-repo polling is driven by secrets.

## Workflow

Reference your runner labels in `runs-on`:

```yaml
jobs:
  build:
    runs-on: [self-hosted, blip]
    steps:
      - uses: actions/checkout@v4
      - run: echo "Running on a Blip VM"
```

A queued job is picked up only if at least one of the job's labels matches a configured `RUNNER_LABELS` entry. Matching is case-insensitive.

## VM image

The VM's cloud-init script must:

1. Poll for the `blip.io/runner-jitconfig` annotation on the VM (via the Kubernetes API using the pod-mounted service account).
2. When the annotation appears, start the runner with `./run.sh --jitconfig <config>`.

The JIT config is a sealed, ephemeral configuration generated by GitHub. No registration tokens or repository URLs are needed — the config contains everything the runner agent requires.

See `images/github-runner/Containerfile` for a reference implementation.

## Security

- JIT runner configs are sealed by GitHub and single-use. No persistent runner tokens are stored.
- Runner VMs are hard-capped at 30 minutes (`runnerMaxTTL`) regardless of `ACTIONS_SESSION_DURATION`.
- Duplicate job sightings are deduplicated — only one VM is claimed per job.
- The `/auth/github` endpoint verifies OIDC token signatures against GitHub's published JWKS keys and checks the repository owner against `GITHUB_ALLOWED_ORGS`.
- The gateway's self-signed TLS certificate is published in `kube-public` for cross-cluster trust without disabling verification.

## Troubleshooting

```shell
kubectl logs -n blip -l app=ssh-gateway --tail=200
```

| Message | Cause |
|---------|-------|
| `github oidc token verification failed` | Token expired, wrong audience, or JWKS fetch failure |
| `organization not allowed` | Repository owner not in `GITHUB_ALLOWED_ORGS` |
| `failed to create JIT runner config` | GitHub App lacks permissions or is not installed on the repo |
| `failed to allocate runner VM` | No VMs available in pool |
| `job labels do not match runner labels` | `runs-on` labels don't overlap with `RUNNER_LABELS` |
