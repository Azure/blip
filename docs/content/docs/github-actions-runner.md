---
title: "GitHub Actions Runner"
description: "Use Blip VMs as just-in-time self-hosted GitHub Actions runners"
weight: 6
---

Blip can act as a GitHub Actions self-hosted runner backend. When a workflow job is queued, Blip claims a VM from the pool, registers it as a just-in-time runner, and destroys it when the job completes. This makes Blip VMs available as `runs-on` targets — no SSH step required.

## Prerequisites

- A working Blip deployment ([Getting Started]({{% relref "getting-started" %}}))
- A VM pool whose cloud-init image starts the GitHub Actions runner agent (see [VM image](#vm-image))

## Create and install a GitHub App

The integration authenticates to the GitHub API as a [GitHub App](https://docs.github.com/en/apps/creating-github-apps).

1. Create a new GitHub App (**Settings > Developer settings > GitHub Apps**) with:
   - **Webhook URL:** `https://<your-blip-webhook-host>/webhook`
   - **Webhook secret:** a random secret (`openssl rand -hex 32`)
   - **Repository permissions:** Actions (read), Administration (read & write)
   - **Organization permissions** (org-level install only): Self-hosted runners (read & write)
   - **Events:** Workflow job

2. Note the **App ID**, generate a **private key** (PEM), and download it.

3. Install the app on your target organization or repositories. Note the **installation ID** from the URL (`https://github.com/settings/installations/<install-id>`).

## Configure the gateway

Create secrets:

```shell
kubectl create secret generic github-webhook-secret \
  -n blip --from-literal=secret=<your-webhook-secret>

kubectl create secret generic github-app-key \
  -n blip --from-file=private-key.pem=<path-to-pem-file>
```

Uncomment all the GitHub Actions sections in `deploy.yaml` (six environment variables, volume mount, volume, and Service HTTP port) and fill in your App ID and installation ID:

```yaml
- name: GITHUB_APP_ID
  value: "<app-id>"
- name: GITHUB_INSTALL_ID
  value: "<install-id>"
```

Apply:

```shell
kubectl apply -f deploy.yaml
```

The webhook endpoint is exposed at `:8080/webhook`. Terminate TLS in front of the gateway (e.g. Ingress or cloud load balancer) so that GitHub delivers over HTTPS.

## Configuration reference

| Environment variable | CLI flag | Required | Description |
|---------------------|----------|----------|-------------|
| `GITHUB_APP_ID` | `--github-app-id` | yes | GitHub App ID |
| `GITHUB_INSTALL_ID` | `--github-install-id` | yes | GitHub App installation ID |
| `GITHUB_KEY_PATH` | `--github-key-path` | yes | Path to GitHub App PEM private key |
| `WEBHOOK_SECRET` | `--webhook-secret` | recommended | Shared secret for `X-Hub-Signature-256` validation. Without it, any POST to `/webhook` can trigger VM allocation |
| `RUNNER_LABELS` | `--runner-labels` | yes | Comma-separated runner labels (e.g. `self-hosted,blip`) |
| `ACTIONS_SESSION_DURATION` | `--actions-session-duration` | no | Max runner session TTL in seconds (default: `3600`) |

## Workflow

Reference your runner labels in `runs-on`:

```yaml
name: CI
on: push

jobs:
  build:
    runs-on: [self-hosted, blip]
    steps:
      - uses: actions/checkout@v4
      - run: echo "Running on a Blip VM"
```

A `workflow_job` event is handled only if at least one of the job's labels matches a configured `RUNNER_LABELS` entry. Matching is case-insensitive. Unmatched jobs are silently ignored, so multiple Blip deployments can share the same webhook.

## VM image

The VM's cloud-init script must:

1. Poll for the `blip.io/runner-token` annotation to appear on the VM.
2. Read `blip.io/runner-url` (repository URL) and `blip.io/runner-labels` (comma-separated).
3. Download the [GitHub Actions runner agent](https://github.com/actions/runner), configure it with the token and URL, and start it with `--ephemeral`.

## Security

- Set `WEBHOOK_SECRET` to match the GitHub App. Without it, any POST to `/webhook` can trigger VM allocation.
- Runner VMs are released after `ACTIONS_SESSION_DURATION` even if the `completed` event is never received.
- Duplicate webhook deliveries for the same job are deduplicated — only one VM is claimed per job.

## Troubleshooting

```shell
kubectl logs -n blip -l app=ssh-gateway --tail=100 | grep webhook
```

- **`webhook signature verification failed`** — `WEBHOOK_SECRET` mismatch.
- **`registration token request failed (HTTP 403)`** — missing permissions or app not installed on the repo.
- **`job labels do not match runner labels`** — `runs-on` labels do not overlap with `RUNNER_LABELS`.
- **No webhook deliveries** — verify the webhook URL is reachable and the HTTP port is exposed. Check **Advanced > Recent Deliveries** in the GitHub App settings.

## Next steps

- [Create a VM Pool]({{% relref "create-vm-pool" %}})
- [OIDC Authentication]({{% relref "oidc-auth" %}})
