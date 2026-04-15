---
title: "GitHub Actions Runner"
description: "Use Blip VMs as just-in-time self-hosted GitHub Actions runners"
weight: 6
---

Blip can act as a GitHub Actions self-hosted runner backend. The gateway polls the GitHub API for queued workflow jobs, claims a VM from the pool, registers it as a just-in-time runner, and releases it when the job completes. This makes Blip VMs available as `runs-on` targets — no SSH step required.

## Prerequisites

- A working Blip deployment ([Getting Started]({{% relref "getting-started" %}}))
- A VM pool whose cloud-init image starts the GitHub Actions runner agent (see [VM image](#vm-image))

## Create and install a GitHub App

The integration authenticates to the GitHub API as a [GitHub App](https://docs.github.com/en/apps/creating-github-apps).

1. Create a new GitHub App (**Settings > Developer settings > GitHub Apps**) with:
   - **Webhook:** set to **Disabled** (Blip polls the API; no inbound webhook is needed)
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

Create a BlipOwner CR for each repository to poll (one CR per repo):

```yaml
apiVersion: blip.io/v1alpha1
kind: BlipOwner
metadata:
  name: myorg-myrepo
  namespace: blip
spec:
  actionsRepo:
    repo: my-org/my-repo
---
apiVersion: blip.io/v1alpha1
kind: BlipOwner
metadata:
  name: myorg-another-repo
  namespace: blip
spec:
  actionsRepo:
    repo: my-org/another-repo
```

```shell
kubectl apply -f actions-repos.yaml
```

The gateway watches BlipOwner CRs in real time — changes take effect without a restart.

Uncomment all the GitHub Actions sections in `manifests/deploy.yaml` (environment variables, volume mount, and volume) and fill in your App ID and installation ID:

```yaml
- name: GITHUB_APP_ID
  value: "<app-id>"
- name: GITHUB_INSTALL_ID
  value: "<install-id>"
```

Apply:

```shell
kubectl apply -f manifests/deploy.yaml
```

## Configuration reference

| Environment variable | CLI flag | Required | Description |
|---------------------|----------|----------|-------------|
| `GITHUB_APP_ID` | `--github-app-id` | yes | GitHub App ID |
| `GITHUB_INSTALL_ID` | `--github-install-id` | yes | GitHub App installation ID |
| `GITHUB_KEY_PATH` | `--github-key-path` | yes | Path to GitHub App PEM private key |
| `RUNNER_LABELS` | `--runner-labels` | yes | Comma-separated runner labels (e.g. `self-hosted,blip`) |
| `ACTIONS_SESSION_DURATION` | `--actions-session-duration` | no | Max runner session TTL in seconds (default: `3600`) |
| `ACTIONS_POLL_INTERVAL` | `--actions-poll-interval` | no | How often to poll for queued jobs in seconds (default: `10`) |

The list of repositories to poll is read from BlipOwner CRs with `spec.actionsRepo` set, not from environment variables.

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

A queued job is picked up only if at least one of the job's labels matches a configured `RUNNER_LABELS` entry. Matching is case-insensitive. Unmatched jobs are silently ignored, so multiple Blip deployments can share the same GitHub App installation.

## VM image

The VM's cloud-init script must:

1. Poll for the `blip.io/runner-token` annotation to appear on the VM.
2. Read `blip.io/runner-url` (repository URL) and `blip.io/runner-labels` (comma-separated).
3. Download the [GitHub Actions runner agent](https://github.com/actions/runner), configure it with the token and URL, and start it with `--ephemeral`.

## Security

- Runner VMs are released after `ACTIONS_SESSION_DURATION` even if the job never completes.
- Duplicate queued-job sightings for the same job are deduplicated — only one VM is claimed per job.
- No inbound HTTP endpoint is required. The gateway makes outbound API calls to `api.github.com` only.

## Troubleshooting

```shell
kubectl logs -n blip -l app=ssh-gateway --tail=200
```

- **`failed to list queued jobs`** — the GitHub App may lack permissions, or the repo format in the BlipOwner CR is invalid (must be `owner/repo`).
- **`request registration token: HTTP 403`** — missing permissions or app not installed on the repo.
- **`job labels do not match runner labels`** — `runs-on` labels do not overlap with `RUNNER_LABELS`.
- **No VMs being allocated** — verify that BlipOwner CRs with `spec.actionsRepo` exist for the correct repos and that `RUNNER_LABELS` matches your workflow's `runs-on`.

## Next steps

- [Create a VM Pool]({{% relref "create-vm-pool" %}})
- [OIDC Authentication]({{% relref "oidc-auth" %}})
