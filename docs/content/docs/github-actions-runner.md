---
title: "GitHub Actions Runner"
description: "Use Blip VMs as just-in-time self-hosted GitHub Actions runners"
weight: 6
---

## How it works

1. A GitHub PAT is stored in a Kubernetes Secret and watched by the gateway.
2. The actions runner backend polls for queued workflow jobs in configured repositories.
3. Each poll uses the PAT to list queued jobs and match them against configured runner labels.
4. For each matched job, the controller claims a VM and annotates it with the target repository and job ID.
5. The runner-config controller detects the annotations, generates a JIT runner config via the GitHub API, SSHes into the VM, and starts the runner with `./run.sh --jitconfig <config>`.
6. On job completion, the VM is released.

## Prerequisites

- A working Blip deployment ([Getting Started]({{% relref "getting-started" %}}))
- A VM pool whose image includes the GitHub Actions runner agent (see [VM image](#vm-image))
- A GitHub PAT — fine-grained recommended, see [PAT scopes](#pat-scopes)

## Create a GitHub PAT

### PAT scopes

| PAT type | Required permissions |
|----------|---------------------|
| Fine-grained (recommended) | **Repository permissions:** "Administration" read & write, "Actions" read — scoped to target repos only |
| Classic | `repo` (grants access to **all** repos — avoid if possible) |

> `admin:org` is **not** needed — Blip uses per-repository runners.

### Generate a fine-grained PAT

1. Navigate to **Settings → Developer settings → Fine-grained tokens**
2. Scope to **only** the repositories Blip will poll
3. Grant repository permissions:
   - **Administration** — read & write (for `generate-jitconfig`)
   - **Actions** — read (for listing queued jobs)

### Write the PAT to a Kubernetes Secret

```shell
kubectl create secret generic github-pat \
  -n blip \
  --from-literal=token="$GITHUB_PAT" \
  --dry-run=client -o yaml | kubectl apply -f -
```

## Configure the gateway

Uncomment the GitHub Actions sections in `manifests/deploy.yaml`:

```yaml
- name: GITHUB_PAT_SECRET
  value: "github-pat"
- name: RUNNER_LABELS
  value: "self-hosted,blip"
- name: ACTIONS_REPOS
  value: "my-org/my-repo"
```

```shell
kubectl apply -f manifests/deploy.yaml
```

## Configuration reference

| Environment variable | CLI flag | Required | Description |
|---------------------|----------|----------|-------------|
| `GITHUB_PAT_SECRET` | `--github-pat-secret` | yes | Kubernetes Secret containing the GitHub PAT in a `token` key |
| `RUNNER_LABELS` | `--runner-labels` | yes | Comma-separated runner labels (e.g. `self-hosted,blip`) |
| `ACTIONS_REPOS` | `--actions-repos` | yes | Comma-separated repos to poll (e.g. `my-org/my-repo`) |

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

Matching is case-insensitive. A job is picked up if at least one label matches a `RUNNER_LABELS` entry.

## VM image

The VM's cloud-init script must install the GitHub Actions runner agent under `/home/runner/actions-runner/`. The runner-config controller will SSH into the VM to deliver the JIT config and start the runner process — no in-VM polling or annotation watching is required.

The JIT config is sealed and ephemeral — no registration tokens or repository URLs needed.

See `images/github-runner/Containerfile` for a reference implementation.

## Security

- JIT runner configs are delivered over SSH and never stored in Kubernetes annotations or on disk.
- JIT runner configs are sealed by GitHub and single-use.
- Runner VMs are hard-capped at 30 minutes (`runnerMaxTTL`).
- Duplicate job sightings are deduplicated — only one VM per job.
- PAT Secret rotations are picked up immediately.

## Troubleshooting

```shell
kubectl logs -n blip -l app=ssh-gateway --tail=200
```

| Message | Cause |
|---------|-------|
| `no PAT available` | PAT Secret missing or has no `token` key |
| `failed to create JIT runner config` | PAT lacks permissions or not authorized for repo |
| `failed to allocate runner VM` | No VMs available in pool |
| `job labels do not match runner labels` | `runs-on` labels don't overlap with `RUNNER_LABELS` |
