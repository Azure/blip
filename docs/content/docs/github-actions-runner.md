---
title: "GitHub Actions Runner"
description: "Use Blip VMs as just-in-time self-hosted GitHub Actions runners"
weight: 6
---

## How it works

1. A GitHub PAT is stored in a Kubernetes Secret (`github-pat`) and watched by the controller.
2. Runner labels and trusted repos are stored in a ConfigMap (`github-actions`) and watched by the controller.
3. When both resources are present, the actions runner backend polls for queued workflow jobs in the configured repositories.
4. For each matched job, the controller claims a VM and annotates it with the target repository and job ID.
5. The runner-config controller detects the annotations, generates a JIT runner config via the GitHub API, SSHes into the VM, and starts the runner with `./run.sh --jitconfig <config>`.
6. On job completion, the VM is released.

No gateway or controller restarts are needed — configuration changes take effect immediately.

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

## Configure the runner

### 1. Write the PAT to a Kubernetes Secret

```shell
kubectl create secret generic github-pat \
  -n blip \
  --from-literal=token="$GITHUB_PAT" \
  --dry-run=client -o yaml | kubectl apply -f -
```

### 2. Write runner labels and repos to a ConfigMap

```shell
kubectl create configmap github-actions \
  -n blip \
  --from-literal=runner-labels="self-hosted,blip" \
  --from-literal=repos="my-org/my-repo" \
  --dry-run=client -o yaml | kubectl apply -f -
```

That's it. The controller detects both resources and begins polling immediately. To reconfigure, edit the ConfigMap or Secret — no restart needed.

## Configuration reference

| Resource | Key | Description |
|----------|-----|-------------|
| Secret `github-pat` | `token` | GitHub Personal Access Token |
| ConfigMap `github-actions` | `runner-labels` | Comma-separated runner labels (e.g. `self-hosted,blip`) |
| ConfigMap `github-actions` | `repos` | Comma-separated repos to poll (e.g. `my-org/my-repo`) |

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

Matching requires all configured `runner-labels` to appear in the job's `runs-on` list. For example, if `runner-labels` is `self-hosted,blip`, a job with `runs-on: [self-hosted, blip]` matches but `runs-on: [self-hosted]` does not. Label comparison is case-sensitive.

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
kubectl logs -n blip -l app=blip-controller --tail=200
```

| Message | Cause |
|---------|-------|
| `no PAT available` | `github-pat` Secret missing or has no `token` key |
| `actions config incomplete` | `github-actions` ConfigMap missing or has empty `runner-labels`/`repos` |
| `failed to create JIT runner config` | PAT lacks permissions or not authorized for repo |
| `failed to allocate runner VM` | No VMs available in pool |
| `job labels do not match runner labels` | `runs-on` labels don't overlap with `runner-labels` |
