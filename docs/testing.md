<!-- Copyright (c) Microsoft Corporation.
Licensed under the MIT License. -->

# Testing

Each tier proves one thing. Push depth down to the cheapest tier that can
observe a behavior, and keep one end-to-end test per user-facing feature to
prove the real components are wired together.

| Tier | Proves | May fake | Run |
|---|---|---|---|
| Unit | Logic and error branches | Anything | `go test ./...` |
| Simulation | Concurrency, ordering, faults, liveness | Kernel, Kubernetes API, time | `make test-sim` ([simulation.md](simulation.md)) |
| Privileged host | Kernel contracts the simulations assume: dm, loop, ext4, NVMe, peer transfer | Nothing on the host | `hack/storage-test.sh storage nvme peer` |
| Browser UI | blipchat UI behavior in real Chromium against the real server | Kubernetes and the agent | `make test-ui` |
| System e2e | Every feature through the real images on kind with KVM | Only external systems: the model, identity proxy, registry | `make kind-up && hack/e2e.sh` |
| Full-stack chat | Agent turns in a real OpenCode VM from the browser | Only the model | `hack/e2e/opencode/run.sh` |

## End-to-end boundary

E2E tests act only through public interfaces: `kubectl blip`, Kubernetes
objects applied as a user would, blipchat HTTP, SSE, and MCP, and the browser.
They assert what a user can observe: command output and exit codes, object
status, files and processes inside the guest, HTTP responses, and the page.
After each scenario the harness also checks that no running blips leaked.

## System e2e scenarios

| Scenario | Covers |
|---|---|
| `10-basics` | run, exit codes, durable workspaces, mounts, runtime patches, resume, forks, gather, timeouts |
| `15-cli` | run labels and preflight, interrupted runs, stop, send `--eof` and stdin, logs offsets/state/follow, gather `--wait`, pull flags, mount replicas |
| `20-runtime` | env, workdir, user, image defaults, stdout/stderr, exit codes, stdin |
| `25-pool` | pool CPUs, memory, DNS, tolerations, pull secrets; idle timeout; locality |
| `30-network` | endpoints, pod identity, guest service-account access, egress policy |
| `40-mounts` | auxiliary mounts, read-only enforcement, mount removal and copies |
| `50-state` | single writer, conflicts, state deletion, gather options, TTL, stop |
| `55-build` | build recipes, incremental builds, history limit, git cache labels |
| `60-cluster` | nodes, replicas and placement, warm pools, serial console |
| `70-blipchat` | blipchat API: sessions, SSE, user isolation, origin checks, delete |
| `90-resilience` | drain, controller/agent/blipchat restarts, pool churn (churn on every PR, the rest nightly) |

Select scenarios by number with `BLIP_E2E_SCENARIOS="15 25"`. Every scenario
runs in its own subshell; a failure dumps diagnostics and the suite continues
unless `BLIP_E2E_FAIL_FAST=1`. `BLIP_E2E_REPORT=junit.xml` writes a JUnit
report. `BLIP_E2E_RESILIENCE=1` adds `90-resilience`, and
`BLIP_E2E_RESILIENCE_STEPS="restart churn"` narrows it to some step groups
(`drain agent restart churn`).

`TestE2ECoversEveryFlag` in `internal/cli` fails when a CLI command or flag has
no e2e invocation under `hack/e2e/`. Add a scenario step, or list the flag in
`e2eUncovered` with the reason.
