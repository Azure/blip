# Deterministic cross-component lifecycle

Run with the repository's Go toolchain:

```sh
go test ./internal/simapp
```

The tests execute **production** `controller.PoolReconciler`,
`controller.BlipReconciler`, `controller.StateReconciler`, `node.compute`
(through `node.Compute`), `runtime.Machine`, `node.Scheduler`, and
`peer.NextLeaseEffect`. There are no goroutines, real
timers, sockets, privileged devices, or additional dependencies in the harness.

The workload allocates a warm VM and two writable states, writes distinct
content, hot-unmounts its auxiliary disk, waits for confirmed VMM removal,
seals and replicates it, stops the VM, saves and replicates its root, then
reacquires both states from the second node under a new owner and new
attachment IDs. A competing client also attempts allocation while the first
writer remains live.

## Environment and checks

- Kubernetes authoritative objects and informer objects are separate fake
  clients with real status-subresource and optimistic-patch behavior. Explicit
  watch delivery advances the cache. Reconcilers are recreated after each turn;
  allocation and save decisions are never reproduced in the fixture.
- Guest filesystem mounts, VMM device handles, runtime observations, queued
  replies, working bytes, immutable commits, partial replica data, and lease
  resources are separate environment state. Lost replies can follow completed
  operations. Device-removal acceptance does not close its handle.
- Node passes consume the informer snapshot, each node's physical volume
  inventory, pod-directory documents/device numbers, scheduler reservations,
  and export pins. Production planning supplies warm/observed pod metadata,
  desired claims/mounts/stop/network policy, prepare and seal requests, trusted
  replica-source selection, reservation sets, and state observation entries.
  The environment services one planned I/O job per workload turn.
- Invariants check exclusive writer/device ownership, fencing before seal,
  immutable bases, exact bytes on every selected replica, incarnation-matched
  reports, truthful success, lease pin/device ordering, and exact saved bytes
  after reacquisition on node two.
- Fault scenarios cover every applied controller API write, failures before
  storage effects, lost preparation/seal/control/removal/revocation replies,
  and stale-incarnation replica reports. Healing supplies fair observation,
  completion and reconcile turns with a checked finite recovery budget.
- `sim.Run` schedules seeded interleavings; `sim.Replay` verifies exact keys;
  `sim.Explore` exhaustively checks explicitly bounded four-transition windows.
  Window completeness is not a claim of exhaustive whole-system exploration.
- `Clone` uses the runtime and scheduler's deep-copy APIs. Keys include their
  complete canonical private state, clocks, queues, cache,
  physical and durable state, fault budgets, and monitors. An in-flight removal
  clone-isolation test and a deliberately premature commit check validate the
  harness's isolation and content monitor.
- Focused composition checks remove a prepared device node, separate physical
  removal from runtime acknowledgement, and invalidate replica source identity,
  heartbeat, or incarnation. These exercise production node readiness, fencing,
  and source-selection decisions using the lifecycle's real observations.

## Composition boundary

`internal/node/planner.go` is a value-only snapshot/plan projection around the
same private `view` and `compute` used by the node agent. It retains no live
agent state, copies returned documents, and contains no duplicate lifecycle
decisions. The simulation adapter assembles inputs and applies the resulting
documents, metadata, requests, and reports to the virtual environment. The
stale-incarnation fault changes only the incarnation of a planner-produced
report before delivery.

Initial committed states and guest-ready warm-pod observations are fixtures.
The workload does not execute node image import/build, live copy, garbage
collection, the node agent's file/API I/O executor, or its background worker
loop. In particular, old volumes remain available to the immutable-base
monitor. Node API reports use the fake client's status update path rather than
the live executor's server-side-apply field ownership. Applied-controller-write
fault coverage counts controller writes, not these node-adapter writes.

Storage effects still copy exact bytes and update physical volume inventory;
they do not execute the storage device-mapper operation/recovery core. Guest
effects implement the wire operations exercised here and do not execute the
guest session/freeze cores. Those production cores can be composed through
their own value/effect boundaries in subsequent workloads. Preparation here
uses local committed bases; a remote/image preparation request is rejected as
an unsupported environment effect. Replica fetches use the production-selected
remote source and the peer lease effect sequencer, while the full HTTP/NVMe
server and authorization path remain outside this workload. Runtime networking
is disabled, although node desired documents include the production policy.
