# Deterministic simulation

Blip's simulations execute production decision and operation code against
controlled external effects. The virtual worlds need no Kubernetes cluster,
VM, or privileged storage devices. Some tests use temporary files, real bbolt,
or subprocesses to qualify persistence and process-crash behavior. The regular
Go test suite runs them; the focused target also checks the concurrent
production adapters with the race detector:

```sh
go test ./...
make test-sim
```

The daily campaign explores a fresh, reproducible range of lifecycle seeds and
runs the component model target with a fresh seed base. Both jobs retain failing
test output as a workflow artifact; lifecycle failures also include JSON traces.
`internal/simtest.Seeds` applies `BLIP_SIM_SEED` and `BLIP_SIM_RUNS` to component
models, while the composed lifecycle test reads them directly. To replay a
particular seed or expand the local campaign, bypass the Go test cache:

```sh
BLIP_SIM_SEED=123 BLIP_SIM_RUNS=1 go test -count=1 -v \
  -run '^TestSimulationLifecycleSeededReplayAndHealing$' ./internal/simapp
```

The default pull-request campaign uses seeds 1 through 12. `BLIP_SIM_RUNS`
accepts 1 through 10000; the daily job uses 128 runs.

## Execution model

Keep decisions, retry policy, reservations, and operation continuations in
deterministic state. Supply clocks, identities, observations, and effect results
explicitly. Production adapters perform I/O; simulated adapters track what the
external system actually did independently of what the application has observed.

An operation being applied and its result being delivered are separate steps.
Timeout, cancellation, and process death do not roll back applied operations.
An abrupt crash discards the affected process state without running deferred
cleanup. Model recovery by executing the production recovery path.

`internal/sim` supplies a small exploration interface:

```go
type Model interface {
    Clone() Model
    Key() string
    Enabled() []string
    Step(action string) error
    Check() error
}
```

`Clone` must isolate mutable state. `Key` must canonically include everything
that can affect future transitions or property checks: application state,
external state, durable state, queued results, clocks, and monitor state.
`Enabled` names legal actions; `Step` executes one; `Check` independently checks
the resulting state. Keep the world model below the production operation being
tested, so that a test cannot manufacture its own successful business outcome.

### Exploration and replay

```go
trace, err := sim.Run(initial, seed, 1000)
// trace is JSON-serializable; retain it with any failure.
final, replayErr := sim.Replay(initial, trace)

report, exploreErr := sim.Explore(initial, sim.Limits{
    States: 10000,
    Depth: 100,
})
```

`Run` chooses among sorted enabled actions using a seeded PRNG. `Replay` checks
the action and the state keys at every step, detecting model or trace drift.
`Explore` searches breadth-first and returns a shortest discovered failure
trace. Its `Complete` field distinguishes an exhausted finite graph from a
truncated search. Neither a successful bounded run nor complete safety
exploration establishes unbounded liveness.

### Bounded liveness checking

`internal/simlive` checks eventual reachability of a supplied goal using the
same `sim.Model`. Configure named weak-fairness groups for the environment
actions that must receive service when continuously enabled:

```go
report, err := simlive.Check(initial, simlive.Options{
    Limits: sim.Limits{States: 10000, Depth: 100},
    Goal: goal,
    WeakFairness: []simlive.Group{
        {Name: "storage service", Actions: []string{"apply", "complete"}},
    },
})
```

Use the model's actual action names. Group fairness promises service to the
group, not to every member. The checker searches the goal-avoiding graph for
terminal deadlocks and fair cycles. A witness contains a replayable prefix and
a closed cycle; repeating that cycle satisfies the configured fairness groups.
Only `Complete && Witness == nil`, with no error, establishes eventuality for
the finite model. An incomplete search is inconclusive. Intermittently enabled
actions are not required to run by weak fairness.

## Failure contracts

Use faults supported by the modeled boundary, including successful operations
whose responses are lost. Document assumptions alongside each model.

| Boundary | Distinctions to preserve |
| --- | --- |
| Process lifetime | Agent death, runtime death, pod termination, guest death, host reboot, and storage replacement affect different resources. The runtime's configured parent-death signal also affects the VMM. |
| Persistent files | File contents/mode and directory entries have separate synchronization requirements. Rename visibility alone is not a durability acknowledgement. |
| Database | Model transaction construction and commit outcomes; qualify bbolt's actual mmap and synchronization behavior separately. |
| Block storage | Thin data, thin metadata, host backing-file capacity, active mappings, open handles, and remote dependencies are distinct. |
| Network | HTTPS and NVMe can fail independently. Streams preserve byte order; retries can duplicate application operations. |
| NVMe | A namespace may remain visible while I/O stalls. Apply actual reconnect and controller-loss behavior. |
| Kubernetes | Authoritative state, cache observations, conditional writes, and result delivery are separate. Respect watch/API guarantees. |
| Time | Wall-clock adjustment differs from elapsed-time deadlines and process scheduling delays. |
| Liveness | State the surviving resources, eventual service, scheduling fairness, and fault-healing assumptions required for each obligation. |

Use the production timeout constants where possible. In particular, transient
peer release failure is not necessarily a leak: server lease expiry is another
cleanup path and must be represented when asserting end-to-end release.

## Coverage map

This coverage map is the simulation coverage ledger: each row names the production code under model and the boundary left to other tests, while `internal/simtest` provides shared replay and exploration conformance checks for component models.

| Tests | Production code exercised | Important scope boundary |
| --- | --- | --- |
| `internal/atomicfile` | Durable replacement operation and real filesystem adapter | Simulated power-loss contract; subprocess tests cover actual process death |
| `internal/storage` | Production create, snapshot, hydration, teardown and recovery workflows, metadata transactions and remote-release obligations | Symbolic device model and real bbolt; seal filesystem checks and kernel persistence additionally need privileged tests |
| `internal/controller/simulation_test.go` | Allocation, state publication, claims, cleanup and optimistic API writes | Fake API with explicit cache delivery; lost replies followed by restart after normal error handling |
| `internal/node/{plan,scheduler}_test.go` | Snapshot planning, GC, admission, source reservations, retries and completion generations | External device and API operations have separate tests |
| `internal/runtime` | Production claim/mount/detach/freeze/stop machine and hypervisor confirmation helper | Guest, network and hypervisor service represented by effect outcomes |
| `internal/guest`, `internal/wire` | Guest freeze/thaw lease expiry and stale-result handling, protocol framing | Real guest filesystem/process behavior and host signal delivery need real-host qualification |
| `internal/peer`, `internal/nvme` | Lease lifecycle, persistence, retry policy and connection workflows | Real transport/device semantics additionally tested by privileged suites |
| `internal/stream/{stream_test.go,simulation_test.go}` | Ring append, whole-record trim, restart recovery, torn-tail rejection, reader gap reporting, and bounded-depth exhaustive exploration of a crash model with injected before/torn/lost writes | The model uses an in-memory `ReadWriterAt`; real volume I/O, concurrent failover and power-loss persistence need device tests |
| `internal/workspace/{fork_test.go,simulation_test.go}` | Production `Fork` snapshot, preflight, child/root creation, owner patching, UID-guarded rollback, and rejected/transport/server read faults plus rejected/transport/server/lost-response write faults | Fake API with injected rejected and ambiguous responses; live API-server races, controller-driven snapshots and filesystem copy behavior are out of scope |
| `internal/apiproxy/simulation_test.go` | Projected token and CA rotation/revocation, idle TLS connection invalidation, request admission, tracked connections, watch/upgrade lifetime and shutdown | In-memory credential filesystem and synchronous upstream; real TLS handshakes, API server, socket and `http.Server` goroutine behavior are out of scope |
| `internal/blipchat/simulation_test.go` | Hub publish/replay/gap ring and subscriber cancellation; ACP driver generation restart, transcript retention and teardown | Production handlers are called synchronously, so driver goroutines/tickers, the real ACP subprocess, Kubernetes watch delivery and the SSE handler are out of scope |
| `internal/streamapi/simulation_test.go` | Production stream handler authorization gate, log/stdin cursor lifecycle, gap/restart/EOF handling, response framing and backend error mapping | Simulated backend ring and generation; real node transport, TLS/SAR authentication and discovery remain in the existing unit tests |
| `internal/simapp` | Composed allocation, production node planning/admission, runtime, lease sequencing, save/replication, reacquisition and bounded liveness windows for runtime-claim handoff and seal/report progress | See its README for exact simulated services and exploration windows |
| `internal/sim`, `internal/simlive` | Replay, exploration bounds and fair-cycle witnesses | Checker tests include deliberately broken models; production properties live in component/world tests |

Pure and thin packages use property tests instead of a simulation model. In
particular, `internal/network` checks that a Blip layer never widens the pool
layer across an address/protocol/port grid and that every compiled policy
passes the runtime's `netpolicy` validation; `internal/netpolicy` validates the
wire representation directly; and `internal/image` shuffles unique layer
entries to check parent-before-child emission and single-copy flattening.
These tests run in the ordinary suite.

Tests use independent content, ownership and resource monitors where applicable.
Seeded campaigns check reproducibility, while complete bounded exploration is
reported only for the specific finite models/windows whose graphs were exhausted.
`internal/simlive/runtime_test.go` additionally checks eventual claim acceptance
using the production runtime machine, with host execution and response delivery
as separate actions. It finds a non-progress cycle without fairness and exhausts
the goal-avoiding graph without a counterexample under the stated service groups.
`internal/simapp/liveness_test.go` applies the same bounded check to the
runtime-claim handoff and the seal/report phase, and includes a stalled-progress
negative control that must produce a fair cycle.

## Durable document replacement

`internal/atomicfile` executes the same resumable operation in production and
simulation:

```text
create temporary file → write → chmod → file sync → close
  → rename → directory sync
```

Its contract requires an already-durable parent directory, working file and
directory synchronization, and crash-atomic same-directory rename. An error
after rename reports publication ambiguity through `*atomicfile.Error`.
Positive short writes continue; zero-progress writes fail. Crash recovery may
leave orphan temporary files, and retry uses a fresh exclusive temporary name.

`TestReplacementCrashExploration` separates inode durability from directory
durability, explores crashes before result acknowledgement, and runs a
fault-free recovery suffix. Negative controls verify that removing file or
directory synchronization breaks the monitored guarantee. `TestReplaceOS`
checks the real filesystem adapter. `TestReplacementProcessCrash` kills an
actual subprocess after each successful filesystem effect but before result
delivery, then checks visibility and successful recovery. This qualifies
process death; the surviving kernel cache makes it different from power loss.

## Qualifying the environment model

Simulated kernel, filesystem, and API behavior is a contract, not evidence that
every production implementation satisfies it. Run the existing real-device
tests on a suitable disposable Linux host:

```sh
hack/storage-test.sh storage nvme peer e2e
```

These require Docker, privileged containers, and the relevant kernel modules.
They exercise actual device-mapper/NVMe behavior; the ordinary unprivileged
suite skips tests requiring those facilities. Actual host power-loss behavior,
silent corruption, and workload-dependent timing need separate infrastructure
qualification. Do not equate in-memory fault exploration with those tests.

When adding a workflow, include production admission/retry/recovery decisions,
enumerate every externally interruptible boundary, and check an independent
property. Record the explored fault budget and bounds. Extend coverage with
ambiguous results, stale identities, cancellation, faults during recovery, and
correlated outages rather than only adding successful examples.
