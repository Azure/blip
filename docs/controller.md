# Controller notes

How `blipd controller` implements the design (`docs/design.md`), and what it expects from nodes. Code: `internal/controller`. Tests: see [Tests](#tests). Protocol flows: `internal/proto/nodepb/README.md`.

## Serving

- One TLS listener on `:8443` for the `nodepb.Controller` gRPC service. There is no other API.
- Only the leader serves. When leadership ends, all node connections are closed, so nodes reconnect to the next leader.
- Metrics on `:9090`, health probes (`/healthz`, `/readyz`) on `:8081`.
- At start the controller creates or loads:
  - Secret `blip-ca` (CA and serving certificate for `blip-controller.blip-system.svc`),
  - ConfigMap `blip-ca` (key `ca.crt`), mounted by the node DaemonSet at `/etc/blip-ca/ca.crt`,
  - Secret `blip-nvme-psk` (key `key`, 32 bytes).

## Node authentication and certificates

- Every RPC needs `authorization: Bearer <token>`, a projected token with audience `blip`.
- The controller runs a TokenReview, requires user `system:serviceaccount:blip-system:blip-node`, reads the bound pod from the token, and checks that the pod is scheduled on the node named in `Hello`.
- Results are cached for 1 minute per token.
- Nodes trust the controller through the `blip-ca` ConfigMap. Nodes get no certificates: storage traffic (including snapshot writes) uses NVMe/TCP with TLS and the per-host PSK from `Welcome`.

## What the controller expects from a node

**Session**
- Send `Hello` first, with the full `NodeState`. The controller answers `Welcome`.
- Send a `Heartbeat` at least every `Welcome.heartbeat_interval` (10s). The controller closes a session that is silent for 3 intervals.
- A new session from the same node replaces the old one.
- A node disconnected for 2 minutes (`--node-lost-timeout`) is lost. Its running Blips fail with `NodeLost`, but their claims stay until the node returns or is fenced (see Node loss).

**Commands**
- Operation IDs are stable. The controller sends each operation once per session and again, with the same ID and deadline, after each reconnect until it gets a final result. The node returns the cached result for a known ID, or does the work idempotently.
- Retries that need a new attempt use a new operation ID: `AttachVolume` (and its exports) after a transient failure, `DetachVolume` after a failure, `CaptureLocal` after a failure, and every snapshot save attempt.
- `IN_PROGRESS` results are ignored. Results for unknown operation IDs are ignored.
- The controller gives up on an operation 30s after its `deadline` and treats it as `DEADLINE_EXCEEDED`.
- `REJECTED` for `Release` or `Kill` of a finished allocation counts as done. `NOT_FOUND` for `Kill` means the VM is gone.

**State the controller reads**
- `NodeState.contents` (from `Hello`, `ListState` and every `NodeState` message): which replicas hold sealed content, for saves, repair and scrub.
- `NodeState.allocations` (from the same states): `assigned`, `boot_count` (boots that reached `EXEC`), `exit`, `slot_lost`, `deadline`, `root_attachment_id`, and the attachments. The node sends no events; it sends a full state whenever something changed. `applyStateLocked` replaces the node's view and compares each allocation with the runtime state (`AllocRuntime`): a higher `boot_count`, a first `exit` or `slot_lost`, or a new assignment wakes the Blip (`AllocChanged`). `exit` and `slot_lost` are kept once set, so an exit is recorded once. A state is applied only from the node's current session (`applyState`); one from a replaced session is ignored. After `Hello`, an assigned allocation missing from the state is marked lost. A controller that started later has no runtime state for the allocation, so `run` also fails a started Blip with `SlotLost` when the connected node's state lacks its allocation (`AllocMissing`).
- `Capacity`: storage fullness for placement and `StorageFull`; compute `memory_pressure` stops claims on the node; `assigned_slots`/`slots` is the node load; `disks_per_slot` limits volumes per Blip.

## Claims, holds and deletion

- A claim (`BlipVol.status.claim`) gives one attachment of one Blip exclusive use of a BlipVol. Taking it sets `claimGeneration + 1` as the claim generation, `claim.snapshot` = `status.current`, `claim.baseline` = 0, and adds an `Attachment` hold, in one status update with a resourceVersion precondition. It is refused while the BlipVol is being deleted or not Ready.
- Claim, hold and finalizer writes use the uncached client. A claim and a deletion cannot both win: the second write fails or sees the first.
- A claim is released only after `ReleaseAttachment` returned OK (VM stopped or volume detached, overlay gone), when the node is fenced (out-of-service taint, or the Node object is NotFound), or when a reschedule abandons it with `nodeLoss: Abandon`. Releasing a claim fails any `Pending` capture of the attachment. There is no separate generation bump: the next claim gets `claimGeneration + 1`, so the old node's commands are refused.
- Holds: `Attachment` (the BlipVol is claimed) and `Clone` (a derive in progress; `snapshot` names the source snapshot, holder is the derived BlipVol). Holds whose holder no longer exists do not count.
- `deleteVol` (finalizer `blip.example.com/storage`) deletes the content of every snapshot only when the BlipVol has no claim, no holds and no own operation in flight. Otherwise it sets `Ready` with reason `DeletionBlocked` and waits. Derived BlipVols never block it. Holds whose holder object is gone are dropped; a claim whose Blip is gone is dropped when the node is fenced or does not report the attachment. The finalizer is removed with an optimistic lock.
- BlipVol status has several writers; see design 7.9.

## Scheduling (Pending)

1. Get every `spec.volumes` BlipVol. Missing or not Ready: wait `WaitingForBlipVol`. Failed: the Blip fails with `InputBlipVolFailed`.
2. Every volume's current snapshot needs 2 reachable sealed replicas (`NoCapacity`); the root volume's group must be below `--storage-full-threshold` (`StorageFull`).
3. SKU, service account, quota and free slots. Only slot pods in the Blip's namespace count (each namespace is its own pool): no BlipPool for the SKU is `UnknownSKU`, no free slot pod is `NoCapacity`; free pods with the pool's `status.templateHash` are preferred; a missing `spec.serviceAccountName` (default `default`) is `ServiceAccountNotFound`. A node qualifies only if `disks_per_slot >= len(volumes)` (`TooManyVolumes` if none does). Nodes are ranked by locality score (100 if the root volume's group has a member there, +1 per data volume group), then free slots, then load.
4. Write `status.volumes` (`Reserving`, attachment ID, slot disk) first, then claim every volume in UID order. A refusal releases all claims of the Blip and waits `VolumeInUse`. A waiting Blip holds no claims. Each entry records `snapshot` (= `claim.snapshot`).
5. Claim the slot pod and write `status.allocation`.

The controller acts on a Blip only when its cached copy is not older than the last status it wrote (a live read checks this), and acts on a new attachment ID only after it was written. So no command is sent for an ID that is not recorded.

## Run

1. `AssignSlot`. A failure ends the run with `StartFailed`.
2. For each volume: `Export` read-only of the `claim.snapshot` content on its sealed replicas (host = compute node), then `AttachVolume` with the claim generation and slot disk. A transient failure (`FAILED` or `DEADLINE_EXCEEDED` with a code other than `NOT_FOUND`, `STALE_GENERATION`, `CONFLICT`; or no replica exported) is retried with new operation IDs (`<op>.rN`, exports included) after 2s, 4s, 8s; the volume message shows the attempt. A rejection, `NOT_FOUND`, or the 4th failed attempt fails the Blip with `AttachFailed`.
3. All `Attached`: `VolumesReady=True`, then `StartWorkload` with `root_attachment_id`, all volumes, `params.init`, `params.root_mount_options` from the spec, `params.hostname` (the Blip name), and `credentials`: a TokenRequest token for the service account (1h; bound to the Secret `blip-token-<alloc>`, which the controller creates with the live client before minting, owned by the Blip and labeled `blip.example.com/name` and `blip.example.com/allocation`), the controller's API server CA (`rest.Config` CAData or CAFile) and the namespace. The node writes all of this to the metadata disk; `blip-boot` then mounts the root and execs init. `AssignSlot` carries the deadline, `kill_grace` (`--graceful-timeout` plus 10s) and `spec.ports` for `blipd slot`. `blipd slot` kills the VM at deadline plus `kill_grace`, after the controller's graceful stop at the deadline.
   - A `boot_count` above 0 (the node raises it when the guest area says `EXEC`, again after each reboot) sets `Started=True`. `status.restartCount` is `boot_count - 1`.
   - Rotation: the controller keeps each allocation's token expiry in memory and, at 80% of the lifetime, mints a new token and sends `UpdateCredentials` (operation `<alloc>.creds.<time>.<n>`; a failure is retried after 10s). After a restart it has no expiry, so every started Blip gets a fresh token on its next reconcile.
   - Revocation: the binding Secret is deleted when the Blip finishes and when the slot is given up, revoking all tokens of the allocation. Before the first token of an allocation, the Blip's other binding Secrets are listed (label selector, uncached client) and deleted. Secrets are never cached.
4. The run ends when the node reports the allocation's `exit` (`exitOutcome`). `blipd slot` classified it; the controller copies `exit.reason` and `exit.message` into the conditions. `Succeeded` sets `Complete`; any other reason sets `Failed` (an empty reason counts as `HypervisorExited`).
   - `status.lastExitCode` is the exit's exit code. Other failures: `StartFailed` (assign or start call failed), `SlotLost` (only from the node's `slot_lost`; the controller does not inspect slot pods for it), `NodeLost`, `Cancelled`, `TTLExceeded`.
5. With `spec.reschedule`, every failure above passes through `endAttempt`: `Error`, `GuestPanic`, `InitExited`, `BootFailed`, `NodeLost`, `SlotLost`, `HypervisorExited`, `StartFailed` and `AttachFailed` set `Rescheduling=True` (reason = the failure), `status.lastFailure`, and a `shutdownSnapshot{reason: Reschedule}` on every `Attached` spec volume, if `rescheduleCount < limit` and `now + backoff < deadline`. Otherwise `Failed` as usual (the message notes the limit or deadline).

## Reschedule

- Release runs as below with release reason `Reschedule`; `Kill` carries the failure reason. The capture is taken even with `skipShutdown`.
- Per volume (design 4.5): node connected: stop, capture, save, append (`Ready`). Capture or save gives up: `Failed`. Node back without the attachment, fenced, or Node NotFound: `Unavailable` at once. Node unreachable: wait up to `spec.reschedule.salvageTimeout` (default 5m) from the attempt end; if it returns with the overlay, stop the VM (generation-checked) and capture. After the window, `nodeLoss: Fence` keeps waiting with `Rescheduling=False/NodeUnreachable`; `nodeLoss: Abandon` marks the snapshot `Unavailable`, fails any `Pending` capture, asks replicas (best-effort) to stop exporting the attached snapshot to the lost node, and drops the claim (`abandon`). While waiting the reason is `Rescheduling=True/NodeUnreachable` with the time the window ends.
- When it is done (`finishReschedule`): status entries are reset to `{name, blipVolRef, message}`. There are no carries, `Input` holds or fallbacks: the next attempt attaches each BlipVol's `status.current`. Then `forgetBlip`, allocation, pod IP and `stopRequestedTime` cleared, `rescheduleCount + 1`, `nextScheduleTime`, `Started`/`VolumesReady`/`Finished=False/Rescheduled`, `Scheduled=False/RescheduleBackoff`, phase `Pending`.
- In `finishReschedule`, for each volume whose `Reschedule` shutdown snapshot is not `Ready`, the new entry gets `resumedFrom {sequence, captureTime}` of the BlipVol's newest Ready snapshot (corrected to the snapshot actually claimed when the next attempt claims it) and a message saying the overlay was not saved. `Rescheduling` then has reason `ResumedFromOlderSnapshot` (instead of `RescheduleBackoff`), with the lost time window per volume in the message.
- A node that returns holding an allocation of an abandoned (finished) Blip finds it in `Welcome.finished_allocation_ids` and releases it, stopping the stale VM and dropping its overlays. An allocation no Blip knows gets an explicit `Release`. In both cases the controller emits a `Warning` event `OverlayDiscarded` on the Blip, naming the allocation and attachments (`nodeConnected`).
- Scheduling: before the backoff ends it waits; once the deadline passed it fails `TTLExceeded`. `startTime`/`deadline` are only set when unset. The slot claim sets `Rescheduling=False` with message `attempt N`. The reason is `ResumedFromOlderSnapshot` if any volume has `resumedFrom` (the message names each volume, its claimed snapshot and the lost window), else `Rescheduled`.
- Metric `blip_reschedules_total`.

## Live attach and detach

Driven by the difference between `spec.volumes` and `status.volumes`, only after `Started`. An attach or detach waits only while a capture of the same volume is in flight.

- Added entry: `Reserving` (new attachment ID, lowest free slot disk; none free: message `TooManyVolumes`), claim (refused: message `VolumeInUse`, retried), `Attaching` (export of `claim.snapshot`, `AttachVolume`, retried like the initial attach), `Attached`. A failed attach goes through detach and release to `Failed` with message `AttachFailed: ...`; remove and re-add the entry to retry.
- Removed entry: `Detaching`, `DetachVolume`. The node unplugs the disk without asking the guest (forced). `NOT_FOUND` (the node has no record of the allocation): counts as detached when the node's last reported state does not list the allocation either; otherwise the controller sends `ListState` to refresh it and retries with a new operation ID and a backoff from 5s doubling to 5 minutes. Other failures use the same backoff. OK (or detached): the shutdown snapshot (reason `Detach`) unless `skipShutdown` (then `Skipped`), then `ReleaseAttachment`, `Unexport` of the origin for the compute node, release the claim: `Released`. Released entries stay in status until the name is added again.

## Release (every terminal path)

Phase `Saving` until done.

1. Node not connected: if the Node has taint `node.kubernetes.io/out-of-service` or is NotFound, see Node loss. Otherwise wait with `Finished=False/NodeUnreachable` (reschedules follow the salvage rules above).
2. Stop the VM unless the node reported the exit: `Kill{graceful: true}` with `--graceful-timeout`. The node presses the ACPI power button (`vm.power-button`) and kills Cloud Hypervisor if it has not exited in time. The first request writes `status.stopRequestedTime`. The graceful timeout counts from `stopRequestedTime`, so it survives a controller restart: a new leader sends `Kill{graceful: true}` with the remaining time, or `graceful: false` when none is left. A guest that powered off by itself needs no `Kill`.
3. A capture of a volume in flight finishes first.
4. For each attachment, in any state: if it reached `Attached` and `skipShutdown` is not set (a `Reschedule` release ignores `skipShutdown`), the shutdown snapshot (capture loop below); then `ReleaseAttachment`, `Unexport`, release the claim. The volume is `Capturing` while its shutdown snapshot is taken and saved, and `Publishing` once it is Ready.
5. `Release` of the allocation, delete the slot pod.
6. `Finished` (and the removal of the `blip.example.com/cleanup` finalizer) only after every shutdown snapshot is `Ready`, `Skipped`, `Unavailable` or `Failed` and every claim is released.

Shutdown snapshot reasons: `Completed`, `Failed`, `DeadlineExceeded`, `Deleted`, `Detach`, `Reschedule`. A failed run never skips a shutdown snapshot.

## Capture loop and saves

The algorithm (triggers, steps, base and group choice, ownership, shutdown snapshots) is in design 7.7 to 7.9. Code: `capture.go`, `save.go`. Implementation notes:

- No schedule is stored: the next interval capture is computed from the snapshot entries and the claim time.
- Waiting derives are found through the field index on `status.origin.uid`. A change of a derived BlipVol wakes the Blip that holds its parent's claim (BlipVol watch on the Blip controller).
- Sequence `q`, content ID `<vol uid>-<q>` and operation ID `cap-<vol uid>-<q>` are fixed before any node command, so a retry after a lost write reuses them.
- `CaptureLocal` failures other than `NOT_FOUND` and `STALE_GENERATION` are retried with new operation IDs (backoff 2s to 1m), up to `--transfer-attempts`.
- For interval and derive captures the outcome sets `SnapshotsBehind` (`Saved` or `CaptureFailed`). A refused capture (claim lost, `StorageFull`, base gone) sets `SnapshotsBehind=True` with that reason.
- Save attempts live in memory only. After a controller restart a save starts a new attempt; `PrepareReceive` keeps prepared content of the same generation, and the rewrite covers the same ranges.

## Derive

A BlipVol with `spec.parent` (source `S`):

- `parent.snapshot` set: that snapshot must be Ready. Above `lastSequence`: wait (`SnapshotNotYetTaken`, message `snapshot N ... does not exist yet`). `Pending`: wait (`ParentNotReady`). Deleted or `Failed`: the BlipVol fails (`SnapshotNotFound`). Unset and `S` not claimed: `S`'s newest Ready snapshot. `S` missing: `ParentNotFound`; no Ready snapshot: `ParentNotReady`.
- Unset and `S` claimed by a running Blip: set `status.origin.uid`, wait `WaitingForCapture`; use the first Ready snapshot of `S` with `captureTime` after the BlipVol's `creationTimestamp`. If the claim is released first, use the newest Ready one. `S`'s node unreachable: `SourceUnreachable`. `S` being deleted: wait (`ParentNotReady`).
- Discovery: field indexes on `status.origin.uid` and `spec.parent`. A BlipVol watch on the BlipVol controller wakes derived BlipVols when their parent changes, and wakes the origin when a derived BlipVol changes or is deleted.
- Clone: `Clone` hold on `S` with `snapshot` (checked Ready on a fresh copy of `S`), then snapshot clone (`Clone SNAPSHOT` and `Seal` on each source replica) or, above `--placement-threshold`, full copy (`CreateContent` and `Export` on the least full other group, `Clone COPY` on one source replica, `Unexport`, `Seal`). Result: sequence 1 (`Initial`), `status.origin = {namespace, name, uid, snapshot, contentID}`. The hold goes when the clone is Ready, Failed or deleted.
- Cross-namespace parents need `get` on the source (admission policy).

## Compaction

The BlipVol controller, per vol, on changes and every 5 minutes: keeps the newest `snapshotPolicy.limit` (default 24) Ready snapshots and deletes older Ready ones. Failed snapshots older than the newest Ready are deleted; of the Failed ones newer than every Ready one, the newest `limit` are kept. Never deletes `Pending` entries or a protected snapshot:

- `Held`: `claim.snapshot`, `claim.baseline`, the snapshot of a `Clone` hold, the base of a `Pending` capture.
- `Pinned`: `status.origin.snapshot` of an existing BlipVol derived from this one (field index on `status.origin.uid`, all namespaces), and the explicit `spec.parent.snapshot` of a derived BlipVol that is still provisioning. Pins are computed after the live read, and only when the cached BlipVol has the live `resourceVersion`; otherwise compaction retries in 1s.

The newest Ready is always within the limit. Ready snapshots kept beyond the limit set `RetentionLimitExceeded=True`, reason `Pinned` (wins) or `Held`. Deleting a snapshot: remove the entry first (on a fresh copy, so a hold or claim taken meanwhile is seen), then `DeleteContent` on each member of its group; content left on an absent node is removed by the orphan scan.

## Node loss and fencing

- Lost or rebooted nodes never release claims by themselves. A Blip on an unreachable node stays `Saving` with `Finished=False/NodeUnreachable` (reschedules: see Reschedule).
- Node returns with the same state: the release continues. Node rebooted: `Kill` gets `NOT_FOUND`, `CaptureLocal` gets `NOT_FOUND` (shutdown snapshot `Unavailable`), `ReleaseAttachment` succeeds (unknown), claims are released.
- Node fenced (taint `node.kubernetes.io/out-of-service`, watched on Node objects) or Node NotFound (`nodeGone()` treats both alike): `abandon` marks unsettled shutdown snapshots `Unavailable`, fails any `Pending` entry of the attachment, releases holds and claims and deletes the pod. The Blip finishes (or, when rescheduled, goes back to Pending). The next claim has a higher generation, so stale commands from the node are refused (the node daemon checks generations; the controller only sends them). When the node returns, `Welcome.finished_allocation_ids` lists the allocation and an `OverlayDiscarded` event is emitted.

## Volumes

- Root import, primary = first connected group member by name: `CreateContent` and `Export` (read-write, host = primary) on the others, `Import` on the primary, `Unexport` on the others, `Seal` on the primary and the targets that reported `ok`. A BlipVol with neither image nor parent is a zero-filled raw device. The result is sequence 1 (`Initial`).
- Derive: see Derive.
- Delete: `DeleteContent` of every snapshot's content on every group member that is not lost.
- Content IDs: `<BlipVol UID>-<sequence>` for every snapshot. Allocation and attachment IDs are 16 hex characters.

## Repair loop

Each storage node, every minute: `ListState`; map each content ID back to (vol UID, sequence); delete unexpected content older than `--orphan-age` (10 minutes) unless a save into it runs here; delete unsealed copies of Ready snapshots and partial receives of Failed ones; never delete sealed content of a known snapshot, or any content of a claimed or held BlipVol. Pending entries get their content ID before `PrepareReceive`, so receives in flight are expected content. Rebuild missing sealed content in sequence order (`Clone SNAPSHOT` of a base or `CreateContent REPAIR`, `Export` to the source, `Repair`, `Unexport`, `Seal`). The base is the snapshot's `base`, else another snapshot of the same vol or `rootContentID` in the group, else empty. The first connected member of a group also runs the scrub, one snapshot per pass, each once per `--scrub-interval`. On a mismatch, if 2 replicas agree the odd one is repaired; otherwise the snapshot entry is marked `Failed` (message `ScrubMismatch: ...`, even if it was Ready) and `current` moves to the newest Ready one left. Only when no Ready snapshot is left is the BlipVol `Failed` (`Ready=False`, `Failed=True`, reason `ScrubMismatch`).

## Flags

Defined in `internal/controller/options.go`.

| Flag | Default | Meaning |
|---|---|---|
| `--namespace` | `blip-system` | System namespace |
| `--listen` | `:8443` | Node gRPC address (TLS) |
| `--metrics-addr` | `:9090` | Prometheus metrics |
| `--probe-addr` | `:8081` | Health probes |
| `--leader-elect` | true | Use a Lease for leader election |
| `--default-quota` | 10 | Running Blips per namespace and SKU without a namespace annotation |
| `--snapshot-interval-scale` | 1 (kind: 60) | Divides `snapshotPolicy.interval`; test clusters only |
| `--token-ttl` | 1h (at least 10m) | Guest service account token lifetime; renewed at 80% |
| `--graceful-timeout` | 30s | Power button to kill on deadline, cancel or deletion |
| `--transfer-attempts` | 5 | Tries per capture or save before the snapshot is `Failed` |
| `--save-timeout` | 15m | Limit for one snapshot (capture, save, seal) |
| `--node-lost-timeout` | 2m (kind: 40s) | A node disconnected this long is lost |
| `--command-timeout` | 2m | Deadline of short node commands |
| `--import-timeout` | 60m | Deadline of import, full-copy clone and repair |
| `--heartbeat` | 10s (kind: 3s) | Heartbeat interval sent to nodes |
| `--placement-threshold` | 80 | Group fullness percent at which new roots and clones go elsewhere |
| `--storage-full-threshold` | 90 | Group fullness percent at which Blips wait with `StorageFull` and captures go to another group |
| `--orphan-age` | 10m | Minimum age of unexpected content before it is deleted |
| `--repair-interval` | 1m | Orphan and repair loop interval |
| `--scrub-interval` | 7d | Scrub interval per content |
| `--slot-image` | none (required) | Image of the slot pods |
| `--slot-cpu-overcommit` | 4 | Slot pod CPU request = guest vCPUs / this |
| `--slot-memory-overcommit` | 1.5 | Slot pod memory request = guest memory / this, plus `--slot-vmm-overhead` |
| `--slot-vmm-overhead` | 256Mi | Hypervisor memory added to slot pod requests and limits |

## Metrics

`blip_slots`, `blip_pool_slots{namespace,pool,state=free|booting|assigned}`, `blip_pool_desired_free{namespace,pool}`, `blip_pending_blips`, `blip_quota_used`, `blip_claim_to_started_seconds`, `blip_create_to_started_seconds`, `blip_snapshot_seconds{kind}`, `blip_snapshots_total{kind,result}` (`kind` is the snapshot reason: `initial`, `shutdown`, `interval`, `derive`, `reschedule`; `result` is `ready`, `failed`, `unavailable`, `deleted`), `blip_snapshot_written_bytes_total`, `blip_attachments` (claimed BlipVols), `blip_holds{kind}`, `blip_storage_pool_percent`, `blip_replicas_missing`, `blip_scrub_mismatches_total`, `blip_repairs_total{result}`, `blip_orphan_lvs{node}`, `blip_reschedules_total`, `blip_nodes_connected`.

## Slot pools

- The pool controller creates slot pods for each BlipPool (design 6.1) and writes `status.free`, `booting`, `assigned`, `desiredFree`, `templateHash`, `lastScaleTime` and the `Ready` condition. It watches BlipPools, slot pods and Blips.
- Sizing is a pure function: `desiredFree = clamp(minFree + demand, minFree, maxFree)`, where the part above `minFree` is limited by quota minus running Blips. The target of free and booting pods with the current hash is `desiredFree` plus Blips waiting with `NoCapacity`, at most `maxSlots - assigned`. Scale-down waits `scaleDownDelay`.
- Creates and deletes are tracked as expectations until the cache shows them (1 minute timeout), like the ReplicaSet controller.
- Free pods are deleted under the scheduling lock, skipping pods with an assumed claim, with UID and resourceVersion preconditions, so a pod is never deleted while it is being claimed.
- Claiming a pod removes its BlipPool owner reference. Admission policy 3 (design 3.4) stops the garbage collector from deleting assigned pods.
- RBAC: `create` on pods (limited by admission policy 6), read and update on `blippools`, `blippools/status`, and `update` on `blippools/finalizers` for the `blockOwnerDeletion` owner references.

## Slot pods

Slot pods live in tenant namespaces. The manager's pod cache is cluster-wide but limited to pods with the `blip.example.com/slot` label, so other pods (including node pods, which `TokenAuthenticator` reads with the uncached client) are not cached. Assumed claims are keyed by namespace and name. A slot pod is claimable when it is free, Running and Ready (Kubernetes pod readiness); the node does not report slot readiness. A free slot pod event for a Ready pod wakes the Blips waiting for its SKU.

## Differences from the design

- The base of a save gets no hold object: compaction treats the base of every `Pending` capture as `Held`.
- Failed imports and derives mark the BlipVol `Failed` without retry. A missing pull secret waits.
- Shutdown clocks are persisted (`status.stopRequestedTime`, condition times); retry counters are not.
- Save attempts and the snapshot timer are kept in memory; after a controller restart they start again.
- `status.restartCount` counts guest reboots of the current attempt only; reschedules are counted in `status.rescheduleCount`.
- A Blip deleted while a reschedule release runs finishes that release (`Reschedule` snapshots included) and is then cancelled from Pending.
- Scrub times are kept in memory; after a restart the first scrubs are spread over the interval.

## Tests

The envtest suite (`internal/controller/*_test.go`, needs `KUBEBUILDER_ASSETS`) runs the controller against a real kube-apiserver and eight nodes from `internal/testing/fakenode`. Each fake node is the real node daemon (`internal/node`) running in the test process, connected to the controller over TLS like a deployed one. Only the host parts are replaced:

- Storage: `internal/node/nodetest.FakeStorage`. Contents live in memory. Snapshot writes copy small files between the fake nodes of the process.
- Slot pods: the node lists the slot pods bound to its Kubernetes node. A fake blipd slot prepares a ready slot directory for each, writes `exit.json` on the kill file, and the test's workload plays the guest (`EXEC`, `Poweroff`, ...).
- Cloud Hypervisor: hot-plug succeeds; the power button powers the guest off.

The fake blipd slot kills the VM at the kill time of the assignment (deadline plus `kill_grace`), like the real one. `TestDeadline` covers the graceful stop at the deadline, `TestDeadlineSlotBackstop` the slot kill when the controller's Kill fails.

Faults: `SetHook` intercepts commands on the session stream (fail, delay or drop them), `Pause`/`Resume` break the session, `Reboot` restarts the daemon with a new boot ID and empty slot and state directories, and `FailTransfersTo`, `FailNextCapture` and `SetGracefulHang` switch the fakes.
