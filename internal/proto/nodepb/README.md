# nodepb: controller-node protocol

Design: `docs/design.md`. Controller behavior: `docs/controller.md`.

The node daemon dials the controller at `blip-controller.blip-system.svc:8443` with TLS and calls `Controller.Session`. It sends its projected service-account token (audience `blip`) as `authorization: Bearer <token>` metadata on every RPC.

Notation: `C` is the controller, `S1..S3` are the storage nodes of the group, `N` is the compute node. `X -> Y: Msg` means X sends Msg to Y. Every command gets a `CommandResult` with the same `operation_id`. Commands are idempotent; after a reconnect the controller may resend any command with the same operation ID.

## Connect

1. `N -> C: Hello` (node name, boot ID, capabilities, capacity incl. `disks_per_slot`, full `NodeState`).
2. `C` checks the token with TokenReview and that the pod runs on `node_name`.
3. `C -> N: Welcome` (host NQN, host PSK, finished allocation IDs, heartbeat interval).
4. `N` tears down allocations listed as finished and any it does not know (after `C` sends `Release`). `C` compares `NodeState` (allocations, attachments with generations, contents) with the CRs and adopts or cleans up. `C` never releases a claim because an attachment is missing from `NodeState` alone; it issues `ReleaseAttachment` and waits for OK.
5. Both sides send `Heartbeat`. A node that is not connected for 2 minutes is lost (but see "Node loss").

## State

`N` has no events. Whenever anything in its `NodeState` changes (allocations with boots, exit and slot loss, attachments, slots, capacity, contents), `N -> C: NodeState`, complete. `N` keeps only a "state changed" flag, not a queue: changes made before the state is built collapse into one message, so nothing is dropped. A pending state is sent before any queued result, so a change made before a result was queued (for example the exit before the `Kill` result) reaches `C` first. After every command and after a `ListState` result, `N` marks the state changed. `C` replaces its view of `N` with each state and compares the allocations with the previous one: a new boot, an exit or a lost slot wakes the Blip. The exit and slot loss are recorded once and never replaced. `C` applies a state only from the current session of `N`; a state that arrives on a replaced session is ignored.

## Initial attach and start

Blip with volumes `root` (BlipVol `R`, content `r`) and `data` (BlipVol `D`, content `d`), allocation `A` on `N`. `C` has already claimed `R` and `D` (claim generations `gR`, `gD`) and chosen attachment IDs `aR`, `aD` and slot disks 0, 1.

1. `C -> N: AssignSlot{A, blip, pod, deadline, kill_grace, ports}`. `pod` is in the Blip's namespace. The warm VM runs the boot stub, which waits for its root volume.
2. For each volume, `C -> Si: Export{content, READ_ONLY, host N}` on the replicas of its group. Results: `Path`s.
3. `C -> N: AttachVolume{A, aR, gR, uid(R), "root", r, size, paths, slot_disk 0}`, likewise `{A, aD, gD, uid(D), "data", d, size, paths, slot_disk 1}`. `N` builds the origin multipath, the overlay, points the slot disk, creates the links and hot-plugs with virtio serial = volume name. Result: guest path `/dev/disk/by-id/virtio-<name>`. Each volume becomes `Attached`.
4. Once all are attached (`VolumesReady`): `C -> N: StartWorkload{A, blip, params{init, root_mount_options, hostname}, root_attachment_id aR, volumes, credentials}`. `N` writes these to the metadata disk; the deadline and ports came with `AssignSlot`. The stub mounts the root attachment (serial = its volume name, here `root`) as `/` and execs `init`. If it cannot, it records FAIL with a reason (for example `RootMountFailed`) and powers off: `Exited{reason: BootFailed, message}`.
5. `N -> C: NodeState` with `boot_count` raised each time the stub reports EXEC (again after every guest reboot), and with `exit` set when the VM ends.
6. Before the token expires (80% of its lifetime): `C -> N: UpdateCredentials{A, credentials}`; `N` rewrites the metadata disk. Before `StartWorkload` ran, `N` keeps them for the start. Credentials are not written to any other disk on the node.

## Live attach

Running Blip, new `spec.volumes` entry `x` (BlipVol `X`, current snapshot content `x`). `C` waits only while a capture of `X` is in flight.

1. `C` claims `X` (generation `gX`, `claim.snapshot` = `X.status.current`), records `aX` and a free slot disk `k` in `status.volumes` (`Reserving`, then `Attaching`).
2. `C -> Si: Export{x, READ_ONLY, host N}`.
3. `C -> N: AttachVolume{A, aX, gX, uid(X), "x", x, size, paths, slot_disk k}`. OK: `Attached`, guest has `/dev/disk/by-id/virtio-x`. A transient failure is retried up to 4 attempts with new operation IDs (`attach.rN`, `exp.<node>.rN`); `AttachVolume` is idempotent per attachment ID, so a retry continues where the failed attempt stopped.

## Live detach

Entry `x` removed from `spec.volumes` (never the root volume). `C` waits while a capture of `X` is in flight.

1. `C -> N: DetachVolume{A, aX, gX}`.
   - `OK`: the detach is forced (the guest is not asked); the hypervisor no longer holds the device. The overlay stays.
   - `NOT_FOUND`: `N` has no record of `A` (so no VM of `A` holds the device). `C` treats it as `OK` if `N`'s last `NodeState` does not list `A`; otherwise it sends `ListState` and retries with a new operation ID and backoff.
2. Unless `X` has `snapshotPolicy.skipShutdown`: the capture flow below (reason `Shutdown`, release reason `Detach`).
3. `C -> N: ReleaseAttachment{A, aX, gX}`. `C -> Si: Unexport{x, host N}` if no other attachment on `N` uses `x`.
4. `C` drops the `Attachment` hold and releases the claim on `X`. The entry stays in `status.volumes` as `Released` until the name is added again.

## Capture (shutdown, interval, derive, reschedule)

One attachment `aX` of `A` at a time; there are no snapshot sets. Triggers: release (shutdown or reschedule), an interval tick, or a BlipVol waiting to derive from `X`. Sequence `q = X.status.lastSequence + 1`, content `o = <uid(X)>-<q>`, operation ID `cap-<uid(X)>-<q>`. Local sequence on `N`: `l(q) = q * 1024 + slot disk k`, unique within `A`. Base `b` and target group: see design 7.9 (a full write with empty base when the base's group is at `--storage-full-threshold`).

1. `C` appends entry `q` (`Pending`, content `o`, writer `aX` with the claim generation, `captureTime` now, group, base `b`) to `X.status.snapshots`, before any node command.
2. `C -> N: CaptureLocal{A, seq l(q), [aX/gX]}`. Crash-consistent; the guest keeps running. `NOT_FOUND` or `STALE_GENERATION` (overlay gone or not ours): entry `q` `Failed`; a shutdown snapshot is `Unavailable`. Other failures are retried with new operation IDs; after `--transfer-attempts` entry `q` is `Failed`. For an interval or derive capture the outcome sets `SnapshotsBehind`.
3. `C -> Ti: PrepareReceive{o, base b, size, owner X, gX}` on every target replica: a thin snapshot of `b`, or a blank thin when `b` is empty. Then `C -> Ti: Export{o, READ_WRITE, host N}`. Results: `Path`s.
4. `C -> N: WriteSnapshot{A, aX, gX, seq l(q), base_seq (l of the base if aX wrote it, else 0 for the origin), full, o, targets[paths]}`. `N` connects to every path over NVMe/TCP with TLS (its host PSK), writes the changed ranges with direct I/O, flushes and disconnects. Result: `changed_bytes` and per-target `ok`.
5. `C -> Ti: Unexport{o}`, then `Seal{o, X}` on the written targets (at least 2; otherwise delete `o` on all targets, retry with backoff and new operation IDs; after `--transfer-attempts` or `--save-timeout` entry `q` is `Failed`).
6. Entry `q` is `Ready`; `current = q`, `claim.baseline = q`. For a release, `shutdownSnapshot.state = Ready`. Before the next capture, `C -> N: DropLocalSnapshot{A, aX, gX, l(s)}` for every settled snapshot `s` of `aX` other than the baseline, once (`C` remembers dropped ones in memory). If entry `q` was marked `Failed` or deleted while being saved (for example its writer lost the claim), the shutdown snapshot is `Failed`, not `Ready`.

## Release on terminal paths

1. Stop the VM:
   - the guest powers off, panics or its init exits: `N -> C: NodeState` with `exit{reason, exit_code}` on the allocation.
   - deadline, cancel, deletion: `C -> N: Kill{A, reason, graceful: true}`; `N` presses the ACPI power button and kills Cloud Hypervisor after `graceful_timeout`. Result OK when Cloud Hypervisor exited.
2. VM stopped: for each attachment, the capture flow, unless `skipShutdown` (then `Skipped`). A reschedule always captures.
3. For each attachment: `C -> N: ReleaseAttachment{A, a, g}`; drop holds; release claims.
4. `C -> N: Release{A}`, unexport origin contents for `N`, delete the pod. `Finished` once every shutdown snapshot is settled and every claim is released.

A command failure never skips a shutdown snapshot.

## Node loss and fencing

1. `N` is disconnected. `C` does not release claims or holds on a lost heartbeat or lease alone; the Blip stays `Saving` with reason `NodeUnreachable`.
2. If `N` reconnects (same boot ID), `C` resumes from `NodeState`. If the boot ID changed, overlays and local snapshots are gone: shutdown snapshots become `Unavailable`; each BlipVol's newest Ready snapshot is the recovery point.
3. When the Node has the taint `node.kubernetes.io/out-of-service`, or the Node object is gone (fenced), `C` marks unsettled shutdown snapshots `Unavailable` and `Pending` entries `Failed`, drops holds, releases the claims (the next claim gets a higher generation) and finishes the Blip. If `N` comes back, its stale commands are refused by generation; `Welcome.finished_allocation_ids` lists the allocation, so `N` releases it; `C` sends `Release` for allocations no Blip knows, and emits `OverlayDiscarded` on the Blip.
4. Reschedule with `nodeLoss: Abandon`: after `salvageTimeout`, `C` releases the claims without fencing, as in step 3, and asks the replicas (best-effort) to `Unexport` the attached snapshot from `N`. The next claim gets a higher generation. If `N` comes back with the old overlay, it finds `A` in `Welcome.finished_allocation_ids` and releases it (kills the stale VM, tears down the overlays). The overlay is discarded; `C` emits `OverlayDiscarded`.

## Import (image or empty volume)

New content `R` (= `<uid>-1`) in a group, primary `S1`:

1. `C -> S2,S3: CreateContent{R, size, ROOT}`.
2. `C -> S2,S3: Export{R, READ_WRITE, host S1, PSK of S1}`.
3. `C -> S1: Import{R, size, image, pull secret, targets}` (no image: zero-filled raw device, no filesystem). Result: digest and per-target success.
4. `C -> S2,S3: Unexport{R}`.
5. `C -> S1,S2,S3: Seal{R}` on those that succeeded (S1 always). At least 2. `R` is sequence 1 (`Initial`).

## Derive (clone)

New BlipVol `D` from source snapshot content `P` (`<uid(S)>-<n>`), new content `R` = `<uid(D)>-1`. `C` holds `S` with a `Clone` hold naming `n`. If `S` is attached and no snapshot was named, `D` waits (`WaitingForCapture`) while the Blip holding `S` runs the capture flow (reason `Derive`); `D` uses the first Ready snapshot of `S` captured after `D` was created.

Snapshot clone, same group: `C -> Si: Clone{R, P, SNAPSHOT}` on every replica, then `Seal{R}`.

Full-copy clone to another group `{T1,T2,T3}`, source `S1` holding `P`:

1. `C -> Tj: CreateContent{R, size, CLONE}`, then `Export{R, READ_WRITE, host S1}`.
2. `C -> S1: Clone{R, P, COPY, targets}`.
3. `C -> Tj: Unexport{R}`, then `Seal{R}` on targets that succeeded.

## Delete

Per snapshot content (compaction deletes one; deleting a BlipVol deletes all):

- Compaction: `C` removes the snapshot entry first, then `C -> Si: DeleteContent{[R]}` on every reachable replica. Content left on an absent node is removed by the orphan scan.
- BlipVol delete: `C -> Si: DeleteContent{[R...]}` on every reachable replica, then removes the finalizer once all return OK for every snapshot.

## Repair

Content `R` (`<vol uid>-<seq>`) missing on `T`, healthy source `S`, base `B` (the snapshot's `base`, else another snapshot of the same vol or the same root content on `T`):

1. With a base: `C -> T: Clone{R, B, SNAPSHOT}`. Without: `C -> T: CreateContent{R, size, REPAIR}`.
2. `C -> T: Export{R, READ_WRITE, host S, PSK of S}`.
3. `C -> S: Repair{R, base B, target}`. `S` copies `thin_delta(B, R)` (or all mapped ranges).
4. `C -> T: Unexport{R}`, then `Seal{R}`.

## Scrub

1. `C -> Si: Scrub{R, blocks_per_hash: large}` on all replicas; compare.
2. For mismatching ranges, scrub again with smaller ranges down to 1 chunk.
3. Minority mismatch: `T` keeps its LV. `C -> T: Export{R, READ_WRITE, host S, repair_sealed: true}`, `C -> S: Repair{R, extents, target}` copies only the bad chunks, then `C -> T: Unexport{R}`. No majority: the snapshot entry is marked `Failed` (even if Ready) and `current` moves to the newest Ready one left; the BlipVol is `Failed` (`ScrubMismatch`) only if none is left.

## Node behavior notes

- **Slots.** The device plugin names slot devices `slot-0` to `slot-<N-1>`. The slot directory on the host is `/run/blip/slots/<device ID>`. `SlotInfo.pod` has the pod namespace and name but no UID, because the kubelet PodResources API does not report it. `SlotInfo.allocation_id` names the allocation on the slot.
- **Readiness.** The node does not track slot readiness. `blipd slot` writes `ready` once the boot stub wrote WAITING to the metadata disk; the pod readiness probe reads it, and the controller claims only Ready pods. `AssignSlot` is rejected when the node does not know the pod (after one refresh of the pod map), when the slot is used by another allocation, or when the slot already ran a VM. The controller fails the run with `StartFailed`.
- **Counting.** `AllocationInfo.boot_count` is 1 after the first boot. `Exited.restart_count` is the number of guest reboots (`boot_count - 1`).
- **Exit classification.** `blipd slot` classifies the end of the VM once and writes the Blip reason and message to `exit.json`: `Succeeded` or `Error` (clean shutdown, by guest exit code), `GuestPanic` (pvpanic or a kernel panic in the serial log), `InitExited` (with the init exit code), `BootFailed` (the stub wrote FAIL; the message has its reason), `TTLExceeded` (killed at its kill time), `HypervisorExited` (killed, or any other exit). The node passes `Exited.reason` and `message` on unchanged, and the controller copies them into the Blip. `exit_code` is the code the guest recorded with `blip-meta exit`, else the init exit code. A reboot is not an exit. Overlays stay until `ReleaseAttachment`.
- **Deadline.** The node does not enforce the deadline. It writes `deadline + kill_grace` as the kill time to `assignment.json`; `blipd slot` kills Cloud Hypervisor then, with exit reason `TTLExceeded`. The controller sends a graceful `Kill` at the deadline, so that normally ends the VM first.
- **Slot lost.** The node sets `AllocationInfo.slot_lost` (the reason) when the pod holding the slot is gone for 10 seconds, when the slot is given to another pod, or when the Cloud Hypervisor API socket is unreachable for 30 seconds and no `exit.json` was written.
- **Release** kills Cloud Hypervisor if it still runs, waits up to 15 seconds for it to exit, then releases every remaining attachment. Releasing a finished or unknown allocation succeeds.
- **Generations.** Every attachment command carries `attachment_id` and `generation`; see the comment on `AttachmentRef` in `node.proto` for the rejection rules. Rejections have status `REJECTED` with code `STALE_GENERATION` (lower) or `CONFLICT` (higher). The node daemon checks generations against its allocation records and the per-UID highest generation, before any side effect; the storage layer records generations but does not check them. The per-UID highest generation is kept in `node.json` in the node's state directory (tmpfs) with the boot ID, so it survives daemon restarts but not reboots (which also lose the overlays).
- **Finished allocations.** `ReleaseAttachment` and `DropLocalSnapshot` for an allocation that is finished (or unknown) succeed, since `Release` already removed everything; other commands for finished allocations are rejected.
- **Hot unplug.** `DetachVolume` OK means Cloud Hypervisor removed the device (`vm.remove-device`) and no Cloud Hypervisor process on the node still has the slot disk open (checked in `/proc/<pid>/fd`; the node daemon runs with hostPID). Timeout: `FAILED` with `ERROR_CODE_HOTPLUG`. When the VM exits (or the slot is lost) every attachment becomes `DETACHED`.
- **Receives.** `PrepareReceive` content carries LV tags `blip.receiving` and `blip.generation` until `Seal`, so it is reported with kind `SNAPSHOT` and `sealed: false`. The node keeps no other state for it. `Seal` requires the content to be unexported.
- **Unknown thins.** Thin IDs in the compute pool with no device and no journal entry are logged. The node rescans every 2.5 minutes and deletes an ID that stayed unknown in every scan for 10 minutes (`UnknownThinGrace`); the delete checks the device and journal again under the storage lock. Thin creation is journaled before the thin exists and the journal survives daemon restarts, so a thin of a running operation is never unknown. No command is involved.
- **Devices.** Slot disk N is `/dev/blip/disks/N` in the slot container, backed by `blip_<node>_slot_<slot>_d<N>` (error target when unused). The guest sees `/dev/disk/by-id/virtio-<name>`. The metadata disk has serial `blip-meta`, so no volume may use that name.
- **Results** are cached by operation ID for one hour. Failures are cached too: the controller retries a failed command with a new operation ID. `ListState` is not cached. Results are queued while the session is down and sent after the next `Welcome`; none is dropped. The state is not queued: `Hello` carries a fresh one.
