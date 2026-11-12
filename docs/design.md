# Blip v1 design

## 0. Summary

Blip runs microVMs on Kubernetes.

- A **blip** boots a guest OS from its root volume in a microVM, with one or more volumes attached. The guest runs its own init.
- A **blipvol** is a long-lived block device with a bounded history of snapshots (`status.snapshots[]`). The newest Ready snapshot is its current content.
- Every attachment of a blipvol gets a private writable copy of the current content on the compute node. Writes reach the blipvol only as new snapshots.
- A blipvol gets a new snapshot when it is released (shutdown, on by default), at a fixed interval while attached (`snapshotPolicy.interval`), when another blipvol is derived from it while it is attached, and when a failed attempt is rescheduled. There are no ad-hoc snapshot requests; derive a new blipvol instead.

Blip uses two namespaced CRDs for workloads and volumes (plus BlipPool for slots), one controller, one node daemon, and pools of pre-booted VMs. Guest disk I/O goes only through kernel block devices. All storage traffic between nodes, including snapshot saves, is NVMe/TCP with TLS 1.3.

Related docs:
- `docs/controller.md`: how the controller implements this design, with all flags and reasons.
- `internal/proto/nodepb/README.md`: controller-node message flows and node behavior.
- `docs/e2e.md`: the end-to-end test on kind.

---

## 1. Goals and non-goals

**Goals**
- Fast start from warm pools.
- Simple API that works with `kubectl wait`.
- Long-lived volumes with a bounded snapshot history, copy-on-write attachments, and safe deletion of any volume or snapshot that is not in use.
- Exclusive use: at most one blip at a time is attached to a given blipvol.
- Snapshots on shutdown and at an interval, per volume. New volumes derived from any snapshot, or from a live capture of an attached volume.
- Only changed data crosses the network.
- Per-namespace RBAC and per-SKU quotas.
- KVM and MSHV support.
- Storage traffic is always encrypted on the wire. Disks are trusted to be encrypted at rest by the platform.

**Non-goals for v1**
- Live migration, memory or CPU snapshots.
- Starting a new blip from the memory of a running one. A new blip can start from a crash-consistent copy of a running blip's volume (`kubectl blip derive`, see [kubectl-plugin.md](kubectl-plugin.md)).
- Consistency across volumes. Each volume is snapshotted on its own.
- Code inside the guest OS. Blip only adds a small boot stub in the initramfs (`blip-boot`). The guest image owns mounts, network, services and shutdown.
- Formatting or mounting data volumes. Blip only mounts the root volume.
- Exec, console and file copy. (Port forwarding of `spec.ports` is supported.)
- Inbound network access to guests from the pod network.
- Disk resize, byte-based storage quotas, content-hash dedup.
- A standalone CLI. Use `kubectl`. The optional `kubectl blip` plugin only adds helpers on top of the API.
- A durable local disk cache on compute nodes.
- A time limit for Pending blips. Users delete blips they no longer want.
- Automatic replacement of storage nodes; an operator edits the config.
- Our own encryption at rest.

---

## 2. Components

| Component | Runs as | Job |
|---|---|---|
| `blipd controller` | Deployment, 1 replica, `Recreate` strategy, plus a Lease | All decisions: allocation, quota, claims, snapshots, compaction, GC. |
| `blipd node` | Privileged DaemonSet, `hostNetwork`, `hostPID` | Device plugin, local and replica storage, NVMe/TCP TLS, snapshot writes, guest connections |
| `tlshd` | Sidecar in the node DaemonSet | Kernel TLS handshakes for NVMe/TCP |
| `blipd slot` | Entrypoint of each slot pod (in tenant namespaces) | Gives the pod IP to the guest (DHCP), runs Cloud Hypervisor, watches the guest boot state, enforces the deadline, classifies the VM exit |
| `blip-boot` | `/init` of the initramfs, PID 1 until it execs the guest init | Waits for an allocation on the metadata disk, mounts the root volume, execs `spec.init` |
| `blip-meta` | Optional helper that guest images can include | Reads the metadata disk: identity, service account credentials, exit code |

**Images**
1. `blipd`: the `blipd` binary plus lvm2, thin-provisioning-tools, e2fsprogs and ktls-utils (`tlshd`). Used by the controller and the node DaemonSet.
2. `blip-slot`: `blipd`, a pinned Cloud Hypervisor build, the guest kernel, and an initramfs that holds only `blip-boot`.
3. Guest images (BlipVols) are built by users. `images/blip-ubuntu` is an example; `images/blip-e2e` is the e2e test image.

**Code layout** (one Go module, `github.com/example/blip`)
```text
cmd/blipd  cmd/blip-boot  cmd/blip-meta
internal/api        CRD types, names, defaults
internal/controller reconcile, allocate, quota, claims, snapshots, compaction, GC
internal/node       device plugin, storage orchestration, hot-plug, guest relay
internal/storage    LVM, dm, nvmet, NVMe host, TLS keys, capture, extent copy (no Kubernetes code)
internal/slot       Cloud Hypervisor supervisor, guest network and DHCP server, exit classification
internal/meta       metadata disk format, reader and writer (host and guest)
internal/boot       blip-boot (initramfs stub)
internal/proto      message types and gRPC services (controller-node)
internal/testing    fakenode: the node daemon in-process with fake storage and slots, for controller tests
config/             CRDs, policies, RBAC, kustomize manifests
hack/               kind cluster setup, image builds, e2e tests
```

---

## 3. API

API group `blip.example.com/v1alpha1`. `example.com` is a placeholder domain.

### 3.1 Blip

```yaml
apiVersion: blip.example.com/v1alpha1
kind: Blip
metadata: {name: worker-7, namespace: team-a}
spec:
  sku: default                 # default "default"
  init: ["/sbin/init"]         # default ["/sbin/init"]; argv that blip-boot execs as PID 1; first item an absolute path
  rootMountOptions: noatime    # optional; ext4 mount options of the root volume (as for mount -o)
  maxTTLSeconds: 3600          # default 3600, max 604800
  ttlSecondsAfterFinished: 300 # default 300; mutable
  reschedule:                  # optional; immutable; set: retry failed attempts in a new VM (section 4.5)
    limit: 5                   # optional; unset: no limit other than the deadline
    initialBackoffSeconds: 10  # default 10; doubles per reschedule
    maxBackoffSeconds: 300     # default 300; at least initialBackoffSeconds
    salvageTimeout: 5m         # default 5m; how long to wait for an unreachable node to return
    nodeLoss: Fence            # Fence (default) | Abandon; what happens after salvageTimeout
  serviceAccountName: default  # default "default"; its token is given to the guest (section 13)
  ports: [{name: ssh, port: 22}]  # guest vsock ports reachable with kubectl port-forward to the slot pod (section 6.4)
  rootVolume: root             # required, names an entry in volumes; immutable
  volumes:                     # 1 to 16 entries, keyed by name
  - name: root                 # DNS label, at most 20 characters (virtio serial), not blip-meta
    blipVolRef: {name: worker-root}        # same namespace
  - name: workspace
    blipVolRef: {name: workspace}
status:
  phase: Running               # Pending | Running | Saving | Succeeded | Failed (display only)
  allocation: {id: …, node: …, podName: …, podUID: …}
  volumes:
  - name: workspace
    blipVolRef: {name: workspace, uid: …}
    attachmentID: 3f9c0a…      # 16 hex characters, new for every attach
    generation: 7              # claim generation of the BlipVol
    slotDisk: 1
    devicePath: /dev/disk/by-id/virtio-workspace  # path in the guest
    state: Attached            # Reserving | Attaching | Attached | Detaching
                               # | Capturing | Publishing | Released | Failed
    message: …
    snapshot: 40               # BlipVol snapshot sequence this attachment started from
    resumedFrom: {sequence: 40, captureTime: …}   # set when this attempt started from an older
                               # snapshot than where the previous attempt stopped (section 4.5)
    shutdownSnapshot:          # the snapshot taken when the attachment is released
      sequence: 42
      reason: Completed        # Detach | Completed | Failed | DeadlineExceeded | Deleted | Reschedule
      state: Ready             # Pending | Ready | Skipped | Unavailable | Failed
      message: ""
  startTime: …                 # slot claimed by the first attempt
  deadline: …                  # startTime + maxTTLSeconds; kept across attempts
  completionTime: …
  stopRequestedTime: …         # first graceful Kill; the graceful timeout counts from here
  restartCount: 0              # guest reboots in the current attempt
  rescheduleCount: 0           # attempts that ended and were given a new VM
  nextScheduleTime: …          # end of the reschedule backoff
  lastFailure: {reason: NodeLost, message: …, time: …}  # why the last rescheduled attempt ended
  lastExitCode: 0              # exit code from the guest (`blip-meta exit`, or the code of an exiting init)
  podIP: 10.244.1.5            # the slot pod IP, owned by the guest
  message: "the guest powered off with exit code 3"
  conditions: […]
```

Snapshot settings live on the BlipVol (section 3.2), not on the Blip.

**Conditions**

| Type | True means | Reasons |
|---|---|---|
| `Scheduled` | A slot is claimed (stays True) | True: `Claimed`. False: `QuotaExceeded`, `NoCapacity`, `UnknownSKU`, `ServiceAccountNotFound`, `WaitingForBlipVol`, `StorageFull`, `VolumeInUse`, `TooManyVolumes`, `RescheduleBackoff` |
| `VolumesReady` | Every initial volume is attached | False: `Attaching`, `Rescheduled` |
| `Started` | `blip-boot` started the guest init at least once (stays True) | True: `Started`. False: `Rescheduled` |
| `SnapshotsBehind` | An interval capture of a volume was skipped or failed | `CaptureSkipped` and others |
| `Rescheduling` | A failed attempt is being released, or the Blip waits for its next attempt | True: the failure reason, `NodeUnreachable` (in the salvage window), then `RescheduleBackoff` or `ResumedFromOlderSnapshot` (section 4.5). False: `Rescheduled` or `ResumedFromOlderSnapshot` (new slot claimed), `NodeUnreachable` (`nodeLoss: Fence`, waiting after the salvage window) or the final failure reason |
| `Finished` | Done, every shutdown snapshot settled and every claim released (stays True) | False: `Releasing`, `Rescheduled`, `NodeUnreachable` |
| `Complete` | The guest powered off cleanly with no error exit code (stays True) | `Succeeded` |
| `Failed` | The run did not succeed (stays True) | `Error`, `GuestPanic`, `InitExited`, `BootFailed`, `TTLExceeded`, `Cancelled`, `NodeLost`, `SlotLost`, `HypervisorExited`, `InputBlipVolFailed`, `StartFailed`, `AttachFailed` |

- Every condition starts False with reason `Pending`.
- At most one of `Complete` and `Failed` is True, and one of them is True once `Finished` is True.
- The workload result is separate from snapshot results. A blip whose run failed can still have Ready shutdown snapshots.
- A rescheduled attempt never sets `Failed`. `Failed` is set only when no new attempt is made.
- Printer columns: `NAME SKU PHASE RESTARTS RESCHEDULES ROOT AGE`.

### 3.2 BlipVol

```yaml
apiVersion: blip.example.com/v1alpha1
kind: BlipVol
metadata:
  generateName: workspace-
  namespace: team-a
  labels:                                   # set by the controller
    blip.example.com/lineage: "<uid of the root of this lineage>"
spec:
  # Source: at most one of image / parent. Neither means a zero-filled raw device.
  # image, parent and size are immutable.
  image: {reference: ghcr.io/acme/ws:1.0, pullSecretRef: {name: registry}}
  parent: {namespace: shared, name: base, snapshot: 12}   # derive; namespace optional;
                                            # snapshot optional (section 7.10)
  size: 20Gi                                # default 20Gi; not allowed with parent
  snapshotPolicy:                           # optional; mutable
    skipShutdown: false                     # default false: a snapshot is taken on release
    interval: 1h                            # optional; at least 5m
    limit: 24                               # 1 to 100, default 24: Ready snapshots kept
status:
  phase: Ready                  # Pending | Importing | Ready | Failed; Ready once sequence 1 is Ready
  size: 20Gi
  imageDigest: sha256:…
  rootContentID: …              # content at the root of the lineage, used for replica rebuild
  current: 41                   # sequence of the newest Ready snapshot; 0 = none yet
  lastSequence: 42              # highest sequence ever allocated
  origin:                       # set when derived; pins the source snapshot (section 7.11)
    {namespace: shared, name: base, uid: …, snapshot: 12, contentID: <base uid>-12}
  snapshots:                    # oldest first, keyed by sequence
  - sequence: 41
    contentID: <vol uid>-41
    reason: Interval            # Initial | Shutdown | Interval | Derive | Reschedule
    state: Ready                # Pending | Ready | Failed
    captureTime: …
    storageGroup: sg-1
    base: <vol uid>-40          # content this was sent against; "" for a full copy
    replicas: [{node: s1, state: Sealed}, …]
    writer: {blipName: worker-7, blipUID: …, attachmentID: …, generation: 3}   # absent for Initial
    result: {exitCode: 0, restartCount: 0}   # for snapshots taken at the end of a run
    message: ""
  claim:                        # the one attachment that uses this volume
    {blipName: worker-7, blipUID: …, attachmentID: …, allocationID: …, node: c3, generation: 7, since: …,
     snapshot: 40,              # sequence the attachment started from
     baseline: 41}              # newest Ready snapshot of this attachment; 0 until the first
  claimGeneration: 7            # never decreases, survives claim release
  holds:                        # reasons the data cannot be deleted
  - {kind: Attachment, holder: {kind: Blip, namespace: team-a, name: worker-7, uid: …}, since: …}
  - {kind: Clone, holder: {kind: BlipVol, …}, snapshot: 12}   # snapshot being cloned
  conditions: [Ready, Failed, RetentionLimitExceeded]
```

- **Content.** An image import builds an ext4 filesystem from the image, because containers need one. An empty BlipVol is a zero-filled raw device with no filesystem. Workloads format data volumes themselves.
- **Snapshots.** Snapshots are entries in `status.snapshots`, not Kubernetes objects. Sequence 1 is the initial content (reason `Initial`: the import, the empty device, or the derive). Sequences only grow and are never reused. Every attach starts from `status.current`. Snapshots are taken on shutdown, at the interval, for a derive and for a reschedule (section 7.9). Compaction keeps the newest `limit` Ready snapshots (section 7.11).
- **Content IDs.** Every snapshot has its own data on the storage nodes, with content ID `<BlipVol UID>-<sequence>`. The ID is fixed before any data is written, so retries never make a second copy.
- **Lineage.** A BlipVol from an image or `size` starts a lineage (its own UID). A derived BlipVol copies the lineage of its parent. The label is informational only.
- `Ready=True` reason: `Ready`. `Ready=False` reasons: `Importing`, `NoReadySnapshot`, `ScrubMismatch`, `DeletionBlocked`, and for a derive `ParentNotFound`, `ParentNotReady`, `SnapshotNotYetTaken`, `SnapshotNotFound`, `WaitingForCapture`, `SourceUnreachable` (section 7.10).
- `Failed=True` reasons: `ImportFailed`, `ImagePullFailed`, `CloneFailed`, `ParentDeleted`, `NoReadySnapshot`, `ScrubMismatch`, and terminal derive reasons such as `SnapshotNotFound`.
- `RetentionLimitExceeded=True` (reason `Pinned` or `Held`) when compaction keeps more than `limit` Ready snapshots (section 7.11); otherwise False with `WithinLimit`.
- Printer columns: `NAME PHASE CURRENT SIZE AGE`.

### 3.3 Namespace settings

```yaml
metadata:
  annotations:
    quota.blip.example.com/default: "10"   # running blips for SKU "default"
```

Unset values fall back to the controller flag `--default-quota=10`. Tenants with `edit` cannot change namespace annotations.

### 3.4 Validation

**CRD CEL rules**
- Blip spec is immutable except `volumes` and `ttlSecondsAfterFinished`.
- `rootVolume` names an entry in `volumes`. The root entry cannot be removed.
- A volume entry (`name`, `blipVolRef`) is immutable. To change it, remove the entry and add it again. Other entries can be added and removed at any time (live attach and detach).
- `volumes` has 1 to 16 entries with unique DNS-label names.
- `maxTTLSeconds` is between 1 and 604800. `init` has 1 to 32 items and its first item is an absolute path. `reschedule.maxBackoffSeconds` is at least `initialBackoffSeconds`.
- Volume names are at most 20 characters and `blip-meta` is reserved.
- Blip names are at most 57 characters.
- BlipVol `image`, `parent` and `size` are immutable each. `snapshotPolicy` can change at any time. A BlipVol sets at most one of `image` and `parent`. `size` is not allowed with `parent`.
- `snapshotPolicy.interval` is at least `5m`, compared as a duration. `snapshotPolicy.limit` is 1 to 100. `parent.snapshot` is at least 1.

**ValidatingAdmissionPolicies**
1. Only the controller service account may add, change or remove labels starting with `blip.example.com/` on BlipVols.
2. A cross-namespace `parent` requires `get` on that BlipVol, checked with the CEL `authorizer`. A Blip can only refer to BlipVols in its own namespace.
3. In every namespace, the garbage collector may not delete pods labeled `blip.example.com/slot=assigned`.
4. Only the controller may change `blip.example.com/` labels and annotations of a slot pod, so tenants who can edit pods cannot free, steal or relabel slots, or add the slot label to their own pods.
5. Outside `blip-system` the controller may only create and delete token binding Secrets.
6. Only the controller may create pods with the `blip.example.com/slot` label, and it may only create free slot pods: `sku` and `pool` labels, one controller owner reference to a BlipPool, one container, no init or ephemeral containers, no volumes, no host namespaces, not privileged, no privilege escalation, no added capability except `NET_ADMIN`, and `automountServiceAccountToken: false`.

### 3.5 RBAC

ClusterRoles are aggregated into the built-in roles:

| Role | Rules | Aggregated into |
|---|---|---|
| `blip-view` | get, list, watch on `blips`, `blipvols` and `blippools` | `view` |
| `blip-edit` | create, delete, patch, update on `blips` and `blipvols`; get, list on `pods`; get, create on `pods/portforward` | `edit`, `admin` |

- Stopping a blip uses the normal `delete` permission.
- Deriving a volume is creating a BlipVol with `spec.parent`. Changing `snapshotPolicy` is a patch of the BlipVol.
- Status subresources are written only by the controller. Tenants get no access to `blip-system`.
- `kubectl port-forward pod/<status.allocation.podName> 2222:22` reaches guest vsock port 22 if it is in `spec.ports` (section 6.4).
- Native `ResourceQuota` with `count/blipvols.blip.example.com` can cap the number of blipvols users create. Snapshots are not objects and do not count. `snapshotPolicy.limit` bounds them per volume.

---

## 4. Blip lifecycle

### 4.1 Flow

1. **Resolve volumes.** Get every BlipVol named in `spec.volumes`.
   - Missing or not Ready yet: wait with `WaitingForBlipVol`.
   - Failed: `Failed` / `InputBlipVolFailed`.
2. **Check placement and quota** (sections 5 and 6). Every volume needs 2 reachable sealed replicas. The node must have `disks-per-slot >= len(volumes)`, otherwise `TooManyVolumes`.
3. **Claim every volume** (section 5.2), in UID order. If one is refused, release all and wait with `VolumeInUse`. A waiting blip holds no claims.
4. **Claim a slot** (section 6.3). The VM is already booted and `blip-boot` waits (section 8).
5. **Attach** each volume (section 7.6). When all are attached, set `VolumesReady`.
6. **Start.** The node writes the allocation to the metadata disk. `blip-boot` mounts the root volume and execs `spec.init`. When the guest reports this, the controller sets `Started`.
7. **Run.** Volumes can be attached and detached live (section 4.3). Interval and derive snapshots are taken (section 7.9).
8. **End** (table below), then **release** every volume (section 4.4). With `spec.reschedule`, a retryable failure instead releases the attempt and goes back to step 1 after a backoff (section 4.5).
9. **Clean up.** Delete the slot pod, release the quota, set `Finished` and `completionTime`. Delete the Blip `ttlSecondsAfterFinished` seconds later.

### 4.2 How a run ends

The run ends when the VM exits. `blipd slot` classifies the exit once (section 8): it writes the Blip reason and message, which the node and the controller pass on unchanged:

| Event | Result |
|---|---|
| Guest powers off, no exit code or exit code 0 | `Complete` / `Succeeded`. Release reason `Completed`. |
| Guest powers off after `blip-meta exit N` with N not 0 | `Failed` / `Error`. Release reason `Failed`. |
| Guest kernel panics (pvpanic or `Kernel panic` on the serial console) | `Failed` / `GuestPanic`. `blipd slot` kills the VM. |
| Guest init exits (`Attempted to kill init!`) | `Failed` / `InitExited`, with the exit code |
| `blip-boot` fails (root volume not found within 5 minutes, root mount fails, init not found) | `Failed` / `BootFailed`. The message has the stub reason, for example `RootMountFailed`. |
| Guest reboots | Not an end. The VM keeps running, `restartCount` goes up and the guest boots again from the same disks. |
| Blip deleted | Deadline reached | Graceful stop, then kill. `Failed` / `TTLExceeded`. Release reason `DeadlineExceeded`. |
| Cloud Hypervisor crashes or is killed for another reason | `Failed` / `HypervisorExited` |
| Slot container restarts, or the pod is deleted | `Failed` / `SlotLost` |
| Node unreachable for 2 minutes | `Failed` / `NodeLost`. Claims stay until the node returns or is fenced. |
| Assign or start call fails | `Failed` / `StartFailed` |

A guest that powers off ends the run, so the guest decides when the job is done. To report failure, run `blip-meta exit <code>` before poweroff. The exit code is kept in the guest area of the metadata disk (section 8).

With `spec.reschedule`, the failures `Error`, `GuestPanic`, `InitExited`, `BootFailed`, `NodeLost`, `SlotLost`, `HypervisorExited`, `StartFailed` and `AttachFailed` start a new attempt instead (section 4.5).

**Rules**
- A graceful stop presses the ACPI power button of the VM (`vm.power-button`). The guest has `--graceful-timeout` (30s) to power off, counted from `status.stopRequestedTime` so a controller restart does not restart or skip it. Then the hypervisor is killed and the volumes are only crash-consistent.
- Only the node daemon detects a lost slot: the slot pod is gone for 10s, the slot is given to another pod, or the Cloud Hypervisor API socket is unreachable for 30s without an `exit.json` (for example after a slot container restart, since a restarted `blipd slot` refuses an assigned slot). The node reports it in its state and the run fails with `SlotLost`. An unreachable node is `NodeLost` instead.
- The deadline runs from the first slot claim. It covers boot, reboots and reschedules, and never resets. Release can run past it.
- The deadline is enforced in two places, in a fixed order. At the deadline the controller starts a graceful stop (power button, then kill after `--graceful-timeout`). `blipd slot` kills Cloud Hypervisor itself at the deadline plus `AssignSlot.kill_grace` (the graceful timeout plus 10s), so the graceful stop finishes first and the slot kill is a backstop when the controller cannot reach the node. The node daemon does not enforce the deadline.
- A failed run never skips a shutdown snapshot.
- **Deleting a Blip** is how users stop it. Its finalizer `blip.example.com/cleanup` stays until every shutdown snapshot is settled and every claim is released. Its snapshots are in the `status.snapshots` of its BlipVols.

### 4.3 Live attach and detach

Driven by the difference between `spec.volumes` and `status.volumes`, only after `Started`. An attach or detach of a volume waits only while a capture of that same volume is in flight (section 7.9).

- **Attach.** Add an entry. The volume goes `Reserving` (new attachment ID, lowest free slot disk), then is claimed, `Attaching`, `Attached`. The attachment starts from the BlipVol's `status.current`. The guest sees a new disk at `/dev/disk/by-id/virtio-<name>`, and the volume list on the metadata disk is updated. If no slot disk is free, the message says `TooManyVolumes`. If the claim is refused, the message says `VolumeInUse` and it is retried. A failed attach ends in `Failed`; remove and re-add the entry to retry.
- **Detach.** Remove the entry. The volume goes `Detaching`. The detach is forced: the guest is not asked, and the disk is removed even if it is mounted. Unmount it in the guest first. The root volume cannot be detached. Once the hypervisor has let go, the shutdown snapshot (reason `Detach`) is taken unless `skipShutdown`, then the claim is released and the state is `Released`. Released entries stay in status until the name is added again.

### 4.4 Release

Runs for every volume when the blip ends, and for one volume on detach. Phase `Saving` until done.

1. The VM is stopped (or the volume is unplugged).
2. A capture of the volume in flight finishes first.
3. Each attachment that reached `Attached` gets a shutdown snapshot, unless its BlipVol has `snapshotPolicy.skipShutdown: true`: a final local capture, written to the storage group, sealed and appended to the BlipVol's `status.snapshots` (section 7.9). With `skipShutdown`, `shutdownSnapshot.state` is `Skipped` and writes after the newest snapshot are discarded.
4. Remove the attachment on the node, unexport its origin, drop its hold and release its claim. The next attach of the BlipVol starts from the new `status.current`.
5. If the node is unreachable and not fenced, wait with `Finished=False/NodeUnreachable`. A Node object that no longer exists counts as fenced.

A release for a reschedule (section 4.5) is the same, except: the snapshot (reason `Reschedule`) is always taken, also with `skipShutdown`, because the next attempt continues the same run; and the Blip does not finish.

### 4.5 Rescheduling

`spec.reschedule` gives a failed workload more attempts, each in a new VM, possibly on another node. Retrying inside one VM is up to the guest (for example systemd restarts units, or the guest reboots). The new VM boots the root volume with a new MAC, so the guest image must follow the rules in section 8.

1. **Decide.** On a retryable failure (section 4.2) the Blip is rescheduled if the limit is not reached and `now + backoff` is before the deadline. Otherwise it fails as usual. The deadline, `Cancelled` and bad inputs are never retried.
2. **Release** the attempt (section 4.4) with `Rescheduling=True`. Each attached volume is saved as a `Reschedule` snapshot where possible (table below).
3. **Wait.** Allocation cleared, phase `Pending`, `Scheduled=False/RescheduleBackoff`, `rescheduleCount + 1`, `nextScheduleTime = now + min(initial * 2^(count-1), max)`.
4. **Next attempt.** Scheduling (section 4.1) starts again. Each volume attaches its BlipVol's newest Ready snapshot, as for any attach. There is no separate carry state. `startTime` and `deadline` are kept. If the deadline passes before a slot is claimed: `Failed` / `TTLExceeded`. Deleting the Blip while it waits: `Failed` / `Cancelled`.

**Saving the volumes of a failed attempt**, for each attached volume:

| Situation | Action | `shutdownSnapshot.state` |
|---|---|---|
| Node connected | Stop the VM, capture, save, append with reason `Reschedule` | `Ready` |
| Capture or save fails after `--transfer-attempts` or `--save-timeout` | Give up; the next attempt starts from the newest Ready snapshot | `Failed` |
| Node reconnects without the attachment (rebooted, overlay gone) | Abandon at once | `Unavailable` |
| Node fenced (out-of-service taint), or the Node object is gone | Abandon at once | `Unavailable` |
| Node unreachable, not known to be gone | Wait up to `reschedule.salvageTimeout` (default 5m, from the end of the attempt) for it to return. If it returns with the overlay, stop the VM (generation-checked) and capture | `Ready` |
| Salvage window expires | `nodeLoss: Fence` (default): keep waiting until the node returns or is fenced, with `Rescheduling=False/NodeUnreachable`. `nodeLoss: Abandon`: release the claim (any `Pending` capture is `Failed`), ask replicas (best-effort) to stop exporting the attached snapshot to the lost node, and reschedule from the newest Ready snapshot without fencing. The next claim gets a higher generation | `Unavailable` (Abandon) |

- **Lost writes.** When a volume's `Reschedule` snapshot is not `Ready`, the next attempt starts from an older snapshot. `status.volumes[].resumedFrom` records the sequence and capture time of the snapshot the next attempt actually claimed. During the backoff `Rescheduling` has reason `ResumedFromOlderSnapshot` with the lost time window per volume in the message. Claiming the next slot sets `Rescheduling=False`, with reason `ResumedFromOlderSnapshot` (naming the volumes, claimed snapshots and lost window) if any volume has `resumedFrom`, else `Rescheduled`. On sudden node loss, `snapshotPolicy.interval` bounds how much is lost.
- **Stale overlays.** If a node comes back holding the allocation of an abandoned attempt, `Welcome.finished_allocation_ids` lists it, so the node releases it: it kills the stale VM and tears down the overlays. The overlay is discarded, never merged. Its commands carry the old generation and are refused. The controller emits a `Warning` event `OverlayDiscarded` on the Blip, naming the allocation and attachments.

---

## 5. Quota, claims and deletion

### 5.1 Running quota

- Per namespace and SKU, counts Blips that have an `allocation` and are not `Finished`.
- The limit comes from the namespace annotation, or the controller default.
- Counts come from the controller's cache plus an in-memory "assumed" set for claims not yet visible in the cache, as the kube-scheduler does.

### 5.2 Exclusive claims

A claim (`BlipVol.status.claim`) gives one attachment of one Blip exclusive use of a BlipVol.

- **Taking a claim** is one status update with a resourceVersion precondition. It sets `claim` with `generation = claimGeneration + 1`, bumps `claimGeneration` and adds an `Attachment` hold.
- It is refused if the BlipVol is being deleted, is not Ready, or is claimed by another attachment. Setting `deletionTimestamp` also changes the resourceVersion, so a claim and a deletion cannot both win.
- **Releasing a claim** happens only when:
  - the node confirmed the volume is detached or the VM is stopped, and the overlay is gone; or
  - the node is fenced: it has the taint `node.kubernetes.io/out-of-service`, or its Node object is gone; or
  - a reschedule abandons the claim with `nodeLoss: Abandon` (section 4.5). The next claim gets a higher generation, so the old node can no longer change anything.
- A lost heartbeat or lease never releases a claim.
- **Fencing by generation.** Every node command that touches an attachment carries its attachment ID and generation. A node rejects commands with a lower generation than it has seen for that volume (`STALE_GENERATION`). The node daemon does this check, once, before any side effect; the storage layer records generations but does not check them. `PrepareReceive` and `WriteSnapshot` carry the generation too. So a node that comes back after its claim moved cannot change anything; its overlay is discarded (section 4.5).

### 5.3 Holds and the deletion barrier

`status.holds` lists reasons a BlipVol's data must stay:

| Kind | On | Until |
|---|---|---|
| `Attachment` | A claimed BlipVol (its snapshot `claim.snapshot` is the read-only origin of the overlay) | The claim is released |
| `Clone` | The source of a derive in progress; `snapshot` names the source snapshot | The derived BlipVol is Ready, Failed or deleted |

Holds and the claim also protect single snapshots from compaction (section 7.11): `claim.snapshot`, `claim.baseline`, the snapshot of a `Clone` hold and the base of a `Pending` capture are never compacted.

The finalizer `blip.example.com/storage` deletes backing data only when the BlipVol has no claim, no holds and no own operation in flight. Otherwise it sets `Ready` with reason `DeletionBlocked` and waits. This applies to every deleter: users and GC. Holds whose holder is gone are dropped.

Derived BlipVols never block deletion of their source. Each thin snapshot has its own complete block map, so any snapshot or source volume can be deleted. A derived BlipVol's `status.origin` only pins the source snapshot against compaction.

### 5.4 Who deletes blipvols and snapshots

Only operators create and edit BlipPools.

Users delete the BlipVols they create, including derived ones. Snapshots are deleted by compaction (section 7.11) or with their BlipVol. To keep a snapshot after compaction would delete it, derive a BlipVol from it (`spec.parent.snapshot`).

---

## 6. Namespaces and slots

### 6.1 Slot pools

Each namespace is its own pool. A Blip only ever gets a slot pod in its own namespace, so the guest, the slot pod and the Blip share one namespace (and its RBAC, quotas and NetworkPolicies). Operators create one BlipPool per SKU in each namespace. The kustomize component `config/components/slots` has a BlipPool `default` and the NetworkPolicy `blip-slots`:

```yaml
apiVersion: blip.example.com/v1alpha1
kind: BlipPool
metadata: {name: default}
spec:
  sku: default          # default "default"; immutable
  cpus: 2               # guest vCPUs
  memory: 2Gi           # guest memory; at least 256Mi, whole MiB
  hypervisor: kvm       # kvm | mshv; unset: any hypervisor node
  nodeSelector: {}      # merged with blip.example.com/hypervisor: <hypervisor>
  tolerations: []
  minFree: 2            # default 1
  maxFree: 20           # at least minFree
  maxSlots: 50          # optional cap on free + booting + assigned; at least maxFree
  demandWindow: 5m      # default 5m
  scaleDownDelay: 10m   # default 10m
```

`kubectl get blippools` shows `SKU CPUS MEMORY FREE ASSIGNED DESIRED READY`.

**Slot pods.** The controller builds the pods; operators never write a pod template. Each pod is named `<pool>-<random>`, has the labels `blip.example.com/sku`, `blip.example.com/slot=free`, `blip.example.com/pool` and `blip.example.com/template-hash`, and is owned by the BlipPool. It has one container `slot` running `--slot-image` with `args: [slot]`, `VM_CPUS` and `VM_MEMORY` from the pool, `NET_ADMIN`, the `RuntimeDefault` seccomp profile, no service account token, no volumes, and the readiness probe `blipd slot probe`. Resources follow from the pool and controller flags:

| Resource | Formula | 2 vCPU, 2Gi | 1 vCPU, 512Mi |
|---|---|---|---|
| CPU request | `cpus / --slot-cpu-overcommit` (4) | 500m | 250m |
| CPU limit | `cpus` | 2 | 1 |
| Memory request | `memory / --slot-memory-overcommit` (1.5), rounded up to MiB, `+ --slot-vmm-overhead` (256Mi) | 1622Mi | 598Mi |
| Memory limit | `memory + --slot-vmm-overhead` | 2304Mi | 768Mi |
| `blip.example.com/hypervisor` | 1 | 1 | 1 |

The VMM overhead is not oversubscribed.

**Scaling.** The pool keeps a buffer of free slots, whatever the number in use:
- `free` counts Ready, unclaimed slot pods of the pool; `booting` counts unclaimed ones that are not Ready yet; `assigned` counts claimed pods with the pool label.
- Demand is the number of Blips of the SKU in the namespace scheduled in the last `demandWindow`. `desiredFree` is `minFree + demand`, at most `maxFree`. The part above `minFree` is also limited by the namespace's free quota.
- The pool targets `desiredFree` free and booting slots, plus one for each Blip waiting with `NoCapacity`, but never more than `maxSlots - assigned`.
- It scales up at once. It scales down only after the target has been lower for `scaleDownDelay`, deleting unscheduled pods first, then pods that are not Ready, then pods on the nodes with the most free slots of the pool. It never deletes an assigned pod.

**Rollout.** The template hash covers the whole pod spec, so a change to `cpus`, `memory`, placement, `--slot-image` or the ratio flags gives a new hash. The controller creates pods with the new hash, and deletes free pods with the old hash as the new ones become Ready. Assigned pods keep running.

**Status.** The `Ready` condition is `True` when at least `minFree` free pods have the current hash. Otherwise its reason is:
- `Scaling`: slots are booting;
- `CreateFailed`: pod creation failed (the message has the error);
- `DuplicateSKU`: an older pool in the namespace (by creation time, then name) has the same SKU. This pool creates no pods and deletes its free ones.

**SKUs.** A slot pod's SKU is its `blip.example.com/sku` label.
- No BlipPool for the SKU in the Blip's namespace: `UnknownSKU`.
- No free slot pod: `NoCapacity`. The pool controller watches Blips and adds slots.
- The controller prefers free pods with the pool's current template hash, and falls back to older ones.

**Discovery.** The controller watches pods in all namespaces, restricted to those with the `blip.example.com/slot` label. It keys slot pods by namespace and name.

### 6.2 Device plugin (inside `blipd node`)

- **Capacity.** It advertises `blip.example.com/hypervisor`, set by `slots` in the node config.
- **Allocate.** For each slot device ID it returns:
  - **Devices:**
    - `/dev/kvm` or `/dev/mshv`, whichever the node config names (never both);
    - `/dev/net/tun`;
    - `/dev/blip/disks/0` to `/dev/blip/disks/N-1`, where N is `--disks-per-slot` (default 8). Each is a per-slot device-mapper device `blip_<node>_slot_<slot>_d<n>`. It starts as a 1-sector `error` target and is later pointed at an overlay. Device permissions are fixed when the container starts, so the slot container is never privileged.
  - **Mount:** `/run/blip/slots/<id>`, mounted at `/run/blip` in the pod. It holds the Cloud Hypervisor API socket, the vsock socket, the metadata disk `meta.img`, `assignment.json`, `network.json`, `resolv.conf`, the serial log, the Cloud Hypervisor event file `events.json`, the `ready`, `assigned` and `kill` files, `exit.json`, and `volumes/<uid>` links to slot disks.
- **Pod mapping.** The node daemon maps slot ID to pod with the kubelet PodResources API.
- **Cleanup.** It removes slot devices and directories whose pods are gone.

### 6.3 Claim (controller)

0. **Service account.** The Blip's `spec.serviceAccountName` (default `default`) must exist in its namespace; otherwise it waits with `ServiceAccountNotFound`.
1. **Pick a node.** Choose a Ready pod in the Blip's namespace that is free, not being deleted, of the right SKU, on a node with enough disks per slot. Score its node:
   1. locality: 100 if the root volume's storage group has a member there, +1 per data volume group with a member there;
   2. free capacity;
   3. lower load.
   Nodes under memory pressure are skipped.
2. **Claim the pod with one patch.** The patch carries a `resourceVersion` precondition. It:
   - sets `slot=assigned`;
   - removes the BlipPool owner reference (the `pool` label stays), so deleting the pool never deletes a running Blip's pod;
   - adds the labels `blip.example.com/namespace` and `blip.example.com/name`, and annotations with the Blip UID and allocation ID.
   The pool then creates a new free pod (section 6.1).
3. **Record `status.allocation` and `startTime` on the Blip.**
4. **Pod readiness is the only slot readiness signal.** If the node refuses the slot anyway (`AssignSlot` fails), the run fails with `StartFailed`. Claimed pods never return to `free`. A free slot pod that becomes Ready wakes the Blips waiting for a slot of its SKU.

### 6.4 `blipd slot`

1. Give the pod's network identity to the guest and start the DHCP server (section 9). Then drop all capabilities, including `NET_ADMIN`.
2. Create an empty metadata disk `meta.img` (256 KiB, section 8).
3. Start Cloud Hypervisor with:
   - the kernel, the initramfs (`blip-boot`) and the command line `console=ttyS0 loglevel=4 panic=0`;
   - CPU and memory from the environment variables;
   - one disk at boot: the metadata disk, serial `blip-meta`. Volumes are hot-plugged later;
   - the TAP device for networking, with the MAC of the pod's `eth0`;
   - hybrid vsock at `/run/blip/vsock.sock`;
   - the API socket at `/run/blip/ch.sock`;
   - serial output to a file. `blipd slot` copies it to its own stdout, so the guest console is in the slot container log;
   - `--pvpanic` and `--event-monitor` (`events.json`), used to classify the exit;
   - virtio-balloon with free page reporting.
   - At startup it checks from the open files of Cloud Hypervisor that it uses the expected device.
4. **Readiness.** `blipd slot` watches `meta.img` (inotify, plus a slow poll). When `blip-boot` writes `WAITING` and the slot is not assigned, it writes `/run/blip/ready`. The readiness probe checks that file. The node daemon removes it on assignment. Neither the node daemon nor the controller reads it.
5. **Assignment.** The node daemon writes `assignment.json`, which holds the kill time (deadline plus `kill_grace`), and creates the `assigned` marker. From then on:
   - `blipd slot` listens on `127.0.0.1:<port>` (and `[::1]`) in the pod for each port of `spec.ports`. It proxies each connection over hybrid vsock (`CONNECT <port>`) to the same port number on the guest's vsock. `kubectl port-forward` to the slot pod therefore reaches guest services that listen on `AF_VSOCK`.
   - At the kill time, `blipd slot` kills Cloud Hypervisor (exit reason `TTLExceeded`). It also kills it when the node daemon creates the `kill` file.
   - If the container starts and the `assigned` marker exists, it exits with an error and does not boot.
6. **Exit.** When Cloud Hypervisor exits, `blipd slot` writes `exit.json` in the slot directory (section 8) and exits with Cloud Hypervisor's exit status.

**Memory oversubscription** (1.5x) is a scheduling policy only.
- Free page reporting returns guest memory the guest isn't using.
- Under node memory pressure, the node daemon stops accepting claims.
- A run that is evicted fails with `SlotLost`.

---

## 7. Storage

### 7.1 Layout

**Storage nodes**
- Labeled `blip.example.com/storage=true`.
- Each has an LVM VG (default name `blip`) with thin pool `pool`, created by the operator with a 64KiB chunk size. The VG name is set in the node config.
- Each content is a thin LV named `c-<contentID>`, with tags for kind, `sealed`, and owner. Each BlipVol snapshot is one content, with content ID `<BlipVol UID>-<sequence>`.
- Exports use the kernel NVMe/TCP target (`nvmet` via configfs) with TLS required. The node daemon rebuilds the exports after a reboot, from the LVs and controller requests.

**Storage groups**
- Groups are 3 nodes, listed in the `blip-storage` ConfigMap:
  ```yaml
  groups: [{name: sg-1, nodes: [s1, s2, s3]}]
  ```
- New roots go to the least full group.
- Snapshots and derived volumes stay in their base's group, because thin snapshots only work within one pool.

**Compute nodes**
- A raw dm-thin pool on a local disk, with a 64KiB block size and `ignore_discard`.
- The pool is wiped and recreated on each boot. Device-mapper state does not survive a reboot, so if the pool device exists it is from this boot and is reused; otherwise the disk is wiped. The first 1MiB of the disk holds a header with the boot ID. Local data is never durable.
- Every live thin device has a named device-mapper device, so a restarted daemon can rebuild its state by scanning them. Names (all prefixed `blip_<node>_`):
  - `mp_<alloc>_<att>`: read-only origin multipath;
  - `ov_<thinID>_<alloc>_<att>`: writable overlay;
  - `ls_<thinID>_<alloc>_<att>_<seq>`: read-only local snapshot;
  - `slot_<slot>_d<n>`: slot disk.
- **Compute journal.** A boot-scoped intent journal at `/run/blip-node/compute/journal.json` (tmpfs, same lifetime as the pool) is the one store of attachment storage state: per attachment its UID, generation, content, slot disk and replica exports (the path health loop connects them again after a daemon restart), and every thin ID, recorded before it is created or deleted. It is written atomically (temp file, fsync, rename). The node daemon keeps only allocation records (`allocs/<id>.json`) and `node.json` (finished allocations and the highest generation per BlipVol UID) in its own tmpfs state directory. The next ID is above every ID in the journal, in device-mapper and in pool metadata. Unknown thin IDs (in pool metadata, with no device and no journal entry) are logged; the node deletes one only after it stayed unknown in consecutive scans for 10 minutes (the orphan age), and the delete checks again under the storage lock. The first-seen times are in memory, so a daemon restart starts the grace again.

**Data path for an attached volume**
```text
guest virtio-blk → slot disk (dm linear) → overlay (local thin device)
    unmapped reads → external origin: the sealed content of snapshot claim.snapshot over NVMe/TCP + TLS
                     (dm-multipath over replicas, read-only)
    writes → copy-on-write into the local pool (64KiB blocks)
```

**Naming rule.** Every device-mapper device, subsystem and VG name that Blip creates includes the node name. Several nodes can then share one kernel, as in a kind cluster. nvmet port names must be numbers, so the port number is a hash of the node name and listen address.

### 7.2 Exports

- **Read-only export of sealed content.**
  - Each replica exports its copy under its own subsystem NQN `nqn.2026-01.com.example.blip:<node>:<lvname>`.
  - The compute node connects to every replica and builds one read-only `multipath` device-mapper device over the paths, with the `round-robin` selector, `queue_mode bio` (NVMe namespace heads are bio-based) and no `queue_if_no_path`. This is safe because the content is sealed and identical on every replica. No `multipathd` is involved; the dm uuid prefix is `BLIP-`, so a host `multipathd` ignores it.
  - Without `multipathd`, a failed path stays failed. While a volume is attached, the node daemon reconnects lost replicas, reloads the table and reinstates paths whose controller is live again.
  - nvmet has no read-only namespace. "Read-only" is enforced by the compute node: the multipath device is read-only and the storage node refuses a read-write export while a read-only one exists.
  - Namespace UUID and NGUID are derived from the subsystem NQN, so a host can reconnect after a re-export.
- **Read-write export.**
  - One subsystem per replica, with a distinct NQN.
  - Used only for imports, full copies and repair, which the controller orchestrates.
- **Access and timeouts.**
  - Every export allows only the requesting node's host NQN `nqn.2026-01.com.example.blip:host:<node>`.
  - `ctrl_loss_tmo` is 60s, so a lost storage path turns into an I/O error instead of a hang. `fast_io_fail_tmo` is 5s, so multipath moves to another path quickly.
  - Storage traffic stays on the host network. Guests are blocked from it (section 9).

### 7.3 Encryption on the wire (NVMe/TCP TLS)

- Every nvmet port is created with `addr_tsas=tls1.3` and `addr_treq=required`. A plain TCP port is never opened.
- Every host connection uses the `tls` option with an explicit key. If TLS setup fails, the operation fails. There is no fallback to plain TCP.
- **Keys.**
  - The controller keeps a 32-byte cluster key in Secret `blip-nvme-psk` in `blip-system`. It creates the Secret if it is missing.
  - The PSK for a host is `HMAC-SHA256(clusterKey, hostNQN)`.
  - A node gets its own PSK when it connects to the controller. A storage node gets the PSK of each host it exports to, inside the `Export` command. Nodes never see the cluster key.
  - Each node inserts keys of type `psk` into the kernel `.nvme` keyring, with the identity `NVMe0R01 <hostNQN> <subsystemNQN>` (a configured PSK with SHA-256), for each (host NQN, subsystem NQN) pair. The host passes the key with `tls_key=`. Target keys add the suffix ` target` (the kernel matches by prefix), so on a shared kernel each side removes only its own keys. Keys are removed when the export or connection goes away.
  - Each node also uses a host ID derived from its host NQN.
- **Handshake.** `tlshd` runs as a sidecar in the node DaemonSet, in the host network namespace, and serves both the target and host side of the handshake. Its config has `keyrings=.nvme`, so target lookups find the keys. Handshakes go to the `tlshd` of the socket's network namespace; reconnect sockets are made in the initial one.
- **Limit.** Kernel 7.0 does not bind the TLS identity to the host NQN in the Connect command. TLS proves that the peer holds a PSK the storage node accepts, not which node it is (see `docs/spikes/storage.md`). This also holds for snapshot saves (section 7.8).
- Snapshot saves use the same NVMe/TCP exports (section 7.8). The controller-node gRPC link is also TLS (section 11). So all traffic between nodes is encrypted. Data at rest relies on platform disk encryption.

### 7.4 Content operations on storage nodes

1. **Thin snapshot on replicas.** O(1). Uses `lvcreate -s`, activated with `-K`.
2. **Read-only multipath export.**
3. **Extent writer** (imports, full copies, repair).
   - Writes a list of block ranges to each replica's read-write export, using direct I/O.
   - Flushes, checks success, then tags the LV `sealed`.
   - Needs at least 2 replicas sealed to succeed.
   - A replica that misses the write is filled in later by repair.
4. **Prepare receive.** For a snapshot save: a thin snapshot of the base content on this replica, or a blank thin LV of the volume size when there is no base. Unsealed. The controller then exports it read-write to the compute node (section 7.8).

### 7.5 Creating roots

| Source | Steps |
|---|---|
| Image | 1. On one group member, pull the image with go-containerregistry, using credentials the controller passes in. Extract the layers and apply whiteouts. 2. Create the LV and run `mkfs.ext4 -d rootfs` (fixed options). 3. Copy the mapped ranges (`thin_dump`) to the other replicas with the extent writer. 4. Record the image digest. |
| Empty | Create zero-filled thin LVs on each replica. No filesystem. |
| Derive | `Clone` hold on the parent naming the source snapshot. Thin snapshot of that snapshot's content on each replica. O(1) and in the same group. If the parent's group is at 80% or more, a full copy instead (section 7.13). See section 7.10. |

The result of each is sequence 1 of the BlipVol, reason `Initial`.

### 7.6 Attaching a volume

1. The controller exports the sealed content of the snapshot the attachment starts from (`claim.snapshot`, the BlipVol's `status.current` at claim time) read-only on its replicas, for the compute node.
2. The compute node connects to the replicas, builds the origin multipath device, and creates the overlay: a local thin device with the origin as external origin.
3. It points slot disk N at the overlay, creates the link `<slotDir>/volumes/<uid>` to `/dev/blip/disks/N`, and the host link `/dev/blip/volumes/<uid>` to the overlay.
4. It hot-plugs `/run/blip/volumes/<uid>` with Cloud Hypervisor `vm.add-disk` (id `blip-<attachmentID>`, serial = volume name, `direct=on`, raw, `sparse=off`). Hot-plug is idempotent by ID. Volume names are at most 20 characters, the virtio serial limit.
5. The guest sees `/dev/disk/by-id/virtio-<name>` (udev or mdev makes the link from the serial). This is `status.volumes[].devicePath`. Once the workload has started, the node also updates the volume list on the metadata disk.

**Detach** is forced. The guest is not asked. The node calls `vm.remove-device` and polls `/proc/<pid>/fd` of Cloud Hypervisor until the slot disk is closed. Data the guest has not written yet is lost, so the guest should unmount the volume first. The root volume is never detached from a running VM. The overlay stays for the shutdown snapshot.

**Discard.** Discard is off. With `sparse=off`, Cloud Hypervisor advertises no discard. Because the local pool has `ignore_discard`, nothing below unmaps either. Cloud Hypervisor still advertises write-zeroes, without unmap, and serves it with `BLKZEROOUT`, which writes zeros. Zeroed ranges are therefore normal writes and part of the changed set.

### 7.7 Local capture

`CaptureLocal(allocation, attachments, seq)` takes a local snapshot of overlays. The controller always passes one attachment (section 7.9). `seq` is a local sequence, unique within the allocation: the BlipVol sequence times 1024, plus the attachment's slot disk.

1. Suspend the overlay. This drains and flushes in-flight I/O. The guest CPU never pauses; guest I/O to that disk just waits.
2. Create a thin snapshot.
3. Resume.
4. Activate the snapshot read-only, with the same external origin as its overlay (the kernel requires this).

**Consistency.** Blip does not freeze guest filesystems. Every live snapshot is crash-consistent: it looks like a power loss, and ext4 replays its journal on the next mount. Volumes are captured one by one, so two volumes of one Blip are not captured at the same instant. Shutdown snapshots of a VM that powered off cleanly (the normal end, or a graceful stop) have clean filesystems, because the guest unmounted them. A guest that needs application-consistent live snapshots must flush or quiesce its data itself.

The suspend budget is 2s. If it is exceeded, the overlay is resumed, the new snapshot is deleted and the capture fails with `SUSPEND_TIMEOUT`. Capture is idempotent per (allocation, seq). A partial capture is deleted and taken again.

**Delta.** `LocalDelta(new, base)` runs `thin_delta` on a pool metadata snapshot and returns the changed 64KiB blocks. With no base, it returns every block written since the origin. If the base has blocks the new snapshot lacks (should not happen with `ignore_discard`), the whole device is written.

**Local retention.** Per attachment, the node keeps the local snapshot of `claim.baseline` and the capture in flight. Before a new capture, the controller drops every other settled local snapshot of the attachment with `DropLocalSnapshot`. The controller remembers in memory which ones it dropped, so it does not send the same drop again. Pool fullness counts local snapshots.

### 7.8 Snapshot save

Snapshots go directly from the compute node to the storage replicas, over the same NVMe/TCP read-write exports that imports, full copies and repair use (validated in `docs/spikes/storage.md`).

1. **Prepare.** On each target replica of the output group the controller sends `PrepareReceive`: a thin snapshot of the base content, or a blank thin LV of the volume size when there is no base. The content is unsealed and tagged with the claim generation. Then `Export` read-write to the compute node (its host NQN and PSK, as for every export).
2. **Write.** The controller sends `WriteSnapshot` to the compute node with the export paths. The node computes `LocalDelta(new, base)` (section 7.7), connects to every target over NVMe/TCP with TLS, and writes the changed ranges from the local snapshot device to all targets in parallel with direct I/O. It flushes, disconnects and reports success per target. The command is idempotent per operation ID and fenced by the attachment generation.
3. **Seal.** The controller unexports the targets and seals the ones that were written. It needs at least 2. Otherwise it deletes the received content on all targets, keeps the previous baseline, and retries with new operation IDs and backoff, up to `--transfer-attempts` (5) or `--save-timeout` (15m). Then the snapshot entry is `Failed`.
4. **Stats.** Bytes written are reported per save and in `blip_snapshot_written_bytes_total`.

Limits of this path:
- No compression, and blocks rewritten with identical data are written again.
- No end-to-end digest. Integrity relies on NVMe/TCP with TLS and on scrub (section 7.12).
- Authorization is the export model: the storage node only accepts the compute node's host NQN, and TLS proves only that the peer holds an accepted PSK, not which node it is (section 7.3).

### 7.9 Capture loop

Each attachment has its own capture loop. There are no snapshot sets: each volume is snapshotted on its own, and there is no consistency between volumes. One capture per attachment runs at a time.

**Triggers**
- **Shutdown**: the VM stops, the volume is live-detached, or the run ends (section 4.4). Skipped with `snapshotPolicy.skipShutdown: true`.
- **Interval**: while attached, with `snapshotPolicy.interval` set. The next capture is due one interval after the attachment's newest Ready or Pending capture, or after the claim was taken. After a Failed capture it is retried `min(interval, 1m)` later. No other schedule state is stored. `--snapshot-interval-scale` (default 1) divides the interval; it is for test clusters only. A tick while a capture runs is skipped (`SnapshotsBehind=True/CaptureSkipped`).
- **Derive**: a new BlipVol derives from this one while it is attached (section 7.10). Only derives without `spec.parent.snapshot` that wait for a capture (`Ready` reason `WaitingForCapture` or `SourceUnreachable`) trigger one.
- **Reschedule**: an attempt ended with a retryable failure (section 4.5). Always taken, also with `skipShutdown`.

One capture can serve an interval tick and any number of waiting derives. Its reason is `Derive` if a derive was waiting.

**Steps** for a capture of attachment `a` of BlipVol `V`:
1. Append a `Pending` entry to `V.status.snapshots` with sequence `lastSequence + 1`, content ID `<V uid>-<seq>`, `writer` = `a` with the claim generation, `captureTime` = now, and its group and base, and bump `lastSequence`. This comes before any node command, so a capture is never lost track of. The base is the `claim.baseline` snapshot if it is Ready and was written by this attachment, else the `claim.snapshot` it started from. The output goes to the base's group. If that group is at `--storage-full-threshold` (90%), it goes to the least full other group with no base: the whole device is written.
2. `CaptureLocal` of that one overlay (section 7.7), with a fixed operation ID (`cap-<V uid>-<seq>`).
3. Save (section 7.8). `WriteSnapshot.base_seq` is the local sequence of the base if this attachment wrote it, else 0 (the attached origin).
4. Once at least 2 replicas are sealed, the entry is `Ready`. `status.current` and `claim.baseline` move to it. Older local snapshots of the attachment are dropped later (section 7.7). If the save still fails after `--transfer-attempts` (5) or `--save-timeout` (15m), the entry is `Failed`, and `current` and `baseline` do not change.

A writer owns its entry only while it holds the claim with the same generation (entries without `generation` match any). A `Pending` snapshot whose writer no longer holds the claim (claim released, taken over, or replaced by a newer claim generation) is marked `Failed` with message `the writer no longer holds the claim`, then compacted like any Failed snapshot. When an orphan claim is taken over, its `Pending` captures fail with `the claim was taken over by another attachment`.

Several writers update BlipVol status (the Blip controller appends, the BlipVol controller compacts and updates replicas). Every status write uses optimistic concurrency and retries on conflict with a fresh read.

**Shutdown snapshots.** For a release, the capture is the last one of the attachment. The Blip records it in `status.volumes[].shutdownSnapshot` (`sequence`, `reason`, `state`). The volume is `Capturing` while the snapshot is taken and saved, and `Publishing` once it is Ready. If the overlay is gone (node rebooted or fenced), the state is `Unavailable`, any `Pending` entry of the attachment is `Failed`, and the BlipVol's newest Ready snapshot is the recovery point. If the snapshot entry was marked `Failed` or deleted while being saved, the shutdown snapshot is `Failed`, not `Ready`. A clean poweroff gives clean filesystems, because the guest unmounted them.

**Data loss.** On sudden node loss, writes since the newest Ready snapshot are lost. `interval` bounds that window.

### 7.10 Derive

A derived BlipVol `D` has `spec.parent: {namespace, name: S, snapshot}`. To keep or reuse the state of a volume, derive a new one.

1. **Pick the snapshot.**
   - With `snapshot` set, use that snapshot of `S`. If it is not taken yet (above `lastSequence`), `D` waits (`SnapshotNotYetTaken`); if it is `Pending`, `D` waits (`ParentNotReady`); if it was deleted or `Failed`, `D` fails (`SnapshotNotFound`).
   - Without `snapshot`, and `S` not claimed: use the newest Ready snapshot of `S` now.
   - Without `snapshot`, and `S` claimed by a running Blip: `D` sets `status.origin.uid` and waits with `Ready=False/WaitingForCapture`. The Blip controller of `S` sees the waiting derive and captures at once (section 7.9). `D` uses the first Ready snapshot of `S` with a `captureTime` after `D`'s creation, whatever triggered it. If the claim on `S` is released first, `D` uses the newest Ready snapshot. While the node of `S` is unreachable, `D` waits with `SourceUnreachable`; pick an older snapshot with `snapshot` to avoid the wait.
   - `S` missing: `ParentNotFound`. `S` has no Ready snapshot yet, or is being deleted: `ParentNotReady`.
   - The controller finds waiting derives with field indexes on `status.origin.uid` and `spec.parent`. A change of `D` wakes the Blip holding `S`'s claim; a change of `S` wakes `D`.
2. **Clone.** A `Clone` hold on `S` names the snapshot while the clone runs. The clone is a thin snapshot of that content in the same group, O(1). If the group is at `--placement-threshold` (80%) or more, it is a full copy into the least full other group instead (section 7.13).
3. **Record.** The result is `D`'s sequence 1 (reason `Initial`). `status.origin` records `{namespace, name, uid, snapshot, contentID}` of the source. The `Clone` hold is dropped.

The capture is crash-consistent. Blip does not freeze guest filesystems; run `sync` in the guest first (`kubectl blip derive` does this inside a Blip). A cross-namespace `parent` needs `get` on the source (section 3.4).

### 7.11 Compaction

Runs per BlipVol, also when no Blip uses it, and again every 5 minutes. It keeps the newest `snapshotPolicy.limit` (default 24) Ready snapshots and deletes older Ready ones. It deletes Failed snapshots older than the newest Ready one. Of the Failed snapshots newer than every Ready one, it keeps the newest `limit`, so a volume whose captures keep failing does not grow without bound. It never deletes:
- the newest Ready snapshot;
- a `Pending` snapshot;
- a **held** snapshot: `claim.snapshot`, `claim.baseline`, the snapshot of a `Clone` hold, or the base of a `Pending` capture;
- a **pinned** snapshot: the `status.origin.snapshot` of any existing BlipVol derived from this one, in any namespace. Deleting a derived BlipVol runs compaction of its source again. The explicit `spec.parent.snapshot` of a derived BlipVol that is still provisioning is pinned too. Pins are computed after the live read of the BlipVol, and only when the cached copy has the same `resourceVersion`; otherwise compaction retries in 1s.

When it keeps more than `limit` Ready snapshots, it sets `RetentionLimitExceeded=True` with reason `Pinned` or `Held`. Pins only affect compaction: deleting the source BlipVol is not blocked by derived ones.

Deleting a snapshot first removes the entry from status (on a fresh copy, so a hold or claim taken meanwhile is seen), then runs `DeleteContent` of its content ID on each member of its group. Content left on a node that is away is removed by the orphan check.

### 7.12 Deleting content, orphans and repair

Content, replicas, repair, scrub and the orphan check work per snapshot entry. Each snapshot has content ID `<BlipVol UID>-<sequence>`, so a content ID maps back to its BlipVol and sequence.

- Deleting a BlipVol (finalizer `blip.example.com/storage`) deletes the content of every snapshot in every group, once the deletion barrier allows it (section 5.3). The finalizer is removed once every reachable replica confirms.
- Thin snapshots are independent: deleting any snapshot frees only the blocks that nothing else shares.

One loop per storage node (every `--repair-interval`, 1m) compares the LVs with the expected set: every snapshot entry of every live BlipVol in that group, including `Pending` ones that are still receiving.

| Found | Action |
|---|---|
| LV not expected, older than `--orphan-age` (10 min), no save into it running | Delete it |
| Unsealed copy of a Ready snapshot, or partial receive of a Failed snapshot | Delete it |
| Sealed content of a known snapshot, or any content of a claimed or held BlipVol | Never deleted |
| Expected sealed content missing | Rebuild from a healthy replica: snapshot a base (the snapshot's `base`, else another snapshot of the same BlipVol or with the same `rootContentID` in the group, else empty), copy `thin_delta(base, content)`, seal. Rebuild in sequence order, so sharing is preserved. |

**Scrub.** Every `--scrub-interval` (weekly), each content is hashed per 64KiB block on all replicas and compared. A minority mismatch is repaired from the majority. If no two replicas agree, the snapshot entry is marked `Failed` (message `ScrubMismatch: ...`), even if it was Ready, and `status.current` moves to the newest Ready snapshot left. The BlipVol is `Failed` (reason `ScrubMismatch`) only if no Ready snapshot is left.

**Replacing a storage node.** The operator edits `blip-storage`. The repair loop then fills the new member. While a group has only 2 healthy replicas it still works, but it is shown as degraded.

### 7.13 Capacity and group sizing

- **Group fullness** is the highest of three numbers on any member: thin data usage, thin metadata usage, LV count divided by `maxLVs`.
- **At 80% or more** (`--placement-threshold`): new roots go to other groups; volumes derived from a snapshot in this group become full copies in another group.
- **At 90% or more** (`--storage-full-threshold`): new blips whose root volume is in this group wait with `StorageFull`; new snapshots go to another group as full copies.
- Pools use `error_if_no_space`.

**Fixed rules**
- A group always has exactly 3 storage nodes. To scale, add groups. Never grow a group.
- Each storage node is set up the same way:
  - **VG:** `pvcreate --metadatasize 64m`. The 1MiB default is too small for thousands of LVs. VGs use `--setautoactivation n`.
  - **Thin pool:** 64KiB chunks, with the metadata LV at the maximum size (about 16GiB in production).
  - **`maxLVs`:** 5000 by default. This counts contents and LVs from operations in progress.
- **LVM commands** run one at a time through a single worker. State is read with one `lvs` call per reconcile.

**Full-copy derive**
1. The controller picks the least full group and creates new LVs there.
2. It copies the source snapshot's mapped ranges with the extent writer and seals the copy.
- The new BlipVol shows `Importing` until the copy is done, and gets a new `rootContentID`.

**Sizing estimate**
```text
LVs per group ≈ BlipVols × (limit + 1)   # plus pinned snapshots
groups = max( LVs / (0.8 × maxLVs), total data / (0.8 × pool size),
              peak blip starts per second / measured starts per second per group )
```

---

## 8. Guest and hypervisor

**Hypervisor**
- One pinned Cloud Hypervisor release, built with both `kvm` and `mshv`.
- The node config `hypervisor: kvm|mshv` (also the node label `blip.example.com/hypervisor`) picks the device the device plugin exposes.
- At startup, `blipd slot` checks which backend Cloud Hypervisor actually uses.
- MSHV nodes need a host that supports MSHV, with `/dev/mshv`.

**Guest kernel.** A pinned kernel from the slot image, with no modules. Everything is built in: virtio-blk, virtio-net, vsock, ext4, balloon, ACPI PCI hotplug, the ACPI power button, pvpanic and cgroup v2. Filesystems that guests make on data volumes must also be built in (the e2e test uses vfat). The kernel comes from the node, not from the root volume, so the guest image must not need its own kernel or modules.

**Metadata disk.** Each VM boots with one raw disk, `meta.img` in the slot directory (256 KiB, virtio serial `blip-meta`, `/dev/disk/by-id/virtio-blip-meta` in the guest). It is the only channel between host and guest besides the console and port forwarding. Package `internal/meta` has the format:
- Header at offset 0: magic `BLIPMETA`, version 1.
- Two host slots (at 4 KiB and 64 KiB). The node writes the older slot with a higher sequence number and a CRC, so a reader never sees a half-written record. Readers use `O_DIRECT` and take the newest valid slot.
- A guest area at 128 KiB, written by the guest with `O_DIRECT|O_DSYNC`. The host treats it as untrusted and limits its size.
- Both hold JSON. Fields are only ever added, so old `blip-meta` builds in guest images keep working.

Host data (written by the node at `StartWorkload`, then on every live attach, detach and credential rotation): `allocationID`, `identity` (Blip name, namespace, UID), `boot` (`rootSerial` = root volume name, `init`, `rootMountOptions`, `rootFSType: ext4`), `credentials` (service account token, CA, namespace, expiry), `volumes` (name and serial of each attached volume), `hostname` (the Blip name), and `network` (MAC, MTU, addresses, routes, DNS; for information only, the guest uses DHCP).

Guest data: `state` (`WAITING`, `EXEC` or `FAIL`), `reason`, `message`, `bootCount`, `exitCode`, `time`.

**`blip-boot`** (`cmd/blip-boot`, `/init` in the initramfs, a small static Go program):
1. Mount devtmpfs, `/proc` and `/sys`. Find the metadata disk by serial (wait up to 1 minute, else fail `MetaNotFound`). Increment `bootCount` and write `WAITING`.
2. Wait for the host data and a block device whose serial is `boot.rootSerial`. It listens for kernel uevents and rescans `/sys/block` every second. After the host data appears, the root disk must appear within 5 minutes, else `RootNotFound`.
3. Mount the root as ext4 at a new root with `rootMountOptions`; on error `RootMountFailed`. Move `/dev`, `/proc`, `/sys` and `/run` into the new root when it has those directories, delete the initramfs files, and `chroot` (like `switch_root`).
4. Check that `init[0]` is executable (else `InitNotFound`), write `EXEC`, and exec `init` with `PATH` and `TERM` set.
5. On any failure it writes `FAIL` with the reason and message, then powers off. The host reports `Failed` / `BootFailed`.

It does no fsck, no network setup and no other mounts. After a guest reboot, Cloud Hypervisor runs `blip-boot` again; the metadata disk and volumes are still attached, so it boots at once with a higher `bootCount`.

**`blip-meta`** (`cmd/blip-meta`) is an optional static helper for guest images. It finds the metadata disk by serial:
- `blip-meta creds --dir D [--watch]` writes the service account token, `ca.crt` and `namespace` like the kubelet (timestamped directory and an atomically swapped `..data` symlink; `token` 0600). With `--watch` it follows rotations.
- `blip-meta identity` prints the name, namespace, UID and allocation ID as JSON. `blip-meta get <field>` prints one field.
- `blip-meta exit <code>` records the workload exit code in the guest area. Run it before poweroff to report failure (section 4.2).
- `blip-meta wait` blocks until an allocation is present.

**Exit classification.** `blipd slot` follows the VM through the Cloud Hypervisor event file (`--event-monitor`), pvpanic events, the serial log, and the guest area. When Cloud Hypervisor exits it writes `exit.json` with the hypervisor exit status, `cause` (how Cloud Hypervisor ended), `reason` (the Blip reason), `message`, `guestExitCode` and `bootCount`. This is the only place an exit is classified:

| Reason | When |
|---|---|
| `Succeeded` | Cloud Hypervisor exited 0 after a guest shutdown, and the guest exit code is unset or 0 |
| `Error` | The same, with another guest exit code |
| `GuestPanic` | pvpanic event, or `Kernel panic` on the serial console. The kernel runs with `panic=0`, so it hangs and `blipd slot` kills the VM. |
| `InitExited` | A panic with `Attempted to kill init! exitcode=…`; the code becomes `guestExitCode` |
| `BootFailed` | The guest area says `FAIL` (from `blip-boot`); the message has the stub reason |
| `TTLExceeded` | `blipd slot` killed the VM at its kill time (section 6.4) |
| `HypervisorExited` | `blipd slot` killed the VM (the `kill` file or a stop), or any other exit |

`guestExitCode` is the code from `blip-meta exit` if the guest wrote one. Reboots are counted from the event file and `bootCount`. The node reads `exit.json` and reports it as the allocation's `exit` in its state; the controller copies the reason and message into the Blip (section 4.2).

**Guest image requirements.** A root BlipVol is a whole guest OS. It must:
- have an ext4 root filesystem and an init at `spec.init` (default `/sbin/init`);
- power off to end the run, and power off on the ACPI power button (graceful stop). systemd does this by default;
- run a DHCP client on its Ethernet NIC (section 9);
- listen on `AF_VSOCK` for the ports in `spec.ports` (for example a systemd socket with `ListenStream=vsock::22`);
- read credentials and identity from the metadata disk if it needs them (with `blip-meta`, or by reading the format itself).

**Portability rules.** A BlipVol can boot in any slot on any node, and its snapshots can boot in another Blip. Each boot can have a different MAC, IP, hostname, node and kernel build. So the image must:
- use DHCP, never a static IP;
- never pin the MAC: match the NIC by type or name (systemd-networkd `Type=ether`);
- refer to disks in `fstab` by `/dev/disk/by-id/virtio-<volume name>` or by filesystem UUID or LABEL, never by `/dev/vdX`, and use `nofail` for data volumes that may be detached;
- take the hostname from DHCP or the metadata disk;
- not depend on kernel modules or a kernel in the image;
- regenerate `/etc/machine-id` when the Blip changes (`images/blip-ubuntu` derives it from the Blip UID), so clones of one image do not share it;
- expect journal replay after a crash or kill, since `blip-boot` does not run fsck.

`images/blip-ubuntu` is an Ubuntu image that follows these rules with systemd, networkd, resolved, `blip-meta` units, and sshd on vsock port 22 (`docs/kubectl-plugin.md`).

---

## 9. Networking

- **The guest owns the pod IP.** At start, before the guest boots, `blipd slot`:
  1. reads the MAC, MTU, addresses and routes of the pod's `eth0`, and saves them in `network.json` in the slot directory;
  2. creates a TAP device for Cloud Hypervisor and gives the guest NIC the same MAC;
  3. adds an ingress qdisc and a tc `matchall` filter with a `mirred` redirect on `eth0` and on the TAP, so every frame goes straight between the pod's veth and the guest;
  4. adds a higher-priority tc filter on the TAP ingress that drops UDP to port 67, so the guest's DHCP requests do not leak into the pod network;
  5. removes all addresses from `eth0`, so the pod's own stack does not answer ARP or send traffic;
  6. starts a DHCP server on the TAP (a packet socket, which sees frames before tc drops them).
  There is no NAT and no IP forwarding. It works with any CNI plugin that gives the pod one `eth0`.
- **DHCP.** The server answers only the guest MAC and offers only the pod IPv4 address. Lease 24h, renewable. Options: subnet mask, router, classless static routes (121, including on-link gateway routes like those of ptp CNI plugins), DNS servers and search domains from the pod's `resolv.conf`, domain name, MTU, and hostname (the Blip name, once the node wrote it to the metadata disk). Rapid commit is supported. The server ID is the gateway (or `169.254.0.1`). The guest needs a DHCP client; with a static config it would not work on another slot.
- **Requirements.** The slot container needs `NET_ADMIN` (dropped before Cloud Hypervisor starts) and the node kernel needs `sch_ingress`, `cls_matchall`, `act_mirred`, `cls_flower` and `act_gact` (built in or loadable; `blipd node` loads them at start). Probes must not use the pod IP; the slot readiness probe is an `exec` probe. `blipd slot` itself needs no pod network: it talks to the node through files and Unix sockets in `/run/blip`.
- **Address.** `status.podIP` is the slot pod IP, which is the guest IP. DNS uses the pod's DNS servers. There is no IPv6: the guest kernel has none and the DHCP server is IPv4 only.
- **Default NetworkPolicy** for slot pods (part of `config/components/slots`, in each tenant namespace):
  - Ingress: none. It applies to the guest directly, so nothing in the cluster can open a connection to a guest. Replies to connections the guest opens are allowed. `kubectl port-forward` is not affected: it enters through the kubelet and the pod's loopback (section 6.4), and needs `pods/portforward` in the namespace.
  - Egress: allow DNS and `0.0.0.0/0`, except:
    - pod, service and node CIDRs;
    - `169.254.169.254/32`, the cloud metadata service.
  - The Kubernetes API server: guests use it with their service account token. A public API server endpoint is covered by the rule above. NetworkPolicy matches after service DNAT, so a private API server needs a rule for its endpoint addresses and port (the kind overlay allows tcp/6443 to the kind node network and the `kubernetes` Service IP).
  - Operators set these CIDRs in the install config.
- **Storage.** NVMe/TCP and node-daemon ports are therefore unreachable from guests. Exports also require host NQNs and TLS PSKs.

---

## 10. Console output

- There is no logs API; the console is the slot pod log.
- The guest serial console (`ttyS0`) goes to `serial.log` in the slot directory. `blipd slot` copies it to its own stdout, so anyone who can read pod logs in the Blip's namespace can read it with `kubectl logs <slot pod>`. It is gone when the slot pod is deleted. What appears there is up to the guest (kernel messages, init output, and anything a service writes to the console).
- `status.message` on failure says why the run failed (exit code, panic, boot failure, deadline, VM exit), not what the guest printed. For a panic it has the panic line from the console.

**Usage with `kubectl`**
```sh
kubectl create -f worker-7.yaml
kubectl wait blip/worker-7 --for=condition=Finished --timeout=2h
kubectl get blip worker-7 -o jsonpath='{.status.volumes[*].shutdownSnapshot}'
kubectl get blipvol workspace -o jsonpath='{.status.snapshots[*].sequence}'   # history
kubectl blip derive workspace --name ws-copy --wait   # new BlipVol from a snapshot (or a live capture)
kubectl patch blip worker-7 --type=json -p '[{"op":"remove","path":"/spec/volumes/2"}]'   # live detach
kubectl delete blip worker-7                 # stop; shutdown snapshots are still taken
```

---

## 11. Internal interfaces

| Link | Transport | Authentication |
|---|---|---|
| Node daemon to controller | The node dials `blip-controller.blip-system.svc:8443` over gRPC with TLS. One long-lived two-way stream carries commands, results and node states. | Controller: a self-signed CA it generates, stored in a Secret, and published in ConfigMap `blip-ca`. Node: a projected service-account token (audience `blip`). The controller checks it with TokenReview and confirms the pod runs on the node it claims. |
| Node daemon to `blipd slot` | Unix socket and files in the per-slot directory | Filesystem only |
| Node daemon to Cloud Hypervisor | Cloud Hypervisor API socket in the slot directory | Filesystem only |
| Node daemon to guest | Metadata disk `meta.img` in the slot directory (host slots written by the node, guest area read as untrusted) | None; the guest can only write its own area |
| Slot pod loopback to guest ports | Hybrid vsock socket in the slot directory, `CONNECT <port>` | `pods/portforward` on the slot pod |
| Node to node (storage data) | NVMe/TCP with TLS 1.3 | Host NQN plus PSK (section 7.3) |

**Controller to node commands:** `AssignSlot`, `Export`, `Unexport`, `AttachVolume`, `DetachVolume`, `StartWorkload`, `Kill{graceful}`, `UpdateCredentials`, `CaptureLocal`, `DropLocalSnapshot`, `PrepareReceive`, `WriteSnapshot`, `ReleaseAttachment`, `Release`, `Seal`, `DeleteContent`, `CreateContent`, `Import`, `Clone`, `Repair`, `Scrub`, `ListState`. Messages and flows: `internal/proto/nodepb` and its README.

**Rules for every command**
- It carries object UIDs and an operation ID. Attachment commands carry the attachment ID and claim generation.
- It is idempotent: the node checks LVs and devices before acting, and caches results by operation ID.
- A node rejects commands for allocations it was told are finished, and commands with a stale generation.

**Node to controller:** operation results, and the full `NodeState` (in `Hello`, and again whenever it changes). There are no separate events: the state carries per allocation the boot count (guest init started), the classified VM exit (section 8) and slot loss, plus slots, contents and capacity (including `disks_per_slot`). The node coalesces changes into one fresh state instead of queueing them, so nothing is lost when the controller is slow or away, and sends it before any later result. The controller compares each state with the previous one to react, records an exit once, and ignores states from a replaced session.

There is no protocol to the guest. The node writes the metadata disk and reads the guest area; `blipd slot` reads the event file, serial log and guest area.

The node daemon has **no Kubernetes RBAC** and never writes to the API.

---

## 12. Failure handling

| Failure | Behavior |
|---|---|
| Controller restart | Rebuilds from CRs plus the state nodes report on reconnect. Running guests keep running; deadlines are still enforced locally. Snapshot saves in progress start a new attempt. |
| Node daemon restart | Device-mapper devices, NVMe connections, configfs exports and guests survive. It rescans and reconnects. Allocation records, finished allocations and generations are kept in its tmpfs state directory; attachment storage state is in the compute journal. State files of an older version are not migrated: wipe them (or reboot the node). |
| `blipd slot` or Cloud Hypervisor dies | `SlotLost` or `HypervisorExited`. Overlays stay, so shutdown snapshots are still taken. |
| Guest panics, its init exits, or `blip-boot` fails | `GuestPanic`, `InitExited` or `BootFailed` (section 4.2); retried with `spec.reschedule` |
| Guest does not power off on the power button | Killed after `--graceful-timeout`; volumes are crash-consistent |
| Attempt fails with `spec.reschedule` | Release with `Reschedule` snapshots, backoff, new attempt from each volume's newest Ready snapshot (section 4.5) |
| Node lost | After 2 minutes: `NodeLost`. Claims and holds stay. The Blip waits with `NodeUnreachable` until the node returns or is fenced (Node object gone counts as fenced). With `spec.reschedule`, see the salvage rules in section 4.5. |
| Node returns after a reboot | Overlays are gone: shutdown snapshots are `Unavailable`, then claims are released. Each BlipVol's newest Ready snapshot is the recovery point. |
| Node fenced (`node.kubernetes.io/out-of-service`, or the Node object is gone) | Unsettled shutdown snapshots become `Unavailable`, `Pending` snapshot entries become `Failed`, holds and claims are released, the pod is deleted and the Blip finishes. Stale commands from the node are refused by generation. |
| Storage path lost | Multipath fails over after `fast_io_fail_tmo` (5s). If every path is down, the guest gets I/O errors. The node daemon reconnects for `ctrl_loss_tmo` (60s) and restores paths. |
| Storage replica down | Operations and snapshot saves continue with 2 replicas; repair fills the gap later |
| Snapshot save fails | Received content is deleted on all targets; the previous baseline is kept; retry with backoff |
| Capture over budget | Overlay resumed, local snapshot deleted, capture fails, `SnapshotsBehind` (interval) |
| Lost API response when appending a snapshot | Sequence, content ID and capture operation ID are fixed (`<uid>-<seq>`, `cap-<uid>-<seq>`), so a retry reuses them. It never creates a second copy. |
| Namespace deleted | Blips are cancelled and BlipVols deleted through their finalizers. UIDs prevent reuse. |

---

## 13. Security

- **Guest isolation** comes from the hypervisor. Cloud Hypervisor runs in an unprivileged pod:
  - no host namespaces;
  - no service-account token of its own (`automountServiceAccountToken: false`); the guest gets its Blip's token (below);
  - only `NET_ADMIN`, used to set up the TAP and tc filters and dropped before Cloud Hypervisor starts;
  - RuntimeDefault seccomp, plus Cloud Hypervisor's own seccomp.
- **Per-slot devices and directories** come from the device plugin. A slot cannot see other slots' disks.
- **Exclusive volumes.** A BlipVol's writable copy exists for at most one attachment at a time, fenced by claim generations.
- **Privileges.** Only the node daemon is privileged. The controller is unprivileged.
- **Service account credentials.** Each Blip runs as `spec.serviceAccountName`. When it starts the workload the controller mints a token with the TokenRequest API (default audiences, `--token-ttl`, default 1h). Every token is bound (`boundObjectRef`) to a per-allocation Secret `blip-token-<allocation>` in the Blip's namespace (type `blip.example.com/token-binding`, no data, labels `blip.example.com/name` and `blip.example.com/allocation`, owned by the Blip). The controller deletes this Secret when the allocation ends, which makes the API server reject the allocation's tokens at once; garbage collection removes it if the controller misses the release, and binding Secrets of earlier allocations are deleted when a new allocation starts. The token, the API server CA (from the controller's own config) and the namespace go controller → node in `StartWorkload.credentials` (gRPC with TLS) → the host slot of the metadata disk. The node keeps them in memory and on the metadata disk only. **Anything in the guest that can read the metadata disk can read the token**; by default that is root in the guest. Images that use `blip-meta creds` get the kubelet layout (timestamped directory and an atomically swapped `..data` symlink; `token` 0600) at `/run/secrets/kubernetes.io/serviceaccount`. **Rotation:** the controller re-mints at 80% of the lifetime and sends `UpdateCredentials`; the node rewrites the host slot and `blip-meta creds --watch` swaps the files. Expiry times are in controller memory; after a controller restart every running Blip gets a new token at once.
- **Metadata disk.** The guest can write only its own area. The host limits its size and treats it as untrusted: it only affects the result of the guest's own Blip.
- **Controller RBAC:**
  - CRDs and their status and finalizers;
  - pods in all namespaces (get, list, watch, update, patch, delete; the cache holds only slot pods);
  - get, list, watch service accounts, and create `serviceaccounts/token`;
  - read Namespaces and Nodes (Nodes for the fencing taint);
  - Leases;
  - TokenReview;
  - read Secrets in tenant namespaces (image pull secrets), and create, list and delete token binding Secrets (a ValidatingAdmissionPolicy limits its Secret create/delete outside `blip-system` to Secrets labeled `blip.example.com/allocation`);
  - write the `blip-ca` ConfigMap, and the `blip-nvme-psk` and CA Secrets.
- **Tenants** cannot reach guests over the network. They can read Blip status, read snapshots, derive and delete BlipVols, and (with `edit`) port-forward to the `spec.ports` of their Blips.
- **Storage traffic**, including snapshot saves, is NVMe/TCP with TLS 1.3 and per-host PSKs. Data at rest relies on platform disk encryption.

---

## 14. Defaults and config

| Setting | Default | Where |
|---|---|---|
| `ttlSecondsAfterFinished` | 300 | CRD |
| `maxTTLSeconds` | 3600 (max 604800) | CRD |
| `init` | `["/sbin/init"]` | CRD |
| Volume name | at most 20 characters, not `blip-meta` | CRD |
| Metadata disk | 256 KiB, serial `blip-meta` | slot |
| Boot stub timeouts | metadata disk 1m, root disk 5m after the allocation, rescan 1s | `blip-boot` |
| DHCP lease | 24h | slot |
| `reschedule` | off; when set: no limit, backoff 10s doubling to 300s | CRD |
| Volumes per Blip | 1 to 16, and at most `--disks-per-slot` | CRD, node flag |
| Disks per slot | 8 | node `--disks-per-slot` |
| `snapshotPolicy.interval` | at least 5m | CRD |
| `snapshotPolicy.limit` | 1 to 100, default 24 | CRD |
| `reschedule.salvageTimeout` / `nodeLoss` | 5m / `Fence` | CRD |
| BlipVol size | 20Gi | controller |
| Thin block / chunk size | 64KiB | node config |
| Capture suspend budget | 2s | node |
| Graceful stop (power button to kill) | 30s | `--graceful-timeout` |
| `ctrl_loss_tmo` / `fast_io_fail_tmo` | 60s / 5s | node config |
| `maxLVs` | 5000 per storage node | node config |
| Default SKU | 2 vCPU, 2Gi; 2 to 20 free | BlipPool `default` in `config/components/slots` |
| Pool demand window / scale-down delay | 5m / 10m | BlipPool `demandWindow`, `scaleDownDelay` |

Controller flags and their defaults are listed in `docs/controller.md` (Flags).

**Node config** is a file at `/etc/blip/node.yaml` on each node, written by the operator:
```yaml
hypervisor: kvm            # kvm | mshv
slots: 8
address: 10.0.0.5          # storage traffic address; default: node InternalIP
storage:                   # storage nodes only
  vg: blip
  maxLVs: 5000
  devices: [/dev/nvme2n1]  # PVs of the VG; LVM never looks at other disks
compute:
  device: /dev/nvme1n1     # wiped on every boot
```

**Install** uses plain kustomize manifests:
- namespace `blip-system`;
- CRDs, ValidatingAdmissionPolicies and RBAC;
- controller Deployment and Service;
- node DaemonSet with the `tlshd` sidecar;
- the `config/components/slots` component (BlipPool and NetworkPolicy) for each tenant namespace;
- the `blip-storage` ConfigMap.

**Operators prepare:**
- the VG and thin pool on storage nodes;
- a local disk for the compute pool;
- the kernel modules `nvme-tcp`, `nvmet-tcp`, `nvme-keyring`, `tls`, `dm-thin-pool` and `dm-multipath`;
- node labels and `/etc/blip/node.yaml`.

**Metrics** (Prometheus, on the controller and node daemon): see `docs/controller.md` for the controller list. They cover slots per SKU, pending reasons, quota usage, start latency, snapshot latency and results, snapshot bytes written, claims and holds, pool usage, replica health, scrub mismatches, repairs and orphans.
