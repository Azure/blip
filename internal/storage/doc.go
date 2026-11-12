// Package storage holds the storage operations the node daemon calls. It
// has no Kubernetes code.
//
// # Storage nodes
//
// A StorageNode owns one LVM volume group with a thin pool. Each content is
// a thin LV "c-<contentID>" with tags:
//
//	blip.kind=<content|...>       set at creation
//	blip.owner=<string>           set at creation, for example a BlipVol UID
//	                              (content IDs are <BlipVol UID>-<sequence>)
//	blip.sealed                   set by Seal; the content is then immutable
//	blip.digest=<sha256:...>      image roots only
//	blip.generation=<n>           claim generation of a received snapshot
//	blip.receiving                received content not sealed yet
//	blip.creating                 Snapshot not finished (tags copied from the parent)
//
// Operations: CreateRoot (zero-filled raw device, or ext4 from an image),
// CreateBlank (for copies and repair), Snapshot (clones and repair bases),
// PrepareReceive (destination of a captured snapshot, written by the
// compute node over a read-write export),
// Export and Unexport (NVMe/TCP with TLS required), Seal, Delete, State,
// Usage, MappedRanges, ThinDelta, Scrub, and WriteExtents (copy local
// ranges into remote read-write exports, for replication and repair).
//
// # Compute nodes
//
// A ComputeNode owns a raw dm-thin pool on a local disk. Each attachment
// of a BlipVol to an allocation has an origin (a read-only multipath
// device over the read-only exports of one sealed BlipVol snapshot) and
// an overlay (a local thin device with the origin as external origin).
// Local snapshots of overlays are read-only thin devices with the same
// external origin. Capture suspends I/O briefly and never freezes the
// guest, so snapshots are crash-consistent. Slots have DisksPerSlot
// disks, each a 1-sector error target or a linear map onto an overlay. Operations: PreparePool,
// EnsureSlot, RemoveSlot, ResetSlotDisk, Attach, CaptureLocal, LocalDelta,
// LocalSnapshotPath, WriteLocalSnapshot, DropLocalSnapshot, ReleaseAttachment, Cleanup,
// RefreshPaths, ReinstatePaths, Rescan and DeleteThins.
//
// The compute journal on tmpfs (same lifetime as the pool) holds every
// attachment (UID, generation, content, slot disk, replica exports) and
// every thin ID. Generations are recorded, not checked: the node daemon
// fences stale commands. Thin IDs are allocated through the journal: an ID is recorded before it is created or
// deleted, new IDs are above every ID in the journal, in device names and
// in the pool metadata, and only IDs the journal marks as creating or
// deleting are ever deleted on recovery. Snapshots that lost their device
// are never mistaken for garbage.
//
// # Rules
//
//   - Every operation is idempotent. Callers retry after errors.
//   - Every kernel name includes the node name (package names).
//   - Network calls (key insertion, configfs port links, NVMe connects)
//     happen in the network namespace of the calling thread. The node
//     daemon runs in the host network namespace, so this is the host one.
//   - Read-only exports are read-only because the host maps them through a
//     read-only multipath device. nvmet itself has no read-only option.
//     Export refuses a read-write export while a read-only export of the
//     same content exists (ErrInUse), which enforces the safety rule of
//     design 7.6 and keeps scrub repair away from attached origins.
//   - Device nodes are created in a private directory (Config.DevDir)
//     because containers have no udev.
package storage
