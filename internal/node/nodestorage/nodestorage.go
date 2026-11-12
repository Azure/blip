// Package nodestorage defines the storage interface of the node daemon
// (internal/node). The real implementation is node.RealStorage; the
// in-memory one for tests is nodetest.FakeStorage. It is a package of its
// own so the fake does not import the node package.
package nodestorage

import (
	"context"
	"fmt"
	"time"

	pb "github.com/example/blip/internal/proto/nodepb"
	"github.com/example/blip/internal/storage/extent"
)

// Storage is the storage data path used by the node daemon. The real
// implementation is node.RealStorage, built on internal/storage;
// nodetest.FakeStorage is the in-memory one for tests.
//
// Every method must be idempotent: it checks LVs and devices before it
// acts, so a repeated call after a crash or a resent command is safe.
// Errors may be wrapped with CodeError to give the controller an
// ErrorCode. Generation checks are done by the node; implementations may
// check again (the real one does, per attachment).
type Storage interface {
	// SetHostKey installs this node's host NQN and PSK, received in
	// Welcome. It is called on every connect, before any command.
	SetHostKey(ctx context.Context, hostNQN string, psk []byte) error

	// Storage node commands.
	Export(ctx context.Context, c *pb.Export) (*pb.ExportResult, error)
	Unexport(ctx context.Context, c *pb.Unexport) error
	Seal(ctx context.Context, c *pb.Seal) error
	DeleteContent(ctx context.Context, c *pb.DeleteContent) error
	CreateContent(ctx context.Context, c *pb.CreateContent) error
	Import(ctx context.Context, c *pb.Import) (*pb.ImportResult, error)
	Clone(ctx context.Context, c *pb.Clone) (*pb.CopyResult, error)
	Repair(ctx context.Context, c *pb.Repair) (*pb.CopyResult, error)
	Scrub(ctx context.Context, c *pb.Scrub) (*pb.ScrubResult, error)
	// PrepareReceive creates the unsealed content that receives a
	// captured snapshot (see storage.StorageNode.PrepareReceive).
	PrepareReceive(ctx context.Context, r ReceiveSpec) error

	// SlotDisks makes sure the disks of a slot exist (1-sector error
	// targets when unused) and returns their host device paths, disk 0
	// first. The device plugin exposes disk N as /dev/blip/disks/N.
	SlotDisks(ctx context.Context, slotID string) ([]string, error)
	// ResetSlot points every disk of the slot back at the error target.
	ResetSlot(ctx context.Context, slotID string) error
	// ResetSlotDisk points disk n of the slot back at the error target.
	ResetSlotDisk(ctx context.Context, slotID string, n int) error

	// AttachVolume connects the origin paths, builds the origin and the
	// overlay, points the slot disk at the overlay and creates the host
	// link. It returns the host link path.
	AttachVolume(ctx context.Context, v VolumeSpec) (string, error)
	// CaptureLocal takes local snapshot seq of a set of overlays of one
	// allocation in one suspend window.
	CaptureLocal(ctx context.Context, allocID string, attIDs []string, seq int64) (*CaptureResult, error)
	// DropLocalSnapshot deletes local snapshot seq of an attachment. A
	// missing snapshot is not an error.
	DropLocalSnapshot(ctx context.Context, allocID, attID string, seq int64) error
	// SnapshotSource returns the ranges of local snapshot seq that
	// WriteSnapshot writes: the delta against baseSeq, or the whole
	// device with full or when the delta is impossible.
	SnapshotSource(ctx context.Context, allocID, attID string, seq, baseSeq int64, full bool) (*SnapshotSource, error)
	// WriteSnapshot writes ranges of local snapshot seq to every target
	// (a read-write export for this node) in parallel. It returns one
	// error (or nil) per target, or an error when it could not start.
	WriteSnapshot(ctx context.Context, allocID, attID string, seq int64, ranges []extent.Range, targets []*pb.Path) ([]error, error)
	// ReleaseAttachment removes the overlay, its local snapshots, the
	// origin, the slot disk mapping and the host link.
	ReleaseAttachment(ctx context.Context, allocID, attID string) error
	// ReleaseAllocation releases every attachment of an allocation,
	// whatever their generation.
	ReleaseAllocation(ctx context.Context, allocID string) error

	// State reports contents, exports and compute allocations as found
	// on the host. Used for Hello and ListState.
	State(ctx context.Context) (*StorageState, error)
	// DeleteThins deletes unknown compute pool thin IDs. It checks again,
	// under the storage lock, that each ID has no device and no journal
	// entry, and refuses those that do.
	DeleteThins(ctx context.Context, ids []uint32) error
	// Capacity reports pool usage. Either part may be nil.
	Capacity(ctx context.Context) (*pb.StorageCapacity, *pb.ComputeCapacity, error)
}

// VolumeSpec is the input of Storage.AttachVolume.
type VolumeSpec struct {
	AllocationID string
	AttachmentID string
	Generation   int64
	UID          string
	ContentID    string
	SizeBytes    int64
	SlotID       string
	SlotDisk     int
	Paths        []*pb.Path
}

// ReceiveSpec is the input of Storage.PrepareReceive.
type ReceiveSpec struct {
	ContentID     string
	BaseContentID string
	SizeBytes     int64
	Owner         string
	Generation    int64
}

// CaptureResult is the outcome of Storage.CaptureLocal.
type CaptureResult struct {
	// Suspended is how long the overlays were suspended; 0 if the
	// snapshots existed already.
	Suspended time.Duration
}

// SnapshotSource is the input of WriteSnapshot.
type SnapshotSource struct {
	Size   int64
	Ranges []extent.Range
	// Full is true when the ranges cover the whole device because the
	// delta was impossible (or full was asked for).
	Full bool
	// FullResend is true when the delta was impossible.
	FullResend bool
}

// StorageState is what Storage finds on the host.
type StorageState struct {
	Contents []*pb.ContentInfo
	// Compute allocations by allocation ID, then attachment ID.
	Allocations map[string]map[string]AttachmentStorage
	// UnknownThins are compute pool thin IDs nobody accounts for: no
	// device and no journal entry. The node deletes them with
	// DeleteThins once they stayed unknown for Config.UnknownThinGrace.
	UnknownThins []uint32
}

// AttachmentStorage is the device state of one attachment.
type AttachmentStorage struct {
	UID        string
	Generation int64
	ContentID  string
	Overlay    bool // the overlay device exists
	SlotDisk   int  // -1 if no slot disk maps it
	Snaps      []LocalSnapStorage
}

// LocalSnapStorage is one local snapshot as found on the host.
type LocalSnapStorage struct {
	Seq   int64
	State pb.LocalSnapshotState
}

// CodeError attaches an ErrorCode to an error.
type CodeError struct {
	Code pb.ErrorCode
	Err  error
}

func (e *CodeError) Error() string { return e.Err.Error() }
func (e *CodeError) Unwrap() error { return e.Err }

// WithCode wraps err with code.
func WithCode(code pb.ErrorCode, err error) error {
	if err == nil {
		return nil
	}
	return &CodeError{Code: code, Err: err}
}

// Codef is WithCode with a formatted message.
func Codef(code pb.ErrorCode, format string, args ...any) error {
	return &CodeError{Code: code, Err: fmt.Errorf(format, args...)}
}
