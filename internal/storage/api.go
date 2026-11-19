// Package storage manages the node's dm-thin pool: image bases, immutable
// commits, and writable working volumes. Thin devices hold only ciphertext:
// filesystems are read and written through a dm-crypt mapping above them.
// See the README's implementation outline.
package storage

import "errors"

// KeySize is the size of the cluster disk key (AES-256-XTS).
const KeySize = 64

// Config configures a node store.
type Config struct {
	DataDir   string // /var/lib/blip
	NodeName  string // used to derive the dm name prefix
	PoolBytes int64  // size of the sparse data file; 0 = 40 GiB
	// Key is the cluster disk key: KeySize bytes for aes-xts-plain64. Every
	// node must use the same key, because volumes move between nodes as
	// ciphertext.
	Key []byte
	// ReleaseRemote releases a Remote by its ID when its Release func was lost
	// in a restart (interrupted fetch, or hydration finished after restart).
	// It must be idempotent: a crash after release but before its durable
	// acknowledgement causes the same ID to be released again.
	// Return acknowledges callback dispatch. This API cannot report remote
	// completion; asynchronous implementations own subsequent retries.
	ReleaseRemote func(remoteID string)
	// ResumeRemote resumes lease renewal for a remote working volume recovered
	// after a restart. It must return without waiting for peer discovery.
	ResumeRemote func(remoteID string)
}

// Kind is a volume kind.
type Kind string

const (
	KindImage   Kind = "image"
	KindCommit  Kind = "commit"
	KindWorking Kind = "working"
)

// Volume describes one thin volume known to the store.
type Volume struct {
	ID        string // image digest, commit ID, or attachment ID
	Kind      Kind
	StateUID  string // commits and durable working volumes
	Base      string // volume ID this was created from ("" if none)
	SizeBytes int64
	ReadOnly  bool
	Hydrating bool   // working volume still copying remote data
	Device    string // /dev/mapper path when active: plaintext for working volumes, ciphertext otherwise
	Pins      []string
	Failed    string // non-empty if the volume is unusable (e.g. remote clone lost in a restart)
	Digest    string // content digest of an immutable volume; "" until computed (see Digest)
}

// Region is a byte range, aligned to the 64 KiB pool block size.
type Region struct {
	Offset int64 `json:"offset"`
	Length int64 `json:"length"`
}

// Remote is a read-only source volume on another node, already connected
// locally (for example an NVMe/TCP namespace).
type Remote struct {
	Device    string   // local block device path of the remote volume
	SizeBytes int64    // size of the remote volume
	Base      string   // local volume ID that Regions are relative to; "" = no base
	Regions   []Region // ranges to copy; everything else comes from Base (or zeros)
	ID        string   // persisted; passed to Config.ResumeRemote/ReleaseRemote after a restart
	// Release is called exactly once when the store no longer needs Device
	// (after hydration, when the volume is deleted, or when the create or
	// fetch fails). May be nil.
	Release func()
}

// CreateCommit asks for a new commit built from local data.
// Exactly one of FromImage and FromCommit may be set; neither means an empty
// ext4 filesystem of SizeBytes.
type CreateCommit struct {
	StateUID   string
	CommitID   string
	FromImage  string // image digest; filesystem grown to SizeBytes
	FromCommit string // local commit ID (copy)
	SizeBytes  int64  // filesystem size
	StreamSize int64  // trajectory ring size; 0 = no ring
}

// CreateWorking asks for a writable (or read-only) working volume.
// Exactly one of FromImage, FromCommit, Remote must be set.
type CreateWorking struct {
	AttachmentID string
	StateUID     string // "" for ephemeral roots
	FromImage    string
	FromCommit   string // local commit
	Remote       *Remote
	SizeBytes    int64 // grow filesystem to this size if larger than the source (0 = keep)
	StreamSize   int64 // trajectory ring size; 0 = no ring
	ReadOnly     bool
}

var (
	ErrNotFound = errors.New("volume not found")
	ErrPinned   = errors.New("volume is pinned")
	ErrUnclean  = errors.New("filesystem was not cleanly unmounted")
	ErrInUse    = errors.New("volume is in use")
	// ErrConflict reports an ID held by a record this operation cannot
	// replace: another kind of volume, a deletion in progress, or a record
	// that did not finish. Unlike ErrInUse for an open device, retrying does
	// not help until that owner resolves, so callers may bound their retries.
	ErrConflict = errors.New("volume record conflict")
)
