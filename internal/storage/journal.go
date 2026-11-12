package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/example/blip/internal/storage/run"
)

// DefaultJournalPath is where a compute node keeps its intent journal. It
// is on tmpfs, so it lives exactly as long as the device-mapper pool.
const DefaultJournalPath = "/run/blip-node/compute/journal.json"

// thinState is the lifecycle state of a thin ID in the journal.
type thinState string

const (
	// thinCreating is recorded before create_thin/create_snap. An entry
	// still creating after a crash is incomplete and may be deleted.
	thinCreating thinState = "creating"
	// thinLive marks a thin that belongs to an attachment.
	thinLive thinState = "live"
	// thinDeleting is recorded before the device and ID are removed.
	thinDeleting thinState = "deleting"
)

// thinKind says what a thin ID is used for.
type thinKind string

const (
	kindOverlay   thinKind = "overlay"
	kindLocalSnap thinKind = "snap"
)

// thinEntry is one thin ID of the pool.
type thinEntry struct {
	State   thinState `json:"state"`
	Kind    thinKind  `json:"kind"`
	AllocID string    `json:"alloc"`
	AttID   string    `json:"att"`
	Seq     int64     `json:"seq,omitempty"`
}

// attEntry is what the compute node knows about an attachment beyond its
// device-mapper devices.
type attEntry struct {
	AllocID    string `json:"alloc"`
	AttID      string `json:"att"`
	UID        string `json:"uid"`
	Generation int64  `json:"generation"`
	ContentID  string `json:"contentID"`
	Slot       string `json:"slot,omitempty"`
	SlotDisk   int    `json:"slotDisk"` // -1: none
	Sectors    int64  `json:"sectors,omitempty"`
	// Replicas are the exports of the content from the last Attach.
	// The path health loop connects them again after a restart.
	Replicas []Remote `json:"replicas,omitempty"`
}

func attKey(allocID, attID string) string { return allocID + "/" + attID }

// journal is the boot-scoped intent journal of a compute node. Every thin
// ID is recorded before it is created in the pool and before it is
// deleted, so a restarted daemon can tell leftovers of interrupted
// operations from thin devices that belong to someone (for example local
// snapshots whose device was removed).
type journal struct {
	path string
	// stale is set when a save failed: the file and memory may differ,
	// so the next operation loads the file again.
	stale bool

	Node        string                `json:"node"`
	BootID      string                `json:"bootID"`
	Thins       map[uint32]*thinEntry `json:"thins"`
	Attachments map[string]*attEntry  `json:"attachments"`
}

func newJournal(path, node string) *journal {
	return &journal{path: path, Node: node, BootID: bootID(),
		Thins: map[uint32]*thinEntry{}, Attachments: map[string]*attEntry{}}
}

// loadJournal reads the journal. A missing journal, or one from another
// boot or node, yields an empty journal.
func loadJournal(path, node string) (*journal, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return newJournal(path, node), nil
	}
	if err != nil {
		return nil, err
	}
	j := newJournal(path, node)
	if err := json.Unmarshal(b, j); err != nil {
		return nil, fmt.Errorf("journal %s: %w", path, err)
	}
	if j.BootID != bootID() || j.Node != node {
		return newJournal(path, node), nil
	}
	if j.Thins == nil {
		j.Thins = map[uint32]*thinEntry{}
	}
	if j.Attachments == nil {
		j.Attachments = map[string]*attEntry{}
	}
	j.path = path
	return j, nil
}

// save writes the journal atomically and durably. If it fails, the
// journal is marked stale.
func (j *journal) save() error {
	err := run.Step("journal-save", []string{j.path}, j.write)
	if err != nil {
		j.stale = true
	}
	return err
}

func (j *journal) write() error {
	b, err := json.MarshalIndent(j, "", " ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(j.path), 0o700); err != nil {
		return err
	}
	tmp := j.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, j.path)
}

// maxID returns the largest thin ID in the journal.
func (j *journal) maxID() uint32 {
	var m uint32
	for id := range j.Thins {
		m = max(m, id)
	}
	return m
}
