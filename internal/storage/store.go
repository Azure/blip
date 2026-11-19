package storage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/sys/unix"

	"github.com/Azure/blip/internal/stream"
)

const (
	defaultPoolBytes = 40 << 30
	metaFileBytes    = 1 << 30

	phaseCreating  = "creating"
	phaseReady     = "ready"
	phaseDetaching = "detaching" // deletion has not been durably accepted
	phaseDeleting  = "deleting"

	kindExport Kind = "export" // per-lease writable snapshot served over NVMe/TCP
)

var (
	bucketVolumes = []byte("volumes")
	bucketMeta    = []byte("meta")
	keyNextThin   = []byte("nextThin")
	keyIncarn     = []byte("incarnation")
	keyDiskKeyID  = []byte("diskKeyID")
)

// record is the persisted state of one volume. Creation, deletion, and clone
// completion checkpoint their intent before touching the kernel, so Open can
// roll back or finish them.
type record struct {
	ID         string     `json:"id"`
	Kind       Kind       `json:"kind"`
	StateUID   string     `json:"stateUID,omitempty"`
	Base       string     `json:"base,omitempty"`
	Thin       uint32     `json:"thin"`
	Size       int64      `json:"size"`
	StreamSize int64      `json:"streamSize,omitempty"`
	FSBytes    int64      `json:"fsBytes,omitempty"`
	ReadOnly   bool       `json:"readOnly,omitempty"`
	Pins       []string   `json:"pins,omitempty"`
	Phase      string     `json:"phase"`
	Layered    bool       `json:"layered,omitempty"` // top device over a separate thin device (remote working volumes)
	Clone      *cloneInfo `json:"clone,omitempty"`   // remote data still hydrating
	Failed     string     `json:"failed,omitempty"`
	Digest     string     `json:"digest,omitempty"` // content digest, computed on first use (see Digest)

	// TeardownMetaThin keeps the clone metadata thin ID of an abandoned
	// hydration. Clone is cleared when a failed delete gives up on the clone,
	// but removeAll must still free this thin ID on the retry.
	TeardownMetaThin uint32 `json:"teardownMetaThin,omitempty"`

	// PendingRemote is a durable release outbox. A release interrupted by a
	// crash is retried by ID; the peer's release operation must be idempotent.
	PendingRemote string `json:"pendingRemote,omitempty"`
	// ResumeDevice is written before suspending a snapshot origin. Recovery
	// resumes it before dropping an interrupted snapshot's creating record.
	ResumeDevice string `json:"resumeDevice,omitempty"`
	// CloneFinishing records that hydration completed before table replacement.
	// It distinguishes an interrupted swap from an unhealthy remote clone.
	CloneFinishing bool `json:"cloneFinishing,omitempty"`
}

type cloneInfo struct {
	MetaThin   uint32 `json:"metaThin"`
	MetaSize   int64  `json:"metaSize"`
	Source     string `json:"source"`
	SourceSize int64  `json:"sourceSize"`
	RemoteID   string `json:"remoteID,omitempty"`
}

// Store is a node-local volume store.
type Store struct {
	cfg    Config
	prefix string
	db     *bolt.DB
	meta   string // metadata loop device (for thin_dump/thin_delta)
	incarn string

	mu       sync.Mutex
	vols     map[string]*record
	tmpPins  map[string]int
	hydrates map[string]*hydration

	locks  keyLock
	snapMu sync.Mutex

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	devices        storageDevices
	metadataUpdate func(func(*bolt.Tx) error) error
	metadataErr    error // uncertain durability: no further effects until reopen
	cloneWait      func(context.Context, string, string, func(int64, int64)) error

	// testTeardownStep, when set, is called before every destructive step of
	// removeAll. Production leaves it nil; tests use it to inject a failed
	// teardown.
	testTeardownStep func() error

	// testDeleteLocked, when set, is called by Delete after it took the
	// volume's key lock and re-checked deletion eligibility, before it touches
	// any device. Production leaves it nil; tests use it to race a Pin against
	// that window.
	testDeleteLocked func()
}

// Open opens (creating if needed) the pool and metadata, rebuilds device
// tables, and finishes or rolls back interrupted operations.
func Open(ctx context.Context, cfg Config) (*Store, error) {
	if cfg.NodeName == "" || cfg.DataDir == "" {
		return nil, errors.New("storage: NodeName and DataDir are required")
	}
	if len(cfg.Key) != KeySize {
		return nil, fmt.Errorf("storage: the disk key must be %d bytes", KeySize)
	}
	if cfg.PoolBytes == 0 {
		cfg.PoolBytes = defaultPoolBytes
	}
	s := &Store{
		cfg:      cfg,
		prefix:   DMPrefix(cfg.NodeName),
		vols:     map[string]*record{},
		tmpPins:  map[string]int{},
		hydrates: map[string]*hydration{},
	}
	if err := os.MkdirAll(filepath.Join(cfg.DataDir, "pool"), 0o700); err != nil {
		return nil, err
	}
	db, err := bolt.Open(filepath.Join(cfg.DataDir, "storage.db"), 0o600, nil)
	if err != nil {
		return nil, err
	}
	s.db = db
	if err := s.load(); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.openPool(); err != nil {
		db.Close()
		return nil, err
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	if err := s.recover(); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// DMPrefix returns the device-mapper name prefix of a node.
func DMPrefix(node string) string {
	sum := sha256.Sum256([]byte(node))
	return "blip-" + hex.EncodeToString(sum[:4])
}

func (s *Store) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()
	return s.db.Close()
}

func (s *Store) Incarnation() string { return s.incarn }

func (s *Store) poolName() string { return s.prefix + "-pool" }

func (s *Store) load() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		vb, err := tx.CreateBucketIfNotExists(bucketVolumes)
		if err != nil {
			return err
		}
		mb, err := tx.CreateBucketIfNotExists(bucketMeta)
		if err != nil {
			return err
		}
		if v := mb.Get(keyIncarn); v != nil {
			s.incarn = string(v)
		} else {
			s.incarn = randHex(8)
			if err := mb.Put(keyIncarn, []byte(s.incarn)); err != nil {
				return err
			}
		}
		id := diskKeyID(s.cfg.Key)
		switch v := mb.Get(keyDiskKeyID); {
		case v == nil:
			if k, _ := vb.Cursor().First(); k != nil {
				return fmt.Errorf("storage: %s holds unencrypted volumes; delete it and %s to start over",
					filepath.Join(s.cfg.DataDir, "storage.db"), filepath.Join(s.cfg.DataDir, "pool"))
			}
			if err := mb.Put(keyDiskKeyID, []byte(id)); err != nil {
				return err
			}
		case string(v) != id:
			return fmt.Errorf("storage: volumes are encrypted with disk key %s, not with the configured key %s", v, id)
		}
		return vb.ForEach(func(k, v []byte) error {
			var r record
			if err := json.Unmarshal(v, &r); err != nil {
				return fmt.Errorf("volume %s: %w", k, err)
			}
			s.vols[r.ID] = &r
			return nil
		})
	})
}

func (s *Store) openPool() error {
	dataFile := filepath.Join(s.cfg.DataDir, "pool", "data")
	metaFile := filepath.Join(s.cfg.DataDir, "pool", "metadata")
	for _, f := range []struct {
		path string
		size int64
	}{{dataFile, s.cfg.PoolBytes}, {metaFile, metaFileBytes}} {
		if _, err := os.Stat(f.path); errors.Is(err, os.ErrNotExist) {
			if err := createSparse(f.path, f.size); err != nil {
				return err
			}
		}
	}
	metaDev, metaHold, err := attachLoop(metaFile)
	if err != nil {
		return fmt.Errorf("attach metadata: %w", err)
	}
	if metaHold != nil {
		defer metaHold.Close()
	}
	s.meta = metaDev
	if dmExists(s.poolName()) {
		return nil
	}
	dataDev, dataHold, err := attachLoop(dataFile)
	if err != nil {
		return fmt.Errorf("attach data: %w", err)
	}
	if dataHold != nil {
		defer dataHold.Close()
	}
	st, err := os.Stat(dataFile)
	if err != nil {
		return err
	}
	sectors := st.Size() / blockSize * blockSectors
	table := fmt.Sprintf("0 %d thin-pool %s %s %d %d", sectors, metaDev, dataDev, blockSectors, 1024)
	return dmCreate(s.poolName(), table, false)
}

func createSparse(path string, size int64) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := f.Truncate(size); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// recover rebuilds device tables and resolves unfinished operations. A
// volume that cannot be brought back is marked failed (or, for unfinished
// operations, retried at the next Open) instead of blocking the store.
func (s *Store) recover() error {
	// An interrupted snapshot may have suspended a different record's device.
	// Resume every origin before reactivating volumes or starting watchers, and
	// do not open a store that would expose a still-suspended writer as healthy.
	for _, r := range s.sorted() {
		if r.ResumeDevice != "" {
			if err := s.runOperation([]deviceEffect{{Kind: eResume, Name: r.ResumeDevice}}, nil); err != nil {
				return fmt.Errorf("recover snapshot origin %s: %w", r.ResumeDevice, err)
			}
		}
	}
	for _, r := range s.sorted() {
		unlock := s.locks.lock(r.ID)
		var err error
		if r.PendingRemote != "" {
			if err := s.releaseRemote(r); err != nil {
				logf("recover release %s: %v", r.ID, err)
			}
		}
		switch r.Phase {
		case phaseCreating:
			err = s.rollback(r)
		case phaseDeleting:
			err = s.finishDelete(r)
		case phaseDetaching:
			// Only phaseDeleting accepts deletion durably. Missing DM tables
			// say nothing about acceptance: a host reboot loses all of them.
			err = s.restoreDetached(r)
			if rerr := s.reactivate(r); rerr != nil {
				s.markFailed(r, "reactivate: "+rerr.Error())
				err = errors.Join(err, rerr)
			}
		default:
			if err = s.reactivate(r); err != nil {
				s.markFailed(r, "reactivate: "+err.Error())
			} else if r.Failed != "" && r.Clone == nil {
				s.markFailed(r, "")
			}
		}
		if err != nil {
			logf("recover %s: %v", r.ID, err)
		}
		unlock()
	}
	return nil
}

func (s *Store) sorted() []*record {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*record, 0, len(s.vols))
	for _, r := range s.vols {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// reactivate makes the devices of a ready volume exist after a restart.
// Immutable volumes are activated on demand.
func (s *Store) reactivate(r *record) error {
	if r.Kind != KindWorking && r.Kind != kindExport {
		return nil
	}
	if err := s.reactivateLower(r); err != nil {
		return err
	}
	if r.Kind == kindExport || (r.Failed != "" && r.Clone != nil) || s.deviceExists(s.plainName(r)) {
		return nil
	}
	return s.openPlain(r)
}

// reactivateLower makes the devices below the crypt device exist.
func (s *Store) reactivateLower(r *record) error {
	if !r.Layered {
		if s.deviceExists(s.thinName(r)) {
			return nil
		}
		return s.deviceCreate(s.thinName(r), thinTable(s.poolName(), r.Thin, r.Size), r.ReadOnly)
	}
	if !s.deviceExists(s.thinName(r)) {
		if err := s.deviceCreate(s.thinName(r), thinTable(s.poolName(), r.Thin, r.Size), false); err != nil {
			return err
		}
	}
	top := s.topName(r)
	if r.Clone == nil {
		if s.deviceExists(top) {
			return nil
		}
		return s.deviceCreate(top, linearTable(mapperPath(s.thinName(r)), r.Size), r.ReadOnly)
	}
	table, err := s.deviceTable(top)
	switch {
	case err != nil && r.CloneFinishing:
		// Hydration was durably complete before a host reboot discarded the
		// dm graph. The destination is local, so the remote is no longer needed
		// to recreate the top mapping and finish metadata cleanup.
		if err := s.deviceCreate(top, linearTable(mapperPath(s.thinName(r)), r.Size), r.ReadOnly); err != nil {
			return err
		}
		return s.finishClone(r)
	case err != nil:
		return s.markFailed(r, "remote clone lost after restart")
	case strings.Contains(table, " clone "):
		if r.CloneFinishing {
			return s.finishClone(r)
		}
		if r.Failed != "" {
			return nil // an unhealthy remote clone cannot be resumed
		}
		if r.Clone.RemoteID != "" && s.cfg.ResumeRemote != nil {
			s.cfg.ResumeRemote(r.Clone.RemoteID)
		}
		s.startWatch(r, nil)
		return nil
	default:
		// The swap to linear happened but was not recorded.
		return s.finishClone(r)
	}
}

func (s *Store) markFailed(r *record, msg string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.changeLocked(r, func(next *record) { next.Failed = msg })
}

// device names

func dmSafe(id string) string { return strings.ReplaceAll(id, ":", "_") }

// thinName is the dm device of the volume's own thin device.
func (s *Store) thinName(r *record) string {
	if r.Layered {
		return s.prefix + "-" + dmSafe(r.ID) + "-d"
	}
	return s.prefix + "-" + dmSafe(r.ID)
}

// topName is the device holding the volume's ciphertext.
func (s *Store) topName(r *record) string { return s.prefix + "-" + dmSafe(r.ID) }

// plainName is the crypt device over topName: the device users open.
func (s *Store) plainName(r *record) string { return s.prefix + "-" + dmSafe(r.ID) + "-p" }

func (s *Store) entryName(r *record) string {
	if r.Kind == KindWorking {
		return s.plainName(r)
	}
	return s.topName(r)
}

// openPlain creates the crypt device of an active volume.
func (s *Store) openPlain(r *record) error {
	return s.deviceCreate(s.plainName(r), cryptTable(mapperPath(s.topName(r)), r.Size, s.cfg.Key), r.ReadOnly)
}

// withPlain runs fn on a temporary crypt device over the active top device
// of r.
func (s *Store) withPlain(r *record, readOnly bool, fn func(dev string) error) error {
	name := s.plainName(r)
	if err := s.deviceCreate(name, cryptTable(mapperPath(s.topName(r)), r.Size, s.cfg.Key), readOnly); err != nil {
		return err
	}
	err := fn(mapperPath(name))
	if rerr := s.deviceRemove(name); err == nil {
		err = rerr
	}
	return err
}

// diskKeyID identifies a disk key without revealing it.
func diskKeyID(key []byte) string {
	sum := sha256.Sum256(append([]byte("blip-disk-key-id\x00"), key...))
	return hex.EncodeToString(sum[:8])
}

func (s *Store) metaName(r *record) string { return s.prefix + "-" + dmSafe(r.ID) + "-m" }

// fetchName is the temporary clone device of a replica fetch.
func (s *Store) fetchName(r *record) string { return s.prefix + "-" + dmSafe(r.ID) + "-c" }

// persistence

func copyRecord(r *record) record {
	next := *r
	next.Pins = slices.Clone(r.Pins)
	if r.Clone != nil {
		c := *r.Clone
		next.Clone = &c
	}
	return next
}

func (s *Store) update(fn func(*bolt.Tx) error) error {
	if s.metadataErr != nil {
		return s.metadataErr
	}
	var attempted int
	apply := func(tx *bolt.Tx) error {
		attempted = tx.ID()
		return fn(tx)
	}
	var err error
	if s.metadataUpdate != nil {
		err = s.metadataUpdate(apply)
	} else {
		err = s.db.Update(apply)
	}
	if err != nil && attempted != 0 {
		// A committed transaction can lose its acknowledgement. Confirm its
		// identity and durability before publishing memory or doing more I/O;
		// otherwise a stale record could undo a committed ready/release state.
		committed := false
		if rerr := s.db.View(func(tx *bolt.Tx) error {
			committed = tx.ID() == attempted
			return nil
		}); rerr == nil && committed {
			if serr := s.db.Sync(); serr == nil {
				return nil
			} else {
				s.metadataErr = errors.Join(err, serr)
				return s.metadataErr
			}
		}
	}
	return err
}

// changeLocked publishes only committed metadata. In particular a failed
// ready/delete/pin write must not change eligibility in the running process.
func (s *Store) changeLocked(r *record, change func(*record)) error {
	next := copyRecord(r)
	change(&next)
	if err := s.putLocked(&next); err != nil {
		return err
	}
	// Identity and geometry are immutable after begin. Do not rewrite those
	// fields: operations holding a source pin read them without holding mu.
	r.Pins = next.Pins
	if r.Phase != next.Phase {
		r.Phase = next.Phase
	}
	if r.Failed != next.Failed {
		r.Failed = next.Failed
	}
	if r.Digest != next.Digest {
		r.Digest = next.Digest
	}
	if (r.Clone == nil) != (next.Clone == nil) || (r.Clone != nil && next.Clone != nil && *r.Clone != *next.Clone) {
		r.Clone = next.Clone
	}
	r.TeardownMetaThin = next.TeardownMetaThin
	r.PendingRemote = next.PendingRemote
	r.ResumeDevice = next.ResumeDevice
	r.CloneFinishing = next.CloneFinishing
	return nil
}

func (s *Store) change(r *record, change func(*record)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.changeLocked(r, change)
}

func (s *Store) putLocked(r *record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return s.update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketVolumes).Put([]byte(r.ID), b)
	})
}

func (s *Store) setPhase(r *record, phase string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.changeLocked(r, func(next *record) { next.Phase = phase })
}

// restoreDetached rolls back an unaccepted delete. Publishing ready even when
// its write fails is conservative: both possible disk states (ready/detaching)
// recover as ready. In particular, a refused delete must not become pending
// cleanup or hide a live writer merely because its rollback write failed.
func (s *Store) restoreDetached(r *record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.changeLocked(r, func(next *record) { next.Phase = phaseReady })
	r.Phase = phaseReady
	return err
}

func (s *Store) drop(r *record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketVolumes).Delete([]byte(r.ID))
	}); err != nil {
		return err
	}
	delete(s.vols, r.ID)
	return nil
}

// begin records a new volume in phase creating and allocates n thin IDs.
func (s *Store) begin(r *record, n int) ([]uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.vols[r.ID]; ok {
		return nil, fmt.Errorf("%w: %s already exists", ErrInUse, r.ID)
	}
	var ids []uint32
	candidate := copyRecord(r)
	err := s.update(func(tx *bolt.Tx) error {
		if tx.Bucket(bucketVolumes).Get([]byte(r.ID)) != nil {
			return fmt.Errorf("%w: %s already exists on disk", ErrInUse, r.ID)
		}
		mb := tx.Bucket(bucketMeta)
		next := uint32(1)
		if v := mb.Get(keyNextThin); v != nil {
			next = binary.BigEndian.Uint32(v)
		}
		// Allocation wraps in the 24-bit dm-thin namespace. Both live records
		// and interrupted operations retain ownership until their durable drop.
		used := map[uint32]bool{}
		if err := tx.Bucket(bucketVolumes).ForEach(func(_, value []byte) error {
			var owner record
			if err := json.Unmarshal(value, &owner); err != nil {
				return err
			}
			used[owner.Thin], used[owner.TeardownMetaThin] = true, true
			if owner.Clone != nil {
				used[owner.Clone.MetaThin] = true
			}
			return nil
		}); err != nil {
			return err
		}
		for range n {
			found := false
			for attempts := 0; attempts < (1<<24)-1; attempts++ {
				if next == 0 || next >= 1<<24 {
					next = 1
				}
				if !used[next] {
					found = true
					break
				}
				next++
			}
			if !found {
				return errors.New("storage: thin IDs exhausted")
			}
			ids = append(ids, next)
			used[next] = true
			next++
			if next >= 1<<24 {
				next = 1
			}
		}
		if err := mb.Put(keyNextThin, binary.BigEndian.AppendUint32(nil, next)); err != nil {
			return err
		}
		candidate.Phase = phaseCreating
		if len(ids) > 0 {
			candidate.Thin = ids[0]
		}
		if candidate.Clone != nil && len(ids) > 1 {
			candidate.Clone.MetaThin = ids[1]
		}
		b, err := json.Marshal(&candidate)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketVolumes).Put([]byte(r.ID), b)
	})
	if err != nil {
		return nil, err
	}
	*r = candidate
	s.vols[r.ID] = r
	return ids, nil
}

// removeAll tears down every device and thin ID of a volume. Missing pieces
// are fine, so it is safe to repeat. A failure leaves the record in phase
// deleting: the node retries PendingDeletes until the teardown succeeds.
func (s *Store) removeAll(r *record) error {
	return s.runOperation(teardownPlan(s.layout(r), r), nil)
}

// beforeTeardown runs the test hook, if any, before one destructive step.
func (s *Store) beforeTeardown() error {
	if s.testTeardownStep != nil {
		return s.testTeardownStep()
	}
	return nil
}

func (s *Store) rollback(r *record) error {
	return s.finishDelete(r)
}

func (s *Store) finishDelete(r *record) error {
	if err := s.removeAll(r); err != nil {
		return err
	}
	if err := s.releaseRemote(r); err != nil {
		return err
	}
	return s.drop(r)
}

// releaseRemote first persists release intent, then calls the release adapter,
// then acknowledges dispatch durably. The void callback owns any asynchronous
// retries. The closure is called once per process, even if the acknowledgement
// fails. After a crash the ID is retried (at least once).
func (s *Store) releaseRemote(r *record) error {
	var release func()
	var call bool
	err := func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if r.Clone != nil && r.Clone.RemoteID != "" {
			if err := s.changeLocked(r, func(next *record) {
				next.PendingRemote = next.Clone.RemoteID
				next.Clone.RemoteID = ""
			}); err != nil {
				return err
			}
		}
		h := s.hydrates[r.ID]
		if h == nil {
			h = &hydration{}
			s.hydrates[r.ID] = h
		}
		remoteID := r.PendingRemote
		release = h.release
		if release == nil && remoteID != "" && s.cfg.ReleaseRemote != nil {
			release = func() { s.cfg.ReleaseRemote(remoteID) }
		}
		if remoteID != "" && release == nil && !h.released {
			return fmt.Errorf("storage: no release adapter for remote %s", remoteID)
		}
		call = !h.released && release != nil
		h.released = true
		return nil
	}()
	if err != nil {
		return err
	}
	if call {
		release()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.PendingRemote != "" {
		if err := s.changeLocked(r, func(next *record) { next.PendingRemote = "" }); err != nil {
			return err
		}
	}
	delete(s.hydrates, r.ID)
	return nil
}

// queries

func (s *Store) List() []Volume {
	names := s.deviceNames()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Volume
	for _, r := range s.vols {
		if r.Kind == kindExport || r.Phase != phaseReady {
			continue
		}
		out = append(out, s.volume(r, names))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// PendingDeletes returns the IDs of volumes whose deletion was durably accepted
// but did not finish. An in-flight detaching gate may still refuse deletion and
// must never be queued for automatic cleanup. Accepted deletes stay out of
// List/Get/lookup so a half-deleted volume is never used, but the node retries
// their teardown instead of leaving an invisible record that blocks the ID forever.
func (s *Store) PendingDeletes() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ids []string
	for id, r := range s.vols {
		if r.Phase == phaseDeleting {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	return ids
}

func (s *Store) Get(id string) (Volume, bool) {
	names := s.deviceNames()
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.vols[id]
	if !ok || r.Kind == kindExport || r.Phase != phaseReady {
		return Volume{}, false
	}
	return s.volume(r, names), true
}

// volume requires mu to be held.
func (s *Store) volume(r *record, names map[string]bool) Volume {
	v := Volume{
		ID:        r.ID,
		Kind:      r.Kind,
		StateUID:  r.StateUID,
		Base:      r.Base,
		SizeBytes: r.Size,
		ReadOnly:  r.ReadOnly || r.Kind != KindWorking,
		Hydrating: r.Clone != nil && r.Failed == "",
		Pins:      slices.Clone(r.Pins),
		Failed:    r.Failed,
		Digest:    r.Digest,
	}
	name := s.topName(r)
	if r.Kind == KindWorking {
		name = s.plainName(r)
	}
	if names[name] {
		v.Device = mapperPath(name)
	}
	return v
}

func (s *Store) lookup(id string) (*record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.vols[id]
	if !ok || r.Phase != phaseReady {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return r, nil
}

// FreeBytes reports usable free space: the smaller of unallocated thin-pool
// data space and the free space of the backing filesystem. Thin-pool data
// allocation alone overstates free space because the pool is a sparse file on
// the data filesystem.
func (s *Store) FreeBytes() int64 {
	thin, known := s.thinFree()
	var st unix.Statfs_t
	if err := unix.Statfs(s.cfg.DataDir, &st); err != nil {
		if !known {
			return 0
		}
		return thin
	}
	avail := int64(st.Bavail) * int64(st.Bsize)
	if avail < 0 {
		avail = 0
	}
	if !known {
		return avail
	}
	return min(thin, avail)
}

// thinFree reports unallocated thin-pool data bytes and whether the pool
// status could be read.
func (s *Store) thinFree() (int64, bool) {
	st, err := dmStatus(s.poolName())
	if err != nil {
		return 0, false
	}
	return thinFree(st)
}

// thinFree parses a dm thin-pool status line and returns its unallocated data
// bytes. It never underflows.
func thinFree(st string) (int64, bool) {
	// 0 <len> thin-pool <transaction> <meta used>/<total> <data used>/<total> ...
	f := strings.Fields(st)
	if len(f) < 6 {
		return 0, false
	}
	var used, total int64
	if _, err := fmt.Sscanf(f[5], "%d/%d", &used, &total); err != nil {
		return 0, false
	}
	free := (total - used) * blockSize
	if free < 0 {
		free = 0
	}
	return free, true
}

// Pin marks id as held by holder; pinned volumes cannot be deleted.
//
// It takes the volume's key lock, like every other operation that changes the
// volume: Delete re-checks deletability while holding that lock, so a pin
// either lands before that check (and Delete fails with ErrPinned) or waits
// until the delete has dropped the record (and then fails with ErrNotFound).
// Without this, a pin accepted between Delete's check and the teardown was
// silently dropped with the record.
func (s *Store) Pin(id, holder string) error {
	defer s.locks.lock(id)()
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.vols[id]
	if !ok || r.Phase != phaseReady {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if slices.Contains(r.Pins, holder) {
		return nil
	}
	return s.changeLocked(r, func(next *record) { next.Pins = append(next.Pins, holder) })
}

// Unpin releases a pin. It takes the volume's key lock for the same reason as
// Pin: its result must be ordered with Delete's eligibility check.
func (s *Store) Unpin(id, holder string) error {
	defer s.locks.lock(id)()
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.vols[id]
	if !ok || !slices.Contains(r.Pins, holder) {
		return nil
	}
	return s.changeLocked(r, func(next *record) {
		next.Pins = slices.DeleteFunc(next.Pins, func(h string) bool { return h == holder })
	})
}

// Activate ensures an active device for a volume and returns its path:
// the plaintext device of a working volume, or the read-only ciphertext
// device of an image or commit.
func (s *Store) Activate(id string) (string, error) {
	defer s.locks.lock(id)()
	r, err := s.lookup(id)
	if err != nil {
		return "", err
	}
	if r.Failed != "" {
		return "", errors.New(r.Failed)
	}
	switch r.Kind {
	case KindWorking:
		// A ready working volume can lose its device without losing its
		// record (for example when a snapshot observed the pool between
		// device creation and the ready phase). Recreate it instead of
		// handing out a path that does not exist.
		if err := s.reactivate(r); err != nil {
			return "", err
		}
		return mapperPath(s.plainName(r)), nil
	case kindExport:
		return mapperPath(s.topName(r)), nil
	}
	name := s.thinName(r)
	if !s.deviceExists(name) {
		if err := s.deviceCreate(name, thinTable(s.poolName(), r.Thin, r.Size), true); err != nil {
			return "", err
		}
	}
	return mapperPath(name), nil
}

// Delete removes a volume of any kind. Deleting an ID whose earlier teardown
// failed resumes it: the missing pieces are skipped, so it is safe to repeat.
func (s *Store) Delete(ctx context.Context, id string) error {
	if _, err := s.deletable(id); err != nil {
		return err
	}
	// Inspect the current watcher while holding the key lock. Another refused
	// Delete can restart it while this call waits. Never wait with that lock:
	// the watcher itself needs it to finish.
	var h *hydration
	var stopped bool
	for {
		unlock := s.locks.lock(id)
		s.mu.Lock()
		h = s.hydrates[id]
		s.mu.Unlock()
		stopped = h != nil && h.stopped != nil
		if stopped {
			select {
			case <-h.stopped:
			default:
				h.cancel()
				unlock()
				<-h.stopped
				continue
			}
		}
		defer unlock()
		break
	}
	r, err := s.deletable(id)
	if s.testDeleteLocked != nil {
		s.testDeleteLocked()
	}
	teardown := false
	if err == nil && r != nil {
		// Stage intent before removing the user-facing device. Until that gate
		// succeeds, ErrInUse must preserve a usable working volume.
		r, err = s.beginDelete(id)
		if err == nil && r != nil {
			teardown = true
			err = s.detachAndDelete(r)
		}
	}
	if err == nil {
		return nil
	}
	if r != nil && (teardown || stopped) {
		s.deleteFailed(r, h, teardown)
	}
	return err
}

func (s *Store) detachAndDelete(r *record) error {
	if r.Phase == phaseDetaching {
		err := s.deviceRemove(s.entryName(r))
		if errors.Is(err, ErrInUse) {
			return errors.Join(err, s.restoreDetached(r))
		}
		// A non-busy failure is still a deletion request. Persist acceptance
		// so ordinary device failures remain eligible for cleanup retries.
		if commitErr := s.setPhase(r, phaseDeleting); commitErr != nil {
			s.mu.Lock()
			fenced := s.metadataErr != nil
			s.mu.Unlock()
			if fenced {
				return errors.Join(err, commitErr) // uncertain acceptance requires reopen
			}
			// Acceptance was not committed. Rebuild the entry we may have
			// removed and restore visibility, so a fresh request can retry
			// instead of stranding an invisible, non-pending record.
			var entryErr error
			if r.Kind == KindWorking && !s.deviceExists(s.plainName(r)) {
				entryErr = s.openPlain(r)
			} else if r.Kind == kindExport {
				entryErr = s.reactivate(r)
			}
			rollbackErr := s.restoreDetached(r)
			if entryErr != nil {
				s.markFailed(r, "reactivate: "+entryErr.Error())
			}
			return errors.Join(err, commitErr, entryErr, rollbackErr)
		}
		if err != nil {
			return err
		}
	}
	return s.finishDelete(r)
}

// deleteFailed repairs an interrupted Delete. Delete always stops the
// hydration watcher before it touches the volume, so every error after that
// point must either restart the watcher or abandon hydration. Otherwise the
// record stays a live clone with a closed watcher: waitHydrated returns at
// once, Seal/LiveCopy/Sync/Diff report "still hydrating" forever, and the
// remote lease is never released.
func (s *Store) deleteFailed(r *record, h *hydration, teardown bool) {
	s.mu.Lock()
	live := s.vols[r.ID] == r
	phase, failed, cloning := r.Phase, r.Failed, r.Clone != nil
	s.mu.Unlock()
	if !live || !cloning {
		return
	}
	// Hydration can continue only while this is still a live, healthy clone
	// and its top device (which holds the clone table) survived the delete.
	if phase == phaseReady && failed == "" && s.deviceExists(s.topName(r)) {
		var release func()
		if h != nil {
			release = h.release
		}
		s.startWatch(r, release)
		return
	}
	if !teardown && phase == phaseReady {
		// Delete was refused before it touched anything (for example a pin
		// won the race). The volume is still live; do not turn a refused
		// delete into a pending one.
		return
	}
	// A stopped watcher does not make the remote unused: a surviving clone
	// target can still serve guest I/O. Keep its lease until that target is gone.
	if !s.deviceExists(s.topName(r)) && !s.deviceExists(s.fetchName(r)) {
		s.abandonHydration(r)
	}
}

// abandonHydration gives up on a clone whose delete failed after its top
// device was removed. Hydration cannot continue without that device, so the
// remote is released and the clone state is dropped. The record becomes a
// pending delete: invisible to readers, retried by PendingDeletes, and still
// owning its thin IDs (including the clone metadata thin in TeardownMetaThin)
// so the retry can finish the teardown.
func (s *Store) abandonHydration(r *record) {
	s.mu.Lock()
	live := s.vols[r.ID] == r
	s.mu.Unlock()
	if !live {
		return
	}
	s.mu.Lock()
	if s.vols[r.ID] != r {
		s.mu.Unlock()
		return
	}
	err := s.changeLocked(r, func(next *record) {
		if next.Clone != nil {
			if next.TeardownMetaThin == 0 {
				next.TeardownMetaThin = next.Clone.MetaThin
			}
			if next.Clone.RemoteID != "" {
				next.PendingRemote = next.Clone.RemoteID
			}
			next.Clone = nil
		}
		next.Phase = phaseDeleting
	})
	s.mu.Unlock()
	if err == nil {
		err = s.releaseRemote(r)
	}
	if err != nil {
		logf("abandon hydration of %s: %v", r.ID, err)
	}
}

// deletable returns the record of id (nil if it does not exist) or why it
// cannot be deleted.
func (s *Store) deletable(id string) (*record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deletableLocked(id)
}

// beginDelete orders temporary source holds as well as durable Pins with the
// ready -> detaching transition. source holds use mu, not the volume key lock.
func (s *Store) beginDelete(id string) (*record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.deletableLocked(id)
	if err != nil || r == nil {
		return r, err
	}
	if r.Phase != phaseReady {
		return r, nil
	}
	return r, s.changeLocked(r, func(next *record) { next.Phase = phaseDetaching })
}

func (s *Store) deletableLocked(id string) (*record, error) {
	r, ok := s.vols[id]
	if !ok {
		return nil, nil
	}
	if len(r.Pins) > 0 || s.tmpPins[id] > 0 {
		return r, fmt.Errorf("%w: %s", ErrPinned, id)
	}
	if r.Phase == phaseCreating {
		return r, fmt.Errorf("%w: %s is being created", ErrInUse, id)
	}
	for _, o := range s.vols {
		if o.Base == id && o.Clone != nil && o.Failed == "" {
			return r, fmt.Errorf("%w: %s is the base of hydrating %s", ErrInUse, id, o.ID)
		}
	}
	return r, nil
}

type keyLock struct {
	mu sync.Mutex
	m  map[string]*keyEntry
}

type keyEntry struct {
	mu sync.Mutex
	n  int
}

func (k *keyLock) lockPair(a, b string) func() {
	if a > b {
		a, b = b, a
	}
	first := k.lock(a)
	if a == b {
		return first
	}
	second := k.lock(b)
	return func() { second(); first() }
}

func (k *keyLock) lock(id string) func() {
	k.mu.Lock()
	if k.m == nil {
		k.m = map[string]*keyEntry{}
	}
	e := k.m[id]
	if e == nil {
		e = &keyEntry{}
		k.m[id] = e
	}
	e.n++
	k.mu.Unlock()
	e.mu.Lock()
	return func() {
		e.mu.Unlock()
		k.mu.Lock()
		e.n--
		if e.n == 0 {
			delete(k.m, id)
		}
		k.mu.Unlock()
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func logf(format string, args ...any) { log.Printf("storage: "+format, args...) }

// fsBytes is the filesystem size of a volume.
func (r *record) fsBytes() int64 { return r.FSBytes }

// VolumeBytes returns the total device size of a volume whose filesystem is
// fsSize bytes and whose trajectory ring is streamSize bytes. The ring sits at
// the fixed stream.Offset, after any filesystem. A zero streamSize means no
// ring: the filesystem fills the device.
func VolumeBytes(fsSize, streamSize int64) int64 {
	fsSize = roundUp(fsSize, blockSize)
	if streamSize <= 0 {
		return fsSize
	}
	return roundUp(max(fsSize, stream.Offset)+streamSize, blockSize)
}

// roundUp rounds n up to a multiple of to. It saturates at the largest
// representable block-aligned value instead of overflowing to a negative
// length; callers that accept user sizes reject those values beforehand.
func roundUp(n, to int64) int64 {
	if n <= 0 || to <= 0 {
		return n
	}
	q := n / to
	if n%to != 0 {
		q++
	}
	if q > math.MaxInt64/to {
		return (math.MaxInt64 / to) * to
	}
	return q * to
}
