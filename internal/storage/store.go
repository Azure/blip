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
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/sys/unix"
)

const (
	defaultPoolBytes = 40 << 30
	metaFileBytes    = 1 << 30

	phaseCreating = "creating"
	phaseReady    = "ready"
	phaseDeleting = "deleting"

	kindExport Kind = "export" // per-lease writable snapshot served over NVMe/TCP
)

var (
	bucketVolumes = []byte("volumes")
	bucketMeta    = []byte("meta")
	keyNextThin   = []byte("nextThin")
	keyIncarn     = []byte("incarnation")
	keyDiskKeyID  = []byte("diskKeyID")
)

// record is the persisted state of one volume. Every mutation writes the
// record in phase "creating" or "deleting" before touching the kernel, so Open
// can roll back or finish it.
type record struct {
	ID       string     `json:"id"`
	Kind     Kind       `json:"kind"`
	StateUID string     `json:"stateUID,omitempty"`
	Base     string     `json:"base,omitempty"`
	Thin     uint32     `json:"thin"`
	Size     int64      `json:"size"`
	ReadOnly bool       `json:"readOnly,omitempty"`
	Pins     []string   `json:"pins,omitempty"`
	Phase    string     `json:"phase"`
	Layered  bool       `json:"layered,omitempty"` // top device over a separate thin device (remote working volumes)
	Clone    *cloneInfo `json:"clone,omitempty"`   // remote data still hydrating
	Failed   string     `json:"failed,omitempty"`
	Digest   string     `json:"digest,omitempty"` // content digest, computed on first use (see Digest)
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
	for _, r := range s.sorted() {
		var err error
		switch r.Phase {
		case phaseCreating:
			err = s.rollback(r)
		case phaseDeleting:
			err = s.finishDelete(r)
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
	if r.Failed != "" && r.Clone != nil {
		return nil // a lost remote clone cannot come back
	}
	if err := s.reactivateLower(r); err != nil {
		return err
	}
	if r.Kind == kindExport || (r.Failed != "" && r.Clone != nil) || dmExists(s.plainName(r)) {
		return nil
	}
	return s.openPlain(r)
}

// reactivateLower makes the devices below the crypt device exist.
func (s *Store) reactivateLower(r *record) error {
	if !r.Layered {
		if dmExists(s.thinName(r)) {
			return nil
		}
		return dmCreate(s.thinName(r), thinTable(s.poolName(), r.Thin, r.Size), r.ReadOnly)
	}
	if !dmExists(s.thinName(r)) {
		if err := dmCreate(s.thinName(r), thinTable(s.poolName(), r.Thin, r.Size), false); err != nil {
			return err
		}
	}
	top := s.topName(r)
	if r.Clone == nil {
		if dmExists(top) {
			return nil
		}
		return dmCreate(top, linearTable(mapperPath(s.thinName(r)), r.Size), r.ReadOnly)
	}
	table, err := dmTable(top)
	switch {
	case err != nil:
		return s.markFailed(r, "remote clone lost after restart")
	case strings.Contains(table, " clone "):
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
	r.Failed = msg
	return s.putLocked(r)
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

// openPlain creates the crypt device of an active volume.
func (s *Store) openPlain(r *record) error {
	return dmCreate(s.plainName(r), cryptTable(mapperPath(s.topName(r)), r.Size, s.cfg.Key), r.ReadOnly)
}

// withPlain runs fn on a temporary crypt device over the active top device
// of r.
func (s *Store) withPlain(r *record, readOnly bool, fn func(dev string) error) error {
	name := s.plainName(r)
	if err := dmCreate(name, cryptTable(mapperPath(s.topName(r)), r.Size, s.cfg.Key), readOnly); err != nil {
		return err
	}
	err := fn(mapperPath(name))
	if rerr := dmRemove(name); err == nil {
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

func (s *Store) putLocked(r *record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketVolumes).Put([]byte(r.ID), b)
	})
}

func (s *Store) put(r *record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.putLocked(r)
}

func (s *Store) setPhase(r *record, phase string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r.Phase = phase
	return s.putLocked(r)
}

func (s *Store) drop(r *record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.vols, r.ID)
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketVolumes).Delete([]byte(r.ID))
	})
}

// begin records a new volume in phase creating and allocates n thin IDs.
func (s *Store) begin(r *record, n int) ([]uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.vols[r.ID]; ok {
		return nil, fmt.Errorf("%w: %s already exists", ErrInUse, r.ID)
	}
	var ids []uint32
	err := s.db.Update(func(tx *bolt.Tx) error {
		mb := tx.Bucket(bucketMeta)
		next := uint32(1)
		if v := mb.Get(keyNextThin); v != nil {
			next = binary.BigEndian.Uint32(v)
		}
		for range n {
			ids = append(ids, next)
			next++
			if next >= 1<<24 {
				next = 1
			}
		}
		if err := mb.Put(keyNextThin, binary.BigEndian.AppendUint32(nil, next)); err != nil {
			return err
		}
		r.Phase = phaseCreating
		if len(ids) > 0 {
			r.Thin = ids[0]
		}
		if r.Clone != nil && len(ids) > 1 {
			r.Clone.MetaThin = ids[1]
		}
		b, err := json.Marshal(r)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketVolumes).Put([]byte(r.ID), b)
	})
	if err != nil {
		return nil, err
	}
	s.vols[r.ID] = r
	return ids, nil
}

// removeAll tears down every device and thin ID of a volume. Missing pieces
// are fine, so it is safe to repeat. A failure leaves the record in phase
// deleting: the node retries PendingDeletes until the teardown succeeds.
func (s *Store) removeAll(r *record) error {
	names := []string{s.fetchName(r), s.plainName(r), s.topName(r), s.thinName(r), s.metaName(r)}
	for _, n := range names {
		if err := s.beforeTeardown(); err != nil {
			return err
		}
		if err := dmRemove(n); err != nil {
			return err
		}
	}
	if err := s.beforeTeardown(); err != nil {
		return err
	}
	if err := s.deleteThin(r.Thin); err != nil {
		return err
	}
	if r.Clone != nil {
		if err := s.beforeTeardown(); err != nil {
			return err
		}
		if err := s.deleteThin(r.Clone.MetaThin); err != nil {
			return err
		}
	}
	return nil
}

// beforeTeardown runs the test hook, if any, before one destructive step.
func (s *Store) beforeTeardown() error {
	if s.testTeardownStep != nil {
		return s.testTeardownStep()
	}
	return nil
}

func (s *Store) rollback(r *record) error {
	if err := s.removeAll(r); err != nil {
		return err
	}
	s.releaseRemote(r)
	return s.drop(r)
}

func (s *Store) finishDelete(r *record) error {
	if err := s.removeAll(r); err != nil {
		return err
	}
	s.releaseRemote(r)
	return s.drop(r)
}

// releaseRemote releases the clone source of r, if any, exactly once.
func (s *Store) releaseRemote(r *record) {
	s.mu.Lock()
	h := s.hydrates[r.ID]
	delete(s.hydrates, r.ID)
	s.mu.Unlock()
	if h != nil && h.release != nil {
		h.release()
		return
	}
	if r.Clone != nil && r.Clone.RemoteID != "" && s.cfg.ReleaseRemote != nil {
		s.cfg.ReleaseRemote(r.Clone.RemoteID)
	}
}

// queries

func (s *Store) List() []Volume {
	names := dmNames()
	var out []Volume
	for _, r := range s.sorted() {
		if r.Kind == kindExport || r.Phase != phaseReady {
			continue
		}
		out = append(out, s.volume(r, names))
	}
	return out
}

// PendingDeletes returns the IDs of volumes whose deletion started but did not
// finish. They stay out of List/Get/lookup so a half-deleted volume is never
// used, but the node retries their teardown, instead of leaving an invisible
// record that blocks the ID forever.
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
	s.mu.Lock()
	r, ok := s.vols[id]
	s.mu.Unlock()
	if !ok || r.Kind == kindExport || r.Phase != phaseReady {
		return Volume{}, false
	}
	return s.volume(r, dmNames()), true
}

func (s *Store) volume(r *record, names map[string]bool) Volume {
	s.mu.Lock()
	defer s.mu.Unlock()
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
	r.Pins = append(r.Pins, holder)
	return s.putLocked(r)
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
	r.Pins = slices.DeleteFunc(r.Pins, func(h string) bool { return h == holder })
	return s.putLocked(r)
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
		return mapperPath(s.plainName(r)), nil
	case kindExport:
		return mapperPath(s.topName(r)), nil
	}
	name := s.thinName(r)
	if !dmExists(name) {
		if err := dmCreate(name, thinTable(s.poolName(), r.Thin, r.Size), true); err != nil {
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
	// Stop the hydration watcher first: it takes the volume lock to swap.
	s.mu.Lock()
	h := s.hydrates[id]
	s.mu.Unlock()
	if h != nil && h.stopped != nil {
		h.cancel()
		<-h.stopped
	}
	defer s.locks.lock(id)()
	r, err := s.deletable(id)
	if s.testDeleteLocked != nil {
		s.testDeleteLocked()
	}
	if err == nil && r != nil {
		// The devices users open go first: if they are still open nothing changes.
		if err = dmRemove(s.plainName(r)); err == nil {
			err = dmRemove(s.topName(r))
		}
		if err == nil {
			if err = s.setPhase(r, phaseDeleting); err == nil {
				return s.finishDelete(r)
			}
		}
	}
	if h != nil && h.stopped != nil && r != nil && r.Clone != nil && r.Failed == "" && dmExists(s.topName(r)) {
		s.startWatch(r, h.release)
	}
	return err
}

// deletable returns the record of id (nil if it does not exist) or why it
// cannot be deleted.
func (s *Store) deletable(id string) (*record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
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

func roundUp(n, to int64) int64 { return (n + to - 1) / to * to }
