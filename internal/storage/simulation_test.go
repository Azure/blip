// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package storage

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"

	bolt "go.etcd.io/bbolt"

	"github.com/Azure/blip/internal/stream"
)

// storageSimulation executes the production Store, bbolt transactions and
// operation cursors against a symbolic dm graph. Thin snapshots copy block
// symbols; clone reads select remote or local blocks, and foreground writes
// win over later hydration. It enforces dependencies rather than returning
// canned success for each expected command.
type storageSimulation struct {
	mu       sync.Mutex
	t        *testing.T
	s        *Store
	thin     map[uint32]map[int]string
	flushed  map[uint32]map[int]string
	dm       map[string]*simDevice
	remote   map[int]string
	leased   bool
	releases int
	trace    []string
	fault    int
	mode     string
}

type simDevice struct {
	table, pending                 string
	readOnly, pendingRO, suspended bool
	open                           int
	hydrated                       map[int]bool
}

type storageCrash struct{}

func newStorageSimulation(t *testing.T) *storageSimulation {
	t.Helper()
	s := newDeleteTestStore(t)
	s.cfg.Key = make([]byte, KeySize)
	if err := s.load(); err != nil {
		t.Fatal(err)
	}
	x := &storageSimulation{t: t, s: s, thin: map[uint32]map[int]string{}, dm: map[string]*simDevice{},
		flushed: map[uint32]map[int]string{},
		remote:  map[int]string{0: "super", 1: "remote-A", 3: "remote-B", 6: "remote-C"}, leased: true, fault: -1}
	x.attach(s)
	t.Cleanup(func() { x.s.cancel(); x.s.wg.Wait(); x.s.db.Close() })
	return x
}

func (x *storageSimulation) attach(s *Store) {
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.devices = x
	s.cfg.ReleaseRemote = func(id string) {
		if err := x.action("release "+id, func() error {
			for name, dev := range x.dm {
				if strings.Contains(dev.table, " clone ") {
					x.t.Fatalf("released source while clone %s still depends on it", name)
				}
			}
			x.leased = false
			x.releases++
			return nil
		}); err != nil {
			// The public release callback has no error result. Model its
			// ambiguous completion as a process crash, not a fake ACK.
			panic(storageCrash{})
		}
	}
	s.metadataUpdate = func(fn func(*bolt.Tx) error) error {
		return x.action("metadata", func() error { return s.db.Update(fn) })
	}
	// Background watchers have an explicit cancellation boundary. Simulated
	// hydration is driven below one block at a time, with no wall-clock sleeps.
	s.cloneWait = func(ctx context.Context, _, _ string, _ func(int64, int64)) error {
		<-ctx.Done()
		return ctx.Err()
	}
}

func (x *storageSimulation) action(label string, apply func() error) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	n := len(x.trace)
	x.trace = append(x.trace, label)
	hit := n == x.fault
	if hit && strings.HasPrefix(x.mode, "before") {
		if x.mode == "before-crash" {
			panic(storageCrash{})
		}
		return errors.New("injected before " + label)
	}
	err := apply()
	if hit && strings.HasPrefix(x.mode, "after") {
		if x.mode == "after-crash" {
			panic(storageCrash{})
		}
		return errors.New("injected lost acknowledgement of " + label)
	}
	return err
}

func (x *storageSimulation) Names() map[string]bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	names := map[string]bool{}
	for name := range x.dm {
		names[name] = true
	}
	return names
}

func (x *storageSimulation) Table(name string) (string, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if dev := x.dm[name]; dev != nil {
		return dev.table, nil
	}
	return "", errors.New("missing device " + name)
}

func deviceRefs(table string) []string {
	var refs []string
	for _, line := range strings.Split(table, "\n") {
		f := strings.Fields(line)
		switch f[2] {
		case "crypt":
			refs = append(refs, strings.TrimPrefix(f[6], "/dev/mapper/"))
		case "linear":
			refs = append(refs, strings.TrimPrefix(f[3], "/dev/mapper/"))
		case "clone":
			refs = append(refs, strings.TrimPrefix(f[3], "/dev/mapper/"), strings.TrimPrefix(f[4], "/dev/mapper/"))
		}
	}
	return refs
}

func thinID(table string) uint32 {
	f := strings.Fields(table)
	if f[2] != "thin" {
		return 0
	}
	id, _ := strconv.ParseUint(f[4], 10, 32)
	return uint32(id)
}

func (x *storageSimulation) Apply(e deviceEffect) error {
	return x.action(string(e.Kind)+" "+e.Name, func() error {
		switch e.Kind {
		case eCreateThin, eSnapshot:
			if _, exists := x.thin[e.Thin]; exists {
				return errors.New("thin already exists")
			}
			data := map[int]string{}
			if e.Kind == eSnapshot {
				origin, ok := x.thin[e.Origin]
				if !ok {
					return errors.New("missing snapshot origin")
				}
				for name, dev := range x.dm {
					if thinID(dev.table) == e.Origin && !dev.readOnly && !dev.suspended {
						return fmt.Errorf("writable snapshot origin %s was not suspended", name)
					}
				}
				data = maps.Clone(origin)
			}
			x.thin[e.Thin] = data
		case eDeleteThin:
			for _, dev := range x.dm {
				if thinID(dev.table) == e.Thin && e.Thin != 0 {
					return ErrInUse
				}
			}
			delete(x.thin, e.Thin)
		case eCreate:
			if x.dm[e.Name] != nil {
				return errors.New("device already exists")
			}
			if id := thinID(e.Table); id != 0 && x.thin[id] == nil {
				return errors.New("missing thin")
			}
			for _, ref := range deviceRefs(e.Table) {
				if x.dm[ref] == nil {
					return errors.New("missing dependency " + ref)
				}
			}
			x.dm[e.Name] = &simDevice{table: e.Table, readOnly: e.ReadOnly, hydrated: map[int]bool{}}
		case eRemove:
			if dev := x.dm[e.Name]; dev != nil && dev.open > 0 {
				return ErrInUse
			}
			for _, dev := range x.dm {
				for _, ref := range append(deviceRefs(dev.table), pendingRefs(dev.pending)...) {
					if ref == e.Name {
						return ErrInUse
					}
				}
			}
			delete(x.dm, e.Name)
		case eSuspend:
			dev := x.dm[e.Name]
			if dev == nil {
				return errors.New("missing suspend device")
			}
			dev.suspended = true
		case eLoad:
			dev := x.dm[e.Name]
			if dev == nil || !dev.suspended {
				return errors.New("load without suspend")
			}
			for _, ref := range deviceRefs(e.Table) {
				if x.dm[ref] == nil {
					return errors.New("missing loaded dependency " + ref)
				}
			}
			dev.pending, dev.pendingRO = e.Table, e.ReadOnly
		case eResume:
			if dev := x.dm[e.Name]; dev != nil {
				if dev.pending != "" {
					dev.table, dev.readOnly, dev.pending = dev.pending, dev.pendingRO, ""
				}
				dev.suspended = false
			}
		case eNodes, eMessage:
			if x.dm[e.Name] == nil {
				return errors.New("missing device")
			}
		case eFormat:
			x.write(e.Name, 0, "ext4")
		case eGrow:
			x.write(e.Name, 7, "grown")
		case eFlush:
			id, _ := x.dataDevice(e.Name)
			x.flushed[id] = maps.Clone(x.thin[id])
		case eCheckClosed:
			if dev := x.dm[e.Name]; dev == nil {
				return errors.New("missing device")
			} else if dev.open > 0 {
				return ErrInUse
			}
		case eCheckClean:
			if x.read(e.Name, 0) == "dirty" {
				return ErrUnclean
			}
		case eResetStream:
			for off := int64(0); off < e.Size; off += blockSize {
				x.write(e.Name, int((stream.Offset+off)/blockSize), "")
			}
		case eDiscard:
			dev := x.dm[e.Name]
			for block := 0; int64(block)*blockSize < e.Size; block++ {
				copy := false
				for _, r := range e.Regions {
					if off := int64(block) * blockSize; off >= r.Offset && off < r.Offset+r.Length {
						copy = true
					}
				}
				if !copy {
					dev.hydrated[block] = true
				}
			}
		default:
			return fmt.Errorf("unmodeled effect %s", e.Kind)
		}
		x.checkOwnership()
		return nil
	})
}

func pendingRefs(table string) []string {
	if table == "" {
		return nil
	}
	return deviceRefs(table)
}

func (x *storageSimulation) dataDevice(name string) (uint32, *simDevice) {
	dev := x.dm[name]
	if dev == nil {
		x.t.Fatalf("I/O to missing device %s", name)
	}
	if dev.suspended {
		x.t.Fatalf("I/O to suspended device %s", name)
	}
	if id := thinID(dev.table); id != 0 {
		return id, nil
	}
	f := strings.Fields(dev.table)
	if f[2] == "clone" {
		id, _ := x.dataDevice(strings.TrimPrefix(f[4], "/dev/mapper/"))
		return id, dev
	}
	return x.dataDevice(deviceRefs(dev.table)[0])
}

func (x *storageSimulation) read(name string, block int) string {
	id, clone := x.dataDevice(name)
	if clone != nil && !clone.hydrated[block] {
		if !x.leased {
			x.t.Fatal("read from released remote")
		}
		return x.remote[block]
	}
	return x.thin[id][block]
}

func (x *storageSimulation) write(name string, block int, symbol string) {
	if x.dm[name].readOnly {
		x.t.Fatal("write to read-only mapping")
	}
	id, clone := x.dataDevice(name)
	x.thin[id][block] = symbol
	if clone != nil {
		clone.hydrated[block] = true
	}
}

func (x *storageSimulation) hydrate(name string, block int) {
	id, clone := x.dataDevice(name)
	if clone == nil {
		x.t.Fatal("hydrate non-clone")
	}
	if !clone.hydrated[block] {
		if !x.leased {
			x.t.Fatal("hydrating released remote")
		}
		x.thin[id][block] = x.remote[block]
		clone.hydrated[block] = true
	}
}

func (x *storageSimulation) diskRecords() map[string]record {
	rs := map[string]record{}
	if err := x.s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketVolumes).ForEach(func(_, v []byte) error {
			var r record
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			rs[r.ID] = r
			return nil
		})
	}); err != nil {
		x.t.Fatal(err)
	}
	return rs
}

func (x *storageSimulation) checkOwnership() {
	owned := map[uint32]string{}
	claim := func(id uint32, owner string) {
		if id == 0 {
			return
		}
		if previous := owned[id]; previous != "" {
			x.t.Fatalf("thin %d is owned by both %s and %s", id, previous, owner)
		}
		owned[id] = owner
	}
	for _, r := range x.diskRecords() {
		claim(r.Thin, r.ID)
		claim(r.TeardownMetaThin, r.ID+" teardown metadata")
		if r.Clone != nil {
			claim(r.Clone.MetaThin, r.ID+" clone metadata")
		}
	}
	for id := range x.thin {
		if owned[id] == "" {
			x.t.Fatalf("orphan thin %d, trace %v", id, x.trace)
		}
	}
}

func (x *storageSimulation) restart() {
	x.s.cancel()
	x.s.wg.Wait()
	old := x.s
	if err := old.db.Close(); err != nil {
		x.t.Fatal(err)
	}
	db, err := bolt.Open(filepath.Join(old.cfg.DataDir, "storage.db"), 0o600, nil)
	if err != nil {
		x.t.Fatal(err)
	}
	x.s = &Store{cfg: old.cfg, prefix: old.prefix, db: db, vols: map[string]*record{},
		tmpPins: map[string]int{}, hydrates: map[string]*hydration{}}
	x.fault = -1
	x.attach(x.s)
	if err := x.s.load(); err != nil {
		x.t.Fatal(err)
	}
	if err := x.s.recover(); err != nil {
		x.t.Fatal(err)
	}
	x.checkOwnership()
}

func (x *storageSimulation) image() {
	x.t.Helper()
	err := x.s.CreateImage(context.Background(), "image", 8*blockSize, func(path string) error {
		return x.action("populate image", func() error {
			x.write(strings.TrimPrefix(path, "/dev/mapper/"), 0, "super")
			x.write(strings.TrimPrefix(path, "/dev/mapper/"), 1, "base")
			return nil
		})
	})
	if err != nil {
		x.t.Fatal(err)
	}
}

func (x *storageSimulation) working() *record {
	x.image()
	_, err := x.s.CreateWorking(context.Background(), CreateWorking{AttachmentID: "working", FromImage: "image"})
	if err != nil {
		x.t.Fatal(err)
	}
	return x.s.vols["working"]
}

func (x *storageSimulation) cloning() *record {
	x.image()
	r := &record{ID: "clone", Kind: KindWorking, Base: "image", Size: 8 * blockSize, FSBytes: 8 * blockSize, Layered: true,
		Clone: &cloneInfo{MetaSize: blockSize, Source: "/remote/source", SourceSize: 8 * blockSize, RemoteID: "remote/lease"}}
	if _, err := x.s.begin(r, 2); err != nil {
		x.t.Fatal(err)
	}
	if err := x.s.setupClone(r, x.s.vols["image"], x.s.topName(r), []Region{{0, 8 * blockSize}}); err != nil {
		x.t.Fatal(err)
	}
	if err := x.s.openPlain(r); err != nil {
		x.t.Fatal(err)
	}
	if err := x.s.setPhase(r, phaseReady); err != nil {
		x.t.Fatal(err)
	}
	return r
}

func simulateCall(fn func() error) (err error, crashed bool) {
	defer func() {
		if p := recover(); p != nil {
			if _, ok := p.(storageCrash); !ok {
				panic(p)
			}
			crashed = true
		}
	}()
	err = fn()
	return
}

// Every boundary is run with failure before application, lost acknowledgement,
// crash before application, and crash after application. Recovery reconstructs
// volatile state from actual persisted JSON while preserving the kernel graph.
func TestStorageSimulationCrashMatrix(t *testing.T) {
	type scenario struct {
		setup func(*storageSimulation)
		run   func(*storageSimulation) error
		check func(*storageSimulation)
	}
	ctx := context.Background()
	assertNoPending := func(x *storageSimulation) {
		for _, r := range x.diskRecords() {
			if r.Phase != phaseReady {
				x.t.Fatalf("unfinished record after recovery: %+v", r)
			}
		}
		for name, dev := range x.dm {
			if dev.suspended {
				x.t.Fatalf("device %s left suspended", name)
			}
		}
	}
	scenarios := map[string]scenario{
		"create-image": {run: func(x *storageSimulation) error {
			return x.s.CreateImage(ctx, "new", 8*blockSize, func(path string) error {
				return x.action("populate", func() error { x.write(strings.TrimPrefix(path, "/dev/mapper/"), 2, "payload"); return nil })
			})
		}, check: func(x *storageSimulation) {
			assertNoPending(x)
			if r := x.s.vols["new"]; r != nil && x.thin[r.Thin][2] != "payload" {
				x.t.Fatal("published incomplete image")
			}
		}},
		"empty-commit": {run: func(x *storageSimulation) error {
			return x.s.CreateCommit(ctx, CreateCommit{CommitID: "new", SizeBytes: 8 * blockSize})
		}, check: assertNoPending},
		"grow-commit": {setup: func(x *storageSimulation) { x.image() }, run: func(x *storageSimulation) error {
			return x.s.CreateCommit(ctx, CreateCommit{CommitID: "new", FromImage: "image", SizeBytes: 16 * blockSize})
		}, check: assertNoPending},
		"grow-readonly-working": {setup: func(x *storageSimulation) { x.image() }, run: func(x *storageSimulation) error {
			_, err := x.s.CreateWorking(ctx, CreateWorking{AttachmentID: "new", FromImage: "image", SizeBytes: 16 * blockSize, ReadOnly: true})
			return err
		}, check: func(x *storageSimulation) {
			assertNoPending(x)
			if r := x.s.vols["new"]; r != nil {
				if !x.dm[x.s.plainName(r)].readOnly || x.read(x.s.plainName(r), 1) != "base" {
					x.t.Fatal("incorrect ready working volume")
				}
			}
			if x.thin[x.s.vols["image"].Thin][7] != "" {
				x.t.Fatal("grow modified snapshot origin")
			}
		}},
		"export": {setup: func(x *storageSimulation) { x.image() }, run: func(x *storageSimulation) error {
			_, err := x.s.OpenExport("image", "lease")
			return err
		}, check: assertNoPending},
		"create-remote-working": {setup: func(x *storageSimulation) { x.image() }, run: func(x *storageSimulation) error {
			_, err := x.s.CreateWorking(ctx, CreateWorking{AttachmentID: "new", Remote: &Remote{
				ID: "remote/lease", Device: "/remote/source", SizeBytes: 8 * blockSize, Base: "image",
				Regions: []Region{{blockSize, blockSize}, {3 * blockSize, blockSize}, {6 * blockSize, blockSize}},
			}})
			return err
		}, check: func(x *storageSimulation) {
			assertNoPending(x)
			if r := x.s.vols["new"]; r != nil {
				for block := range 8 {
					if got := x.read(x.s.plainName(r), block); got != x.remote[block] {
						x.t.Fatalf("incorrect remote delta block %d: %q", block, got)
					}
				}
			}
		}},
		"fetch-commit": {setup: func(x *storageSimulation) { x.image() }, run: func(x *storageSimulation) error {
			x.s.cloneWait = func(_ context.Context, name, _ string, progress func(int64, int64)) error {
				return x.action("hydrate all", func() error {
					for block := range 8 {
						x.hydrate(name, block)
					}
					return nil
				})
			}
			return x.s.FetchCommit(ctx, "state", "new", Remote{
				ID: "remote/lease", Device: "/remote/source", SizeBytes: 8 * blockSize, Base: "image",
				Regions: []Region{{blockSize, blockSize}, {3 * blockSize, blockSize}, {6 * blockSize, blockSize}},
			}, nil)
		}, check: func(x *storageSimulation) {
			assertNoPending(x)
			if r := x.s.vols["new"]; r != nil {
				for block := range 8 {
					if got := x.thin[r.Thin][block]; got != x.remote[block] {
						x.t.Fatalf("incorrect fetched block %d: %q", block, got)
					}
				}
				if r.Clone != nil || x.leased {
					x.t.Fatal("fetched commit still depends on remote")
				}
			}
		}},
		"delete": {setup: func(x *storageSimulation) { x.working() }, run: func(x *storageSimulation) error {
			return x.s.Delete(ctx, "working")
		}, check: assertNoPending},
		"delete-clone": {setup: func(x *storageSimulation) { x.cloning() }, run: func(x *storageSimulation) error {
			return x.s.Delete(ctx, "clone")
		}, check: assertNoPending},
		"finish-clone": {setup: func(x *storageSimulation) {
			r := x.cloning()
			for block := range 8 {
				x.hydrate(x.s.topName(r), block)
			}
		}, run: func(x *storageSimulation) error { return x.s.finishClone(x.s.vols["clone"]) }, check: func(x *storageSimulation) {
			assertNoPending(x)
			r := x.s.vols["clone"]
			for block := range 8 {
				if x.read(x.s.plainName(r), block) != x.remote[block] {
					x.t.Fatalf("lost hydrated block %d", block)
				}
			}
			if r.Clone == nil && x.leased {
				x.t.Fatal("completed clone leaked lease")
			}
		}},
		"snapshot-active": {setup: func(x *storageSimulation) { x.working() }, run: func(x *storageSimulation) error {
			origin := x.s.vols["working"]
			r := &record{ID: "new", Kind: KindCommit, Size: origin.Size, FSBytes: origin.fsBytes()}
			if _, err := x.s.begin(r, 1); err != nil {
				return err
			}
			if err := x.s.snapshotActive(origin, r); err != nil {
				_ = x.s.rollback(r)
				return err
			}
			return x.s.setPhase(r, phaseReady)
		}, check: assertNoPending},
		"seal": {setup: func(x *storageSimulation) { x.working() }, run: func(x *storageSimulation) error {
			_, err := x.s.Seal(ctx, "working", "new")
			return err
		}, check: assertNoPending},
		"live-copy": {setup: func(x *storageSimulation) { x.working() }, run: func(x *storageSimulation) error {
			_, err := x.s.LiveCopy(ctx, "working", "new", "state")
			return err
		}, check: assertNoPending},
		"live-copy-copy": {setup: func(x *storageSimulation) {
			const streamSize = 64 << 20
			x.image()
			if _, err := x.s.CreateWorking(ctx, CreateWorking{AttachmentID: "working", FromImage: "image",
				StateUID: "src", SizeBytes: 8 * blockSize, StreamSize: streamSize}); err != nil {
				x.t.Fatal(err)
			}
			x.write(x.s.plainName(x.s.vols["working"]), int(stream.Offset/blockSize), "marker")
		}, run: func(x *storageSimulation) error {
			_, err := x.s.LiveCopy(ctx, "working", "new", "dst")
			return err
		}, check: func(x *storageSimulation) {
			assertNoPending(x)
			header := int(stream.Offset / blockSize)
			if r := x.s.vols["new"]; r != nil {
				if _, err := x.s.Activate("new"); err != nil {
					x.t.Fatal(err)
				}
				if got := x.read(x.s.thinName(r), header); got != "" {
					x.t.Fatalf("live copy inherited ring header %q", got)
				}
			}
			if r := x.s.vols["working"]; r != nil {
				if got := x.read(x.s.plainName(r), header); got != "marker" {
					x.t.Fatalf("live copy source lost ring header %q", got)
				}
			}
		}},
		"copy-commit": {setup: func(x *storageSimulation) {
			const streamSize = 64 << 20
			if err := x.s.CreateCommit(ctx, CreateCommit{CommitID: "base", StateUID: "src",
				SizeBytes: 8 * blockSize, StreamSize: streamSize}); err != nil {
				x.t.Fatal(err)
			}
			if _, err := x.s.CreateWorking(ctx, CreateWorking{AttachmentID: "working", FromCommit: "base",
				StateUID: "src", SizeBytes: 8 * blockSize, StreamSize: streamSize}); err != nil {
				x.t.Fatal(err)
			}
			x.write(x.s.plainName(x.s.vols["working"]), int(stream.Offset/blockSize), "marker")
			if _, err := x.s.Seal(ctx, "working", "src"); err != nil {
				x.t.Fatal(err)
			}
		}, run: func(x *storageSimulation) error {
			return x.s.CreateCommit(ctx, CreateCommit{CommitID: "new", FromCommit: "src",
				StateUID: "dst", StreamSize: 64 << 20})
		}, check: func(x *storageSimulation) {
			assertNoPending(x)
			header := int(stream.Offset / blockSize)
			if r := x.s.vols["new"]; r != nil {
				if _, err := x.s.Activate("new"); err != nil {
					x.t.Fatal(err)
				}
				if got := x.read(x.s.thinName(r), header); got != "" {
					x.t.Fatalf("copied commit inherited ring header %q", got)
				}
			}
			if r := x.s.vols["src"]; r != nil {
				if _, err := x.s.Activate("src"); err != nil {
					x.t.Fatal(err)
				}
				if got := x.read(x.s.thinName(r), header); got != "marker" {
					x.t.Fatalf("source commit lost ring header %q", got)
				}
			}
		}},
	}
	for name, test := range scenarios {
		t.Run(name, func(t *testing.T) {
			base := newStorageSimulation(t)
			if test.setup != nil {
				test.setup(base)
			}
			base.trace = nil
			if err := test.run(base); err != nil {
				t.Fatal(err)
			}
			boundaries := append([]string(nil), base.trace...)
			for i, label := range boundaries {
				for _, mode := range []string{"before-error", "after-error", "before-crash", "after-crash"} {
					t.Run(fmt.Sprintf("%02d-%s/%s", i, label, mode), func(t *testing.T) {
						x := newStorageSimulation(t)
						if test.setup != nil {
							test.setup(x)
						}
						x.trace, x.fault, x.mode = nil, i, mode
						err, crashed := simulateCall(func() error { return test.run(x) })
						if err == nil && !crashed && !(label == "metadata" && mode == "after-error") {
							t.Fatalf("fault not observed: %v", x.trace)
						}
						x.restart()
						test.check(x)
					})
				}
			}
		})
	}
}

func TestStorageSimulationHydrationAndSnapshotContent(t *testing.T) {
	x := newStorageSimulation(t)
	r := x.cloning()
	top, plain := x.s.topName(r), x.s.plainName(r)
	if got := x.read(plain, 1); got != "remote-A" {
		t.Fatal(got)
	}
	x.write(plain, 1, "guest-write-before-copy")
	x.hydrate(top, 1)
	x.hydrate(top, 3)
	x.write(plain, 3, "guest-write-after-copy")
	for block := range 8 {
		x.hydrate(top, block)
	}
	if err := x.s.finishClone(r); err != nil {
		t.Fatal(err)
	}
	if x.leased || x.releases != 1 {
		t.Fatalf("release state %v %d", x.leased, x.releases)
	}
	want := maps.Clone(x.remote)
	want[1], want[3] = "guest-write-before-copy", "guest-write-after-copy"
	for block := range 8 {
		if got := x.read(plain, block); got != want[block] {
			t.Fatalf("block %d: %q != %q", block, got, want[block])
		}
	}
	snapshot := &record{ID: "snapshot", Kind: KindCommit, Size: r.Size, FSBytes: r.fsBytes()}
	if _, err := x.s.begin(snapshot, 1); err != nil {
		t.Fatal(err)
	}
	if err := x.s.snapshotActive(r, snapshot); err != nil {
		t.Fatal(err)
	}
	if err := x.s.setPhase(snapshot, phaseReady); err != nil {
		t.Fatal(err)
	}
	x.write(plain, 1, "later-write")
	if x.thin[snapshot.Thin][1] != want[1] {
		t.Fatal("working write changed immutable snapshot")
	}
	x.restart()
	if x.read(x.s.plainName(x.s.vols["clone"]), 1) != "later-write" {
		t.Fatal("restart lost local data")
	}
}

func TestStorageSimulationMetadataFailureOrdering(t *testing.T) {
	x := newStorageSimulation(t)
	r := x.working()
	before := copyRecord(r)
	x.s.metadataUpdate = func(func(*bolt.Tx) error) error { return errors.New("disk full") }
	for _, op := range []func() error{
		func() error { return x.s.setPhase(r, phaseDeleting) },
		func() error { return x.s.markFailed(r, "failed") },
		func() error { return x.s.Pin(r.ID, "pin") },
		func() error { return x.s.drop(r) },
		func() error { return x.s.Delete(context.Background(), r.ID) },
	} {
		if err := op(); err == nil {
			t.Fatal("metadata failure ignored")
		}
		if !reflect.DeepEqual(*r, before) || x.s.vols[r.ID] != r {
			t.Fatal("uncommitted metadata published")
		}
		if x.read(x.s.plainName(r), 1) != "base" {
			t.Fatal("delete touched devices before durable intent")
		}
	}
}

func TestHydrationDecisionRejectsFailedFullTarget(t *testing.T) {
	for _, status := range []string{
		"0 100 clone 8 1/2 128 8/8 1 ro", "0 100 clone 8 1/2 128 8/8 1 fail",
		"0 100 clone 8 1/2 128 9/8 1 rw", "0 100 clone 8 1/2 128 0/0 1 rw",
	} {
		if done, _, _, err := hydrationDecision("clone", status); done || err == nil {
			t.Fatalf("accepted %q", status)
		}
	}
}

func TestStorageSimulationBusyCloneRetainsRemote(t *testing.T) {
	x := newStorageSimulation(t)
	r := x.cloning()
	x.dm[x.s.plainName(r)].open++
	if err := x.s.Delete(context.Background(), r.ID); !errors.Is(err, ErrInUse) {
		t.Fatalf("delete open clone: %v", err)
	}
	if !x.leased || x.releases != 0 {
		t.Fatal("busy clone lost remote source")
	}
	if _, ok := x.s.Get(r.ID); !ok {
		t.Fatal("busy delete hid a live writer")
	}
	if x.read(x.s.plainName(r), 1) != "remote-A" {
		t.Fatal("open handle stopped reading")
	}
	x.dm[x.s.plainName(r)].open--
	if err := x.s.Delete(context.Background(), r.ID); err != nil {
		t.Fatal(err)
	}
	if x.leased || x.releases != 1 {
		t.Fatal("delete did not release source exactly once")
	}
}

func TestStorageSimulationReleaseAcknowledgementRetry(t *testing.T) {
	x := newStorageSimulation(t)
	r := x.cloning()
	for block := range 8 {
		x.hydrate(x.s.topName(r), block)
	}
	// Fail just the durable acknowledgement after the remote release callback.
	x.s.metadataUpdate = func(fn func(*bolt.Tx) error) error {
		if x.releases > 0 {
			return errors.New("release acknowledgement write failed")
		}
		return x.s.db.Update(fn)
	}
	if err := x.s.finishClone(r); err == nil {
		t.Fatal("expected acknowledgement failure")
	}
	if r.Clone != nil || r.PendingRemote == "" || x.releases != 1 {
		t.Fatal("lost durable release intent")
	}
	if err := x.s.finishClone(r); err == nil {
		t.Fatal("expected repeated metadata failure")
	}
	if x.releases != 1 {
		t.Fatal("same-process retry called release twice")
	}
	x.restart()
	if x.releases != 2 {
		t.Fatal("restart did not replay unacknowledged release ID")
	}
	if x.s.vols[r.ID].PendingRemote != "" {
		t.Fatal("release outbox not acknowledged")
	}
}

func TestStorageSimulationSourceHoldWinsDeleteWindow(t *testing.T) {
	x := newStorageSimulation(t)
	x.image()
	x.s.testDeleteLocked = func() {
		if _, err := x.s.source("image", KindImage); err != nil {
			t.Fatal(err)
		}
	}
	if err := x.s.Delete(context.Background(), "image"); !errors.Is(err, ErrPinned) {
		t.Fatalf("delete held source: %v", err)
	}
	if _, ok := x.s.Get("image"); !ok {
		t.Fatal("accepted source hold lost to delete")
	}
	x.s.unhold("image")
	x.s.testDeleteLocked = nil
	if err := x.s.Delete(context.Background(), "image"); err != nil {
		t.Fatal(err)
	}
}

func TestStorageSimulationThinIDWrapAndAmbiguousBegin(t *testing.T) {
	x := newStorageSimulation(t)
	x.cloning() // owns thin IDs 1, 2, and clone metadata 3
	if err := x.s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketMeta).Put(keyNextThin, binary.BigEndian.AppendUint32(nil, (1<<24)-1))
	}); err != nil {
		t.Fatal(err)
	}
	r := &record{ID: "wrapping", Kind: KindWorking, Clone: &cloneInfo{}}
	ids, err := x.s.begin(r, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ids, []uint32{(1 << 24) - 1, 4}) {
		t.Fatalf("allocated owned IDs after wrap: %v", ids)
	}
	x.trace, x.fault, x.mode = nil, 0, "after-error"
	r = &record{ID: "ambiguous", Kind: KindCommit}
	if _, err := x.s.begin(r, 1); err != nil {
		t.Fatalf("durably committed begin was not reconciled: %v", err)
	}
	if r.Thin == 0 || r.Phase != phaseCreating {
		t.Fatal("committed begin not published")
	}
	x.fault = -1
	if _, err := x.s.begin(r, 1); !errors.Is(err, ErrInUse) {
		t.Fatalf("overwrote durable ownership: %v", err)
	}
	x.restart()
	if x.s.vols["ambiguous"] != nil || x.s.vols["wrapping"] != nil {
		t.Fatal("interrupted allocations not recovered")
	}
}

func TestStorageSimulationHostRestartAfterHydration(t *testing.T) {
	x := newStorageSimulation(t)
	r := x.cloning()
	for block := range 8 {
		x.hydrate(x.s.topName(r), block)
	}
	// Crash immediately after the production completion checkpoint.
	x.s.metadataUpdate = func(fn func(*bolt.Tx) error) error {
		err := x.s.db.Update(fn)
		if x.diskRecords()[r.ID].CloneFinishing {
			panic(storageCrash{})
		}
		return err
	}
	if _, crashed := simulateCall(func() error { return x.s.finishClone(r) }); !crashed {
		t.Fatal("did not reach hydration checkpoint")
	}
	// Unlike a process restart, a host reboot loses every dm table. Thin-pool
	// blocks and the completed-hydration checkpoint survive on disk.
	x.dm = map[string]*simDevice{}
	x.thin[r.Thin] = maps.Clone(x.flushed[r.Thin])
	x.restart()
	r = x.s.vols["clone"]
	if r.Clone != nil || r.Failed != "" || x.leased {
		t.Fatalf("completed hydration not recovered: %+v", r)
	}
	for block := range 8 {
		if x.read(x.s.plainName(r), block) != x.remote[block] {
			t.Fatalf("host restart lost block %d", block)
		}
	}
}

// fetchHydration returns a cloneWait that completes the fetch immediately.
func fetchHydration(x *storageSimulation) func(context.Context, string, string, func(int64, int64)) error {
	return func(_ context.Context, name, _ string, _ func(int64, int64)) error {
		return x.action("hydrate all", func() error {
			for block := range 8 {
				x.hydrate(name, block)
			}
			return nil
		})
	}
}

func fetchRemote() Remote {
	return Remote{ID: "remote/lease", Device: "/remote/source", SizeBytes: 8 * blockSize,
		Regions: []Region{{0, 8 * blockSize}}}
}

// TestFetchReplacesOrphanedDevices covers a fetch interrupted after it created
// its destination, metadata, and clone target while its record was lost. Those
// names are derived from the commit ID alone, so every later fetch used to fail
// creating them ("Device or resource busy") and the save stayed pending
// forever. A fetch holding the commit's key lock and finding no record may
// clear them, including their pool allocations.
func TestFetchReplacesOrphanedDevices(t *testing.T) {
	x := newStorageSimulation(t)
	x.s.cloneWait = fetchHydration(x)
	rec := &record{ID: "new", Kind: KindCommit, Size: 8 * blockSize}
	l := x.s.layout(rec)
	for _, d := range []struct {
		name string
		thin uint32
	}{{l.thin, 900}, {l.meta, 901}} {
		x.dm[d.name] = &simDevice{table: thinTable(x.s.poolName(), d.thin, 8*blockSize), hydrated: map[int]bool{}}
	}
	x.dm[l.fetch] = &simDevice{table: fmt.Sprintf("0 %d clone %s %s /remote/source %d",
		8*blockSize/512, mapperPath(l.meta), mapperPath(l.thin), blockSectors), hydrated: map[int]bool{}}

	if err := x.s.FetchCommit(context.Background(), "state", "new", fetchRemote(), nil); err != nil {
		t.Fatalf("FetchCommit with orphaned devices = %v", err)
	}
	r := x.s.vols["new"]
	if r == nil || r.Phase != phaseReady || r.Clone != nil {
		t.Fatalf("fetched commit = %+v", r)
	}
	for _, name := range []string{l.fetch, l.thin, l.meta} {
		if x.dm[name] != nil {
			t.Fatalf("orphaned device %s survived the fetch", name)
		}
	}
	if got := x.thin[r.Thin][1]; got != x.remote[1] {
		t.Fatalf("fetched block 1 = %q", got)
	}
	// Both orphaned thin IDs were reclaimed, plus the clone's own metadata.
	deletes := 0
	for _, step := range x.trace {
		if strings.HasPrefix(step, string(eDeleteThin)+" ") {
			deletes++
		}
	}
	if deletes < 3 {
		t.Fatalf("stale thin IDs were not deleted: %v", x.trace)
	}
	x.checkOwnership()
}

// TestFetchRetriesUnfinishedRecord covers an attempt whose rollback failed:
// its record stays in the creating phase, which begin rejects and recovery
// retries only at startup. A later fetch on the same node must retry that
// rollback, otherwise the commit can never be fetched again.
func TestFetchRetriesUnfinishedRecord(t *testing.T) {
	x := newStorageSimulation(t)
	x.s.cloneWait = fetchHydration(x)
	rec := &record{ID: "new", Kind: KindCommit, Size: 8 * blockSize, FSBytes: 8 * blockSize,
		Clone: &cloneInfo{MetaSize: blockSize, Source: "/remote/source", SourceSize: 8 * blockSize}}
	if _, err := x.s.begin(rec, 2); err != nil {
		t.Fatal(err)
	}
	if err := x.s.setupClone(rec, nil, x.s.fetchName(rec), nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := x.s.Get("new"); ok {
		t.Fatal("unfinished record is visible")
	}
	if err := x.s.FetchCommit(context.Background(), "state", "new", fetchRemote(), nil); err != nil {
		t.Fatalf("FetchCommit after failed rollback = %v", err)
	}
	r := x.s.vols["new"]
	if r == nil || r.Phase != phaseReady || r.Clone != nil {
		t.Fatalf("fetched commit = %+v", r)
	}
	if x.dm[x.s.fetchName(r)] != nil {
		t.Fatal("fetch device survived")
	}
	x.checkOwnership()
}
