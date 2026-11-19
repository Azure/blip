// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package storage

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestBusyDeletePreservesWriter(t *testing.T) {
	x := newStorageSimulation(t)
	r := x.working()
	plain := x.s.plainName(r)
	x.dm[plain].open++
	if err := x.s.Delete(context.Background(), r.ID); !errors.Is(err, ErrInUse) {
		t.Fatalf("Delete = %v", err)
	}
	if v, ok := x.s.Get(r.ID); !ok || v.Device != mapperPath(plain) {
		t.Fatalf("busy writer no longer discoverable: %+v, %v", v, ok)
	}
	if pending := x.s.PendingDeletes(); len(pending) != 0 {
		t.Fatalf("refused delete was scheduled for retry: %v", pending)
	}
	x.restart()
	if dev, err := x.s.Activate(r.ID); err != nil || dev != mapperPath(plain) {
		t.Fatalf("busy writer lost on restart: %q, %v", dev, err)
	}
	x.dm[plain].open--
	if _, err := x.s.Seal(context.Background(), r.ID, "sealed"); err != nil {
		t.Fatalf("writer cannot seal after refused delete: %v", err)
	}
	if got := x.thin[x.s.vols["sealed"].Thin][1]; got != "base" {
		t.Fatalf("sealed data = %q", got)
	}
}

func TestActivateRecreatesMissingWorkingDevice(t *testing.T) {
	x := newStorageSimulation(t)
	r := x.working()
	plain := x.s.plainName(r)
	delete(x.dm, plain) // a snapshot can observe the record ready without its device
	dev, err := x.s.Activate(r.ID)
	if err != nil {
		t.Fatalf("Activate = %v", err)
	}
	if dev != mapperPath(plain) || x.dm[plain] == nil {
		t.Fatalf("device not recreated: %q, %v", dev, x.dm[plain])
	}
	if got := x.read(plain, 1); got != "base" {
		t.Fatalf("reactivation lost data: %q", got)
	}
	// A second activation is a no-op and still returns the active device.
	if dev, err := x.s.Activate(r.ID); err != nil || dev != mapperPath(plain) || x.dm[plain] == nil {
		t.Fatalf("second Activate = %q, %v", dev, err)
	}
}

func failDeleteRestoration(s *Store) {
	writes := 0
	s.metadataUpdate = func(fn func(*bolt.Tx) error) error {
		writes++
		if writes == 2 {
			return errors.New("ready restoration failed")
		}
		return s.db.Update(fn)
	}
}

func TestBusyDeleteRestorationFailureRecovers(t *testing.T) {
	for _, hostReboot := range []bool{false, true} {
		name := "process-restart"
		if hostReboot {
			name = "host-reboot"
		}
		t.Run(name, func(t *testing.T) {
			x := newStorageSimulation(t)
			r := x.working()
			x.dm[x.s.plainName(r)].open++
			failDeleteRestoration(x.s)
			if err := x.s.Delete(context.Background(), r.ID); !errors.Is(err, ErrInUse) {
				t.Fatalf("Delete = %v", err)
			}
			if x.diskRecords()[r.ID].Phase != phaseDetaching {
				t.Fatal("lost the uncommitted deletion gate")
			}
			if hostReboot {
				x.dm = map[string]*simDevice{} // thin-pool data survives, DM tables do not
			}
			x.restart()
			if _, ok := x.s.Get(r.ID); !ok || len(x.s.PendingDeletes()) != 0 {
				t.Fatal("recovery permanently hid a refused writer deletion")
			}
			if x.read(x.s.plainName(r), 1) != "base" {
				t.Fatal("recovery destroyed the busy writer")
			}
		})
	}
}

func TestBusyDeleteRestorationFailureStillAllowsSeal(t *testing.T) {
	x := newStorageSimulation(t)
	r := x.working()
	x.dm[x.s.plainName(r)].open++
	failDeleteRestoration(x.s)
	if err := x.s.Delete(context.Background(), r.ID); !errors.Is(err, ErrInUse) {
		t.Fatalf("Delete = %v", err)
	}
	if x.diskRecords()[r.ID].Phase != phaseDetaching {
		t.Fatal("restoration failure was not exercised")
	}
	x.dm[x.s.plainName(r)].open--
	// Model the node's pending-delete retry after the writer closes, before
	// sealing. A refused delete must not silently authorize this cleanup.
	pending := x.s.PendingDeletes()
	for _, id := range pending {
		if err := x.s.Delete(context.Background(), id); err != nil {
			t.Fatal(err)
		}
	}
	if len(pending) != 0 {
		t.Fatalf("refused delete became accepted cleanup: %v", pending)
	}
	if _, ok := x.s.Get(r.ID); !ok {
		t.Fatal("failed rollback hid the writer in the running process")
	}
	if _, err := x.s.Seal(context.Background(), r.ID, "sealed"); err != nil {
		t.Fatalf("Seal after refused delete and failed rollback: %v", err)
	}
	if x.thin[x.s.vols["sealed"].Thin][1] != "base" {
		t.Fatal("refused delete lost writer data")
	}
	// A fresh, explicit deletion still accepts and completes normally.
	if err := x.s.Delete(context.Background(), r.ID); err != nil {
		t.Fatal(err)
	}
	if x.s.vols[r.ID] != nil {
		t.Fatal("explicit deletion did not complete")
	}
}

func TestDetachingGateIsNotPendingCleanup(t *testing.T) {
	x := newStorageSimulation(t)
	r := x.working()
	if _, err := x.s.beginDelete(r.ID); err != nil {
		t.Fatal(err)
	}
	if pending := x.s.PendingDeletes(); len(pending) != 0 {
		t.Fatalf("in-flight gate leaked to cleanup before it could refuse: %v", pending)
	}
	// Even if the entry removal succeeded, a crash before accepted deletion
	// is persisted must preserve the data and reconstruct the entry device.
	if err := x.s.deviceRemove(x.s.entryName(r)); err != nil {
		t.Fatal(err)
	}
	x.restart()
	if x.read(x.s.plainName(r), 1) != "base" {
		t.Fatal("unaccepted entry removal destroyed the writer")
	}
}

func TestDeleteGateDeviceFailureStaysRetryable(t *testing.T) {
	x := newStorageSimulation(t)
	r := x.working()
	x.trace, x.fault, x.mode = nil, 1, "before-error" // intent, then entry removal
	if err := x.s.Delete(context.Background(), r.ID); err == nil || errors.Is(err, ErrInUse) {
		t.Fatalf("Delete = %v, want a non-busy device failure", err)
	}
	if pending := x.s.PendingDeletes(); len(pending) != 1 || pending[0] != r.ID {
		t.Fatalf("accepted deletion lost cleanup liveness: %v", pending)
	}
	x.fault = -1
	if err := x.s.Delete(context.Background(), r.ID); err != nil {
		t.Fatal(err)
	}
	if x.s.vols[r.ID] != nil || len(x.s.PendingDeletes()) != 0 {
		t.Fatal("accepted deletion did not complete on retry")
	}
}

func TestDeleteAcceptanceFailureRestoresEntry(t *testing.T) {
	x := newStorageSimulation(t)
	r := x.working()
	writes := 0
	x.s.metadataUpdate = func(fn func(*bolt.Tx) error) error {
		writes++
		if writes >= 2 { // fail acceptance and its rollback, after entry removal
			return errors.New("metadata unavailable")
		}
		return x.s.db.Update(fn)
	}
	if err := x.s.Delete(context.Background(), r.ID); err == nil {
		t.Fatal("ignored failed deletion acceptance")
	}
	if _, ok := x.s.Get(r.ID); !ok || len(x.s.PendingDeletes()) != 0 {
		t.Fatal("unaccepted delete stranded an invisible record")
	}
	if x.read(x.s.plainName(r), 1) != "base" {
		t.Fatal("unaccepted delete did not reconstruct the entry")
	}
	x.s.metadataUpdate = nil
	if err := x.s.Delete(context.Background(), r.ID); err != nil {
		t.Fatalf("fresh deletion could not retry: %v", err)
	}
	if x.s.vols[r.ID] != nil {
		t.Fatal("fresh deletion did not complete")
	}
}

func TestBusyCloseExportPreservesLease(t *testing.T) {
	x := newStorageSimulation(t)
	x.image()
	dev, err := x.s.OpenExport("image", "lease")
	if err != nil {
		t.Fatal(err)
	}
	x.dm[strings.TrimPrefix(dev, "/dev/mapper/")].open++
	if err := x.s.CloseExport("lease"); !errors.Is(err, ErrInUse) {
		t.Fatalf("CloseExport = %v", err)
	}
	if x.s.Exports()["lease"] != "image" {
		t.Fatal("busy close lost the export")
	}
	if again, err := x.s.OpenExport("image", "lease"); err != nil || again != dev {
		t.Fatalf("busy export cannot reopen: %q, %v", again, err)
	}
}

func TestConcurrentBusyDeletesKeepOneWatcher(t *testing.T) {
	x := newStorageSimulation(t)
	r := x.cloning()
	x.dm[x.s.plainName(r)].open++
	const callers = 16
	started := make(chan struct{}, callers+1)
	var active atomic.Int32
	x.s.cloneWait = func(ctx context.Context, _, _ string, _ func(int64, int64)) error {
		active.Add(1)
		defer active.Add(-1)
		started <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	}
	x.s.startWatch(r, nil)
	<-started
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := x.s.Delete(context.Background(), r.ID); !errors.Is(err, ErrInUse) {
				t.Errorf("busy Delete = %v", err)
			}
		}()
	}
	wg.Wait()
	// Every refused delete restarts a watcher. All superseded watchers must
	// have exited, including ones created while another Delete was waiting.
	for range callers {
		<-started
	}
	if n := active.Load(); n != 1 {
		t.Fatalf("busy deletes left %d watchers, want one", n)
	}
	if _, ok := x.s.Get(r.ID); !ok || !x.leased {
		t.Fatal("busy deletes abandoned a live clone")
	}
	x.dm[x.s.plainName(r)].open--
	if err := x.s.Delete(context.Background(), r.ID); err != nil {
		t.Fatal(err)
	}
	if active.Load() != 0 || x.leased || x.releases != 1 {
		t.Fatal("successful delete did not stop hydration and release its source")
	}
}

type resumeFailure struct{ storageDevices }

func (d resumeFailure) Apply(e deviceEffect) error {
	if e.Kind == eResume {
		return errors.New("origin cannot resume")
	}
	return d.storageDevices.Apply(e)
}

func TestRecoveryResumesOriginsBeforeActivation(t *testing.T) {
	x := newStorageSimulation(t)
	origin := x.working()
	dest := &record{ID: "z-snapshot", Kind: KindCommit, Size: origin.Size, FSBytes: origin.fsBytes()}
	if _, err := x.s.begin(dest, 1); err != nil {
		t.Fatal(err)
	}
	x.trace, x.fault, x.mode = nil, 1, "after-crash" // persist intent, suspend, crash
	if _, crashed := simulateCall(func() error { return x.s.snapshotActive(origin, dest) }); !crashed {
		t.Fatal("snapshot did not crash")
	}
	delete(x.dm, x.s.plainName(origin))
	x.fault = -1
	x.s.devices = resumeFailure{x}
	if err := x.s.recover(); err == nil {
		t.Fatal("recovery accepted an unresumable writer")
	}
	if x.dm[x.s.plainName(origin)] != nil {
		t.Fatal("reactivated writer before resuming snapshot origin")
	}
	x.s.devices = x
	x.trace = nil
	if err := x.s.recover(); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(x.trace[0], string(eResume)+" ") {
		t.Fatalf("recovery order: %v", x.trace)
	}
	if x.read(x.s.plainName(origin), 1) != "base" {
		t.Fatal("recovery lost the writer")
	}
}

func TestDeleteRetainsUndeliveredRemoteOutbox(t *testing.T) {
	x := newStorageSimulation(t)
	r := x.cloning()
	release := x.s.cfg.ReleaseRemote
	x.s.cfg.ReleaseRemote = nil
	if err := x.s.Delete(context.Background(), r.ID); err == nil {
		t.Fatal("delete accepted an undeliverable release")
	}
	if r.Clone != nil || r.PendingRemote != "remote/lease" || !x.leased {
		t.Fatalf("abandon lost the release outbox: %+v", r)
	}
	if onDisk := x.diskRecords()[r.ID]; onDisk.PendingRemote != r.PendingRemote {
		t.Fatal("release retry is not durable")
	}
	x.s.cfg.ReleaseRemote = release
	if err := x.s.Delete(context.Background(), r.ID); err != nil {
		t.Fatal(err)
	}
	if x.leased || x.releases != 1 {
		t.Fatal("release outbox was not delivered exactly once")
	}
}

func TestSealAndLiveCopyFences(t *testing.T) {
	x := newStorageSimulation(t)
	r := x.working()
	plain := x.s.plainName(r)
	x.dm[plain].open++
	if _, err := x.s.Seal(context.Background(), r.ID, "sealed"); !errors.Is(err, ErrInUse) {
		t.Fatalf("Seal open writer = %v", err)
	}
	if x.s.vols["sealed"] != nil {
		t.Fatal("allocated snapshot before fencing the writer")
	}
	x.dm[plain].open--
	x.write(plain, 0, "dirty")
	if _, err := x.s.Seal(context.Background(), r.ID, "sealed"); !errors.Is(err, ErrUnclean) {
		t.Fatalf("Seal dirty writer = %v", err)
	}
	if _, err := x.s.LiveCopy(context.Background(), r.ID, "copy", "state"); !errors.Is(err, ErrUnclean) {
		t.Fatalf("LiveCopy dirty writer = %v", err)
	}
	if x.s.vols["copy"] != nil || x.s.vols["sealed"] != nil || len(x.thin) != 2 {
		t.Fatal("rejected dirty snapshot leaked a volume")
	}
	x.write(plain, 0, "super")
	if _, err := x.s.LiveCopy(context.Background(), r.ID, "copy", "state"); err != nil {
		t.Fatal(err)
	}
	x.write(plain, 1, "new write")
	if x.thin[x.s.vols["copy"].Thin][1] != "base" {
		t.Fatal("writer changed its immutable copy")
	}
}

func TestSnapshotLocksOrderAndIdentity(t *testing.T) {
	x := newStorageSimulation(t)
	r := x.working()
	if _, err := x.s.Seal(context.Background(), r.ID, r.ID); err == nil {
		t.Fatal("Seal accepted identical source and destination")
	}
	if _, err := x.s.LiveCopy(context.Background(), r.ID, "", "state"); err == nil {
		t.Fatal("LiveCopy accepted an empty destination")
	}
	var locks keyLock
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				a, b := "a", "b"
				if i%2 != 0 {
					a, b = b, a
				}
				locks.lockPair(a, b)()
			}
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("opposite snapshot lock orders deadlocked")
	}
}

func TestHydrationFlushFailureDoesNotCheckpoint(t *testing.T) {
	x := newStorageSimulation(t)
	r := x.cloning()
	for block := range 8 {
		x.hydrate(x.s.topName(r), block)
	}
	x.trace, x.fault, x.mode = nil, 1, "before-error" // resume, then flush
	if err := x.s.finishClone(r); err == nil {
		t.Fatal("ignored hydration flush failure")
	}
	if x.diskRecords()[r.ID].CloneFinishing || !x.leased || r.Clone == nil {
		t.Fatal("unflushed data was checkpointed as local")
	}
}
