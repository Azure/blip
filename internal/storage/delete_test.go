// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package storage

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// newDeleteTestStore builds a store without a thin pool. The volumes in these
// tests have no kernel devices, so Delete only exercises the record state
// machine; testTeardownStep injects the failures a real pool can return.
func newDeleteTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	db, err := bolt.Open(filepath.Join(dir, "storage.db"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s := &Store{
		cfg:      Config{DataDir: dir, NodeName: "delete-test"},
		prefix:   DMPrefix("delete-test"),
		db:       db,
		vols:     map[string]*record{},
		tmpPins:  map[string]int{},
		hydrates: map[string]*hydration{},
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(bucketVolumes); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists(bucketMeta)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return s
}

func addRecord(t *testing.T, s *Store, r *record) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.putLocked(r); err != nil {
		t.Fatal(err)
	}
	s.vols[r.ID] = r
}

// TestDeleteFailureStaysRetryable: a transient teardown failure must not turn
// into an invisible record that blocks the ID forever. The volume stays out of
// List/Get, PendingDeletes exposes it, and a retry completes the teardown so
// the ID can be created again.
func TestDeleteFailureStaysRetryable(t *testing.T) {
	s := newDeleteTestStore(t)
	const id = "a000000000000001"
	r := &record{ID: id, Kind: KindCommit, Size: 32 << 20, Phase: phaseReady}
	addRecord(t, s, r)

	// Fail the first teardown step, like a busy thin device or exhausted thin
	// metadata would.
	s.testTeardownStep = func() error {
		s.testTeardownStep = nil
		return errors.New("transient teardown failure")
	}
	if err := s.Delete(context.Background(), id); err == nil {
		t.Fatal("Delete succeeded despite a failed teardown")
	}
	if _, ok := s.Get(id); ok {
		t.Fatal("half-deleted volume is visible")
	}
	if l := s.List(); len(l) != 0 {
		t.Fatalf("half-deleted volume listed: %+v", l)
	}
	if pending := s.PendingDeletes(); len(pending) != 1 || pending[0] != id {
		t.Fatalf("pending deletes = %v, want [%s]", pending, id)
	}
	// The unfinished record still owns the ID: its thin device and data may
	// not be gone yet.
	if _, err := s.begin(&record{ID: id, Kind: KindCommit, Size: 32 << 20}, 1); !errors.Is(err, ErrInUse) {
		t.Fatalf("begin while the delete is pending: %v", err)
	}

	// The retry path (planGC -> Delete) finishes the teardown.
	if err := s.Delete(context.Background(), id); err != nil {
		t.Fatalf("retry delete: %v", err)
	}
	if pending := s.PendingDeletes(); len(pending) != 0 {
		t.Fatalf("pending deletes after retry = %v", pending)
	}
	if _, ok := s.Get(id); ok {
		t.Fatal("deleted volume still visible")
	}
	if _, err := s.begin(&record{ID: id, Kind: KindCommit, Size: 32 << 20}, 1); err != nil {
		t.Fatalf("ID not reusable after teardown: %v", err)
	}
	if _, ok := s.Get(id); ok {
		t.Fatal("new record should still be creating")
	}
}

// TestRecoverRetriesOldDeletingRecord: a phase=deleting record written by an
// older build is finished by recover when possible, and remains visible as a
// pending delete when the teardown still fails.
func TestRecoverRetriesOldDeletingRecord(t *testing.T) {
	s := newDeleteTestStore(t)
	const id = "b000000000000001"
	addRecord(t, s, &record{ID: id, Kind: KindCommit, Size: 32 << 20, Phase: phaseDeleting})

	s.testTeardownStep = func() error {
		s.testTeardownStep = nil
		return errors.New("device still busy")
	}
	if err := s.recover(); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if pending := s.PendingDeletes(); len(pending) != 1 || pending[0] != id {
		t.Fatalf("pending after failed recover = %v", pending)
	}

	// A later reconcile pass retries through Delete, not only a restart.
	if err := s.Delete(context.Background(), id); err != nil {
		t.Fatalf("retry delete: %v", err)
	}
	if pending := s.PendingDeletes(); len(pending) != 0 {
		t.Fatalf("pending after retry = %v", pending)
	}
}

// failTeardownAfterTop makes the next Delete fail one teardown step after the
// volume's top device has been removed. removeAll's destructive steps are:
// fetch, plain, top, thin, meta, thin ID, clone meta thin.
func failTeardownAfterTop(s *Store) {
	n := 0
	s.testTeardownStep = func() error {
		n++
		if n == 4 {
			s.testTeardownStep = nil
			return errors.New("transient teardown failure after top removal")
		}
		return nil
	}
}

// TestDeleteFailureAfterTopRemovalAbandonsHydration: Delete stops the
// hydration watcher before tearing down. If it then fails after removing the
// top device, hydration cannot continue, so the record must be abandoned
// rather than left as a live clone whose watcher is gone (which would make
// Seal/LiveCopy/Sync/Diff fail with "still hydrating" forever).
func TestDeleteFailureAfterTopRemovalAbandonsHydration(t *testing.T) {
	s := newDeleteTestStore(t)
	const id = "f000000000000001"
	released := 0
	h := &hydration{
		release: func() { released++ },
		cancel:  func() {},
		stopped: make(chan struct{}),
	}
	close(h.stopped)
	r := &record{
		ID: id, Kind: KindWorking, Size: 32 << 20, Phase: phaseReady, Layered: true,
		Clone: &cloneInfo{RemoteID: "node/lease/nqn", Source: "/dev/null", SourceSize: 32 << 20},
	}
	addRecord(t, s, r)
	s.mu.Lock()
	s.hydrates[id] = h
	s.mu.Unlock()

	failTeardownAfterTop(s)
	if err := s.Delete(context.Background(), id); err == nil {
		t.Fatal("Delete succeeded despite a failed teardown")
	}

	// (a) No live record is left advertising hydration behind a closed
	// watcher: the volume is visible only as a pending delete.
	if v, ok := s.Get(id); ok {
		t.Fatalf("half-deleted hydrating volume is visible: %+v", v)
	}
	if l := s.List(); len(l) != 0 {
		t.Fatalf("half-deleted volume listed: %+v", l)
	}
	if pending := s.PendingDeletes(); len(pending) != 1 || pending[0] != id {
		t.Fatalf("pending deletes = %v, want [%s]", pending, id)
	}
	s.mu.Lock()
	clone, phase := r.Clone, r.Phase
	_, watching := s.hydrates[id]
	s.mu.Unlock()
	if clone != nil {
		t.Fatalf("abandoned hydration keeps clone state: %+v", clone)
	}
	if phase != phaseDeleting {
		t.Fatalf("phase after abandoned delete = %q, want %q", phase, phaseDeleting)
	}
	if watching {
		t.Fatal("abandoned hydration still has a watcher entry")
	}
	// Seal must see the pending delete, not a successful wait followed by
	// "still hydrating" forever.
	if _, err := s.Seal(context.Background(), id, "f0000000000000c1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Seal after abandoned delete = %v, want ErrNotFound", err)
	}

	// (b) The remote lease is released exactly once.
	if released != 1 {
		t.Fatalf("remote released %d times, want 1", released)
	}

	// (c) The existing delete retry finishes the teardown and frees the ID.
	if err := s.Delete(context.Background(), id); err != nil {
		t.Fatalf("retry delete: %v", err)
	}
	if pending := s.PendingDeletes(); len(pending) != 0 {
		t.Fatalf("pending deletes after retry = %v", pending)
	}
	if _, err := s.begin(&record{ID: id, Kind: KindWorking, Size: 32 << 20}, 1); err != nil {
		t.Fatalf("ID not reusable after retry: %v", err)
	}
	if released != 1 {
		t.Fatalf("remote released %d times after retry, want 1", released)
	}
}

// TestDeleteFailureReleasesRecoveredRemoteOnce covers the restart case: the
// Release closure is gone, so the lease is released through Config and the
// persisted remote ID is cleared so the retried teardown cannot release it
// again.
func TestDeleteFailureReleasesRecoveredRemoteOnce(t *testing.T) {
	s := newDeleteTestStore(t)
	const id = "f000000000000002"
	released := 0
	s.cfg.ReleaseRemote = func(string) { released++ }
	r := &record{
		ID: id, Kind: KindWorking, Size: 32 << 20, Phase: phaseReady, Layered: true,
		Clone: &cloneInfo{RemoteID: "node/lease/nqn", Source: "/dev/null", SourceSize: 32 << 20},
	}
	addRecord(t, s, r)

	failTeardownAfterTop(s)
	if err := s.Delete(context.Background(), id); err == nil {
		t.Fatal("Delete succeeded despite a failed teardown")
	}
	if released != 1 {
		t.Fatalf("remote released %d times, want 1", released)
	}
	s.mu.Lock()
	remoteID := ""
	if r.Clone != nil {
		remoteID = r.Clone.RemoteID
	}
	s.mu.Unlock()
	if remoteID != "" {
		t.Fatalf("released remote ID still set: %q", remoteID)
	}

	if err := s.Delete(context.Background(), id); err != nil {
		t.Fatalf("retry delete: %v", err)
	}
	if released != 1 {
		t.Fatalf("remote released %d times after retry, want 1", released)
	}
}

// TestPinRacingDeleteCannotBeLost pins the lock ordering between Pin and
// Delete. Delete holds the volume's key lock across its final eligibility
// check and the teardown; a Pin that arrives in that window must wait and then
// fail with ErrNotFound, never be accepted into a record that is then dropped.
func TestPinRacingDeleteCannotBeLost(t *testing.T) {
	s := newDeleteTestStore(t)
	const id = "d000000000000001"
	addRecord(t, s, &record{ID: id, Kind: KindCommit, Size: 32 << 20, Phase: phaseReady})

	// Stop Delete inside its key-locked critical section, right after the
	// eligibility re-check and before the record is touched.
	entered, proceed := make(chan struct{}), make(chan struct{})
	s.testDeleteLocked = func() {
		close(entered)
		<-proceed
	}
	deleted := make(chan error, 1)
	go func() { deleted <- s.Delete(context.Background(), id) }()
	<-entered

	pinned := make(chan error, 1)
	go func() { pinned <- s.Pin(id, "lease:late") }()
	select {
	case err := <-pinned:
		t.Fatalf("Pin returned while Delete held the key lock: %v", err)
	case <-time.After(50 * time.Millisecond):
		// Pin is blocked on the key lock: what a racing Pin must do.
	}

	close(proceed)
	if err := <-deleted; err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := <-pinned; !errors.Is(err, ErrNotFound) {
		t.Fatalf("Pin that lost the race = %v, want ErrNotFound", err)
	}
	if _, ok := s.Get(id); ok {
		t.Fatal("deleted volume still visible")
	}
}

// TestPinBeforeDeletePreventsDeletion: a pin that does land before Delete's
// final check makes Delete fail with ErrPinned and stays on the record.
func TestPinBeforeDeletePreventsDeletion(t *testing.T) {
	s := newDeleteTestStore(t)
	const id = "d000000000000002"
	addRecord(t, s, &record{ID: id, Kind: KindCommit, Size: 32 << 20, Phase: phaseReady})

	if err := s.Pin(id, "lease:a"); err != nil {
		t.Fatalf("pin: %v", err)
	}
	if err := s.Delete(context.Background(), id); !errors.Is(err, ErrPinned) {
		t.Fatalf("delete pinned volume = %v, want ErrPinned", err)
	}
	v, ok := s.Get(id)
	if !ok || len(v.Pins) != 1 || v.Pins[0] != "lease:a" {
		t.Fatalf("pin lost after refused delete: %+v", v)
	}

	if err := s.Unpin(id, "lease:a"); err != nil {
		t.Fatalf("unpin: %v", err)
	}
	if err := s.Delete(context.Background(), id); err != nil {
		t.Fatalf("delete unpinned volume: %v", err)
	}
	if err := s.Pin(id, "lease:b"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("pin after delete = %v, want ErrNotFound", err)
	}
}

// TestPinUnpinIdempotent keeps the documented return semantics: double Pin is
// a no-op, Unpin of a missing pin or record succeeds.
func TestPinUnpinIdempotent(t *testing.T) {
	s := newDeleteTestStore(t)
	const id = "d000000000000003"
	addRecord(t, s, &record{ID: id, Kind: KindCommit, Size: 32 << 20, Phase: phaseReady})

	for range 2 {
		if err := s.Pin(id, "lease:a"); err != nil {
			t.Fatalf("pin: %v", err)
		}
	}
	v, _ := s.Get(id)
	if len(v.Pins) != 1 {
		t.Fatalf("pins after double pin = %v", v.Pins)
	}
	if err := s.Unpin(id, "missing"); err != nil {
		t.Fatalf("unpin missing holder: %v", err)
	}
	if err := s.Unpin(id, "lease:a"); err != nil {
		t.Fatalf("unpin: %v", err)
	}
	if err := s.Unpin(id, "lease:a"); err != nil {
		t.Fatalf("second unpin: %v", err)
	}
	if err := s.Unpin("unknown", "lease:a"); err != nil {
		t.Fatalf("unpin unknown volume: %v", err)
	}
}

// TestPinDeleteStress runs Pin/Unpin/Delete concurrently under -race. A pin
// that Pin accepts must stay visible until it is unpinned: Delete may not drop
// a pinned record.
func TestPinDeleteStress(t *testing.T) {
	s := newDeleteTestStore(t)
	const id = "d000000000000004"
	addRecord(t, s, &record{ID: id, Kind: KindCommit, Size: 32 << 20, Phase: phaseReady})

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			holder := fmt.Sprintf("lease:%d", i)
			for range 50 {
				if err := s.Pin(id, holder); err == nil {
					// The pin is held here, so Delete must not have dropped
					// the record.
					if _, ok := s.Get(id); !ok {
						t.Errorf("pinned volume %s is gone", id)
					}
					if err := s.Unpin(id, holder); err != nil {
						t.Errorf("unpin %s: %v", id, err)
					}
				} else if !errors.Is(err, ErrNotFound) {
					t.Errorf("pin %s: %v", id, err)
				}
			}
		}()
	}
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				if err := s.Delete(context.Background(), id); err != nil && !errors.Is(err, ErrPinned) {
					t.Errorf("delete %s: %v", id, err)
				}
			}
		}()
	}
	wg.Wait()
	if err := s.Delete(context.Background(), id); err != nil {
		t.Fatalf("final delete: %v", err)
	}
	if _, ok := s.Get(id); ok {
		t.Fatal("volume still visible after final delete")
	}
}
