package storage

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

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
