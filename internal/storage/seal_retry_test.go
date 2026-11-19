package storage

import (
	"context"
	"errors"
	"testing"
)

// TestSealRetriesFailedSnapshotCleanup covers a seal whose snapshot fails and
// whose rollback then fails once. The commit record stays in phase creating;
// a later Seal on the same node must retry that cleanup (as FetchCommit does)
// instead of failing with ErrInUse forever.
func TestSealRetriesFailedSnapshotCleanup(t *testing.T) {
	x := newStorageSimulation(t)
	r := x.working()
	s := x.s
	const commit = "sealed"

	// The 7th effect of Seal is the snapshot itself: check-closed,
	// check-clean, flush, begin metadata, resume metadata, suspend, snapshot.
	x.fault = len(x.trace) + 6
	x.mode = "before"
	s.testTeardownStep = func() error {
		s.testTeardownStep = nil
		return errors.New("injected teardown failure")
	}
	if _, err := s.Seal(context.Background(), r.ID, commit); err == nil {
		t.Fatal("seal succeeded despite the injected snapshot failure")
	}
	x.mode = ""
	x.fault = -1
	if rec, ok := x.diskRecords()[commit]; !ok || rec.Phase != phaseCreating {
		t.Fatalf("commit record after failed rollback = %+v, %v; want phase creating", rec, ok)
	}

	// The node retries with the same deterministic commit ID. The retry must
	// finish the leftover rollback and seal successfully.
	if size, err := s.Seal(context.Background(), r.ID, commit); err != nil {
		t.Fatalf("seal retry after failed cleanup: %v", err)
	} else if size != r.Size {
		t.Fatalf("seal retry size = %d, want %d", size, r.Size)
	}
	if rec := s.vols[commit]; rec == nil || rec.Phase != phaseReady {
		t.Fatalf("sealed record after retry = %+v", rec)
	}
	if got := x.thin[s.vols[commit].Thin][1]; got != "base" {
		t.Fatalf("sealed content = %q, want base", got)
	}
	x.checkOwnership()
}

// TestSealRetriesFailedSetPhase covers a completed snapshot whose ready-phase
// write fails and whose rollback then fails once. The record must not be
// stranded: a retry retries the cleanup and seals again.
func TestSealRetriesFailedSetPhase(t *testing.T) {
	x := newStorageSimulation(t)
	r := x.working()
	s := x.s
	const commit = "sealed-phase"

	// setPhase is the 10th and last effect of Seal.
	x.fault = len(x.trace) + 9
	x.mode = "before"
	s.testTeardownStep = func() error {
		s.testTeardownStep = nil
		return errors.New("injected teardown failure")
	}
	if _, err := s.Seal(context.Background(), r.ID, commit); err == nil {
		t.Fatal("seal succeeded despite the injected phase write failure")
	}
	x.mode = ""
	x.fault = -1
	if rec, ok := x.diskRecords()[commit]; !ok || rec.Phase != phaseCreating {
		t.Fatalf("commit record after failed rollback = %+v, %v; want phase creating", rec, ok)
	}

	if size, err := s.Seal(context.Background(), r.ID, commit); err != nil {
		t.Fatalf("seal retry after failed phase write: %v", err)
	} else if size != r.Size {
		t.Fatalf("seal retry size = %d, want %d", size, r.Size)
	}
	if rec := s.vols[commit]; rec == nil || rec.Phase != phaseReady {
		t.Fatalf("sealed record after retry = %+v", rec)
	}
	if got := x.thin[s.vols[commit].Thin][1]; got != "base" {
		t.Fatalf("sealed content = %q, want base", got)
	}
	x.checkOwnership()
}
