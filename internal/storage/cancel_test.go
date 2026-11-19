package storage

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestRunInContextKillsProcessGroup ensures cancelling a long filesystem tool
// also stops helpers it spawned. Without the process-group kill, mkfs would
// outlive a deleted state's build and keep consuming the thin pool.
func TestRunInContextKillsProcessGroup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	_, err := runInContext(ctx, "", nil, "sh", "-c", "sleep 60")
	if err == nil {
		t.Fatal("cancelled command succeeded")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("cancelled command took %s", elapsed)
	}
}

// TestCreateCommitCancelledContextRollsBack checks that a build rejected
// before it starts does not leave a volume or thin ID behind. The operation
// cursor still runs its compensations after cancellation.
func TestCreateCommitCancelledContextRollsBack(t *testing.T) {
	x := newStorageSimulation(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := x.s.CreateCommit(ctx, CreateCommit{CommitID: "cancelled", SizeBytes: 8 * blockSize})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("CreateCommit = %v, want context.Canceled", err)
	}
	if _, ok := x.s.Get("cancelled"); ok {
		t.Fatal("cancelled commit is visible")
	}
	if r := x.diskRecords()["cancelled"]; r.ID != "" {
		t.Fatalf("cancelled commit record left behind: %+v", r)
	}
	if len(x.thin) != 0 || len(x.dm) != 0 {
		t.Fatalf("cancelled commit left devices: thin=%v dm=%v", x.thin, x.dm)
	}
	x.checkOwnership()
}
