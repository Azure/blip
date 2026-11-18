package node

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Azure/blip/internal/podapi"
	"github.com/Azure/blip/internal/storage"
)

// TestExecuteTightensPodDir checks that writing Desired makes the pod tree
// root-only even when an older release (or kubelet) created it 0755.
func TestExecuteTightensPodDir(t *testing.T) {
	dataDir := t.TempDir()
	a := &Agent{cfg: Config{DataDir: dataDir}}
	key := pkey("p")
	podDir := a.podDirFor(key)
	nsDir := filepath.Dir(podDir)
	if err := os.MkdirAll(podDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(nsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	desired := filepath.Join(podDir, podapi.DesiredFile)
	if err := os.WriteFile(desired, []byte(`{"stop":false}`), 0o644); err != nil {
		t.Fatal(err)
	}

	a.execute(context.Background(), newView(), &plan{
		desired: map[string]podapi.Desired{key: {Stop: true}},
	})

	for _, p := range []string{nsDir, podDir} {
		if got := modeOf(t, p); got != podapi.DirMode {
			t.Errorf("%s mode %#o, want %#o", p, got, podapi.DirMode)
		}
	}
	if got := modeOf(t, desired); got != podapi.FileMode {
		t.Errorf("%s mode %#o, want %#o", desired, got, podapi.FileMode)
	}
	var d podapi.Desired
	if err := podapi.ReadJSON(desired, &d); err != nil || !d.Stop {
		t.Fatalf("desired %+v: %v", d, err)
	}
}

func modeOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

type sealTestStore struct {
	*fakeStore
	err error
}

func (s *sealTestStore) Seal(ctx context.Context, attachment, commit string) (int64, error) {
	if s.err != nil {
		return 0, s.err
	}
	return s.fakeStore.Seal(ctx, attachment, commit)
}

func TestSealRetryMachinePreservesWriterSafety(t *testing.T) {
	for _, tc := range []struct {
		name     string
		err      error
		attempts int
		terminal bool
	}{
		{"in use never gives up", storage.ErrInUse, 12, false},
		{"unclean reports immediately", storage.ErrUnclean, 1, true},
		{"other errors bounded", errors.New("disk I/O failure"), maxSealAttempts, true},
		{"success", nil, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := &sealTestStore{fakeStore: newFakeStore(), err: tc.err}
			a := &Agent{store: st, sealErrs: map[string]string{}}
			job := seal{attachmentID: "attachment", commitID: SealCommitID("attachment")}
			op := (&plan{seals: []seal{job}}).operations()
			now := testNow
			for i := 0; i < tc.attempts; i++ {
				started := a.operations.Schedule(now, op)
				if len(started) != 1 {
					t.Fatal("seal was not eligible at its deadline")
				}
				err := a.seal(context.Background(), job)
				terminal := tc.terminal && i == tc.attempts-1
				if (err == nil) != terminal {
					t.Fatalf("attempt %d: %v, terminal=%v", i+1, err, terminal)
				}
				outcome := Succeeded
				if err != nil {
					outcome = Failed
				}
				a.operations.Complete(now, started[0], outcome)
				if !terminal {
					var ok bool
					now, ok = a.operations.Deadline(now)
					if !ok {
						t.Fatal("retry has no deadline")
					}
				}
			}
			if got := a.sealErrs[job.attachmentID]; (got != "") != (tc.terminal && tc.err != nil) {
				t.Fatalf("unsafe terminal seal error: %q", got)
			}
		})
	}
}

func TestSealCancellationCannotBecomeTerminalFailure(t *testing.T) {
	st := &sealTestStore{fakeStore: newFakeStore(), err: context.Canceled}
	a := &Agent{store: st, sealErrs: map[string]string{}}
	job := seal{attachmentID: "attachment", commitID: SealCommitID("attachment")}
	ops := (&plan{seals: []seal{job}}).operations()
	now := testNow
	for range maxSealAttempts {
		attempt := a.operations.Schedule(now, ops)[0]
		a.operations.Complete(now, attempt, Failed)
		now = now.Add(2 * time.Minute)
	}
	if err := a.seal(context.Background(), job); !errors.Is(err, context.Canceled) || a.sealErrs[job.attachmentID] != "" {
		t.Fatalf("cancellation consumed writer safety: err=%v terminal=%v", err, a.sealErrs)
	}
}
