package node

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Azure/blip/internal/podapi"
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
