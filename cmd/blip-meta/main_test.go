//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/example/blip/internal/meta"
)

func setup(t *testing.T) (string, *meta.Writer) {
	img := filepath.Join(t.TempDir(), "meta.img")
	if err := meta.Create(img); err != nil {
		t.Fatal(err)
	}
	w, err := meta.OpenWriter(img)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })
	return img, w
}

func readLink(t *testing.T, p string) string {
	s, err := os.Readlink(p)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCredsLayout(t *testing.T) {
	img, w := setup(t)
	dir := filepath.Join(t.TempDir(), "sa")
	w.WriteHost(&meta.HostData{AllocationID: "a", Credentials: &meta.Credentials{Token: "t1", CACrt: "ca", Namespace: "ns"}})
	if err := run(img, "creds", []string{"--dir", dir}); err != nil {
		t.Fatal(err)
	}
	data1 := readLink(t, filepath.Join(dir, "..data"))
	if !strings.HasPrefix(data1, "..20") {
		t.Fatal(data1)
	}
	for name, want := range map[string]string{"token": "t1", "ca.crt": "ca", "namespace": "ns"} {
		if l := readLink(t, filepath.Join(dir, name)); l != "..data/"+name {
			t.Fatal(name, l)
		}
		b, _ := os.ReadFile(filepath.Join(dir, name))
		if string(b) != want {
			t.Fatal(name, string(b))
		}
	}
	st, _ := os.Stat(filepath.Join(dir, "token"))
	if st.Mode().Perm() != 0o600 {
		t.Fatal(st.Mode())
	}

	// Unchanged: no rewrite.
	if changed, err := WriteCreds(dir, &meta.Credentials{Token: "t1", CACrt: "ca", Namespace: "ns"}); err != nil || changed {
		t.Fatal(changed, err)
	}
	// Rotation swaps ..data and removes the old dir.
	w.WriteHost(&meta.HostData{AllocationID: "a", Credentials: &meta.Credentials{Token: "t2", CACrt: "ca", Namespace: "ns"}})
	if err := run(img, "creds", []string{"--dir", dir}); err != nil {
		t.Fatal(err)
	}
	data2 := readLink(t, filepath.Join(dir, "..data"))
	if data2 == data1 {
		t.Fatal("..data not swapped")
	}
	if _, err := os.Stat(filepath.Join(dir, data1)); !os.IsNotExist(err) {
		t.Fatal("old dir kept", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "token")); string(b) != "t2" {
		t.Fatal(string(b))
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 5 { // ..ts, ..data, 3 links
		t.Fatal(len(ents))
	}
}

func TestCredsMissing(t *testing.T) {
	img, w := setup(t)
	w.WriteHost(&meta.HostData{AllocationID: "a"})
	if err := run(img, "creds", []string{"--dir", t.TempDir()}); err == nil {
		t.Fatal("expected error")
	}
}

func TestExitPreservesGuest(t *testing.T) {
	img, w := setup(t)
	d, _ := meta.Open(img)
	d.WriteGuest(&meta.GuestData{State: meta.StateExec, BootCount: 2})
	d.Close()
	if err := run(img, "exit", []string{"7"}); err != nil {
		t.Fatal(err)
	}
	g, err := w.ReadGuest()
	if err != nil || g.ExitCode == nil || *g.ExitCode != 7 || g.State != meta.StateExec || g.BootCount != 2 || g.Seq != 2 {
		t.Fatalf("%+v %v", g, err)
	}
}

func TestWaitTimeout(t *testing.T) {
	img, w := setup(t)
	if err := run(img, "wait", []string{"--timeout", "100ms"}); err == nil {
		t.Fatal("expected timeout")
	}
	w.WriteHost(&meta.HostData{AllocationID: "a"})
	if err := run(img, "wait", []string{"--timeout", "1s"}); err != nil {
		t.Fatal(err)
	}
}
