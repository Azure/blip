package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Azure/blip/api/v1alpha1"
)

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func writeCollectFile(t *testing.T, root, state, name, content string, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(root, state, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCollectFiles(t *testing.T) {
	root := withCollectMountRoot(t)
	worker := ownedBlip("alice.w1", "alice.w1")
	worker.Status.Phase = v1alpha1.BlipSucceeded
	h := newHarness(t, ownedBlip("alice.box", "alice.home"), worker, readyState("alice.w1"))
	h.self = "alice.box"
	writeCollectFile(t, root, "alice.w1", "/home/dev/out/a.log", "hello\n", 0o640)
	writeCollectFile(t, root, "alice.w1", "/home/dev/out/sub/b.sh", "#!/bin/sh\n", 0o755)
	if err := os.Symlink("a.log", filepath.Join(root, "alice.w1", "home/dev/out/link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(root, "alice.w1", "home/dev/out/escape")); err != nil {
		t.Fatal(err)
	}

	t.Run("single file", func(t *testing.T) {
		dst := filepath.Join(t.TempDir(), "a.log")
		code, _, errOut := h.run("", "collect", "w1", "/home/dev/out/a.log:"+dst)
		if code != 0 {
			t.Fatalf("code %d: %s", code, errOut)
		}
		if got := readFile(t, dst); got != "hello\n" {
			t.Fatalf("content = %q", got)
		}
		if info, err := os.Stat(dst); err != nil || info.Mode().Perm() != 0o640 {
			t.Fatalf("mode = %v %v", info, err)
		}
		assertCollectReleased(t, h, "alice.box", "alice.w1")
	})

	t.Run("relative destination creates parents", func(t *testing.T) {
		dir := t.TempDir()
		t.Chdir(dir)
		code, _, errOut := h.run("", "collect", "w1", "/home/dev/out/a.log:nested/deep/a.log")
		if code != 0 {
			t.Fatalf("code %d: %s", code, errOut)
		}
		if got := readFile(t, filepath.Join(dir, "nested/deep/a.log")); got != "hello\n" {
			t.Fatalf("content = %q", got)
		}
		assertCollectReleased(t, h, "alice.box", "alice.w1")
	})

	t.Run("directory", func(t *testing.T) {
		dst := filepath.Join(t.TempDir(), "artifacts")
		code, _, errOut := h.run("", "collect", "w1", "/home/dev/out:"+dst)
		if code != 0 {
			t.Fatalf("code %d: %s", code, errOut)
		}
		if got := readFile(t, filepath.Join(dst, "a.log")); got != "hello\n" {
			t.Fatalf("a.log = %q", got)
		}
		if info, err := os.Stat(filepath.Join(dst, "sub/b.sh")); err != nil || info.Mode().Perm() != 0o755 {
			t.Fatalf("b.sh mode = %v %v", info, err)
		}
		if target, err := os.Readlink(filepath.Join(dst, "link")); err != nil || target != "a.log" {
			t.Fatalf("link = %q %v", target, err)
		}
		// A symlink is copied as a link, not followed.
		if target, err := os.Readlink(filepath.Join(dst, "escape")); err != nil || target != "/etc/passwd" {
			t.Fatalf("escape = %q %v", target, err)
		}
		assertCollectReleased(t, h, "alice.box", "alice.w1")
	})

	t.Run("symlinked parent cannot escape", func(t *testing.T) {
		if err := os.Symlink("/etc", filepath.Join(root, "alice.w1", "home/dev/evil")); err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(t.TempDir(), "passwd")
		code, _, errOut := h.run("", "collect", "w1", "/home/dev/evil/passwd:"+dst)
		if code != 1 || !strings.Contains(errOut, "escapes state") {
			t.Fatalf("code %d stderr %q", code, errOut)
		}
		assertCollectReleased(t, h, "alice.box", "alice.w1")
	})

	t.Run("overwrite and existing directory", func(t *testing.T) {
		dir := t.TempDir()
		dst := filepath.Join(dir, "a.log")
		if err := os.WriteFile(dst, []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
		if code, _, errOut := h.run("", "collect", "w1", "/home/dev/out/a.log:"+dst); code != 0 {
			t.Fatalf("code %d: %s", code, errOut)
		}
		if got := readFile(t, dst); got != "hello\n" {
			t.Fatalf("overwritten content = %q", got)
		}
		assertCollectReleased(t, h, "alice.box", "alice.w1")
		// A file copied into an existing directory keeps its name.
		if code, _, errOut := h.run("", "collect", "w1", "/home/dev/out/a.log:"+dir); code != 0 {
			t.Fatalf("code %d: %s", code, errOut)
		}
		if got := readFile(t, filepath.Join(dir, "a.log")); got != "hello\n" {
			t.Fatalf("content = %q", got)
		}
		assertCollectReleased(t, h, "alice.box", "alice.w1")
	})

	t.Run("missing source releases mount", func(t *testing.T) {
		dst := filepath.Join(t.TempDir(), "missing")
		code, _, errOut := h.run("", "collect", "w1", "/home/dev/out/missing:"+dst)
		if code != 1 || !strings.Contains(errOut, "collect /home/dev/out/missing") {
			t.Fatalf("code %d stderr %q", code, errOut)
		}
		assertCollectReleased(t, h, "alice.box", "alice.w1")
	})

	t.Run("type mismatch", func(t *testing.T) {
		dst := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(dst, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		code, _, errOut := h.run("", "collect", "w1", "/home/dev/out:"+dst)
		if code != 1 || !strings.Contains(errOut, "not a directory") {
			t.Fatalf("code %d stderr %q", code, errOut)
		}
		assertCollectReleased(t, h, "alice.box", "alice.w1")
	})
}

func TestCollectMultipleStatesAndOps(t *testing.T) {
	root := withCollectMountRoot(t)
	worker := ownedBlip("alice.w1", "alice.w1", v1alpha1.Mount{State: "alice.repo", Path: "/work"})
	worker.Status.Phase = v1alpha1.BlipSucceeded
	h := newHarness(t, ownedBlip("alice.box", "alice.home"), worker, readyState("alice.w1"), readyState("alice.repo"))
	h.self = "alice.box"
	writeCollectFile(t, root, "alice.w1", "/home/dev/log", "root state\n", 0o644)
	writeCollectFile(t, root, "alice.repo", "/out.txt", "mounted state\n", 0o644)

	dir := t.TempDir()
	dst1, dst2 := filepath.Join(dir, "log"), filepath.Join(dir, "out.txt")
	code, _, errOut := h.run("", "collect", "w1",
		"/home/dev/log:"+dst1, "/work/out.txt:"+dst2)
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if got := readFile(t, dst1); got != "root state\n" {
		t.Fatalf("log = %q", got)
	}
	if got := readFile(t, dst2); got != "mounted state\n" {
		t.Fatalf("out = %q", got)
	}
	assertCollectReleased(t, h, "alice.box", "alice.w1")
	assertCollectReleased(t, h, "alice.box", "alice.repo")
}

func TestCollectRejectsStaleMount(t *testing.T) {
	defer func(r string) { collectMountRoot = r }(collectMountRoot)
	collectMountRoot = "/run/blip-collect"
	worker := ownedBlip("alice.w1", "alice.w1")
	worker.Status.Phase = v1alpha1.BlipSucceeded
	caller := ownedBlip("alice.box", "alice.home", v1alpha1.Mount{State: "alice.w1", Path: "/w1"})
	caller.Status.Mounts = []v1alpha1.MountStatus{{State: "alice.w1", Path: "/w1", Phase: v1alpha1.MountMounted, CommitID: "old"}}
	h := newHarness(t, caller, worker, readyState("alice.w1"))
	h.self = "alice.box"
	a := &app{env: h.env(strings.NewReader(""), io.Discard, io.Discard)}
	ctx := context.Background()
	if _, _, err := a.collectMount(ctx, "alice.w1"); err == nil || !strings.Contains(err.Error(), "older version") {
		t.Fatalf("reused a stale mount: %v", err)
	}

	// Once the mount pins the committed version, collect reuses it.
	b := h.blip("alice.box")
	b.Status.Mounts[0].CommitID = h.state("alice.w1").Status.Committed.ID
	if err := h.kube.Status().Update(ctx, b); err != nil {
		t.Fatal(err)
	}
	dir, cleanup, err := a.collectMount(ctx, "alice.w1")
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	if dir != "/w1" {
		t.Fatalf("dir = %q", dir)
	}
}

func TestCollectWaitsForState(t *testing.T) {
	root := withCollectMountRoot(t)
	worker := ownedBlip("alice.w1", "alice.w1")
	worker.Status.Phase = v1alpha1.BlipSucceeded
	inUse := readyState("alice.w1")
	inUse.Status.Phase = v1alpha1.StateInUse
	inUse.Status.Writer = &v1alpha1.Writer{BlipName: "alice.w1"}
	h := newHarness(t, ownedBlip("alice.box", "alice.home"), worker, inUse)
	h.self = "alice.box"
	writeCollectFile(t, root, "alice.w1", "/home/dev/done", "saved\n", 0o644)

	dst := filepath.Join(t.TempDir(), "done")
	waiting := make(chan struct{}, 1)
	env := h.env(strings.NewReader(""), io.Discard, writerFunc(func(p []byte) (int, error) {
		select {
		case waiting <- struct{}{}:
		default:
		}
		return len(p), nil
	}))
	env.ProgressDelay = 0
	type result struct {
		code   int
		errOut string
	}
	done := make(chan result, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		var errOut strings.Builder
		env.Err = io.MultiWriter(env.Err, &errOut)
		done <- result{Main(ctx, env, []string{"collect", "w1", "/home/dev/done:" + dst}), errOut.String()}
	}()
	select {
	case <-waiting:
	case r := <-done:
		t.Fatalf("collect returned while the state was busy: code %d: %s", r.code, r.errOut)
	case <-time.After(5 * time.Second):
		t.Fatal("collect did not report that it was waiting")
	}
	select {
	case r := <-done:
		t.Fatalf("collect returned while the state was busy: code %d: %s", r.code, r.errOut)
	default:
	}
	st := h.state("alice.w1")
	st.Status.Phase = v1alpha1.StateReady
	st.Status.Writer = nil
	if err := h.kube.Status().Update(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		if r.code != 0 {
			t.Fatalf("collect failed after the state became ready: %s", r.errOut)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("collect did not resume")
	}
	if got := readFile(t, dst); got != "saved\n" {
		t.Fatalf("content = %q", got)
	}
	assertCollectReleased(t, h, "alice.box", "alice.w1")
}
