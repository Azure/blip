// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/blip/api/v1alpha1"
	"golang.org/x/sys/unix"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
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
		code, _, errOut := h.collect("w1", "/home/dev/out/a.log:"+dst)
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
		code, _, errOut := h.collect("w1", "/home/dev/out/a.log:nested/deep/a.log")
		if code != 0 {
			t.Fatalf("code %d: %s", code, errOut)
		}
		if got := readFile(t, filepath.Join(dir, "nested/deep/a.log")); got != "hello\n" {
			t.Fatalf("content = %q", got)
		}
		assertCollectReleased(t, h, "alice.box", "alice.w1")
	})

	t.Run("relative parent destination", func(t *testing.T) {
		base := t.TempDir()
		child := filepath.Join(base, "child")
		if err := os.MkdirAll(child, 0o755); err != nil {
			t.Fatal(err)
		}
		t.Chdir(child)
		if code, _, errOut := h.collect("w1", "/home/dev/out/a.log:../out/a.log"); code != 0 {
			t.Fatalf("code %d: %s", code, errOut)
		}
		if got := readFile(t, filepath.Join(base, "out/a.log")); got != "hello\n" {
			t.Fatalf("content = %q", got)
		}
		assertCollectReleased(t, h, "alice.box", "alice.w1")
	})

	t.Run("directory", func(t *testing.T) {
		dst := filepath.Join(t.TempDir(), "artifacts")
		code, _, errOut := h.collect("w1", "/home/dev/out:"+dst)
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

	t.Run("read-only source directory", func(t *testing.T) {
		roSrc := filepath.Join(root, "alice.w1", "home/dev/ro")
		sub := filepath.Join(roSrc, "sub")
		if err := os.MkdirAll(sub, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(roSrc, "f"), []byte("f\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sub, "g"), []byte("g\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(sub, 0o500); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(roSrc, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(sub, 0o755) })
		t.Cleanup(func() { os.Chmod(roSrc, 0o755) })

		dst := filepath.Join(t.TempDir(), "ro")
		code, _, errOut := h.collect("w1", "/home/dev/ro:"+dst)
		if code != 0 {
			t.Fatalf("code %d: %s", code, errOut)
		}
		if got := readFile(t, filepath.Join(dst, "f")); got != "f\n" {
			t.Fatalf("f = %q", got)
		}
		if got := readFile(t, filepath.Join(dst, "sub/g")); got != "g\n" {
			t.Fatalf("sub/g = %q", got)
		}
		if info, err := os.Stat(dst); err != nil || info.Mode().Perm() != 0o555 {
			t.Fatalf("mode = %v %v", info, err)
		}
		if info, err := os.Stat(filepath.Join(dst, "sub")); err != nil || info.Mode().Perm() != 0o500 {
			t.Fatalf("sub mode = %v %v", info, err)
		}
		t.Cleanup(func() { os.Chmod(dst, 0o755) })
		t.Cleanup(func() { os.Chmod(filepath.Join(dst, "sub"), 0o755) })
		assertCollectReleased(t, h, "alice.box", "alice.w1")
	})

	t.Run("destination parent symlink cannot escape", func(t *testing.T) {
		base := t.TempDir()
		outside := filepath.Join(base, "outside")
		dest := filepath.Join(base, "dest")
		if err := os.MkdirAll(outside, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(dest, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(dest, "sub")); err != nil {
			t.Fatal(err)
		}
		code, _, errOut := h.collect("w1", "/home/dev/out/a.log:"+filepath.Join(dest, "sub/x"))
		if code != 1 || !strings.Contains(errOut, "symlink") {
			t.Fatalf("code %d stderr %q", code, errOut)
		}
		if _, err := os.Stat(filepath.Join(outside, "x")); !os.IsNotExist(err) {
			t.Fatalf("wrote through destination symlink: %v", err)
		}
		// A file copied to a symlinked directory follows it when stat'ing
		// the destination, so the parent check has to run after that.
		if code, _, _ := h.collect("w1", "/home/dev/out/a.log:"+filepath.Join(dest, "sub")); code != 1 {
			t.Fatalf("code %d, want 1", code)
		}
		if _, err := os.Stat(filepath.Join(outside, "a.log")); !os.IsNotExist(err) {
			t.Fatalf("wrote into symlinked destination directory: %v", err)
		}
		assertCollectReleased(t, h, "alice.box", "alice.w1")
	})

	t.Run("symlinked parent cannot escape", func(t *testing.T) {
		if err := os.Symlink("/etc", filepath.Join(root, "alice.w1", "home/dev/evil")); err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(t.TempDir(), "passwd")
		code, _, errOut := h.collect("w1", "/home/dev/evil/passwd:"+dst)
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
		if code, _, errOut := h.collect("w1", "/home/dev/out/a.log:"+dst); code != 0 {
			t.Fatalf("code %d: %s", code, errOut)
		}
		if got := readFile(t, dst); got != "hello\n" {
			t.Fatalf("overwritten content = %q", got)
		}
		assertCollectReleased(t, h, "alice.box", "alice.w1")
		// A file copied into an existing directory keeps its name.
		if code, _, errOut := h.collect("w1", "/home/dev/out/a.log:"+dir); code != 0 {
			t.Fatalf("code %d: %s", code, errOut)
		}
		if got := readFile(t, filepath.Join(dir, "a.log")); got != "hello\n" {
			t.Fatalf("content = %q", got)
		}
		assertCollectReleased(t, h, "alice.box", "alice.w1")
	})

	t.Run("missing source releases mount", func(t *testing.T) {
		dst := filepath.Join(t.TempDir(), "missing")
		code, _, errOut := h.collect("w1", "/home/dev/out/missing:"+dst)
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
		code, _, errOut := h.collect("w1", "/home/dev/out:"+dst)
		if code != 1 || !strings.Contains(errOut, "not a directory") {
			t.Fatalf("code %d stderr %q", code, errOut)
		}
		assertCollectReleased(t, h, "alice.box", "alice.w1")
	})
}

func TestCopyPathRejectsOverlap(t *testing.T) {
	t.Run("file onto itself is not truncated", func(t *testing.T) {
		src := filepath.Join(t.TempDir(), "f")
		if err := os.WriteFile(src, []byte("keep\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		err := copyPath(context.Background(), src, src)
		if err == nil || !strings.Contains(err.Error(), "same file") {
			t.Fatalf("err = %v", err)
		}
		if got := readFile(t, src); got != "keep\n" {
			t.Fatalf("source was modified: %q", got)
		}
	})

	t.Run("directory into itself", func(t *testing.T) {
		src := filepath.Join(t.TempDir(), "d")
		if err := os.MkdirAll(filepath.Join(src, "sub"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(src, "sub", "f"), []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		for _, dst := range []string{src, filepath.Join(src, "out")} {
			err := copyPath(context.Background(), src, dst)
			if err == nil || !strings.Contains(err.Error(), "into itself") {
				t.Fatalf("copy to %s: err = %v", dst, err)
			}
		}
		if _, err := os.Stat(filepath.Join(src, "out")); !os.IsNotExist(err) {
			t.Fatalf("destination was created before rejecting: %v", err)
		}
	})
}

// Collecting a directory into ".", "..", or "/" must not stage inside the
// destination it is walking: the staging tree would be copied into itself
// until the path exceeds PATH_MAX.
func TestCopyTreeIntoDotAndDotDot(t *testing.T) {
	for _, tc := range []struct {
		name string
		cwd  string
		dst  string
	}{
		{name: "dot", cwd: "work", dst: "."},
		{name: "dotdot", cwd: "work/deep", dst: ".."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			src := filepath.Join(base, "src")
			if err := os.MkdirAll(filepath.Join(src, "sub"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(src, "root.txt"), []byte("ROOT\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(src, "sub", "child.txt"), []byte("CHILD\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			cwd := filepath.Join(base, tc.cwd)
			if err := os.MkdirAll(cwd, 0o755); err != nil {
				t.Fatal(err)
			}
			t.Chdir(cwd)

			if err := copyPath(context.Background(), src, tc.dst); err != nil {
				t.Fatal(err)
			}
			dst := filepath.Join(base, "work")
			if got := readFile(t, filepath.Join(dst, "root.txt")); got != "ROOT\n" {
				t.Fatalf("root.txt = %q", got)
			}
			if got := readFile(t, filepath.Join(dst, "sub", "child.txt")); got != "CHILD\n" {
				t.Fatalf("sub/child.txt = %q", got)
			}
			// The destination contains the working directory, so it must
			// still be a real, reachable path after the merge.
			if wd, err := os.Getwd(); err != nil || wd != cwd {
				t.Fatalf("cwd = %q, %v; want %q", wd, err, cwd)
			}
			assertNoTempFiles(t, dst)
			assertNoTempFiles(t, base)
		})
	}
}

func TestCopyTreePreservesExistingDestination(t *testing.T) {
	base := t.TempDir()
	src := filepath.Join(base, "src")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatal(err)
	}
	srcTime := time.Date(2019, 2, 3, 4, 5, 6, 0, time.UTC)
	if err := os.Chtimes(src, srcTime, srcTime); err != nil {
		t.Fatal(err)
	}

	// A destination the user already has keeps its mode and mtime.
	dst := filepath.Join(base, "existing")
	if err := os.Mkdir(dst, 0o700); err != nil {
		t.Fatal(err)
	}
	dstTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(dst, dstTime, dstTime); err != nil {
		t.Fatal(err)
	}
	if err := copyPath(context.Background(), src, dst); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("existing destination mode = %o, want 700", info.Mode().Perm())
	}
	if !info.ModTime().Equal(dstTime) {
		t.Fatalf("existing destination mtime = %v, want %v", info.ModTime(), dstTime)
	}

	// A destination this call creates takes the source's mode and mtime.
	created := filepath.Join(base, "created")
	if err := copyPath(context.Background(), src, created); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(created)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("created destination mode = %o, want 755", info.Mode().Perm())
	}
	if !info.ModTime().Equal(srcTime) {
		t.Fatalf("created destination mtime = %v, want %v", info.ModTime(), srcTime)
	}
}

func TestCopyPathCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	file := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(file, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "dst")
	if err := copyPath(ctx, file, dst); !errors.Is(err, context.Canceled) {
		t.Fatalf("file err = %v", err)
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatalf("file was written after cancellation: %v", err)
	}

	dir := filepath.Join(t.TempDir(), "d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dirDst := filepath.Join(t.TempDir(), "dd")
	if err := copyPath(ctx, dir, dirDst); !errors.Is(err, context.Canceled) {
		t.Fatalf("dir err = %v", err)
	}
	if _, err := os.Stat(dirDst); !os.IsNotExist(err) {
		t.Fatalf("directory was created after cancellation: %v", err)
	}

	// A copy in progress stops at the next chunk.
	if _, err := io.ReadAll(ctxReader{ctx: ctx, r: strings.NewReader("data")}); !errors.Is(err, context.Canceled) {
		t.Fatalf("reader err = %v", err)
	}
}

// A copy interrupted halfway must leave an existing destination untouched.
func TestCopyFileAtomicOnCancel(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "big")
	data := make([]byte, 128<<20)
	for i := range data {
		data[i] = byte(i)
	}
	if err := os.WriteFile(src, data, 0o644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(dst, []byte("GOOD"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- copyPath(ctx, src, dst) }()

	// Wait until the copy has started writing. With an atomic copy that is
	// the temporary file next to the destination.
	grown := func() bool {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return false
		}
		for _, e := range entries {
			if e.Name() == "big" {
				continue
			}
			info, err := e.Info()
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			if e.Name() != "dst" || info.Size() > int64(len("GOOD")) {
				if info.Size() > 0 {
					return true
				}
			}
		}
		return false
	}
	deadline := time.Now().Add(10 * time.Second)
	for !grown() {
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatal("copy never started writing")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("copy err = %v, want context.Canceled", err)
	}
	if got := readFile(t, dst); got != "GOOD" {
		t.Fatalf("destination changed to %d bytes after an interrupted copy", len(got))
	}
	assertNoTempFiles(t, dir)
}

// A directory copy that fails on a later child must not have replaced an
// earlier child of an existing destination.
// A destination already held by another collect must fail clearly instead of
// silently overwriting it.
func TestCopyPathLocksDestination(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("NEW"), 0o644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(dst, []byte("OLD"), 0o644); err != nil {
		t.Fatal(err)
	}
	unlock, err := lockDestination(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()

	err = copyPath(context.Background(), src, dst)
	if err == nil || !strings.Contains(err.Error(), "already being collected") {
		t.Fatalf("err = %v, want a destination-in-use error", err)
	}
	if got := readFile(t, dst); got != "OLD" {
		t.Fatalf("locked destination changed: %q", got)
	}
}

func TestCopyTreeAtomicOnFailure(t *testing.T) {
	base := t.TempDir()
	src := filepath.Join(base, "src")
	dst := filepath.Join(base, "dst")
	for _, d := range []string{src, dst} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("NEW"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "a.txt"), []byte("OLD"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "b.txt"), []byte("B-OLD"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A special file fails after a.txt was copied. ReadDir sorts names, so
	// a.txt comes first.
	if err := unix.Mkfifo(filepath.Join(src, "z.fifo"), 0o644); err != nil {
		t.Skipf("cannot create a fifo: %v", err)
	}
	err := copyPath(context.Background(), src, dst)
	if err == nil || !strings.Contains(err.Error(), "special file") {
		t.Fatalf("err = %v, want a special file error", err)
	}
	if got := readFile(t, filepath.Join(dst, "a.txt")); got != "OLD" {
		t.Fatalf("earlier child was replaced after a later one failed: %q", got)
	}
	if got := readFile(t, filepath.Join(dst, "b.txt")); got != "B-OLD" {
		t.Fatalf("destination child changed: %q", got)
	}
	assertNoTempFiles(t, base)
}

// Collect must not turn a sparse source into a dense destination.
func TestCopyFilePreservesSparseHoles(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "sparse")
	f, err := os.Create(src)
	if err != nil {
		t.Fatal(err)
	}
	const size = int64(16 << 20)
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("start"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("end"), size-3); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(src, &st); err != nil {
		t.Fatal(err)
	}
	if st.Blocks*512 > 1<<20 {
		t.Skipf("filesystem did not make the source sparse (%d allocated bytes)", st.Blocks*512)
	}

	dst := filepath.Join(dir, "dst")
	if err := copyPath(context.Background(), src, dst); err != nil {
		t.Fatal(err)
	}
	if err := unix.Stat(dst, &st); err != nil {
		t.Fatal(err)
	}
	if st.Size != size {
		t.Fatalf("size = %d, want %d", st.Size, size)
	}
	if allocated := int64(st.Blocks) * 512; allocated >= size/2 {
		t.Fatalf("destination is dense: %d allocated bytes for a %d byte sparse file", allocated, size)
	}
	out, err := os.Open(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	buf := make([]byte, 5)
	if _, err := out.ReadAt(buf, 0); err != nil || string(buf) != "start" {
		t.Fatalf("start = %q %v", buf, err)
	}
	if _, err := out.ReadAt(buf[:3], size-3); err != nil || string(buf[:3]) != "end" {
		t.Fatalf("end = %q %v", buf[:3], err)
	}
}

// assertNoTempFiles rejects staging paths left behind by a failed copy.
func assertNoTempFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), "blip-tmp") {
			t.Fatalf("temporary path %q was not cleaned up", filepath.Join(dir, e.Name()))
		}
	}
}

func TestCollectOwnRootState(t *testing.T) {
	root := withCollectMountRoot(t)
	defer func(r string) { collectSelfRoot = r }(collectSelfRoot)
	collectSelfRoot = filepath.Join(root, "alice.home")

	// The worker's root is the same state the caller runs on, and the caller
	// is writing it: collect must use / instead of waiting for a mount.
	worker := ownedBlip("alice.w1", "alice.home")
	worker.Status.Phase = v1alpha1.BlipSucceeded
	own := readyState("alice.home")
	own.Status.Phase = v1alpha1.StateInUse
	own.Status.Writer = &v1alpha1.Writer{BlipName: "alice.box"}
	h := newHarness(t, ownedBlip("alice.box", "alice.home"), worker, own)
	h.self = "alice.box"
	writeCollectFile(t, root, "alice.home", "/home/dev/x", "self\n", 0o644)

	dst := filepath.Join(t.TempDir(), "x")
	code, _, errOut := h.collect("w1", "/home/dev/x:"+dst)
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if got := readFile(t, dst); got != "self\n" {
		t.Fatalf("content = %q", got)
	}
	s := h.rootState("alice.box")
	if m := findSpecMount(s.Spec.Mounts, "alice.home"); m != nil {
		t.Fatalf("collect mounted the caller's root state: %+v", m)
	}
	if v := s.Annotations[v1alpha1.AnnotationCollectMounts]; v != "" {
		t.Fatalf("annotation = %q, want cleared", v)
	}
}

func TestCollectMultipleStatesAndOps(t *testing.T) {
	root := withCollectMountRoot(t)
	worker := ownedBlip("alice.w1", "alice.w1")
	worker.Status.Phase = v1alpha1.BlipSucceeded
	source := readyState("alice.w1")
	source.Spec.Mounts = []v1alpha1.Mount{{State: "alice.repo", Path: "/work"}}
	h := newHarness(t, ownedBlip("alice.box", "alice.home"), worker, source, readyState("alice.repo"))
	h.self = "alice.box"
	writeCollectFile(t, root, "alice.w1", "/home/dev/log", "root state\n", 0o644)
	writeCollectFile(t, root, "alice.repo", "/out.txt", "mounted state\n", 0o644)

	dir := t.TempDir()
	dst1, dst2 := filepath.Join(dir, "log"), filepath.Join(dir, "out.txt")
	code, _, errOut := h.collect("w1",
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
	var errOut strings.Builder
	a := h.app(strings.NewReader(""), io.Discard, io.MultiWriter(writerFunc(func(p []byte) (int, error) {
		select {
		case waiting <- struct{}{}:
		default:
		}
		return len(p), nil
	}), &errOut))
	a.env.ProgressDelay = 0
	type result struct {
		code   int
		errOut string
	}
	done := make(chan result, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		code := 0
		if err := a.collect(ctx, "w1", []string{"/home/dev/done:" + dst}); err != nil {
			code = 1
			var exit *ExitError
			if errors.As(err, &exit) {
				code = exit.Code
			}
		}
		done <- result{code, errOut.String()}
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

func TestCollectResolvesRootDesiredAndActualMounts(t *testing.T) {
	b := runningBlip("worker")
	root := readyState(b.Spec.State)
	root.Spec.Mounts = []v1alpha1.Mount{
		{State: "repo", Path: "/new"},
		{State: "replacement", Path: "/work"},
		{State: "nested", Path: "/work/deep"},
		{State: "abandoned", Path: "/old", BlipUID: "another-execution"},
	}
	b.Status.Mounts = []v1alpha1.MountStatus{{State: "repo", Path: "/work", Phase: v1alpha1.MountMounted}}
	for dir, want := range map[string][2]string{
		"/work/file":      {"repo", "/file"},
		"/work/deep/file": {"nested", "/file"},
		"/new/file":       {root.Name, "/new/file"},
		"/old/file":       {root.Name, "/old/file"},
		"/etc/file":       {root.Name, "/etc/file"},
	} {
		if state, rel := stateForPath(b, root, dir); state != want[0] || rel != want[1] {
			t.Errorf("%s resolved to %s:%s, want %s:%s", dir, state, rel, want[0], want[1])
		}
	}
}

// collectFixture supplies a runtime attachment while leaving desired intent
// empty, so concurrent acquisitions must create and count it atomically.
func collectFixture(t *testing.T) (*app, *v1alpha1.BlipState, *v1alpha1.Blip) {
	t.Helper()
	b := runningBlip("caller")
	root := readyState(b.Spec.State)
	root.Status.Writer = &v1alpha1.Writer{BlipName: b.Name, BlipUID: string(b.UID)}
	data := readyState("data")
	b.Status.Mounts = []v1alpha1.MountStatus{{
		State: data.Name, Path: filepath.Join(collectMountRoot, data.Name),
		Phase: v1alpha1.MountMounted, CommitID: data.Status.Committed.ID,
	}}
	a := mountTestApp(t, b, root, data)
	a.self = b
	return a, root, b
}

func TestCollectConcurrentMountOwnership(t *testing.T) {
	a, root, _ := collectFixture(t)
	// Force both acquisitions to read the same resource version. Exactly
	// one update succeeds; the other must retry its mount+refcount edit.
	var updates atomic.Int32
	ready := make(chan struct{})
	a.c.Kube = interceptor.NewClient(a.c.Kube, interceptor.Funcs{Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
		if obj.GetName() == root.Name {
			switch updates.Add(1) {
			case 1:
				select {
				case <-ready:
				case <-ctx.Done():
					return ctx.Err()
				}
			case 2:
				close(ready)
			}
		}
		return c.Update(ctx, obj, opts...)
	}})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type result struct {
		cleanup func()
		err     error
	}
	done := make(chan result, 2)
	for range 2 {
		go func() {
			_, cleanup, err := a.collectMount(ctx, "data")
			done <- result{cleanup, err}
		}()
	}
	var cleanups []func()
	for range 2 {
		r := <-done
		if r.err != nil {
			t.Fatal(r.err)
		}
		cleanups = append(cleanups, r.cleanup)
	}
	s, err := a.getState(ctx, root.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Spec.Mounts) != 1 || s.Spec.Mounts[0].BlipUID != string(a.self.UID) || mountUsers(s)["data"].Users != 2 {
		t.Fatalf("mounts %+v users %+v", s.Spec.Mounts, mountUsers(s))
	}
	cleanups[0]()
	cleanups[0]() // a cleanup is idempotent even while another collect uses it
	s, _ = a.getState(ctx, root.Name)
	if len(s.Spec.Mounts) != 1 || mountUsers(s)["data"].Users != 1 {
		t.Fatalf("removed another collect's mount: %+v %+v", s.Spec.Mounts, mountUsers(s))
	}
	cleanups[1]()
	s, _ = a.getState(ctx, root.Name)
	if len(s.Spec.Mounts) != 0 || len(mountUsers(s)) != 0 {
		t.Fatalf("last collect did not release: %+v %+v", s.Spec.Mounts, mountUsers(s))
	}
}

func TestCollectConcurrentWaitsForFreshAttachment(t *testing.T) {
	a, root, b := collectFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	mountPath := filepath.Join(collectMountRoot, "data")
	b.Status.Mounts[0] = v1alpha1.MountStatus{
		State: "data", Path: mountPath, Phase: v1alpha1.MountUnmounting,
		AttachmentID: "old-attachment", CommitID: "old-version",
	}
	if err := a.c.Kube.Status().Update(ctx, b); err != nil {
		t.Fatal(err)
	}
	waiting := make(chan struct{}, 2)
	a.env.ProgressDelay = 0
	a.env.Err = writerFunc(func(p []byte) (int, error) {
		if strings.Contains(string(p), "finish detaching") {
			select {
			case waiting <- struct{}{}:
			default:
			}
		}
		return len(p), nil
	})
	type result struct {
		cleanup func()
		err     error
	}
	done := make(chan result, 2)
	for range 2 {
		go func() {
			_, cleanup, err := a.collectMount(ctx, "data")
			done <- result{cleanup, err}
		}()
		// Neither collector may add the mount while the old attachment is
		// visible, or the controller could revive that attachment.
		select {
		case <-waiting:
		case r := <-done:
			t.Fatalf("collect returned before the old attachment detached: %v", r.err)
		case <-ctx.Done():
			t.Fatal("collect did not wait for the old attachment to detach")
		}
	}
	s, err := a.getState(ctx, root.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Spec.Mounts) != 0 {
		t.Fatalf("mount was re-added while the old attachment was visible: %+v", s.Spec.Mounts)
	}

	// The old mount detaches, then both collectors add and share one mount.
	b, err = a.getBlip(ctx, b.Name)
	if err != nil {
		t.Fatal(err)
	}
	b.Status.Mounts = nil
	if err := a.c.Kube.Status().Update(ctx, b); err != nil {
		t.Fatal(err)
	}
	for shared := false; !shared; {
		s, err = a.getState(ctx, root.Name)
		if err != nil {
			t.Fatal(err)
		}
		shared = mountUsers(s)["data"].Users == 2
		select {
		case r := <-done:
			t.Fatalf("collect returned before a new mount attached: %v", r.err)
		case <-time.After(time.Millisecond):
		}
	}
	if u := mountUsers(s)["data"]; u.PreviousAttachment != "" {
		t.Fatalf("stale attachment was carried into the new mount: %+v", u)
	}
	data, err := a.getState(ctx, "data")
	if err != nil {
		t.Fatal(err)
	}
	b, err = a.getBlip(ctx, b.Name)
	if err != nil {
		t.Fatal(err)
	}
	b.Status.Mounts = []v1alpha1.MountStatus{{
		State: "data", Path: mountPath, Phase: v1alpha1.MountMounted,
		AttachmentID: "new-attachment", CommitID: data.Status.Committed.ID,
	}}
	if err := a.c.Kube.Status().Update(ctx, b); err != nil {
		t.Fatal(err)
	}
	var cleanups []func()
	for range 2 {
		select {
		case r := <-done:
			if r.err != nil {
				t.Fatal(r.err)
			}
			cleanups = append(cleanups, r.cleanup)
		case <-ctx.Done():
			t.Fatal("collect did not accept the fresh attachment")
		}
	}
	for _, cleanup := range cleanups {
		cleanup()
	}
	s, err = a.getState(ctx, root.Name)
	if err != nil || len(s.Spec.Mounts) != 0 || len(mountUsers(s)) != 0 {
		t.Fatalf("temporary mount was not released: %+v %v", s, err)
	}
}

// TestCollectWaitsForOldAttachmentDetach covers back-to-back collects of one
// state: the second collect finds the previous read-only attachment still in
// status and must let it detach before adding the mount again.
func TestCollectWaitsForOldAttachmentDetach(t *testing.T) {
	a, root, b := collectFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	mountPath := filepath.Join(collectMountRoot, "data")
	b.Status.Mounts[0] = v1alpha1.MountStatus{
		State: "data", Path: mountPath, Phase: v1alpha1.MountUnmounting,
		AttachmentID: "old-attachment", CommitID: "old-version",
	}
	if err := a.c.Kube.Status().Update(ctx, b); err != nil {
		t.Fatal(err)
	}
	a.env.ProgressDelay = 0
	waiting := make(chan struct{}, 1)
	a.env.Err = writerFunc(func(p []byte) (int, error) {
		if strings.Contains(string(p), "finish detaching") {
			select {
			case waiting <- struct{}{}:
			default:
			}
		}
		return len(p), nil
	})
	type result struct {
		dir     string
		cleanup func()
		err     error
	}
	done := make(chan result, 1)
	go func() {
		dir, cleanup, err := a.collectMount(ctx, "data")
		done <- result{dir, cleanup, err}
	}()
	select {
	case <-waiting:
	case r := <-done:
		t.Fatalf("collect returned before the old attachment detached: %v", r.err)
	case <-ctx.Done():
		t.Fatal("collect did not report waiting for the old attachment")
	}
	s, err := a.getState(ctx, root.Name)
	if err != nil {
		t.Fatal(err)
	}
	if findSpecMount(s.Spec.Mounts, "data") != nil {
		t.Fatalf("mount was re-added while the old attachment was visible: %+v", s.Spec.Mounts)
	}

	// Detach the old mount; the collect then adds the mount and waits for
	// its fresh attachment.
	b, err = a.getBlip(ctx, b.Name)
	if err != nil {
		t.Fatal(err)
	}
	b.Status.Mounts = nil
	if err := a.c.Kube.Status().Update(ctx, b); err != nil {
		t.Fatal(err)
	}
	for added := false; !added; {
		s, err = a.getState(ctx, root.Name)
		if err != nil {
			t.Fatal(err)
		}
		added = findSpecMount(s.Spec.Mounts, "data") != nil
		select {
		case r := <-done:
			t.Fatalf("collect returned before a fresh attachment: %v", r.err)
		case <-time.After(time.Millisecond):
		}
	}
	data, err := a.getState(ctx, "data")
	if err != nil {
		t.Fatal(err)
	}
	b, err = a.getBlip(ctx, b.Name)
	if err != nil {
		t.Fatal(err)
	}
	b.Status.Mounts = []v1alpha1.MountStatus{{
		State: "data", Path: mountPath, Phase: v1alpha1.MountMounted,
		AttachmentID: "new-attachment", CommitID: data.Status.Committed.ID,
	}}
	if err := a.c.Kube.Status().Update(ctx, b); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("collect failed after the fresh attachment: %v", r.err)
		}
		if r.dir != mountPath {
			t.Fatalf("mount path %q, want %q", r.dir, mountPath)
		}
		r.cleanup()
	case <-ctx.Done():
		t.Fatal("collect did not accept the fresh attachment")
	}
	s, err = a.getState(ctx, root.Name)
	if err != nil || len(s.Spec.Mounts) != 0 || len(mountUsers(s)) != 0 {
		t.Fatalf("temporary mount was not released: %+v %v", s, err)
	}
}

func TestCollectManualAdoptionAndUnmount(t *testing.T) {
	a, root, _ := collectFixture(t)
	ctx := context.Background()
	dir, cleanup, err := a.collectMount(ctx, "data")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.unmountState(ctx, "data", root.Name); err == nil || !strings.Contains(err.Error(), "in use by collect") {
		t.Fatalf("manual unmount removed a borrowed mount: %v", err)
	}
	if err := a.mountState(ctx, "data", root.Name, dir, nil); err != nil {
		t.Fatal(err)
	}
	cleanup()
	s, _ := a.getState(ctx, root.Name)
	if len(s.Spec.Mounts) != 1 || s.Spec.Mounts[0].BlipUID != "" || len(mountUsers(s)) != 0 {
		t.Fatalf("adopted mount lost: %+v %+v", s.Spec.Mounts, mountUsers(s))
	}
}

func TestCollectCleanupProvenance(t *testing.T) {
	for _, change := range []string{"durable", "new token", "new lifetime", "lost annotation", "new root"} {
		t.Run(change, func(t *testing.T) {
			a, root, _ := collectFixture(t)
			ctx := context.Background()
			_, cleanup, err := a.collectMount(ctx, "data")
			if err != nil {
				t.Fatal(err)
			}
			s, _ := a.getState(ctx, root.Name)
			u := mountUsers(s)
			switch change {
			case "durable":
				s.Spec.Mounts[0].BlipUID = "" // intentionally leave stale annotation
			case "new token":
				entry := u["data"]
				entry.Token = "new-mount-instance"
				u["data"] = entry
				if err := setMountUsers(s, u); err != nil {
					t.Fatal(err)
				}
			case "new lifetime":
				s.Spec.Mounts[0].BlipUID = "new-execution"
			case "lost annotation":
				delete(s.Annotations, v1alpha1.AnnotationCollectMounts)
			case "new root":
				if err := a.c.Kube.Delete(ctx, s); err != nil {
					t.Fatal(err)
				}
				s.UID, s.ResourceVersion = "new-root", ""
				if err := a.c.Kube.Create(ctx, s); err != nil {
					t.Fatal(err)
				}
			}
			if change != "new root" {
				if err := a.c.Kube.Update(ctx, s); err != nil {
					t.Fatal(err)
				}
			}
			cleanup()
			s, _ = a.getState(ctx, root.Name)
			if len(s.Spec.Mounts) != 1 {
				t.Fatalf("stale cleanup removed replacement mount: %+v", s.Spec.Mounts)
			}
		})
	}
}

func TestCollectReusesDurableMountWithStaleAnnotation(t *testing.T) {
	a, root, _ := collectFixture(t)
	ctx := context.Background()
	s, _ := a.getState(ctx, root.Name)
	s.Spec.Mounts = []v1alpha1.Mount{{State: "data", Path: filepath.Join(collectMountRoot, "data")}}
	if err := setMountUsers(s, map[string]collectMountUse{"data": {
		CollectMountUse: v1alpha1.CollectMountUse{BlipUID: string(a.self.UID), Path: s.Spec.Mounts[0].Path},
		Token:           "abrupt-exit",
		Users:           1,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := a.c.Kube.Update(ctx, s); err != nil {
		t.Fatal(err)
	}
	_, cleanup, err := a.collectMount(ctx, "data")
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	s, _ = a.getState(ctx, root.Name)
	if len(s.Spec.Mounts) != 1 || s.Spec.Mounts[0].BlipUID != "" {
		t.Fatalf("durable mount removed: %+v", s.Spec.Mounts)
	}
}

// TestCollectBackToBackLoops runs collects of one state without a pause, the
// shape that used to copy from a mount path the previous collect had already
// detached.
func TestCollectBackToBackLoops(t *testing.T) {
	root := withCollectMountRoot(t)
	worker := ownedBlip("alice.w1", "alice.w1")
	worker.Status.Phase = v1alpha1.BlipSucceeded
	h := newHarness(t, ownedBlip("alice.box", "alice.home"), worker, readyState("alice.w1"))
	h.self = "alice.box"
	writeCollectFile(t, root, "alice.w1", "/home/dev/out/f.txt", "hello\n", 0o644)
	dir := t.TempDir()
	for i := range 10 {
		dst := filepath.Join(dir, fmt.Sprintf("f%d", i))
		code, _, errOut := h.collect("w1", "/home/dev/out/f.txt:"+dst)
		if code != 0 {
			t.Fatalf("cycle %d: code %d: %s", i, code, errOut)
		}
		if got := readFile(t, dst); got != "hello\n" {
			t.Fatalf("cycle %d: content %q", i, got)
		}
		assertCollectReleased(t, h, "alice.box", "alice.w1")
	}
}

func TestCollectConcurrentCleanupAndAdoption(t *testing.T) {
	a, root, _ := collectFixture(t)
	ctx := context.Background()
	dir, cleanup, err := a.collectMount(ctx, "data")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Go(cleanup)
	if err := a.mountState(ctx, "data", root.Name, dir, nil); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	s, _ := a.getState(ctx, root.Name)
	if len(s.Spec.Mounts) != 1 || s.Spec.Mounts[0].BlipUID != "" {
		t.Fatalf("adoption lost to cleanup: %+v", s.Spec.Mounts)
	}
}
