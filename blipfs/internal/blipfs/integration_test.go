package blipfs

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The integration test needs a real storage account and /dev/fuse:
//
//	BLIPFS_ACCOUNT_URL=https://<account>.blob.core.windows.net go test -run Integration ./internal/blipfs/
//
// (or BLIPFS_CONN=<connection string>). It creates and deletes a container.
func testConfig(t *testing.T) Config {
	url, conn := os.Getenv("BLIPFS_ACCOUNT_URL"), os.Getenv("BLIPFS_CONN")
	if url == "" && conn == "" {
		t.Skip("set BLIPFS_ACCOUNT_URL or BLIPFS_CONN to run integration tests")
	}
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skip("no /dev/fuse")
	}
	dir := t.TempDir()
	return Config{
		Conn: conn, AccountURL: url,
		Container:  "blipfs-it-" + randHex(4),
		Slots:      1024,
		TmpDir:     filepath.Join(dir, "tmp"),
		Standalone: true,
		Socket:     filepath.Join(dir, "s.sock"),
		Host:       "it",
	}
}

func TestIntegration(t *testing.T) {
	cfg := testConfig(t)
	ctx := context.Background()
	v, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		st, err := NewStore(cfg.Conn, cfg.AccountURL, cfg.Container)
		if err == nil {
			st.DeleteContainer(context.Background())
		}
	})
	closed := false
	defer func() {
		if !closed {
			v.Close()
		}
	}()

	run := func(cwd string, args ...string) string {
		t.Helper()
		out, code := v.runCmd(ctx, args, cwd)
		if code != 0 {
			t.Fatalf("blipfs %s: %s", strings.Join(args, " "), out)
		}
		return out
	}
	write := func(p, s string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	expect := func(p, want string) {
		t.Helper()
		got, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Fatalf("%s = %q, want %q", p, got, want)
		}
	}

	mm, mf := t.TempDir(), t.TempDir()
	run("", "mount", "main", mm)

	big := make([]byte, 3<<20+12345)
	rand.Read(big)
	write(filepath.Join(mm, "a.txt"), "line1\nline2\nline3\n")
	if err := os.WriteFile(filepath.Join(mm, "big"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(mm, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(mm, "d", "s.txt"), "small")
	if err := os.Symlink("d/s.txt", filepath.Join(mm, "ln")); err != nil {
		t.Fatal(err)
	}
	expect(filepath.Join(mm, "ln"), "small")

	// Fork and change both sides without conflicts.
	run("", "fork", "main", "feat")
	run("", "mount", "feat", mf)
	expect(filepath.Join(mf, "a.txt"), "line1\nline2\nline3\n")
	write(filepath.Join(mm, "a.txt"), "LINE1\nline2\nline3\n")
	write(filepath.Join(mf, "a.txt"), "line1\nline2\nLINE3\n")
	write(filepath.Join(mf, "f.txt"), "new on feat\n")
	if err := os.Remove(filepath.Join(mf, "d", "s.txt")); err != nil {
		t.Fatal(err)
	}
	if out := run("", "diff", "main", "feat"); !strings.Contains(out, "A /f.txt") {
		t.Fatalf("diff output:\n%s", out)
	}
	run("", "merge", "feat", "--into", "main")
	expect(filepath.Join(mm, "a.txt"), "LINE1\nline2\nLINE3\n")
	expect(filepath.Join(mm, "f.txt"), "new on feat\n")
	if _, err := os.Stat(filepath.Join(mm, "d", "s.txt")); !os.IsNotExist(err) {
		t.Fatalf("d/s.txt should be gone after merge: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(mm, "big")); !bytes.Equal(got, big) {
		t.Fatal("big file differs")
	}

	// Conflicting edits go through a merge workspace.
	write(filepath.Join(mm, "a.txt"), "LINE1\nmain\nLINE3\n")
	write(filepath.Join(mf, "a.txt"), "line1\nfeat\nLINE3\n")
	out := run(mm, "merge", "feat")
	m := regexp.MustCompile(`\.blipfs/merge/([^/]+)/work`).FindStringSubmatch(out)
	if !strings.Contains(out, "CONFLICT: /a.txt") || m == nil {
		t.Fatalf("expected conflict, got:\n%s", out)
	}
	work := filepath.Join(mm, ".blipfs", "merge", m[1], "work")
	got, err := os.ReadFile(filepath.Join(work, "a.txt"))
	if err != nil || !strings.Contains(string(got), "<<<<<<< ours") {
		t.Fatalf("work/a.txt = %q, %v", got, err)
	}
	expect(filepath.Join(mm, ".blipfs", "merge", m[1], "theirs", "a.txt"), "line1\nfeat\nLINE3\n")
	if _, code := v.runCmd(ctx, []string{"merge", "--continue"}, mm); code == 0 {
		t.Fatal("merge --continue succeeded with unresolved conflicts")
	}
	write(filepath.Join(work, "a.txt"), "LINE1\nboth\nLINE3\n")
	run(work, "resolve", "a.txt")
	run(mm, "merge", "--continue")
	expect(filepath.Join(mm, "a.txt"), "LINE1\nboth\nLINE3\n")

	// Time travel and revert.
	log := run(mm, "log", "--", "a.txt")
	revs := regexp.MustCompile(`(?m)^(main@\d+)`).FindAllStringSubmatch(log, -1)
	if len(revs) < 3 {
		t.Fatalf("log:\n%s", log)
	}
	head := revs[0][1]
	expect(filepath.Join(mm, ".blipfs", "rev", head, "a.txt"), "LINE1\nboth\nLINE3\n")
	run(mm, "revert", head)
	expect(filepath.Join(mm, "a.txt"), "LINE1\nmain\nLINE3\n")

	// GC removes a chunk nothing references and keeps everything else.
	defer func(g time.Duration) { gcGrace = g }(gcGrace)
	gcGrace = 0
	orphan := make([]byte, 100<<10)
	rand.Read(orphan)
	packs := map[string]bool{}
	ent := v.chunks.upload(orphan, packs)
	if err := v.chunks.flush(ctx, packs); err != nil {
		t.Fatal(err)
	}
	ops := []Op{{Kind: OpChunkPut, Chunks: []ChunkEnt{ent}}}
	if _, err := v.writeRecord(ctx, RecCommit, streamsFor(ops), ops); err != nil {
		t.Fatal(err)
	}
	if out := run("", "gc"); !strings.Contains(out, "removed 1 orphan") {
		t.Fatalf("gc: %s", out)
	}
	run("", "gc")

	run("", "umount", mf)
	run("", "umount", mm)
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	closed = true

	// Everything survives a restart (served from the checkpoint and WAL).
	v, err = Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	closed = false
	run("", "mount", "main", mm)
	expect(filepath.Join(mm, "a.txt"), "LINE1\nmain\nLINE3\n")
	expect(filepath.Join(mm, "f.txt"), "new on feat\n")
	if l, err := os.Readlink(filepath.Join(mm, "ln")); err != nil || l != "d/s.txt" {
		t.Fatalf("readlink ln = %q, %v", l, err)
	}
	if got, _ := os.ReadFile(filepath.Join(mm, "big")); !bytes.Equal(got, big) {
		t.Fatal("big file differs after restart")
	}
	if out := run("", "branches"); !strings.Contains(out, "feat") {
		t.Fatalf("branches:\n%s", out)
	}
}
