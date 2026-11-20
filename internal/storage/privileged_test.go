// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package storage

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Azure/blip/internal/image"
)

// Privileged tests touch the kernel (dm, loop). Run them only inside a
// disposable privileged container: hack/storage-test.sh.

var nodeSeq atomic.Int32

func privileged(t *testing.T) {
	t.Helper()
	if os.Getenv("BLIP_PRIVILEGED_TESTS") != "1" {
		t.Skip("set BLIP_PRIVILEGED_TESTS=1 (inside a disposable privileged container)")
	}
}

// testNode returns a node name unique to this run; hack/storage-cleanup.sh
// removes everything of blipt-<run>-<0..19>.
func testNode(t *testing.T) string {
	run := os.Getenv("BLIP_TEST_RUN")
	if run == "" {
		run = randHex(4)
	}
	n := nodeSeq.Add(1)
	if n >= 20 {
		t.Fatal("too many test nodes")
	}
	return fmt.Sprintf("blipt-%s-%d", run, n)
}

func openTest(t *testing.T) (*Store, Config) {
	t.Helper()
	privileged(t)
	cfg := Config{DataDir: t.TempDir(), NodeName: testNode(t), PoolBytes: 2 << 30, Key: testKey}
	s, err := Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.Close()
		RemoveNodeDevices(cfg.NodeName)
	})
	return s, cfg
}

var testKey = bytes.Repeat([]byte{0x5a}, KeySize)

// plain runs fn on a read-only plaintext view of image or commit id.
func plain(t *testing.T, s *Store, id string, fn func(dev string)) {
	t.Helper()
	mustActivate(t, s, id)
	r, err := s.lookup(id)
	must(t, err)
	must(t, s.withPlain(r, true, func(dev string) error { fn(dev); return nil }))
}

// RemoveNodeDevices removes every dm device of node (tests only).
func RemoveNodeDevices(node string) {
	prefix := DMPrefix(node) + "-"
	for range 5 {
		left := 0
		for name := range dmNames() {
			if strings.HasPrefix(name, prefix) && name != prefix+"pool" {
				dmRemove(name)
				left++
			}
		}
		if left == 0 {
			break
		}
	}
	dmRemove(prefix + "pool")
}

// mkImage builds an ext4 image of size bytes containing files.
func mkImage(t *testing.T, size int64, files map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	os.MkdirAll(root, 0o755)
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(root, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	img := filepath.Join(dir, "img")
	sh(t, "mkfs.ext4", "-q", "-F", "-b", "4096", "-d", root, img, fmt.Sprint(size/1024)+"k")
	return img
}

func sh(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

func catFile(t *testing.T, dev, name string) []byte {
	t.Helper()
	out, err := exec.Command("debugfs", "-R", "cat /"+name, dev).Output()
	if err != nil {
		t.Fatalf("debugfs cat %s on %s: %v", name, dev, err)
	}
	return out
}

func writeFile(t *testing.T, dev, name string, data []byte) {
	t.Helper()
	src := filepath.Join(t.TempDir(), "f")
	os.WriteFile(src, data, 0o644)
	sh(t, "debugfs", "-w", "-R", "write "+src+" "+name, dev)
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func hashDev(t *testing.T, dev string, size int64) string {
	t.Helper()
	f, err := os.Open(dev)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.CopyN(h, f, size); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func devSize(t *testing.T, dev string) int64 {
	t.Helper()
	f, err := os.Open(dev)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	n, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func importFile(t *testing.T, s *Store, digest, path string) int64 {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Every block is written: an unwritten block reads back as the
	// decryption of zeros, not as zeros.
	err = s.CreateImage(context.Background(), digest, st.Size(), func(dev string) error {
		out, err := exec.Command("dd", "if="+path, "of="+dev, "bs=64k", "conv=notrunc,fsync", "status=none").CombinedOutput()
		if err != nil {
			return fmt.Errorf("dd: %w: %s", err, out)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return st.Size()
}

func TestPrivilegedVolumes(t *testing.T) {
	s, _ := openTest(t)
	ctx := context.Background()
	payload := randBytes(3 << 20)
	img := mkImage(t, 64<<20, map[string][]byte{"payload": payload})
	imgID := "sha256:" + strings.Repeat("ab", 32)

	free := s.FreeBytes()
	size := importFile(t, s, imgID, img)
	plain(t, s, imgID, func(dev string) {
		if hashDev(t, dev, size) != hashDev(t, img, size) {
			t.Fatal("imported image differs from source")
		}
	})
	// The pool holds ciphertext only.
	raw, err := os.ReadFile(mustActivate(t, s, imgID))
	must(t, err)
	if bytes.Contains(raw, payload[:4096]) {
		t.Fatal("image stored in plaintext")
	}
	// Import is idempotent.
	importFile(t, s, imgID, img)

	// A commit may not be smaller than its image.
	if err := s.CreateCommit(ctx, CreateCommit{StateUID: "uid1", CommitID: "c000000000000009", FromImage: imgID, SizeBytes: 32 << 20}); err == nil || !strings.Contains(err.Error(), "needs") {
		t.Fatalf("CreateCommit smaller than image: %v", err)
	}
	if _, ok := s.Get("c000000000000009"); ok {
		t.Fatal("rejected commit left a volume")
	}

	// Commit from image, grown.
	if err := s.CreateCommit(ctx, CreateCommit{StateUID: "uid1", CommitID: "c000000000000001", FromImage: imgID, SizeBytes: 128 << 20}); err != nil {
		t.Fatal(err)
	}
	c1, err := s.Activate("c000000000000001")
	if err != nil {
		t.Fatal(err)
	}
	if got := devSize(t, c1); got != 128<<20 {
		t.Fatalf("commit size %d", got)
	}
	plain(t, s, "c000000000000001", func(dev string) {
		if out := sh(t, "dumpe2fs", "-h", dev); !strings.Contains(out, "Block count:              32768") {
			t.Fatalf("filesystem not grown:\n%s", out)
		}
		if !bytes.Equal(catFile(t, dev, "payload"), payload) {
			t.Fatal("payload lost in commit")
		}
	})

	// Empty commit.
	if err := s.CreateCommit(ctx, CreateCommit{StateUID: "uid2", CommitID: "e000000000000001", SizeBytes: 32 << 20}); err != nil {
		t.Fatal(err)
	}
	plain(t, s, "e000000000000001", func(dev string) { sh(t, "e2fsck", "-fn", dev) })

	// Copy commit.
	if err := s.CreateCommit(ctx, CreateCommit{StateUID: "uid3", CommitID: "f000000000000001", FromCommit: "c000000000000001"}); err != nil {
		t.Fatal(err)
	}
	v, ok := s.Get("f000000000000001")
	if !ok || v.StateUID != "uid3" || v.Base != "c000000000000001" || v.SizeBytes != 128<<20 {
		t.Fatalf("copy: %+v", v)
	}
	plain(t, s, "f000000000000001", func(dev string) {
		if !bytes.Equal(catFile(t, dev, "payload"), payload) {
			t.Fatal("payload lost in copy")
		}
	})

	// Working volume, write, seal.
	w, err := s.CreateWorking(ctx, CreateWorking{AttachmentID: "a000000000000001", StateUID: "uid1", FromCommit: "c000000000000001"})
	if err != nil {
		t.Fatal(err)
	}
	extra := randBytes(1 << 20)
	writeFile(t, w, "extra", extra)
	n, err := s.Seal(ctx, "a000000000000001", "c000000000000002")
	if err != nil || n != 128<<20 {
		t.Fatalf("seal: %d %v", n, err)
	}
	if n, err := s.Seal(ctx, "a000000000000001", "c000000000000002"); err != nil || n != 128<<20 {
		t.Fatalf("second seal: %d %v", n, err)
	}
	plain(t, s, "c000000000000002", func(dev string) {
		if !bytes.Equal(catFile(t, dev, "extra"), extra) || !bytes.Equal(catFile(t, dev, "payload"), payload) {
			t.Fatal("sealed commit content wrong")
		}
	})
	if v, _ := s.Get("c000000000000002"); v.StateUID != "uid1" || v.Base != "c000000000000001" {
		t.Fatalf("sealed commit: %+v", v)
	}

	// Unclean filesystem is refused.
	w2, err := s.CreateWorking(ctx, CreateWorking{AttachmentID: "a000000000000002", StateUID: "uid1", FromCommit: "c000000000000002"})
	if err != nil {
		t.Fatal(err)
	}
	sh(t, "debugfs", "-w", "-R", "feature needs_recovery", w2)
	if _, err := s.Seal(ctx, "a000000000000002", "c000000000000003"); !errors.Is(err, ErrUnclean) {
		t.Fatalf("seal of unclean fs: %v", err)
	}
	if _, ok := s.Get("c000000000000003"); ok {
		t.Fatal("unclean seal created a commit")
	}

	// Read-only working volume from an image, grown.
	ro, err := s.CreateWorking(ctx, CreateWorking{AttachmentID: "a000000000000003", FromImage: imgID, SizeBytes: 96 << 20, ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if f, err := os.OpenFile(ro, os.O_WRONLY, 0); err == nil {
		isRO, _ := unix.IoctlGetInt(int(f.Fd()), unix.BLKROGET)
		_, werr := f.WriteAt(make([]byte, 4096), 0)
		f.Close()
		if isRO != 1 || werr == nil {
			t.Fatalf("read-only working volume is writable (ro=%d, write err %v)", isRO, werr)
		}
	}
	if devSize(t, ro) != 96<<20 || !bytes.Equal(catFile(t, ro, "payload"), payload) {
		t.Fatal("read-only working volume wrong")
	}

	// Pins.
	if err := s.Pin("c000000000000002", "lease:x"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, "c000000000000002"); !errors.Is(err, ErrPinned) {
		t.Fatalf("delete pinned: %v", err)
	}
	s.Unpin("c000000000000002", "lease:x")

	// Open device refuses deletion.
	h, _ := os.Open(w)
	if err := s.Delete(ctx, "a000000000000001"); !errors.Is(err, ErrInUse) {
		t.Fatalf("delete open volume: %v", err)
	}
	if v, ok := s.Get("a000000000000001"); !ok || v.Device != w {
		t.Fatalf("refused delete hid the writer: %+v, %v", v, ok)
	}
	if dev, err := s.Activate("a000000000000001"); err != nil || dev != w {
		t.Fatalf("activate after refused delete: %q, %v", dev, err)
	}
	h.Close()
	if _, err := s.Seal(ctx, "a000000000000001", "c000000000000002"); err != nil {
		t.Fatalf("seal after refused delete: %v", err)
	}

	for _, id := range []string{"a000000000000001", "a000000000000002", "a000000000000003", "c000000000000002", "c000000000000001", "f000000000000001", "e000000000000001", imgID} {
		if err := s.Delete(ctx, id); err != nil {
			t.Fatalf("delete %s: %v", id, err)
		}
	}
	if l := s.List(); len(l) != 0 {
		t.Fatalf("volumes left: %+v", l)
	}
	if left := free - s.FreeBytes(); left != 0 {
		t.Fatalf("%d pool bytes still allocated", left)
	}
	for name := range dmNames() {
		if strings.HasPrefix(name, s.prefix) && name != s.poolName() {
			t.Fatalf("device %s left", name)
		}
	}
}

func TestPrivilegedCreateImageFillError(t *testing.T) {
	s, _ := openTest(t)
	imgID := "sha256:" + strings.Repeat("cd", 32)
	var filled string
	err := s.CreateImage(context.Background(), imgID, 32<<20, func(dev string) error {
		filled = dev
		return errors.New("boom")
	})
	if err == nil || err.Error() != "boom" {
		t.Fatalf("CreateImage = %v", err)
	}
	if _, ok := s.Get(imgID); ok {
		t.Fatal("failed image left a volume")
	}
	if _, err := os.Stat(filled); !os.IsNotExist(err) {
		t.Fatalf("device %s still exists: %v", filled, err)
	}
	importFile(t, s, imgID, mkImage(t, 32<<20, map[string][]byte{"a": []byte("hello")}))
}

// TestPrivilegedLiveCopy snapshots a mounted working volume: refused while
// the journal is live, kept while the filesystem is frozen.
func TestPrivilegedLiveCopy(t *testing.T) {
	s, _ := openTest(t)
	ctx := context.Background()
	if err := s.CreateCommit(ctx, CreateCommit{StateUID: "src", CommitID: "b000000000000001", SizeBytes: 64 << 20}); err != nil {
		t.Fatal(err)
	}
	w, err := s.CreateWorking(ctx, CreateWorking{AttachmentID: "b0000000000000a1", StateUID: "src", FromCommit: "b000000000000001"})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := unix.Mount(w, dir, "ext4", 0, ""); err != nil {
		t.Fatal(err)
	}
	mounted := true
	defer func() {
		if mounted {
			exec.Command("fsfreeze", "-u", dir).Run()
			unix.Unmount(dir, 0)
		}
	}()
	data := randBytes(1 << 20)
	if err := os.WriteFile(filepath.Join(dir, "data"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LiveCopy(ctx, "b0000000000000a1", "b000000000000002", "dst"); !errors.Is(err, ErrUnclean) {
		t.Fatalf("live copy of an unfrozen fs: %v", err)
	}
	if _, ok := s.Get("b000000000000002"); ok {
		t.Fatal("unclean live copy created a commit")
	}
	sh(t, "fsfreeze", "-f", dir)
	n, err := s.LiveCopy(ctx, "b0000000000000a1", "b000000000000002", "dst")
	sh(t, "fsfreeze", "-u", dir)
	if err != nil || n != 64<<20 {
		t.Fatalf("live copy: %d %v", n, err)
	}
	if n, err := s.LiveCopy(ctx, "b0000000000000a1", "b000000000000002", "dst"); err != nil || n != 64<<20 {
		t.Fatalf("second live copy: %d %v", n, err)
	}
	if v, _ := s.Get("b000000000000002"); v.StateUID != "dst" || v.Base != "b000000000000001" {
		t.Fatalf("live copy commit: %+v", v)
	}
	plain(t, s, "b000000000000002", func(dev string) {
		if !bytes.Equal(catFile(t, dev, "data"), data) {
			t.Fatal("live copy content wrong")
		}
	})
	must(t, unix.Unmount(dir, 0))
	mounted = false
	for _, id := range []string{"b000000000000002", "b0000000000000a1", "b000000000000001"} {
		must(t, s.Delete(ctx, id))
	}
}

func TestPrivilegedDiskKey(t *testing.T) {
	s, cfg := openTest(t)
	must(t, s.CreateCommit(context.Background(), CreateCommit{StateUID: "u", CommitID: "a000000000000001", SizeBytes: 32 << 20}))
	s.Close()
	other := cfg
	other.Key = bytes.Repeat([]byte{0xa5}, KeySize)
	if _, err := Open(context.Background(), other); err == nil || !strings.Contains(err.Error(), "not with the configured key") {
		t.Fatalf("open with another key: %v", err)
	}
	other.Key = testKey[:32]
	if _, err := Open(context.Background(), other); err == nil {
		t.Fatal("open with a short key")
	}
	s, err := Open(context.Background(), cfg)
	must(t, err)
	t.Cleanup(func() { s.Close() })
}

func TestPrivilegedRestart(t *testing.T) {
	s, cfg := openTest(t)
	ctx := context.Background()
	img := mkImage(t, 32<<20, map[string][]byte{"a": []byte("hello")})
	imgID := "sha256:" + strings.Repeat("cd", 32)
	importFile(t, s, imgID, img)
	w, err := s.CreateWorking(ctx, CreateWorking{AttachmentID: "b000000000000001", FromImage: imgID})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, w, "b", []byte("world"))
	incarn := s.Incarnation()

	// An operation interrupted by a crash.
	crash := &record{ID: "b000000000000002", Kind: KindWorking, Size: 32 << 20, FSBytes: 32 << 20}
	if _, err := s.begin(crash, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.runOperation([]deviceEffect{{Kind: eCreateThin, Name: s.poolName(), Thin: crash.Thin}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := dmCreate(s.thinName(crash), thinTable(s.poolName(), crash.Thin, crash.Size), false); err != nil {
		t.Fatal(err)
	}
	s.Close()

	// Process restart: kernel state survives.
	s, err = Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s.Incarnation() != incarn {
		t.Fatal("incarnation changed")
	}
	if dmExists(s.prefix + "-b000000000000002") {
		t.Fatal("interrupted volume not rolled back")
	}
	if _, ok := s.Get("b000000000000002"); ok {
		t.Fatal("interrupted volume still listed")
	}
	if v, ok := s.Get("b000000000000001"); !ok || v.Device != w {
		t.Fatalf("working volume after restart: %+v", v)
	}
	if got := string(catFile(t, w, "b")); got != "world" {
		t.Fatalf("data after restart: %q", got)
	}
	s.Close()

	// Host reboot: every device is gone.
	RemoveNodeDevices(cfg.NodeName)
	s, err = Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if got := string(catFile(t, w, "b")); got != "world" {
		t.Fatalf("data after reboot: %q", got)
	}
	if _, err := s.CreateWorking(ctx, CreateWorking{AttachmentID: "b000000000000003", FromImage: imgID}); err != nil {
		t.Fatalf("thin IDs reused? %v", err)
	}
}

func TestPrivilegedRefusedDeleteHostRestart(t *testing.T) {
	s, cfg := openTest(t)
	ctx := context.Background()
	must(t, s.CreateCommit(ctx, CreateCommit{CommitID: "base", SizeBytes: 32 << 20}))
	dev, err := s.CreateWorking(ctx, CreateWorking{AttachmentID: "writer", FromCommit: "base"})
	must(t, err)
	writeFile(t, dev, "payload", []byte("preserved after refused deletion"))
	h, err := os.Open(dev)
	must(t, err)
	defer h.Close()
	failDeleteRestoration(s)
	if err := s.Delete(ctx, "writer"); !errors.Is(err, ErrInUse) {
		t.Fatalf("Delete = %v", err)
	}
	if s.vols["writer"].Phase != phaseReady || len(s.PendingDeletes()) != 0 {
		t.Fatal("refused delete is not usable before restart")
	}
	must(t, h.Close())
	must(t, s.Close())
	RemoveNodeDevices(cfg.NodeName) // host reboot: no surviving DM table can disambiguate the gate
	s, err = Open(ctx, cfg)
	must(t, err)
	t.Cleanup(func() { s.Close() })
	if v, ok := s.Get("writer"); !ok || v.Device != dev {
		t.Fatalf("host restart lost refused writer: %+v, %v", v, ok)
	}
	if got := string(catFile(t, dev, "payload")); got != "preserved after refused deletion" {
		t.Fatalf("data after host restart = %q", got)
	}
	_, err = s.Seal(ctx, "writer", "sealed")
	must(t, err)
}

func TestPrivilegedDiff(t *testing.T) {
	s, _ := openTest(t)
	ctx := context.Background()
	img := mkImage(t, 64<<20, map[string][]byte{"big": randBytes(8 << 20)})
	imgID := "sha256:" + strings.Repeat("ef", 32)
	importFile(t, s, imgID, img)
	// Commits built from an image are delta bases only when their content
	// digest matches (each node converts images itself); d1 is a copy of one.
	must(t, s.CreateCommit(ctx, CreateCommit{StateUID: "u", CommitID: "d000000000000000", FromImage: imgID}))
	must(t, s.CreateCommit(ctx, CreateCommit{StateUID: "u", CommitID: "d000000000000001", FromCommit: "d000000000000000"}))
	w, err := s.CreateWorking(ctx, CreateWorking{AttachmentID: "d0000000000000a1", StateUID: "u", FromCommit: "d000000000000001"})
	must(t, err)
	writeFile(t, w, "small", randBytes(100<<10))
	_, err = s.Seal(ctx, "d0000000000000a1", "d000000000000002")
	must(t, err)

	base, delta, err := s.Diff(ctx, "d000000000000002", []string{"zzz", "d000000000000001"}, nil)
	must(t, err)
	if base != "d000000000000001" {
		t.Fatalf("base %q", base)
	}
	_, full, err := s.Diff(ctx, "d000000000000002", nil, nil)
	must(t, err)
	if total(delta) == 0 || total(delta) >= total(full) || total(delta) > 4<<20 {
		t.Fatalf("delta %d bytes, full %d bytes", total(delta), total(full))
	}
	for i := 1; i < len(delta); i++ {
		if delta[i].Offset <= delta[i-1].Offset+delta[i-1].Length {
			t.Fatal("regions not merged")
		}
	}
	// Applying the delta to the base reproduces the commit; applying the
	// full mapping to zeros does too.
	d1, _ := s.Activate("d000000000000001")
	d2, _ := s.Activate("d000000000000002")
	want := hashDev(t, d2, 64<<20)
	if got := applyRegions(t, d1, d2, delta, 64<<20); got != want {
		t.Fatal("base + delta != commit")
	}
	if got := applyRegions(t, "/dev/zero", d2, full, 64<<20); got != want {
		t.Fatal("zeros + full != commit")
	}
	if b, r, _ := s.Diff(ctx, "d000000000000002", []string{"d000000000000002"}, nil); b != "d000000000000002" || len(r) != 0 {
		t.Fatal("diff against itself")
	}
	// An image-built base offered by ID only is never used: the importer's
	// copy is its own conversion. With a matching content digest it is.
	if b, r, _ := s.Diff(ctx, "d000000000000002", []string{"d000000000000000", imgID}, nil); b != "" || total(r) != total(full) {
		t.Fatalf("diff against an image-built base: base %q", b)
	}
	d0, err := s.Digest(ctx, "d000000000000000")
	must(t, err)
	if !strings.HasPrefix(d0, digestPrefix) {
		t.Fatalf("digest %q", d0)
	}
	if v, _ := s.Get("d000000000000000"); v.Digest != d0 {
		t.Fatalf("digest not recorded: %+v", v)
	}
	b, r, err := s.Diff(ctx, "d000000000000002", nil, map[string]string{"d000000000000000": d0})
	must(t, err)
	if b != "d000000000000000" || total(r) == 0 || total(r) >= total(full) {
		t.Fatalf("diff against a digest-matched base: base %q, %d of %d bytes", b, total(r), total(full))
	}
	if got := applyRegions(t, mustActivate(t, s, "d000000000000000"), d2, r, 64<<20); got != want {
		t.Fatal("image base + delta != commit")
	}
	for _, bad := range []string{digestPrefix + strings.Repeat("0", 64), "v0:" + d0, ""} {
		if b, r, _ := s.Diff(ctx, "d000000000000002", nil, map[string]string{"d000000000000000": bad}); b != "" || total(r) != total(full) {
			t.Fatalf("diff with digest %q: base %q", bad, b)
		}
	}
	// A nearer base by ID wins over a digest-matched one.
	if b, _, _ := s.Diff(ctx, "d000000000000002", []string{"d000000000000001"}, map[string]string{"d000000000000000": d0}); b != "d000000000000001" {
		t.Fatalf("base %q", b)
	}
	// The digest covers content only: a copy with different mappings and
	// a different commit with the same content agree, others differ.
	d1Digest, err := s.Digest(ctx, "d000000000000001")
	must(t, err)
	d2Digest, err := s.Digest(ctx, "d000000000000002")
	must(t, err)
	if d1Digest != d0 || d2Digest == d0 {
		t.Fatalf("digests d0 %s d1 %s d2 %s", d0, d1Digest, d2Digest)
	}
	if _, err := s.Digest(ctx, "d0000000000000a1"); err == nil {
		t.Fatal("digest of a sealed-away working volume")
	}
}

func mustActivate(t *testing.T, s *Store, id string) string {
	t.Helper()
	dev, err := s.Activate(id)
	must(t, err)
	return dev
}

// TestPrivilegedImageBases converts the same image on two stores and checks
// that the generation 1 commits are byte-identical, so that one serves as
// the delta base for the other.
func TestPrivilegedImageBases(t *testing.T) {
	src, _ := openTest(t)
	dst, _ := openTest(t)
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "root")
	must(t, os.MkdirAll(filepath.Join(root, "etc", "conf.d"), 0o755))
	for i := range 200 {
		must(t, os.WriteFile(filepath.Join(root, "etc", "conf.d", fmt.Sprintf("f%03d", i)), []byte(strings.Repeat("x", i*37)), 0o644))
	}
	must(t, os.WriteFile(filepath.Join(root, "big"), randBytes(6<<20), 0o755))
	must(t, os.Symlink("big", filepath.Join(root, "link")))
	tarPath := filepath.Join(t.TempDir(), "rootfs.tar")
	sh(t, "tar", "--format=pax", "--owner=0", "--group=0", "-C", root, "-cf", tarPath, ".")
	st, err := os.Stat(tarPath)
	must(t, err)
	imgID := "sha256:" + strings.Repeat("9a", 32)

	var digests [2]string
	for i, s := range []*Store{src, dst} {
		if i == 1 {
			// The conversions run at different times.
			time.Sleep(1100 * time.Millisecond)
		}
		free := s.FreeBytes()
		must(t, s.CreateImage(ctx, imgID, image.FSSize(st.Size()), func(dev string) error {
			return image.MakeFS(ctx, tarPath, dev, imgID)
		}))
		if used := free - s.FreeBytes(); used <= 0 || used > 16<<20 {
			t.Fatalf("image conversion used %d bytes of pool; want sparse", used)
		}
		// Generation 1 is grown, which rewrites metadata.
		must(t, s.CreateCommit(ctx, CreateCommit{StateUID: "u", CommitID: "f000000000000001", FromImage: imgID, SizeBytes: 512 << 20}))
		digests[i], err = s.Digest(ctx, "f000000000000001")
		must(t, err)
	}
	if digests[0] != digests[1] {
		t.Fatalf("image conversion is not reproducible: %s != %s", digests[0], digests[1])
	}

	w, err := src.CreateWorking(ctx, CreateWorking{AttachmentID: "f0000000000000a1", StateUID: "u", FromCommit: "f000000000000001"})
	must(t, err)
	writeFile(t, w, "changed", randBytes(1<<20))
	_, err = src.Seal(ctx, "f0000000000000a1", "f000000000000002")
	must(t, err)
	srcDev := mustActivate(t, src, "f000000000000002")
	want := hashDev(t, srcDev, 512<<20)

	base, regions, err := src.Diff(ctx, "f000000000000002", nil, map[string]string{"f000000000000001": digests[1]})
	must(t, err)
	_, full, err := src.Diff(ctx, "f000000000000002", nil, nil)
	must(t, err)
	if base != "f000000000000001" || total(regions) > 4<<20 || total(regions) >= total(full) {
		t.Fatalf("base %q, delta %d bytes, full %d bytes", base, total(regions), total(full))
	}
	r := Remote{Device: srcDev, SizeBytes: 512 << 20, Base: base, Regions: regions, ID: "r", Release: func() {}}
	must(t, dst.FetchCommit(ctx, "u", "f000000000000002", r, nil))
	if hashDev(t, mustActivate(t, dst, "f000000000000002"), 512<<20) != want {
		t.Fatal("delta fetch onto a local image conversion differs")
	}
	srcDigest, err := src.Digest(ctx, "f000000000000002")
	must(t, err)
	dstDigest, err := dst.Digest(ctx, "f000000000000002")
	must(t, err)
	if srcDigest != dstDigest {
		t.Fatal("fetched commit digest differs")
	}
}

func applyRegions(t *testing.T, basePath, srcPath string, regions []Region, size int64) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "out")
	o, _ := os.Create(out)
	b, _ := os.Open(basePath)
	io.CopyN(o, b, size)
	b.Close()
	src, _ := os.Open(srcPath)
	for _, r := range regions {
		buf := make([]byte, r.Length)
		src.ReadAt(buf, r.Offset)
		o.WriteAt(buf, r.Offset)
	}
	src.Close()
	o.Close()
	return hashDev(t, out, size)
}

func total(rs []Region) (n int64) {
	for _, r := range rs {
		n += r.Length
	}
	return n
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// TestPrivilegedClone runs the remote clone engine against a local device.
func TestPrivilegedClone(t *testing.T) {
	src, _ := openTest(t)
	dst, dstCfg := openTest(t)
	ctx := context.Background()
	img := mkImage(t, 256<<20, map[string][]byte{"big": randBytes(64 << 20), "small": []byte("x")})
	imgID := "sha256:" + strings.Repeat("12", 32)
	importFile(t, src, imgID, img)
	importFile(t, dst, imgID, img)
	for _, s := range []*Store{src, dst} {
		must(t, s.CreateCommit(ctx, CreateCommit{StateUID: "u", CommitID: "e000000000000000", FromImage: imgID}))
		must(t, s.CreateCommit(ctx, CreateCommit{StateUID: "u", CommitID: "e000000000000001", FromCommit: "e000000000000000"}))
	}
	w, err := src.CreateWorking(ctx, CreateWorking{AttachmentID: "e0000000000000a1", StateUID: "u", FromCommit: "e000000000000001"})
	must(t, err)
	changed := randBytes(2 << 20)
	writeFile(t, w, "changed", changed)
	_, err = src.Seal(ctx, "e0000000000000a1", "e000000000000002")
	must(t, err)
	srcDev, err := src.Activate("e000000000000002")
	must(t, err)
	want := hashDev(t, srcDev, 256<<20)

	remote := func(bases []string) (Remote, *atomic.Int32) {
		base, regions, err := src.Diff(ctx, "e000000000000002", bases, nil)
		must(t, err)
		var released atomic.Int32
		return Remote{Device: srcDev, SizeBytes: 256 << 20, Base: base, Regions: regions, ID: "r", Release: func() { released.Add(1) }}, &released
	}

	// Replica fetch with a delta.
	r, released := remote([]string{"e000000000000001"})
	if r.Base != "e000000000000001" {
		t.Fatalf("base %q", r.Base)
	}
	var last [2]int64
	must(t, dst.FetchCommit(ctx, "u", "e000000000000002", r, func(done, total int64) { last = [2]int64{done, total} }))
	if released.Load() != 1 || last[0] != last[1] || last[1] != 256<<20 {
		t.Fatalf("released %d progress %v", released.Load(), last)
	}
	got, _ := dst.Activate("e000000000000002")
	if hashDev(t, got, 256<<20) != want {
		t.Fatal("delta fetch content differs")
	}
	if v, _ := dst.Get("e000000000000002"); v.Hydrating || v.Base != "e000000000000001" {
		t.Fatalf("fetched: %+v", v)
	}

	// Full fetch.
	r, released = remote(nil)
	must(t, dst.FetchCommit(ctx, "u", "e000000000000003", r, nil))
	got, _ = dst.Activate("e000000000000003")
	if released.Load() != 1 || hashDev(t, got, 256<<20) != want {
		t.Fatal("full fetch content differs")
	}
	// Copies with different block mappings have the same content digest.
	for _, id := range []string{"e000000000000002", "e000000000000003"} {
		a, err := src.Digest(ctx, "e000000000000002")
		must(t, err)
		b, err := dst.Digest(ctx, id)
		must(t, err)
		if a != b {
			t.Fatalf("digest of %s differs from its source", id)
		}
	}

	// Remote attach: usable at once, swapped to linear after hydration.
	r, released = remote(nil)
	dev, err := dst.CreateWorking(ctx, CreateWorking{AttachmentID: "e0000000000000b1", StateUID: "u", Remote: &r})
	must(t, err)
	var st unix.Stat_t
	must(t, unix.Stat(dev, &st))
	if !bytes.Equal(catFile(t, dev, "changed"), changed) {
		t.Fatal("remote attach read")
	}
	writeFile(t, dev, "new", []byte("written during hydration"))
	waitHydrated(t, dst, "e0000000000000b1")
	if released.Load() != 1 {
		t.Fatalf("released %d", released.Load())
	}
	var st2 unix.Stat_t
	must(t, unix.Stat(dev, &st2))
	table, _ := dmTable(DMPrefix(dst.cfg.NodeName) + "-e0000000000000b1")
	if st.Rdev != st2.Rdev || !strings.Contains(table, " linear ") {
		t.Fatalf("not swapped in place: %s", table)
	}
	if string(catFile(t, dev, "new")) != "written during hydration" || !bytes.Equal(catFile(t, dev, "changed"), changed) {
		t.Fatal("data after swap")
	}
	_, err = dst.Seal(ctx, "e0000000000000b1", "e000000000000004")
	must(t, err)
	must(t, dst.Delete(ctx, "e0000000000000b1"))

	// Deleting while hydrating releases the remote.
	r, released = remote(nil)
	_, err = dst.CreateWorking(ctx, CreateWorking{AttachmentID: "e0000000000000b2", Remote: &r})
	must(t, err)
	must(t, dst.Delete(ctx, "e0000000000000b2"))
	if released.Load() != 1 {
		t.Fatalf("released %d after delete", released.Load())
	}

	// Restart during hydration: the kernel keeps the clone, the watcher
	// resumes lease renewal through Config.ResumeRemote and releases through
	// Config.ReleaseRemote. A clone device lost in the restart is marked failed.
	r3, rel3 := remote(nil)
	r3.ID = "remote-3"
	_, err = dst.CreateWorking(ctx, CreateWorking{AttachmentID: "e0000000000000b3", Remote: &r3})
	must(t, err)
	r4, rel4 := remote(nil)
	r4.ID = "remote-4"
	_, err = dst.CreateWorking(ctx, CreateWorking{AttachmentID: "e0000000000000b4", Remote: &r4})
	must(t, err)
	dst.Close()
	resuming, err := dmTable(DMPrefix(dstCfg.NodeName) + "-e0000000000000b3")
	must(t, err)
	must(t, dmRemove(DMPrefix(dstCfg.NodeName)+"-e0000000000000b4-p"))
	must(t, dmRemove(DMPrefix(dstCfg.NodeName)+"-e0000000000000b4"))
	var mu sync.Mutex
	byID := map[string]int{}
	resumed := map[string]int{}
	dstCfg.ResumeRemote = func(id string) {
		mu.Lock()
		resumed[id]++
		mu.Unlock()
	}
	dstCfg.ReleaseRemote = func(id string) {
		mu.Lock()
		byID[id]++
		mu.Unlock()
	}
	dst, err = Open(ctx, dstCfg)
	must(t, err)
	t.Cleanup(func() { dst.Close() })
	if v, _ := dst.Get("e0000000000000b4"); v.Failed == "" || v.Hydrating {
		t.Fatalf("lost clone not failed: %+v", v)
	}
	waitHydrated(t, dst, "e0000000000000b3")
	if v, _ := dst.Get("e0000000000000b3"); !bytes.Equal(catFile(t, v.Device, "changed"), changed) {
		t.Fatal("data after resumed hydration")
	}
	must(t, dst.Delete(ctx, "e0000000000000b4"))
	mu.Lock()
	defer mu.Unlock()
	wantResume := 0
	if strings.Contains(resuming, " clone ") {
		wantResume = 1
	}
	if resumed["remote-3"] != wantResume || resumed["remote-4"] != 0 {
		t.Fatalf("resumed: %v, want remote-3=%d only", resumed, wantResume)
	}
	if int(rel3.Load())+byID["remote-3"] != 1 || int(rel4.Load())+byID["remote-4"] != 1 {
		t.Fatalf("releases: closures %d %d, by ID %v", rel3.Load(), rel4.Load(), byID)
	}
}

func waitHydrated(t *testing.T, s *Store, id string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for {
		v, ok := s.Get(id)
		if !ok || v.Failed != "" {
			t.Fatalf("volume %s: %+v", id, v)
		}
		if !v.Hydrating {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("hydration timed out")
		}
		time.Sleep(100 * time.Millisecond)
	}
}
