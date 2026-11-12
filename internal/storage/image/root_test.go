package image

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestMkfsExt4 needs mkfs.ext4 and debugfs. It writes a plain file, so it
// does not need root.
func TestMkfsExt4(t *testing.T) {
	if _, err := exec.LookPath("debugfs"); err != nil {
		t.Skip("no debugfs")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	os.MkdirAll(filepath.Join(src, "bin"), 0o755)
	os.WriteFile(filepath.Join(src, "bin", "hello"), []byte("hi"), 0o755)
	img := filepath.Join(dir, "fs.img")
	if err := os.WriteFile(img, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(img, 64<<20); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := MkfsExt4(ctx, img, src, MkfsOptions{UUID: "1b4e28ba-2fa1-11d2-883f-0016d3cca427"}); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("debugfs", "-R", "cat /bin/hello", img).Output()
	if err != nil || string(out) != "hi" {
		t.Fatalf("%q %v", out, err)
	}
	out, _ = exec.Command("dumpe2fs", "-h", img).CombinedOutput()
	for _, want := range []string{"1b4e28ba-2fa1-11d2-883f-0016d3cca427", "Reserved block count:     0", "has_journal"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("dumpe2fs lacks %q", want)
		}
	}
	if err := exec.Command("e2fsck", "-fn", img).Run(); err != nil {
		t.Fatalf("e2fsck: %v", err)
	}
}

// TestPull needs network access: BLIP_NET_TESTS=1.
func TestPull(t *testing.T) {
	if os.Getenv("BLIP_NET_TESTS") != "1" {
		t.Skip("set BLIP_NET_TESTS=1")
	}
	dir := filepath.Join(t.TempDir(), "root")
	d, err := Pull(context.Background(), "docker.io/library/busybox:1.36", nil, "linux/amd64", dir)
	if os.Geteuid() != 0 && err != nil && strings.Contains(err.Error(), "chown") {
		t.Skip("needs root for chown")
	}
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(d, "sha256:") {
		t.Fatal(d)
	}
	if _, err := os.Lstat(filepath.Join(dir, "bin", "sh")); err != nil {
		t.Fatal(err)
	}
}
