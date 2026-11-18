package nvme

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestUUIDFrom(t *testing.T) {
	u := uuidFrom("x")
	if len(u) != 36 || u[14] != '4' || u != uuidFrom("x") || u == uuidFrom("y") {
		t.Fatalf("uuid %q", u)
	}
	if HostID("a") == HostID("b") {
		t.Fatal("host IDs collide")
	}
}

func TestSecrets(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	// base64(00 01 .. 1f || crc32 0x91267e8a little-endian)
	if got, want := formatSecret(raw), "DHHC-1:00:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh+KfiaR:"; got != want {
		t.Fatalf("formatSecret = %s, want %s", got, want)
	}
	host, ctrl := secrets(bytes.Repeat([]byte{1}, 64), "nqn.2014-08.dev.blip:host:n1")
	if host != "DHHC-1:00:mravLPvTYhbAwwD2TpMPgRjE7FQA7VfGG2gCYq+2BJ3LtfSP:" ||
		ctrl != "DHHC-1:00:fC69tOxuhj0WS6GDwHWArCwhZNdxiRZArEPLGg6FkjDAg0CD:" {
		t.Fatalf("secrets = %s, %s", host, ctrl)
	}
	if h2, _ := secrets(bytes.Repeat([]byte{1}, 64), "nqn.2014-08.dev.blip:host:n2"); h2 == host {
		t.Fatal("secrets do not depend on the host NQN")
	}
	if h3, _ := secrets(bytes.Repeat([]byte{2}, 64), "nqn.2014-08.dev.blip:host:n1"); h3 == host {
		t.Fatal("secrets do not depend on the key")
	}
	if checkKey(nil) == nil || checkKey(make([]byte, 16)) == nil {
		t.Fatal("short key accepted")
	}
}

// TestPrivilegedExportConnect exports a loop device and connects to it over
// 127.0.0.1. Run only inside a disposable privileged container
// (hack/storage-test.sh).
func TestPrivilegedExportConnect(t *testing.T) {
	if os.Getenv("BLIP_PRIVILEGED_TESTS") != "1" {
		t.Skip("set BLIP_PRIVILEGED_TESTS=1 (inside a disposable privileged container)")
	}
	node := fmt.Sprintf("blipt-%s-19", os.Getenv("BLIP_TEST_RUN"))
	data := make([]byte, 8<<20)
	rand.Read(data)
	file := filepath.Join(t.TempDir(), "disk")
	os.WriteFile(file, data, 0o600)
	out, err := exec.Command("losetup", "-f", "--show", file).Output()
	if err != nil {
		t.Fatal(err)
	}
	loop := strings.TrimSpace(string(out))
	t.Cleanup(func() { exec.Command("losetup", "-d", loop).Run() })

	key := bytes.Repeat([]byte{7}, 64)
	tgt, err := NewTarget(node, "127.0.0.1", 4420, key)
	if err != nil {
		t.Fatal(err)
	}
	host := "nqn.2014-08.dev.blip:host:" + node
	nqn, err := tgt.Export("l1", loop, host)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		Disconnect(nqn)
		tgt.Unexport("l1")
	})
	if _, err := tgt.Export("l1", loop, host); err != nil {
		t.Fatalf("re-export: %v", err)
	}
	if got := tgt.Leases(); len(got) != 1 || got[0] != "l1" {
		t.Fatalf("leases %v", got)
	}

	if _, err := Connect(context.Background(), "127.0.0.1", 4420, nqn, host+"-other", key); err == nil {
		t.Fatal("a host that is not allowed connected")
	}
	if _, err := Connect(context.Background(), "127.0.0.1", 4420, nqn, host, bytes.Repeat([]byte{8}, 64)); err == nil {
		t.Fatal("a host with the wrong key connected")
	}
	dev, err := Connect(context.Background(), "127.0.0.1", 4420, nqn, host, key)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(dev)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(io.LimitReader(f, int64(len(data))+1))
	f.Close()
	if !bytes.Equal(got, data) {
		t.Fatalf("read %d bytes, content mismatch", len(got))
	}
	if again, err := Connect(context.Background(), "127.0.0.1", 4420, nqn, host, key); err != nil || again != dev {
		t.Fatalf("reconnect: %s %v", again, err)
	}
	if err := Disconnect(nqn); err != nil {
		t.Fatal(err)
	}
	if err := tgt.Unexport("l1"); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{subsysDir(nqn), tgt.portDir(), filepath.Join(nvmetDir, "hosts", host)} {
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("%s left behind", p)
		}
	}
}
