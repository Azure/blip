package guest

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func swapSelf(t *testing.T, dir string, meta func() (Identity, bool, error)) {
	oldDir, oldMeta := RunDir, readMeta
	t.Cleanup(func() { RunDir, readMeta = oldDir, oldMeta })
	RunDir, readMeta = dir, meta
}

func TestSelf(t *testing.T) {
	dir := t.TempDir()
	metaCalls := 0
	swapSelf(t, dir, func() (Identity, bool, error) {
		metaCalls++
		return Identity{Name: "meta", Namespace: "mns"}, true, nil
	})
	t.Setenv("BLIP_NAME", "")
	t.Setenv("BLIP_NAMESPACE", "")

	// Metadata disk last.
	if id, ok, err := Self(); err != nil || !ok || id != (Identity{"meta", "mns"}) || metaCalls != 1 {
		t.Fatal(id, ok, err, metaCalls)
	}
	// RunDir files before the metadata disk.
	_ = os.WriteFile(filepath.Join(dir, "name"), []byte("run\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "namespace"), []byte(" rns\n"), 0o644)
	if id, ok, err := Self(); err != nil || !ok || id != (Identity{"run", "rns"}) || metaCalls != 1 {
		t.Fatal(id, ok, err)
	}
	// Environment first.
	t.Setenv("BLIP_NAME", "env")
	t.Setenv("BLIP_NAMESPACE", "ens")
	if id, ok, err := Self(); err != nil || !ok || id != (Identity{"env", "ens"}) || metaCalls != 1 {
		t.Fatal(id, ok, err)
	}
}

func TestSelfOutside(t *testing.T) {
	boom := errors.New("boom")
	swapSelf(t, t.TempDir(), func() (Identity, bool, error) { return Identity{}, false, boom })
	t.Setenv("BLIP_NAME", "")
	if _, ok, err := Self(); ok || !errors.Is(err, boom) {
		t.Fatal(ok, err)
	}
}

func TestInClusterEnv(t *testing.T) {
	old := TokenFile
	t.Cleanup(func() { TokenFile = old })
	TokenFile = filepath.Join(t.TempDir(), "token")
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")

	if InClusterEnv() || os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		t.Fatal("set without a token")
	}
	_ = os.WriteFile(TokenFile, []byte("tok"), 0o600)
	if !InClusterEnv() || os.Getenv("KUBERNETES_SERVICE_HOST") != "kubernetes.default.svc" || os.Getenv("KUBERNETES_SERVICE_PORT") != "443" {
		t.Fatal(os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT"))
	}
	// Already set: unchanged.
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "6443")
	if InClusterEnv() || os.Getenv("KUBERNETES_SERVICE_HOST") != "10.0.0.1" || os.Getenv("KUBERNETES_SERVICE_PORT") != "6443" {
		t.Fatal("overrode")
	}
	// Host unset, port set: port kept.
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	if !InClusterEnv() || os.Getenv("KUBERNETES_SERVICE_PORT") != "6443" {
		t.Fatal(os.Getenv("KUBERNETES_SERVICE_PORT"))
	}
}

const mountinfo = `22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
30 22 8:16 / /mnt/a\040b rw,relatime shared:2 - ext4 /dev/sdb rw
31 22 8:160 / /mnt/other rw - ext4 /dev/sdk rw
32 22 8:16 /sub /srv/data\011tab rw - ext4 /dev/sdb rw
short line
33 22 8:16 / /mnt/back\134slash\04 rw - ext4 /dev/sdb rw
`

func TestMountPoints(t *testing.T) {
	got := MountPoints(strings.NewReader(mountinfo), "8:16")
	want := []string{"/mnt/a b", "/srv/data\ttab", `/mnt/back\slash\04`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%q", got)
	}
	if got := MountPoints(strings.NewReader(mountinfo), "9:9"); got != nil {
		t.Fatal(got)
	}
}

func TestUnescapeMount(t *testing.T) {
	for in, want := range map[string]string{
		"/plain":   "/plain",
		`/a\040b`:  "/a b",
		`/x\999`:   `/x\999`,
		`/end\`:    `/end\`,
		`\040\040`: "  ",
	} {
		if got := unescapeMount(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}
