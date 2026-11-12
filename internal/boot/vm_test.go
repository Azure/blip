//go:build linux

package boot_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/example/blip/internal/meta"
)

// VM integration test: boots Cloud Hypervisor with the blip-boot initramfs
// and a metadata disk, then hot-plugs an ext4 root. Needs BLIP_VM_TEST=1,
// /dev/kvm, cloud-hypervisor, a kernel (BLIP_KERNEL) and an alpine rootfs
// dir (BLIP_ROOTFS, see hack/guest/mkrootfs.sh). No root required.

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

type vmEnv struct {
	repo, kernel, ch, rootfs, initramfs, blipMeta string
}

func setupVM(t *testing.T) vmEnv {
	if os.Getenv("BLIP_VM_TEST") != "1" {
		t.Skip("BLIP_VM_TEST != 1")
	}
	if f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0); err != nil {
		t.Skip("no kvm:", err)
	} else {
		f.Close()
	}
	repo, _ := filepath.Abs("../..")
	e := vmEnv{
		repo:   repo,
		kernel: env("BLIP_KERNEL", "/home/azureuser/code/blip/_output/guest/vmlinuz"),
		ch:     env("BLIP_CH", "/usr/local/bin/cloud-hypervisor"),
		rootfs: env("BLIP_ROOTFS", "/mnt/nvme2/blip/guest/rootfs-alpine"),
	}
	for _, p := range []string{e.kernel, e.ch, e.rootfs + "/bin/busybox"} {
		if _, err := os.Stat(p); err != nil {
			t.Skip(err)
		}
	}
	out := t.TempDir()
	for _, c := range []string{"blip-boot", "blip-meta"} {
		run(t, repo, nil, "go", "build", "-trimpath", "-ldflags=-s -w", "-o", filepath.Join(out, c), "./cmd/"+c)
	}
	e.initramfs = filepath.Join(out, "initramfs.cpio.gz")
	e.blipMeta = filepath.Join(out, "blip-meta")
	run(t, repo, nil, "go", "run", "./hack/guest/mkinitramfs", "-init", filepath.Join(out, "blip-boot"), "-o", e.initramfs)
	return e
}

func run(t *testing.T, dir string, extraEnv []string, name string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = append(append(os.Environ(), "CGO_ENABLED=0"), extraEnv...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}

// mkRoot builds an ext4 image from the alpine rootfs plus blip-meta and init.
func mkRoot(t *testing.T, e vmEnv, initScript string) string {
	dir := filepath.Join(t.TempDir(), "root")
	run(t, "", nil, "cp", "-a", e.rootfs, dir)
	run(t, "", nil, "cp", e.blipMeta, filepath.Join(dir, "usr/bin/blip-meta"))
	init := filepath.Join(dir, "sbin/blip-test-init")
	if err := os.WriteFile(init, []byte(initScript), 0o755); err != nil {
		t.Fatal(err)
	}
	img := filepath.Join(t.TempDir(), "root.img")
	run(t, "", nil, "mkfs.ext4", "-q", "-F", "-d", dir, img, "64M")
	return img
}

type vm struct {
	cmd    *exec.Cmd
	sock   string
	serial string
	done   chan error
}

func startVM(t *testing.T, e vmEnv, metaImg string) *vm {
	dir := t.TempDir()
	v := &vm{sock: filepath.Join(dir, "api.sock"), serial: filepath.Join(dir, "serial.log"), done: make(chan error, 1)}
	v.cmd = exec.Command(e.ch,
		"--api-socket", "path="+v.sock,
		"--kernel", e.kernel, "--initramfs", e.initramfs,
		"--cmdline", "console=ttyS0 loglevel=4 panic=0",
		"--cpus", "boot=1", "--memory", "size=512M",
		"--disk", "path="+metaImg+",serial="+meta.Serial+",id="+meta.Serial+",image_type=raw",
		"--serial", "file="+v.serial, "--console", "off")
	var stderr bytes.Buffer
	v.cmd.Stdout, v.cmd.Stderr = &stderr, &stderr
	if err := v.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { v.done <- v.cmd.Wait() }()
	t.Cleanup(func() {
		v.cmd.Process.Kill()
		if t.Failed() {
			s, _ := os.ReadFile(v.serial)
			t.Logf("ch output:\n%s\nserial:\n%s", stderr.String(), s)
		}
	})
	return v
}

func (v *vm) addDisk(t *testing.T, path, serial string) {
	c := http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", v.sock)
		}}}
	body := fmt.Sprintf(`{"path":%q,"serial":%q,"id":%q,"image_type":"Raw"}`, path, serial, serial)
	req, _ := http.NewRequest(http.MethodPut, "http://localhost/api/v1/vm.add-disk", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		t.Fatalf("add-disk: %s", resp.Status)
	}
}

func waitGuest(t *testing.T, w *meta.Writer, d time.Duration, ok func(*meta.GuestData) bool) *meta.GuestData {
	t.Helper()
	deadline := time.Now().Add(d)
	var last *meta.GuestData
	for time.Now().Before(deadline) {
		if g, err := w.ReadGuest(); err == nil {
			last = g
			if ok(g) {
				return g
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for guest state; last %+v", last)
	return nil
}

func (v *vm) waitExit(t *testing.T) {
	select {
	case <-v.done:
	case <-time.After(60 * time.Second):
		t.Fatal("cloud-hypervisor did not exit")
	}
}

func newMeta(t *testing.T) (string, *meta.Writer) {
	p := filepath.Join(t.TempDir(), "meta.img")
	if err := meta.Create(p); err != nil {
		t.Fatal(err)
	}
	w, err := meta.OpenWriter(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })
	return p, w
}

func TestVMBoot(t *testing.T) {
	e := setupVM(t)
	root := mkRoot(t, e, "#!/bin/sh\nmount -t proc proc /proc 2>/dev/null\necho blip-test-init running\n/usr/bin/blip-meta exit 7\npoweroff -f\n")
	metaImg, w := newMeta(t)
	v := startVM(t, e, metaImg)

	start := time.Now()
	g := waitGuest(t, w, 30*time.Second, func(g *meta.GuestData) bool { return g.State == meta.StateWaiting })
	t.Logf("WAITING after %v (bootCount %d)", time.Since(start), g.BootCount)
	if g.BootCount != 1 {
		t.Fatalf("bootCount %d", g.BootCount)
	}
	const serial = "root-vol-0123456789" // 19 bytes, under the virtio limit
	if _, err := w.WriteHost(&meta.HostData{AllocationID: "alloc-1",
		Identity: meta.Identity{Name: "b", Namespace: "ns", UID: "u"},
		Boot:     meta.Boot{RootSerial: serial, Init: []string{"/sbin/blip-test-init"}}}); err != nil {
		t.Fatal(err)
	}
	start = time.Now()
	v.addDisk(t, root, serial)
	waitGuest(t, w, 30*time.Second, func(g *meta.GuestData) bool { return g.State == meta.StateExec })
	t.Logf("EXEC after %v", time.Since(start))
	g = waitGuest(t, w, 30*time.Second, func(g *meta.GuestData) bool { return g.ExitCode != nil })
	if *g.ExitCode != 7 || g.State != meta.StateExec || g.BootCount != 1 {
		t.Fatalf("%+v", g)
	}
	v.waitExit(t)
	s, _ := os.ReadFile(v.serial)
	for _, want := range []string{"blip-boot: waiting", "blip-boot: exec /sbin/blip-test-init", "blip-test-init running"} {
		if !bytes.Contains(s, []byte(want)) {
			t.Errorf("serial missing %q", want)
		}
	}
}

func TestVMBootFailures(t *testing.T) {
	e := setupVM(t)
	root := mkRoot(t, e, "#!/bin/sh\npoweroff -f\n")
	for _, tc := range []struct {
		name, reason string
		boot         meta.Boot
	}{
		{"mount", meta.ReasonRootMountFailed, meta.Boot{RootFSType: "xfs"}},
		{"init", meta.ReasonInitNotFound, meta.Boot{Init: []string{"/sbin/nope"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			metaImg, w := newMeta(t)
			// Host data before boot: the stub must not wait for WAITING to be seen.
			tc.boot.RootSerial = "root"
			w.WriteHost(&meta.HostData{AllocationID: "a", Boot: tc.boot})
			v := startVM(t, e, metaImg)
			waitGuest(t, w, 30*time.Second, func(g *meta.GuestData) bool { return g.State == meta.StateWaiting })
			v.addDisk(t, root, "root")
			g := waitGuest(t, w, 30*time.Second, func(g *meta.GuestData) bool { return g.State == meta.StateFail })
			if g.Reason != tc.reason || g.Message == "" {
				t.Fatalf("%+v", g)
			}
			v.waitExit(t)
		})
	}
}
