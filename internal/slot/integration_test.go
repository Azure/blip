package slot_test

// Root integration test: boots real guests (the blip-boot stub, then an
// alpine root with a scripted init) with Cloud Hypervisor on /dev/kvm,
// driven through the slot directory as the node daemon does: the metadata
// disk host slot, the assignment and hot-plug. Run with:
//
//	make -f hack/guest/Makefile guest rootfs
//	hack/guest/itest.sh

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/example/blip/internal/api"
	"github.com/example/blip/internal/meta"
	"github.com/example/blip/internal/slot"
	"github.com/example/blip/internal/slot/chapi"
)

type env struct {
	root, out, work, rootfs, slotdev string
}

var (
	envOnce sync.Once
	theEnv  env
	envErr  error
	vmSeq   atomic.Int32
)

func TestMain(m *testing.M) {
	code := m.Run()
	if theEnv.work != "" && os.Getenv("BLIP_KEEP_TEST_DIR") == "" {
		os.RemoveAll(theEnv.work)
	}
	os.Exit(code)
}

func setup(t *testing.T) env {
	t.Helper()
	if os.Getenv("BLIP_ROOT_TESTS") != "1" {
		t.Skip("set BLIP_ROOT_TESTS=1 and run as root")
	}
	envOnce.Do(func() {
		e := env{}
		wd, _ := os.Getwd()
		for e.root = wd; ; e.root = filepath.Dir(e.root) {
			if _, err := os.Stat(filepath.Join(e.root, "go.mod")); err == nil {
				break
			}
			if e.root == "/" {
				envErr = errors.New("go.mod not found")
				return
			}
		}
		e.out = filepath.Join(e.root, "_output/guest")
		for _, f := range []string{"cloud-hypervisor", "vmlinuz", "initramfs.cpio.gz", "blip-meta"} {
			if _, err := os.Stat(filepath.Join(e.out, f)); err != nil {
				envErr = fmt.Errorf("%v; run make -f hack/guest/Makefile guest", err)
				return
			}
		}
		base := os.Getenv("BLIP_GUEST_DIR")
		if base == "" {
			base = "/mnt/nvme2/blip/guest"
		}
		e.rootfs = filepath.Join(base, "rootfs-alpine")
		if _, err := os.Stat(e.rootfs); err != nil {
			envErr = fmt.Errorf("%v; run hack/guest/mkrootfs.sh", err)
			return
		}
		e.work = filepath.Join(base, "itest", fmt.Sprint(os.Getpid()))
		if envErr = os.MkdirAll(e.work, 0o755); envErr != nil {
			return
		}
		e.slotdev = filepath.Join(e.out, "slotdev")
		if _, err := os.Stat(e.slotdev); err != nil {
			envErr = fmt.Errorf("%v; run make -f hack/guest/Makefile guest", err)
			return
		}
		// Without capabilities, root cannot read files in a home
		// directory, so copy the artifacts next to the slot dirs.
		for _, f := range []string{"cloud-hypervisor", "vmlinuz", "initramfs.cpio.gz", "blip-meta"} {
			b, err := os.ReadFile(filepath.Join(e.out, f))
			if err == nil {
				err = os.WriteFile(filepath.Join(e.work, f), b, 0o755)
			}
			if err != nil {
				envErr = err
				return
			}
		}
		e.out = e.work
		theEnv = e
	})
	if envErr != nil {
		t.Fatal(envErr)
	}
	return theEnv
}

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if b, err := exec.CommandContext(ctx, name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v: %s", name, args, err, b)
	}
}

// vm is one slot: a netns with a veth to the host, a slot dir and a
// running slotdev. The netns is set up like the kindnet ptp CNI plugin:
// the pod has podIP/32 and a default route via hostIP on the link; the
// host has hostIP/32 on its end and a route to podIP/32.
type vm struct {
	t        *testing.T
	ns       string
	dir      string
	hostIP   string // host end of the veth, reachable from the guest
	podIP    string
	podMAC   string
	alloc    string
	cmd      *exec.Cmd
	exited   chan struct{}
	exitErr  error
	launched time.Time
}

func newVM(t *testing.T, e env, assigned bool) *vm {
	t.Helper()
	n := vmSeq.Add(1)
	v := &vm{
		t: t, ns: fmt.Sprintf("blipt-%d-%d", os.Getpid(), n),
		dir:    filepath.Join(e.work, fmt.Sprintf("vm%d", n)),
		hostIP: fmt.Sprintf("192.168.%d.1", 200+n), podIP: fmt.Sprintf("192.168.%d.2", 200+n),
		alloc:  fmt.Sprintf("alloc-%d-%d", os.Getpid()%10000, n),
		exited: make(chan struct{}),
	}
	if err := os.MkdirAll(v.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if assigned {
		os.WriteFile(filepath.Join(v.dir, slot.FileAssigned), nil, 0o644)
	}
	hostIf := fmt.Sprintf("bth%d", n)
	run(t, "ip", "netns", "add", v.ns)
	t.Cleanup(func() { exec.Command("ip", "netns", "del", v.ns).Run() })
	run(t, "ip", "link", "add", hostIf, "type", "veth", "peer", "name", "eth0", "netns", v.ns)
	t.Cleanup(func() { exec.Command("ip", "link", "del", hostIf).Run() })
	run(t, "ip", "addr", "add", v.hostIP+"/32", "dev", hostIf)
	run(t, "ip", "link", "set", hostIf, "up")
	run(t, "ip", "route", "add", v.podIP+"/32", "dev", hostIf)
	run(t, "ip", "-n", v.ns, "addr", "add", v.podIP+"/32", "dev", "eth0")
	run(t, "ip", "-n", v.ns, "link", "set", "eth0", "up")
	run(t, "ip", "-n", v.ns, "link", "set", "lo", "up")
	run(t, "ip", "-n", v.ns, "route", "add", "default", "via", v.hostIP, "dev", "eth0", "onlink")
	b, err := exec.Command("ip", "-n", v.ns, "-br", "link", "show", "eth0").Output()
	if f := strings.Fields(string(b)); err != nil || len(f) < 3 {
		t.Fatalf("pod eth0: %q %v", b, err)
	} else {
		v.podMAC = f[2]
	}

	logf, err := os.Create(filepath.Join(v.dir, "slot.log"))
	if err != nil {
		t.Fatal(err)
	}
	v.cmd = exec.Command("ip", "netns", "exec", v.ns, e.slotdev,
		"--run-dir", v.dir,
		"--cloud-hypervisor", filepath.Join(e.out, "cloud-hypervisor"),
		"--kernel", filepath.Join(e.out, "vmlinuz"),
		"--initramfs", filepath.Join(e.out, "initramfs.cpio.gz"),
		"--poll", "100ms")
	v.cmd.Env = append(os.Environ(), "VM_CPUS=1", "VM_MEMORY=512Mi")
	v.cmd.Stdout, v.cmd.Stderr = logf, logf
	v.launched = time.Now()
	if err := v.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { v.exitErr = v.cmd.Wait(); logf.Close(); close(v.exited) }()
	t.Cleanup(func() {
		v.cmd.Process.Kill()
		<-v.exited
		if t.Failed() {
			for _, f := range []string{"slot.log", slot.FileSerial} {
				b, _ := os.ReadFile(filepath.Join(v.dir, f))
				t.Logf("--- %s:\n%s", f, b)
			}
		}
	})
	return v
}

// waitExit waits for slotdev to end and returns its exit code.
func (v *vm) waitExit(d time.Duration) int {
	v.t.Helper()
	select {
	case <-v.exited:
	case <-time.After(d):
		v.t.Fatalf("slot did not exit within %v", d)
	}
	var ee *exec.ExitError
	if errors.As(v.exitErr, &ee) {
		return ee.ExitCode()
	}
	if v.exitErr != nil {
		v.t.Fatal(v.exitErr)
	}
	return 0
}

// waitReady waits for blipd slot to mark the slot ready (the stub reports
// WAITING) and returns the time since launch.
func (v *vm) waitReady() time.Duration {
	v.t.Helper()
	end := time.Now().Add(30 * time.Second)
	for time.Now().Before(end) {
		if _, err := os.Stat(filepath.Join(v.dir, slot.FileReady)); err == nil {
			return time.Since(v.launched)
		}
		select {
		case <-v.exited:
			v.t.Fatal("slot exited early")
		case <-time.After(5 * time.Millisecond):
		}
	}
	v.t.Fatal("slot not ready")
	return 0
}

// rootAtt is the attachment ID of the root volume; its serial is "root".
const rootAtt = "0123456789abcdef"

// start does what the node does for an allocation: assignment, host slot
// of the metadata disk, then hot-plug of a root image whose
// /sbin/blip-test-init is script. init defaults to that script.
func (v *vm) start(e env, script string, deadline time.Time, init ...string) string {
	v.t.Helper()
	if err := slot.WriteAssignment(v.dir, slot.Assignment{AllocationID: v.alloc, KillTime: deadline}); err != nil {
		v.t.Fatal(err)
	}
	os.Remove(filepath.Join(v.dir, slot.FileReady)) // as the node does
	if len(init) == 0 {
		init = []string{"/sbin/blip-test-init"}
	}
	w, err := meta.OpenWriter(filepath.Join(v.dir, slot.FileMeta))
	if err != nil {
		v.t.Fatal(err)
	}
	_, err = w.WriteHost(&meta.HostData{AllocationID: v.alloc, Hostname: "itest",
		Identity: meta.Identity{Name: "itest", Namespace: "ns", UID: "u"},
		Boot:     meta.Boot{RootSerial: "root", Init: init, RootFSType: "ext4"}})
	w.Close()
	if err != nil {
		v.t.Fatal(err)
	}
	dir := filepath.Join(v.dir, "rootfs")
	run(v.t, "cp", "-a", e.rootfs, dir)
	run(v.t, "cp", filepath.Join(e.out, "blip-meta"), filepath.Join(dir, "usr/bin/blip-meta"))
	if err := os.WriteFile(filepath.Join(dir, "sbin/blip-test-init"), []byte(script), 0o755); err != nil {
		v.t.Fatal(err)
	}
	img := filepath.Join(v.dir, "root.img")
	run(v.t, "mkfs.ext4", "-q", "-F", "-d", dir, img, "256M")
	os.RemoveAll(dir)
	link := slot.VolumePath(v.dir, "uroot")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		v.t.Fatal(err)
	}
	if err := os.Symlink(img, link); err != nil {
		v.t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if _, err := slot.Client(v.dir).AddDisk(ctx, chapi.VolumeDisk(link, rootAtt, "root")); err != nil {
		v.t.Fatal(err)
	}
	return img
}

// exit waits for the slot to end and returns exit.json.
func (v *vm) exit(d time.Duration) (*slot.ExitRecord, int) {
	v.t.Helper()
	code := v.waitExit(d)
	rec, err := slot.ReadExit(v.dir)
	if err != nil {
		v.t.Fatal(err)
	}
	return rec, code
}

// console returns the guest console output (the boot after the last
// reboot), as lines.
func (v *vm) console() string {
	b, _ := os.ReadFile(filepath.Join(v.dir, slot.FileSerial))
	return strings.ReplaceAll(string(b), "\r", "")
}

const initHead = "#!/bin/sh\nmount -t proc proc /proc 2>/dev/null\nmount -t sysfs sys /sys 2>/dev/null\n"

func TestIntegrationSuccess(t *testing.T) {
	e := setup(t)
	v := newVM(t, e, false)
	t.Logf("boot to ready: %v", v.waitReady())
	// The guest takes the pod IP over DHCP, reaches the host, reports
	// its exit code and powers off.
	v.start(e, initHead+`echo blip-test-init running
ip link set lo up
ip link set eth0 up
udhcpc -i eth0 -n -q -t 5 -T 1 && echo dhcp-ok
ip -4 addr show eth0
echo hostname=$(hostname)
ping -c 1 -W 2 `+v.hostIP+` >/dev/null && echo ping-ok
/usr/bin/blip-meta exit 0
poweroff -f
`, time.Now().Add(time.Hour))
	rec, code := v.exit(60 * time.Second)
	if code != 0 || rec.Reason != api.ReasonSucceeded || rec.GuestExitCode == nil || *rec.GuestExitCode != 0 || rec.BootCount != 1 {
		t.Fatalf("exit %d %+v", code, rec)
	}
	con := v.console()
	for _, want := range []string{"blip-test-init running", "dhcp-ok", "inet " + v.podIP + "/", "ping-ok"} {
		if !strings.Contains(con, want) {
			t.Errorf("console lacks %q", want)
		}
	}
}

func TestIntegrationInitExited(t *testing.T) {
	e := setup(t)
	v := newVM(t, e, false)
	v.waitReady()
	v.start(e, initHead+"echo bye\nexit 3\n", time.Now().Add(time.Hour))
	rec, _ := v.exit(60 * time.Second)
	if rec.Reason != api.ReasonInitExited || rec.GuestExitCode == nil || *rec.GuestExitCode != 3 || !strings.Contains(rec.Message, "Attempted to kill init") {
		t.Fatalf("%+v", rec)
	}
}

func TestIntegrationPanic(t *testing.T) {
	e := setup(t)
	v := newVM(t, e, false)
	v.waitReady()
	v.start(e, initHead+"echo c > /proc/sysrq-trigger\nsleep 100\n", time.Now().Add(time.Hour))
	rec, _ := v.exit(60 * time.Second)
	if rec.Reason != api.ReasonGuestPanic || rec.GuestExitCode != nil || !strings.Contains(rec.Message, "Kernel panic") {
		t.Fatalf("%+v", rec)
	}
}

func TestIntegrationReboot(t *testing.T) {
	e := setup(t)
	v := newVM(t, e, false)
	v.waitReady()
	v.start(e, initHead+`mount -o remount,rw /
if [ -e /rebooted ]; then echo second-boot; /usr/bin/blip-meta exit 4; poweroff -f; fi
touch /rebooted
sync
reboot -f
`, time.Now().Add(time.Hour))
	rec, code := v.exit(90 * time.Second)
	if code != 0 || rec.BootCount != 2 || rec.GuestExitCode == nil || *rec.GuestExitCode != 4 || rec.Reason != api.ReasonError {
		t.Fatalf("exit %d %+v", code, rec)
	}
	// The serial log was truncated at the reboot.
	if con := v.console(); !strings.Contains(con, "second-boot") {
		t.Fatalf("console:\n%s", con)
	}
	if _, err := os.Stat(filepath.Join(v.dir, slot.FileReady)); err == nil {
		t.Fatal("ready again after the reboot of an assigned slot")
	}
}

func TestIntegrationBootFailed(t *testing.T) {
	e := setup(t)
	v := newVM(t, e, false)
	v.waitReady()
	// Init is missing from the root: the stub reports FAIL and powers off.
	v.start(e, initHead, time.Now().Add(time.Hour), "/sbin/nope")
	rec, _ := v.exit(60 * time.Second)
	if rec.Reason != api.ReasonBootFailed || !strings.Contains(rec.Message, "("+meta.ReasonInitNotFound+")") {
		t.Fatalf("%+v", rec)
	}
}

func TestIntegrationDeadline(t *testing.T) {
	e := setup(t)
	v := newVM(t, e, false)
	v.waitReady()
	v.start(e, initHead+"sleep 1000\n", time.Now().Add(3*time.Second))
	begin := time.Now()
	rec, code := v.exit(30 * time.Second)
	if code == 0 || rec.Reason != api.ReasonTTLExceeded || rec.Cause != "deadline" {
		t.Fatalf("exit %d %+v", code, rec)
	}
	t.Logf("killed %v after start", time.Since(begin))
}

func TestIntegrationKill(t *testing.T) {
	e := setup(t)
	v := newVM(t, e, false)
	v.waitReady()
	v.start(e, initHead+"sleep 1000\n", time.Now().Add(time.Hour))
	// busybox init ignores the power button; the press must not break anything.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := slot.PowerButton(ctx, v.dir); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	if err := slot.RequestKill(v.dir); err != nil {
		t.Fatal(err)
	}
	rec, _ := v.exit(30 * time.Second)
	if rec.Reason != api.ReasonHypervisorExited || rec.Cause != "killed" {
		t.Fatalf("%+v", rec)
	}
}

func TestIntegrationAssignedRefuses(t *testing.T) {
	e := setup(t)
	v := newVM(t, e, true)
	if code := v.waitExit(10 * time.Second); code == 0 {
		t.Fatal("slot booted although assigned")
	}
	if _, err := os.Stat(filepath.Join(v.dir, slot.FileAPISocket)); err == nil {
		t.Fatal("cloud-hypervisor was started")
	}
}
