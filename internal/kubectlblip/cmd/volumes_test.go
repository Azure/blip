package cmd

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/example/blip/internal/api/v1alpha1"
	"github.com/example/blip/internal/kubectlblip/guest"
	"github.com/example/blip/internal/kubectlblip/session"
)

// fakeKube swaps targetKube, selfIdentity and guestOps for a test. id nil
// means outside a Blip.
func fakeKube(t *testing.T, id *guest.Identity, objs ...client.Object) client.WithWatch {
	t.Helper()
	raw := fake.NewClientBuilder().WithScheme(session.Scheme()).WithObjects(objs...).
		WithStatusSubresource(&v1alpha1.Blip{}, &v1alpha1.BlipVol{}).Build()
	oldK, oldS, oldG := targetKube, selfIdentity, guestOps
	t.Cleanup(func() { targetKube, selfIdentity, guestOps = oldK, oldS, oldG })
	targetKube = func(e *env) (*session.Client, string, error) {
		ns := "default"
		if e.flags.namespace != "" {
			ns = e.flags.namespace
		}
		return &session.Client{C: raw, Log: e.logf, Poll: time.Millisecond}, ns, nil
	}
	selfIdentity = func() (guest.Identity, bool, error) {
		if id == nil {
			return guest.Identity{}, false, nil
		}
		return *id, true, nil
	}
	guestOps.sync = func() { t.Error("unexpected sync") }
	guestOps.findDevice = func(string) string { t.Error("unexpected findDevice"); return "" }
	guestOps.waitDevice = func(context.Context, string) (string, error) { return "", errors.New("unexpected waitDevice") }
	guestOps.mount = func(context.Context, string, string, bool) error { return errors.New("unexpected mount") }
	guestOps.unmountDevice = func(string) ([]string, error) { return nil, errors.New("unexpected unmount") }
	return raw
}

func run(args ...string) (string, error) {
	var out, errb bytes.Buffer
	root := NewRoot(strings.NewReader(""), &out, &errb)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), err
}

func TestTarget(t *testing.T) {
	fakeKube(t, &guest.Identity{Name: "self", Namespace: "home"})
	e := &env{}
	for _, c := range []struct {
		name, nsFlag, wantNS, wantName string
		self                           bool
	}{
		{"", "", "home", "self", true},
		{"self", "", "home", "self", true},
		{"other", "", "default", "other", false},
		{"", "elsewhere", "elsewhere", "self", false},
		{"self", "home", "home", "self", true},
	} {
		e.flags.namespace = c.nsFlag
		tg, err := e.target(c.name)
		if err != nil || tg.ns != c.wantNS || tg.name != c.wantName || tg.self != c.self {
			t.Errorf("%+v: %+v %v", c, tg, err)
		}
	}

	// Identity without namespace.
	fakeKube(t, &guest.Identity{Name: "self"})
	e.flags.namespace = ""
	if tg, err := e.target(""); err != nil || tg.ns != "default" || !tg.self {
		t.Fatal(tg, err)
	}

	// Lookup errors only matter without a name.
	fakeKube(t, nil)
	selfIdentity = func() (guest.Identity, bool, error) { return guest.Identity{}, false, errors.New("boom") }
	if _, err := e.target(""); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatal(err)
	}
	if tg, err := e.target("x"); err != nil || tg.self {
		t.Fatal(tg, err)
	}
}

func TestVolumeCommandsOutside(t *testing.T) {
	fakeKube(t, nil)
	for _, args := range [][]string{{"derive", "--volume", "root"}, {"attach", "bv"}, {"detach", "data"}} {
		if _, err := run(args...); err == nil || !strings.Contains(err.Error(), "not running inside a blip") {
			t.Errorf("%v: %v", args, err)
		}
	}
	if _, err := run("attach", "Bad_Name", "--to", "dev"); err == nil || !strings.Contains(err.Error(), "set --name") {
		t.Fatal(err)
	}
	if _, err := run("attach", "bv", "--to", "dev", "--mount", "/mnt"); err == nil || !strings.Contains(err.Error(), "--mount only works inside blip dev") {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"attach"}, {"detach"}, {"derive"}, {"derive", "a", "b"}, {"derive", "a", "--volume", "root"},
		{"derive", "a", "--snapshot", "0"}, {"derive", "a", "--interval", "1m"}, {"snapshot"}} {
		if _, err := run(args...); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}

func cmdBlip(vols ...string) *v1alpha1.Blip {
	b := &v1alpha1.Blip{ObjectMeta: metav1.ObjectMeta{Namespace: "home", Name: "self"}, Status: v1alpha1.BlipStatus{Phase: v1alpha1.BlipRunning}}
	for i := 0; i+1 < len(vols); i += 2 {
		b.Spec.Volumes = append(b.Spec.Volumes, v1alpha1.BlipVolume{Name: vols[i], BlipVolRef: v1alpha1.LocalObjectRef{Name: vols[i+1]}})
	}
	return b
}

// controller updates the Blip status with f until f returns true.
func controller(t *testing.T, raw client.Client, f func(b *v1alpha1.Blip) bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	go func() {
		for ctx.Err() == nil {
			b := &v1alpha1.Blip{}
			if raw.Get(ctx, client.ObjectKey{Namespace: "home", Name: "self"}, b) == nil && f(b) {
				_ = raw.Status().Update(ctx, b)
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
}

func srcVol(ns, name string) *v1alpha1.BlipVol {
	return &v1alpha1.BlipVol{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Status: v1alpha1.BlipVolStatus{Snapshots: []v1alpha1.VolSnapshot{{Sequence: 1, State: v1alpha1.SnapshotReady}}}}
}

func getVol(t *testing.T, raw client.Client, ns, name string) *v1alpha1.BlipVol {
	t.Helper()
	bv := &v1alpha1.BlipVol{}
	if err := raw.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: name}, bv); err != nil {
		t.Fatal(err)
	}
	return bv
}

func TestDerive(t *testing.T) {
	raw := fakeKube(t, nil, srcVol("default", "src"))
	out, err := run("derive", "src")
	if err != nil || !strings.HasPrefix(out, "src-") {
		t.Fatal(out, err)
	}
	if bv := getVol(t, raw, "default", strings.TrimSpace(out)); bv.Spec.Parent.Name != "src" || bv.Spec.Parent.Snapshot != nil || bv.Spec.SnapshotPolicy != nil {
		t.Fatal(bv.Spec)
	}
	out, err = run("derive", "src", "--name", "copy", "--snapshot", "1", "--skip-shutdown", "--interval", "30m", "--limit", "5")
	if err != nil || out != "copy\n" {
		t.Fatal(out, err)
	}
	bv := getVol(t, raw, "default", "copy")
	if p := bv.Spec.SnapshotPolicy; *bv.Spec.Parent.Snapshot != 1 || p == nil || !p.SkipShutdown || p.Limit != 5 || p.Interval.Duration != 30*time.Minute {
		t.Fatal(bv.Spec)
	}
	if _, err := run("derive", "src", "--snapshot", "9"); err == nil || !strings.Contains(err.Error(), "no snapshot 9") {
		t.Fatal(err)
	}
}

func TestDeriveWait(t *testing.T) {
	raw := fakeKube(t, nil, srcVol("default", "src"))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		for ctx.Err() == nil {
			bv := &v1alpha1.BlipVol{}
			if raw.Get(ctx, client.ObjectKey{Namespace: "default", Name: "copy"}, bv) == nil {
				bv.Status.Phase = v1alpha1.BlipVolReady
				_ = raw.Status().Update(ctx, bv)
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	if out, err := run("derive", "src", "--name", "copy", "--wait", "--timeout", "5s"); err != nil || out != "copy\n" {
		t.Fatal(out, err)
	}
}

func TestDeriveSelf(t *testing.T) {
	raw := fakeKube(t, &guest.Identity{Name: "self", Namespace: "home"}, cmdBlip("root", "img"), srcVol("home", "img"))
	synced := false
	guestOps.sync = func() { synced = true }
	out, err := run("derive", "--volume", "root", "--name", "snap")
	if err != nil || out != "snap\n" || !synced {
		t.Fatal(out, err, synced)
	}
	if bv := getVol(t, raw, "home", "snap"); bv.Spec.Parent.Name != "img" {
		t.Fatal(bv.Spec)
	}
	if _, err := run("derive", "--volume", "nope"); err == nil || !strings.Contains(err.Error(), "no volume nope") {
		t.Fatal(err)
	}
}

func TestVolumes(t *testing.T) {
	now := metav1.Now()
	src := srcVol("default", "src")
	src.UID = "uid-src"
	src.Status.Phase = v1alpha1.BlipVolReady
	src.Status.Current = 2
	src.Status.Snapshots = append(src.Status.Snapshots, v1alpha1.VolSnapshot{
		Sequence: 2, Reason: v1alpha1.SnapshotShutdown, State: v1alpha1.SnapshotReady, CaptureTime: &now,
		Writer: &v1alpha1.Writer{BlipName: "dev"},
	})
	src.Status.Claim = &v1alpha1.Claim{BlipName: "dev", Snapshot: 2}
	d := srcVol("default", "derived")
	d.Spec.Parent = &v1alpha1.ParentRef{Name: "src"}
	d.Status.Origin = &v1alpha1.OriginStatus{Namespace: "default", Name: "src", UID: "uid-src", Snapshot: 1}
	fakeKube(t, nil, src, d)
	out, err := run("volumes")
	if err != nil || !strings.Contains(out, "CURRENT") || !strings.Contains(out, "src@1") {
		t.Fatal(out, err)
	}
	lines := strings.Split(out, "\n")
	if f := strings.Fields(lines[2]); len(f) < 6 || f[0] != "src" || f[1] != "Ready" || f[2] != "2" || f[3] != "2" || f[4] != "2" || f[5] != "dev" {
		t.Fatal(out)
	}
	out, err = run("volumes", "src")
	for _, want := range []string{"Current:    2", "* 2", "Shutdown", "dev", "snapshot 1: origin of blipvol derived", "snapshot 2: start of the attachment to blip dev"} {
		if err != nil || !strings.Contains(out, want) {
			t.Fatalf("%q missing: %s %v", want, out, err)
		}
	}
	if _, err := run("volumes", "nope"); err == nil {
		t.Fatal("missing accepted")
	}
}

func TestAttachMountSelf(t *testing.T) {
	bv := &v1alpha1.BlipVol{ObjectMeta: metav1.ObjectMeta{Namespace: "home", Name: "bv"}}
	raw := fakeKube(t, &guest.Identity{Name: "self", Namespace: "home"}, cmdBlip("root", "img"), bv)
	var mounted string
	guestOps.waitDevice = func(_ context.Context, name string) (string, error) { return "/dev/vdb-" + name, nil }
	guestOps.mount = func(_ context.Context, dev, dir string, ro bool) error {
		mounted = dev + " " + dir
		if !ro {
			t.Error("not read-only")
		}
		return nil
	}
	controller(t, raw, func(b *v1alpha1.Blip) bool {
		if len(b.Spec.Volumes) < 2 {
			return false
		}
		b.Status.Volumes = []v1alpha1.BlipVolumeStatus{{Name: "data", AttachmentID: "a", State: v1alpha1.VolumeAttached, DevicePath: "/dev/disk/by-id/virtio-data"}}
		return true
	})
	out, err := run("attach", "bv", "--name", "data", "--mount", "/mnt/d", "--read-only", "--timeout", "5s")
	if err != nil || out != "/dev/vdb-data\n" || mounted != "/dev/vdb-data /mnt/d" {
		t.Fatal(out, err, mounted)
	}
}

func TestDetachSelfDelete(t *testing.T) {
	bv := &v1alpha1.BlipVol{ObjectMeta: metav1.ObjectMeta{Namespace: "home", Name: "bv"}}
	raw := fakeKube(t, &guest.Identity{Name: "self", Namespace: "home"}, cmdBlip("root", "img", "data", "bv"), bv)
	unmounted := false
	guestOps.findDevice = func(name string) string { return "/dev/vdb" }
	guestOps.unmountDevice = func(dev string) ([]string, error) { unmounted = dev == "/dev/vdb"; return []string{"/mnt/d"}, nil }
	out, err := run("detach", "data", "--delete", "--timeout", "5s")
	if err != nil || out != "volume/data detached\nblipvol/bv deleted\n" || !unmounted {
		t.Fatal(out, err, unmounted)
	}
	if err := raw.Get(context.Background(), client.ObjectKeyFromObject(bv), bv); err == nil {
		t.Fatal("blipvol not deleted")
	}
	// Unmount failure stops the detach.
	fakeKube(t, &guest.Identity{Name: "self", Namespace: "home"}, cmdBlip("root", "img", "data", "bv"))
	guestOps.findDevice = func(string) string { return "/dev/vdb" }
	guestOps.unmountDevice = func(string) ([]string, error) { return nil, errors.New("busy") }
	if _, err := run("detach", "data"); err == nil || !strings.Contains(err.Error(), "busy") {
		t.Fatal(err)
	}
}
