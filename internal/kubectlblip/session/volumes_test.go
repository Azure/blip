package session

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/example/blip/internal/api"
	"github.com/example/blip/internal/api/v1alpha1"
)

func TestValidateVolumeName(t *testing.T) {
	for _, n := range []string{"data", "a", "d-1", strings.Repeat("x", MaxVolumeName)} {
		if err := ValidateVolumeName(n); err != nil {
			t.Error(n, err)
		}
	}
	for _, n := range []string{"", "Data", "a_b", "-a", strings.Repeat("x", MaxVolumeName+1), "blip-meta"} {
		if err := ValidateVolumeName(n); err == nil {
			t.Errorf("%q accepted", n)
		}
	}
}

func volBlip(phase v1alpha1.BlipPhase, vols ...v1alpha1.BlipVolume) *v1alpha1.Blip {
	return &v1alpha1.Blip{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "dev", UID: "uid-dev"},
		Spec:       v1alpha1.BlipSpec{Volumes: vols},
		Status:     v1alpha1.BlipStatus{Phase: phase},
	}
}

func bvol(name, blipVol string) v1alpha1.BlipVolume {
	return v1alpha1.BlipVolume{Name: name, BlipVolRef: v1alpha1.LocalObjectRef{Name: blipVol}}
}

// fakeController applies f to the Blip until it returns true, updating
// the status when f changed it.
func fakeController(ctx context.Context, raw client.Client, f func(b *v1alpha1.Blip) (changed, done bool)) {
	go func() {
		for ctx.Err() == nil {
			b := &v1alpha1.Blip{}
			if raw.Get(ctx, types.NamespacedName{Namespace: "ns", Name: "dev"}, b) == nil {
				changed, done := f(b)
				if changed {
					_ = raw.Status().Update(ctx, b)
				}
				if done {
					return
				}
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()
}

func getBlip(t *testing.T, raw client.Client) *v1alpha1.Blip {
	t.Helper()
	b := &v1alpha1.Blip{}
	if err := raw.Get(context.Background(), types.NamespacedName{Namespace: "ns", Name: "dev"}, b); err != nil {
		t.Fatal(err)
	}
	return b
}

func testCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestDerive(t *testing.T) {
	ctx := testCtx(t)
	src := blipVol("src", nil)
	src.Status.Snapshots = []v1alpha1.VolSnapshot{{Sequence: 1, State: v1alpha1.SnapshotReady}, {Sequence: 2, State: v1alpha1.SnapshotFailed}}
	c, raw := newClient(src)
	bv, err := c.Derive(ctx, "ns", "src", DeriveOptions{})
	if err != nil || !strings.HasPrefix(bv.Name, "src-") || len(bv.Name) <= len("src-") || bv.Spec.Parent.Name != "src" || bv.Spec.Parent.Snapshot != nil {
		t.Fatal(bv, err)
	}
	if !exists(t, raw, bv) {
		t.Fatal("not created")
	}
	one := int64(1)
	pol := &v1alpha1.SnapshotPolicy{SkipShutdown: true, Limit: 3}
	bv, err = c.Derive(ctx, "ns", "src", DeriveOptions{Name: "copy", Snapshot: &one, Policy: pol})
	if err != nil || bv.Name != "copy" || *bv.Spec.Parent.Snapshot != 1 || !reflect.DeepEqual(bv.Spec.SnapshotPolicy, pol) {
		t.Fatal(bv, err)
	}
	for _, n := range []int64{2, 3} {
		if _, err := c.Derive(ctx, "ns", "src", DeriveOptions{Snapshot: &n}); err == nil {
			t.Errorf("snapshot %d accepted", n)
		}
	}
	if _, err := c.Derive(ctx, "ns", "nope", DeriveOptions{}); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatal(err)
	}
	long := BuildDerived("ns", strings.Repeat("a", 70), DeriveOptions{})
	if len(long.GenerateName)+5 > 63 {
		t.Fatal(long.GenerateName)
	}
}

func TestWaitVolume(t *testing.T) {
	ctx := testCtx(t)
	c, raw := newClient(blipVol("d", nil))
	var logs bytes.Buffer
	c.Log = func(f string, a ...any) { fmt.Fprintf(&logs, f+"\n", a...) }
	go func() {
		for i, st := range []struct {
			phase  v1alpha1.BlipVolPhase
			reason string
		}{{"", api.ReasonWaitingForCapture}, {"", api.ReasonDeletionBlocked}, {v1alpha1.BlipVolReady, "Ready"}} {
			time.Sleep(20 * time.Millisecond)
			bv := &v1alpha1.BlipVol{}
			_ = raw.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "d"}, bv)
			bv.Status.Phase = st.phase
			meta.SetStatusCondition(&bv.Status.Conditions, metav1.Condition{Type: api.CondReady, Status: metav1.ConditionFalse, Reason: st.reason, Message: fmt.Sprint("m", i)})
			_ = raw.Status().Update(ctx, bv)
		}
	}()
	if bv, err := c.WaitVolume(ctx, "ns", "d"); err != nil || bv.Status.Phase != v1alpha1.BlipVolReady {
		t.Fatal(bv, err)
	}
	if !strings.Contains(logs.String(), "WaitingForCapture: m0") || !strings.Contains(logs.String(), "DeletionBlocked: m1") {
		t.Fatal(logs.String())
	}

	f := blipVol("f", nil)
	f.Status.Phase = v1alpha1.BlipVolFailed
	f.Status.Conditions = []metav1.Condition{{Type: api.CondReady, Status: metav1.ConditionFalse, Reason: api.ReasonParentNotFound, Message: "gone"}}
	c, _ = newClient(f)
	if _, err := c.WaitVolume(ctx, "ns", "f"); err == nil || !strings.Contains(err.Error(), "ParentNotFound: gone") {
		t.Fatal(err)
	}
}

func TestAttachmentVolume(t *testing.T) {
	ctx := testCtx(t)
	c, _ := newClient(volBlip(v1alpha1.BlipRunning, bvol(RootVolume, "img")))
	if v, err := c.AttachmentVolume(ctx, "ns", "dev", RootVolume); err != nil || v != "img" {
		t.Fatal(v, err)
	}
	if _, err := c.AttachmentVolume(ctx, "ns", "dev", "x"); err == nil {
		t.Fatal("missing volume accepted")
	}
}

func TestPins(t *testing.T) {
	v := blipVol("v", nil)
	v.Status.Claim = &v1alpha1.Claim{BlipName: "dev", Snapshot: 3, Baseline: 5}
	v.Status.Holds = []v1alpha1.Hold{{Kind: v1alpha1.HoldClone, Holder: v1alpha1.HolderRef{Kind: "BlipVol", Name: "c"}, Snapshot: 4}}
	d := blipVol("d", nil)
	d.Status.Origin = &v1alpha1.OriginStatus{UID: "uid-v", Snapshot: 2}
	other := blipVol("o", nil)
	other.Status.Origin = &v1alpha1.OriginStatus{UID: "uid-x", Snapshot: 1}
	got := Pins(v, []v1alpha1.BlipVol{*v, *d, *other})
	want := []Pin{
		{2, "origin of blipvol d"},
		{3, "start of the attachment to blip dev"},
		{4, "clone hold by blipvol c on snapshot 4"},
		{5, "baseline of the attachment to blip dev"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v", got)
	}
	c, _ := newClient(v, d, other)
	l, err := c.ListVolumes(context.Background(), "ns", "")
	if err != nil || len(l) != 3 || l[2].Vol.Name != "v" || len(l[2].Pins) != 4 {
		t.Fatal(l, err)
	}
	if l, err := c.ListVolumes(context.Background(), "ns", "d"); err != nil || len(l) != 1 {
		t.Fatal(l, err)
	}
	if _, err := c.ListVolumes(context.Background(), "ns", "nope"); err == nil {
		t.Fatal("missing accepted")
	}
}

func blipVol(name string, labels map[string]string) *v1alpha1.BlipVol {
	return &v1alpha1.BlipVol{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: name, UID: types.UID("uid-" + name), Labels: labels}}
}

func TestAttach(t *testing.T) {
	ctx := testCtx(t)
	b := volBlip(v1alpha1.BlipRunning, bvol(RootVolume, "img"))
	// A stale entry of an earlier attachment of the same name.
	b.Status.Volumes = []v1alpha1.BlipVolumeStatus{{Name: "data", AttachmentID: "old", State: v1alpha1.VolumeReleased}}
	c, raw := newClient(b, blipVol("bv", nil), blipVol("other", nil))
	step := 0
	fakeController(ctx, raw, func(b *v1alpha1.Blip) (bool, bool) {
		if len(b.Spec.Volumes) < 2 {
			return false, false
		}
		step++
		switch step {
		case 1: // still the stale entry, but Attached: must be ignored
			b.Status.Volumes[0].State = v1alpha1.VolumeAttached
			return true, false
		case 2, 3, 4:
			return false, false
		}
		b.Status.Volumes[0] = v1alpha1.BlipVolumeStatus{Name: "data", AttachmentID: "new", State: v1alpha1.VolumeAttached, DevicePath: "/dev/disk/by-id/virtio-data"}
		return true, true
	})
	vs, err := c.Attach(ctx, "ns", "dev", "data", "bv")
	if err != nil || vs.AttachmentID != "new" || vs.DevicePath != "/dev/disk/by-id/virtio-data" {
		t.Fatal(vs, err)
	}
	if v := getBlip(t, raw).Spec.Volumes; len(v) != 2 || v[1] != bvol("data", "bv") {
		t.Fatal(v)
	}
	// Already requested: waits for it without changing the spec.
	if vs, err := c.Attach(ctx, "ns", "dev", "data", "bv"); err != nil || vs.AttachmentID != "new" {
		t.Fatal(vs, err)
	}
	if _, err := c.Attach(ctx, "ns", "dev", "data", "other"); err == nil || !strings.Contains(err.Error(), "already has a volume") {
		t.Fatal(err)
	}
}

func TestAttachFailed(t *testing.T) {
	ctx := testCtx(t)
	c, raw := newClient(volBlip(v1alpha1.BlipRunning, bvol(RootVolume, "img")), blipVol("bv", nil))
	fakeController(ctx, raw, func(b *v1alpha1.Blip) (bool, bool) {
		if len(b.Spec.Volumes) < 2 {
			return false, false
		}
		b.Status.Volumes = []v1alpha1.BlipVolumeStatus{{Name: "data", AttachmentID: "a", State: v1alpha1.VolumeFailed, Message: "no slot disk"}}
		return true, true
	})
	if _, err := c.Attach(ctx, "ns", "dev", "data", "bv"); err == nil || !strings.Contains(err.Error(), "no slot disk") {
		t.Fatal(err)
	}
}

func TestAttachErrors(t *testing.T) {
	ctx := testCtx(t)
	c, raw := newClient(volBlip(v1alpha1.BlipRunning, bvol(RootVolume, "img")), blipVol("bv", nil))
	for _, n := range []string{"Bad", "blip-meta", strings.Repeat("a", 21)} {
		if _, err := c.Attach(ctx, "ns", "dev", n, "bv"); err == nil || !strings.Contains(err.Error(), "invalid volume name") {
			t.Fatal(n, err)
		}
	}
	if _, err := c.Attach(ctx, "ns", "dev", "data", "missing"); err == nil || !strings.Contains(err.Error(), "blipvol missing not found") {
		t.Fatal(err)
	}
	if len(getBlip(t, raw).Spec.Volumes) != 1 {
		t.Fatal("spec changed")
	}
}

func TestDetach(t *testing.T) {
	ctx := testCtx(t)
	b := volBlip(v1alpha1.BlipRunning, bvol(RootVolume, "img"), bvol("data", "bv"))
	b.Status.Volumes = []v1alpha1.BlipVolumeStatus{{Name: "data", AttachmentID: "a", State: v1alpha1.VolumeAttached, BlipVolRef: &v1alpha1.ObjectRef{Name: "bv"}}}
	c, raw := newClient(b)
	fakeController(ctx, raw, func(b *v1alpha1.Blip) (bool, bool) {
		if len(b.Spec.Volumes) != 1 {
			return false, false
		}
		b.Status.Volumes[0].State = v1alpha1.VolumeReleased
		return true, true
	})
	if bv, err := c.Detach(ctx, "ns", "dev", "data"); err != nil || bv != "bv" {
		t.Fatal(bv, err)
	}
	if v := getBlip(t, raw).Spec.Volumes; len(v) != 1 || v[0].Name != RootVolume {
		t.Fatal(v)
	}
	// Already removed: returns the BlipVol from the status.
	if bv, err := c.Detach(ctx, "ns", "dev", "data"); err != nil || bv != "bv" {
		t.Fatal(bv, err)
	}
	if _, err := c.Detach(ctx, "ns", "dev", RootVolume); !errors.Is(err, ErrRootVolume) {
		t.Fatal(err)
	}
	if _, err := c.Detach(ctx, "ns", "dev", "nope"); err == nil || !strings.Contains(err.Error(), "no volume nope") {
		t.Fatal(err)
	}
}

func TestDetachAbsentStatus(t *testing.T) {
	ctx := testCtx(t)
	c, _ := newClient(volBlip(v1alpha1.BlipRunning, bvol(RootVolume, "img"), bvol("data", "bv")))
	// Never attached: no status entry, done at once.
	if bv, err := c.Detach(ctx, "ns", "dev", "data"); err != nil || bv != "bv" {
		t.Fatal(bv, err)
	}
}

func exists(t *testing.T, raw client.Client, o client.Object) bool {
	t.Helper()
	err := raw.Get(context.Background(), client.ObjectKeyFromObject(o), o)
	if err != nil && !apierrors.IsNotFound(err) {
		t.Fatal(err)
	}
	return err == nil
}

func TestDeleteVolume(t *testing.T) {
	ctx := context.Background()

	// Missing is fine.
	c, raw := newClient(blipVol("plain", nil))
	if _, err := c.DeleteVolume(ctx, "ns", "plain"); err != nil || exists(t, raw, blipVol("plain", nil)) {
		t.Fatal(err)
	}
	if _, err := c.DeleteVolume(ctx, "ns", "plain"); err != nil {
		t.Fatal(err)
	}

	// Waits until a finalizer is removed.
	fin := blipVol("v1", nil)
	fin.Finalizers = []string{"test/hold"}
	c, raw = newClient(fin)
	removed := make(chan struct{})
	go func() {
		defer close(removed)
		time.Sleep(30 * time.Millisecond)
		cur := &v1alpha1.BlipVol{}
		if err := raw.Get(ctx, client.ObjectKeyFromObject(fin), cur); err != nil {
			t.Error(err)
			return
		}
		cur.Finalizers = nil
		if err := raw.Update(ctx, cur); err != nil {
			t.Error(err)
		}
	}()
	if _, err := c.DeleteVolume(ctx, "ns", "v1"); err != nil || exists(t, raw, blipVol("v1", nil)) {
		t.Fatal(err)
	}
	select {
	case <-removed:
	default:
		t.Fatal("DeleteVolume returned before the finalizer was removed")
	}
	// Claimed or held: pending, no wait.
	for _, f := range []func(v *v1alpha1.BlipVol){
		func(v *v1alpha1.BlipVol) { v.Status.Claim = &v1alpha1.Claim{BlipName: "dev"} },
		func(v *v1alpha1.BlipVol) {
			v.Status.Holds = []v1alpha1.Hold{{Kind: v1alpha1.HoldClone, Holder: v1alpha1.HolderRef{Kind: "BlipVol", Name: "dev"}}}
		},
	} {
		v := blipVol("v1", nil)
		v.Finalizers = []string{"test/hold"}
		f(v)
		c, _ = newClient(v)
		if pending, err := c.DeleteVolume(ctx, "ns", "v1"); err != nil || !strings.Contains(pending, "dev") {
			t.Fatalf("want pending, got %q, %v", pending, err)
		}
	}

	tctx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	fin = blipVol("v1", nil)
	fin.Finalizers = []string{"test/hold"}
	c, _ = newClient(fin)
	if _, err := c.DeleteVolume(tctx, "ns", "v1"); err == nil || !strings.Contains(err.Error(), "not deleted") {
		t.Fatalf("want timeout error, got %v", err)
	}
}

func TestSetupNested(t *testing.T) {
	ctx := context.Background()
	c, raw := newClient()
	var out bytes.Buffer
	if err := c.Setup(ctx, "ns", true, &out); err != nil {
		t.Fatal(err)
	}
	want := "serviceaccount/blip-ssh created\nrole/blip-ssh created\nrolebinding/blip-ssh created\n" +
		"role/blip-ssh-nested created\nrolebinding/blip-ssh-nested created\n"
	if out.String() != want {
		t.Fatal(out.String())
	}
	r := &rbacv1.Role{}
	if err := raw.Get(ctx, client.ObjectKey{Namespace: "ns", Name: NestedRole}, r); err != nil || len(r.Rules) != 4 || r.Rules[3].Resources[0] != "pods/portforward" {
		t.Fatal(r.Rules, err)
	}
	rb := &rbacv1.RoleBinding{}
	if err := raw.Get(ctx, client.ObjectKey{Namespace: "ns", Name: NestedRole}, rb); err != nil ||
		rb.RoleRef.Name != NestedRole || len(rb.Subjects) != 1 || rb.Subjects[0].Name != ServiceAccount || rb.Subjects[0].Namespace != "ns" {
		t.Fatal(rb, err)
	}
	out.Reset()
	if err := c.Setup(ctx, "ns", true, &out); err != nil || strings.Count(out.String(), "\n") != 5 || strings.Contains(out.String(), "created") {
		t.Fatal(out.String(), err)
	}
	if objs, err := SetupObjects("ns", false); err != nil || len(objs) != 3 {
		t.Fatal(len(objs), err)
	}
}
