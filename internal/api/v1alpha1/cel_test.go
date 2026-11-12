package v1alpha1_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	v1 "github.com/example/blip/internal/api/v1alpha1"
)

// TestCEL checks the CRD validation rules against a real kube-apiserver.
// It runs only when KUBEBUILDER_ASSETS is set (see make test-envtest).
func TestCEL(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS not set")
	}
	te := &envtest.Environment{CRDDirectoryPaths: []string{filepath.Join("..", "..", "..", "config", "base", "crd")}, ErrorIfCRDPathMissing: true}
	cfg, err := te.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = te.Stop() })
	s := runtime.NewScheme()
	if err := v1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	c, err := client.New(cfg, client.Options{Scheme: s})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	n := 0
	vol := func(name, ref string) v1.BlipVolume {
		return v1.BlipVolume{Name: name, BlipVolRef: v1.LocalObjectRef{Name: ref}}
	}
	blip := func(root string, vols ...v1.BlipVolume) *v1.Blip {
		n++
		return &v1.Blip{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("b%d", n), Namespace: "default"},
			Spec:       v1.BlipSpec{RootVolume: root, Volumes: vols},
		}
	}
	create := func(name string, b *v1.Blip, wantErr string) {
		t.Helper()
		err := c.Create(ctx, b)
		check(t, name, err, wantErr)
	}

	create("root not in list", blip("root", vol("data", "d")), "rootVolume must name an entry")
	create("bad name", blip("Root", vol("Root", "img")), "volumes[0].name")
	create("no volumes", blip("root"), "volumes")
	create("volume name too long", blip("root", vol("root", "img"), vol("abcdefghijklmnopqrstu", "d")), "volumes[1].name")
	create("volume name 20", blip("root", vol("root", "img"), vol("abcdefghijklmnopqrst", "d")), "")
	create("reserved volume name", blip("root", vol("root", "img"), vol("blip-meta", "d")), "blip-meta is reserved")
	in := blip("root", vol("root", "img"))
	create("init default", in, "")
	if len(in.Spec.Init) != 1 || in.Spec.Init[0] != "/sbin/init" {
		t.Errorf("init default: %q", in.Spec.Init)
	}
	in = blip("root", vol("root", "img"))
	in.Spec.Init = []string{"sbin/init"}
	create("init relative", in, "absolute path")
	in = blip("root", vol("root", "img"))
	in.Spec.Init = []string{"/lib/systemd/systemd", "--unit=multi-user.target"}
	in.Spec.RootMountOptions = "noatime,errors=remount-ro"
	create("init argv and mount options", in, "")
	in = blip("root", vol("root", "img"))
	in.Spec.RootMountOptions = strings.Repeat("a", 257)
	create("mount options too long", in, "rootMountOptions")
	many := []v1.BlipVolume{}
	for i := 0; i < 17; i++ {
		many = append(many, vol(fmt.Sprintf("v%d", i), "d"))
	}
	create("too many volumes", blip("v0", many...), "must have at most 16 items")
	rs := blip("root", vol("root", "img"))
	rs.Spec.Reschedule = &v1.ReschedulePolicy{InitialBackoffSeconds: 60, MaxBackoffSeconds: 30}
	create("reschedule max below initial", rs, "maxBackoffSeconds must be at least initialBackoffSeconds")
	rs = blip("root", vol("root", "img"))
	rs.Spec.Reschedule = &v1.ReschedulePolicy{}
	create("reschedule defaults", rs, "")
	if p := rs.Spec.Reschedule; p.InitialBackoffSeconds != 10 || p.MaxBackoffSeconds != 300 || p.Limit != nil ||
		p.SalvageTimeout == nil || p.SalvageTimeout.Duration != 5*time.Minute || p.NodeLoss != v1.NodeLossFence {
		t.Errorf("reschedule defaults: %+v", p)
	}
	rs = blip("root", vol("root", "img"))
	rs.Spec.Reschedule = &v1.ReschedulePolicy{NodeLoss: v1.NodeLossAbandon}
	create("nodeLoss Abandon", rs, "")
	rs = blip("root", vol("root", "img"))
	rs.Spec.Reschedule = &v1.ReschedulePolicy{NodeLoss: "Ignore"}
	create("nodeLoss invalid", rs, "nodeLoss")

	// Updates.
	b := blip("root", vol("root", "img"), vol("data", "d"))
	create("base", b, "")
	update := func(name string, mut func(*v1.Blip), wantErr string) {
		t.Helper()
		cp := b.DeepCopy()
		mut(cp)
		err := c.Update(ctx, cp)
		check(t, name, err, wantErr)
		if err == nil {
			b = cp
		}
	}
	update("add volume", func(b *v1.Blip) { b.Spec.Volumes = append(b.Spec.Volumes, vol("extra", "e")) }, "")
	update("remove volume", func(b *v1.Blip) { b.Spec.Volumes = b.Spec.Volumes[:len(b.Spec.Volumes)-1] }, "")
	update("mutate entry", func(b *v1.Blip) { b.Spec.Volumes[1].BlipVolRef.Name = "other" }, "immutable")
	update("root blipVolRef", func(b *v1.Blip) { b.Spec.Volumes[0].BlipVolRef.Name = "z" }, "immutable")
	update("remove root entry", func(b *v1.Blip) { b.Spec.Volumes = b.Spec.Volumes[1:] }, "root volume entry cannot be removed")
	update("change rootVolume", func(b *v1.Blip) { b.Spec.RootVolume = "data" }, "immutable")
	update("change init", func(b *v1.Blip) { b.Spec.Init = []string{"/bin/sh"} }, "immutable")
	update("change rootMountOptions", func(b *v1.Blip) { b.Spec.RootMountOptions = "ro" }, "immutable")
	update("add reschedule", func(b *v1.Blip) { b.Spec.Reschedule = &v1.ReschedulePolicy{} }, "immutable")
	update("ttl mutable", func(b *v1.Blip) { ttl := int64(9); b.Spec.TTLSecondsAfterFinished = &ttl }, "")

	// BlipVol.
	vn := 0
	bv := func(spec v1.BlipVolSpec) *v1.BlipVol {
		vn++
		return &v1.BlipVol{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("v%d", vn), Namespace: "default"}, Spec: spec}
	}
	dur := func(s string) *metav1.Duration {
		d, err := time.ParseDuration(s)
		if err != nil {
			t.Fatal(err)
		}
		return &metav1.Duration{Duration: d}
	}
	size := resource.MustParse("1Gi")
	img := &v1.ImageSource{Reference: "example.com/img:1"}
	i64 := func(v int64) *int64 { return &v }
	for _, tc := range []struct {
		name string
		spec v1.BlipVolSpec
		err  string
	}{
		{"image and parent", v1.BlipVolSpec{Image: img, Parent: &v1.ParentRef{Name: "p"}}, "at most one of image and parent"},
		{"parent and size", v1.BlipVolSpec{Parent: &v1.ParentRef{Name: "p"}, Size: &size}, "size is not allowed with parent"},
		{"parent snapshot", v1.BlipVolSpec{Parent: &v1.ParentRef{Name: "p", Snapshot: i64(3)}}, ""},
		{"parent snapshot 0", v1.BlipVolSpec{Parent: &v1.ParentRef{Name: "p", Snapshot: i64(0)}}, "snapshot"},
		{"interval 4m", v1.BlipVolSpec{Size: &size, SnapshotPolicy: &v1.SnapshotPolicy{Interval: dur("4m")}}, "at least 5m"},
		{"interval 300s", v1.BlipVolSpec{Size: &size, SnapshotPolicy: &v1.SnapshotPolicy{Interval: dur("300s")}}, ""},
		{"limit 0 defaults", v1.BlipVolSpec{Size: &size, SnapshotPolicy: &v1.SnapshotPolicy{}}, ""},
		{"limit 100", v1.BlipVolSpec{Size: &size, SnapshotPolicy: &v1.SnapshotPolicy{Limit: 100}}, ""},
		{"limit 101", v1.BlipVolSpec{Size: &size, SnapshotPolicy: &v1.SnapshotPolicy{Limit: 101}}, "limit"},
		{"limit negative", v1.BlipVolSpec{Size: &size, SnapshotPolicy: &v1.SnapshotPolicy{Limit: -1}}, "limit"},
	} {
		o := bv(tc.spec)
		check(t, "blipvol "+tc.name, c.Create(ctx, o), tc.err)
		if tc.name == "limit 0 defaults" && o.Spec.SnapshotPolicy.Limit != 24 {
			t.Errorf("limit default: %d", o.Spec.SnapshotPolicy.Limit)
		}
	}
	vu := bv(v1.BlipVolSpec{Image: img})
	check(t, "blipvol base", c.Create(ctx, vu), "")
	vupdate := func(name string, o *v1.BlipVol, mut func(*v1.BlipVolSpec), wantErr string) {
		t.Helper()
		cp := o.DeepCopy()
		mut(&cp.Spec)
		err := c.Update(ctx, cp)
		check(t, name, err, wantErr)
		if err == nil {
			*o = *cp
		}
	}
	vupdate("add snapshotPolicy", vu, func(s *v1.BlipVolSpec) { s.SnapshotPolicy = &v1.SnapshotPolicy{Interval: dur("1h"), Limit: 3} }, "")
	vupdate("change snapshotPolicy", vu, func(s *v1.BlipVolSpec) { s.SnapshotPolicy.SkipShutdown = true; s.SnapshotPolicy.Limit = 5 }, "")
	vupdate("interval too short on update", vu, func(s *v1.BlipVolSpec) { s.SnapshotPolicy.Interval = dur("1m") }, "at least 5m")
	vupdate("remove snapshotPolicy", vu, func(s *v1.BlipVolSpec) { s.SnapshotPolicy = nil }, "")
	vupdate("change image", vu, func(s *v1.BlipVolSpec) { s.Image.Reference = "example.com/img:2" }, "image is immutable")
	vupdate("remove image", vu, func(s *v1.BlipVolSpec) { s.Image = nil }, "image is immutable")
	vupdate("add size", vu, func(s *v1.BlipVolSpec) { s.Size = &size }, "size is immutable")
	vp := bv(v1.BlipVolSpec{Parent: &v1.ParentRef{Name: "p"}})
	check(t, "blipvol parent", c.Create(ctx, vp), "")
	vupdate("change parent", vp, func(s *v1.BlipVolSpec) { s.Parent.Snapshot = i64(2) }, "parent is immutable")
	vupdate("parent snapshotPolicy", vp, func(s *v1.BlipVolSpec) { s.SnapshotPolicy = &v1.SnapshotPolicy{SkipShutdown: true} }, "")
	vs := bv(v1.BlipVolSpec{Size: &size})
	check(t, "blipvol size", c.Create(ctx, vs), "")
	vupdate("change size", vs, func(s *v1.BlipVolSpec) { q := resource.MustParse("2Gi"); s.Size = &q }, "size is immutable")
	vupdate("same size", vs, func(s *v1.BlipVolSpec) { q := resource.MustParse("1024Mi"); s.Size = &q }, "")

	// BlipPool.
	pn := 0
	pool := func(mut func(*v1.BlipPoolSpec)) *v1.BlipPool {
		pn++
		p := &v1.BlipPool{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("p%d", pn), Namespace: "default"},
			Spec:       v1.BlipPoolSpec{CPUs: 2, Memory: resource.MustParse("2Gi"), MinFree: 1, MaxFree: 4},
		}
		if mut != nil {
			mut(&p.Spec)
		}
		return p
	}
	i32 := func(v int32) *int32 { return &v }
	p := pool(nil)
	check(t, "pool create", c.Create(ctx, p), "")
	if p.Spec.SKU != "default" || p.Spec.DemandWindow == nil || p.Spec.DemandWindow.Duration != 5*time.Minute || p.Spec.ScaleDownDelay == nil || p.Spec.ScaleDownDelay.Duration != 10*time.Minute {
		t.Errorf("pool defaults: %+v", p.Spec)
	}
	p.Spec.SKU = "other"
	check(t, "pool sku immutable", c.Update(ctx, p), "sku is immutable")
	for _, tc := range []struct {
		name string
		mut  func(*v1.BlipPoolSpec)
		err  string
	}{
		{"minFree > maxFree", func(s *v1.BlipPoolSpec) { s.MinFree = 5 }, "minFree must not exceed maxFree"},
		{"maxSlots < maxFree", func(s *v1.BlipPoolSpec) { s.MaxSlots = i32(3) }, "maxSlots must be at least maxFree"},
		{"maxSlots ok", func(s *v1.BlipPoolSpec) { s.MaxSlots = i32(4) }, ""},
		{"memory small", func(s *v1.BlipPoolSpec) { s.Memory = resource.MustParse("255Mi") }, "at least 256Mi"},
		{"memory 256Mi", func(s *v1.BlipPoolSpec) { s.Memory = resource.MustParse("256Mi") }, ""},
		{"memory not MiB", func(s *v1.BlipPoolSpec) { s.Memory = resource.MustParse("1000M") }, "whole number of MiB"},
		{"cpus 0", func(s *v1.BlipPoolSpec) { s.CPUs = 0 }, "cpus"},
		{"bad hypervisor", func(s *v1.BlipPoolSpec) { s.Hypervisor = "xen" }, "hypervisor"},
		{"mshv", func(s *v1.BlipPoolSpec) { s.Hypervisor = v1.HypervisorMSHV }, ""},
	} {
		check(t, "pool "+tc.name, c.Create(ctx, pool(tc.mut)), tc.err)
	}
}

func check(t *testing.T, name string, err error, wantErr string) {
	t.Helper()
	switch {
	case wantErr == "" && err != nil:
		t.Errorf("%s: unexpected error: %v", name, err)
	case wantErr != "" && err == nil:
		t.Errorf("%s: accepted, want error %q", name, wantErr)
	case wantErr != "" && !strings.Contains(err.Error(), wantErr):
		t.Errorf("%s: error %v, want %q", name, err, wantErr)
	}
}
