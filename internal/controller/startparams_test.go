package controller

import (
	"context"
	"slices"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"

	"github.com/example/blip/internal/api"
	v1 "github.com/example/blip/internal/api/v1alpha1"
	"github.com/example/blip/internal/proto/nodepb"
	"github.com/example/blip/internal/testing/fakenode"
)

func startOf(b *v1.Blip) *nodepb.StartWorkload {
	var start *nodepb.StartWorkload
	for _, c := range env.nodes["s1"].Commands() {
		if s := c.GetStartWorkload(); s != nil && s.AllocationId == b.Status.Allocation.ID {
			start = s
		}
	}
	return start
}

// TestStartParams checks that StartWorkload carries init argv, root mount
// options, root volume name, hostname and identity.
func TestStartParams(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "sp", "s1", "s1")
	emptyVol(t, ns, "ws")
	setWork(ns, "b", fakenode.Hang())
	newBlip(t, ns, "b", "ws", "sp", func(b *v1.Blip) {
		b.Spec.Init = []string{"/lib/systemd/systemd", "--unit=multi-user.target"}
		b.Spec.RootMountOptions = "noatime"
	})
	b := waitBlip(t, ns, "b", 20*time.Second, func(b *v1.Blip) bool { return isTrue(b.Status.Conditions, api.CondStarted) })
	start := startOf(b)
	p := start.GetParams()
	if !slices.Equal(p.GetInit(), []string{"/lib/systemd/systemd", "--unit=multi-user.target"}) || p.GetRootMountOptions() != "noatime" || p.GetHostname() != "b" {
		t.Fatalf("params %+v", p)
	}
	if start.Blip.GetUid() != string(b.UID) || start.Blip.GetNamespace() != ns || start.Blip.GetName() != "b" {
		t.Fatalf("start %+v", start)
	}
	// Immutable.
	var cur v1.Blip
	if err := env.k.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: "b"}, &cur); err != nil {
		t.Fatal(err)
	}
	cur.Spec.Init = []string{"/bin/sh"}
	if err := env.k.Update(context.Background(), &cur); err == nil {
		t.Fatal("init changed")
	}
	// Defaulted.
	emptyVol(t, ns, "ws2")
	setWork(ns, "d", fakenode.Hang())
	d := newBlip(t, ns, "d", "ws2", "sp", nil)
	if !slices.Equal(d.Spec.Init, []string{"/sbin/init"}) {
		t.Fatalf("default init %q", d.Spec.Init)
	}
	d = waitBlip(t, ns, "d", 20*time.Second, func(b *v1.Blip) bool { return isTrue(b.Status.Conditions, api.CondStarted) })
	if got := startOf(d).GetParams().GetInit(); !slices.Equal(got, []string{"/sbin/init"}) {
		t.Fatalf("start init %q", got)
	}
}
