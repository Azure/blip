package controller

import (
	"context"
	"maps"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

const testOwner = "u-0123456789abcdef0123456789abcdef"

func withOwner(owner string) func(*v1.Blip) {
	return func(b *v1.Blip) { b.Labels = map[string]string{v1.LabelOwner: owner} }
}

func (e *env) owners() map[string]string {
	e.t.Helper()
	cm := &corev1.ConfigMap{}
	e.must(e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: VMOwnersConfigMap}, cm))
	return cm.Data
}

// claimCheck fails a pod claim whose owner entry is not written yet.
type claimCheck struct {
	client.Client
	e      *env
	claims int
}

func (c *claimCheck) Patch(ctx context.Context, o client.Object, p client.Patch, opts ...client.PatchOption) error {
	if pod, ok := o.(*corev1.Pod); ok && pod.Labels[v1.LabelBlipUID] != "" {
		c.claims++
		if got := c.e.owners()[pod.Name]; got == "" {
			c.e.t.Errorf("pod %s claimed before its owner entry was written", pod.Name)
		}
	}
	return c.Client.Patch(ctx, o, p, opts...)
}

func TestVMOwnersWrittenBeforeClaim(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 0, 0)
	check := &claimCheck{Client: e.c, e: e}
	e.blip.Client = check
	root := e.readyState(testOwner+".root", "n1")
	root.Labels = map[string]string{v1.LabelOwner: testOwner}
	e.must(e.c.Update(e.ctx, root))
	e.readyState("plain-root", "n2")

	b := e.startBlip(testOwner+".a", "n1", withRoot(testOwner+".root"), withOwner(testOwner))
	plain := e.startBlip("plain", "n2", withRoot("plain-root"))
	if check.claims != 2 {
		t.Fatalf("claims = %d", check.claims)
	}
	want := map[string]string{"sa.vm": "default", b.Status.Pod: testOwner, plain.Status.Pod: ownerAny}
	if got := e.owners(); !maps.Equal(got, want) {
		t.Fatalf("owners = %v, want %v", got, want)
	}
	// Claimed pods carry their owner for the guest API proxy. Warm pods stay
	// unlabelled so they are never exposed.
	if got := e.getPod(b.Status.Pod).Labels[v1.LabelOwner]; got != testOwner {
		t.Errorf("owned pod owner label = %q", got)
	}
	if got := e.getPod(plain.Status.Pod).Labels[v1.LabelOwner]; got != "" {
		t.Errorf("unrestricted pod owner label = %q, want none", got)
	}
	if uid := e.getPod(b.Status.Pod).Labels[v1.LabelBlipUID]; uid != string(b.UID) {
		t.Errorf("owned pod lost its blip UID label: %q", uid)
	}
}

func TestVMOwnersSync(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 1, 0)
	e.run(e.pool, ns, "default")
	if got := e.owners(); !maps.Equal(got, map[string]string{"sa.vm": "default"}) {
		t.Fatalf("owners of an idle pool = %v", got)
	}
	root := e.readyState(testOwner+".root", "n1")
	root.Labels = map[string]string{v1.LabelOwner: testOwner}
	e.must(e.c.Update(e.ctx, root))
	b := e.startBlip(testOwner+".a", "n1", withRoot(testOwner+".root"), withOwner(testOwner))

	// Rebuilt after loss, and stale entries are dropped.
	cm := &corev1.ConfigMap{}
	e.must(e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: VMOwnersConfigMap}, cm))
	e.must(e.c.Delete(e.ctx, cm))
	e.run(e.pool, ns, "default")
	e.must(patchVMOwners(e.ctx, e.c, ns, map[string]*string{"default-gone": new(string), "sa.old": new(string)}))
	e.run(e.pool, ns, "default")
	want := map[string]string{"sa.vm": "default", b.Status.Pod: testOwner}
	if got := e.owners(); !maps.Equal(got, want) {
		t.Fatalf("owners = %v, want %v", got, want)
	}

	// The entry goes with the pod.
	e.must(e.c.Delete(e.ctx, e.getPod(b.Status.Pod)))
	e.run(e.pool, ns, "default")
	if got := e.owners(); got[b.Status.Pod] != "" || got["sa.vm"] != "default" || len(got) != 1 {
		t.Fatalf("owners after pod deletion = %v", got)
	}
}

func TestVMOwnersSharedBases(t *testing.T) {
	e := newEnv(t)
	e.newPool("default", 0, 0)
	e.newState("base-tools", func(s *v1.BlipState) { s.Spec.Image = "reg/tools:v1" })
	e.newState("base-dev", func(s *v1.BlipState) { s.Spec.Image = "reg/dev:v1" })
	e.newState("private-base", func(s *v1.BlipState) {
		s.Spec.Image = "reg/private:v1"
		s.Labels = map[string]string{v1.LabelOwner: testOwner}
	})
	e.newState("workspace", func(s *v1.BlipState) { s.Spec.CopyFrom = "base-dev" })
	e.must(syncVMOwners(e.ctx, e.c, ns))
	if got := e.owners()[ownersBasesKey]; got != "base-dev base-tools" {
		t.Fatalf("shared bases = %q", got)
	}
	e.must(e.c.Delete(e.ctx, e.getState("base-tools")))
	e.must(syncVMOwners(e.ctx, e.c, ns))
	if got := e.owners()[ownersBasesKey]; got != "base-dev" {
		t.Fatalf("shared bases after deletion = %q", got)
	}
	base := e.getState("base-dev")
	base.Labels = map[string]string{v1.LabelOwner: testOwner}
	e.must(e.c.Update(e.ctx, base))
	e.must(syncVMOwners(e.ctx, e.c, ns))
	if _, ok := e.owners()[ownersBasesKey]; ok {
		t.Fatal("private base remains shared")
	}
}

func TestVMOwnersRestoredAfterLostClaim(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.readyState("first-root", "n1")
	root := e.readyState(testOwner+".root", "n1")
	root.Labels = map[string]string{v1.LabelOwner: testOwner}
	e.must(e.c.Update(e.ctx, root))
	stale := func() corev1.Pod {
		e.newBlip("first", withRoot("first-root"))
		e.run(e.blip, ns, "first")
		e.run(e.pool, ns, "default")
		e.warmOn("n1")
		return e.pods()[0]
	}()
	e.run(e.blip, ns, "first")
	expectPhase(t, e.getBlip("first"), v1.BlipRunning, "")

	// A Blip working from a stale cache tries the pod that "first" holds.
	e.newBlip(testOwner+"-b", withRoot(testOwner+".root"), withOwner(testOwner))
	pod, err := e.blip.claim(e.ctx, e.getBlip(testOwner+"-b"), []corev1.Pod{stale})
	if err != nil || pod != nil {
		t.Fatalf("claim = %v, %v", pod, err)
	}
	if got := e.owners()[stale.Name]; got != ownerAny {
		t.Fatalf("owner of %s = %q, want %q", stale.Name, got, ownerAny)
	}
	// A failed claim must not relabel a pod that another Blip still owns.
	if got := e.getPod(stale.Name).Labels[v1.LabelOwner]; got != "" {
		t.Fatalf("failed claim changed owner label of %s to %q", stale.Name, got)
	}

	// A claim of a pod that is gone leaves no entry behind.
	gone := stale.DeepCopy()
	gone.Name = "default-gone"
	if pod, err := e.blip.claim(e.ctx, e.getBlip(testOwner+"-b"), []corev1.Pod{*gone}); err != nil || pod != nil {
		t.Fatalf("claim = %v, %v", pod, err)
	}
	if got, ok := e.owners()["default-gone"]; ok {
		t.Fatalf("entry of a missing pod = %q", got)
	}
}

// Each service account lists its pools; a pool without one gives its VMs no
// token and is not listed.
func TestVMOwnersPools(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.newPool("big", 0, 0)
	e.create(&v1.BlipPool{
		ObjectMeta: metadata("open"),
		Spec:       v1.BlipPoolSpec{Hypervisor: "kvm", CPUs: 2, Memory: resource.MustParse("2Gi"), WarmCount: 1},
	})
	e.run(e.pool, ns, "open")
	if got, want := e.owners(), map[string]string{"sa.vm": "big default"}; !maps.Equal(got, want) {
		t.Fatalf("owners = %v, want %v", got, want)
	}
	pods := e.pods()
	if len(pods) != 1 || pods[0].Spec.AutomountServiceAccountToken == nil || *pods[0].Spec.AutomountServiceAccountToken {
		t.Fatalf("pod of a pool without a service account mounts a token: %+v", pods)
	}
}

// A pool without a service account still materializes the table. The
// blip-write policy binding has parameterNotFoundAction Deny, so a missing
// table would reject every Blip and BlipState change in the namespace.
func TestVMOwnersEmptyServiceAccount(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.create(&v1.BlipPool{
		ObjectMeta: metadata("open"),
		Spec:       v1.BlipPoolSpec{Hypervisor: "kvm", CPUs: 2, Memory: resource.MustParse("2Gi")},
	})

	e.run(e.pool, ns, "open")
	if got := e.owners(); len(got) != 0 {
		t.Fatalf("table of a pool without a service account = %v", got)
	}

	// A deleted table is recreated, still empty.
	cm := &corev1.ConfigMap{}
	e.must(e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: VMOwnersConfigMap}, cm))
	e.must(e.c.Delete(e.ctx, cm))
	e.run(e.pool, ns, "open")
	if got := e.owners(); len(got) != 0 {
		t.Fatalf("recreated table = %v", got)
	}

	// A service account added later is listed in the same table.
	pool := e.getPool("open")
	pool.Spec.ServiceAccountName = "vm"
	e.must(e.c.Update(e.ctx, pool))
	e.run(e.pool, ns, "open")
	if got, want := e.owners(), map[string]string{"sa.vm": "open"}; !maps.Equal(got, want) {
		t.Fatalf("table after pool update = %v, want %v", got, want)
	}

	// Removing the last pool prunes the entry; the (empty) table stays,
	// since the controller has no permission to delete it.
	e.must(e.c.Delete(e.ctx, e.getPool("open")))
	e.run(e.pool, ns, "open")
	if got := e.owners(); len(got) != 0 {
		t.Fatalf("table after pool removal = %v", got)
	}
}

func TestPodServiceAccount(t *testing.T) {
	e := newEnv(t)
	pool := &v1.BlipPool{ObjectMeta: metadata("default"), Spec: v1.BlipPoolSpec{ServiceAccountName: "vm"}}
	base := e.pool.podFor(pool, "default-vm")
	enabled, disabled := true, false
	for _, tt := range []struct {
		name   string
		mutate func(*corev1.Pod)
		want   string
	}{
		{"projected proxy token", func(*corev1.Pod) {}, "vm"},
		{"default account", func(p *corev1.Pod) { p.Spec.ServiceAccountName = "" }, "default"},
		{"legacy automount", func(p *corev1.Pod) {
			p.Spec.AutomountServiceAccountToken = &enabled
			p.Spec.InitContainers = nil
			p.Spec.Volumes = nil
		}, "vm"},
		{"legacy implicit automount", func(p *corev1.Pod) {
			p.Spec.AutomountServiceAccountToken = nil
			p.Spec.InitContainers = nil
			p.Spec.Volumes = nil
		}, "vm"},
		{"automount disabled without proxy", func(p *corev1.Pod) {
			p.Spec.AutomountServiceAccountToken = &disabled
			p.Spec.InitContainers = nil
		}, ""},
		{"unmounted projection", func(p *corev1.Pod) { p.Spec.InitContainers[0].VolumeMounts = nil }, ""},
		{"proxy without token", func(p *corev1.Pod) {
			for i := range p.Spec.Volumes {
				if projected := p.Spec.Volumes[i].Projected; projected != nil {
					projected.Sources = projected.Sources[1:]
				}
			}
		}, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := base.DeepCopy()
			tt.mutate(p)
			if got := podServiceAccount(p); got != tt.want {
				t.Errorf("pod service account = %q, want %q", got, tt.want)
			}
		})
	}
}

// Pool edits or deletion must not remove restrictions on a still-live pod's
// account. This covers both old automounted tokens and new proxy projections.
func TestVMOwnersRetainsLivePodAccounts(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		name := "proxy"
		if legacy {
			name = "legacy"
		}
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.newPool("default", 0, 0)
			pool := e.getPool("default")
			oldPool := pool.DeepCopy()
			oldPool.Spec.ServiceAccountName = "old"
			p := e.pool.podFor(oldPool, "default-old")
			if legacy {
				enabled := true
				p.Spec.AutomountServiceAccountToken = &enabled
				p.Spec.InitContainers = nil
				p.Spec.Volumes = p.Spec.Volumes[:1]
				p.Spec.Containers[0].VolumeMounts = p.Spec.Containers[0].VolumeMounts[:1]
			}
			e.newBlip("owned", withOwner(testOwner))
			b := e.getBlip("owned")
			p.Labels[v1.LabelBlipUID] = string(b.UID)
			p.Annotations[v1.AnnotationBlip] = b.Name
			e.create(p)
			e.must(setVMOwner(e.ctx, e.c, p, b))
			if got, want := e.owners(), map[string]string{"sa.old": "", p.Name: testOwner}; !maps.Equal(got, want) {
				t.Fatalf("claim did not record old pod's account: %v, want %v", got, want)
			}
			e.must(syncVMOwners(e.ctx, e.c, ns))
			if got, want := e.owners(), map[string]string{"sa.vm": "default", "sa.old": "", p.Name: testOwner}; !maps.Equal(got, want) {
				t.Fatalf("account changed before old pod exited: %v, want %v", got, want)
			}
			e.must(e.c.Delete(e.ctx, pool))
			e.must(syncVMOwners(e.ctx, e.c, ns))
			if got, want := e.owners(), map[string]string{"sa.old": "", p.Name: testOwner}; !maps.Equal(got, want) {
				t.Fatalf("live pod account lost with pool: %v, want %v", got, want)
			}
			e.must(e.c.Delete(e.ctx, p))
			e.must(syncVMOwners(e.ctx, e.c, ns))
			if got := e.owners(); len(got) != 0 {
				t.Errorf("deleted pod left owner/account entries: %v", got)
			}
		})
	}
}

func TestPodOwnerLabelTracksBlip(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 1, 0)
	e.readyState("root", "n1")
	b := e.startBlip("b", "n1", withRoot("root"))
	pod := e.getPod(b.Status.Pod)
	if got := pod.Labels[v1.LabelOwner]; got != "" {
		t.Fatalf("unrestricted pod owner label = %q", got)
	}

	setOwner := func(owner string) {
		t.Helper()
		b = e.getBlip("b")
		if owner == "" {
			delete(b.Labels, v1.LabelOwner)
		} else {
			if b.Labels == nil {
				b.Labels = map[string]string{}
			}
			b.Labels[v1.LabelOwner] = owner
		}
		e.must(e.c.Update(e.ctx, b))
		e.run(e.blip, ns, "b")
		if got := e.getPod(b.Status.Pod).Labels[v1.LabelOwner]; got != owner {
			t.Fatalf("pod owner label = %q, want %q", got, owner)
		}
	}

	// An owner applied after the claim reaches the running pod.
	setOwner(testOwner)
	// A changed owner replaces the old one, so the previous owner cannot
	// list the pod.
	setOwner("u-other")
	// Removing the owner makes the Blip unrestricted again.
	setOwner("")
}

// Threads are published with their project owner hash so the turn policy can
// bind a pod-bound producer to its own thread without trusting turn labels.
func TestVMOwnersThreadOwners(t *testing.T) {
	e := newEnv(t)
	e.newPool("default", 0, 0)
	thread := &v1.BlipThread{
		ObjectMeta: metav1.ObjectMeta{Name: "proj", Namespace: ns},
		Spec:       v1.BlipThreadSpec{Pool: "default"},
	}
	e.create(thread)
	e.must(syncVMOwners(e.ctx, e.c, ns))
	if got, want := e.owners()["thread.proj"], v1.ThreadOwner(ns, "proj"); got != want {
		t.Fatalf("thread owner key = %q, want %q", got, want)
	}
	if err := e.c.Delete(e.ctx, thread); err != nil {
		t.Fatal(err)
	}
	e.must(syncVMOwners(e.ctx, e.c, ns))
	if got, ok := e.owners()["thread.proj"]; ok {
		t.Fatalf("deleted thread left owner key %q", got)
	}
}

// A long thread name cannot be a label value, so blip.dev/thread carries
// ThreadLabel(name). The table must publish that key too; otherwise a
// restricted VM cannot attach its Blip to its own long-named thread.
func TestVMOwnersThreadOwnersLongName(t *testing.T) {
	e := newEnv(t)
	e.newPool("default", 0, 0)
	long := strings.Repeat("thread-", 12)
	if len(long) <= 63 {
		t.Fatalf("test thread name %q is not long", long)
	}
	thread := &v1.BlipThread{
		ObjectMeta: metav1.ObjectMeta{Name: long, Namespace: ns},
		Spec:       v1.BlipThreadSpec{Pool: "default"},
	}
	e.create(thread)
	e.must(syncVMOwners(e.ctx, e.c, ns))
	owner := v1.ThreadOwner(ns, long)
	for _, name := range []string{long, v1.ThreadLabel(long)} {
		if got := e.owners()["thread."+name]; got != owner {
			t.Errorf("thread owner key %q = %q, want %q", "thread."+name, got, owner)
		}
	}
	if err := e.c.Delete(e.ctx, thread); err != nil {
		t.Fatal(err)
	}
	e.must(syncVMOwners(e.ctx, e.c, ns))
	for _, name := range []string{long, v1.ThreadLabel(long)} {
		if got, ok := e.owners()["thread."+name]; ok {
			t.Errorf("deleted thread left owner key %q = %q", "thread."+name, got)
		}
	}
}
