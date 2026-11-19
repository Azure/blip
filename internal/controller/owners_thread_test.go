package controller

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// A long thread's hashed label is under a reserved prefix that cannot be a
// legal thread name, so no short thread (and no turn labelled for one) can
// share it. The table still keeps the hashed label entry separate from raw
// names.
func TestVMOwnersThreadKeysAreUnambiguous(t *testing.T) {
	e := newEnv(t)
	long := "project-" + strings.Repeat("x", 70)
	label := v1.ThreadLabel(long)
	if len(label) != 63 || len(long) <= 63 {
		t.Fatalf("test names: label %q (%d), long %q (%d)", label, len(label), long, len(long))
	}
	if problems := validation.IsDNS1123Subdomain(label); len(problems) == 0 {
		t.Fatalf("hashed label %q is a legal thread name; a short thread could collide", label)
	}
	e.create(&v1.BlipThread{
		ObjectMeta: metav1.ObjectMeta{Name: long, Namespace: ns},
		Spec:       v1.BlipThreadSpec{Pool: "default"},
	})
	e.must(syncVMOwners(e.ctx, e.c, ns))

	owner := v1.ThreadOwner(ns, long)
	owners := e.owners()
	for _, tc := range []struct {
		key  string
		want string
	}{
		{"thread." + long, owner},
		{"thread-hash." + label, owner},
	} {
		if got := owners[tc.key]; got != tc.want {
			t.Errorf("%s = %q, want %q", tc.key, got, tc.want)
		}
	}
	// The hashed label is reserved, so it never needs a raw-name entry.
	if got, ok := owners["thread."+label]; ok {
		t.Errorf("reserved hash was recorded as a short thread: %q", got)
	}
}

// Removing a thread prunes both encodings of its owner entry.
func TestVMOwnersThreadKeysPruned(t *testing.T) {
	e := newEnv(t)
	long := "project-" + strings.Repeat("y", 70)
	thread := &v1.BlipThread{
		ObjectMeta: metav1.ObjectMeta{Name: long, Namespace: ns},
		Spec:       v1.BlipThreadSpec{Pool: "default"},
	}
	e.create(thread)
	e.must(syncVMOwners(e.ctx, e.c, ns))
	if got := e.owners()[ownersThreadHashPrefix+v1.ThreadLabel(long)]; got == "" {
		t.Fatal("hashed thread key was not written")
	}
	e.must(e.c.Delete(e.ctx, thread))
	e.must(syncVMOwners(e.ctx, e.c, ns))
	for _, key := range []string{"thread." + long, ownersThreadHashPrefix + v1.ThreadLabel(long)} {
		if got, ok := e.owners()[key]; ok {
			t.Errorf("stale thread key %s = %q", key, got)
		}
	}
	if got, ok := e.owners()[ownersThreadIncPrefix+v1.ThreadOwner(ns, long)]; ok {
		t.Errorf("stale thread incarnation key = %q", got)
	}
}

// A claimed pod's entry carries the thread incarnation its Blip was created
// for, so a producer left over from a deleted incarnation is distinguishable
// from one created for the recreated thread.
func TestVMOwnersPodEntryPinsThreadIncarnation(t *testing.T) {
	e := newEnv(t)
	const name = "proj-thread"
	thread := &v1.BlipThread{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       v1.BlipThreadSpec{Pool: "default"},
	}
	e.create(thread)
	owner := v1.ThreadOwner(ns, name)
	b := &v1.Blip{ObjectMeta: metav1.ObjectMeta{
		Name: owner + ".task", Namespace: ns,
		Labels:      map[string]string{v1.LabelOwner: owner, v1.LabelThread: v1.ThreadLabel(name)},
		Annotations: map[string]string{v1.AnnotationThread: name, v1.AnnotationThreadUID: string(thread.UID)},
	}}
	e.create(b)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "proj-pod", Namespace: ns,
		Labels:      map[string]string{v1.LabelPool: "default", v1.LabelBlipUID: string(b.UID)},
		Annotations: map[string]string{v1.AnnotationBlip: b.Name},
	}}
	e.create(pod)
	e.must(syncVMOwners(e.ctx, e.c, ns))

	owners := e.owners()
	if got, want := owners[pod.Name], owner+" "+string(thread.UID); got != want {
		t.Errorf("pod entry = %q, want %q", got, want)
	}
	if got, want := owners[ownersThreadIncPrefix+owner], string(thread.UID); got != want {
		t.Errorf("thread incarnation entry = %q, want %q", got, want)
	}
}
