package controller

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// A long thread's hashed label can equal a legal short thread name. The table
// must keep their owners apart, so neither thread can be authorized through
// the other's entry.
func TestVMOwnersThreadKeysAreUnambiguous(t *testing.T) {
	e := newEnv(t)
	long := "project-" + strings.Repeat("x", 70)
	short := v1.ThreadLabel(long)
	if len(short) != 63 || len(long) <= 63 {
		t.Fatalf("test names: short %q (%d), long %q (%d)", short, len(short), long, len(long))
	}
	for _, name := range []string{long, short} {
		e.create(&v1.BlipThread{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			Spec:       v1.BlipThreadSpec{Pool: "default"},
		})
	}
	e.must(syncVMOwners(e.ctx, e.c, ns))

	longOwner, shortOwner := v1.ThreadOwner(ns, long), v1.ThreadOwner(ns, short)
	if longOwner == shortOwner {
		t.Fatal("test threads have the same owner")
	}
	owners := e.owners()
	for _, tc := range []struct {
		key  string
		want string
	}{
		{"thread." + long, longOwner},
		{"thread-hash." + short, longOwner},
		{"thread." + short, shortOwner},
	} {
		if got := owners[tc.key]; got != tc.want {
			t.Errorf("%s = %q, want %q", tc.key, got, tc.want)
		}
	}
	// A short thread's label is its name, so it needs no hash entry.
	if got, ok := owners["thread-hash."+long]; ok {
		t.Errorf("short thread recorded a hashed key: %q", got)
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
}
