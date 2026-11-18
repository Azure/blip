package node

import (
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/Azure/blip/api/v1alpha1"
)

func digestRef(c string) string {
	return "registry.local/img@" + "sha256:" + strings.Repeat(c, 64)
}

// TestImageRefsFiltering proves a node only imports images of states and blips
// it may actually run, and merges their pull secrets.
func TestImageRefsFiltering(t *testing.T) {
	v := newView()
	placed := state("placed")
	placed.Status.Placements = []string{self}
	placed.Status.ImageDigest = digestRef("a")
	placed.Spec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: "state-secret"}}

	pending := state("pending")
	pending.Status.Pending = &v1alpha1.PendingCommit{CommitID: "c1", SourceNode: "n2", Replicas: []string{"n2", self}}
	pending.Status.ImageDigest = digestRef("b")

	other := state("other")
	other.Status.Placements = []string{"n2"}
	other.Status.ImageDigest = digestRef("c")

	unplaced := state("unplaced")
	unplaced.Status.ImageDigest = digestRef("d")
	unplaced.Spec.NodeSelector = map[string]string{"blip.dev/enrolled": "true"}

	mismatch := state("mismatch")
	mismatch.Status.ImageDigest = digestRef("e")
	mismatch.Spec.NodeSelector = map[string]string{"blip.dev/enrolled": "false"}
	v.states = append(v.states, placed, pending, other, unplaced, mismatch)

	pool := &v1alpha1.BlipPool{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "default"},
		Spec:       v1alpha1.BlipPoolSpec{ImagePullSecrets: []corev1.LocalObjectReference{{Name: "pool-secret"}}},
	}
	v.pools[ns+"/default"] = pool
	assigned := &v1alpha1.Blip{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "assigned", UID: types.UID("uid-assigned")},
	}
	assigned.Spec.Pool = "default"
	assigned.Spec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: "blip-secret"}}
	assigned.Status.Node = self
	assigned.Status.ImageDigest = digestRef("f")
	v.blips = append(v.blips, assigned)

	podBlip := &v1alpha1.Blip{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "pod", UID: types.UID("uid-pod")},
	}
	podBlip.Status.Pod = "vm"
	podBlip.Status.ImageDigest = digestRef("7")
	v.blips = append(v.blips, podBlip)
	pod := vmPod("vm", string(podBlip.UID))
	v.pods[podKey(ns, "vm")] = pod

	remote := &v1alpha1.Blip{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "remote", UID: types.UID("uid-remote")},
	}
	remote.Status.Node = "n2"
	remote.Status.ImageDigest = digestRef("8")
	v.blips = append(v.blips, remote)

	done := &v1alpha1.Blip{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "done", UID: types.UID("uid-done")},
	}
	done.Status.Node = self
	done.Status.Phase = v1alpha1.BlipSucceeded
	done.Status.ImageDigest = digestRef("9")
	v.blips = append(v.blips, done)

	// The same digest from a state and a blip merges their secrets.
	same := &v1alpha1.Blip{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "same", UID: types.UID("uid-same")},
	}
	same.Status.Node = self
	same.Status.ImageDigest = digestRef("a")
	v.blips = append(v.blips, same)

	got := map[string][]pullSecret{}
	for _, r := range v.imageRefs() {
		got[r.Ref] = r.Secrets
	}
	want := []string{digestRef("a"), digestRef("b"), digestRef("d"), digestRef("f"), digestRef("7")}
	var have []string
	for ref := range got {
		have = append(have, ref)
	}
	slices.Sort(have)
	slices.Sort(want)
	if !slices.Equal(have, want) {
		t.Fatalf("refs = %v, want %v", have, want)
	}
	if secrets := got[digestRef("f")]; !slices.Contains(secrets, pullSecret{ns, "blip-secret"}) ||
		!slices.Contains(secrets, pullSecret{ns, "pool-secret"}) {
		t.Fatalf("assigned blip secrets = %v", secrets)
	}
	if secrets := got[digestRef("a")]; !slices.Contains(secrets, pullSecret{ns, "state-secret"}) {
		t.Fatalf("merged state secrets = %v", secrets)
	}
}
