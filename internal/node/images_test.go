package node

import (
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/registryauth"
)

func digestRef(c string) string {
	return "registry.local/img@" + "sha256:" + strings.Repeat(c, 64)
}

// TestImageRefsFiltering proves a node only imports images for state placements
// and merges their state pull secrets, excluding infrastructure credentials.
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
	unplaced.Spec.NodeSelector = map[string]string{v1alpha1.LabelEnrolled: "true"}

	mismatch := state("mismatch")
	mismatch.Status.ImageDigest = digestRef("e")
	mismatch.Spec.NodeSelector = map[string]string{v1alpha1.LabelEnrolled: "false"}
	v.states = append(v.states, placed, pending, other, unplaced, mismatch)

	pool := &v1alpha1.BlipPool{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "default"},
		Spec:       v1alpha1.BlipPoolSpec{ImagePullSecrets: []corev1.LocalObjectReference{{Name: "pool-secret"}}},
	}
	v.pools[ns+"/default"] = pool
	assigned := blip("assigned")
	assigned.Spec.Pool = "default"
	assigned.Spec.State = other.Name
	assigned.Status.Node = self
	v.blips = append(v.blips, assigned)

	// The same digest from states in different namespaces merges their secrets.
	same := state("same")
	same.Namespace = "other"
	same.Status.Placements = []string{self}
	same.Status.ImageDigest = digestRef("a")
	same.Spec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: "second-secret"}}
	v.states = append(v.states, same)

	got := map[string][]registryauth.PullSecret{}
	for _, r := range v.imageRefs() {
		got[r.Ref] = r.Secrets
	}
	want := []string{digestRef("a"), digestRef("b"), digestRef("d")}
	var have []string
	for ref := range got {
		have = append(have, ref)
	}
	slices.Sort(have)
	slices.Sort(want)
	if !slices.Equal(have, want) {
		t.Fatalf("refs = %v, want %v", have, want)
	}
	if secrets := got[digestRef("a")]; !slices.Equal(secrets, []registryauth.PullSecret{{Namespace: ns, Name: "state-secret"}, {Namespace: "other", Name: "second-secret"}}) {
		t.Fatalf("merged state secrets = %v", secrets)
	}
	for _, secrets := range got {
		if slices.Contains(secrets, registryauth.PullSecret{Namespace: ns, Name: "pool-secret"}) {
			t.Fatalf("state import uses infrastructure credentials: %v", secrets)
		}
	}
}
