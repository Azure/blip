package node

import (
	"slices"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/image"
	"github.com/Azure/blip/internal/registryauth"
)

// imageSource is one pinned image this node may need, with the namespaced
// imagePullSecrets that authenticate its pull.
type imageSource struct {
	Ref     string
	Secrets []registryauth.PullSecret
}

// imageRefs returns the image references this node may need to import. It only
// includes images of states placed on (or being placed on) this node, so a
// large cluster does not import every image on every node.
func (v *view) imageRefs() []imageSource {
	byID := map[string]*imageSource{}
	add := func(ref string, secrets []corev1.LocalObjectReference, namespace string) {
		if id, err := image.DigestOf(ref); err == nil {
			r := byID[id]
			if r == nil {
				r = &imageSource{Ref: ref}
				byID[id] = r
			} else if ref < r.Ref {
				r.Ref = ref
			}
			for _, s := range secrets {
				ps := registryauth.PullSecret{Namespace: namespace, Name: s.Name}
				if !slices.Contains(r.Secrets, ps) {
					r.Secrets = append(r.Secrets, ps)
				}
			}
		}
	}
	for _, s := range v.states {
		if !v.stateImageRelevant(s) {
			continue
		}
		add(s.Status.ImageDigest, s.Spec.ImagePullSecrets, s.Namespace)
	}
	refs := make([]imageSource, 0, len(byID))
	for _, r := range byID {
		slices.SortFunc(r.Secrets, func(a, b registryauth.PullSecret) int {
			if a.Namespace != b.Namespace {
				return strings.Compare(a.Namespace, b.Namespace)
			}
			return strings.Compare(a.Name, b.Name)
		})
		refs = append(refs, *r)
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].Ref < refs[j].Ref })
	return refs
}

// stateImageRelevant reports whether this node may hold s, and therefore needs
// its image: a placement, a pending replica, or an unplaced state whose
// nodeSelector matches this node.
func (v *view) stateImageRelevant(s *v1alpha1.BlipState) bool {
	st := s.Status
	if slices.Contains(st.Placements, v.node) {
		return true
	}
	if st.Pending != nil && slices.Contains(st.Pending.Replicas, v.node) {
		return true
	}
	return len(st.Placements) == 0 && v.nodeMatches(s.Spec.NodeSelector)
}

// nodeMatches reports whether this node's labels satisfy selector. Without a
// known Kubernetes Node only an empty selector matches.
func (v *view) nodeMatches(selector map[string]string) bool {
	if len(selector) == 0 {
		return true
	}
	n := v.kubeNodes[v.node]
	if n == nil {
		return false
	}
	for k, want := range selector {
		if n.Labels[k] != want {
			return false
		}
	}
	return true
}
