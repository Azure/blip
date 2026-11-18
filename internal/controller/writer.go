package controller

import (
	"context"
	"fmt"
	"slices"
	"sort"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// writerBlocked explains why nobody can take the state's writer slot now.
func writerBlocked(st *v1.BlipState) string {
	s := st.Status
	switch {
	case st.DeletionTimestamp != nil:
		return "is being deleted"
	case s.Committed == nil:
		return "has no committed version"
	case s.Writer != nil:
		return "is in use by blip " + s.Writer.BlipName
	case s.Pending != nil:
		return fmt.Sprintf("is saving generation %d", s.Pending.Generation)
	}
	return ""
}

// acquire takes the writer slots of names in sorted order with
// resourceVersion-checked status patches. Slots this Blip already holds are
// reused. If any slot is blocked, every slot the Blip holds without a pod is
// released (so two Blips never wait on each other while holding slots) and
// the reason is returned. pod, if set, is recorded in the new writers.
func (r *BlipReconciler) acquire(ctx context.Context, b *v1.Blip, states map[string]*v1.BlipState, names []string, pod *corev1.Pod) (map[string]string, string, error) {
	names = append([]string(nil), names...)
	sort.Strings(names)
	ids := map[string]string{}
	giveUp := func() error {
		for _, n := range names {
			if err := releaseWriter(ctx, r.Client, states[n], b.UID); err != nil {
				return err
			}
		}
		return nil
	}
	for _, n := range names {
		st := states[n]
		if w := st.Status.Writer; w != nil && w.BlipUID == string(b.UID) {
			ids[n] = w.AttachmentID
			continue
		}
		if why := writerBlocked(st); why != "" {
			return nil, fmt.Sprintf("state %q %s", n, why), giveUp()
		}
		base := st.DeepCopy()
		st.Status.Writer = &v1.Writer{
			AttachmentID: newID(),
			BlipName:     b.Name,
			BlipUID:      string(b.UID),
			BaseCommit:   st.Status.Committed.ID,
		}
		if pod != nil {
			setWriterPod(st.Status.Writer, pod.Name, string(pod.UID), pod.Spec.NodeName)
		}
		if err := patchStatus(ctx, r.Client, st, base); err != nil {
			*st = *base
			if rerr := giveUp(); rerr != nil {
				return nil, "", rerr
			}
			return nil, "", err
		}
		ids[n] = st.Status.Writer.AttachmentID
	}
	return ids, "", nil
}

func setWriterPod(w *v1.Writer, name, uid, node string) {
	w.PodName, w.PodUID, w.Node = name, uid, node
}

// releaseWriter clears the writer slot if blip holds it and no pod uses it.
// Once a pod has the slot only the node's seal (or node deletion) ends it.
func releaseWriter(ctx context.Context, c client.Client, st *v1.BlipState, blip types.UID) error {
	w := st.Status.Writer
	if w == nil || w.BlipUID != string(blip) || w.PodUID != "" {
		return nil
	}
	base := st.DeepCopy()
	st.Status.Writer = nil
	return client.IgnoreNotFound(patchStatus(ctx, c, st, base))
}

// releaseHeld releases every slot the Blip holds without a pod, except on
// states in keep.
func (r *BlipReconciler) releaseHeld(ctx context.Context, b *v1.Blip, keep ...string) error {
	for _, n := range stateRefs(b) {
		if slices.Contains(keep, n) {
			continue
		}
		st := &v1.BlipState{}
		if err := r.Get(ctx, types.NamespacedName{Namespace: b.Namespace, Name: n}, st); err != nil {
			if client.IgnoreNotFound(err) != nil {
				return err
			}
			continue
		}
		if err := releaseWriter(ctx, r.Client, st, b.UID); err != nil {
			return err
		}
	}
	return nil
}

// releaseSwitchWriter returns a writer slot pre-acquired for a promotion that
// was cancelled before the writable mount appeared.
func (r *BlipReconciler) releaseSwitchWriter(ctx context.Context, b *v1.Blip, state string) error {
	st := &v1.BlipState{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: b.Namespace, Name: state}, st); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return err
		}
		return nil
	}
	return releaseWriter(ctx, r.Client, st, b.UID)
}

// ensureWriterPods records the claimed pod in each writer slot the Blip
// holds; the node acts only when writer.podUID matches the pod.
func (r *BlipReconciler) ensureWriterPods(ctx context.Context, b *v1.Blip) error {
	atts := map[string]string{}
	if b.Spec.State != "" && b.Status.RootAttachmentID != "" {
		atts[b.Spec.State] = b.Status.RootAttachmentID
	}
	for _, m := range b.Status.Mounts {
		if m.Writable && m.AttachmentID != "" {
			atts[m.State] = m.AttachmentID
		}
	}
	for name, id := range atts {
		st := &v1.BlipState{}
		if err := r.Get(ctx, types.NamespacedName{Namespace: b.Namespace, Name: name}, st); err != nil {
			if client.IgnoreNotFound(err) != nil {
				return err
			}
			continue
		}
		w := st.Status.Writer
		if w == nil || w.AttachmentID != id || w.PodUID == b.Status.PodUID {
			continue
		}
		base := st.DeepCopy()
		setWriterPod(st.Status.Writer, b.Status.Pod, b.Status.PodUID, b.Status.Node)
		if err := patchStatus(ctx, r.Client, st, base); err != nil {
			return err
		}
	}
	return nil
}
