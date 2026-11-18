package controller

import (
	"context"
	"fmt"
	"slices"
	"sort"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// writerBlocked explains why nobody can take the state's writer slot now.
func writerBlocked(st *v1.BlipState) string {
	s := st.Status
	switch {
	case st.Spec.Image != "":
		return "is an immutable image template; fork it before writing"
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
		if msg := mountStateError(b, st, true); msg != "" {
			return nil, msg, giveUp()
		}
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

// releaseUnpublished runs only at the start of the owner's serialized Blip
// reconcile. The state reconciler cannot release these reservations: another
// root edit can arrive while this Blip is between acquiring and publishing one.
func (r *BlipReconciler) releaseUnpublished(ctx context.Context, b *v1.Blip) error {
	live := r.Live
	if live == nil {
		live = r.Client
	}
	fresh := &v1.Blip{}
	if err := live.Get(ctx, client.ObjectKeyFromObject(b), fresh); err != nil {
		return client.IgnoreNotFound(err)
	}
	if fresh.UID != b.UID {
		return nil
	}
	published := map[string]bool{fresh.Status.RootAttachmentID: true}
	for _, m := range fresh.Status.Mounts {
		published[m.AttachmentID] = true
	}
	wanted := map[string]bool{}
	if fresh.Spec.State != "" && !finished(fresh) && !stopping(fresh) && fresh.Status.Phase != v1.BlipSaving {
		root := &v1.BlipState{}
		err := live.Get(ctx, types.NamespacedName{Namespace: b.Namespace, Name: fresh.Spec.State}, root)
		if err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		if err == nil && root.DeletionTimestamp == nil {
			wanted[root.Name] = true
			for _, m := range desiredMounts(root, fresh) {
				if m.Writable {
					wanted[m.State] = true
				}
			}
		}
	}
	var states v1.BlipStateList
	if err := live.List(ctx, &states, client.InNamespace(b.Namespace)); err != nil {
		return err
	}
	for i := range states.Items {
		st := &states.Items[i]
		w := st.Status.Writer
		if w == nil || w.BlipUID != string(b.UID) || published[w.AttachmentID] || wanted[st.Name] {
			continue
		}
		base := st.DeepCopy()
		st.Status.Writer = nil
		if err := patchStatus(ctx, r.Client, st, base); err != nil {
			return client.IgnoreNotFound(err)
		}
	}
	return nil
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
	// Include unpublished reservations left by an interrupted acquisition,
	// even when the root profile no longer references the state.
	var states v1.BlipStateList
	if err := r.List(ctx, &states, client.InNamespace(b.Namespace)); err != nil {
		return err
	}
	for i := range states.Items {
		st := &states.Items[i]
		if slices.Contains(keep, st.Name) {
			continue
		}
		if err := releaseWriter(ctx, r.Client, st, b.UID); err != nil {
			return err
		}
	}
	return nil
}

// releaseUnattachedWriter clears the writer slot of an attachment that never
// attached, even if ensureWriterPods already recorded the pod. The node stops
// a VM whose desired mount loses its writer slot (writerLost), so a release
// that races an actual attachment fences the VM instead of letting a second
// writer mount the same state.
func (r *BlipReconciler) releaseUnattachedWriter(ctx context.Context, b *v1.Blip, state, attachmentID string) error {
	st := &v1.BlipState{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: b.Namespace, Name: state}, st); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return err
		}
		return nil
	}
	w := st.Status.Writer
	if w == nil || w.BlipUID != string(b.UID) || w.AttachmentID != attachmentID {
		return nil
	}
	base := st.DeepCopy()
	st.Status.Writer = nil
	return client.IgnoreNotFound(patchStatus(ctx, r.Client, st, base))
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
