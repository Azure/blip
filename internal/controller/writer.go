package controller

import (
	"context"
	"fmt"
	"maps"
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
			if err := r.releaseWriter(ctx, states[n], b.UID); err != nil {
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
			AttachmentID: r.newID(),
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
	fresh := &v1.Blip{}
	if err := r.Live.Get(ctx, client.ObjectKeyFromObject(b), fresh); err != nil {
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
	if fresh.Spec.State != "" && !v1.Finished(fresh) && !stopping(fresh) && fresh.Status.Phase != v1.BlipSaving {
		root := &v1.BlipState{}
		err := r.Live.Get(ctx, types.NamespacedName{Namespace: b.Namespace, Name: fresh.Spec.State}, root)
		if err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		if err == nil && root.DeletionTimestamp == nil {
			wanted[root.Name] = true
			for _, m := range v1.DesiredMounts(root, fresh) {
				if m.Writable {
					wanted[m.State] = true
				}
			}
		}
	}
	var states v1.BlipStateList
	if err := r.Live.List(ctx, &states, client.InNamespace(b.Namespace)); err != nil {
		return err
	}
	for i := range states.Items {
		st := &states.Items[i]
		name := st.Name
		if err := r.clearWriter(ctx, st, func(w *v1.Writer) bool {
			return w.BlipUID == string(b.UID) && !published[w.AttachmentID] && !wanted[name]
		}); err != nil {
			return err
		}
	}
	return nil
}

// clearWriter clears the writer slot when match accepts it.
func (r *BlipReconciler) clearWriter(ctx context.Context, st *v1.BlipState, match func(*v1.Writer) bool) error {
	w := st.Status.Writer
	if w == nil || !match(w) {
		return nil
	}
	base := st.DeepCopy()
	st.Status.Writer = nil
	return client.IgnoreNotFound(patchStatus(ctx, r.Client, st, base))
}

// releaseWriter clears the writer slot if blip holds it and no pod uses it.
// Once a pod has the slot only the node's seal (or node deletion) ends it.
func (r *BlipReconciler) releaseWriter(ctx context.Context, st *v1.BlipState, blip types.UID) error {
	return r.clearWriter(ctx, st, func(w *v1.Writer) bool {
		return w.BlipUID == string(blip) && w.PodUID == ""
	})
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
		if err := r.releaseWriter(ctx, st, b.UID); err != nil {
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
		return client.IgnoreNotFound(err)
	}
	return r.clearWriter(ctx, st, func(w *v1.Writer) bool {
		return w.BlipUID == string(b.UID) && w.AttachmentID == attachmentID
	})
}

// releaseSwitchWriter returns a writer slot pre-acquired for a promotion that
// was cancelled before the writable mount appeared.
func (r *BlipReconciler) releaseSwitchWriter(ctx context.Context, b *v1.Blip, state string) error {
	st := &v1.BlipState{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: b.Namespace, Name: state}, st); err != nil {
		return client.IgnoreNotFound(err)
	}
	return r.releaseWriter(ctx, st, b.UID)
}

// ensureMountedWriters restores the writer slot of every writable mount that
// is already attached. A concurrent replacement can publish the mounted
// attachment after another edit moved or cleared the state's writer, leaving a
// writable disk that the node will never seal: the node seals the writer
// attachment only. The mounted attachment must own the writer.
//
// It never steals a writer from another Blip or pod; that would let two guests
// write the same disk. The Blip is stopped instead, so no more writes are
// accepted. stopped reports that the caller must persist the returned status
// and stop reconciling mounts in this pass.
func (r *BlipReconciler) ensureMountedWriters(ctx context.Context, b *v1.Blip, pod *corev1.Pod) (stopped bool, err error) {
	podName, podUID, node := pod.Name, string(pod.UID), pod.Spec.NodeName
	for _, m := range b.Status.Mounts {
		if !m.Writable || m.Phase != v1.MountMounted || m.AttachmentID == "" {
			continue
		}
		st := &v1.BlipState{}
		if err := r.Live.Get(ctx, types.NamespacedName{Namespace: b.Namespace, Name: m.State}, st); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return false, err
		}
		w := st.Status.Writer
		if w != nil && w.AttachmentID == m.AttachmentID && w.BlipUID == string(b.UID) &&
			w.PodName == podName && w.PodUID == podUID && w.Node == node {
			continue
		}
		otherPod := w != nil && (w.PodUID != "" && w.PodUID != podUID ||
			w.PodUID == "" && w.PodName != "" && w.PodName != podName)
		if w != nil && (w.BlipUID != string(b.UID) || otherPod) {
			msg := fmt.Sprintf("writable mount %s lost its writer attachment %s: state %q is held by blip %q pod %q",
				m.State, m.AttachmentID, m.State, w.BlipName, w.PodName)
			// Stop a copy so b keeps the mount status this reconcile built.
			stop := b.DeepCopy()
			if err := r.stop(ctx, stop, ReasonSaveFailed); err != nil {
				return false, err
			}
			b.ResourceVersion = stop.ResourceVersion
			b.Status.Reason, b.Status.Message = ReasonSaveFailed, msg
			return true, nil
		}
		if st.Status.Committed == nil {
			// A mounted writable disk without a committed version cannot
			// describe its base; the normal save path reports the failure.
			continue
		}
		base := st.DeepCopy()
		st.Status.Writer = &v1.Writer{
			AttachmentID: m.AttachmentID,
			BlipName:     b.Name,
			BlipUID:      string(b.UID),
			BaseCommit:   st.Status.Committed.ID,
		}
		setWriterPod(st.Status.Writer, podName, podUID, node)
		if err := patchStatus(ctx, r.Client, st, base); err != nil {
			return false, err
		}
	}
	return false, nil
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
	for _, name := range slices.Sorted(maps.Keys(atts)) {
		id := atts[name]
		st := &v1.BlipState{}
		if err := r.Get(ctx, types.NamespacedName{Namespace: b.Namespace, Name: name}, st); err != nil {
			if !apierrors.IsNotFound(err) {
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
