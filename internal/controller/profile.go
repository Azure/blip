// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package controller

import (
	"context"
	"encoding/json"
	"slices"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// pruneTemporaryMounts removes execution-scoped collect references after their
// execution ends. UID matching deliberately ignores names: a replacement Blip
// must neither inherit nor keep alive the old execution's temporary references.
func pruneTemporaryMounts(ctx context.Context, c client.Client, live client.Reader, root *v1.BlipState) error {
	if !slices.ContainsFunc(root.Spec.Mounts, func(m v1.Mount) bool { return m.BlipUID != "" }) && root.Annotations[v1.AnnotationCollectMounts] == "" {
		return nil
	}
	var blips v1.BlipList
	if err := live.List(ctx, &blips, client.InNamespace(root.Namespace)); err != nil {
		return err
	}
	active := map[string]bool{}
	for _, b := range blips.Items {
		if b.Spec.State == root.Name && !v1.Finished(&b) && (!stopping(&b) || b.Status.Pod != "" || len(b.Status.Mounts) != 0) {
			active[string(b.UID)] = true
		}
	}
	var mounts []v1.Mount
	for _, m := range root.Spec.Mounts {
		if m.BlipUID == "" {
			mounts = append(mounts, m)
			continue
		}
		// Check the target state even while its Blip is active: a deleted
		// collector can leave a temporary mount of a fork state behind, and
		// that mount would otherwise block deleting the state.
		st := &v1.BlipState{}
		err := live.Get(ctx, types.NamespacedName{Namespace: root.Namespace, Name: m.State}, st)
		if err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		if st.DeletionTimestamp != nil {
			continue
		}
		keep := active[m.BlipUID]
		if !keep {
			// A failed/deleted execution can still have a node sealing its
			// writer. Do not erase intent until those saves have resolved.
			keep = st.Status.Writer != nil && st.Status.Writer.BlipUID == m.BlipUID ||
				st.Status.Pending != nil && st.Status.Pending.AttachmentID != ""
		}
		if keep {
			mounts = append(mounts, m)
		}
	}
	base := root.DeepCopy()
	if len(mounts) != len(root.Spec.Mounts) {
		root.Spec.Mounts = mounts
	}
	// Counters belong to the exact temporary reference, never to a state name
	// alone. Adoption, removal, or a later execution invalidates old counters.
	var users map[string]json.RawMessage
	if raw := root.Annotations[v1.AnnotationCollectMounts]; raw != "" && json.Unmarshal([]byte(raw), &users) == nil {
		changed := false
		for state, raw := range users {
			var use v1.CollectMountUse
			if json.Unmarshal(raw, &use) != nil || !slices.ContainsFunc(mounts, func(m v1.Mount) bool {
				return m.State == state && m.BlipUID != "" && m.BlipUID == use.BlipUID && m.Path == use.Path
			}) {
				delete(users, state)
				changed = true
			}
		}
		if len(users) == 0 {
			delete(root.Annotations, v1.AnnotationCollectMounts)
		} else if changed {
			raw, err := json.Marshal(users)
			if err != nil {
				return err
			}
			root.Annotations[v1.AnnotationCollectMounts] = string(raw)
		}
	}
	if semanticEqual(base.Spec.Mounts, root.Spec.Mounts) && semanticEqual(base.Annotations, root.Annotations) {
		return nil
	}
	return patchObject(ctx, c, root, base)
}
