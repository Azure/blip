// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package controller

import (
	"context"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// historyRetry is how often a ready state retries an ancestor it could not
// delete because something still uses it.
const historyRetry = time.Minute

// compactHistory deletes the copyFrom ancestors of a ready state beyond its
// spec.historyLimit. The walk follows each copy's recorded source UID, so a
// reused name ends it, and it stops at the first ancestor that is not part of
// the same history. Committed copies do not depend on their source. An
// ancestor that still has deletion blockers, such as a writer, a Blip using
// it, a persistent mount, or an uncommitted copy, is skipped and reported as
// blocked so the caller retries later.
func (r *StateReconciler) compactHistory(ctx context.Context, st *v1.BlipState) (blocked bool, err error) {
	if st.Spec.HistoryLimit <= 0 || st.DeletionTimestamp != nil || statePhase(st) != v1.StateReady {
		return false, nil
	}
	cur := st
	for depth := 1; depth <= int(st.Spec.HistoryLimit)+maxCopyChain; depth++ {
		cf := cur.Status.CopiedFrom
		if cur.Spec.CopyFrom == "" || cf == nil || cur.Status.Committed == nil {
			return blocked, nil
		}
		src := &v1.BlipState{}
		if err := r.Get(ctx, types.NamespacedName{Namespace: st.Namespace, Name: cur.Spec.CopyFrom}, src); err != nil {
			return blocked, client.IgnoreNotFound(err)
		}
		if string(src.UID) != cf.StateUID || !sameHistory(st, src) {
			return blocked, nil
		}
		if depth > int(st.Spec.HistoryLimit) && src.DeletionTimestamp == nil {
			blockers, err := r.deletionBlockers(ctx, src)
			if err != nil {
				return blocked, err
			}
			if len(blockers) > 0 {
				blocked = true
			} else if err := r.Delete(ctx, src, client.Preconditions{UID: &src.UID}); err != nil && !apierrors.IsNotFound(err) && !apierrors.IsConflict(err) {
				return blocked, fmt.Errorf("delete superseded state %s: %w", src.Name, err)
			}
		}
		cur = src
	}
	return blocked, nil
}

// sameHistory reports whether ancestor opted into history compaction under
// the same owner as st and is not owned by another object.
func sameHistory(st, ancestor *v1.BlipState) bool {
	return ancestor.Spec.HistoryLimit > 0 &&
		ancestor.Labels[v1.LabelOwner] == st.Labels[v1.LabelOwner] &&
		ancestor.Labels[v1.LabelChatSession] == "" &&
		len(ancestor.OwnerReferences) == 0
}
