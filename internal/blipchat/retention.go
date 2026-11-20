// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"context"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

const annotationActivityAt = "chat.blip.dev/activity-at"

// Cover bounded admission RPCs even when retention is configured very short.
const chatAdmissionGrace = 2 * time.Minute

// retentionExpired deliberately requires a terminal execution with a known
// finish time. Creation time is not a safe fallback for a long-running chat.
func retentionExpired(st *v1.BlipState, blips []v1.Blip, now time.Time, retention time.Duration) bool {
	if retention <= 0 || st.DeletionTimestamp != nil || st.Status.Writer != nil || st.Status.Pending != nil {
		return false
	}
	switch st.Status.Phase {
	case v1.StateReady, v1.StateFailed:
	default:
		return false
	}
	for i := range blips {
		switch blips[i].Status.Phase {
		case v1.BlipSucceeded, v1.BlipFailed:
		default:
			return false
		}
	}
	latest := latestBlip(blips)
	if latest == nil || latest.Status.FinishTime == nil || latest.Status.FinishTime.IsZero() {
		return false
	}
	finished := latest.Status.FinishTime.Time
	if raw := st.Annotations[annotationActivityAt]; raw != "" {
		activity, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return false
		}
		if now.Before(activity.Add(chatAdmissionGrace)) {
			return false
		}
		if activity.After(finished) {
			finished = activity
		}
	}
	return !now.Before(finished.Add(retention))
}

// reapSessions deletes expired leaves only. Waiting until children disappear
// avoids cascading deletion of a descendant whose retention has not elapsed.
func (s *Server) reapSessions(ctx context.Context, states []v1.BlipState, byState map[string][]v1.Blip, now time.Time) {
	if s.chatRetention == 0 {
		return
	}
	parents := make(map[string]bool)
	for i := range states {
		if parent := states[i].Annotations[AnnotationParent]; parent != "" {
			parents[parent] = true
		}
	}
	for i := range states {
		st := &states[i]
		if parents[st.Name] || !s.shards.owns(st.Name) || !retentionExpired(st, byState[st.Name], now, s.chatRetention) {
			continue
		}
		if err := s.reapSession(ctx, st, now); err != nil && !apierrors.IsNotFound(err) && !apierrors.IsConflict(err) {
			s.log.Warn("delete expired chat", "session", st.Name, "err", err)
		}
	}
}

func (s *Server) reapSession(ctx context.Context, snapshot *v1.BlipState, now time.Time) error {
	// Recheck candidates against current objects, not the supervisor's list:
	// a new turn or a child may have appeared since that snapshot was taken.
	st, err := s.cluster.GetSession(ctx, s.namespace, snapshot.Name)
	if err != nil {
		return err
	}
	if st.UID != snapshot.UID {
		return nil
	}
	blips, err := s.cluster.ListStateBlips(ctx, s.namespace, st.Name)
	if err != nil {
		return err
	}
	if !retentionExpired(st, blips, now, s.chatRetention) {
		return nil
	}
	children, err := s.cluster.ListChildSessions(ctx, s.namespace, st.Name)
	if err != nil || len(children) != 0 {
		return err
	}
	if err := s.cluster.DeleteSession(ctx, s.namespace, st.Name, st.UID, st.ResourceVersion); err != nil {
		return err
	}
	if e := s.lookupEngine(st.Name); e != nil {
		s.finishEngine(e)
	}
	s.invalidateView(st.Name)
	s.log.Info("deleted expired chat", "session", st.Name)
	return nil
}
