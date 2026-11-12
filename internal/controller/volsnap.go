package controller

import (
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/example/blip/internal/api"
	v1 "github.com/example/blip/internal/api/v1alpha1"
)

// Helpers over the snapshot history of a BlipVol (status.snapshots).
// Entries are written by the BlipVol controller (sequence 1, compaction,
// replica state) and by the Blip controller holding the claim (captures);
// every write goes through updateVolStatus on a fresh copy.

// snapReplicas returns the connected nodes holding a Sealed replica of a
// snapshot, sorted.
func (c *Controller) snapReplicas(s *v1.VolSnapshot) []string {
	if s == nil {
		return nil
	}
	var out []string
	for _, r := range s.Replicas {
		if r.State == v1.ReplicaSealed && c.nodes.Connected(r.Node) {
			out = append(out, r.Node)
		}
	}
	sort.Strings(out)
	return out
}

// currentSnap returns the current (newest Ready) snapshot, or nil.
func currentSnap(v *v1.BlipVol) *v1.VolSnapshot {
	if s := v.Snapshot(v.Status.Current); s != nil && s.State == v1.SnapshotReady {
		return s
	}
	return v.NewestReady()
}

// snapByContent returns the entry with the content ID, or nil.
func snapByContent(v *v1.BlipVol, id string) *v1.VolSnapshot {
	for i := range v.Status.Snapshots {
		if v.Status.Snapshots[i].ContentID == id {
			return &v.Status.Snapshots[i]
		}
	}
	return nil
}

// pendingCapture returns the Pending snapshot written by an attachment, or
// nil. There is at most one per attachment.
func pendingCapture(v *v1.BlipVol, attachmentID string) *v1.VolSnapshot {
	for i := range v.Status.Snapshots {
		s := &v.Status.Snapshots[i]
		if s.State == v1.SnapshotPending && s.Writer != nil && s.Writer.AttachmentID == attachmentID {
			return s
		}
	}
	return nil
}

// lastCaptureBy returns the newest capture time of the snapshots written
// by an attachment, or nil: of the Failed ones with failed set, else of
// the others (Ready or Pending).
func lastCaptureBy(v *v1.BlipVol, attachmentID string, failed bool) *metav1.Time {
	var t *metav1.Time
	for i := range v.Status.Snapshots {
		s := &v.Status.Snapshots[i]
		if (s.State == v1.SnapshotFailed) != failed {
			continue
		}
		if s.Writer != nil && s.Writer.AttachmentID == attachmentID && s.CaptureTime != nil && (t == nil || s.CaptureTime.After(t.Time)) {
			t = s.CaptureTime
		}
	}
	return t
}

// ownClaim reports whether the claim of v is the attachment's, taken at
// claim generation gen (0: any generation).
func ownClaim(v *v1.BlipVol, blipUID, attachmentID string, gen int64) bool {
	cl := v.Status.Claim
	return cl != nil && cl.BlipUID == blipUID && cl.AttachmentID == attachmentID && (gen == 0 || cl.Generation == gen)
}

// writerOwnsClaim reports whether the writer of s holds the claim of v
// (same attachment and, when recorded, claim generation).
func writerOwnsClaim(v *v1.BlipVol, s *v1.VolSnapshot) bool {
	w := s.Writer
	return w != nil && ownClaim(v, w.BlipUID, w.AttachmentID, w.Generation)
}

// syncCurrent sets status.current to the newest Ready snapshot and the
// phase to Ready once one exists. It reports whether it changed anything.
func syncCurrent(v *v1.BlipVol) bool {
	var cur int64
	if s := v.NewestReady(); s != nil {
		cur = s.Sequence
	}
	changed := cur != v.Status.Current
	v.Status.Current = cur
	if cur != 0 && v.Status.Phase != v1.BlipVolReady && v.Status.Phase != v1.BlipVolFailed {
		v.Status.Phase = v1.BlipVolReady
		setCond(&v.Status.Conditions, v.Generation, api.CondReady, true, api.ReasonReady, "")
		setCond(&v.Status.Conditions, v.Generation, api.CondFailed, false, api.ReasonReady, "")
		changed = true
	}
	return changed
}

// setSnapFailed marks a Pending (or, with any set, a Ready) entry Failed.
// It reports whether it changed anything. The partial content is removed
// by compaction, deletion or the orphan scan.
func setSnapFailed(v *v1.BlipVol, seq int64, msg string, evenReady bool) bool {
	s := v.Snapshot(seq)
	if s == nil || s.State == v1.SnapshotFailed || (s.State == v1.SnapshotReady && !evenReady) {
		return false
	}
	s.State, s.Message = v1.SnapshotFailed, msg
	metricSnapshots.WithLabelValues(snapKind(s.Reason), "failed").Inc()
	syncCurrent(v)
	if v.Status.Current == 0 && v.Status.Phase == v1.BlipVolReady {
		v.Status.Phase = v1.BlipVolFailed
		setCond(&v.Status.Conditions, v.Generation, api.CondReady, false, api.ReasonNoReadySnapshot, msg)
		setCond(&v.Status.Conditions, v.Generation, api.CondFailed, true, api.ReasonNoReadySnapshot, msg)
	}
	return true
}

// failCaptures marks every Pending capture of an attachment Failed.
func failCaptures(v *v1.BlipVol, attachmentID, msg string) bool {
	changed := false
	for {
		s := pendingCapture(v, attachmentID)
		if s == nil {
			return changed
		}
		setSnapFailed(v, s.Sequence, msg, false)
		changed = true
	}
}

// snapKind is the metric kind of a snapshot reason.
func snapKind(r v1.SnapshotReason) string { return strings.ToLower(string(r)) }

// setReplicaState sets the state of one replica of an entry.
func setReplicaState(s *v1.VolSnapshot, node string, state v1.ReplicaState) bool {
	for i := range s.Replicas {
		if s.Replicas[i].Node == node {
			if s.Replicas[i].State == state {
				return false
			}
			s.Replicas[i].State = state
			return true
		}
	}
	s.Replicas = append(s.Replicas, v1.Replica{Node: node, State: state})
	sort.Slice(s.Replicas, func(i, j int) bool { return s.Replicas[i].Node < s.Replicas[j].Node })
	return true
}

func sealedList(nodes []string) []v1.Replica {
	var out []v1.Replica
	for _, n := range nodes {
		out = append(out, v1.Replica{Node: n, State: v1.ReplicaSealed})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Node < out[j].Node })
	return out
}
