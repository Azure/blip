package controller

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// TestStaleIncarnationSealIgnored: a seal reported by a previous incarnation
// describes storage the recreated node no longer has. Turning it into a
// pending version would advertise a successful save of a commit no node
// holds, so the seal must be ignored until the current incarnation reports it.
func TestStaleIncarnationSealIgnored(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	st := e.readyState("s", "n1", "n2")
	e.newBlip("job")

	st = e.getState("s")
	st.Status.Writer = &v1.Writer{
		AttachmentID: "att1", BlipName: "job", BlipUID: "uid-job",
		PodName: "job-pod", PodUID: "pod1", Node: "n1", BaseCommit: st.Status.Committed.ID,
	}
	e.must(e.c.Status().Update(e.ctx, st))

	const saved = "c2c2c2c2c2c2c2c2"
	e.report("s", "n1", func(o *v1.NodeObservation) {
		o.Incarnation = "old-inc"
		o.Sealed = append(o.Sealed, v1.SealResult{AttachmentID: "att1", CommitID: saved, SizeBytes: 1 << 30})
	})
	bn := &v1.BlipNode{}
	e.must(e.c.Get(e.ctx, types.NamespacedName{Name: "n1"}, bn))
	bn.Status.Incarnation = "new-inc"
	hb := metav1.NewTime(e.now)
	bn.Status.Heartbeat = &hb
	e.must(e.c.Status().Update(e.ctx, bn))

	e.run(e.state, ns, "s")
	st = e.getState("s")
	if st.Status.Writer == nil {
		t.Fatalf("stale seal released the writer: %+v", st.Status)
	}
	if st.Status.Pending != nil || len(st.Status.Seals) != 0 {
		t.Fatalf("stale seal created a pending version or seal: pending=%+v seals=%+v", st.Status.Pending, st.Status.Seals)
	}

	// The current incarnation's seal is trusted.
	e.report("s", "n1", func(o *v1.NodeObservation) {
		o.Incarnation = "new-inc"
		o.Sealed = []v1.SealResult{{AttachmentID: "att1", CommitID: saved, SizeBytes: 1 << 30}}
	})
	e.run(e.state, ns, "s")
	st = e.getState("s")
	if st.Status.Writer != nil || st.Status.Pending == nil || st.Status.Pending.CommitID != saved {
		t.Fatalf("current seal not accepted: writer=%+v pending=%+v", st.Status.Writer, st.Status.Pending)
	}
	if len(st.Status.Seals) != 1 || st.Status.Seals[0].AttachmentID != "att1" || st.Status.Seals[0].CommitID != saved {
		t.Fatalf("current seal not recorded: %+v", st.Status.Seals)
	}
}
