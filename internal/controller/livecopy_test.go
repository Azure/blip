package controller

import (
	"reflect"
	"strings"
	"testing"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// liveSource creates state repo on n1 and n2 and runs a Blip with it as its
// root on n3.
func liveSource(t *testing.T) (*env, *v1.Writer) {
	e := newEnv(t)
	e.addNodes("n1", "n2", "n3")
	e.newPool("default", 0, 0)
	e.readyState("repo", "n1", "n2")
	e.startBlip("git", "n3", withRoot("repo"))
	w := e.getState("repo").Status.Writer
	if w == nil || w.Node != "n3" || w.PodUID == "" {
		t.Fatalf("writer %+v", w)
	}
	return e, w
}

func (e *env) setWriter(state string, w *v1.Writer) {
	e.t.Helper()
	st := e.getState(state)
	st.Status.Writer = w
	e.must(e.c.Status().Update(e.ctx, st))
}

func TestLiveCopyFromRunningWriter(t *testing.T) {
	e, w := liveSource(t)
	before := e.getState("repo").Status

	e.newState("cp", func(st *v1.BlipState) { st.Spec.CopyFrom = "repo" })
	e.run(e.state, ns, "cp")
	cp := e.getState("cp")
	want := &v1.CopySource{StateUID: string(e.getState("repo").UID), AttachmentID: w.AttachmentID, Nodes: []string{"n3"}}
	if !reflect.DeepEqual(cp.Status.CopiedFrom, want) {
		t.Fatalf("copied from %+v, want %+v", cp.Status.CopiedFrom, want)
	}
	p := cp.Status.Pending
	if p == nil || p.SourceNode != "n3" || p.Replicas[0] != "n3" || len(p.Replicas) != 2 || cp.Status.SizeBytes != before.SizeBytes {
		t.Fatalf("pending %+v size %d", p, cp.Status.SizeBytes)
	}
	if after := e.getState("repo").Status; !reflect.DeepEqual(after, before) {
		t.Fatalf("copy changed its source:\n%+v\n%+v", before, after)
	}

	e.hold("cp", p.CommitID, p.Replicas...)
	e.run(e.state, ns, "cp")
	if cp = e.getState("cp"); cp.Status.Phase != v1.StateReady {
		t.Fatalf("live copy not ready %+v", cp.Status)
	}
	if w2 := e.getState("repo").Status.Writer; !reflect.DeepEqual(w2, w) {
		t.Fatalf("source writer changed %+v", w2)
	}
}

func TestLiveCopyWaitsForUsableWriterNode(t *testing.T) {
	e, _ := liveSource(t)
	e.newState("cp", func(st *v1.BlipState) {
		st.Spec.CopyFrom = "repo"
		st.Spec.NodeSelector = map[string]string{"zone": "a"}
	})
	e.label("zone", "a", "n1", "n2")
	e.run(e.state, ns, "cp")
	if cp := e.getState("cp"); cp.Status.Pending != nil || !strings.Contains(cp.Status.Message, "cannot hold the copy") {
		t.Fatalf("copy %+v", cp.Status)
	}

	e.updateBlip("git", func(b *v1.Blip) { b.Spec.Stop = true })
	e.label("zone", "a", "n3")
	e.run(e.state, ns, "cp")
	if cp := e.getState("cp"); cp.Status.Pending != nil || !strings.Contains(cp.Status.Message, "not running") {
		t.Fatalf("copy of stopping writer %+v", cp.Status)
	}
}

func TestLiveCopyReplansWhenWriterChanges(t *testing.T) {
	e, w := liveSource(t)
	e.newState("cp", func(st *v1.BlipState) { st.Spec.CopyFrom = "repo" })
	e.run(e.state, ns, "cp")
	first := e.getState("cp").Status.Pending
	if first == nil {
		t.Fatal("live copy not planned")
	}

	// The writer is replaced before the source node built the copy.
	other := *w
	other.AttachmentID = "ffffffffffffffff"
	e.setWriter("repo", &other)
	e.run(e.state, ns, "cp")
	cp := e.getState("cp")
	if cp.Status.CopiedFrom != nil || cp.Status.Pending != nil || !strings.Contains(cp.Status.Message, "replanning") {
		t.Fatalf("after writer change %+v", cp.Status)
	}

	// No writer: copy the committed version as before.
	e.setWriter("repo", nil)
	e.run(e.state, ns, "cp")
	cp = e.getState("cp")
	committed := e.getState("repo").Status.Committed.ID
	if cf := cp.Status.CopiedFrom; cf == nil || cf.AttachmentID != "" || cf.CommitID != committed || cp.Status.Pending == nil || cp.Status.Pending.CommitID == first.CommitID {
		t.Fatalf("copy %+v", cp.Status)
	}
}

func TestLiveCopyReplansWhenSourceBlipFinishes(t *testing.T) {
	e, _ := liveSource(t)
	e.newState("cp", func(st *v1.BlipState) { st.Spec.CopyFrom = "repo" })
	e.run(e.state, ns, "cp")
	first := e.getState("cp").Status.Pending
	if first == nil {
		t.Fatal("live copy not planned")
	}

	// The source Blip finishes (its pod is gone) before the copy was built.
	// A previous live-copy attempt already failed and stuck the state in
	// Failed; replanning must make it retryable.
	st := e.getState("cp")
	st.Status.Phase = v1.StateFailed
	st.Status.LastError = "initial version failed: guest did not freeze"
	e.must(e.c.Status().Update(e.ctx, st))
	e.updateBlipStatus("git", func(b *v1.Blip) { b.Status.Phase = v1.BlipSucceeded })
	e.run(e.state, ns, "cp")
	cp := e.getState("cp")
	if cp.Status.CopiedFrom != nil || cp.Status.Pending != nil || !strings.Contains(cp.Status.Message, "replanning") {
		t.Fatalf("after source finished %+v", cp.Status)
	}
	if cp.Status.Phase == v1.StateFailed || cp.Status.LastError != "" {
		t.Fatalf("copy of finished source stayed failed: %+v", cp.Status)
	}

	// Once the writer clears, the copy falls back to the committed version.
	e.setWriter("repo", nil)
	e.run(e.state, ns, "cp")
	cp = e.getState("cp")
	committed := e.getState("repo").Status.Committed.ID
	if cf := cp.Status.CopiedFrom; cf == nil || cf.AttachmentID != "" || cf.CommitID != committed || cp.Status.Pending == nil || cp.Status.Pending.CommitID == first.CommitID {
		t.Fatalf("copy %+v", cp.Status)
	}
}

func TestLiveCopyKeptOnceSourceNodeHoldsIt(t *testing.T) {
	e, _ := liveSource(t)
	e.newState("cp", func(st *v1.BlipState) { st.Spec.CopyFrom = "repo" })
	e.run(e.state, ns, "cp")
	p := e.getState("cp").Status.Pending
	e.hold("cp", p.CommitID, p.SourceNode)

	e.setWriter("repo", nil)
	e.run(e.state, ns, "cp")
	cp := e.getState("cp")
	if cp.Status.CopiedFrom == nil || cp.Status.Pending == nil || cp.Status.Pending.CommitID != p.CommitID {
		t.Fatalf("built live copy was replanned %+v", cp.Status)
	}
}

func TestWarmPodsPreferWritableMounts(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2", "n3")
	e.label("only", "n2", "n2")
	e.label("only", "n3", "n3")
	for name, node := range map[string]string{"ro": "n2", "data": "n3"} {
		e.newState(name, func(st *v1.BlipState) {
			st.Spec.Replicas = 1
			st.Spec.NodeSelector = map[string]string{"only": node}
		})
		e.run(e.state, ns, name)
		p := e.getState(name).Status.Pending
		e.hold(name, p.CommitID, p.Replicas...)
		e.run(e.state, ns, name)
	}
	e.newPool("default", 3, 0)
	e.run(e.pool, ns, "default")
	e.warmOn("n1", "n2", "n3")
	e.newBlip("b", e.withImage("reg/img:v1"), e.withMount("ro", "/ro", false), e.withMount("data", "/data", true))

	states := map[string]*v1.BlipState{"ro": e.getState("ro"), "data": e.getState("data")}
	root := e.getState(e.getBlip("b").Spec.State)
	states[root.Name] = root
	pods := e.warmPods("b", states)
	if len(pods) != 3 || pods[0].Spec.NodeName != "n3" {
		t.Fatalf("warm pods %+v", pods)
	}
	e.run(e.blip, ns, "b")
	if b := e.getBlip("b"); b.Status.Node != "n3" {
		t.Fatalf("claimed on %q", b.Status.Node)
	}
}
