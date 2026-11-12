package controller

import (
	"strings"
	"testing"

	"github.com/go-logr/logr"

	"github.com/example/blip/internal/api"
	"github.com/example/blip/internal/proto/nodepb"
)

// A node that returns without the record of an assigned allocation lost
// its slot, also when it still reports the allocation's devices
// (record-less: its state was on a tmpfs, the overlays in device-mapper).
func TestHelloRecordlessAllocationIsLost(t *testing.T) {
	m := NewNodeManager(logr.Discard(), nil, nil, &Options{}, NodeHooks{})
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range []string{"kept", "recordless", "gone"} {
		rt := m.alloc(id)
		rt.Node, rt.Assigned, rt.Started = "n1", true, true
	}
	m.applyStateLocked(m.node("n1"), &nodepb.NodeState{Allocations: []*nodepb.AllocationInfo{
		{AllocationId: "kept", Assigned: true, BootCount: 1},
		{AllocationId: "recordless", Attachments: []*nodepb.AttachmentInfo{{AttachmentId: "a"}}},
	}}, true)
	if m.allocs["kept"].SlotLost != "" {
		t.Fatalf("kept: %q", m.allocs["kept"].SlotLost)
	}
	for _, id := range []string{"recordless", "gone"} {
		if m.allocs[id].SlotLost == "" {
			t.Fatalf("%s not lost", id)
		}
	}
}

// A controller that started after an allocation was assigned has no
// runtime record of it; AllocMissing still sees it missing from the state
// of the connected node.
func TestAllocMissingWithoutRuntimeRecord(t *testing.T) {
	m := NewNodeManager(logr.Discard(), nil, nil, &Options{}, NodeHooks{})
	m.mu.Lock()
	rec := m.node("n1")
	m.applyStateLocked(rec, &nodepb.NodeState{Allocations: []*nodepb.AllocationInfo{
		{AllocationId: "kept", Assigned: true, BootCount: 1},
		{AllocationId: "recordless"},
	}}, true)
	m.mu.Unlock()
	if m.AllocMissing("n1", "gone") {
		t.Fatal("missing reported for a disconnected node")
	}
	m.mu.Lock()
	rec.sess = &session{node: "n1"}
	m.mu.Unlock()
	for id, want := range map[string]bool{"kept": false, "recordless": true, "gone": true} {
		if got := m.AllocMissing("n1", id); got != want {
			t.Errorf("AllocMissing(%s) = %v, want %v", id, got, want)
		}
	}
	if m.AllocMissing("n2", "gone") {
		t.Error("missing reported for an unknown node")
	}
}

// Full states from the node: the owner is woken only for allocations
// whose runtime state changed, the exit is recorded once, and a state
// from a replaced session is ignored.
func TestApplyStateDiff(t *testing.T) {
	var woken []string
	m := NewNodeManager(logr.Discard(), nil, nil, &Options{}, NodeHooks{AllocChanged: func(id string) { woken = append(woken, id) }})
	cur := &session{node: "n1"}
	m.node("n1").sess = cur
	state := func(as ...*nodepb.AllocationInfo) *nodepb.NodeState { return &nodepb.NodeState{Allocations: as} }
	expect := func(want string) {
		t.Helper()
		if got := strings.Join(woken, ","); got != want {
			t.Fatalf("woken %q, want %q", got, want)
		}
		woken = nil
	}
	m.applyState("n1", cur, state(&nodepb.AllocationInfo{AllocationId: "a", Assigned: true}, &nodepb.AllocationInfo{AllocationId: "b", Assigned: true}))
	expect("a,b")
	m.applyState("n1", cur, state(&nodepb.AllocationInfo{AllocationId: "a", Assigned: true}, &nodepb.AllocationInfo{AllocationId: "b", Assigned: true}))
	expect("")
	m.applyState("n1", cur, state(&nodepb.AllocationInfo{AllocationId: "a", Assigned: true, BootCount: 2}, &nodepb.AllocationInfo{AllocationId: "b", Assigned: true}))
	expect("a")
	if rt := m.allocs["a"]; !rt.Started || rt.BootCount != 2 {
		t.Fatalf("%+v", rt)
	}
	exit := &nodepb.Exited{AllocationId: "a", Reason: api.ReasonSucceeded}
	m.applyState("n1", cur, state(&nodepb.AllocationInfo{AllocationId: "a", Assigned: true, BootCount: 2, Exit: exit}))
	expect("a")
	// The same exit again, or a different one: recorded once.
	m.applyState("n1", cur, state(&nodepb.AllocationInfo{AllocationId: "a", Assigned: true, BootCount: 2,
		Exit: &nodepb.Exited{AllocationId: "a", Reason: api.ReasonHypervisorExited}}))
	expect("")
	if m.allocs["a"].Exit != exit {
		t.Fatal("exit replaced")
	}
	m.applyState("n1", cur, state(&nodepb.AllocationInfo{AllocationId: "b", Assigned: true, SlotLost: "pod gone"}))
	expect("b")
	// A replaced session: ignored.
	m.applyState("n1", &session{node: "n1"}, state(&nodepb.AllocationInfo{AllocationId: "c", Assigned: true}))
	expect("")
	if m.allocs["c"] != nil {
		t.Fatal("state of an old session applied")
	}
}
