// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package node

import (
	"encoding/json"
	"reflect"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/podapi"
	"github.com/Azure/blip/internal/storage"
)

func TestPublicPlannerOwnsResultsAndSupportsConcurrentReplay(t *testing.T) {
	b, st := blip("b"), state("root")
	b.Spec.Stop = true
	b.Status.RootAttachmentID = "root-disk"
	pod := vmPod("vm", string(b.UID))
	st.Status.Writer = &v1alpha1.Writer{Node: self, PodUID: string(pod.UID), PodName: pod.Name, AttachmentID: "root-disk"}
	previous := &podapi.Desired{Claim: &podapi.Claim{BlipUID: string(b.UID), Root: disk("root-disk", false),
		Command: []string{"command"}, Env: []string{"KEY=value"}}}
	s := Snapshot{Now: testNow, Node: self, Incarnation: "inc-n1",
		States: []v1alpha1.BlipState{*st}, Blips: []v1alpha1.Blip{*b}, Pods: []corev1.Pod{*pod},
		Directories: map[string]PodSnapshot{pkey("vm"): {Desired: previous, Observed: &podapi.Observed{Phase: podapi.PhaseRunning}}},
		Volumes:     []storage.Volume{commit("base", string(st.UID))},
		Freezes:     map[string][]string{pkey("vm"): {"root-disk"}},
		Progress:    map[string]*v1alpha1.Transfer{string(st.UID): {}},
	}
	data := func(v any) string {
		x, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return string(x)
	}
	before := data(s)
	want := Compute(s)
	if len(want.Desired) != 1 || len(want.Entries) != 1 || !want.Desired[pkey("vm")].Stop {
		t.Fatalf("fixture did not exercise retained claims and reports: %+v", want)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 10 {
				if got := Compute(s); !reflect.DeepEqual(got, want) {
					t.Error("concurrent replay changed the plan")
				}
			}
		})
	}
	wg.Wait()
	out := Compute(s)
	d := out.Desired[pkey("vm")]
	d.Claim.Command[0], d.Claim.Env[0], d.Freeze[0] = "changed", "changed", "changed"
	out.Entries[0].Observation.Commits[0] = "changed"
	out.Entries[0].Observation.Fetching = nil
	if data(s) != before || !reflect.DeepEqual(Compute(s), want) {
		t.Fatal("returned values share mutable storage with planner inputs")
	}
	previous.Claim.Command[0] = "input changed"
	s.Freezes[pkey("vm")][0] = "input changed"
	if d.Claim.Command[0] != "changed" || d.Freeze[0] != "changed" {
		t.Fatal("changing input changed a previously returned plan")
	}
}
