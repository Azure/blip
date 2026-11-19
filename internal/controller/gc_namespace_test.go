// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package controller

import (
	"context"
	"testing"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

func gcBlipIn(namespace, name, phase string, finish *time.Time) *v1.Blip {
	b := gcBlip(name, phase, finish)
	b.Namespace = namespace
	return b
}

func gcNamesIn(t *testing.T, c client.Client, namespace string) map[string]bool {
	t.Helper()
	var list v1.BlipList
	if err := c.List(context.Background(), &list, client.InNamespace(namespace)); err != nil {
		t.Fatal(err)
	}
	names := make(map[string]bool, len(list.Items))
	for _, b := range list.Items {
		names[b.Name] = true
	}
	return names
}

// TestCollectTerminatedBlipsPerNamespace covers a namespace exceeding its
// threshold evicting finished Blips from another namespace that is below it.
func TestCollectTerminatedBlipsPerNamespace(t *testing.T) {
	t0 := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	c := gcClient(t,
		gcBlipIn("ns-a", "a-only", v1.BlipSucceeded, &t0),
		gcBlipIn("ns-b", "b-old", v1.BlipSucceeded, ptrTime(t0.Add(time.Minute))),
		gcBlipIn("ns-b", "b-new", v1.BlipSucceeded, ptrTime(t0.Add(2*time.Minute))),
	)
	deleted, err := CollectTerminatedBlips(context.Background(), c, 2)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 0 {
		t.Fatalf("deleted = %d, want 0", deleted)
	}
	if got := gcNamesIn(t, c, "ns-a"); len(got) != 1 || !got["a-only"] {
		t.Fatalf("ns-a = %v, want a-only", got)
	}
	if got := gcNamesIn(t, c, "ns-b"); len(got) != 2 {
		t.Fatalf("ns-b = %v, want both blips", got)
	}

	// One namespace exceeding the threshold only collects from itself.
	c = gcClient(t,
		gcBlipIn("ns-a", "a-old", v1.BlipSucceeded, &t0),
		gcBlipIn("ns-a", "a-new", v1.BlipSucceeded, ptrTime(t0.Add(time.Minute))),
		gcBlipIn("ns-b", "b-only", v1.BlipSucceeded, ptrTime(t0.Add(2*time.Minute))),
	)
	deleted, err = CollectTerminatedBlips(context.Background(), c, 1)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 {
		t.Fatalf("deleted = %d, want 1", deleted)
	}
	if got := gcNamesIn(t, c, "ns-a"); len(got) != 1 || !got["a-new"] {
		t.Fatalf("ns-a = %v, want a-new", got)
	}
	if got := gcNamesIn(t, c, "ns-b"); len(got) != 1 || !got["b-only"] {
		t.Fatalf("ns-b = %v, want b-only", got)
	}
}
