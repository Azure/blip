// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

var retentionNow = time.Date(2026, time.November, 20, 12, 0, 0, 0, time.UTC)

func newRetentionServer(t *testing.T, cluster *fakeCluster, retention time.Duration) *Server {
	t.Helper()
	s, err := New(Options{
		Namespace: "default", Cluster: cluster, Wire: newFakeWire(),
		ChatRetention: retention, Log: testLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	// Do not start the supervisor: retention tests use a fixed clock and
	// explicit snapshots, without background engines or reconciliation.
	return s
}

func retentionBlip(state string, generation int64, phase string, finish time.Time) v1.Blip {
	b := v1.Blip{
		ObjectMeta: metav1.ObjectMeta{
			Name: state + "-g" + strconv.FormatInt(generation, 10), Namespace: "default",
			Labels:      map[string]string{LabelSession: state},
			Annotations: map[string]string{AnnotationGeneration: strconv.FormatInt(generation, 10)},
		},
		Status: v1.BlipStatus{Phase: phase},
	}
	if !finish.IsZero() {
		finished := metav1.NewTime(finish)
		b.Status.FinishTime = &finished
	}
	return b
}

func retentionSnapshot(t *testing.T, cluster *fakeCluster) ([]v1.BlipState, map[string][]v1.Blip) {
	t.Helper()
	states, err := cluster.ListSessions(context.Background(), "default")
	if err != nil {
		t.Fatal(err)
	}
	blips, err := cluster.ListSessionBlips(context.Background(), "default")
	if err != nil {
		t.Fatal(err)
	}
	byState := make(map[string][]v1.Blip)
	for _, b := range blips {
		name := b.Labels[LabelSession]
		byState[name] = append(byState[name], b)
	}
	return states, byState
}

func assertRetentionSession(t *testing.T, cluster *fakeCluster, name string, wantPresent bool) {
	t.Helper()
	_, err := cluster.GetSession(context.Background(), "default", name)
	if wantPresent && err != nil {
		t.Errorf("session %q should be retained: %v", name, err)
	}
	if !wantPresent && !apierrors.IsNotFound(err) {
		t.Errorf("session %q should be deleted; GetSession error = %v", name, err)
	}
}

func TestChatRetentionExpiry(t *testing.T) {
	const retention = 24 * time.Hour
	for _, tt := range []struct {
		name    string
		phase   string
		age     time.Duration
		missing bool
		zero    bool
		wantDel bool
	}{
		{name: "successful expired", phase: v1.BlipSucceeded, age: retention + time.Second, wantDel: true},
		{name: "failed expired", phase: v1.BlipFailed, age: retention + time.Second, wantDel: true},
		{name: "exact boundary", phase: v1.BlipSucceeded, age: retention, wantDel: true},
		{name: "just before boundary", phase: v1.BlipSucceeded, age: retention - time.Nanosecond},
		{name: "future finish", phase: v1.BlipSucceeded, age: -time.Hour},
		{name: "missing finish", phase: v1.BlipSucceeded, missing: true},
		{name: "failed missing finish", phase: v1.BlipFailed, missing: true},
		{name: "zero finish pointer", phase: v1.BlipSucceeded, zero: true},
		{name: "unknown phase", phase: "", age: 2 * retention},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cluster := newFakeCluster()
			st := newChat(cluster, "expired", DefaultProfileName)
			st.UID = types.UID("expired-uid")
			// Creation time is deliberately recent: retention starts at the
			// latest execution's finish, not the workspace's creation time.
			st.CreationTimestamp = metav1.NewTime(retentionNow)
			b := retentionBlip(st.Name, 1, tt.phase, retentionNow.Add(-tt.age))
			if tt.missing {
				b.Status.FinishTime = nil
			}
			if tt.zero {
				b.Status.FinishTime = &metav1.Time{}
			}
			cluster.blips[key(b.Namespace, b.Name)] = &b
			s := newRetentionServer(t, cluster, retention)
			states, byState := retentionSnapshot(t, cluster)
			s.reapSessions(context.Background(), states, byState, retentionNow)
			assertRetentionSession(t, cluster, st.Name, !tt.wantDel)
		})
	}
}

func TestChatRetentionDisabled(t *testing.T) {
	cluster := newFakeCluster()
	st := newChat(cluster, "disabled", DefaultProfileName)
	b := retentionBlip(st.Name, 1, v1.BlipSucceeded, retentionNow.Add(-365*24*time.Hour))
	cluster.blips[key(b.Namespace, b.Name)] = &b
	s := newRetentionServer(t, cluster, 0)
	states, byState := retentionSnapshot(t, cluster)
	s.reapSessions(context.Background(), states, byState, retentionNow)
	assertRetentionSession(t, cluster, st.Name, true)
}

func TestChatRetentionRecentAdmission(t *testing.T) {
	for _, tt := range []struct {
		name, activity string
		wantExpired    bool
	}{
		{"recent", retentionNow.Add(-time.Hour).Format(time.RFC3339Nano), false},
		{"expired", retentionNow.Add(-25 * time.Hour).Format(time.RFC3339Nano), true},
		{"invalid", "invalid", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cluster := newFakeCluster()
			st := newChat(cluster, "admission", DefaultProfileName)
			st.Annotations[annotationActivityAt] = tt.activity
			b := retentionBlip(st.Name, 1, v1.BlipSucceeded, retentionNow.Add(-48*time.Hour))
			if got := retentionExpired(st, []v1.Blip{b}, retentionNow, 24*time.Hour); got != tt.wantExpired {
				t.Fatalf("retentionExpired = %v, want %v", got, tt.wantExpired)
			}
		})
	}
}

func TestChatRetentionAdmissionGrace(t *testing.T) {
	cluster := newFakeCluster()
	st := newChat(cluster, "admission", DefaultProfileName)
	st.Annotations[annotationActivityAt] = retentionNow.Add(-time.Second).Format(time.RFC3339Nano)
	b := retentionBlip(st.Name, 1, v1.BlipSucceeded, retentionNow.Add(-time.Hour))
	if retentionExpired(st, []v1.Blip{b}, retentionNow, time.Millisecond) {
		t.Fatal("short retention must not expire an in-flight admission")
	}
}

func TestChatRetentionRejectsNegative(t *testing.T) {
	s, err := New(Options{Cluster: newFakeCluster(), Wire: newFakeWire(), ChatRetention: -time.Second, Log: testLogger()})
	if s != nil {
		s.Close()
	}
	if err == nil {
		t.Fatal("New accepted negative chat retention")
	}
}

func TestChatRetentionLatestGeneration(t *testing.T) {
	for _, latestExpired := range []bool{false, true} {
		for _, reverse := range []bool{false, true} {
			t.Run(fmt.Sprintf("latestExpired=%v/reverse=%v", latestExpired, reverse), func(t *testing.T) {
				cluster := newFakeCluster()
				st := newChat(cluster, "generations", DefaultProfileName)
				oldFinish, newFinish := retentionNow.Add(-48*time.Hour), retentionNow.Add(-time.Hour)
				if latestExpired {
					oldFinish, newFinish = newFinish, oldFinish
				}
				blips := []v1.Blip{
					retentionBlip(st.Name, 2, v1.BlipSucceeded, oldFinish),
					retentionBlip(st.Name, 10, v1.BlipFailed, newFinish),
				}
				if reverse {
					blips[0], blips[1] = blips[1], blips[0]
				}
				for i := range blips {
					cluster.blips[key(blips[i].Namespace, blips[i].Name)] = &blips[i]
				}
				s := newRetentionServer(t, cluster, 24*time.Hour)
				s.reapSessions(context.Background(), []v1.BlipState{*st.DeepCopy()}, map[string][]v1.Blip{st.Name: blips}, retentionNow)
				assertRetentionSession(t, cluster, st.Name, !latestExpired)
			})
		}
	}
}

func TestChatRetentionProtectsBusySessions(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(*v1.BlipState, *fakeCluster)
	}{
		{name: "no executions", mutate: func(_ *v1.BlipState, c *fakeCluster) { c.blips = map[string]*v1.Blip{} }},
		{name: "pending state", mutate: func(st *v1.BlipState, _ *fakeCluster) { st.Status.Phase = v1.StatePending }},
		{name: "in-use state", mutate: func(st *v1.BlipState, _ *fakeCluster) { st.Status.Phase = v1.StateInUse }},
		{name: "saving state", mutate: func(st *v1.BlipState, _ *fakeCluster) { st.Status.Phase = v1.StateSaving }},
		{name: "writer on ready state", mutate: func(st *v1.BlipState, _ *fakeCluster) { st.Status.Writer = &v1.Writer{BlipName: "writer"} }},
		{name: "older pending blip", mutate: retentionBusyBlip(v1.BlipPending)},
		{name: "older running blip", mutate: retentionBusyBlip(v1.BlipRunning)},
		{name: "older saving blip", mutate: retentionBusyBlip(v1.BlipSaving)},
		{name: "latest missing finish", mutate: func(st *v1.BlipState, c *fakeCluster) {
			b := retentionBlip(st.Name, 3, v1.BlipSucceeded, time.Time{})
			c.blips[key(b.Namespace, b.Name)] = &b
		}},
		{name: "new completed turn", mutate: func(st *v1.BlipState, c *fakeCluster) {
			b := retentionBlip(st.Name, 3, v1.BlipSucceeded, retentionNow.Add(-time.Hour))
			c.blips[key(b.Namespace, b.Name)] = &b
		}},
	} {
		for _, staleSnapshot := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/staleSnapshot=%v", tt.name, staleSnapshot), func(t *testing.T) {
				cluster := newFakeCluster()
				st := newChat(cluster, "protected", DefaultProfileName)
				b := retentionBlip(st.Name, 2, v1.BlipSucceeded, retentionNow.Add(-48*time.Hour))
				cluster.blips[key(b.Namespace, b.Name)] = &b
				s := newRetentionServer(t, cluster, 24*time.Hour)
				states, byState := retentionSnapshot(t, cluster)
				tt.mutate(st, cluster)
				if !staleSnapshot {
					states, byState = retentionSnapshot(t, cluster)
				}
				s.reapSessions(context.Background(), states, byState, retentionNow)
				assertRetentionSession(t, cluster, st.Name, true)
			})
		}
	}
}

func retentionBusyBlip(phase string) func(*v1.BlipState, *fakeCluster) {
	return func(st *v1.BlipState, cluster *fakeCluster) {
		// Even an older generation protects the workspace. A terminal latest
		// generation alone does not prove that no writer is still active.
		b := retentionBlip(st.Name, 1, phase, retentionNow.Add(-72*time.Hour))
		cluster.blips[key(b.Namespace, b.Name)] = &b
	}
}

func retentionChild(cluster *fakeCluster, parent *v1.BlipState, name string) *v1.BlipState {
	st := newChat(cluster, name, DefaultProfileName)
	st.UID = types.UID(name + "-uid")
	st.Labels[LabelParent] = parent.Name
	st.Annotations[AnnotationParent] = parent.Name
	st.Annotations[AnnotationRoot] = parent.Annotations[AnnotationRoot]
	depth, _ := strconv.Atoi(parent.Annotations[AnnotationDepth])
	st.Annotations[AnnotationDepth] = strconv.Itoa(depth + 1)
	st.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: v1.GroupVersion.String(), Kind: "BlipState", Name: parent.Name, UID: parent.UID,
	}}
	return st
}

func TestChatRetentionDeletesLeavesAcrossPasses(t *testing.T) {
	cluster := newFakeCluster()
	parent := newChat(cluster, "parent", DefaultProfileName)
	parent.UID = types.UID("parent-uid")
	child := retentionChild(cluster, parent, "child")
	grandchild := retentionChild(cluster, child, "grandchild")
	for _, st := range []*v1.BlipState{parent, child, grandchild} {
		b := retentionBlip(st.Name, 1, v1.BlipSucceeded, retentionNow.Add(-48*time.Hour))
		cluster.blips[key(b.Namespace, b.Name)] = &b
	}
	s := newRetentionServer(t, cluster, 24*time.Hour)
	for pass, deleted := range []string{grandchild.Name, child.Name, parent.Name} {
		states, byState := retentionSnapshot(t, cluster)
		s.reapSessions(context.Background(), states, byState, retentionNow)
		assertRetentionSession(t, cluster, deleted, false)
		if pass == 0 {
			assertRetentionSession(t, cluster, child.Name, true)
		}
		if pass < 2 {
			assertRetentionSession(t, cluster, parent.Name, true)
		}
	}
}

func TestChatRetentionFreshChildProtectsParent(t *testing.T) {
	cluster := newFakeCluster()
	parent := newChat(cluster, "parent", DefaultProfileName)
	parent.UID = types.UID("parent-uid")
	b := retentionBlip(parent.Name, 1, v1.BlipSucceeded, retentionNow.Add(-48*time.Hour))
	cluster.blips[key(b.Namespace, b.Name)] = &b
	s := newRetentionServer(t, cluster, 24*time.Hour)
	states, byState := retentionSnapshot(t, cluster)
	// A child created after the reconcile snapshot must still prevent deletion.
	child := retentionChild(cluster, parent, "new-child")
	s.reapSessions(context.Background(), states, byState, retentionNow)
	assertRetentionSession(t, cluster, parent.Name, true)
	assertRetentionSession(t, cluster, child.Name, true)
}

func TestChatRetentionProtectsRecreatedSession(t *testing.T) {
	cluster := newFakeCluster()
	st := newChat(cluster, "recreated", DefaultProfileName)
	st.UID = types.UID("original-uid")
	b := retentionBlip(st.Name, 1, v1.BlipSucceeded, retentionNow.Add(-48*time.Hour))
	cluster.blips[key(b.Namespace, b.Name)] = &b
	s := newRetentionServer(t, cluster, 24*time.Hour)
	states, byState := retentionSnapshot(t, cluster)
	// An eligible replacement with the same name is not the session from
	// the snapshot. Its UID must be checked before submitting deletion.
	st.UID = types.UID("replacement-uid")
	s.reapSessions(context.Background(), states, byState, retentionNow)
	assertRetentionSession(t, cluster, st.Name, true)
}

func TestChatRetentionShardOwnership(t *testing.T) {
	for _, owned := range []bool{false, true} {
		t.Run(fmt.Sprintf("owned=%v", owned), func(t *testing.T) {
			cluster := newFakeCluster()
			st := newChat(cluster, "sharded", DefaultProfileName)
			b := retentionBlip(st.Name, 1, v1.BlipSucceeded, retentionNow.Add(-48*time.Hour))
			cluster.blips[key(b.Namespace, b.Name)] = &b
			s := newRetentionServer(t, cluster, 24*time.Hour)
			s.shards = &sharder{service: "blipchat", self: "pod-a", members: []string{"pod-b"}}
			if owned {
				s.shards.self = "pod-b"
			}
			states, byState := retentionSnapshot(t, cluster)
			s.reapSessions(context.Background(), states, byState, retentionNow)
			assertRetentionSession(t, cluster, st.Name, !owned)
		})
	}
}
