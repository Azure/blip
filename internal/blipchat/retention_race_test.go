// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"context"
	"errors"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

type retentionResumeCluster struct {
	Cluster
	patch  func(context.Context, string, string, map[string]string, map[string]string) error
	create func(context.Context, string, *v1.Blip) error
}

func (c *retentionResumeCluster) PatchSession(ctx context.Context, ns, name string, labels, annotations map[string]string) error {
	return c.patch(ctx, ns, name, labels, annotations)
}

func (c *retentionResumeCluster) CreateBlip(ctx context.Context, ns string, blip *v1.Blip) error {
	if c.create != nil {
		return c.create(ctx, ns, blip)
	}
	return c.Cluster.CreateBlip(ctx, ns, blip)
}

func TestRetentionResumeFencesStaleDelete(t *testing.T) {
	ctx := context.Background()
	f := newFakeCluster()
	st := newChat(f, "chat", DefaultProfileName)
	st.UID, st.ResourceVersion = "chat-uid", "1"
	snapshot := st.DeepCopy()
	c := &retentionResumeCluster{Cluster: f}
	c.patch = func(ctx context.Context, ns, name string, labels, annotations map[string]string) error {
		assertAdmissionDeadline(t, ctx)
		return f.PatchSession(ctx, ns, name, labels, annotations)
	}
	c.create = func(ctx context.Context, ns string, blip *v1.Blip) error {
		assertAdmissionDeadline(t, ctx)
		current, err := f.GetSession(ctx, ns, st.Name)
		if err != nil {
			t.Fatal(err)
		}
		activity, err := time.Parse(time.RFC3339Nano, current.Annotations["chat.blip.dev/activity-at"])
		if err != nil || time.Since(activity) > time.Minute {
			t.Fatalf("new execution did not record recent activity: %q, %v", current.Annotations["chat.blip.dev/activity-at"], err)
		}
		if err := f.DeleteSession(ctx, ns, st.Name, snapshot.UID, snapshot.ResourceVersion); !apierrors.IsConflict(err) {
			t.Fatalf("stale delete error = %v, want conflict", err)
		}
		return f.CreateBlip(ctx, ns, blip)
	}
	s := &Server{cluster: c, namespace: "default", chatRetention: time.Hour}
	if _, err := s.ensureRunning(ctx, snapshot, Profile{}); err != nil {
		t.Fatal(err)
	}
	if f.createBlip != 1 {
		t.Fatalf("created %d blips, want 1", f.createBlip)
	}
}

func assertAdmissionDeadline(t *testing.T, ctx context.Context) {
	t.Helper()
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > chatAdmissionTimeout {
		t.Fatalf("admission deadline = %v, present = %v; want deadline within %v", deadline, ok, chatAdmissionTimeout)
	}
}

func TestRetentionResumeTouchesEachCreateAttempt(t *testing.T) {
	f := newFakeCluster()
	st := newChat(f, "chat", DefaultProfileName)
	patches, attempts := 0, 0
	c := &retentionResumeCluster{Cluster: f}
	c.patch = func(ctx context.Context, ns, name string, labels, annotations map[string]string) error {
		patches++
		return f.PatchSession(ctx, ns, name, labels, annotations)
	}
	c.create = func(ctx context.Context, ns string, blip *v1.Blip) error {
		attempts++
		assertAdmissionDeadline(t, ctx)
		if patches != attempts {
			t.Fatalf("create attempt %d has %d activity patches", attempts, patches)
		}
		if attempts == 1 {
			// Another caller won this generation and it has already finished.
			if err := f.CreateBlip(ctx, ns, blip); err != nil {
				t.Fatal(err)
			}
			f.setActive(ns, st.Name, v1.BlipSucceeded)
		}
		return f.CreateBlip(ctx, ns, blip)
	}
	s := &Server{cluster: c, namespace: "default", chatRetention: time.Hour}
	if _, err := s.ensureRunning(context.Background(), st.DeepCopy(), Profile{}); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("create attempts = %d, want 2", attempts)
	}
}

func TestRetentionResumeRefusesChangedState(t *testing.T) {
	for _, change := range []string{"patch error", "deleting", "replaced", "missing"} {
		t.Run(change, func(t *testing.T) {
			ctx := context.Background()
			f := newFakeCluster()
			st := newChat(f, "chat", DefaultProfileName)
			st.UID = "original"
			snapshot := st.DeepCopy()
			patchErr := errors.New("patch failed")
			c := &retentionResumeCluster{Cluster: f}
			c.patch = func(ctx context.Context, ns, name string, labels, annotations map[string]string) error {
				if change == "patch error" {
					return patchErr
				}
				// Simulate deletion or replacement after the caller's read but
				// before the patch; metadata patches can still succeed.
				f.mu.Lock()
				switch change {
				case "deleting":
					now := metav1.Now()
					f.states[key(ns, name)].DeletionTimestamp = &now
				case "replaced":
					f.states[key(ns, name)].UID = "replacement"
				}
				f.mu.Unlock()
				if err := f.PatchSession(ctx, ns, name, labels, annotations); err != nil {
					return err
				}
				if change == "missing" {
					f.mu.Lock()
					delete(f.states, key(ns, name))
					f.mu.Unlock()
				}
				return nil
			}
			s := &Server{cluster: c, namespace: "default", chatRetention: time.Hour}
			if _, err := s.ensureRunning(ctx, snapshot, Profile{}); err == nil {
				t.Fatal("ensureRunning succeeded after state changed")
			} else if change == "patch error" && !errors.Is(err, patchErr) {
				t.Fatalf("error = %v, want patch error", err)
			}
			if f.createBlipAttempt != 0 {
				t.Fatalf("attempted %d creates after state changed", f.createBlipAttempt)
			}
		})
	}
}

func TestRetentionActivityOnlyForNewExecution(t *testing.T) {
	for _, mode := range []string{"disabled", "running", "pending"} {
		t.Run(mode, func(t *testing.T) {
			f := newFakeCluster()
			st := newChat(f, "chat", DefaultProfileName)
			retention := time.Hour
			if mode == "disabled" {
				retention = 0
			} else {
				phase := v1.BlipRunning
				if mode == "pending" {
					phase = v1.BlipPending
				}
				f.blips[key("default", "chat-g1")] = &v1.Blip{
					ObjectMeta: metav1.ObjectMeta{Name: "chat-g1", Namespace: "default", Labels: map[string]string{LabelSession: "chat"}},
					Status:     v1.BlipStatus{Phase: phase},
				}
			}
			c := &retentionResumeCluster{Cluster: f, patch: func(context.Context, string, string, map[string]string, map[string]string) error {
				t.Fatal("unexpected activity patch")
				return nil
			}}
			s := &Server{cluster: c, namespace: "default", chatRetention: retention}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "pending" {
				cancel()
			}
			_, err := s.ensureRunning(ctx, st, Profile{})
			if mode != "pending" && err != nil {
				t.Fatal(err)
			}
		})
	}
}

type retentionDeleteClient struct {
	client.Client
	options client.DeleteOptions
}

func (c *retentionDeleteClient) Delete(_ context.Context, _ client.Object, opts ...client.DeleteOption) error {
	c.options = client.DeleteOptions{}
	for _, opt := range opts {
		opt.ApplyToDelete(&c.options)
	}
	return nil
}

func TestKubeDeleteSessionResourceVersionPrecondition(t *testing.T) {
	c := &retentionDeleteClient{}
	k := &kubeCluster{c: c}
	if err := k.DeleteSession(context.Background(), "default", "chat", "uid", "", "42", "43"); err != nil {
		t.Fatal(err)
	}
	p := c.options.Preconditions
	if p == nil || p.UID == nil || *p.UID != "uid" || p.ResourceVersion == nil || *p.ResourceVersion != "42" {
		t.Fatalf("delete preconditions = %+v, want UID uid and resource version 42", p)
	}
	if err := k.DeleteSession(context.Background(), "default", "chat", "uid"); err != nil {
		t.Fatal(err)
	}
	if c.options.Preconditions.ResourceVersion != nil {
		t.Fatal("unexpected resource version precondition without version")
	}
}
