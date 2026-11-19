package controller

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/podapi"
)

func int64Ptr(v int64) *int64 { return &v }

func int32Ptr(v int32) *int32 { return &v }

func TestActiveDeadlineStopsAndFinishes(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.readyState("home", "n1")
	b := e.startBlip("job", "n1", withRoot("home"))
	e.updateBlip("job", func(b *v1.Blip) { b.Spec.ActiveDeadlineSeconds = int64Ptr(60) })
	start := b.Status.StartTime.Time

	// The deadline is the earliest requeue bound, so it fires on its own.
	e.now = start.Add(30 * time.Second)
	res := e.run(e.blip, ns, "job")
	if b = e.getBlip("job"); b.Spec.Stop {
		t.Fatal("stopped before the deadline")
	}
	if res.RequeueAfter != 30*time.Second {
		t.Fatalf("requeue after %s, want the 30s left before the deadline", res.RequeueAfter)
	}

	// The stop is retried on a conflict instead of losing the deadline.
	conflicts := 0
	e.blip.Client = interceptor.NewClient(e.c.(client.WithWatch), interceptor.Funcs{
		Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			if _, ok := obj.(*v1.Blip); ok && conflicts == 0 {
				conflicts++
				return apierrors.NewConflict(schema.GroupResource{Group: "blip.dev", Resource: "blips"}, obj.GetName(), nil)
			}
			return c.Patch(ctx, obj, patch, opts...)
		},
	})
	e.now = start.Add(61 * time.Second)
	e.run(e.blip, ns, "job")
	b = e.getBlip("job")
	if conflicts != 1 {
		t.Fatalf("deadline stop did not retry the conflict: %d", conflicts)
	}
	if !b.Spec.Stop || b.Annotations[v1.AnnotationStopReason] != "DeadlineExceeded" {
		t.Fatalf("deadline did not set stop/reason: %+v %+v", b.Spec, b.Annotations)
	}

	// A deadline stop finishes exactly like a user-set spec.stop.
	e.observe(b.Status.Pod, podapi.Observed{Phase: podapi.PhaseExited, Exit: &podapi.Exit{Reason: ReasonStopped}})
	e.run(e.blip, ns, "job")
	expectPhase(t, e.getBlip("job"), v1.BlipSaving, ReasonStopped)
	e.saveWriter("home", newID())
	e.run(e.blip, ns, "job")
	b = e.getBlip("job")
	expectPhase(t, b, v1.BlipSucceeded, ReasonStopped)
	if b.Status.ExitCode != nil || b.Status.FinishTime == nil {
		t.Fatalf("deadline stop recorded a command failure or no finish: %+v", b.Status)
	}
}

// TestActiveDeadlineOverflowDoesNotStop guards the seconds-to-duration
// conversion. An activeDeadlineSeconds near int64 max used to overflow
// time.Duration, wrap negative, and stop the Blip immediately. Admission now
// bounds the field, but a stored object must also be saturated rather than
// interpreted as already expired.
func TestActiveDeadlineOverflowDoesNotStop(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if got, want := deadlineTime(start, 9223372036), start.Add(time.Duration(9223372036)*time.Second); !got.Equal(want) {
		t.Errorf("largest safe deadline = %s, want %s", got, want)
	}
	for _, seconds := range []int64{9223372037, math.MaxInt64} {
		got := deadlineTime(start, seconds)
		if got.Before(start) {
			t.Errorf("deadline for %d wrapped negative: %s", seconds, got)
		}
		if !got.After(start.Add(100 * 365 * 24 * time.Hour)) {
			t.Errorf("deadline for %d = %s, want a saturated far-future bound", seconds, got)
		}
	}

	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.readyState("home", "n1")
	b := e.startBlip("job", "n1", withRoot("home"))
	e.updateBlip("job", func(b *v1.Blip) { b.Spec.ActiveDeadlineSeconds = int64Ptr(math.MaxInt64) })
	e.now = b.Status.StartTime.Time.Add(time.Minute)
	e.run(e.blip, ns, "job")
	if b = e.getBlip("job"); b.Spec.Stop {
		t.Fatal("an overflowing activeDeadlineSeconds stopped the blip immediately")
	}
}

func TestFinishedTTLDeletesBlip(t *testing.T) {
	e := newEnv(t)
	e.newBlip("job", withCommand("true"))
	e.updateBlip("job", func(b *v1.Blip) { b.Spec.TTLSecondsAfterFinished = int32Ptr(0) })
	e.setBlipStatus("job", func(b *v1.Blip) {
		b.Status.Phase = v1.BlipSucceeded
		finish := metav1.NewTime(e.now)
		b.Status.FinishTime = &finish
	})
	e.run(e.blip, ns, "job")
	if err := e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: "job"}, &v1.Blip{}); !apierrors.IsNotFound(err) {
		t.Fatalf("TTL 0 did not delete the finished blip: %v", err)
	}
}

// TestFinishedTTLDeleteKeepsReplacement covers a stale cached Get: the
// finished Blip is gone by the time the TTL delete reaches the API server and a
// different Blip now owns the name. The delete must be pinned to the observed
// UID so the replacement survives.
func TestFinishedTTLDeleteKeepsReplacement(t *testing.T) {
	e := newEnv(t)
	e.newBlip("job", withCommand("true"))
	e.updateBlip("job", func(b *v1.Blip) { b.Spec.TTLSecondsAfterFinished = int32Ptr(0) })
	e.setBlipStatus("job", func(b *v1.Blip) {
		b.Status.Phase = v1.BlipSucceeded
		finish := metav1.NewTime(e.now)
		b.Status.FinishTime = &finish
	})
	replaced := false
	var pinned types.UID
	e.blip.Client = interceptor.NewClient(e.c.(client.WithWatch), interceptor.Funcs{
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			b, ok := obj.(*v1.Blip)
			if !ok || b.Name != "job" || replaced {
				return c.Delete(ctx, obj, opts...)
			}
			replaced = true
			// The observed incarnation is already gone; another Blip has
			// since been created under the same name.
			if err := c.Delete(ctx, &v1.Blip{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "job"}}); err != nil {
				return err
			}
			if err := c.Create(ctx, &v1.Blip{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "job", UID: "uid-replacement"}}); err != nil {
				return err
			}
			var do client.DeleteOptions
			do.ApplyOptions(opts)
			if do.Preconditions != nil && do.Preconditions.UID != nil {
				pinned = *do.Preconditions.UID
			}
			return deleteLikeAPI(ctx, c, obj, "uid-replacement", opts...)
		},
	})
	e.run(e.blip, ns, "job")
	if !replaced {
		t.Fatal("TTL did not attempt to delete the finished blip")
	}
	if pinned != "uid-job" {
		t.Fatalf("TTL delete precondition UID = %q, want the observed uid-job", pinned)
	}
	if got := e.getBlip("job"); got.UID != "uid-replacement" {
		t.Fatalf("TTL delete removed the replacement Blip: uid %q", got.UID)
	}
}

func TestFinishedTTLRequeuesUntilDue(t *testing.T) {
	e := newEnv(t)
	e.newBlip("job", withCommand("true"))
	e.updateBlip("job", func(b *v1.Blip) { b.Spec.TTLSecondsAfterFinished = int32Ptr(120) })
	e.setBlipStatus("job", func(b *v1.Blip) {
		b.Status.Phase = v1.BlipSucceeded
		finish := metav1.NewTime(e.now)
		b.Status.FinishTime = &finish
	})

	if res := e.run(e.blip, ns, "job"); res.RequeueAfter != 120*time.Second {
		t.Fatalf("requeue after %s, want the whole TTL", res.RequeueAfter)
	}
	if err := e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: "job"}, &v1.Blip{}); err != nil {
		t.Fatalf("blip deleted before its TTL: %v", err)
	}
	e.now = e.now.Add(119 * time.Second)
	if res := e.run(e.blip, ns, "job"); res.RequeueAfter != time.Second {
		t.Fatalf("requeue after %s, want the 1s left", res.RequeueAfter)
	}
	e.now = e.now.Add(time.Second)
	e.run(e.blip, ns, "job")
	if err := e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: "job"}, &v1.Blip{}); !apierrors.IsNotFound(err) {
		t.Fatalf("blip survived its TTL: %v", err)
	}
}

func TestPruneTemporaryMountDropsDeletingTarget(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.readyState("home", "n1")
	e.readyState("data", "n1")
	e.newBlip("active", withRoot("home"))
	b := e.getBlip("active")
	root := e.getState("home")
	root.Spec.Mounts = []v1.Mount{{State: "data", Path: "/data", BlipUID: string(b.UID)}}
	e.must(e.c.Update(e.ctx, root))

	data := e.getState("data")
	data.Finalizers = []string{v1.Finalizer}
	e.must(e.c.Update(e.ctx, data))
	e.must(e.c.Delete(e.ctx, data))

	e.run(e.state, ns, "home")
	if mounts := e.getState("home").Spec.Mounts; len(mounts) != 0 {
		t.Fatalf("temporary mount of a deleting state was kept: %+v", mounts)
	}
}

// TestSavingFailsDeletingAttachments covers a stopped Blip whose workspace
// (root or writable mount) is deleted before its save resolves. attachment
// treats a deleting state as resolved so the state finalizers cannot deadlock
// with the Blip; the discarded save must still be reported as a failure
// rather than as a successful stop.
func TestSavingFailsDeletingAttachments(t *testing.T) {
	for _, target := range []string{"root", "mount"} {
		t.Run(target, func(t *testing.T) {
			e := newEnv(t)
			e.addNodes("n1")
			e.newPool("default", 0, 0)
			e.readyState("home", "n1")
			mutate := []func(*v1.Blip){withRoot("home")}
			if target == "mount" {
				e.readyState("data", "n1")
				mutate = append(mutate, e.withMount("data", "/data", true))
			}
			b := e.startBlip("job", "n1", mutate...)
			e.updateBlip("job", func(b *v1.Blip) { b.Spec.Stop = true })
			e.observe(b.Status.Pod, podapi.Observed{Phase: podapi.PhaseExited, Exit: &podapi.Exit{Reason: ReasonStopped}})
			e.run(e.blip, ns, "job")
			expectPhase(t, e.getBlip("job"), v1.BlipSaving, ReasonStopped)

			state := "home"
			if target == "mount" {
				// The root resolves normally; only the mount state is deleted.
				e.saveWriter("home", newID())
				state = "data"
			}
			st := e.getState(state)
			st.Finalizers = []string{v1.Finalizer}
			e.must(e.c.Update(e.ctx, st))
			e.must(e.c.Delete(e.ctx, st))

			e.run(e.blip, ns, "job")
			b = e.getBlip("job")
			expectPhase(t, b, v1.BlipFailed, ReasonSaveFailed)
			if !strings.Contains(b.Status.Message, "save was discarded") {
				t.Fatalf("deleted state did not report a discarded save: %+v", b.Status)
			}
			if b.Status.ExitCode != nil {
				t.Fatalf("deleted state gave the stopped command an exit code: %+v", b.Status)
			}
		})
	}
}

func TestPendingFailsDeletingRoot(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.readyState("home", "n1")
	e.newBlip("job", withRoot("home"))
	root := e.getState("home")
	root.Finalizers = []string{v1.Finalizer}
	e.must(e.c.Update(e.ctx, root))
	e.must(e.c.Delete(e.ctx, root))

	e.run(e.blip, ns, "job")
	b := e.getBlip("job")
	expectPhase(t, b, v1.BlipFailed, ReasonStateNotFound)
	if b.Status.Message == "" {
		t.Fatal("no message for a deleting root")
	}
}
