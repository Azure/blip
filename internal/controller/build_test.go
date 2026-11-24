// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

func (e *env) setBlipPhase(name, phase string) {
	e.t.Helper()
	b := &v1.Blip{}
	if err := e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: name}, b); err != nil {
		e.t.Fatalf("get blip %s: %v", name, err)
	}
	b.Status.Phase = phase
	e.must(e.c.Status().Update(e.ctx, b))
}

func (e *env) newBuild(name string, mutate ...func(*v1.BlipState)) *v1.BlipState {
	e.t.Helper()
	st := &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{Name: name, Generation: 1, Labels: map[string]string{
			v1.LabelShared:       "true",
			"chat.blip.dev/base": "unbounded",
		}},
		Spec: v1.BlipStateSpec{
			HistoryLimit: 2,
			Build: &v1.BlipStateBuild{
				IntervalSeconds: 3600,
				Command:         []string{"sh", "-c", "build"},
				User:            "root",
				WorkingDir:      "/",
			},
		},
	}
	for _, m := range mutate {
		m(st)
	}
	e.create(st)
	return st
}

func TestBuildStartsPublishesAndRepeats(t *testing.T) {
	e := newEnv(t)
	e.newState("base", func(st *v1.BlipState) { st.Spec.Replicas = 1 })
	e.newBuild("cache", func(st *v1.BlipState) {
		st.Spec.Build.From = "base"
		st.Spec.Size = quantityPtr("20Gi")
	})

	res := e.run(e.state, ns, "cache")
	if res.RequeueAfter != buildPoll {
		t.Fatalf("requeue after %v, want %v", res.RequeueAfter, buildPoll)
	}
	recipe := e.getState("cache")
	if recipe.Status.Build == nil || recipe.Status.Build.Output == "" {
		t.Fatalf("build status not recorded: %+v", recipe.Status.Build)
	}
	output := e.getState(recipe.Status.Build.Output)
	if output.Spec.CopyFrom != "base" {
		t.Fatalf("output copyFrom = %q, want base", output.Spec.CopyFrom)
	}
	if output.Labels[v1.LabelShared] != "" {
		t.Fatal("output published before its build succeeded")
	}
	if output.Labels[v1.LabelBuild] != "cache" {
		t.Fatalf("output build label = %q", output.Labels[v1.LabelBuild])
	}
	blip := e.getBlip(recipe.Status.Build.Blip)
	if blip.Spec.State != output.Name || blip.Spec.User != "root" || blip.Spec.WorkingDir != "/" {
		t.Fatalf("unexpected build blip spec: %+v", blip.Spec)
	}
	if blip.Spec.ActiveDeadlineSeconds == nil || *blip.Spec.ActiveDeadlineSeconds != 3600 {
		t.Fatalf("active deadline = %v", blip.Spec.ActiveDeadlineSeconds)
	}

	e.setBlipPhase(blip.Name, v1.BlipSucceeded)
	e.run(e.state, ns, "cache")
	recipe = e.getState("cache")
	output = e.getState(recipe.Status.Build.Output)
	if output.Labels[v1.LabelShared] != "true" {
		t.Fatal("successful output was not published")
	}
	if output.Labels["chat.blip.dev/base"] != "unbounded" {
		t.Fatal("recipe labels were not copied to the output")
	}
	if output.Annotations[v1.AnnotationBuildStatus] != buildSucceeded {
		t.Fatalf("output build status = %q", output.Annotations[v1.AnnotationBuildStatus])
	}
	if recipe.Status.Build.Latest != output.Name {
		t.Fatalf("latest = %q, want %q", recipe.Status.Build.Latest, output.Name)
	}

	e.now = e.now.Add(3601 * time.Second)
	e.run(e.state, ns, "cache")
	recipe = e.getState("cache")
	if recipe.Status.Build.Output == output.Name {
		t.Fatal("second build did not start after the interval")
	}
	next := e.getState(recipe.Status.Build.Output)
	if next.Spec.CopyFrom != "base" || next.Spec.Size.String() != "20Gi" {
		t.Fatalf("second output spec = %+v", next.Spec)
	}
}

func TestBuildSpecChangeStartsImmediately(t *testing.T) {
	e := newEnv(t)
	e.newBuild("cache")
	e.run(e.state, ns, "cache")
	recipe := e.getState("cache")
	e.setBlipPhase(recipe.Status.Build.Blip, v1.BlipSucceeded)
	e.run(e.state, ns, "cache")
	recipe = e.getState("cache")
	first := recipe.Status.Build.Output

	recipe.Spec.Build.Command = []string{"sh", "-c", "build2"}
	recipe.Generation = 2
	e.must(e.c.Update(e.ctx, recipe))
	e.run(e.state, ns, "cache")
	recipe = e.getState("cache")
	if recipe.Status.Build.Output == first {
		t.Fatal("spec change did not start a build")
	}
}

// staleBlips is a cache that has not seen any Blip yet.
type staleBlips struct{ client.Client }

func (s staleBlips) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if _, ok := obj.(*v1.Blip); ok {
		return apierrors.NewNotFound(v1.GroupVersion.WithResource("blips").GroupResource(), key.Name)
	}
	return s.Client.Get(ctx, key, obj, opts...)
}

func TestBuildStaleCacheKeepsRunningAttempt(t *testing.T) {
	e := newEnv(t)
	e.newBuild("cache")
	e.run(e.state, ns, "cache")
	output := e.getState("cache").Status.Build.Output

	e.state.Client = staleBlips{e.c}
	e.run(e.state, ns, "cache")
	if got := e.getState(output).Annotations[v1.AnnotationBuildStatus]; got != buildRunning {
		t.Fatalf("output build status = %q after a stale cache miss, want %q", got, buildRunning)
	}

	e.state.Live = staleBlips{e.c}
	e.run(e.state, ns, "cache")
	if got := e.getState(output).Annotations[v1.AnnotationBuildStatus]; got != buildFailed {
		t.Fatalf("output build status = %q after its blip is gone, want %q", got, buildFailed)
	}
}

func TestBuildFailureKeepsLogsUntilNextAttempt(t *testing.T) {
	e := newEnv(t)
	e.newBuild("cache")
	e.run(e.state, ns, "cache")
	recipe := e.getState("cache")
	output := recipe.Status.Build.Output
	blip := e.getBlip(recipe.Status.Build.Blip)
	code := int32(7)
	blip.Status.Phase = v1.BlipFailed
	blip.Status.ExitCode = &code
	blip.Status.Message = "boom"
	e.must(e.c.Status().Update(e.ctx, blip))

	e.run(e.state, ns, "cache")
	recipe = e.getState("cache")
	outputState := e.getState(output)
	if outputState.Annotations[v1.AnnotationBuildStatus] != buildFailed {
		t.Fatalf("output build status = %q", outputState.Annotations[v1.AnnotationBuildStatus])
	}
	if outputState.Labels[v1.LabelShared] != "" {
		t.Fatal("failed output was published")
	}
	if recipe.Status.Build.Latest != "" {
		t.Fatalf("latest = %q after failure", recipe.Status.Build.Latest)
	}

	e.now = e.now.Add(3601 * time.Second)
	e.run(e.state, ns, "cache")
	recipe = e.getState("cache")
	if recipe.Status.Build.Output == output {
		t.Fatal("next attempt reused the failed output")
	}
	st := &v1.BlipState{}
	if err := e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: output}, st); err == nil {
		t.Fatal("failed output was not removed")
	}
}

func TestBuildBuilderMountsOutput(t *testing.T) {
	e := newEnv(t)
	e.newState("devimage")
	e.newBuild("cache", func(st *v1.BlipState) {
		st.Spec.Build.Builder = "devimage"
		st.Spec.Build.Path = "/cache"
	})
	e.run(e.state, ns, "cache")
	recipe := e.getState("cache")
	copied := e.getState(recipe.Status.Build.Builder)
	if copied.Spec.CopyFrom != "devimage" {
		t.Fatalf("builder copyFrom = %q", copied.Spec.CopyFrom)
	}
	if copied.Spec.Size != nil {
		t.Fatalf("builder size = %v, want the builder's own size", copied.Spec.Size)
	}
	if len(copied.Spec.Mounts) != 1 || copied.Spec.Mounts[0].State != recipe.Status.Build.Output ||
		copied.Spec.Mounts[0].Path != "/cache" || !copied.Spec.Mounts[0].Writable {
		t.Fatalf("builder mounts = %+v", copied.Spec.Mounts)
	}
	blip := e.getBlip(recipe.Status.Build.Blip)
	if blip.Spec.State != copied.Name {
		t.Fatalf("build blip root = %q, want %q", blip.Spec.State, copied.Name)
	}
	e.setBlipPhase(blip.Name, v1.BlipSucceeded)
	e.run(e.state, ns, "cache")
	if st := (&v1.BlipState{}); e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: copied.Name}, st) == nil {
		t.Fatal("builder copy was not removed after the build")
	}
}

func TestBuildIncrementalStartsFromLatestOutput(t *testing.T) {
	e := newEnv(t)
	e.newBuild("cache", func(st *v1.BlipState) { st.Spec.Build.Incremental = true })
	e.run(e.state, ns, "cache")
	recipe := e.getState("cache")
	first := recipe.Status.Build.Output
	e.setBlipPhase(recipe.Status.Build.Blip, v1.BlipSucceeded)
	e.run(e.state, ns, "cache")

	e.now = e.now.Add(3601 * time.Second)
	e.run(e.state, ns, "cache")
	recipe = e.getState("cache")
	next := e.getState(recipe.Status.Build.Output)
	if next.Spec.CopyFrom != first {
		t.Fatalf("incremental copyFrom = %q, want %q", next.Spec.CopyFrom, first)
	}
}

func TestBuildWaitsForMissingSource(t *testing.T) {
	e := newEnv(t)
	e.newBuild("cache", func(st *v1.BlipState) { st.Spec.Build.From = "missing" })
	res := e.run(e.state, ns, "cache")
	if res.RequeueAfter != buildPoll {
		t.Fatalf("requeue after %v", res.RequeueAfter)
	}
	recipe := e.getState("cache")
	if recipe.Status.Build != nil && recipe.Status.Build.Output != "" {
		t.Fatal("build started without its source")
	}
	if !strings.Contains(recipe.Status.Message, "missing") {
		t.Fatalf("message = %q", recipe.Status.Message)
	}
}

func TestBuildRetention(t *testing.T) {
	e := newEnv(t)
	e.newBuild("cache", func(st *v1.BlipState) { st.Spec.HistoryLimit = 2 })
	recipe := e.getState("cache")
	old := []string{"cache-20261115t120000", "cache-20261116t120000", "cache-20261117t110000"}
	for _, name := range old {
		e.create(&v1.BlipState{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: ns, Name: name,
				Labels:          map[string]string{v1.LabelBuild: "cache", v1.LabelShared: "true"},
				Annotations:     map[string]string{v1.AnnotationBuildStatus: buildSucceeded},
				OwnerReferences: []metav1.OwnerReference{ownedBy(recipe)},
			},
		})
	}
	e.run(e.state, ns, "cache")
	recipe = e.getState("cache")
	e.setBlipPhase(recipe.Status.Build.Blip, v1.BlipSucceeded)
	e.run(e.state, ns, "cache")

	for _, name := range old[:2] {
		st := &v1.BlipState{}
		if err := e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: name}, st); err == nil {
			t.Fatalf("old output %s was not pruned", name)
		}
	}
	newest := e.getState(recipe.Status.Build.Output)
	if newest.Labels[v1.LabelShared] != "true" {
		t.Fatal("newest output was not published")
	}
}

func TestBuildDeletionRemovesFinalizer(t *testing.T) {
	e := newEnv(t)
	recipe := e.newBuild("cache")
	e.run(e.state, ns, "cache")
	recipe = e.getState("cache")
	e.must(e.c.Delete(e.ctx, recipe))
	e.run(e.state, ns, "cache")
	st := &v1.BlipState{}
	if err := e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: "cache"}, st); err == nil {
		if len(st.Finalizers) > 0 {
			t.Fatal("finalizer was not removed")
		}
	}
}

func quantityPtr(s string) *resource.Quantity {
	q := resource.MustParse(s)
	return &q
}
