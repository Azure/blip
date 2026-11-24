// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package controller

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

const (
	// buildRunning, buildSucceeded, and buildFailed are the values of
	// v1.AnnotationBuildStatus on an output state. Only succeeded outputs
	// are published to consumers by label.
	buildRunning   = "running"
	buildSucceeded = "succeeded"
	buildFailed    = "failed"
	// buildPoll paces a running build. The Blip watch maps a Blip to the
	// states it uses, not to the build recipe that created it, so the recipe
	// polls its build instead of relying on an event.
	buildPoll = 10 * time.Second
	// buildRetry is how soon a recipe is looked at after a build finished,
	// so the release is recorded without waiting for the next interval.
	buildRetry = time.Second
	// annotationBuildCopy marks the throwaway copy a builder build boots.
	// It shares the recipe's owner and build label but is not an output.
	annotationBuildCopy = "blip.dev/build-copy"
	// maxBuildName leaves room for "-<timestamp>", a collision suffix, and
	// "-builder" inside the 253-character object name limit.
	maxBuildName = 253 - len("-20060102t150405") - len("-builder") - len("-0000")
)

// buildState reconciles a BlipState that is a build recipe. A recipe holds no
// data: it periodically creates an output state, runs a Blip that writes into
// it, and publishes the output's labels only after that Blip succeeds.
func (r *StateReconciler) buildState(ctx context.Context, st *v1.BlipState) (reconcile.Result, error) {
	if st.DeletionTimestamp != nil {
		// Outputs, builder copies, and build Blips are owned by the recipe,
		// so garbage collection removes them. Nothing else depends on it.
		if !controllerutil.ContainsFinalizer(st, v1.Finalizer) {
			return reconcile.Result{}, nil
		}
		base := st.DeepCopy()
		controllerutil.RemoveFinalizer(st, v1.Finalizer)
		return reconcile.Result{}, client.IgnoreNotFound(patchObject(ctx, r.Client, st, base))
	}
	base := st.DeepCopy()
	msg, result, err := r.reconcileBuild(ctx, st, r.now())
	if err != nil {
		return reconcile.Result{}, err
	}
	st.Status.Phase = statePhase(st)
	st.Status.Message = msg
	if !semanticEqual(base.Status, st.Status) {
		if err := patchStatus(ctx, r.Client, st, base); err != nil {
			return reconcile.Result{}, client.IgnoreNotFound(err)
		}
	}
	return result, nil
}

func (r *StateReconciler) reconcileBuild(ctx context.Context, st *v1.BlipState, now time.Time) (string, reconcile.Result, error) {
	spec := st.Spec.Build
	// Output names carry a timestamp and the builder copy adds "-builder".
	// Leave room for all of it, plus a collision suffix, in the 253-character
	// object name limit.
	if len(st.Name) > maxBuildName {
		return fmt.Sprintf("name is too long to name build outputs; use at most %d characters", maxBuildName), reconcile.Result{}, nil
	}
	interval := time.Duration(spec.IntervalSeconds) * time.Second
	outputs, err := r.buildOutputs(ctx, st)
	if err != nil {
		return "", reconcile.Result{}, err
	}

	// The newest output is the build in progress or the last finished
	// attempt. Finish it before deciding whether another build is due.
	if n := len(outputs); n > 0 {
		last := &outputs[n-1]
		if last.Annotations[v1.AnnotationBuildStatus] == buildRunning {
			phase, why, err := r.buildPhase(ctx, last.Namespace, last.Name)
			if err != nil {
				return "", reconcile.Result{}, err
			}
			switch phase {
			case v1.BlipSucceeded:
				if err := r.publishBuild(ctx, st, last); err != nil {
					return "", reconcile.Result{}, err
				}
				if err := r.removeBuildCopy(ctx, last.Namespace, buildCopyName(last.Name)); err != nil {
					return "", reconcile.Result{}, err
				}
				last.Annotations[v1.AnnotationBuildStatus] = buildSucceeded
				st.Status.Build = &v1.BlipStateBuildStatus{
					Latest:             last.Name,
					Output:             last.Name,
					Blip:               last.Name,
					Builder:            attemptBuilder(st, last.Name),
					LastBuild:          lastStarted(st, last, now),
					ObservedGeneration: lastGeneration(st),
					Message:            "",
				}
				return "", r.nextBuild(st, now, interval), r.pruneBuilds(ctx, st, outputs)
			case v1.BlipPending, v1.BlipRunning, v1.BlipSaving:
				return "building " + last.Name, reconcile.Result{RequeueAfter: buildPoll}, nil
			default:
				// Failed, or its Blip is gone. Keep the output unpublished
				// until the next attempt removes it, so its logs stay
				// readable in the meantime.
				if err := r.failBuild(ctx, last, why); err != nil {
					return "", reconcile.Result{}, err
				}
				st.Status.Build = &v1.BlipStateBuildStatus{
					Latest:             latestBuild(outputs),
					Output:             last.Name,
					Blip:               last.Name,
					Builder:            attemptBuilder(st, last.Name),
					LastBuild:          lastStarted(st, last, now),
					ObservedGeneration: lastGeneration(st),
					Message:            why,
				}
				last.Annotations[v1.AnnotationBuildStatus] = buildFailed
				if err := r.pruneBuilds(ctx, st, outputs); err != nil {
					return "", reconcile.Result{}, err
				}
				return why, r.nextBuild(st, now, interval), nil
			}
		}
	}

	last := st.Status.Build
	due := last == nil || last.LastBuild == nil ||
		last.ObservedGeneration != st.Generation ||
		!now.Before(last.LastBuild.Time.Add(interval))
	if !due {
		return "", r.nextBuild(st, now, interval), r.pruneBuilds(ctx, st, outputs)
	}

	// Resolve the build's inputs before touching the cluster. A recipe that
	// names another recipe uses its newest successful output.
	from := spec.From
	if spec.Incremental {
		if newest := latestBuild(outputs); newest != "" {
			from = newest
		}
	}
	from, ready, why, err := r.buildSource(ctx, st.Namespace, from)
	if err != nil {
		return "", reconcile.Result{}, err
	}
	if !ready {
		return why, reconcile.Result{RequeueAfter: buildPoll}, nil
	}
	builder := spec.Builder
	builder, ready, why, err = r.buildSource(ctx, st.Namespace, builder)
	if err != nil {
		return "", reconcile.Result{}, err
	}
	if !ready {
		return why, reconcile.Result{RequeueAfter: buildPoll}, nil
	}

	// Only the newest failed attempt is kept for its logs. Remove every
	// earlier unpublished output before allocating another filesystem.
	if err := r.removeBuilds(ctx, outputs); err != nil {
		return "", reconcile.Result{}, err
	}

	newOutput := func(name string) *v1.BlipState {
		return &v1.BlipState{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:       st.Namespace,
				Name:            name,
				Labels:          map[string]string{v1.LabelBuild: st.Name},
				Annotations:     map[string]string{v1.AnnotationBuildStatus: buildRunning},
				OwnerReferences: []metav1.OwnerReference{ownedBy(st)},
			},
			Spec: v1.BlipStateSpec{
				CopyFrom:         from,
				Size:             copyQuantity(st.Spec.Size),
				StreamSize:       copyQuantity(st.Spec.StreamSize),
				Replicas:         st.Spec.Replicas,
				NodeSelector:     maps.Clone(st.Spec.NodeSelector),
				ImagePullSecrets: slices.Clone(st.Spec.ImagePullSecrets),
				Runtime:          copyRuntime(st.Spec.Runtime),
			},
		}
	}
	name := fmt.Sprintf("%s-%s", st.Name, now.UTC().Format("20060102t150405"))
	if err := r.Create(ctx, newOutput(name)); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return "", reconcile.Result{}, err
		}
		// Two builds in one second: keep the name unique.
		name += "-" + r.newID()[:4]
		if err := r.Create(ctx, newOutput(name)); err != nil {
			return "", reconcile.Result{}, err
		}
	}

	copied := ""
	if builder != "" {
		copied = buildCopyName(name)
		copy := &v1.BlipState{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:       st.Namespace,
				Name:            copied,
				Labels:          map[string]string{v1.LabelBuild: st.Name},
				Annotations:     map[string]string{annotationBuildCopy: name},
				OwnerReferences: []metav1.OwnerReference{ownedBy(st)},
			},
			Spec: v1.BlipStateSpec{
				// The builder keeps its own size: the output is a mount,
				// not part of this filesystem.
				CopyFrom:     builder,
				Replicas:     st.Spec.Replicas,
				NodeSelector: maps.Clone(st.Spec.NodeSelector),
				Runtime:      copyRuntime(st.Spec.Runtime),
				Mounts:       []v1.Mount{{State: name, Path: spec.Path, Writable: true}},
			},
		}
		if err := r.Create(ctx, copy); err != nil {
			return "", reconcile.Result{}, err
		}
	}

	root := name
	if copied != "" {
		root = copied
	}
	seconds := spec.IntervalSeconds
	ttl := int32(seconds)
	if int64(ttl) != seconds {
		ttl = 1<<31 - 1
	}
	blip := &v1.Blip{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       st.Namespace,
			Name:            name,
			Labels:          map[string]string{v1.LabelBuild: st.Name},
			OwnerReferences: []metav1.OwnerReference{ownedBy(st)},
		},
		Spec: v1.BlipSpec{
			Pool:                    poolOrDefault(spec.Pool),
			State:                   root,
			Command:                 spec.Command,
			Env:                     spec.Env,
			WorkingDir:              workingDirOrDefault(spec.WorkingDir),
			User:                    userOrDefault(spec.User),
			ActiveDeadlineSeconds:   &seconds,
			TTLSecondsAfterFinished: &ttl,
		},
	}
	if err := r.Create(ctx, blip); err != nil {
		return "", reconcile.Result{}, err
	}
	started := metav1.NewTime(now)
	st.Status.Build = &v1.BlipStateBuildStatus{
		Latest:             latestBuild(outputs),
		Output:             name,
		Blip:               name,
		Builder:            copied,
		LastBuild:          &started,
		ObservedGeneration: st.Generation,
		Message:            "building",
	}
	return "building " + name, reconcile.Result{RequeueAfter: buildPoll}, nil
}

// nextBuild returns the wait until the next scheduled attempt.
func (r *StateReconciler) nextBuild(st *v1.BlipState, now time.Time, interval time.Duration) reconcile.Result {
	if b := st.Status.Build; b != nil && b.LastBuild != nil {
		if wait := b.LastBuild.Time.Add(interval).Sub(now); wait > buildRetry {
			return reconcile.Result{RequeueAfter: wait}
		}
	}
	return reconcile.Result{RequeueAfter: buildRetry}
}

// buildPhase returns the phase of the Blip that runs an output, or Failed with
// a diagnostic when the Blip is gone.
func (r *StateReconciler) buildPhase(ctx context.Context, namespace, name string) (string, string, error) {
	blip := &v1.Blip{}
	key := types.NamespacedName{Namespace: namespace, Name: name}
	err := r.Get(ctx, key, blip)
	if apierrors.IsNotFound(err) && r.Live != nil {
		// The cache can lag the Blip this recipe just created. Failing the
		// attempt on a stale miss would discard a build that is running.
		err = r.Live.Get(ctx, key, blip)
	}
	if err != nil {
		if apierrors.IsNotFound(err) {
			return v1.BlipFailed, "build blip is gone", nil
		}
		return "", "", err
	}
	if !v1.Finished(blip) {
		if blip.Status.Phase == "" {
			// Not reconciled yet.
			return v1.BlipPending, "", nil
		}
		return blip.Status.Phase, "", nil
	}
	if blip.Status.Phase == v1.BlipSucceeded {
		return v1.BlipSucceeded, "", nil
	}
	why := blip.Status.Message
	if why == "" && blip.Status.ExitCode != nil {
		why = fmt.Sprintf("exit code %d", *blip.Status.ExitCode)
	}
	if why == "" {
		why = "build failed"
	}
	return v1.BlipFailed, why, nil
}

// publishBuild copies the recipe's labels and annotations onto a successful
// output. This is the only moment an output becomes visible to selectors.
func (r *StateReconciler) publishBuild(ctx context.Context, st *v1.BlipState, output *v1.BlipState) error {
	latest := &v1.BlipState{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(output), latest); err != nil {
		return client.IgnoreNotFound(err)
	}
	base := latest.DeepCopy()
	if latest.Labels == nil {
		latest.Labels = map[string]string{}
	}
	for k, v := range st.Labels {
		latest.Labels[k] = v
	}
	latest.Labels[v1.LabelBuild] = st.Name
	if latest.Annotations == nil {
		latest.Annotations = map[string]string{}
	}
	for k, v := range st.Annotations {
		if strings.HasPrefix(k, "kubectl.kubernetes.io/") {
			continue
		}
		latest.Annotations[k] = v
	}
	latest.Annotations[v1.AnnotationBuildStatus] = buildSucceeded
	return patchObject(ctx, r.Client, latest, base)
}

func (r *StateReconciler) failBuild(ctx context.Context, output *v1.BlipState, why string) error {
	latest := &v1.BlipState{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(output), latest); err != nil {
		return client.IgnoreNotFound(err)
	}
	base := latest.DeepCopy()
	if latest.Annotations == nil {
		latest.Annotations = map[string]string{}
	}
	latest.Annotations[v1.AnnotationBuildStatus] = buildFailed
	return patchObject(ctx, r.Client, latest, base)
}

// buildOutputs lists the outputs owned by a recipe, oldest first.
func (r *StateReconciler) buildOutputs(ctx context.Context, st *v1.BlipState) ([]v1.BlipState, error) {
	var list v1.BlipStateList
	if err := r.List(ctx, &list, client.InNamespace(st.Namespace), client.MatchingLabels{v1.LabelBuild: st.Name}); err != nil {
		return nil, err
	}
	outputs := make([]v1.BlipState, 0, len(list.Items))
	for _, output := range list.Items {
		if output.Annotations[annotationBuildCopy] != "" {
			continue
		}
		if ownedByUID(output.OwnerReferences, st.UID) {
			outputs = append(outputs, output)
		}
	}
	sort.Slice(outputs, func(i, j int) bool {
		a, b := outputs[i], outputs[j]
		if !a.CreationTimestamp.Equal(&b.CreationTimestamp) {
			return a.CreationTimestamp.Before(&b.CreationTimestamp)
		}
		return a.Name < b.Name
	})
	return outputs, nil
}

// pruneBuilds keeps the newest historyLimit published outputs and removes the
// builder copies of finished attempts.
func (r *StateReconciler) pruneBuilds(ctx context.Context, st *v1.BlipState, outputs []v1.BlipState) error {
	limit := st.Spec.HistoryLimit
	if limit <= 0 {
		limit = 1
	}
	kept := 0
	for i := len(outputs) - 1; i >= 0; i-- {
		output := &outputs[i]
		status := output.Annotations[v1.AnnotationBuildStatus]
		if status == buildSucceeded {
			kept++
			if int32(kept) > limit {
				if err := r.removeBuild(ctx, output); err != nil {
					return err
				}
				continue
			}
		}
		if status != buildRunning {
			if err := r.removeBuildCopy(ctx, output.Namespace, buildCopyName(output.Name)); err != nil {
				return err
			}
		}
	}
	return nil
}

// removeBuilds removes earlier unpublished outputs. It is only called when no
// build is running, so a "running" annotation here is an orphan.
func (r *StateReconciler) removeBuilds(ctx context.Context, outputs []v1.BlipState) error {
	for i := range outputs {
		output := &outputs[i]
		if output.Annotations[v1.AnnotationBuildStatus] == buildSucceeded {
			continue
		}
		if err := r.removeBuild(ctx, output); err != nil {
			return err
		}
	}
	return nil
}

func (r *StateReconciler) removeBuild(ctx context.Context, output *v1.BlipState) error {
	if output.DeletionTimestamp == nil {
		if err := r.Delete(ctx, output); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	blip := &v1.Blip{ObjectMeta: metav1.ObjectMeta{Namespace: output.Namespace, Name: output.Name}}
	if err := r.Delete(ctx, blip); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	return r.removeBuildCopy(ctx, output.Namespace, buildCopyName(output.Name))
}

func (r *StateReconciler) removeBuildCopy(ctx context.Context, namespace, name string) error {
	copied := &v1.BlipState{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
	if err := r.Delete(ctx, copied); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	return nil
}

// buildSource resolves a build input. A state that is itself a recipe resolves
// to its newest successful output.
func (r *StateReconciler) buildSource(ctx context.Context, namespace, name string) (string, bool, string, error) {
	if name == "" {
		return "", true, "", nil
	}
	src := &v1.BlipState{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, src); err != nil {
		if apierrors.IsNotFound(err) {
			return "", false, fmt.Sprintf("waiting for state %q", name), nil
		}
		return "", false, "", err
	}
	if src.Spec.Build == nil {
		return name, true, "", nil
	}
	if src.Status.Build == nil || src.Status.Build.Latest == "" {
		return "", false, fmt.Sprintf("waiting for build %q to produce an output", name), nil
	}
	return src.Status.Build.Latest, true, "", nil
}

// latestBuild returns the newest published output's name.
func latestBuild(outputs []v1.BlipState) string {
	for i := len(outputs) - 1; i >= 0; i-- {
		if outputs[i].Annotations[v1.AnnotationBuildStatus] == buildSucceeded {
			return outputs[i].Name
		}
	}
	return ""
}

func buildCopyName(output string) string { return output + "-builder" }

// attemptBuilder names the builder copy of an attempt, or "" when the recipe
// builds in the output itself.
func attemptBuilder(st *v1.BlipState, output string) string {
	if st.Spec.Build.Builder == "" {
		return ""
	}
	return buildCopyName(output)
}

// userOrDefault and workingDirOrDefault make documented build defaults
// explicit, so a builder's runtime defaults cannot run the build as a
// different user or in a directory that does not exist yet.
func userOrDefault(user string) string {
	if user == "" {
		return "root"
	}
	return user
}

func workingDirOrDefault(dir string) string {
	if dir == "" {
		return "/"
	}
	return dir
}

func poolOrDefault(pool string) string {
	if pool == "" {
		return "default"
	}
	return pool
}

// lastStarted is when the attempt that produced output began. A recipe whose
// status was lost (for example a controller restart between creating the
// output and recording it) falls back to the output's creation time.
func lastStarted(st *v1.BlipState, output *v1.BlipState, now time.Time) *metav1.Time {
	if b := st.Status.Build; b != nil && b.LastBuild != nil {
		return b.LastBuild
	}
	if !output.CreationTimestamp.IsZero() {
		t := output.CreationTimestamp
		return &t
	}
	t := metav1.NewTime(now)
	return &t
}

func lastGeneration(st *v1.BlipState) int64 {
	if b := st.Status.Build; b != nil && b.ObservedGeneration != 0 {
		return b.ObservedGeneration
	}
	return st.Generation
}

func copyQuantity(q *resource.Quantity) *resource.Quantity {
	if q == nil {
		return nil
	}
	c := q.DeepCopy()
	return &c
}

func copyRuntime(r *v1.RuntimeDefaults) *v1.RuntimeDefaults {
	if r == nil {
		return nil
	}
	return r.DeepCopy()
}

func ownedBy(st *v1.BlipState) metav1.OwnerReference {
	yes := true
	return metav1.OwnerReference{
		APIVersion:         v1.GroupVersion.String(),
		Kind:               "BlipState",
		Name:               st.Name,
		UID:                st.UID,
		Controller:         &yes,
		BlockOwnerDeletion: &yes,
	}
}

func ownedByUID(refs []metav1.OwnerReference, uid types.UID) bool {
	for _, ref := range refs {
		if ref.UID == uid {
			return true
		}
	}
	return false
}
