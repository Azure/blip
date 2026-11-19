package blipchat

import (
	"context"
	"fmt"
	"strconv"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// Watcher turns observable blip state into turns: every accepted workload
// report, and the final phase of the blip. It deduplicates with deterministic
// turn names, so it may run on every reconcile.
//
// It intentionally runs on every replica: createTurnIn treats an
// AlreadyExists error with an identical spec as success, so concurrent
// watchers converge on one turn per report/phase instead of needing leader
// election. Only the sequencer is singular.
type Watcher struct {
	client.Client
}

func (w *Watcher) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var b v1.Blip
	if err := w.Get(ctx, req.NamespacedName, &b); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	thread := b.Annotations[v1.AnnotationThread]
	if thread == "" {
		thread = b.Labels[v1.LabelThread]
	}
	if thread == "" {
		return ctrl.Result{}, nil
	}
	owned, err := w.threadOwnedBy(ctx, &b, thread)
	if err != nil {
		return ctrl.Result{}, err
	}
	if !owned {
		return ctrl.Result{}, nil
	}
	task := b.Labels[v1.LabelTask]
	subjects := []v1.TurnSubject{{Kind: "Blip", Name: b.Name}}
	if task != "" {
		subjects = append(subjects, v1.TurnSubject{Kind: "Task", Name: task})
	}
	uid := string(b.UID)
	if uid == "" {
		uid = b.Name
	}
	if r := b.Status.Report; r != nil && r.Seq > 0 {
		attrs, summary := reportFields(r.Text)
		if attrs == nil {
			attrs = map[string]string{}
		}
		attrs["seq"] = strconv.FormatInt(r.Seq, 10)
		name := fmt.Sprintf("blip-%s-r%d", uid, r.Seq)
		if err := createTurnIn(ctx, w.Client, b.Namespace, name, turnSpec{
			Thread: thread, AuthorKind: v1.TurnAuthorBlip, AuthorName: b.Name,
			Topic: "blip.report", Text: summary, Attributes: attrs,
			Subjects: subjects, Wake: v1.WakeBatch,
		}); err != nil {
			return ctrl.Result{}, err
		}
	}
	if !v1.Finished(&b) {
		return ctrl.Result{}, nil
	}
	attrs := map[string]string{"phase": b.Status.Phase}
	if b.Status.ExitCode != nil {
		attrs["exitCode"] = strconv.Itoa(int(*b.Status.ExitCode))
	}
	if b.Status.StartTime != nil && b.Status.FinishTime != nil {
		attrs["durationSeconds"] = strconv.Itoa(int(b.Status.FinishTime.Sub(b.Status.StartTime.Time) / time.Second))
	}
	if b.Status.Message != "" {
		attrs["output"] = truncateRunes(b.Status.Message, 256)
	}
	if err := createTurnIn(ctx, w.Client, b.Namespace, "blip-"+uid+"-fin", turnSpec{
		Thread: thread, AuthorKind: v1.TurnAuthorBlip, AuthorName: b.Name,
		Topic: "blip.finished", Text: fmt.Sprintf("%s %s", b.Status.Phase, b.Status.Reason),
		Attributes: attrs, Subjects: subjects, Wake: v1.WakeBatch,
	}); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// threadOwnedBy reports whether thread exists and belongs to the Blip's
// owner. The thread label is self-asserted: a restricted VM may patch its own
// Blip, so appending its reports to that thread's history also requires the
// derived thread owner to match blip.dev/owner. A foreign, unknown, or
// ownerless label is ignored rather than allowed to inject turns into another
// project.
func (w *Watcher) threadOwnedBy(ctx context.Context, b *v1.Blip, thread string) (bool, error) {
	owner := b.Labels[v1.LabelOwner]
	if owner == "" || owner != v1.ThreadOwner(b.Namespace, thread) {
		log.FromContext(ctx).Info("ignoring blip report for a thread of another owner", "blip", b.Name, "thread", thread)
		return false, nil
	}
	var t v1.BlipThread
	if err := w.Get(ctx, client.ObjectKey{Namespace: b.Namespace, Name: thread}, &t); err != nil {
		if apierrors.IsNotFound(err) {
			log.FromContext(ctx).Info("ignoring blip report for a missing thread", "blip", b.Name, "thread", thread)
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// SetupWithManager registers the watcher for blips labelled with a thread.
func (w *Watcher) SetupWithManager(mgr ctrl.Manager) error {
	threaded := predicate.NewPredicateFuncs(func(o client.Object) bool {
		return o.GetLabels()[v1.LabelThread] != ""
	})
	return ctrl.NewControllerManagedBy(mgr).For(&v1.Blip{}).WithEventFilter(threaded).Complete(w)
}
