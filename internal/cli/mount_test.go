package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Azure/blip/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// mountTestApp has no controller: waits can only succeed from observed status,
// while offline commands must finish using the desired state alone.
func mountTestApp(t *testing.T, objects ...client.Object) *app {
	t.Helper()
	kube := fake.NewClientBuilder().WithScheme(Scheme).
		WithStatusSubresource(&v1alpha1.Blip{}, &v1alpha1.BlipState{}).
		WithObjects(objects...).Build()
	c := &Clients{Kube: kube, Namespace: ns}
	return &app{c: c, env: &Env{In: strings.NewReader(""), Out: io.Discard, Err: io.Discard,
		Connect: func(KubeFlags) (*Clients, error) { return c, nil },
	}}
}

func TestMountOfflineRootEdits(t *testing.T) {
	root, data := readyState("home"), readyState("data")
	// A busy source may still be part of declarative intent for next execution.
	data.Status.Writer = &v1alpha1.Writer{BlipName: "elsewhere", BlipUID: "other"}
	a := mountTestApp(t, root, data)
	var out bytes.Buffer
	a.env.Out = &out
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if code := Main(ctx, a.env, []string{"mount", "data:/data:rw", "--root", "home"}); code != 0 {
		t.Fatalf("mount returned %d", code)
	}
	s, err := a.getState(ctx, root.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Spec.Mounts) != 1 || s.Spec.Mounts[0] != (v1alpha1.Mount{State: "data", Path: "/data", Writable: true}) {
		t.Fatalf("desired mounts %+v", s.Spec.Mounts)
	}
	if !strings.Contains(out.String(), "next execution") {
		t.Fatalf("output %q", out.String())
	}
	// Source deletion must not prevent removing its desired mount.
	if err := a.c.Kube.Delete(ctx, data); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := Main(ctx, a.env, []string{"mount", "--rm", "data", "--root", "home"}); code != 0 {
		t.Fatalf("unmount returned %d", code)
	}
	s, _ = a.getState(ctx, root.Name)
	if len(s.Spec.Mounts) != 0 || !strings.Contains(out.String(), "next execution") {
		t.Fatalf("mounts %+v output %q", s.Spec.Mounts, out.String())
	}
}

func TestMountRejectsStaleOrAuxiliaryWriter(t *testing.T) {
	for _, mode := range []string{"reused name", "auxiliary writer", "finished", "stopping", "missing UID"} {
		t.Run(mode, func(t *testing.T) {
			b := runningBlip("writer")
			root := readyState("home")
			b.Spec.State = root.Name
			root.Status.Writer = &v1alpha1.Writer{BlipName: b.Name, BlipUID: string(b.UID)}
			switch mode {
			case "reused name":
				root.Status.Writer.BlipUID = "previous-execution"
			case "auxiliary writer":
				b.Spec.State = "another-root"
			case "finished":
				b.Status.Phase = v1alpha1.BlipSucceeded
			case "stopping":
				b.Spec.Stop = true
			case "missing UID":
				root.Status.Writer.BlipUID = ""
			}
			a := mountTestApp(t, b, root, readyState("data"))
			var out bytes.Buffer
			a.env.Out = &out
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := a.mountState(ctx, "data", "home", "/data", nil); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), "next execution") {
				t.Fatalf("waited on unrelated execution: %q", out.String())
			}
		})
	}
}

func TestMountIntentSurvivesRuntimeFailure(t *testing.T) {
	for _, op := range []string{"mount", "demote", "unmount"} {
		t.Run(op, func(t *testing.T) {
			b := runningBlip("writer")
			root := readyState(b.Spec.State)
			root.Status.Writer = &v1alpha1.Writer{BlipName: b.Name, BlipUID: string(b.UID)}
			if op != "mount" {
				root.Spec.Mounts = []v1alpha1.Mount{{State: "data", Path: "/data", Writable: true}}
			}
			b.Status.Mounts = []v1alpha1.MountStatus{{State: "data", Path: "/data", Writable: op != "mount", Phase: v1alpha1.MountFailed, Message: "target busy"}}
			a := mountTestApp(t, b, root, readyState("data"))
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
			defer cancel()
			var err error
			if op == "unmount" {
				err = a.unmountState(ctx, "data", root.Name)
			} else {
				readOnly := false
				err = a.mountState(ctx, "data", root.Name, "/data", &readOnly)
			}
			if err == nil {
				t.Fatal("runtime failure not reported")
			}
			s, err := a.getState(context.Background(), root.Name)
			if err != nil {
				t.Fatal(err)
			}
			if op == "unmount" {
				if len(s.Spec.Mounts) != 0 {
					t.Fatalf("removal rolled back: %+v", s.Spec.Mounts)
				}
			} else if len(s.Spec.Mounts) != 1 || s.Spec.Mounts[0].Writable {
				t.Fatalf("mount intent rolled back: %+v", s.Spec.Mounts)
			}
		})
	}
}

// TestMountUnusableSourceBeforeEdit reproduces a mount racing a source state
// deletion: a terminating state must be rejected before the root's desired
// mounts change, so the dead mount cannot poison later executions.
func TestMountUnusableSourceBeforeEdit(t *testing.T) {
	for _, tc := range []struct {
		name string
		prep func(*v1alpha1.BlipState)
		want string
	}{
		{
			name: "terminating",
			prep: func(s *v1alpha1.BlipState) {
				now := metav1.Now()
				s.DeletionTimestamp = &now
				s.Finalizers = []string{"hold"}
			},
			want: "is being deleted",
		},
		{
			name: "missing",
			want: `state "data" not found`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := readyState("home")
			root.Spec.Mounts = []v1alpha1.Mount{{State: "keep", Path: "/keep"}}
			objs := []client.Object{root}
			if tc.prep != nil {
				data := readyState("data")
				tc.prep(data)
				objs = append(objs, data)
			}
			a := mountTestApp(t, objs...)
			var errOut bytes.Buffer
			a.env.Err = &errOut
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if code := Main(ctx, a.env, []string{"mount", "data:/data", "--root", "home"}); code != 1 {
				t.Fatalf("mount code %d: %s", code, errOut.String())
			}
			mustContain(t, errOut.String(), tc.want)
			s, err := a.getState(ctx, root.Name)
			if err != nil {
				t.Fatal(err)
			}
			if len(s.Spec.Mounts) != 1 || s.Spec.Mounts[0].State != "keep" {
				t.Fatalf("unusable source changed desired mounts: %+v", s.Spec.Mounts)
			}
		})
	}
}

// TestMountSourceDeletedBeforeEditLeavesNoIntent reproduces a source state
// deleted after the preflight read but before the root's atomic edit. The edit
// must re-read the source, or the command leaves durable intent that every
// later execution fails to resolve.
func TestMountSourceDeletedBeforeEditLeavesNoIntent(t *testing.T) {
	for _, tc := range []struct {
		name    string
		replace bool
		want    string
	}{
		{"deleted", false, `state "data" not found`},
		{"replaced", true, `state "data" was replaced`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, data := readyState("home"), readyState("data")
			data.UID = "uid-old"
			a := mountTestApp(t, root, data)
			sourceReads := 0
			a.c.Kube = interceptor.NewClient(a.c.Kube, interceptor.Funcs{
				Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					if _, ok := obj.(*v1alpha1.BlipState); ok && key.Name == data.Name {
						sourceReads++
						if sourceReads == 3 {
							// mountSourceChanged's re-check races with a
							// deletion of the source.
							if err := c.Delete(ctx, data); err != nil {
								return err
							}
							if tc.replace {
								replacement := readyState("data")
								replacement.UID = "uid-new"
								if err := c.Create(ctx, replacement); err != nil {
									return err
								}
							}
						}
					}
					return c.Get(ctx, key, obj, opts...)
				},
			})
			var out, errOut bytes.Buffer
			a.env.Out, a.env.Err = &out, &errOut
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if code := Main(ctx, a.env, []string{"mount", "data:/data", "--root", "home"}); code != 1 {
				t.Fatalf("mount code %d: %s", code, errOut.String())
			}
			mustContain(t, errOut.String(), tc.want)
			s, err := a.getState(ctx, root.Name)
			if err != nil {
				t.Fatal(err)
			}
			if len(s.Spec.Mounts) != 0 {
				t.Fatalf("deleted source left desired intent: %+v", s.Spec.Mounts)
			}
			if strings.Contains(out.String(), "applied on next execution") {
				t.Fatalf("command claimed intent for a gone source: %s", out.String())
			}
		})
	}
}

func TestMountStateGone(t *testing.T) {
	for _, tc := range []struct{ name, msg, want string }{
		{
			name: "deleting",
			msg:  `mount data: state "data" is being deleted`,
			want: `mount data: state "data" is being deleted`,
		},
		{
			name: "missing",
			msg:  `mount data: state "data" not found`,
			want: `mount data: state "data" not found`,
		},
		{
			name: "joined waits pick the matching state",
			msg:  `mount other: state "other" not found; mount data: state "data" is being deleted`,
			want: `mount data: state "data" is being deleted`,
		},
		{
			name: "another state",
			msg:  `mount other: state "other" is being deleted`,
		},
		{
			name: "unrelated wait",
			msg:  `mount data: state "data" has no committed version yet`,
		},
		{
			name: "empty",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := mountStateGone(tc.msg, "data"); got != tc.want {
				t.Fatalf("mountStateGone(%q) = %q, want %q", tc.msg, got, tc.want)
			}
		})
	}
}

// TestMountGoneStateWhileWaitingRollsBackAndRetries covers the source
// disappearing after the desired mount was written: the wait must fail fast,
// remove only the mount this command added, and allow a retry once the source
// is usable again.
func TestMountGoneStateWhileWaitingRollsBackAndRetries(t *testing.T) {
	for _, tc := range []struct{ name, msg, want string }{
		{"terminating", `mount data: state "data" is being deleted`, "is being deleted"},
		{"missing", `mount data: state "data" not found`, `state "data" not found`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := runningBlip("writer")
			root := readyState(b.Spec.State)
			root.Status.Writer = &v1alpha1.Writer{BlipName: b.Name, BlipUID: string(b.UID)}
			root.Spec.Mounts = []v1alpha1.Mount{{State: "keep", Path: "/keep"}}
			b.Status.Mounts = nil
			b.Status.Message = tc.msg
			a := mountTestApp(t, b, root, readyState("data"))
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			start := time.Now()
			err := a.mountState(ctx, "data", root.Name, "/data", nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("mount returned %v, want %q", err, tc.want)
			}
			if elapsed := time.Since(start); elapsed > time.Second {
				t.Fatalf("mount took %s to fail: %v", elapsed, err)
			}
			if !strings.Contains(err.Error(), "desired mount was removed") {
				t.Fatalf("error does not report rollback: %v", err)
			}
			s, err := a.getState(ctx, root.Name)
			if err != nil {
				t.Fatal(err)
			}
			if len(s.Spec.Mounts) != 1 || s.Spec.Mounts[0].State != "keep" {
				t.Fatalf("failed mount left desired intent: %+v", s.Spec.Mounts)
			}

			// The rollback leaves the root usable. With no writer the retry
			// applies on the next execution, independent of an attachment.
			latest, err := a.getState(ctx, root.Name)
			if err != nil {
				t.Fatal(err)
			}
			latest.Status.Writer = nil
			if err := a.c.Kube.Status().Update(ctx, latest); err != nil {
				t.Fatal(err)
			}
			if err := a.mountState(ctx, "data", root.Name, "/data", nil); err != nil {
				t.Fatalf("retry after rollback failed: %v", err)
			}
			s, err = a.getState(ctx, root.Name)
			if err != nil {
				t.Fatal(err)
			}
			if len(s.Spec.Mounts) != 2 || findSpecMount(s.Spec.Mounts, "data") == nil {
				t.Fatalf("retry did not restore mount: %+v", s.Spec.Mounts)
			}
		})
	}
}

// TestWaitMountDeletionCauseBeatsStopped covers a writable mount whose source
// is deleted during the wait. The controller stops the writer with a
// StateNotFound message before the CLI sees a stopped Blip, so the deletion
// check must win over the generic "stopped" error; mountState then rolls back
// only the intent this command added.
func TestWaitMountDeletionCauseBeatsStopped(t *testing.T) {
	b := runningBlip("writer")
	root := readyState(b.Spec.State)
	root.Status.Writer = &v1alpha1.Writer{BlipName: b.Name, BlipUID: string(b.UID)}
	// The controller stops the writer and records why before the stopped
	// Blip is visible to the CLI. The deletion cause must win over the
	// generic stop error so waitMount returns a rollback-able error.
	b.Spec.Stop = true
	b.Status.Reason = "StateNotFound"
	b.Status.Message = `mount state "data" is being deleted; stopping before the workspace is removed`
	a := mountTestApp(t, b, root, readyState("data"))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := a.waitMount(ctx, b, "data", "/data", true, 0, "")
	if err == nil || !strings.Contains(err.Error(), "is being deleted") {
		t.Fatalf("waitMount returned %v, want the deletion cause", err)
	}
	var gone *mountStateGoneError
	if !errors.As(err, &gone) {
		t.Fatalf("waitMount returned %T, want a rollback-able deletion error", err)
	}
}

// TestMountGoneStateKeepsPreExistingMount makes sure the rollback removes only
// the mount this command added, not intent that another command owns.
func TestMountGoneStateKeepsPreExistingMount(t *testing.T) {
	b := runningBlip("writer")
	root := readyState(b.Spec.State)
	root.Status.Writer = &v1alpha1.Writer{BlipName: b.Name, BlipUID: string(b.UID)}
	root.Spec.Mounts = []v1alpha1.Mount{{State: "data", Path: "/data"}}
	b.Status.Mounts = nil
	b.Status.Message = `mount data: state "data" is being deleted`
	a := mountTestApp(t, b, root, readyState("data"))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := a.mountState(ctx, "data", root.Name, "/data", nil)
	if err == nil || !strings.Contains(err.Error(), "is being deleted") {
		t.Fatalf("mount returned %v", err)
	}
	s, err := a.getState(ctx, root.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Spec.Mounts) != 1 || s.Spec.Mounts[0].State != "data" {
		t.Fatalf("pre-existing mount was removed: %+v", s.Spec.Mounts)
	}
}

func TestMountGuestRootAndSharedImport(t *testing.T) {
	b := ownedBlip("alice.execution", "alice.workspace")
	root := readyState(b.Spec.State) // offline root edit; execution name differs
	base := readyState("base")
	base.Spec.Image = "registry/base:1"
	a := mountTestApp(t, b, root, base)
	a.env.NamespaceFile = filepath.Join(t.TempDir(), "namespace")
	if err := os.WriteFile(a.env.NamespaceFile, []byte(ns), 0o600); err != nil {
		t.Fatal(err)
	}
	a.env.Hostname = func() (string, error) { return b.Name, nil }
	var errOut bytes.Buffer
	a.env.Err = &errOut
	ctx := context.Background()
	if code := Main(ctx, a.env, []string{"mount", "base:/base"}); code != 0 {
		t.Fatalf("mount code %d: %s", code, errOut.String())
	}
	s, _ := a.getState(ctx, root.Name)
	if len(s.Spec.Mounts) != 1 || s.Spec.Mounts[0].State != "base" {
		t.Fatalf("mounts %+v", s.Spec.Mounts)
	}
	if code := Main(ctx, a.env, []string{"mount", "base:/base:rw"}); code != 1 || !strings.Contains(errOut.String(), "imported base") {
		t.Fatalf("writable imported base: %d %s", code, errOut.String())
	}
	if code := Main(ctx, a.env, []string{"mount", "--rm", "base"}); code != 0 {
		t.Fatalf("unmount: %d %s", code, errOut.String())
	}
	s, _ = a.getState(ctx, root.Name)
	if len(s.Spec.Mounts) != 0 {
		t.Fatalf("shared base not unmounted: %+v", s.Spec.Mounts)
	}
}

func TestMountedAttachmentCapturesUnmounting(t *testing.T) {
	b := runningBlip("writer")
	b.Status.Mounts = []v1alpha1.MountStatus{
		{State: "mounted", Path: "/mounted", Phase: v1alpha1.MountMounted, AttachmentID: "mounted-id"},
		{State: "unmounting", Path: "/unmounting", Phase: v1alpha1.MountUnmounting, AttachmentID: "unmounting-id"},
		{State: "saving", Path: "/saving", Phase: v1alpha1.MountSaving, AttachmentID: "saving-id"},
		{State: "failed", Path: "/failed", Phase: v1alpha1.MountFailed, AttachmentID: "failed-id"},
		{State: "pending", Path: "/pending", Phase: v1alpha1.MountPending, AttachmentID: "pending-id"},
		{State: "empty", Path: "/empty", Phase: v1alpha1.MountUnmounting},
	}
	for state, want := range map[string]string{
		"mounted":    "mounted-id",
		"unmounting": "unmounting-id",
		"saving":     "saving-id",
		"failed":     "failed-id",
		"pending":    "", // a new acquisition, not an old attachment
		"empty":      "",
		"missing":    "",
	} {
		if got := mountedAttachment(b, state); got != want {
			t.Errorf("%s: captured %q, want %q", state, got, want)
		}
	}
	if got := mountedAttachment(nil, "mounted"); got != "" {
		t.Errorf("nil blip: captured %q", got)
	}
}

// TestMountExistingMountedReturnsImmediately keeps re-running a mount that is
// already attached fast: only a re-added mount waits for a fresh attachment.
func TestMountExistingMountedReturnsImmediately(t *testing.T) {
	b := runningBlip("writer")
	root := readyState(b.Spec.State)
	root.Status.Writer = &v1alpha1.Writer{BlipName: b.Name, BlipUID: string(b.UID)}
	root.Spec.Mounts = []v1alpha1.Mount{{State: "data", Path: "/data"}}
	b.Status.Mounts = []v1alpha1.MountStatus{{
		State: "data", Path: "/data", Phase: v1alpha1.MountMounted, AttachmentID: "current-attachment",
	}}
	a := mountTestApp(t, b, root, readyState("data"))
	a.env.ProgressDelay = 0
	var progress bytes.Buffer
	a.env.Err = &progress
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if err := a.mountState(ctx, "data", root.Name, "/data", nil); err != nil {
		t.Fatalf("unchanged mount waited: %v (%s)", err, progress.String())
	}
	if strings.Contains(progress.String(), "detaching") {
		t.Fatalf("unchanged mount reported a detach wait: %s", progress.String())
	}
	s, err := a.getState(ctx, root.Name)
	if err != nil || len(s.Spec.Mounts) != 1 || s.Spec.Mounts[0] != (v1alpha1.Mount{State: "data", Path: "/data"}) {
		t.Fatalf("mounts changed: %+v %v", s, err)
	}
}

func TestWaitDetachedStopsForFreshOrReusedAttachment(t *testing.T) {
	b := runningBlip("writer")
	root := readyState(b.Spec.State)
	root.Status.Writer = &v1alpha1.Writer{BlipName: b.Name, BlipUID: string(b.UID)}
	b.Status.Mounts = []v1alpha1.MountStatus{{
		State: "data", Path: "/data", Phase: v1alpha1.MountMounted, AttachmentID: "new-attachment",
	}}
	a := mountTestApp(t, b, root)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Another collector's fresh attachment is not the stale one.
	if err := a.waitDetached(ctx, b, root.Name, "data", "old-attachment"); err != nil {
		t.Fatal(err)
	}

	// If desired intent reappeared while the old attachment is still
	// visible, the caller reuses it and must not wait for a detach.
	cur, err := a.getBlip(ctx, b.Name)
	if err != nil {
		t.Fatal(err)
	}
	cur.Status.Mounts[0].AttachmentID = "old-attachment"
	if err := a.c.Kube.Status().Update(ctx, cur); err != nil {
		t.Fatal(err)
	}
	s, err := a.getState(ctx, root.Name)
	if err != nil {
		t.Fatal(err)
	}
	s.Spec.Mounts = []v1alpha1.Mount{{State: "data", Path: "/data"}}
	if err := a.c.Kube.Update(ctx, s); err != nil {
		t.Fatal(err)
	}
	if err := a.waitDetached(ctx, cur, root.Name, "data", "old-attachment"); err != nil {
		t.Fatal(err)
	}
}

func TestMountBusy(t *testing.T) {
	for _, tc := range []struct {
		name, msg, state, want string
	}{
		{
			name:  "acquire rejection",
			msg:   `mount data: state "data" is in use by blip other`,
			state: "data",
			want:  `mount data: state "data" is in use by blip other`,
		},
		{
			name:  "promotion rejection",
			msg:   `state "data" is in use by blip other`,
			state: "data",
			want:  `state "data" is in use by blip other`,
		},
		{
			name:  "joined waits pick the matching state",
			msg:   `mount other: state "other" is in use by blip elsewhere; mount data: state "data" is in use by blip other`,
			state: "data",
			want:  `mount data: state "data" is in use by blip other`,
		},
		{
			name:  "another state's failure",
			msg:   `mount other: state "other" is in use by blip elsewhere`,
			state: "data",
		},
		{
			name:  "unrelated wait",
			msg:   `mount data: state "data" has no committed version yet`,
			state: "data",
		},
		{
			name:  "empty",
			state: "data",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := mountBusy(tc.msg, tc.state); got != tc.want {
				t.Fatalf("mountBusy(%q, %q) = %q, want %q", tc.msg, tc.state, got, tc.want)
			}
		})
	}
}

// TestMountWritableBusyStateFailsFast reproduces a writable root mount that
// the controller rejects because another Blip holds the source state's writer.
// The rejection is a top-level status message with no mount status entry;
// waiting for status.mounts would never finish.
func TestMountWritableBusyStateFailsFast(t *testing.T) {
	b := runningBlip("writer")
	data := readyState("data")
	data.Status.Writer = &v1alpha1.Writer{BlipName: "other", BlipUID: "uid-other"}
	data.Status.Phase = v1alpha1.StateInUse
	h := newHarness(t, b, data)
	h.ctrl.set(func(c *fakeController) { c.paused = true })

	cur := h.blip(b.Name)
	cur.Status.Mounts = nil
	cur.Status.Message = `mount data: state "data" is in use by blip other`
	if err := h.kube.Status().Update(context.Background(), cur); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	code, _, errOut := h.run("", "mount", "data:/data:rw", "--root", b.Spec.State)
	if code == 0 {
		t.Fatalf("busy writable mount succeeded: %s", errOut)
	}
	mustContain(t, errOut, `"data"`, "is in use by blip", "other")
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("busy writable mount took %s to fail: %s", elapsed, errOut)
	}
}

// TestMountWritableUnrelatedMessageKeepsWaiting keeps top-level messages that
// do not describe this mount's state out of the fail-fast path.
func TestMountWritableUnrelatedMessageKeepsWaiting(t *testing.T) {
	b := runningBlip("writer")
	h := newHarness(t, b, readyState("data"))
	h.ctrl.set(func(c *fakeController) { c.paused = true })

	cur := h.blip(b.Name)
	cur.Status.Mounts = nil
	cur.Status.Message = `mount other: state "other" is in use by blip elsewhere; mount data: state "data" has no committed version yet`
	if err := h.kube.Status().Update(context.Background(), cur); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	env := h.env(strings.NewReader(""), &out, &errOut)
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	start := time.Now()
	code := Main(ctx, env, []string{"mount", "data:/data:rw", "--root", b.Spec.State})
	if code == 0 {
		t.Fatal("mount succeeded")
	}
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Fatalf("mount returned after %s instead of waiting: %s", elapsed, errOut.String())
	}
	if strings.Contains(errOut.String(), "in use by blip") {
		t.Fatalf("unrelated status message treated as busy: %s", errOut.String())
	}
}

// TestMountPromotionRefusalFailsFast reproduces a promotion the controller
// refuses: a stale read-only mount or a state whose writer is held by another
// Blip. The refusal is reported on the still-mounted read-only entry with
// Switching=false, so the wait must treat it as final and restore the desired
// mode instead of polling forever for a switch that will never start.
func TestMountPromotionRefusalFailsFast(t *testing.T) {
	for _, tc := range []struct{ name, msg string }{
		{"newer version", `cannot switch to writable: state "data" has a newer version; unmount and mount it again`},
		{"writer busy", `cannot switch to writable: state "data" is in use by blip other`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := runningBlip("writer")
			root := readyState(b.Spec.State)
			root.Status.Writer = &v1alpha1.Writer{BlipName: b.Name, BlipUID: string(b.UID)}
			root.Spec.Mounts = []v1alpha1.Mount{{State: "data", Path: "/data"}}
			b.Status.Mounts = []v1alpha1.MountStatus{{
				State: "data", Path: "/data", Phase: v1alpha1.MountMounted, AttachmentID: "attachment",
			}}
			a := mountTestApp(t, b, root, readyState("data"))
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			writable := true
			done := make(chan error, 1)
			go func() { done <- a.mountState(ctx, "data", root.Name, "/data", &writable) }()
			waitForCond(t, func() bool {
				s, err := a.getState(ctx, root.Name)
				return err == nil && len(s.Spec.Mounts) == 1 && s.Spec.Mounts[0].Writable
			})

			cur, err := a.getBlip(ctx, b.Name)
			if err != nil {
				t.Fatal(err)
			}
			cur.Status.Mounts = []v1alpha1.MountStatus{{
				State: "data", Path: "/data", Phase: v1alpha1.MountMounted, AttachmentID: "attachment", Message: tc.msg,
			}}
			if err := a.c.Kube.Status().Update(ctx, cur); err != nil {
				t.Fatal(err)
			}

			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), "cannot switch to writable") {
					t.Fatalf("refused promotion returned %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("refused promotion kept waiting")
			}
			s, err := a.getState(ctx, root.Name)
			if err != nil {
				t.Fatal(err)
			}
			if len(s.Spec.Mounts) != 1 || s.Spec.Mounts[0].Writable {
				t.Fatalf("desired mode not restored: %+v", s.Spec.Mounts)
			}
		})
	}
}

// TestWaitMountKeepsWaitingForTransientPromotionMessage makes sure the retrying
// "waiting to switch" message is not mistaken for a final refusal.
func TestWaitMountKeepsWaitingForTransientPromotionMessage(t *testing.T) {
	b := runningBlip("writer")
	root := readyState(b.Spec.State)
	root.Status.Writer = &v1alpha1.Writer{BlipName: b.Name, BlipUID: string(b.UID)}
	root.Spec.Mounts = []v1alpha1.Mount{{State: "data", Path: "/data", Writable: true}}
	b.Status.Mounts = []v1alpha1.MountStatus{{
		State: "data", Path: "/data", Phase: v1alpha1.MountMounted, AttachmentID: "attachment",
		Message: `waiting to switch to writable: state "data" is saving a new version`,
	}}
	a := mountTestApp(t, b, root)
	a.env.ProgressDelay = 0
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.waitMount(ctx, b, "data", "/data", true, 0, "") }()
	select {
	case err := <-done:
		t.Fatalf("transient promotion message treated as final: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
}

// TestWaitMountIgnoresRevivedAttachment reproduces the back-to-back collect
// race: the pre-add status is Unmounting with the old attachment, and the
// controller revives that same attachment to Mounted after the spec returns.
// The revived entry must not satisfy the wait; only a different attachment
// may.
func TestWaitMountIgnoresRevivedAttachment(t *testing.T) {
	b := runningBlip("writer")
	root := readyState(b.Spec.State)
	root.Status.Writer = &v1alpha1.Writer{BlipName: b.Name, BlipUID: string(b.UID)}
	root.Spec.Mounts = []v1alpha1.Mount{{State: "data", Path: "/data"}}
	b.Status.Mounts = []v1alpha1.MountStatus{{
		State: "data", Path: "/data", Phase: v1alpha1.MountUnmounting, AttachmentID: "old-attachment",
	}}
	a := mountTestApp(t, b, root)
	a.env.ProgressDelay = 0
	progress := make(chan string, 16)
	a.env.Err = writerFunc(func(p []byte) (int, error) {
		select {
		case progress <- string(p):
		default:
		}
		return len(p), nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	old := mountedAttachment(b, "data")
	if old != "old-attachment" {
		t.Fatalf("pre-add attachment %q", old)
	}
	setStatus := func(phase, attachment string) {
		t.Helper()
		var cur v1alpha1.Blip
		if err := a.c.Kube.Get(ctx, client.ObjectKey{Namespace: ns, Name: b.Name}, &cur); err != nil {
			t.Fatal(err)
		}
		cur.Status.Mounts = []v1alpha1.MountStatus{{State: "data", Path: "/data", Phase: phase, AttachmentID: attachment}}
		if err := a.c.Kube.Status().Update(ctx, &cur); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan error, 1)
	go func() { done <- a.waitMount(ctx, b, "data", "/data", false, 0, old) }()
	select {
	case err := <-done:
		t.Fatalf("waitMount returned while the old attachment was unmounting: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	// The controller revives the old attachment: same ID, phase Mounted.
	setStatus(v1alpha1.MountMounted, old)
	waiting := false
	for !waiting {
		select {
		case err := <-done:
			t.Fatalf("waitMount accepted the revived attachment: %v", err)
		case msg := <-progress:
			waiting = strings.Contains(msg, "finish detaching")
		case <-time.After(2 * time.Second):
			t.Fatal("waitMount did not report waiting for a fresh attachment")
		}
	}
	select {
	case err := <-done:
		t.Fatalf("waitMount accepted the revived attachment: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	// Only a different attachment is fresh.
	setStatus(v1alpha1.MountMounted, "new-attachment")
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("waitMount failed after a fresh attachment: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waitMount did not accept the fresh attachment")
	}
}

// TestUnmountWritableEndsWhenWriterFinishes reproduces mount --rm of a
// writable mount whose writer Blip finishes while the removed mount is saving.
// The stale status entry must not keep the command polling after the Blip is
// terminal; a failed save on the finished Blip must still be reported.
func TestUnmountWritableEndsWhenWriterFinishes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		phase   string
		message string
		wantErr bool
	}{
		{name: "saved entry remains mounted", phase: v1alpha1.MountMounted},
		{name: "save failed", phase: v1alpha1.MountFailed, message: "save failed: node is gone", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := runningBlip("writer")
			root := readyState(b.Spec.State)
			root.Status.Writer = &v1alpha1.Writer{BlipName: b.Name, BlipUID: string(b.UID)}
			root.Spec.Mounts = []v1alpha1.Mount{{State: "data", Path: "/data", Writable: true}}
			b.Status.Mounts = []v1alpha1.MountStatus{{
				State: "data", Path: "/data", Writable: true, Phase: v1alpha1.MountMounted, AttachmentID: "attachment",
			}}
			a := mountTestApp(t, b, root)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			done := make(chan error, 1)
			go func() { done <- a.unmountState(ctx, "data", root.Name) }()
			waitForCond(t, func() bool {
				s, err := a.getState(ctx, root.Name)
				return err == nil && len(s.Spec.Mounts) == 0
			})

			setPhase := func(phase string) {
				t.Helper()
				cur, err := a.getBlip(ctx, b.Name)
				if err != nil {
					t.Fatal(err)
				}
				cur.Status.Phase = phase
				if err := a.c.Kube.Status().Update(ctx, cur); err != nil {
					t.Fatal(err)
				}
			}
			// The writer stops; the controller fences the VM and saves.
			cur, err := a.getBlip(ctx, b.Name)
			if err != nil {
				t.Fatal(err)
			}
			cur.Spec.Stop = true
			if err := a.c.Kube.Update(ctx, cur); err != nil {
				t.Fatal(err)
			}
			setPhase(v1alpha1.BlipSaving)
			select {
			case err := <-done:
				t.Fatalf("unmount returned while the save was still running: %v", err)
			case <-time.After(50 * time.Millisecond):
			}

			// The finished Blip may still show the removed entry.
			cur, err = a.getBlip(ctx, b.Name)
			if err != nil {
				t.Fatal(err)
			}
			cur.Status.Phase = v1alpha1.BlipSucceeded
			cur.Status.Mounts[0].Phase = tc.phase
			cur.Status.Mounts[0].Message = tc.message
			if err := a.c.Kube.Status().Update(ctx, cur); err != nil {
				t.Fatal(err)
			}

			select {
			case err := <-done:
				if tc.wantErr {
					if err == nil || !strings.Contains(err.Error(), tc.message) {
						t.Fatalf("finished save failure returned %v", err)
					}
				} else if err != nil {
					t.Fatalf("finished writer did not complete the removal: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("unmount kept waiting after the writer finished")
			}
		})
	}
}

// TestWaitMountSkipsGenerationWaitWithoutDemotion reproduces the concurrent
// ro+rw race: mountState sees the transient writable spec and arms the save
// wait, but the controller only ever saw the final read-only spec, so no save
// will happen. The wait must finish once the mount is stably read-only at the
// committed version.
func TestWaitMountSkipsGenerationWaitWithoutDemotion(t *testing.T) {
	b := runningBlip("writer")
	root := readyState(b.Spec.State)
	root.Status.Writer = &v1alpha1.Writer{BlipName: b.Name, BlipUID: string(b.UID)}
	root.Spec.Mounts = []v1alpha1.Mount{{State: "data", Path: "/data"}}
	data := readyState("data")
	b.Status.Mounts = []v1alpha1.MountStatus{{
		State: "data", Path: "/data", Phase: v1alpha1.MountMounted, CommitID: data.Status.Committed.ID,
	}}
	a := mountTestApp(t, b, root, data)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- a.waitMount(ctx, b, "data", "/data", false, data.Status.Committed.Generation, "") }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("waitMount failed without a demotion: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("waitMount waited for a save that never started")
	}
}

// TestWaitMountWaitsForDemotedCommit keeps the generation wait for a demotion
// the controller actually performed.
func TestWaitMountWaitsForDemotedCommit(t *testing.T) {
	b := runningBlip("writer")
	root := readyState(b.Spec.State)
	root.Status.Writer = &v1alpha1.Writer{BlipName: b.Name, BlipUID: string(b.UID)}
	root.Spec.Mounts = []v1alpha1.Mount{{State: "data", Path: "/data"}}
	data := readyState("data")
	b.Status.Mounts = []v1alpha1.MountStatus{{
		State: "data", Path: "/data", Writable: true, Phase: v1alpha1.MountMounted, CommitID: data.Status.Committed.ID,
	}}
	a := mountTestApp(t, b, root, data)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- a.waitMount(ctx, b, "data", "/data", false, data.Status.Committed.Generation, "") }()
	select {
	case err := <-done:
		t.Fatalf("waitMount accepted a writable mount for a read-only request: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	// The controller tears the writable mount down and brings it back
	// read-only at the saved version, before the committed version moves.
	const saved = "fedcba9876543210"
	cur, err := a.getBlip(ctx, b.Name)
	if err != nil {
		t.Fatal(err)
	}
	cur.Status.Mounts = []v1alpha1.MountStatus{{
		State: "data", Path: "/data", Phase: v1alpha1.MountMounted, CommitID: saved,
	}}
	if err := a.c.Kube.Status().Update(ctx, cur); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		t.Fatalf("waitMount finished before the saved version committed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	st, err := a.getState(ctx, data.Name)
	if err != nil {
		t.Fatal(err)
	}
	st.Status.Committed = &v1alpha1.Commit{ID: saved, Generation: data.Status.Committed.Generation + 1}
	if err := a.c.Kube.Status().Update(ctx, st); err != nil {
		t.Fatal(err)
	}
	// waitMount watches the Blip; an unrelated status change triggers the
	// check that observes the state's new committed generation.
	cur, err = a.getBlip(ctx, b.Name)
	if err != nil {
		t.Fatal(err)
	}
	cur.Status.Sessions++
	if err := a.c.Kube.Status().Update(ctx, cur); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("waitMount failed after the save committed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("waitMount did not finish after the save committed")
	}
}

// TestWaitMountFinishesWhenPromotionCancelled reproduces a read-only request
// racing a promotion to writable. The controller cancels the promotion without
// saving: the mount is read-only at the committed version, so the wait must
// finish instead of waiting for a generation that will never advance. The
// transient entry may be a switch in progress, or a writable mount that never
// attached and was dropped.
func TestWaitMountFinishesWhenPromotionCancelled(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status v1alpha1.MountStatus
	}{
		{
			name: "switch in progress",
			status: v1alpha1.MountStatus{
				Phase: v1alpha1.MountMounted, Switching: true,
			},
		},
		{
			name: "writable mount never attached",
			status: v1alpha1.MountStatus{
				Phase: v1alpha1.MountPending, Writable: true,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := runningBlip("writer")
			root := readyState(b.Spec.State)
			root.Status.Writer = &v1alpha1.Writer{BlipName: b.Name, BlipUID: string(b.UID)}
			root.Spec.Mounts = []v1alpha1.Mount{{State: "data", Path: "/data"}}
			data := readyState("data")
			transient := tc.status
			transient.State, transient.Path = "data", "/data"
			transient.CommitID = data.Status.Committed.ID
			b.Status.Mounts = []v1alpha1.MountStatus{transient}
			a := mountTestApp(t, b, root, data)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			done := make(chan error, 1)
			go func() {
				done <- a.waitMount(ctx, b, "data", "/data", false, data.Status.Committed.Generation, "")
			}()

			// The controller cancels the promotion. The mount is read-only
			// again at the same committed version, so no save will land.
			cur, err := a.getBlip(ctx, b.Name)
			if err != nil {
				t.Fatal(err)
			}
			cur.Status.Mounts = []v1alpha1.MountStatus{{
				State: "data", Path: "/data", Phase: v1alpha1.MountMounted, CommitID: data.Status.Committed.ID,
			}}
			if err := a.c.Kube.Status().Update(ctx, cur); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("waitMount failed after the cancelled promotion: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("waitMount waited for a save that cannot happen after the promotion was cancelled")
			}
		})
	}
}

func TestMountListsRootMounts(t *testing.T) {
	root := readyState("home")
	root.Spec.Mounts = []v1alpha1.Mount{
		{State: "data", Path: "/data"},
		{State: "work", Path: "/work", Writable: true},
		{State: "temporary", Path: "/temporary", BlipUID: "old-execution"},
	}
	h := newHarness(t, root, readyState("empty"))
	code, out, errOut := h.run("", "mount", "--root", "home")
	if code != 0 {
		t.Fatalf("list code %d: %s", code, errOut)
	}
	mustContain(t, out, "data:/data (read-only)", "work:/work (writable)")
	if strings.Contains(out, "temporary") {
		t.Fatalf("temporary collect mount listed: %q", out)
	}

	code, out, errOut = h.run("", "mount", "--root", "empty")
	if code != 0 {
		t.Fatalf("empty list code %d: %s", code, errOut)
	}
	mustContain(t, out, "state empty has no mounts")

	// A running root also shows each attachment's phase.
	running := newHarness(t, runningBlip("agent", v1alpha1.Mount{State: "repo", Path: "/work"}))
	code, out, errOut = running.run("", "mount", "--root", "agent-root")
	if code != 0 {
		t.Fatalf("attached list code %d: %s", code, errOut)
	}
	mustContain(t, out, "repo:/work (read-only) Mounted")
}

func TestMountNewCreatesAndMountsEmptyState(t *testing.T) {
	h := newHarness(t, readyState("home"))
	code, out, errOut := h.run("", "mount", "--new", "cache:/cache", "--root", "home")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "state cache mounted on root state home at /cache (writable)", "next execution")
	s := h.state("cache")
	if s.Spec.Image != "" || s.Spec.CopyFrom != "" || s.Spec.Size != nil || s.Spec.Replicas != 0 {
		t.Fatalf("unexpected spec %+v", s.Spec)
	}
	if s.Status.Committed == nil {
		t.Fatal("state has no first commit")
	}
	root := h.state("home")
	if len(root.Spec.Mounts) != 1 || root.Spec.Mounts[0] != (v1alpha1.Mount{State: "cache", Path: "/cache", Writable: true}) {
		t.Fatalf("mounts %+v", root.Spec.Mounts)
	}
}

func TestMountNewFromWithSize(t *testing.T) {
	h := newHarness(t, readyState("home"), readyState("base"))
	code, out, errOut := h.run("", "mount", "--new", "dev:/work", "--from", "base", "--size", "20Gi", "--root", "home")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "state dev mounted on root state home at /work (writable)")
	s := h.state("dev")
	if s.Spec.CopyFrom != "base" || s.Spec.Size == nil || s.Spec.Size.String() != "20Gi" || s.Spec.Replicas != 0 {
		t.Fatalf("state %+v", s.Spec)
	}
	if s.Status.Committed == nil {
		t.Fatal("copied state has no first commit")
	}
	if root := h.state("home"); len(root.Spec.Mounts) != 1 || root.Spec.Mounts[0].State != "dev" || !root.Spec.Mounts[0].Writable {
		t.Fatalf("mounts %+v", root.Spec.Mounts)
	}
}

func TestMountNewReadOnly(t *testing.T) {
	h := newHarness(t, readyState("home"))
	code, out, errOut := h.run("", "mount", "--new", "cache:/cache:ro", "--root", "home")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "state cache mounted on root state home at /cache (read-only)")
	root := h.state("home")
	if len(root.Spec.Mounts) != 1 || root.Spec.Mounts[0] != (v1alpha1.Mount{State: "cache", Path: "/cache"}) {
		t.Fatalf("mounts %+v", root.Spec.Mounts)
	}
}

// TestMountRemoveFreesPathInSameCommand reproduces a combined move or
// replacement that is legal after the requested removals: mounting a state
// at the path freed by --rm must validate against the final topology instead
// of rejecting the path that this same invocation is about to free.
func TestMountRemoveFreesPathInSameCommand(t *testing.T) {
	t.Run("move existing mount", func(t *testing.T) {
		root := readyState("home")
		root.Spec.Mounts = []v1alpha1.Mount{
			{State: "a", Path: "/a"},
			{State: "b", Path: "/b"},
		}
		h := newHarness(t, root, readyState("a"), readyState("b"))
		code, out, errOut := h.run("", "mount", "a:/b", "--rm", "b", "--root", "home")
		if code != 0 {
			t.Fatalf("code %d: %s", code, errOut)
		}
		mustContain(t, out, "state a mounted on root state home at /b")
		mounts := h.state("home").Spec.Mounts
		if len(mounts) != 1 || mounts[0].State != "a" || mounts[0].Path != "/b" {
			t.Fatalf("final mounts %+v, want only a at /b", mounts)
		}
	})

	t.Run("replace with new state", func(t *testing.T) {
		root := readyState("home")
		root.Spec.Mounts = []v1alpha1.Mount{{State: "b", Path: "/b"}}
		h := newHarness(t, root, readyState("a"), readyState("b"))
		code, out, errOut := h.run("", "mount", "--new", "d:/b", "--rm", "b", "--root", "home")
		if code != 0 {
			t.Fatalf("code %d: %s", code, errOut)
		}
		mustContain(t, out, "state d mounted on root state home at /b")
		mounts := h.state("home").Spec.Mounts
		if len(mounts) != 1 || mounts[0].State != "d" || mounts[0].Path != "/b" {
			t.Fatalf("final mounts %+v, want only d at /b", mounts)
		}
		if s := h.state("d"); s.Status.Committed == nil {
			t.Fatal("new state has no commit")
		}
	})
}

// TestMountRejectsTerminatingRoot reproduces a root state that is being
// deleted: no mount can ever run there, so the command must reject before
// writing intent or creating and committing a --new state.
func TestMountRejectsTerminatingRoot(t *testing.T) {
	newRoot := func() *v1alpha1.BlipState {
		root := readyState("home")
		now := metav1.Now()
		root.Finalizers = []string{"test"}
		root.DeletionTimestamp = &now
		return root
	}
	t.Run("add", func(t *testing.T) {
		h := newHarness(t, newRoot(), readyState("data"), readyState("base"))
		for _, arg := range []string{"data:/data", "base:/y:ro"} {
			code, _, errOut := h.run("", "mount", arg, "--root", "home")
			if code != 1 || !strings.Contains(errOut, `state "home" is being deleted`) {
				t.Fatalf("mount %s: code %d: %s", arg, code, errOut)
			}
			if mounts := h.state("home").Spec.Mounts; len(mounts) != 0 {
				t.Fatalf("mount %s left desired intent: %+v", arg, mounts)
			}
		}
	})
	t.Run("new", func(t *testing.T) {
		h := newHarness(t, newRoot(), readyState("base"))
		code, _, errOut := h.run("", "mount", "--new", "leak:/t4:rw", "--root", "home")
		if code != 1 || !strings.Contains(errOut, `state "home" is being deleted`) {
			t.Fatalf("--new code %d: %s", code, errOut)
		}
		if !stateNotFound(t, h, "leak") {
			t.Fatal("terminating root left the new state behind")
		}
	})
	t.Run("remove still allowed but reports deletion", func(t *testing.T) {
		root := newRoot()
		root.Spec.Mounts = []v1alpha1.Mount{{State: "data", Path: "/data"}}
		h := newHarness(t, root, readyState("data"))
		code, _, errOut := h.run("", "mount", "--rm", "data", "--root", "home")
		if code != 1 || !strings.Contains(errOut, `state "home" is being deleted`) {
			t.Fatalf("--rm code %d: %s", code, errOut)
		}
		if strings.Contains(errOut, "applied on next execution") {
			t.Fatalf("--rm promised a next execution on a terminating root: %s", errOut)
		}
		if mounts := h.state("home").Spec.Mounts; len(mounts) != 0 {
			t.Fatalf("--rm left desired intent: %+v", mounts)
		}
	})
}

func TestMountRejectsDuplicateMounts(t *testing.T) {
	t.Run("duplicate state", func(t *testing.T) {
		h := newHarness(t, readyState("home"), readyState("data"))
		code, _, errOut := h.run("", "mount", "data:/a", "data:/b", "--root", "home")
		if code != 1 || !strings.Contains(errOut, `state "data" is already mounted on root state "home" at /a`) {
			t.Fatalf("code %d: %s", code, errOut)
		}
	})
	t.Run("duplicate path", func(t *testing.T) {
		h := newHarness(t, readyState("home"), readyState("data"), readyState("other"))
		code, _, errOut := h.run("", "mount", "data:/a", "other:/a", "--root", "home")
		if code != 1 || !strings.Contains(errOut, `root state "home" already has state "data" mounted at /a`) {
			t.Fatalf("code %d: %s", code, errOut)
		}
	})
}

// TestMountRejectsAliasDuplicateMounts reproduces /bin/x and /usr/bin/x (and
// the mail spool alias) being accepted as disjoint even though the guest
// resolves both to one directory and stacks the filesystems there.
func TestMountRejectsAliasDuplicateMounts(t *testing.T) {
	for _, tc := range []struct {
		name, existing, added string
	}{
		{"bin", "/bin/x", "/usr/bin/x"},
		{"sbin", "/sbin/x", "/usr/sbin/x"},
		{"mail spool", "/var/spool/mail/x", "/var/mail/x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := readyState("home")
			root.Spec.Mounts = []v1alpha1.Mount{{State: "m2", Path: tc.existing}}
			h := newHarness(t, root, readyState("m2"), readyState("data"))
			code, _, errOut := h.run("", "mount", "data:"+tc.added, "--root", "home")
			if code != 1 || !strings.Contains(errOut, `root state "home" already has state "m2" mounted at `+tc.existing) {
				t.Fatalf("code %d: %s", code, errOut)
			}
			if mounts := h.state("home").Spec.Mounts; len(mounts) != 1 || mounts[0].Path != tc.existing {
				t.Fatalf("rejected alias changed mounts: %+v", mounts)
			}
		})
	}

	// The final topology of one invocation is checked too, not only entries
	// already in the root.
	h := newHarness(t, readyState("home"), readyState("a"), readyState("b"))
	code, _, errOut := h.run("", "mount", "a:/bin/x", "b:/usr/bin/x", "--root", "home")
	if code != 1 || !strings.Contains(errOut, "already has state") {
		t.Fatalf("batch code %d: %s", code, errOut)
	}
	if mounts := h.state("home").Spec.Mounts; len(mounts) != 0 {
		t.Fatalf("partially applied alias batch: %+v", mounts)
	}
}

func TestMountValidationErrors(t *testing.T) {
	h := newHarness(t, readyState("home"), readyState("data"))
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"root required", []string{"mount", "data:/data"}, "--root is required outside a blip"},
		{"missing path", []string{"mount", "data", "--root", "home"}, `invalid mount "data"`},
		{"relative path", []string{"mount", "data:work", "--root", "home"}, `invalid mount "data:work"`},
		{"unclean path", []string{"mount", "data:/a/../b", "--root", "home"}, `invalid mount "data:/a/../b"`},
		{"root path", []string{"mount", "data:/", "--root", "home"}, `invalid mount "data:/"`},
		{"relative path with mode", []string{"mount", "data:work:rw", "--root", "home"}, `invalid mount "data:work:rw"`},
		{"self mount", []string{"mount", "home:/data", "--root", "home"}, "a root state cannot mount itself"},
		{"bad size", []string{"mount", "--new", "x:/data", "--size", "nope", "--root", "home"}, "invalid --size"},
		{"zero size", []string{"mount", "--new", "x:/data", "--size", "0", "--root", "home"}, "must be positive"},
		{"huge size", []string{"mount", "--new", "x:/data", "--size", "10Ei", "--root", "home"}, "too large"},
		{"max int64 size", []string{"mount", "--new", "x:/data", "--size", "9223372036854775807", "--root", "home"}, "too large"},
		{"missing source", []string{"mount", "--new", "x:/data", "--from", "missing", "--root", "home"}, `state "missing" not found`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, errOut := h.run("", tc.args...)
			if code != 1 || !strings.Contains(errOut, tc.want) {
				t.Fatalf("code %d: %s", code, errOut)
			}
		})
	}
}

// TestMountRequiresNewForStateSettings reproduces --size, --replicas and
// --from being accepted and silently discarded on a mount that creates no
// state. They only configure --new, so using them without it is a usage error.
func TestMountRequiresNewForStateSettings(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		flag string
	}{
		{"size", []string{"mount", "data:/data", "--size", "1Gi", "--root", "home"}, "--size"},
		{"replicas", []string{"mount", "data:/data", "--replicas", "2", "--root", "home"}, "--replicas"},
		{"from", []string{"mount", "data:/data", "--from", "base", "--root", "home"}, "--from"},
		{"list", []string{"mount", "--size", "1Gi", "--root", "home"}, "--size"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, readyState("home"), readyState("data"), readyState("base"))
			code, _, errOut := h.run("", tc.args...)
			if code != 1 || !strings.Contains(errOut, tc.flag) || !strings.Contains(errOut, "--new") {
				t.Fatalf("code %d: %s", code, errOut)
			}
			if mounts := h.state("home").Spec.Mounts; len(mounts) != 0 {
				t.Fatalf("discarded flags still changed mounts: %+v", mounts)
			}
		})
	}

	// The same flags remain valid with --new.
	h := newHarness(t, readyState("home"), readyState("base"))
	if code, _, errOut := h.run("", "mount", "--new", "dev:/work", "--from", "base", "--size", "1Gi", "--replicas", "2", "--root", "home"); code != 0 {
		t.Fatalf("--new with state settings rejected: %d %s", code, errOut)
	}
}

// TestMountNewFromWithReplicasAndOwner ports the old create from-owned-state
// coverage: --from and --replicas still configure the new state, and a guest's
// owner label follows it into the cluster.
func TestMountNewFromWithReplicasAndOwner(t *testing.T) {
	h := newHarness(t, ownedBlip("alice.box", "alice.home"), readyState("alice.base"))
	h.self = "alice.box"
	code, out, errOut := h.run("", "mount", "--new", "repo:/data", "--from", "base", "--replicas", "2")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "state repo mounted on blip box at /data (writable)")
	s := h.state("alice.repo")
	if s.Spec.CopyFrom != "alice.base" || s.Spec.Replicas != 2 || s.Labels[v1alpha1.LabelOwner] != "alice" {
		t.Fatalf("state %+v labels %v", s.Spec, s.Labels)
	}
	root := h.state("alice.home")
	if len(root.Spec.Mounts) != 1 || root.Spec.Mounts[0] != (v1alpha1.Mount{State: "alice.repo", Path: "/data", Writable: true}) {
		t.Fatalf("root mounts %+v", root.Spec.Mounts)
	}
}

func TestMountNewRejectsExisting(t *testing.T) {
	h := newHarness(t, readyState("home"), readyState("taken"))
	code, _, errOut := h.run("", "mount", "--new", "taken:/data", "--root", "home")
	if code != 1 || !strings.Contains(errOut, `state "taken" already exists`) {
		t.Fatalf("code %d: %s", code, errOut)
	}
}

// TestMountNewRejectsDuplicateArguments reproduces repeated --new entries:
// validateMountPlan treats an identical repeat as an idempotent update, but
// execution still creates the state once per entry, so the command applies the
// first mount and then fails with "already exists". Duplicates must be rejected
// in the preflight, leaving no state or mount intent behind.
func TestMountNewRejectsDuplicateArguments(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "identical state and destination",
			args: []string{"--new", "dup:/d", "--new", "dup:/d"},
			want: []string{`--new state "dup"`, "more than once"},
		},
		{
			name: "same state at another path",
			args: []string{"--new", "dup:/a", "--new", "dup:/b"},
			want: []string{`--new state "dup"`, "more than once"},
		},
		{
			name: "same destination",
			args: []string{"--new", "a:/same", "--new", "b:/same"},
			want: []string{`--new state "b"`, "same destination", `state "a"`},
		},
		{
			name: "aliased destination",
			args: []string{"--new", "a:/bin/x", "--new", "b:/usr/bin/x"},
			want: []string{`--new state "b"`, "same destination", `state "a"`},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, readyState("home"))
			args := append([]string{"mount"}, tc.args...)
			args = append(args, "--root", "home")
			code, _, errOut := h.run("", args...)
			if code != 1 {
				t.Fatalf("code %d: %s", code, errOut)
			}
			mustContain(t, errOut, tc.want...)
			for _, name := range []string{"dup", "a", "b"} {
				if !stateNotFound(t, h, name) {
					t.Fatalf("rejected --new left state %q behind", name)
				}
			}
			if mounts := h.state("home").Spec.Mounts; len(mounts) != 0 {
				t.Fatalf("rejected --new wrote desired intent: %+v", mounts)
			}
		})
	}
}

func stateNotFound(t *testing.T, h *harness, name string) bool {
	t.Helper()
	var s v1alpha1.BlipState
	err := h.kube.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: name}, &s)
	return apierrors.IsNotFound(err)
}

// TestMountNewDoesNotLeakStateOnPathConflict reproduces a root that already
// has /shared mounted: --new must reject before creating the state, and a retry
// with the same name at a free path must succeed.
func TestMountNewDoesNotLeakStateOnPathConflict(t *testing.T) {
	root := readyState("home")
	root.Spec.Mounts = []v1alpha1.Mount{{State: "m2", Path: "/shared"}}
	h := newHarness(t, root, readyState("m2"))
	code, _, errOut := h.run("", "mount", "--new", "leakrepro:/shared:rw", "--size", "1Gi", "--root", "home")
	if code != 1 || !strings.Contains(errOut, `root state "home" already has state "m2" mounted at /shared`) {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if !stateNotFound(t, h, "leakrepro") {
		t.Fatal("rejected --new left state leakrepro behind")
	}
	code, out, errOut := h.run("", "mount", "--new", "leakrepro:/free:rw", "--size", "1Gi", "--root", "home")
	if code != 0 {
		t.Fatalf("retry code %d: %s", code, errOut)
	}
	mustContain(t, out, "state leakrepro mounted")
}

func TestMountNewDoesNotLeakStateWhenRootMissing(t *testing.T) {
	h := newHarness(t)
	code, _, errOut := h.run("", "mount", "--new", "leakrepro:/shared:rw", "--size", "1Gi", "--root", "missing")
	if code != 1 || !strings.Contains(errOut, `state "missing" not found`) {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if !stateNotFound(t, h, "leakrepro") {
		t.Fatal("rejected --new left state leakrepro behind")
	}
}

// TestMountRejectsOverlappingPaths checks the CLI preflight for the topology
// the controller rejects with InvalidSpec: duplicate and nested mount paths.
func TestMountRejectsOverlappingPaths(t *testing.T) {
	t.Run("new nested under existing", func(t *testing.T) {
		root := readyState("home")
		root.Spec.Mounts = []v1alpha1.Mount{{State: "m2", Path: "/data"}}
		h := newHarness(t, root, readyState("m2"))
		code, _, errOut := h.run("", "mount", "--new", "nest2:/data/sub:rw", "--size", "256Mi", "--root", "home")
		if code != 1 || !strings.Contains(errOut, `mount nest2: path /data/sub overlaps mount m2 at /data`) {
			t.Fatalf("code %d: %s", code, errOut)
		}
		if !stateNotFound(t, h, "nest2") {
			t.Fatal("rejected --new left state nest2 behind")
		}
		if mounts := h.state("home").Spec.Mounts; len(mounts) != 1 || mounts[0].Path != "/data" {
			t.Fatalf("mounts changed: %+v", mounts)
		}
	})
	t.Run("existing nested under new", func(t *testing.T) {
		root := readyState("home")
		root.Spec.Mounts = []v1alpha1.Mount{{State: "m2", Path: "/data/sub"}}
		h := newHarness(t, root, readyState("m2"), readyState("nest2"))
		code, _, errOut := h.run("", "mount", "nest2:/data", "--root", "home")
		if code != 1 || !strings.Contains(errOut, `mount nest2: path /data overlaps mount m2 at /data/sub`) {
			t.Fatalf("code %d: %s", code, errOut)
		}
		if mounts := h.state("home").Spec.Mounts; len(mounts) != 1 || mounts[0].State != "m2" {
			t.Fatalf("mounts changed: %+v", mounts)
		}
	})
	t.Run("add nested under existing", func(t *testing.T) {
		root := readyState("home")
		root.Spec.Mounts = []v1alpha1.Mount{{State: "m2", Path: "/data"}}
		h := newHarness(t, root, readyState("m2"), readyState("nest2"))
		code, _, errOut := h.run("", "mount", "nest2:/data/sub:rw", "--root", "home")
		if code != 1 || !strings.Contains(errOut, "overlaps") {
			t.Fatalf("code %d: %s", code, errOut)
		}
		if mounts := h.state("home").Spec.Mounts; len(mounts) != 1 || mounts[0].State != "m2" {
			t.Fatalf("mounts changed: %+v", mounts)
		}
	})
	t.Run("batch validated before first write", func(t *testing.T) {
		h := newHarness(t, readyState("home"), readyState("a"), readyState("b"))
		code, _, errOut := h.run("", "mount", "a:/data", "b:/data/sub", "--root", "home")
		if code != 1 || !strings.Contains(errOut, "overlaps") {
			t.Fatalf("code %d: %s", code, errOut)
		}
		if mounts := h.state("home").Spec.Mounts; len(mounts) != 0 {
			t.Fatalf("partially applied batch: %+v", mounts)
		}
	})
}

func TestMountNewSurfacesStateFailure(t *testing.T) {
	h := newHarness(t, readyState("home"))
	h.ctrl.set(func(c *fakeController) { c.stateFail = "no space left" })
	code, _, errOut := h.run("", "mount", "--new", "bad:/data", "--root", "home")
	if code != 1 || !strings.Contains(errOut, `state "bad" failed: no space left`) {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if root := h.state("home"); len(root.Spec.Mounts) != 0 {
		t.Fatalf("failed state mounted: %+v", root.Spec.Mounts)
	}
}

// TestMountNewWaitsForFailedPendingState: a Failed initial version that still
// has its retryable pending commit can recover, so mount --new waits for the
// commit instead of reporting a failure the state controller will fix.
func TestMountNewWaitsForFailedPendingState(t *testing.T) {
	h := newHarness(t, readyState("home"))
	h.ctrl.set(func(c *fakeController) {
		c.stateFail = "initial version failed: fetch: device busy"
		c.stateFailPending = true
	})
	code, _, errOut := h.run("", "mount", "--new", "recovered:/data", "--root", "home")
	if code != 0 {
		t.Fatalf("mount failed on a retryable state: code %d: %s", code, errOut)
	}
	if st := h.state("recovered"); st.Status.Pending != nil || st.Status.Committed == nil {
		t.Fatalf("recovered state did not commit: %+v", st.Status)
	}
	if mounts := h.state("home").Spec.Mounts; len(mounts) != 1 || mounts[0].State != "recovered" {
		t.Fatalf("recovered state was not mounted: %+v", mounts)
	}
}

// TestMountNewFailsTerminalInitialVersion: a Failed initial version with no
// pending commit cannot recover. Mount must fail fast and roll back the state
// it created.
func TestMountNewFailsTerminalInitialVersion(t *testing.T) {
	h := newHarness(t, readyState("home"))
	h.ctrl.set(func(c *fakeController) {
		c.stateFail = "initial version failed: retrying"
	})
	start := time.Now()
	code, _, errOut := h.run("", "mount", "--new", "stuck:/data", "--root", "home")
	if code != 1 || !strings.Contains(errOut, `state "stuck" failed: initial version failed: retrying`) {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("mount waited %v for a terminal failure", elapsed)
	}
	if root := h.state("home"); len(root.Spec.Mounts) != 0 {
		t.Fatalf("failed state mounted: %+v", root.Spec.Mounts)
	}
	var st v1alpha1.BlipState
	err := h.kube.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: "stuck"}, &st)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("failed mount left its state behind: %v", err)
	}
}

// TestMountNewFromFailureRemovesForkCopies reproduces a failed
// `mount --new NAME --from SRC` where the new root never becomes usable. Fork
// creates a copy state for each writable mount of the source before the root;
// rollback must remove those copies too, not just the destination root.
func TestMountNewFromFailureRemovesForkCopies(t *testing.T) {
	src := readyState("src")
	src.Spec.Mounts = []v1alpha1.Mount{{State: "data", Path: "/data", Writable: true}}
	h := newHarness(t, readyState("home"), src, readyState("data"))
	h.ctrl.set(func(c *fakeController) {
		c.stateFail = `size 1Gi is smaller than copy source "src" (10Gi)`
	})
	code, _, errOut := h.run("", "mount", "--new", "dev:/work:rw", "--from", "src", "--size", "1Gi", "--root", "home")
	if code != 1 || !strings.Contains(errOut, `state "dev" failed: size 1Gi is smaller than copy source "src" (10Gi)`) {
		t.Fatalf("code %d: %s", code, errOut)
	}
	var states v1alpha1.BlipStateList
	if err := h.kube.List(context.Background(), &states); err != nil {
		t.Fatal(err)
	}
	keep := map[string]bool{"home": true, "src": true, "data": true}
	for _, s := range states.Items {
		if !keep[s.Name] {
			t.Fatalf("failed --new leaked state %q (copyFrom %q)", s.Name, s.Spec.CopyFrom)
		}
	}
	if root := h.state("home"); len(root.Spec.Mounts) != 0 {
		t.Fatalf("failed mount written as desired intent: %+v", root.Spec.Mounts)
	}
}

// TestMountNewFromKeepsForkCopiesOnSuccess is the success counterpart: the new
// root and the copies Fork created for its writable mounts all stay, and the
// root is mounted at the requested path.
func TestMountNewFromKeepsForkCopiesOnSuccess(t *testing.T) {
	src := readyState("src")
	src.Spec.Mounts = []v1alpha1.Mount{
		{State: "data", Path: "/data", Writable: true},
		{State: "tools", Path: "/tools"},
	}
	h := newHarness(t, readyState("home"), src, readyState("data"), readyState("tools"))
	code, out, errOut := h.run("", "mount", "--new", "dev:/work:rw", "--from", "src", "--root", "home")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "state dev mounted on root state home at /work (writable)")
	s := h.state("dev")
	if s.Spec.CopyFrom != "src" || len(s.Spec.Mounts) != 2 {
		t.Fatalf("new state %+v", s.Spec)
	}
	copyName := s.Spec.Mounts[0].State
	if copyName == "data" || !s.Spec.Mounts[0].Writable || s.Spec.Mounts[0].Path != "/data" {
		t.Fatalf("writable mount %+v", s.Spec.Mounts[0])
	}
	child := h.state(copyName)
	if child.Spec.CopyFrom != "data" {
		t.Fatalf("copy %q copyFrom %q", copyName, child.Spec.CopyFrom)
	}
	// Read-only mounts stay references to the existing state.
	if s.Spec.Mounts[1] != (v1alpha1.Mount{State: "tools", Path: "/tools"}) {
		t.Fatalf("read-only mount %+v", s.Spec.Mounts[1])
	}
	if root := h.state("home"); len(root.Spec.Mounts) != 1 || root.Spec.Mounts[0].State != "dev" {
		t.Fatalf("root mounts %+v", root.Spec.Mounts)
	}
	// The pre-existing source and its mount survive a successful --new.
	for _, name := range []string{"src", "data", "tools"} {
		if stateNotFound(t, h, name) {
			t.Fatalf("pre-existing state %q was deleted", name)
		}
	}
}

// TestMountNewFromRejectsDanglingReadOnlyMount covers the --from path: a
// read-only reference of the source root is copied verbatim, so it must be
// validated before any state is created.
func TestMountNewFromRejectsDanglingReadOnlyMount(t *testing.T) {
	src := readyState("src")
	src.Spec.Mounts = []v1alpha1.Mount{{State: "gone", Path: "/ro"}}
	h := newHarness(t, readyState("home"), src)
	code, _, errOut := h.run("", "mount", "--new", "dev:/work:rw", "--from", "src", "--root", "home")
	if code != 1 || !strings.Contains(errOut, `read mount source "gone"`) || !strings.Contains(errOut, "not found") {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if !stateNotFound(t, h, "dev") {
		t.Fatal("rejected --new left a state behind")
	}
	if root := h.state("home"); len(root.Spec.Mounts) != 0 {
		t.Fatalf("rejected --new wrote desired intent: %+v", root.Spec.Mounts)
	}
}

func TestMountNewRejectsFailedSource(t *testing.T) {
	bad := state("bad")
	bad.Status.Phase, bad.Status.Message = v1alpha1.StateFailed, "image too large"
	h := newHarness(t, readyState("home"), bad)
	code, _, errOut := h.run("", "mount", "--new", "copy:/data", "--from", "bad", "--root", "home")
	if code != 1 || !strings.Contains(errOut, `copy source "bad" failed: image too large`) {
		t.Fatalf("code %d: %s", code, errOut)
	}
}

// TestMountPathsMayContainColons reproduces a colon-containing path being
// split as if its last segment were a mode. Modes are only recognized when the
// path before them has no colon; a path that is both colon-containing and
// mode-suffixed is genuinely ambiguous and reported as such.
func TestMountPathsMayContainColons(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		path string
		rw   bool
	}{
		{"colon path", []string{"mount", "data:/a:b", "--root", "home"}, "/a:b", false},
		{"colon path and non-mode suffix", []string{"mount", "data:/a:b:rx", "--root", "home"}, "/a:b:rx", false},
		{"mode", []string{"mount", "data:/a:rw", "--root", "home"}, "/a", true},
		{"read-only mode", []string{"mount", "data:/a:ro", "--root", "home"}, "/a", false},
		{"new colon path", []string{"mount", "--new", "cache:/a:b", "--root", "home"}, "/a:b", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, readyState("home"), readyState("data"))
			code, _, errOut := h.run("", tc.args...)
			if code != 0 {
				t.Fatalf("code %d: %s", code, errOut)
			}
			mounts := h.state("home").Spec.Mounts
			if len(mounts) != 1 || mounts[0].Path != tc.path || mounts[0].Writable != tc.rw {
				t.Fatalf("mounts %+v, want path %s rw=%v", mounts, tc.path, tc.rw)
			}
		})
	}

	for _, arg := range []string{"data:/a:b:rw", "data:/a:b:ro"} {
		t.Run("ambiguous "+arg, func(t *testing.T) {
			h := newHarness(t, readyState("home"), readyState("data"))
			code, _, errOut := h.run("", "mount", arg, "--root", "home")
			if code != 1 || !strings.Contains(errOut, "ambiguous") {
				t.Fatalf("code %d: %s", code, errOut)
			}
			if mounts := h.state("home").Spec.Mounts; len(mounts) != 0 {
				t.Fatalf("ambiguous mount written: %+v", mounts)
			}
		})
	}
}

// TestMountRejectsGuestReservedAndSymlinkPaths reproduces a mount the CLI
// accepts offline but the guest cannot create: the path is reserved for the
// guest itself, lies below a regular file, or is not a directory. The mount
// must be rejected before desired intent is written, or the root cannot start
// again.
func TestMountRejectsGuestReservedAndSymlinkPaths(t *testing.T) {
	for _, path := range []string{"/proc/w2", "/sys", "/dev/w2", "/run/blip/w2", "/run/blip-collect/w2", "/var/run/blip/w2", "/var/run", "/etc/mtab/x"} {
		t.Run(path, func(t *testing.T) {
			h := newHarness(t, readyState("home"), readyState("data"))
			code, _, errOut := h.run("", "mount", "data:"+path, "--root", "home")
			if code != 1 || !strings.Contains(errOut, "mount path") {
				t.Fatalf("code %d: %s", code, errOut)
			}
			if mounts := h.state("home").Spec.Mounts; len(mounts) != 0 {
				t.Fatalf("rejected mount written as desired intent: %+v", mounts)
			}
		})
	}

	// A rejected path must not leave a newly created state behind either.
	h := newHarness(t, readyState("home"))
	code, _, errOut := h.run("", "mount", "--new", "reserved:/proc/w2", "--root", "home")
	if code != 1 || !strings.Contains(errOut, "mount path") {
		t.Fatalf("--new code %d: %s", code, errOut)
	}
	if !stateNotFound(t, h, "reserved") {
		t.Fatal("rejected --new left state reserved behind")
	}

	// A known system alias that resolves into a reserved tree must be
	// rejected offline before desired intent or a --new state is written.
	h = newHarness(t, readyState("home"))
	code, _, errOut = h.run("", "mount", "--new", "aliased:/var/run/blip/w2", "--root", "home")
	if code != 1 || !strings.Contains(errOut, "mount path") {
		t.Fatalf("aliased --new code %d: %s", code, errOut)
	}
	if !stateNotFound(t, h, "aliased") {
		t.Fatal("rejected aliased --new left state aliased behind")
	}
	if mounts := h.state("home").Spec.Mounts; len(mounts) != 0 {
		t.Fatalf("rejected aliased --new left desired intent: %+v", mounts)
	}

	// Prefix-sharing non-overlapping paths stay legal.
	h = newHarness(t, readyState("home"), readyState("a"), readyState("b"))
	if code, _, errOut := h.run("", "mount", "a:/data", "--root", "home"); code != 0 {
		t.Fatalf("legitimate mount rejected: %d %s", code, errOut)
	}
	if code, _, errOut := h.run("", "mount", "b:/procdata", "--root", "home"); code != 0 {
		t.Fatalf("legitimate nested path rejected: %d %s", code, errOut)
	}
}

// TestMountRejectsOverlongPaths reproduces mounts the CLI accepted offline but
// no Linux guest can create. A component over NAME_MAX (255 bytes) or a path at
// PATH_MAX makes the guest fail while creating the mount point; if the intent
// is written the durable root cannot start again. Reject before creating a
// state (--new) or writing desired intent.
func TestMountRejectsOverlongPaths(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
	}{
		{"300 byte component", "/" + strings.Repeat("a", 300)},
		{"260 byte component", "/" + strings.Repeat("b", 260)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, readyState("home"), readyState("data"))
			code, _, errOut := h.run("", "mount", "data:"+tc.path, "--root", "home")
			if code != 1 || !strings.Contains(errOut, "mount path") {
				t.Fatalf("code %d: %s", code, errOut)
			}
			if mounts := h.state("home").Spec.Mounts; len(mounts) != 0 {
				t.Fatalf("rejected mount written as desired intent: %+v", mounts)
			}

			// A rejected path must not leave a newly created state behind.
			code, _, errOut = h.run("", "mount", "--new", "long:"+tc.path, "--root", "home")
			if code != 1 || !strings.Contains(errOut, "mount path") {
				t.Fatalf("--new code %d: %s", code, errOut)
			}
			if !stateNotFound(t, h, "long") {
				t.Fatal("rejected --new left state long behind")
			}
			if mounts := h.state("home").Spec.Mounts; len(mounts) != 0 {
				t.Fatalf("rejected --new left desired intent: %+v", mounts)
			}
		})
	}

	// Safe long nested paths stay legal.
	h := newHarness(t, readyState("home"), readyState("data"))
	safe := "/" + strings.Repeat("abcdefghij/", 20) + strings.Repeat("c", 255)
	code, _, errOut := h.run("", "mount", "data:"+safe, "--root", "home")
	if code != 0 {
		t.Fatalf("legitimate long nested path rejected: %d %s", code, errOut)
	}
	if mounts := h.state("home").Spec.Mounts; len(mounts) != 1 || mounts[0].Path != safe {
		t.Fatalf("legitimate long path not written: %+v", mounts)
	}
}

// TestMountAcceptsBaseImageDirectorySymlinks reproduces the dev/base image's
// directory symlinks: usr-merge aliases and per-package /usr/share/doc
// entries. The guest resolves them inside the root, as Linux mount does, so
// both a running and a stopped root must accept these paths instead of
// writing intent that fails the next execution.
func TestMountAcceptsBaseImageDirectorySymlinks(t *testing.T) {
	for _, path := range []string{
		"/bin/w3",
		"/var/spool/mail",
		"/var/spool/mail/w3",
		"/usr/share/doc/gcc/x",
		"/usr/share/doc/libatomic1/x",
		"/usr/share/doc/git/contrib/hooks/x",
		"/usr/share/doc/gcc-13/probe",
		"/usr/lib/x86_64-linux-gnu/perl/5.38/x",
	} {
		t.Run(path, func(t *testing.T) {
			for _, live := range []bool{false, true} {
				name := "offline"
				var root *v1alpha1.BlipState
				objs := []client.Object{readyState("data")}
				if live {
					name = "live"
					b := runningBlip("agent")
					root = readyState(b.Spec.State)
					objs = append(objs, b, root)
				} else {
					root = readyState("home")
					objs = append(objs, root)
				}
				t.Run(name, func(t *testing.T) {
					h := newHarness(t, objs...)
					code, _, errOut := h.run("", "mount", "data:"+path, "--root", root.Name)
					if code != 0 {
						t.Fatalf("mount %s: code %d: %s", path, code, errOut)
					}
					mounts := h.state(root.Name).Spec.Mounts
					if len(mounts) != 1 || mounts[0].Path != path {
						t.Fatalf("mount %s not written as desired intent: %+v", path, mounts)
					}
				})
			}
		})
	}
}

// TestMountAcceptsNewBelowBaseImageDirectorySymlink covers the offline --new
// path that previously leaked a committed state and durable intent: a mount
// below /usr/share/doc/gcc-13 is valid because the guest resolves the symlink
// to its directory target inside the root.
func TestMountAcceptsNewBelowBaseImageDirectorySymlink(t *testing.T) {
	h := newHarness(t, readyState("home"))
	code, _, errOut := h.run("", "mount", "--new", "doc:/usr/share/doc/gcc-13/probe", "--root", "home")
	if code != 0 {
		t.Fatalf("--new code %d: %s", code, errOut)
	}
	h.state("doc")
	mounts := h.state("home").Spec.Mounts
	if len(mounts) != 1 || mounts[0].State != "doc" || mounts[0].Path != "/usr/share/doc/gcc-13/probe" {
		t.Fatalf("accepted --new did not write desired intent: %+v", mounts)
	}
}

// TestMountRejectsBaseImageFilesOffline covers the offline half of a mount
// below a regular base-image file (/etc/passwd/x): the guest reports "is a
// symlink or not a directory" on the next execution, so the CLI must not
// report success or create a --new state for it.
func TestMountRejectsBaseImageFilesOffline(t *testing.T) {
	for _, path := range []string{
		"/etc/passwd/x", "/etc/group/x", "/etc/ld.so.cache/x",
		"/etc/ld.so.conf/x", "/etc/bash.bashrc/x", "/etc/environment/x",
		"/etc/profile/x", "/etc/inputrc/x", "/etc/login.defs/x",
		"/etc/host.conf/x", "/etc/gai.conf/x",
		"/etc/timezone/x", "/etc/shells/x", "/usr/lib/os-release/x",
		"/lib/os-release/x",
	} {
		t.Run(path, func(t *testing.T) {
			h := newHarness(t, readyState("home"), readyState("data"))
			code, _, errOut := h.run("", "mount", "data:"+path, "--root", "home")
			if code != 1 || !strings.Contains(errOut, "in the base image") {
				t.Fatalf("mount %s: code %d: %s", path, code, errOut)
			}
			code, _, errOut = h.run("", "mount", "--new", "leak:"+path, "--root", "home")
			if code != 1 || !strings.Contains(errOut, "in the base image") {
				t.Fatalf("--new %s: code %d: %s", path, code, errOut)
			}
			if !stateNotFound(t, h, "leak") {
				t.Fatal("rejected --new left its state behind")
			}
			if mounts := h.state("home").Spec.Mounts; len(mounts) != 0 {
				t.Fatalf("rejected mount left desired intent: %+v", mounts)
			}
		})
	}
}

// TestMountRejectsGuestManagedFiles reproduces mounting over /etc/hosts or
// /etc/resolv.conf: the guest bind-mounts those regular files before user
// mounts, so a filesystem mount point there can never attach. Preflight must
// reject it before writing intent or creating a --new state.
func TestMountRejectsGuestManagedFiles(t *testing.T) {
	for _, path := range []string{"/etc/hosts", "/etc/resolv.conf", "/etc/hosts/x"} {
		t.Run(path, func(t *testing.T) {
			h := newHarness(t, readyState("home"), readyState("data"), readyState("base"))
			for _, arg := range []string{"data:" + path, "base:" + path + ":ro"} {
				code, _, errOut := h.run("", "mount", arg, "--root", "home")
				if code != 1 || !strings.Contains(errOut, "guest-managed file") {
					t.Fatalf("mount %s: code %d: %s", arg, code, errOut)
				}
			}
			code, _, errOut := h.run("", "mount", "--new", "leak:"+path, "--root", "home")
			if code != 1 || !strings.Contains(errOut, "guest-managed file") {
				t.Fatalf("--new code %d: %s", code, errOut)
			}
			if !stateNotFound(t, h, "leak") {
				t.Fatal("rejected --new left its state behind")
			}
			if mounts := h.state("home").Spec.Mounts; len(mounts) != 0 {
				t.Fatalf("rejected mount left desired intent: %+v", mounts)
			}
		})
	}
}

// TestMountGuestRejectedPathRollsBack reproduces the guest refusing a mount
// point the CLI could not preflight (a path below a regular file). A running
// root must not keep the desired mount or, for --new, the state that was
// created for a mount that can never attach.
func TestMountGuestRejectedPathRollsBack(t *testing.T) {
	const guestErr = "/usr/bin/env is a symlink or not a directory"
	for _, created := range []bool{false, true} {
		name := "existing state"
		if created {
			name = "new state"
		}
		t.Run(name, func(t *testing.T) {
			b := runningBlip("agent")
			root := readyState(b.Spec.State)
			root.Spec.Mounts = []v1alpha1.Mount{{State: "keep", Path: "/keep"}}
			h := newHarness(t, b, root, readyState("keep"), readyState("data"))
			h.ctrl.set(func(c *fakeController) { c.mountFail = guestErr })
			if created {
				code, _, errOut := h.run("", "mount", "--new", "leak:/usr/bin/env/x", "--root", root.Name)
				if code != 1 || !strings.Contains(errOut, guestErr) || !strings.Contains(errOut, "desired mount was removed") {
					t.Fatalf("--new code %d: %s", code, errOut)
				}
				if strings.Contains(errOut, "remains applied") {
					t.Fatalf("--new rollback message contradicts itself: %s", errOut)
				}
				if !stateNotFound(t, h, "leak") {
					t.Fatal("rejected --new left state leak behind")
				}
			} else {
				code, _, errOut := h.run("", "mount", "data:/usr/bin/env/x", "--root", root.Name)
				if code != 1 || !strings.Contains(errOut, guestErr) || !strings.Contains(errOut, "desired mount was removed") {
					t.Fatalf("mount code %d: %s", code, errOut)
				}
				if strings.Contains(errOut, "remains applied") {
					t.Fatalf("rollback message contradicts itself: %s", errOut)
				}
			}
			mounts := h.state(root.Name).Spec.Mounts
			if len(mounts) != 1 || mounts[0].State != "keep" || mounts[0].Path != "/keep" {
				t.Fatalf("rejected mount left desired intent: %+v", mounts)
			}
		})
	}
}

// TestMountPointRejectedClassifiesTerminalGuestErrors covers every fixed
// message class that means the guest can never create the mount point, and
// checks that transient attach and save failures are not mistaken for one.
func TestMountPointRejectedClassifiesTerminalGuestErrors(t *testing.T) {
	for _, msg := range []string{
		"/usr/bin/env is a symlink or not a directory",
		"/home/dev/proc-link/x is a symlink",
		"mkdir /home/dev/proc-link/x: not a directory",
		"mount path /home/dev/blip-link/x resolves to /run/blip/x, which the guest reserves",
		"mount path /bad overlaps /run/blip",
		"mount path /bad resolves to /",
	} {
		if !mountPointRejected(msg) {
			t.Errorf("terminal guest error not classified as rejected: %q", msg)
		}
	}
	for _, msg := range []string{
		"save failed: no space left on device",
		"save of state data failed: device or resource busy",
		"switch failed: timed out",
		"attach failed: no space left on device",
		"processes are still using /data",
	} {
		if mountPointRejected(msg) {
			t.Errorf("transient failure classified as a rejected mount point: %q", msg)
		}
	}
}

// TestMountTerminalGuestRejectionsRollBack covers the three rollback paths for
// every permanent guest rejection: a live add, a --new state, and a move. The
// same-state move is covered by TestMountRemoveThenRejectedAddRestoresMount.
func TestMountTerminalGuestRejectionsRollBack(t *testing.T) {
	for _, tc := range []struct{ name, msg string }{
		{"symlink", "/usr/bin/env is a symlink or not a directory"},
		{"not directory", "mkdir /home/dev/proc-link/x: not a directory"},
		{"guest reserves", "mount path /home/dev/blip-link/x resolves to /run/blip/x, which the guest reserves"},
		{"overlap", "mount path /bad overlaps /run/blip"},
		{"mount path", "mount path /bad resolves to /"},
	} {
		t.Run(tc.name+"/add", func(t *testing.T) {
			b := runningBlip("agent")
			root := readyState(b.Spec.State)
			root.Spec.Mounts = []v1alpha1.Mount{{State: "keep", Path: "/keep"}}
			h := newHarness(t, b, root, readyState("keep"), readyState("data"))
			h.ctrl.set(func(c *fakeController) { c.mountFail = tc.msg })

			code, _, errOut := h.run("", "mount", "data:/bad", "--root", root.Name)
			if code != 1 || !strings.Contains(errOut, tc.msg) || !strings.Contains(errOut, "desired mount was removed") {
				t.Fatalf("code %d: %s", code, errOut)
			}
			if strings.Contains(errOut, "remains applied") {
				t.Fatalf("rollback message contradicts itself: %s", errOut)
			}
			mounts := h.state(root.Name).Spec.Mounts
			if len(mounts) != 1 || mounts[0].State != "keep" || mounts[0].Path != "/keep" {
				t.Fatalf("rejected add left desired intent: %+v", mounts)
			}
		})

		t.Run(tc.name+"/new", func(t *testing.T) {
			b := runningBlip("agent")
			root := readyState(b.Spec.State)
			h := newHarness(t, b, root)
			h.ctrl.set(func(c *fakeController) { c.mountFail = tc.msg })

			code, _, errOut := h.run("", "mount", "--new", "leak:/bad:rw", "--root", root.Name)
			if code != 1 || !strings.Contains(errOut, tc.msg) || !strings.Contains(errOut, "desired mount was removed") {
				t.Fatalf("code %d: %s", code, errOut)
			}
			if !stateNotFound(t, h, "leak") {
				t.Fatal("rejected --new left state leak behind")
			}
			if mounts := h.state(root.Name).Spec.Mounts; len(mounts) != 0 {
				t.Fatalf("rejected --new left desired intent: %+v", mounts)
			}
		})

		t.Run(tc.name+"/move", func(t *testing.T) {
			b := runningBlip("agent")
			root := readyState(b.Spec.State)
			root.Spec.Mounts = []v1alpha1.Mount{
				{State: "data", Path: "/data"},
				{State: "keep", Path: "/keep"},
			}
			b.Status.Mounts = []v1alpha1.MountStatus{
				{State: "data", Path: "/data", Phase: v1alpha1.MountMounted, AttachmentID: "data-attachment"},
				{State: "keep", Path: "/keep", Phase: v1alpha1.MountMounted, AttachmentID: "keep-attachment"},
			}
			h := newHarness(t, b, root, readyState("data"), readyState("keep"))
			h.ctrl.set(func(c *fakeController) { c.mountFail = tc.msg })

			code, _, errOut := h.run("", "mount", "data:/bad", "--rm", "keep", "--root", root.Name)
			if code != 1 || !strings.Contains(errOut, tc.msg) {
				t.Fatalf("code %d: %s", code, errOut)
			}
			if strings.Contains(errOut, "desired mount remains applied") {
				t.Fatalf("rejected move claims the mount remains applied: %s", errOut)
			}
			mustContain(t, errOut, "previous mount", "/data", "was restored")
			mounts := h.state(root.Name).Spec.Mounts
			if len(mounts) != 2 {
				t.Fatalf("rejected move lost mounts: %+v", mounts)
			}
			if m := findSpecMount(mounts, "data"); m == nil || m.Path != "/data" {
				t.Fatalf("rejected move did not restore /data: %+v", mounts)
			}
			if m := findSpecMount(mounts, "keep"); m == nil || m.Path != "/keep" {
				t.Fatalf("removed mount was not restored: %+v", mounts)
			}
		})
	}
}

// TestMountSourceFailedWhileWaitingRollsBack covers a source that becomes
// Failed while the mount waits. The controller reports it as a terminal
// MountFailed entry, so the desired mount this command added must be removed.
func TestMountSourceFailedWhileWaitingRollsBack(t *testing.T) {
	const failedMsg = `state "data" failed: image not found`
	b := runningBlip("agent")
	root := readyState(b.Spec.State)
	h := newHarness(t, b, root, readyState("data"))
	h.ctrl.set(func(c *fakeController) { c.mountFail = failedMsg })

	code, _, errOut := h.run("", "mount", "data:/data", "--root", root.Name)
	if code != 1 || !strings.Contains(errOut, failedMsg) || !strings.Contains(errOut, "desired mount was removed") {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if strings.Contains(errOut, "remains applied") {
		t.Fatalf("failed source rollback message contradicts itself: %s", errOut)
	}
	if mounts := h.state(root.Name).Spec.Mounts; len(mounts) != 0 {
		t.Fatalf("failed source left desired intent: %+v", mounts)
	}
}

// TestMountMoveRejectedRestoresPreviousPath reproduces a move whose new path
// the guest rejects. The old path must be restored, or every later execution
// of the root fails at the rejected path.
func TestMountMoveRejectedRestoresPreviousPath(t *testing.T) {
	const guestErr = "/usr/bin/env is a symlink or not a directory"
	b := runningBlip("agent")
	root := readyState(b.Spec.State)
	root.Status.Writer = &v1alpha1.Writer{BlipName: b.Name, BlipUID: string(b.UID)}
	root.Spec.Mounts = []v1alpha1.Mount{
		{State: "data", Path: "/data"},
		{State: "keep", Path: "/keep"},
	}
	b.Status.Mounts = []v1alpha1.MountStatus{
		{State: "data", Path: "/data", Phase: v1alpha1.MountMounted, AttachmentID: "data-attachment"},
		{State: "keep", Path: "/keep", Phase: v1alpha1.MountMounted, AttachmentID: "keep-attachment"},
	}
	h := newHarness(t, b, root, readyState("data"), readyState("keep"))
	h.ctrl.set(func(c *fakeController) { c.mountFail = guestErr })

	code, _, errOut := h.run("", "mount", "data:/usr/bin/env/x", "--rm", "keep", "--root", root.Name)
	if code != 1 || !strings.Contains(errOut, guestErr) {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if strings.Contains(errOut, "desired mount remains applied") {
		t.Fatalf("rejected move claims the mount remains applied: %s", errOut)
	}
	mustContain(t, errOut, "previous mount", "/data", "was restored")
	mounts := h.state(root.Name).Spec.Mounts
	if len(mounts) != 2 {
		t.Fatalf("rejected move lost mounts: %+v", mounts)
	}
	if m := findSpecMount(mounts, "data"); m == nil || m.Path != "/data" {
		t.Fatalf("rejected move did not restore /data: %+v", mounts)
	}
	if m := findSpecMount(mounts, "keep"); m == nil || m.Path != "/keep" {
		t.Fatalf("removed mount was not restored: %+v", mounts)
	}
}

// TestMountMoveRollbackHonorsOccupiedPreviousPath reproduces a rejected move
// whose old path a concurrent edit has taken. Restoring over the other mount
// would leave a topology the controller rejects on every execution, so the
// rollback must remove the rejected entry and say the restore was impossible.
func TestMountMoveRollbackHonorsOccupiedPreviousPath(t *testing.T) {
	const guestErr = "/usr/bin/env is a symlink or not a directory"
	for _, tc := range []struct{ name, occupied string }{
		{"nested", "/data/sub"},
		{"exact", "/data"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := runningBlip("agent")
			root := readyState(b.Spec.State)
			root.Status.Writer = &v1alpha1.Writer{BlipName: b.Name, BlipUID: string(b.UID)}
			root.Spec.Mounts = []v1alpha1.Mount{
				{State: "data", Path: "/data"},
				{State: "keep", Path: "/keep"},
			}
			b.Status.Mounts = []v1alpha1.MountStatus{
				{State: "data", Path: "/data", Phase: v1alpha1.MountMounted, AttachmentID: "data-attachment"},
				{State: "keep", Path: "/keep", Phase: v1alpha1.MountMounted, AttachmentID: "keep-attachment"},
			}
			h := newHarness(t, b, root, readyState("data"), readyState("keep"))
			h.ctrl.set(func(c *fakeController) { c.mountFail = guestErr })
			// Take the old path in the same write that applies the move,
			// as a concurrent editor between the root read and update would.
			injected := false
			h.kube = interceptor.NewClient(h.kube, interceptor.Funcs{
				Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
					if s, ok := obj.(*v1alpha1.BlipState); ok && !injected {
						if m := findSpecMount(s.Spec.Mounts, "data"); m != nil && m.Path == "/new" {
							injected = true
							s.Spec.Mounts = append(s.Spec.Mounts, v1alpha1.Mount{State: "other", Path: tc.occupied})
						}
					}
					return c.Update(ctx, obj, opts...)
				},
			})

			code, _, errOut := h.run("", "mount", "data:/new", "--rm", "keep", "--root", root.Name)
			if code != 1 || !strings.Contains(errOut, guestErr) {
				t.Fatalf("code %d: %s", code, errOut)
			}
			if strings.Contains(errOut, "was restored") {
				t.Fatalf("blocked rollback claims success: %s", errOut)
			}
			mustContain(t, errOut, "previous mount", "/data", "could not be restored", "mount data again")
			mounts := h.state(root.Name).Spec.Mounts
			if findSpecMount(mounts, "data") != nil {
				t.Fatalf("blocked rollback left rejected intent: %+v", mounts)
			}
			if m := findSpecMount(mounts, "other"); m == nil || m.Path != tc.occupied {
				t.Fatalf("concurrent mount was lost: %+v", mounts)
			}
			if m := findSpecMount(mounts, "keep"); m == nil || m.Path != "/keep" {
				t.Fatalf("removed mount was not restored: %+v", mounts)
			}
			for _, m := range mounts {
				for _, other := range mounts {
					if m.State != other.State && mountPathsOverlap(m.Path, other.Path) {
						t.Fatalf("rollback left overlapping mounts: %+v", mounts)
					}
				}
			}
		})
	}
}

// TestMountRemoveThenRejectedAddRestoresMount reproduces --rm of a state
// followed by a rejected add of the same state (an implicit move). The removal
// has already been applied, so the original mount must be restored instead of
// silently lost.
func TestMountRemoveThenRejectedAddRestoresMount(t *testing.T) {
	for _, tc := range []struct{ name, msg string }{
		{"symlink", "/usr/bin/env is a symlink or not a directory"},
		{"not directory", "mkdir /home/dev/proc-link/x: not a directory"},
		{"guest reserves", "mount path /home/dev/blip-link/x resolves to /run/blip/x, which the guest reserves"},
		{"overlap", "mount path /bad overlaps /run/blip"},
		{"mount path", "mount path /bad resolves to /"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := runningBlip("agent")
			root := readyState(b.Spec.State)
			root.Status.Writer = &v1alpha1.Writer{BlipName: b.Name, BlipUID: string(b.UID)}
			root.Spec.Mounts = []v1alpha1.Mount{{State: "data", Path: "/data", Writable: true}}
			b.Status.Mounts = []v1alpha1.MountStatus{{
				State: "data", Path: "/data", Writable: true, Phase: v1alpha1.MountMounted, AttachmentID: "data-attachment",
			}}
			h := newHarness(t, b, root, readyState("data"))
			h.ctrl.set(func(c *fakeController) { c.mountFail = tc.msg })

			code, _, errOut := h.run("", "mount", "--rm", "data", "data:/bad", "--root", root.Name)
			if code != 1 || !strings.Contains(errOut, tc.msg) {
				t.Fatalf("code %d: %s", code, errOut)
			}
			if strings.Contains(errOut, "desired mount remains applied") {
				t.Fatalf("rejected add claims the mount remains applied: %s", errOut)
			}
			mustContain(t, errOut, "were restored")
			mounts := h.state(root.Name).Spec.Mounts
			if len(mounts) != 1 || mounts[0] != (v1alpha1.Mount{State: "data", Path: "/data", Writable: true}) {
				t.Fatalf("original mount was lost: %+v", mounts)
			}
		})
	}
}

// TestMountRemoveDuplicatesUnmountsOnce reproduces repeated --rm entries for
// one state. Preflight accepted both, then the first removal succeeded and the
// second failed with "is not mounted", so the command exited 1 after mutating
// the root. Identical removals are de-duplicated; a genuinely unmounted state
// is still rejected before anything changes.
func TestMountRemoveDuplicatesUnmountsOnce(t *testing.T) {
	t.Run("offline", func(t *testing.T) {
		root := readyState("home")
		root.Spec.Mounts = []v1alpha1.Mount{{State: "data", Path: "/data", Writable: true}}
		h := newHarness(t, root, readyState("data"))
		code, _, errOut := h.run("", "mount", "--rm", "data", "--rm", "data", "--root", "home")
		if code != 0 {
			t.Fatalf("code %d: %s", code, errOut)
		}
		if mounts := h.state("home").Spec.Mounts; len(mounts) != 0 {
			t.Fatalf("duplicate removal left desired intent: %+v", mounts)
		}
	})

	t.Run("running", func(t *testing.T) {
		b := runningBlip("agent", v1alpha1.Mount{State: "data", Path: "/data", Writable: true})
		h := newHarness(t, b, readyState("data"))
		code, _, errOut := h.run("", "mount", "--rm", "data", "--rm", "data", "--root", b.Spec.State)
		if code != 0 {
			t.Fatalf("code %d: %s", code, errOut)
		}
		if mounts := h.state(b.Spec.State).Spec.Mounts; len(mounts) != 0 {
			t.Fatalf("duplicate removal left desired intent: %+v", mounts)
		}
	})

	t.Run("unmounted still rejected", func(t *testing.T) {
		root := readyState("home")
		root.Spec.Mounts = []v1alpha1.Mount{{State: "data", Path: "/data", Writable: true}}
		h := newHarness(t, root, readyState("data"))
		code, _, errOut := h.run("", "mount", "--rm", "data", "--rm", "data", "--rm", "ghost", "--root", "home")
		if code != 1 || !strings.Contains(errOut, `state "ghost" is not mounted`) {
			t.Fatalf("code %d: %s", code, errOut)
		}
		if mounts := h.state("home").Spec.Mounts; len(mounts) != 1 || mounts[0].State != "data" {
			t.Fatalf("rejected removal mutated the root: %+v", mounts)
		}
	})
}

// TestMountRemoveUnmountedRejectsWholeCommand covers --rm naming a state that
// is not mounted after an earlier --rm named one that is. The command must be
// rejected before the first removal is applied, leaving the root untouched.
func TestMountRemoveUnmountedRejectsWholeCommand(t *testing.T) {
	t.Run("offline", func(t *testing.T) {
		root := readyState("home")
		root.Spec.Mounts = []v1alpha1.Mount{{State: "data", Path: "/data", Writable: true}}
		a := mountTestApp(t, root, readyState("data"))
		var errOut bytes.Buffer
		a.env.Err = &errOut
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		code := Main(ctx, a.env, []string{"mount", "--rm", "data", "--rm", "ghost", "--root", "home"})
		if code != 1 || !strings.Contains(errOut.String(), `state "ghost" is not mounted`) {
			t.Fatalf("code %d: %s", code, errOut.String())
		}
		s, err := a.getState(ctx, root.Name)
		if err != nil {
			t.Fatal(err)
		}
		if len(s.Spec.Mounts) != 1 || s.Spec.Mounts[0].State != "data" {
			t.Fatalf("rejected removal mutated the root: %+v", s.Spec.Mounts)
		}
	})

	t.Run("running", func(t *testing.T) {
		b := runningBlip("agent", v1alpha1.Mount{State: "data", Path: "/data", Writable: true})
		root := readyState(b.Spec.State)
		root.Status.Writer = &v1alpha1.Writer{BlipName: b.Name, BlipUID: string(b.UID)}
		root.Spec.Mounts = []v1alpha1.Mount{{State: "data", Path: "/data", Writable: true}}
		h := newHarness(t, b, root, readyState("data"))

		code, _, errOut := h.run("", "mount", "--rm", "data", "--rm", "ghost", "--root", root.Name)
		if code != 1 || !strings.Contains(errOut, `state "ghost" is not mounted`) {
			t.Fatalf("code %d: %s", code, errOut)
		}
		mounts := h.state(root.Name).Spec.Mounts
		if len(mounts) != 1 || mounts[0].State != "data" {
			t.Fatalf("rejected removal mutated the root: %+v", mounts)
		}
	})
}

// TestMountRemoveThenRejectedNewRestoresMount is the --new counterpart: the
// invocation removes a mount, creates and commits a state, then the guest
// rejects its path. Rollback removes the new state but must restore the
// original mount it removed first.
func TestMountRemoveThenRejectedNewRestoresMount(t *testing.T) {
	const guestErr = "/usr/bin/env is a symlink or not a directory"
	b := runningBlip("agent")
	root := readyState(b.Spec.State)
	root.Status.Writer = &v1alpha1.Writer{BlipName: b.Name, BlipUID: string(b.UID)}
	root.Spec.Mounts = []v1alpha1.Mount{{State: "keep", Path: "/keep", Writable: true}}
	b.Status.Mounts = []v1alpha1.MountStatus{{
		State: "keep", Path: "/keep", Writable: true, Phase: v1alpha1.MountMounted, AttachmentID: "keep-attachment",
	}}
	h := newHarness(t, b, root, readyState("keep"))
	h.ctrl.set(func(c *fakeController) { c.mountFail = guestErr })

	code, _, errOut := h.run("", "mount", "--new", "cache:/usr/bin/env/x:rw", "--rm", "keep", "--root", root.Name)
	if code != 1 || !strings.Contains(errOut, guestErr) {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, errOut, "were restored")
	if !stateNotFound(t, h, "cache") {
		t.Fatal("rejected --new left state cache behind")
	}
	mounts := h.state(root.Name).Spec.Mounts
	if len(mounts) != 1 || mounts[0] != (v1alpha1.Mount{State: "keep", Path: "/keep", Writable: true}) {
		t.Fatalf("original mount was lost: %+v", mounts)
	}
}

// TestMountRejectsImportedBaseRoot reproduces mounting onto (or creating a
// mount state on) an imported base image. A base is a shared template; edits
// to its mounts propagate into every later fork.
func TestMountRejectsImportedBaseRoot(t *testing.T) {
	base := readyState("base")
	base.Spec.Image = "registry/base:1"
	h := newHarness(t, readyState("home"), base, readyState("data"))
	for _, args := range [][]string{
		{"mount", "data:/data", "--root", "base"},
		{"mount", "--new", "cache:/cache", "--root", "base"},
		{"mount", "--new", "cache:/cache", "--from", "base", "--root", "base"},
	} {
		code, _, errOut := h.run("", args...)
		if code != 1 || !strings.Contains(errOut, "imported base") {
			t.Fatalf("%v: code %d: %s", args, code, errOut)
		}
		if !stateNotFound(t, h, "cache") {
			t.Fatalf("%v: rejected command created state cache", args)
		}
		if mounts := h.state("base").Spec.Mounts; len(mounts) != 0 {
			t.Fatalf("%v: imported base mutated: %+v", args, mounts)
		}
	}
}

// TestMountRejectsUnusableStates rejects a failed source or root before any
// desired intent is written. Such a state can never attach, so an offline
// success would poison the root until the mount is removed by hand.
func TestMountRejectsUnusableStates(t *testing.T) {
	failed := func(name, msg string) *v1alpha1.BlipState {
		s := state(name)
		s.Status.Phase, s.Status.Message = v1alpha1.StateFailed, msg
		return s
	}
	t.Run("failed source", func(t *testing.T) {
		h := newHarness(t, readyState("home"), failed("bad", "image not found"))
		code, _, errOut := h.run("", "mount", "bad:/x", "--root", "home")
		if code != 1 || !strings.Contains(errOut, `state "bad" failed: image not found`) {
			t.Fatalf("code %d: %s", code, errOut)
		}
		if mounts := h.state("home").Spec.Mounts; len(mounts) != 0 {
			t.Fatalf("failed source written as intent: %+v", mounts)
		}
	})
	t.Run("failed root", func(t *testing.T) {
		h := newHarness(t, failed("home", "no space left"), readyState("data"))
		code, _, errOut := h.run("", "mount", "data:/x", "--root", "home")
		if code != 1 || !strings.Contains(errOut, `state "home" failed: no space left`) {
			t.Fatalf("code %d: %s", code, errOut)
		}
		if mounts := h.state("home").Spec.Mounts; len(mounts) != 0 {
			t.Fatalf("failed root written as intent: %+v", mounts)
		}
	})
	t.Run("failed source with committed version is usable", func(t *testing.T) {
		bad := failed("bad", "an earlier attempt failed")
		bad.Status.Committed = &v1alpha1.Commit{ID: "0123456789abcdef", Generation: 1}
		h := newHarness(t, readyState("home"), bad)
		if code, _, errOut := h.run("", "mount", "bad:/x", "--root", "home"); code != 0 {
			t.Fatalf("usable state rejected: %d %s", code, errOut)
		}
	})
	t.Run("removal from failed root stays allowed", func(t *testing.T) {
		root := failed("home", "no space left")
		root.Spec.Mounts = []v1alpha1.Mount{{State: "data", Path: "/data"}}
		h := newHarness(t, root, readyState("data"))
		if code, _, errOut := h.run("", "mount", "--rm", "data", "--root", "home"); code != 0 {
			t.Fatalf("removal rejected: %d %s", code, errOut)
		}
		if mounts := h.state("home").Spec.Mounts; len(mounts) != 0 {
			t.Fatalf("removal left intent: %+v", mounts)
		}
	})
}

// TestCreatedStateUnusedProtectsRunningWriter covers the rollback of a state
// created for a failed --new mount. The state may only be deleted once the
// running writer no longer reports or holds it; deleting it earlier makes the
// controller fail the execution with a discarded save.
func TestCreatedStateUnusedProtectsRunningWriter(t *testing.T) {
	newRoot := func(b *v1alpha1.Blip) *v1alpha1.BlipState {
		root := readyState(b.Spec.State)
		root.Status.Writer = &v1alpha1.Writer{BlipName: b.Name, BlipUID: string(b.UID)}
		return root
	}
	t.Run("failed writable entry keeps state", func(t *testing.T) {
		b := runningBlip("agent")
		b.Status.Mounts = []v1alpha1.MountStatus{{
			State: "leak", Path: "/blocker/x", Writable: true, Phase: v1alpha1.MountFailed, Message: "rejected",
		}}
		leak := readyState("leak")
		leak.Status.Writer = &v1alpha1.Writer{BlipName: b.Name, BlipUID: string(b.UID), AttachmentID: "pre-acquired"}
		a := mountTestApp(t, b, newRoot(b), leak)
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()
		if a.createdStateUnused(ctx, b.Spec.State, "leak") {
			t.Fatal("state still reported by the writer treated as unused")
		}
	})
	t.Run("attached writer keeps state", func(t *testing.T) {
		b := runningBlip("agent")
		leak := readyState("leak")
		leak.Status.Writer = &v1alpha1.Writer{BlipName: b.Name, BlipUID: string(b.UID), PodUID: "pod-agent"}
		a := mountTestApp(t, b, newRoot(b), leak)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		start := time.Now()
		if a.createdStateUnused(ctx, b.Spec.State, "leak") {
			t.Fatal("attached state treated as unused")
		}
		if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
			t.Fatalf("attached state was waited on: %s", elapsed)
		}
	})
	t.Run("root intent keeps state", func(t *testing.T) {
		b := runningBlip("agent")
		root := newRoot(b)
		root.Spec.Mounts = []v1alpha1.Mount{{State: "leak", Path: "/leak", Writable: true}}
		a := mountTestApp(t, b, root, readyState("leak"))
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()
		if a.createdStateUnused(ctx, b.Spec.State, "leak") {
			t.Fatal("state referenced by root intent treated as unused")
		}
	})
	t.Run("released state is unused", func(t *testing.T) {
		b := runningBlip("agent")
		a := mountTestApp(t, b, newRoot(b), readyState("leak"))
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if !a.createdStateUnused(ctx, b.Spec.State, "leak") {
			t.Fatal("released state still treated as in use")
		}
	})
}

// TestRemoveUnusedCreatedStatesKeepsReferencedState drives the rollback that
// follows a rejected --new mount: an unused state is removed, but one the
// running writer still reports is left in place so the controller does not
// fail the execution with a discarded save.
func TestRemoveUnusedCreatedStatesKeepsReferencedState(t *testing.T) {
	newApp := func(b *v1alpha1.Blip, root *v1alpha1.BlipState, leak *v1alpha1.BlipState) *app {
		root.Status.Writer = &v1alpha1.Writer{BlipName: b.Name, BlipUID: string(b.UID)}
		return mountTestApp(t, b, root, leak)
	}
	t.Run("referenced state stays", func(t *testing.T) {
		b := runningBlip("agent")
		leak := readyState("leak")
		leak.Status.Writer = &v1alpha1.Writer{BlipName: b.Name, BlipUID: string(b.UID)}
		b.Status.Mounts = []v1alpha1.MountStatus{{
			State: "leak", Path: "/blocker/x", Writable: true, Phase: v1alpha1.MountFailed, Message: "rejected",
		}}
		a := newApp(b, readyState(b.Spec.State), leak)
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()
		a.removeUnusedCreatedStates(ctx, b.Spec.State, "leak", "/blocker/x", []*v1alpha1.BlipState{leak})
		var st v1alpha1.BlipState
		if err := a.c.Kube.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: "leak"}, &st); err != nil {
			t.Fatalf("state still referenced by the writer was deleted: %v", err)
		}
	})
	t.Run("unused state is removed", func(t *testing.T) {
		b := runningBlip("agent")
		leak := readyState("leak")
		a := newApp(b, readyState(b.Spec.State), leak)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		a.removeUnusedCreatedStates(ctx, b.Spec.State, "leak", "/blocker/x", []*v1alpha1.BlipState{leak})
		var st v1alpha1.BlipState
		err := a.c.Kube.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: "leak"}, &st)
		if !apierrors.IsNotFound(err) {
			t.Fatalf("unused created state was not removed: %v", err)
		}
	})
}

// TestMountDeletedSourceWhileWriterStopsRollsBack reproduces a source deleted
// while the mount waits. The controller sets spec.stop before it publishes the
// deletion cause, so the CLI must re-read the source and remove the intent this
// command added instead of leaving a mount that later runs cannot resolve.
func TestMountDeletedSourceWhileWriterStopsRollsBack(t *testing.T) {
	b := runningBlip("writer")
	root := readyState(b.Spec.State)
	root.Status.Writer = &v1alpha1.Writer{BlipName: b.Name, BlipUID: string(b.UID)}
	data := readyState("data")
	a := mountTestApp(t, b, root, data)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	writable := true
	done := make(chan error, 1)
	go func() { done <- a.mountState(ctx, "data", root.Name, "/data", &writable) }()
	waitForCond(t, func() bool {
		s, err := a.getState(ctx, root.Name)
		return err == nil && findSpecMount(s.Spec.Mounts, "data") != nil
	})

	// Delete the source, then stop the writer without a status message, as
	// the controller's two-step stop does.
	if err := a.c.Kube.Delete(ctx, data); err != nil {
		t.Fatal(err)
	}
	cur, err := a.getBlip(ctx, b.Name)
	if err != nil {
		t.Fatal(err)
	}
	cur.Spec.Stop = true
	if err := a.c.Kube.Update(ctx, cur); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), `state "data" not found`) {
			t.Fatalf("mount returned %v, want the deleted-source cause", err)
		}
		if !strings.Contains(err.Error(), "desired mount was removed") {
			t.Fatalf("deleted source left intent: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("mount did not notice the deleted source")
	}
	s, err := a.getState(ctx, root.Name)
	if err != nil {
		t.Fatal(err)
	}
	if findSpecMount(s.Spec.Mounts, "data") != nil {
		t.Fatalf("deleted source left desired intent: %+v", s.Spec.Mounts)
	}
}

// TestMountNewMountFailureLeavesState ports create's attach-failure coverage:
// the created state keeps its first commit even when mounting it fails.
func TestMountNewMountFailureLeavesState(t *testing.T) {
	h := newHarness(t, runningBlip("agent"))
	h.ctrl.set(func(c *fakeController) { c.mountFail = "device gone" })
	code, _, errOut := h.run("", "mount", "--new", "data:/work", "--root", "agent-root")
	if code != 1 || !strings.Contains(errOut, "device gone") {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if s := h.state("data"); s.Status.Committed == nil {
		t.Fatal("state has no first commit")
	}
}
