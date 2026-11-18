package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Azure/blip/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
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
	if code := Main(ctx, a.env, []string{"mount", "data", "home", "--path", "/data", "--write"}); code != 0 {
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
	if code := Main(ctx, a.env, []string{"unmount", "data", "home"}); code != 0 {
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
	if code := Main(ctx, a.env, []string{"mount", "base", "--path", "/base"}); code != 0 {
		t.Fatalf("mount code %d: %s", code, errOut.String())
	}
	s, _ := a.getState(ctx, root.Name)
	if len(s.Spec.Mounts) != 1 || s.Spec.Mounts[0].State != "base" {
		t.Fatalf("mounts %+v", s.Spec.Mounts)
	}
	if code := Main(ctx, a.env, []string{"mount", "base", "--path", "/base", "--write"}); code != 1 || !strings.Contains(errOut.String(), "imported base") {
		t.Fatalf("writable imported base: %d %s", code, errOut.String())
	}
	if code := Main(ctx, a.env, []string{"unmount", "base"}); code != 0 {
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
	code, _, errOut := h.run("", "mount", "data", b.Spec.State, "--path", "/data", "--write")
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
	code := Main(ctx, env, []string{"mount", "data", b.Spec.State, "--path", "/data", "--write"})
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
