package cli

import (
	"bytes"
	"context"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/Azure/blip/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestRunForkOutsideGuestSnapshotsWorkspace(t *testing.T) {
	base := readyState("base")
	base.Spec.Image = "registry/base:v1"
	base.Spec.Runtime = &v1alpha1.RuntimeDefaults{User: "dev", WorkingDir: "/work", Env: []v1alpha1.EnvVar{{Name: "A", Value: "base"}}}
	base.Spec.Mounts = []v1alpha1.Mount{{State: "repo", Path: "/work", Writable: true}, {State: "tools", Path: "/tools"}, {State: "temporary", Path: "/tmp/collect", BlipUID: "previous"}}
	h := newHarness(t, base, readyState("repo"), readyState("tools"))
	code, out, errOut := h.run("", "run", "--name", "worker", "--from", "base", "--env", "A=execution", "--user", "root", "--workdir", "/override", "--", "true")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if strings.TrimSpace(out) != "worker" {
		t.Fatalf("output %q", out)
	}
	b, root := h.blip("worker"), h.state("worker")
	if b.Spec.State != "worker" || b.Spec.User != "root" || root.Spec.CopyFrom != "base" || root.Spec.Runtime.User != "dev" || root.Spec.Runtime.Env[0].Value != "base" || root.Spec.Runtime.WorkingDir != "/work" {
		t.Fatalf("blip %+v workspace %+v", b.Spec, root.Spec)
	}
	if len(root.Spec.Mounts) != 2 || root.Spec.Mounts[0].State == "repo" || root.Spec.Mounts[1].State != "tools" {
		t.Fatalf("mounts: %+v", root.Spec.Mounts)
	}
	// The blip owns the copies, so its deletion frees them.
	child := h.state(root.Spec.Mounts[0].State)
	for _, st := range []*v1alpha1.BlipState{root, child} {
		if len(st.OwnerReferences) != 1 || st.OwnerReferences[0].Name != "worker" {
			t.Fatalf("workspace ownership: %+v", st.OwnerReferences)
		}
	}
	// The snapshot exists before run returns, so a following fork starts from
	// the same version.
	if root.Status.Committed == nil {
		t.Fatalf("workspace has no snapshot: %+v", root.Status)
	}
}

func TestRunCreatesBlipBeforeItsOwnedStates(t *testing.T) {
	h := newHarness(t, readyState("base"))
	var creates []string
	h.kube = interceptor.NewClient(h.kube, interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
		if _, ok := obj.(*v1alpha1.Blip); ok {
			creates = append(creates, "blip")
		} else {
			creates = append(creates, "state")
		}
		return c.Create(ctx, obj, opts...)
	}})
	if code, _, errOut := h.run("", "run", "--name", "worker", "--from", "base", "--", "true"); code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if !reflect.DeepEqual(creates, []string{"blip", "state"}) {
		t.Fatalf("create ordering: %v", creates)
	}
	// The states are owned by the blip, so deleting it frees them.
	root := h.state("worker")
	if len(root.OwnerReferences) != 1 || root.OwnerReferences[0].Name != "worker" || root.OwnerReferences[0].Kind != "Blip" {
		t.Fatalf("owner references: %+v", root.OwnerReferences)
	}
}

func TestRunImportedBaseRequiresFork(t *testing.T) {
	base := readyState("base")
	base.Spec.Image = "registry/base:v1"
	h := newHarness(t, base)
	code, _, errOut := h.run("", "run", "--name", "worker", "--state", "base", "--", "true")
	if code != 1 || !strings.Contains(errOut, "use --from base") {
		t.Fatalf("code %d: %s", code, errOut)
	}
	var b v1alpha1.Blip
	if err := h.kube.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: "worker"}, &b); !apierrors.IsNotFound(err) {
		t.Fatalf("blip created: %v", err)
	}
}

func TestRunWithoutSourceOutsideBlip(t *testing.T) {
	h := newHarness(t)
	code, _, errOut := h.run("", "run", "--", "true")
	if code != 1 || !strings.Contains(errOut, "--from or --state") {
		t.Fatalf("code %d: %s", code, errOut)
	}
}

func TestRunForkFailureRemovesBlip(t *testing.T) {
	// The source exists but is being deleted, so the fork is rejected.
	gone := readyState("gone")
	now := metav1.Now()
	gone.DeletionTimestamp = &now
	gone.Finalizers = []string{"test"}
	h := newHarness(t, gone)
	code, _, errOut := h.run("", "run", "--name", "worker", "--from", "gone", "--", "true")
	if code != 1 || !strings.Contains(errOut, "being deleted") {
		t.Fatalf("code %d: %s", code, errOut)
	}
	var b v1alpha1.Blip
	if err := h.kube.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: "worker"}, &b); !apierrors.IsNotFound(err) {
		t.Fatalf("blip kept after failed fork: %v", err)
	}
}

func TestRunInsideBlipDefaultsToCallerRoot(t *testing.T) {
	box := ownedBlip("alice.box", "alice.home")
	box.Spec.Pool = "big"
	h := newHarness(t, box)
	h.self = "alice.box"
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	code, out, errOut := h.run("", "run", "--", "true")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	name := strings.TrimSpace(out)
	if !strings.HasPrefix(name, "box-") {
		t.Fatalf("auto name %q", name)
	}
	b := h.blip("alice." + name)
	if b.Spec.State != "alice."+name || b.Spec.Pool != "big" || b.Spec.WorkingDir != cwd {
		t.Fatalf("blip %+v", b.Spec)
	}
	if b.Spec.Command[0] != "true" {
		t.Fatalf("command %v", b.Spec.Command)
	}
	if b.Labels[v1alpha1.LabelParent] != "box" || b.Labels[v1alpha1.LabelOwner] != "alice" {
		t.Fatalf("labels %v", b.Labels)
	}
	if len(b.OwnerReferences) != 1 || b.OwnerReferences[0].Name != "alice.box" {
		t.Fatalf("owner references %+v", b.OwnerReferences)
	}
	root := h.state("alice." + name)
	if root.Spec.CopyFrom != "alice.home" || len(root.OwnerReferences) != 1 || root.OwnerReferences[0].Name != "alice."+name {
		t.Fatalf("fork %+v", root)
	}
	if b.Spec.ActiveDeadlineSeconds == nil || *b.Spec.ActiveDeadlineSeconds != int64(defaultForkTimeout.Seconds()) {
		t.Fatalf("deadline %v", b.Spec.ActiveDeadlineSeconds)
	}
	if b.Spec.TTLSecondsAfterFinished == nil || *b.Spec.TTLSecondsAfterFinished != int32(defaultForkTTL.Seconds()) {
		t.Fatalf("ttl %v", b.Spec.TTLSecondsAfterFinished)
	}
}

func TestRunStateInsideBlipInheritsCallerPool(t *testing.T) {
	box := ownedBlip("alice.box", "alice.home")
	box.Spec.Pool = "big"
	h := newHarness(t, box, readyState("alice.ws"))
	h.self = "alice.box"
	code, out, errOut := h.run("", "run", "--name", "child", "--state", "ws", "--", "true")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if strings.TrimSpace(out) != "child" {
		t.Fatalf("output %q", out)
	}
	b := h.blip("alice.child")
	if b.Spec.State != "alice.ws" || b.Spec.Pool != "big" {
		t.Fatalf("blip %+v", b.Spec)
	}

	// An explicit --pool still wins over the caller's.
	if code, _, errOut := h.run("", "run", "--name", "child2", "--state", "ws", "--pool", "default", "--", "true"); code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if got := h.blip("alice.child2").Spec.Pool; got != "default" {
		t.Fatalf("pool %q", got)
	}
}

func TestRunKeepLeavesWorkspaceOwnedByNobody(t *testing.T) {
	h := newHarness(t, ownedBlip("alice.box", "alice.home"))
	h.self = "alice.box"
	h.run("", "run", "--name", "w1", "--keep", "--ttl", "0", "--timeout", "0", "--", "true")
	b := h.blip("alice.w1")
	if len(b.OwnerReferences) != 0 {
		t.Fatalf("blip owner references %+v", b.OwnerReferences)
	}
	if b.Spec.TTLSecondsAfterFinished != nil || b.Spec.ActiveDeadlineSeconds != nil {
		t.Fatalf("lifetime %+v", b.Spec)
	}
	if root := h.state("alice.w1"); len(root.OwnerReferences) != 0 {
		t.Fatalf("state owner references %+v", root.OwnerReferences)
	}
}

func TestRunLabelsAndNameCollision(t *testing.T) {
	h := newHarness(t, readyState("base"))
	if code, _, errOut := h.run("", "run", "--name", "worker", "--from", "base", "--label", "team=a", "--", "true"); code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if b := h.blip("worker"); b.Labels["team"] != "a" {
		t.Fatalf("labels %v", b.Labels)
	}
	code, _, errOut := h.run("", "run", "--name", "worker", "--from", "base", "--", "true")
	if code != 1 || !strings.Contains(errOut, "already exists") {
		t.Fatalf("code %d: %s", code, errOut)
	}
	code, _, errOut = h.run("", "run", "--name", "worker2", "--label", "blip.dev/owner=x", "--", "true")
	if code != 1 || !strings.Contains(errOut, "reserved") {
		t.Fatalf("code %d: %s", code, errOut)
	}
}

func TestRunSurfacesForkStateFailure(t *testing.T) {
	h := newHarness(t, readyState("base"))
	h.ctrl.set(func(c *fakeController) { c.stateFail = "no space left" })
	code, _, errOut := h.run("", "run", "--name", "worker", "--from", "base", "--", "true")
	if code != 1 || !strings.Contains(errOut, "no space left") {
		t.Fatalf("code %d: %s", code, errOut)
	}
	var b v1alpha1.Blip
	if err := h.kube.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: "worker"}, &b); !apierrors.IsNotFound(err) {
		t.Fatalf("blip kept after failed fork: %v", err)
	}
}

func TestRunInterruptedDuringForkRemovesBlip(t *testing.T) {
	h := newHarness(t, readyState("base"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.kube = interceptor.NewClient(h.kube, interceptor.Funcs{
		Create: func(c context.Context, w client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			err := w.Create(c, obj, opts...)
			// Interrupt after the fork's workspace exists but before the
			// CLI has waited for it to become usable.
			if err == nil {
				if _, ok := obj.(*v1alpha1.BlipState); ok {
					cancel()
				}
			}
			return err
		},
	})
	var out, errb bytes.Buffer
	err := h.app(strings.NewReader(""), &out, &errb).run(ctx, []string{"true"}, &runFlags{name: "worker", from: "base"})
	if err == nil {
		t.Fatal("interrupted run succeeded")
	}
	if !h.gone("worker") {
		t.Fatal("interrupted run leaked its blip")
	}
}

func TestRunInterruptedWithStateKeepsWorkspace(t *testing.T) {
	h := newHarness(t, readyState("ws"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.kube = interceptor.NewClient(h.kube, interceptor.Funcs{
		Create: func(c context.Context, w client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			err := w.Create(c, obj, opts...)
			// Interrupt once the blip exists. launch is a no-op for
			// --state, so the CLI must notice the interrupt itself.
			if err == nil {
				if _, ok := obj.(*v1alpha1.Blip); ok {
					cancel()
				}
			}
			return err
		},
	})
	var out, errb bytes.Buffer
	err := h.app(strings.NewReader(""), &out, &errb).run(ctx, []string{"true"}, &runFlags{name: "worker", state: "ws"})
	if err == nil {
		t.Fatal("interrupted run succeeded")
	}
	if !h.gone("worker") {
		t.Fatal("interrupted run leaked its blip")
	}
	// The workspace existed before the run and is still owned by its owner.
	h.state("ws")
}

func TestRunRejectsInvalidDurations(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"--timeout", "-5s"}, "--timeout must not be negative"},
		{[]string{"--ttl", "-7s"}, "--ttl must not be negative"},
		{[]string{"--timeout", "3500ms"}, "--timeout must be a whole number of seconds"},
		{[]string{"--ttl", "1500ms"}, "--ttl must be a whole number of seconds"},
		{[]string{"--timeout", "500ms"}, "--timeout must be a whole number of seconds"},
	}
	for _, tc := range cases {
		h := newHarness(t, readyState("base"))
		args := append([]string{"run", "--name", "worker", "--from", "base"}, tc.args...)
		args = append(args, "--", "true")
		code, _, errOut := h.run("", args...)
		if code != 1 || !strings.Contains(errOut, tc.want) {
			t.Fatalf("%v: code %d: %s", tc.args, code, errOut)
		}
		if !h.gone("worker") {
			t.Fatalf("%v: blip created despite the invalid duration", tc.args)
		}
	}
}

func TestRunAcceptsWholeSecondDurations(t *testing.T) {
	h := newHarness(t, readyState("base"))
	code, _, errOut := h.run("", "run", "--name", "worker", "--from", "base", "--timeout", "90s", "--ttl", "60s", "--", "true")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	b := h.blip("worker")
	if b.Spec.ActiveDeadlineSeconds == nil || *b.Spec.ActiveDeadlineSeconds != 90 {
		t.Fatalf("deadline %v", b.Spec.ActiveDeadlineSeconds)
	}
	if b.Spec.TTLSecondsAfterFinished == nil || *b.Spec.TTLSecondsAfterFinished != 60 {
		t.Fatalf("ttl %v", b.Spec.TTLSecondsAfterFinished)
	}
}
