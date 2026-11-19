package cli

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/Azure/blip/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestRunForkOutsideGuestSnapshotsWorkspace(t *testing.T) {
	base := readyState("base")
	base.Spec.Image = "registry/base:v1"
	base.Spec.Runtime = &v1alpha1.RuntimeDefaults{User: "dev", WorkingDir: "/work", Env: []v1alpha1.EnvVar{{Name: "A", Value: "base"}}}
	base.Spec.Mounts = []v1alpha1.Mount{{State: "repo", Path: "/work", Writable: true}, {State: "tools", Path: "/tools"}, {State: "temporary", Path: "/tmp/collect", BlipUID: "previous"}}
	h := newHarness(t, base, readyState("repo"), readyState("tools"))
	h.ctrl.set(func(c *fakeController) { c.autoFinish = true })
	var creates []string
	h.kube = interceptor.NewClient(h.kube, interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
		if b, ok := obj.(*v1alpha1.Blip); ok {
			root := &v1alpha1.BlipState{}
			if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: b.Spec.State}, root); err != nil {
				t.Fatalf("execution before state: %v", err)
			}
			creates = append(creates, "blip")
		} else {
			creates = append(creates, "state")
		}
		return c.Create(ctx, obj, opts...)
	}})
	code, _, errOut := h.run("", "run", "worker", "--fork", "base", "--env", "A=execution", "--user", "root", "--workdir", "/override", "--", "true")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if !reflect.DeepEqual(creates, []string{"state", "state", "blip"}) {
		t.Fatalf("create ordering: %v", creates)
	}
	b, root := h.blip("worker"), h.state("worker")
	if b.Spec.State != "worker" || b.Spec.User != "root" || root.Spec.CopyFrom != "base" || root.Spec.Runtime.User != "dev" || root.Spec.Runtime.Env[0].Value != "base" || root.Spec.Runtime.WorkingDir != "/work" {
		t.Fatalf("execution %+v workspace %+v", b.Spec, root.Spec)
	}
	if len(root.Spec.Mounts) != 2 || root.Spec.Mounts[0].State == "repo" || root.Spec.Mounts[1].State != "tools" {
		t.Fatalf("mounts: %+v", root.Spec.Mounts)
	}
	child := h.state(root.Spec.Mounts[0].State)
	if child.Spec.CopyFrom != "repo" || len(child.OwnerReferences) != 0 || len(root.OwnerReferences) != 0 {
		t.Fatalf("workspace ownership: %+v %+v", root, child)
	}
	if err := h.kube.Delete(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	h.state(root.Name)
	h.state(child.Name)
}

func TestRunImportedBaseRequiresFork(t *testing.T) {
	base := readyState("base")
	base.Spec.Image = "registry/base:v1"
	h := newHarness(t, base)
	code, _, errOut := h.run("", "run", "worker", "--state", "base", "--", "true")
	if code != 1 || !strings.Contains(errOut, "use --fork base") {
		t.Fatalf("code %d: %s", code, errOut)
	}
	var b v1alpha1.Blip
	if err := h.kube.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: "worker"}, &b); !apierrors.IsNotFound(err) {
		t.Fatalf("execution created: %v", err)
	}
}

func TestRunForkKeepsWorkspaceOnExecutionCreateFailure(t *testing.T) {
	h := newHarness(t, readyState("base"))
	h.kube = interceptor.NewClient(h.kube, interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
		if _, ok := obj.(*v1alpha1.Blip); ok {
			return errors.New("execution denied")
		}
		return c.Create(ctx, obj, opts...)
	}})
	code, _, errOut := h.run("", "run", "worker", "--fork", "base", "--", "true")
	if code != 1 || !strings.Contains(errOut, "execution denied") {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if root := h.state("worker"); root.Spec.CopyFrom != "base" || len(root.OwnerReferences) != 0 {
		t.Fatalf("workspace %+v", root)
	}
}

func TestOwnedForkSourceResolution(t *testing.T) {
	for _, own := range []bool{false, true} {
		t.Run(map[bool]string{false: "shared", true: "owned preferred"}[own], func(t *testing.T) {
			base := readyState("base")
			base.Spec.Image = "registry/base:v1"
			objects := []client.Object{ownedBlip("alice.box", "alice.home"), base}
			want := "base"
			if own {
				objects = append(objects, readyState("alice.base"))
				want = "alice.base"
			}
			h := newHarness(t, objects...)
			h.self = "alice.box"
			h.ctrl.set(func(c *fakeController) { c.autoFinish = true })
			code, _, errOut := h.run("", "run", "worker", "--fork", "base", "--", "true")
			if code != 0 {
				t.Fatalf("code %d: %s", code, errOut)
			}
			if st := h.state("alice.worker"); st.Spec.CopyFrom != want || st.Labels[v1alpha1.LabelOwner] != "alice" {
				t.Fatalf("fork %+v", st)
			}
		})
	}
}
