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
