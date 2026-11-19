// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package controller

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/podapi"
)

func (e *env) setDrain(node string) {
	e.t.Helper()
	bn := &v1.BlipNode{}
	e.must(e.c.Get(e.ctx, types.NamespacedName{Name: node}, bn))
	bn.Spec.Drain = true
	e.must(e.c.Update(e.ctx, bn))
}

// removeNode deletes both objects that represent a node.
func (e *env) removeNode(node string) {
	e.t.Helper()
	e.must(e.c.Delete(e.ctx, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: node}}))
	e.must(e.c.Delete(e.ctx, &v1.BlipNode{ObjectMeta: metav1.ObjectMeta{Name: node}}))
}

func (e *env) safeToRemove(node string) bool {
	e.t.Helper()
	e.run(e.node, "", node)
	bn := &v1.BlipNode{}
	e.must(e.c.Get(e.ctx, types.NamespacedName{Name: node}, bn))
	return bn.Status.SafeToRemove
}

func TestStateInitialization(t *testing.T) {
	size20G := resource.MustParse("20Gi")
	size200G := resource.MustParse("200Gi")
	size1Pi := resource.MustParse("1Pi")
	zeroSize := resource.MustParse("0")
	negativeSize := resource.MustParse("-1Gi")
	hugeSize := resource.MustParse("10Ei")
	maxInt64Size := resource.MustParse("9223372036854775807")
	tests := []struct {
		name    string
		spec    v1.BlipStateSpec
		size    int64
		nodes   int // pending replicas; default spec.replicas
		message string
		phase   string
	}{
		{name: "empty", spec: v1.BlipStateSpec{Replicas: 2}, size: 10 << 30},
		{name: "empty size", spec: v1.BlipStateSpec{Replicas: 2, Size: &size20G}, size: 20 << 30},
		{name: "zero size", spec: v1.BlipStateSpec{Replicas: 2, Size: &zeroSize}, message: "size 0 must be greater than 0", phase: v1.StateFailed},
		{name: "negative size", spec: v1.BlipStateSpec{Replicas: 2, Size: &negativeSize}, message: "size -1Gi must be greater than 0", phase: v1.StateFailed},
		{name: "huge size", spec: v1.BlipStateSpec{Replicas: 2, Size: &hugeSize}, message: "too large", phase: v1.StateFailed},
		{name: "max int64 size", spec: v1.BlipStateSpec{Replicas: 2, Size: &maxInt64Size}, message: "too large", phase: v1.StateFailed},
		{name: "previous maximum size", spec: v1.BlipStateSpec{Replicas: 2, Size: &size1Pi}, message: "too large", phase: v1.StateFailed},
		{name: "size beyond node free", spec: v1.BlipStateSpec{Replicas: 1, Size: &size200G}, message: "has only 100Gi free", phase: v1.StateFailed},
		{name: "image", spec: v1.BlipStateSpec{Image: "reg/img:v1"}, size: 10 << 30, nodes: 2},
		{name: "image size", spec: v1.BlipStateSpec{Image: "reg/img:v1", Size: &size20G}, size: 20 << 30, nodes: 2},
		{name: "missing image", spec: v1.BlipStateSpec{Image: "reg/nope:v1"}, message: "image reg/nope:v1: not found", phase: v1.StateFailed},
		{name: "invalid image", spec: v1.BlipStateSpec{Image: "bad image!!"}, message: "invalid image reference", phase: v1.StateFailed},
		{name: "missing copy source", spec: v1.BlipStateSpec{CopyFrom: "nope", Replicas: 1}, message: `copy source "nope" not found`, phase: v1.StateFailed},
		{name: "no matching nodes", spec: v1.BlipStateSpec{Replicas: 1, NodeSelector: map[string]string{"zone": "x"}}, message: "no eligible node can hold the state; retrying"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			e.addNodes("n1", "n2")
			e.create(&v1.BlipState{ObjectMeta: metadata("s"), Spec: tt.spec})
			e.run(e.state, ns, "s")
			e.run(e.state, ns, "s")
			st := e.getState("s")
			want := v1.StatePending
			if tt.phase != "" {
				want = tt.phase
			}
			if st.Status.Phase != want {
				t.Fatalf("phase %s", st.Status.Phase)
			}
			if tt.message != "" {
				if st.Status.Pending != nil || !strings.Contains(st.Status.Message, tt.message) {
					t.Fatalf("status %+v, want message %q", st.Status, tt.message)
				}
				return
			}
			nodes := int(tt.spec.Replicas)
			if tt.nodes > 0 {
				nodes = tt.nodes
			}
			if p := st.Status.Pending; p == nil || len(p.Replicas) != nodes || st.Status.SizeBytes != tt.size {
				t.Fatalf("status %+v", st.Status)
			}
		})
	}
}

// imageConfigNotFound resolves any digest reference but reports its image
// config as missing, like a syntactically valid digest that the registry does
// not have.
type imageConfigNotFound struct{}

func (imageConfigNotFound) Digest(_ context.Context, ref, _ string, _ []corev1.LocalObjectReference) (string, error) {
	return ref, nil
}

func (imageConfigNotFound) ImageConfig(_ context.Context, ref, _ string, _ []corev1.LocalObjectReference) (*v1.ImageConfig, error) {
	return nil, fmt.Errorf("image config %s: %w", ref, ErrImageNotFound)
}

// imageConfigUnsupported resolves any digest but reports that the pinned image
// has no manifest for the node platform.
type imageConfigUnsupported struct{}

func (imageConfigUnsupported) Digest(_ context.Context, ref, _ string, _ []corev1.LocalObjectReference) (string, error) {
	return ref, nil
}

func (imageConfigUnsupported) ImageConfig(_ context.Context, ref, _ string, _ []corev1.LocalObjectReference) (*v1.ImageConfig, error) {
	return nil, fmt.Errorf("%w: image config %s: no child with platform linux/amd64", ErrUnsupportedImage, ref)
}

func TestStatePlatformMismatchFailsTerminally(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.state.Registry = imageConfigUnsupported{}
	ref := "reg/img@sha256:" + strings.Repeat("1", 64)
	e.newState("s", func(st *v1.BlipState) {
		st.Spec.Image, st.Spec.Replicas = ref, 0
	})
	e.run(e.state, ns, "s")
	st := e.getState("s")
	if st.Status.Phase != v1.StateFailed || st.Status.Pending != nil {
		t.Fatalf("platform mismatch not terminal: %+v", st.Status)
	}
	if !strings.Contains(st.Status.Message, "no manifest for this platform") ||
		!strings.Contains(st.Status.Message, "no child with platform") {
		t.Fatalf("message %q does not explain the platform mismatch", st.Status.Message)
	}
}

func TestStateMissingDigestFails(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.state.Registry = imageConfigNotFound{}
	ref := "reg/img@sha256:" + strings.Repeat("1", 64)
	e.newState("s", func(st *v1.BlipState) {
		st.Spec.Image, st.Spec.Replicas = ref, 0
	})
	e.run(e.state, ns, "s")
	st := e.getState("s")
	if st.Status.Phase != v1.StateFailed || st.Status.Pending != nil {
		t.Fatalf("missing digest not terminal: %+v", st.Status)
	}
	if !strings.Contains(st.Status.Message, "not found") {
		t.Fatalf("message %q does not explain the missing digest", st.Status.Message)
	}
}

func TestStateUnusablePullSecretFails(t *testing.T) {
	tests := []struct {
		name   string
		secret *corev1.Secret
		ref    string
		want   string
	}{
		{name: "missing", ref: "missing", want: `image pull secret ns/missing`},
		{
			name: "wrong type",
			ref:  "opaque",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "opaque"},
				Type:       corev1.SecretTypeOpaque,
				Data:       map[string][]byte{"foo": []byte("bar")},
			},
			want: "type Opaque has no .dockerconfigjson",
		},
		{
			name: "bad dockerconfigjson",
			ref:  "bad",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "bad"},
				Type:       corev1.SecretTypeDockerConfigJson,
				Data:       map[string][]byte{corev1.DockerConfigJsonKey: []byte(`{`)},
			},
			want: "invalid .dockerconfigjson",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			e.addNodes("n1", "n2")
			e.state.Registry = RemoteRegistry{Reader: e.c}
			if tt.secret != nil {
				e.create(tt.secret)
			}
			e.newState("s", func(st *v1.BlipState) {
				st.Spec.Image = "reg/img:v1"
				st.Spec.Replicas = 0
				st.Spec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: tt.ref}}
			})
			e.run(e.state, ns, "s")
			st := e.getState("s")
			if st.Status.Phase != v1.StateFailed || st.Status.Pending != nil {
				t.Fatalf("unusable pull secret not terminal: %+v", st.Status)
			}
			if !strings.Contains(st.Status.Message, tt.want) {
				t.Fatalf("message %q does not contain %q", st.Status.Message, tt.want)
			}
		})
	}
}

// TestStateRejectedCredentialsFailTerminally is the controller side of the
// `blip pull` hang: a 401 from a registry with the state's immutable
// imagePullSecrets must fail the state, because the CLI waits for a commit
// (or a terminal phase) and would otherwise stay on Pending forever.
func TestStateRejectedCredentialsFailTerminally(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"details":"incorrect username or password"}`)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)

	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.state.Registry = RemoteRegistry{Reader: e.c}
	e.create(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "badcred"},
		Type:       corev1.SecretTypeDockerConfigJson,
		Data: map[string][]byte{corev1.DockerConfigJsonKey: []byte(
			fmt.Sprintf(`{"auths":{%q:{"username":"nouser","password":"definitely-wrong"}}}`, u.Host))},
	})
	e.newState("s", func(st *v1.BlipState) {
		st.Spec.Image = u.Host + "/library/hello-world:latest"
		st.Spec.Replicas = 0
		st.Spec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: "badcred"}}
	})
	e.run(e.state, ns, "s")
	st := e.getState("s")
	if st.Status.Phase != v1.StateFailed || st.Status.Pending != nil {
		t.Fatalf("rejected credentials not terminal: %+v", st.Status)
	}
	if !strings.Contains(st.Status.Message, "registry rejected image pull credentials") ||
		!strings.Contains(st.Status.Message, "incorrect username or password") {
		t.Fatalf("message %q does not explain the rejected credentials", st.Status.Message)
	}
}

func TestStateCopyFromSelfFails(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newState("self", func(st *v1.BlipState) {
		st.Spec.CopyFrom = "self"
		st.Spec.Replicas = 1
	})
	e.run(e.state, ns, "self")
	st := e.getState("self")
	if st.Status.Phase != v1.StateFailed || st.Status.Pending != nil || st.Status.CopiedFrom != nil {
		t.Fatalf("self copy not rejected: %+v", st.Status)
	}
	if !strings.Contains(st.Status.Message, "state itself") {
		t.Fatalf("message %q does not explain the self copy", st.Status.Message)
	}
}

func TestStateCopyCycleFails(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newState("a", func(st *v1.BlipState) {
		st.Spec.CopyFrom = "b"
		st.Spec.Replicas = 1
	})
	e.newState("b", func(st *v1.BlipState) {
		st.Spec.CopyFrom = "a"
		st.Spec.Replicas = 1
	})
	for _, name := range []string{"a", "b"} {
		e.run(e.state, ns, name)
		st := e.getState(name)
		if st.Status.Phase != v1.StateFailed || st.Status.Pending != nil || st.Status.CopiedFrom != nil {
			t.Fatalf("copy cycle at %s not rejected: %+v", name, st.Status)
		}
		if !strings.Contains(st.Status.Message, "copy source cycle") {
			t.Fatalf("message %q does not explain the cycle", st.Status.Message)
		}
	}
}

func TestStateCopyFromFailedSourceFails(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.create(&v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{Name: "src", Namespace: ns, Generation: 1},
		Spec:       v1.BlipStateSpec{Replicas: 1},
		Status: v1.BlipStateStatus{
			Phase:   v1.StateFailed,
			Message: "storage: disk broke",
		},
	})
	e.newState("cp", func(st *v1.BlipState) {
		st.Spec.CopyFrom = "src"
		st.Spec.Replicas = 1
	})
	e.run(e.state, ns, "cp")
	st := e.getState("cp")
	if st.Status.Phase != v1.StateFailed || st.Status.Pending != nil {
		t.Fatalf("copy of failed source not rejected: %+v", st.Status)
	}
	for _, want := range []string{`copy source "src" failed`, "disk broke"} {
		if !strings.Contains(st.Status.Message, want) {
			t.Fatalf("message %q does not contain %q", st.Status.Message, want)
		}
	}
}

func TestStateAcyclicCopyWaits(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newState("base", func(st *v1.BlipState) { st.Spec.Replicas = 1 })
	e.newState("cp", func(st *v1.BlipState) {
		st.Spec.CopyFrom = "base"
		st.Spec.Replicas = 1
	})
	e.run(e.state, ns, "cp")
	st := e.getState("cp")
	if st.Status.Phase != v1.StatePending || st.Status.Pending != nil || !strings.Contains(st.Status.Message, `waiting for copy source "base" to commit`) {
		t.Fatalf("acyclic copy did not wait for its source: %+v", st.Status)
	}
}

func TestCopySizeValidation(t *testing.T) {
	const sourceSize = 10 << 30
	srcSize := resource.MustParse("10Gi")
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newState("src", func(st *v1.BlipState) {
		st.Spec.Replicas = 1
		st.Spec.Size = &srcSize
	})
	e.run(e.state, ns, "src")
	src := e.getState("src")
	if src.Status.Pending == nil {
		t.Fatalf("source pending %+v", src.Status)
	}
	e.hold("src", src.Status.Pending.CommitID, src.Status.Pending.Replicas...)
	e.run(e.state, ns, "src")
	if src = e.getState("src"); src.Status.Phase != v1.StateReady || src.Status.SizeBytes != sourceSize {
		t.Fatalf("source not committed at the expected size: %+v", src.Status)
	}

	// A requested size smaller than the source is rejected instead of being
	// silently raised to the source size.
	smallSize := resource.MustParse("1Gi")
	e.newState("small", func(st *v1.BlipState) {
		st.Spec.Replicas = 1
		st.Spec.CopyFrom = "src"
		st.Spec.Size = &smallSize
	})
	e.run(e.state, ns, "small")
	small := e.getState("small")
	if small.Status.Phase != v1.StateFailed || small.Status.Pending != nil {
		t.Fatalf("small copy not rejected: %+v", small.Status)
	}
	for _, want := range []string{"1Gi", `"src"`, "10Gi", "smaller than copy source"} {
		if !strings.Contains(small.Status.Message, want) {
			t.Fatalf("message %q does not contain %q", small.Status.Message, want)
		}
	}

	// An omitted size still inherits the source size.
	e.newState("inherit", func(st *v1.BlipState) {
		st.Spec.Replicas = 1
		st.Spec.CopyFrom = "src"
	})
	e.run(e.state, ns, "inherit")
	inherit := e.getState("inherit")
	if inherit.Status.Pending == nil || inherit.Status.SizeBytes != sourceSize {
		t.Fatalf("copy did not inherit the source size: %+v", inherit.Status)
	}

	// A requested size larger than the source is honored.
	largeSize := resource.MustParse("20Gi")
	e.newState("large", func(st *v1.BlipState) {
		st.Spec.Replicas = 1
		st.Spec.CopyFrom = "src"
		st.Spec.Size = &largeSize
	})
	e.run(e.state, ns, "large")
	large := e.getState("large")
	if large.Status.Pending == nil || large.Status.SizeBytes != 20<<30 {
		t.Fatalf("larger copy size not honored: %+v", large.Status)
	}
}

// TestCopySkipsFullPreferredSourceNode covers a copy whose preferred source
// node is now too full for the copy. The source is only a read source, so the
// copy must use another target that fits instead of failing terminally.
func TestCopySkipsFullPreferredSourceNode(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2", "n3")
	size := resource.MustParse("20Gi")
	e.newState("src", func(st *v1.BlipState) {
		st.Spec.Replicas = 2
		st.Spec.Size = &size
	})
	e.run(e.state, ns, "src")
	src := e.getState("src")
	e.hold("src", src.Status.Pending.CommitID, src.Status.Pending.Replicas...)
	e.run(e.state, ns, "src")
	src = e.getState("src")
	if src.Status.Phase != v1.StateReady || !slices.Contains(src.Status.Placements, "n1") {
		t.Fatalf("source not ready on n1: %+v", src.Status)
	}

	bn := &v1.BlipNode{}
	e.must(e.c.Get(e.ctx, types.NamespacedName{Name: "n1"}, bn))
	bn.Status.FreeBytes = 1 << 30
	e.must(e.c.Status().Update(e.ctx, bn))

	e.newState("cp", func(st *v1.BlipState) {
		st.Spec.CopyFrom = "src"
		st.Spec.Replicas = 2
	})
	e.run(e.state, ns, "cp")
	cp := e.getState("cp")
	if cp.Status.Phase == v1.StateFailed || cp.Status.Pending == nil {
		t.Fatalf("copy failed on a full preferred source: %+v", cp.Status)
	}
	if !slices.Equal(cp.Status.Pending.Replicas, []string{"n2", "n3"}) {
		t.Fatalf("copy targets %v, want the nodes with room", cp.Status.Pending.Replicas)
	}
}

func TestInitialReplicaWaitsForSource(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newState("s", func(st *v1.BlipState) { st.Spec.Replicas = 2 })
	e.run(e.state, ns, "s")
	p := e.getState("s").Status.Pending
	if p == nil {
		t.Fatal("no pending initial version")
	}
	replica := "n1"
	if p.SourceNode == replica {
		replica = "n2"
	}

	// The replica cannot see the commit until the source publishes it.
	e.report("s", replica, func(o *v1.NodeObservation) {
		o.Error = "no healthy holder of commit " + p.CommitID + " (source node " + p.SourceNode + ")"
	})
	e.run(e.state, ns, "s")
	st := e.getState("s")
	if st.Status.Phase != v1.StatePending || st.Status.Committed != nil {
		t.Fatalf("transient replica error failed the state: %+v", st.Status)
	}
	if !strings.Contains(st.Status.Message, "waiting") {
		t.Fatalf("message %q does not say waiting", st.Status.Message)
	}

	// The source publishes the commit and the replica fetches it.
	e.hold("s", p.CommitID, p.SourceNode)
	e.report("s", replica, func(o *v1.NodeObservation) {
		o.Error = ""
		o.Commits = append(o.Commits, p.CommitID)
	})
	e.run(e.state, ns, "s")
	if st = e.getState("s"); st.Status.Phase != v1.StateReady || st.Status.Committed == nil {
		t.Fatalf("state did not become ready: %+v", st.Status)
	}
}

func TestInitialReplicaErrorAfterSourceFailsState(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newState("s", func(st *v1.BlipState) { st.Spec.Replicas = 2 })
	e.run(e.state, ns, "s")
	p := e.getState("s").Status.Pending
	if p == nil {
		t.Fatal("no pending initial version")
	}
	replica := "n1"
	if p.SourceNode == replica {
		replica = "n2"
	}

	// Once the source holds the commit, a replica error is no longer just
	// status lag; it must surface as a failed initialization.
	e.hold("s", p.CommitID, p.SourceNode)
	e.report("s", replica, func(o *v1.NodeObservation) {
		o.Error = "storage: no space left on device"
	})
	e.run(e.state, ns, "s")
	st := e.getState("s")
	if st.Status.Phase != v1.StateFailed || !strings.Contains(st.Status.Message, "no space") {
		t.Fatalf("replica error not surfaced: %+v", st.Status)
	}
}

// TestStaleIncarnationErrorIgnored keeps an error from an earlier node
// incarnation from settling or failing a healthy initial build. The entry is
// stale: the node lost the storage it described.
func TestStaleIncarnationErrorIgnored(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newState("s", func(st *v1.BlipState) { st.Spec.Replicas = 2 })
	e.run(e.state, ns, "s")
	p := e.getState("s").Status.Pending
	if p == nil {
		t.Fatal("no pending initial version")
	}
	replica := "n1"
	if p.SourceNode == replica {
		replica = "n2"
	}
	e.report("s", p.SourceNode, func(o *v1.NodeObservation) {
		o.Incarnation = "old-inc"
		o.Error = "boom from the previous incarnation"
		o.Commits = nil
	})
	e.report("s", replica, func(o *v1.NodeObservation) {
		o.Error = "storage: no space left on device"
	})
	e.run(e.state, ns, "s")
	st := e.getState("s")
	if st.Status.Phase == v1.StateFailed {
		t.Fatalf("stale incarnation error settled the initial source: %+v", st.Status)
	}
	if strings.Contains(st.Status.LastError, "previous incarnation") {
		t.Fatalf("lastError exposed a stale incarnation error: %q", st.Status.LastError)
	}

	// Without the replica's own error nothing should fail: the source is
	// still healthy and simply has not published the commit yet.
	e.report("s", replica, func(o *v1.NodeObservation) { o.Error = "" })
	e.run(e.state, ns, "s")
	st = e.getState("s")
	if st.Status.Phase != v1.StatePending || !strings.Contains(st.Status.Message, "waiting") || st.Status.LastError != "" {
		t.Fatalf("stale incarnation error failed a healthy build: %+v", st.Status)
	}
}

func TestPendingReplicaReplaced(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2", "n3")
	e.newState("s")
	e.run(e.state, ns, "s")
	p := e.getState("s").Status.Pending
	lost := p.Replicas[1]
	e.must(e.c.Delete(e.ctx, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: lost}}))
	e.run(e.state, ns, "s")
	p = e.getState("s").Status.Pending
	if slices.Contains(p.Replicas, lost) || len(p.Replicas) != 2 {
		t.Fatalf("replicas %v still contain deleted node %s", p.Replicas, lost)
	}
}

// TestPendingSaveCommitsWithLostReplica covers a save whose replica node
// disappears and has no replacement: the source still holds the sealed
// commit, so the state commits with the survivors instead of waiting for the
// dead node forever. repair tops the replicas back up later.
func TestPendingSaveCommitsWithLostReplica(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.readyState("s", "n1", "n2")
	st := e.getState("s")
	const saved = "c9c9c9c9c9c9c9c9"
	const losing = "7777777777777777"
	base := st.DeepCopy()
	st.Status.Pending = &v1.PendingCommit{
		CommitID:     saved,
		Generation:   2,
		SourceNode:   "n1",
		AttachmentID: losing,
		Replicas:     []string{"n1", "n2"},
	}
	e.must(patchStatus(e.ctx, e.c, st, base))
	e.seal("s", "n1", v1.SealResult{AttachmentID: losing, CommitID: saved})
	e.hold("s", saved, "n1")

	// n2 dies before it fetches the commit and there is no other node.
	dead := "n2"
	e.removeNode(dead)

	e.run(e.state, ns, "s")
	st = e.getState("s")
	if st.Status.Pending != nil || st.Status.Committed == nil || st.Status.Committed.ID != saved {
		t.Fatalf("save with a lost replica did not commit with survivors: %+v", st.Status)
	}
	if st.Status.Committed.Generation != 2 {
		t.Fatalf("commit generation %d", st.Status.Committed.Generation)
	}
	if slices.Contains(st.Status.Placements, dead) {
		t.Fatalf("lost replica kept a placement: %v", st.Status.Placements)
	}

	// A recovered node is picked up by repair.
	e.addNodes("n3")
	e.run(e.state, ns, "s")
	st = e.getState("s")
	if !slices.Contains(st.Status.Placements, "n3") {
		t.Fatalf("repair did not top up the lost replica: %v", st.Status.Placements)
	}
	e.hold("s", saved, "n3")
	e.run(e.state, ns, "s")
	st = e.getState("s")
	if !slices.Equal(st.Status.Placements, []string{"n1", "n3"}) {
		t.Fatalf("placements after repair: %v", st.Status.Placements)
	}
}

func TestDrainingSaveSourceCommitsWithLostReplica(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	st := e.readyState("s", "n1", "n2")
	const saved = "draining-source-save"
	st.Status.Pending = &v1.PendingCommit{
		CommitID: saved, Generation: 2, SourceNode: "n1",
		AttachmentID: "save", Replicas: []string{"n1", "n2"},
	}
	e.must(e.c.Status().Update(e.ctx, st))
	e.hold("s", saved, "n1")
	e.setDrain("n1")
	e.removeNode("n2")
	e.run(e.state, ns, "s")
	st = e.getState("s")
	if st.Status.Pending != nil || st.Status.Committed.ID != saved || !slices.Equal(st.Status.Placements, []string{"n1"}) {
		t.Fatalf("healthy draining source stranded its save after replica loss: %+v", st.Status)
	}
	if e.safeToRemove("n1") {
		t.Fatal("the only surviving save replica must remain until repaired")
	}
}

// TestDrainingSaveFallsBackAfterBound covers a save whose replicas cannot
// fetch from the draining source the controller considers serving. Waiting for
// a node that can never fetch would wedge the save, the Blip, and the state
// finalizer; after drainSaveFallback the state commits on the source and
// repair replicates it later.
func TestDrainingSaveFallsBackAfterBound(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	st := e.readyState("s", "n1", "n2")
	const saved = "draining-bound-save"
	since := metav1.NewTime(e.now)
	st.Status.Pending = &v1.PendingCommit{
		CommitID: saved, Generation: 2, SourceNode: "n1",
		AttachmentID: "save", Replicas: []string{"n1", "n2"}, Since: &since,
	}
	e.must(e.c.Status().Update(e.ctx, st))
	e.hold("s", saved, "n1")
	e.setDrain("n1")

	e.run(e.state, ns, "s")
	if st = e.getState("s"); st.Status.Pending == nil || st.Status.Committed.ID == saved {
		t.Fatalf("save committed before the fallback bound: %+v", st.Status)
	}

	e.now = e.now.Add(drainSaveFallback + time.Second)
	e.heartbeat()
	e.run(e.state, ns, "s")
	st = e.getState("s")
	if st.Status.Pending != nil || st.Status.Committed == nil || st.Status.Committed.ID != saved {
		t.Fatalf("draining save did not fall back after %s: %+v", drainSaveFallback, st.Status)
	}
	if !slices.Equal(st.Status.Placements, []string{"n1"}) {
		t.Fatalf("fallback placements %v, want the source that holds the commit", st.Status.Placements)
	}
}

// TestDrainingSaveFallbackClearsFinalizer checks the end-to-end unblock: once
// the fallback commit resolves the attachment, deleting the Blip removes its
// finalizer instead of waiting forever on the stuck save.
func TestDrainingSaveFallbackClearsFinalizer(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	st := e.readyState("s", "n1", "n2")
	const saved = "draining-finalizer-save"
	since := metav1.NewTime(e.now.Add(-drainSaveFallback - time.Second))
	st.Status.Pending = &v1.PendingCommit{
		CommitID: saved, Generation: 2, SourceNode: "n1",
		AttachmentID: "save", Replicas: []string{"n1", "n2"}, Since: &since,
	}
	st.Status.Seals = []v1.SealResult{{AttachmentID: "save", CommitID: saved}}
	e.must(e.c.Status().Update(e.ctx, st))
	e.hold("s", saved, "n1")
	e.setDrain("n1")

	code := int32(0)
	e.newBlip("b", withRoot("s"))
	b := e.getBlip("b")
	b.Finalizers = []string{v1.Finalizer}
	b.Status.Phase = v1.BlipSaving
	b.Status.RootAttachmentID = "save"
	b.Status.ExitCode = &code
	e.must(e.c.Update(e.ctx, b))
	e.must(e.c.Status().Update(e.ctx, b))
	e.must(e.c.Delete(e.ctx, b))

	e.run(e.state, ns, "s")
	if st = e.getState("s"); st.Status.Pending != nil || st.Status.Committed.ID != saved {
		t.Fatalf("state did not resolve the save: %+v", st.Status)
	}
	e.run(e.blip, ns, "b")
	b = &v1.Blip{}
	if err := e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: "b"}, b); err == nil {
		if len(b.Finalizers) != 0 {
			t.Fatalf("stuck save kept the Blip finalizer: %v", b.Finalizers)
		}
	}
}

// TestSaveFallsBackAfterReplicaErrorBound covers a save that cannot complete
// because a healthy replica keeps reporting a fetch error (for example a
// node-local device problem that makes every retry fail with "Device or
// resource busy"). Waiting forever would wedge the save, the Blip, and both
// finalizers; after replicaErrorFallback the state commits with the node that
// holds the version and repair can replicate it later.
func TestSaveFallsBackAfterReplicaErrorBound(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.readyState("s", "n1", "n2")
	const saved = "failing-replica-save"
	since := metav1.NewTime(e.now)
	st := e.getState("s")
	st.Status.Pending = &v1.PendingCommit{
		CommitID: saved, Generation: 2, SourceNode: "n1",
		AttachmentID: "save", Replicas: []string{"n1", "n2"}, Since: &since,
	}
	e.must(e.c.Status().Update(e.ctx, st))
	e.hold("s", saved, "n1")
	e.report("s", "n2", func(o *v1.NodeObservation) {
		o.Error = "fetch blip-n2-c: device-mapper: create ioctl failed: Device or resource busy"
	})

	if res := e.run(e.state, ns, "s"); res.RequeueAfter <= 0 {
		t.Fatal("pending save scheduled no wake-up before its fallback bound")
	}
	if st = e.getState("s"); st.Status.Pending == nil || st.Status.Committed.ID == saved {
		t.Fatalf("save committed before the replica error bound: %+v", st.Status)
	}
	if !strings.Contains(st.Status.LastError, "resource busy") {
		t.Fatalf("lastError lost the fetch error: %q", st.Status.LastError)
	}

	e.now = e.now.Add(replicaErrorFallback + time.Second)
	e.heartbeat()
	e.run(e.state, ns, "s")
	st = e.getState("s")
	if st.Status.Pending != nil || st.Status.Committed == nil || st.Status.Committed.ID != saved {
		t.Fatalf("save did not fall back after %s: %+v", replicaErrorFallback, st.Status)
	}
	if !slices.Equal(st.Status.Placements, []string{"n1"}) {
		t.Fatalf("fallback placements %v, want the holder", st.Status.Placements)
	}
	if !strings.Contains(st.Status.Message, "fewer replicas") || !strings.Contains(st.Status.Message, "resource busy") {
		t.Fatalf("fallback did not explain the dropped replica: %q", st.Status.Message)
	}
}

// TestStaleIncarnationErrorDoesNotDropSaveReplica checks that a stale error
// cannot make a save drop a replica after the error bound.
func TestStaleIncarnationErrorDoesNotDropSaveReplica(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.readyState("s", "n1", "n2")
	const saved = "stale-incarnation-save"
	since := metav1.NewTime(e.now.Add(-replicaErrorFallback - time.Second))
	st := e.getState("s")
	st.Status.Pending = &v1.PendingCommit{
		CommitID: saved, Generation: 2, SourceNode: "n1",
		AttachmentID: "save", Replicas: []string{"n1", "n2"}, Since: &since,
	}
	e.must(e.c.Status().Update(e.ctx, st))
	e.hold("s", saved, "n1")
	e.report("s", "n2", func(o *v1.NodeObservation) {
		o.Incarnation = "old-inc"
		o.Error = "boom from the previous incarnation"
		o.Commits = nil
	})
	e.run(e.state, ns, "s")
	st = e.getState("s")
	if st.Status.Pending == nil || !slices.Equal(st.Status.Pending.Replicas, []string{"n1", "n2"}) {
		t.Fatalf("stale incarnation error dropped a save replica: %+v", st.Status)
	}
	if strings.Contains(st.Status.LastError, "previous incarnation") {
		t.Fatalf("lastError exposed a stale incarnation error: %q", st.Status.LastError)
	}
}

// TestReplicaErrorFallbackFailsLostSave checks the safe side: when no node at
// all holds the sealed version, the bound fails the save instead of committing
// data that does not exist or waiting forever.
func TestReplicaErrorFallbackFailsLostSave(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.readyState("s", "n1", "n2")
	since := metav1.NewTime(e.now.Add(-replicaErrorFallback - time.Second))
	st := e.getState("s")
	st.Status.Pending = &v1.PendingCommit{
		CommitID: "unheld-save", Generation: 2, SourceNode: "n1",
		AttachmentID: "save", Replicas: []string{"n1", "n2"}, Since: &since,
	}
	e.must(e.c.Status().Update(e.ctx, st))
	e.report("s", "n1", func(o *v1.NodeObservation) { o.Error = "cannot seal" })
	e.report("s", "n2", func(o *v1.NodeObservation) { o.Error = "cannot fetch" })

	e.run(e.state, ns, "s")
	st = e.getState("s")
	if st.Status.Committed.ID == "unheld-save" {
		t.Fatalf("committed a save no node holds: %+v", st.Status)
	}
	if st.Status.Pending != nil {
		t.Fatalf("lost save still waiting: %+v", st.Status.Pending)
	}
	found := false
	for _, sr := range st.Status.Seals {
		if sr.AttachmentID == "save" && strings.Contains(sr.Error, "no node holds") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lost save did not fail its seal: %+v", st.Status.Seals)
	}
}

// TestReplicaErrorFallbackClearsFinalizer checks the end-to-end unblock: once
// the bounded fallback resolves the attachment, deleting the Blip removes its
// finalizer instead of waiting forever on the stuck save.
func TestReplicaErrorFallbackClearsFinalizer(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.readyState("s", "n1", "n2")
	const saved = "failing-finalizer-save"
	since := metav1.NewTime(e.now.Add(-replicaErrorFallback - time.Second))
	st := e.getState("s")
	st.Status.Pending = &v1.PendingCommit{
		CommitID: saved, Generation: 2, SourceNode: "n1",
		AttachmentID: "save", Replicas: []string{"n1", "n2"}, Since: &since,
	}
	st.Status.Seals = []v1.SealResult{{AttachmentID: "save", CommitID: saved}}
	e.must(e.c.Status().Update(e.ctx, st))
	e.hold("s", saved, "n1")
	e.report("s", "n2", func(o *v1.NodeObservation) { o.Error = "fetch: Device or resource busy" })

	code := int32(0)
	e.newBlip("b", withRoot("s"))
	b := e.getBlip("b")
	b.Finalizers = []string{v1.Finalizer}
	b.Status.Phase = v1.BlipSaving
	b.Status.RootAttachmentID = "save"
	b.Status.ExitCode = &code
	e.must(e.c.Update(e.ctx, b))
	e.must(e.c.Status().Update(e.ctx, b))
	e.must(e.c.Delete(e.ctx, b))

	e.run(e.state, ns, "s")
	if st = e.getState("s"); st.Status.Pending != nil || st.Status.Committed.ID != saved {
		t.Fatalf("state did not resolve the save: %+v", st.Status)
	}
	e.run(e.blip, ns, "b")
	b = &v1.Blip{}
	if err := e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: "b"}, b); err == nil {
		if len(b.Finalizers) != 0 {
			t.Fatalf("stuck save kept the Blip finalizer: %v", b.Finalizers)
		}
	}
}

// TestInitialVersionCommitsWithLostReplica covers the same node loss for a
// generation-1 build: the survivors build from empty and can commit without
// the node that disappeared.
func TestInitialVersionCommitsWithLostReplica(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2", "n3")
	e.newState("s", func(st *v1.BlipState) { st.Spec.Replicas = 3 })
	e.run(e.state, ns, "s")
	p := e.getState("s").Status.Pending
	if p == nil || len(p.Replicas) != 3 {
		t.Fatalf("pending %+v", p)
	}
	var other, dead string
	for _, n := range p.Replicas {
		switch {
		case n == p.SourceNode:
		case other == "":
			other = n
		default:
			dead = n
		}
	}
	e.hold("s", p.CommitID, p.SourceNode, other)
	e.removeNode(dead)

	e.run(e.state, ns, "s")
	st := e.getState("s")
	if st.Status.Committed == nil || st.Status.Committed.Generation != 1 {
		t.Fatalf("initial version with survivors never commits: %+v", st.Status)
	}
	if slices.Contains(st.Status.Placements, dead) || len(st.Status.Placements) != 2 {
		t.Fatalf("placements after the lost replica: %v", st.Status.Placements)
	}
}

// TestPendingSaveLostWithoutHolder checks the safety side: when no surviving
// node holds the sealed commit, the state must report the lost save instead of
// committing data that no node can provide.
func TestPendingSaveLostWithoutHolder(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	st := e.readyState("s", "n1", "n2")
	committed := st.Status.Committed.ID
	const saved = "dadadadadadadada"
	const losing = "8888888888888888"
	base := st.DeepCopy()
	st.Status.Pending = &v1.PendingCommit{
		CommitID:     saved,
		Generation:   2,
		SourceNode:   "n1",
		AttachmentID: losing,
		Replicas:     []string{"n1", "n2"},
	}
	e.must(patchStatus(e.ctx, e.c, st, base))
	e.seal("s", "n1", v1.SealResult{AttachmentID: losing, CommitID: saved})
	e.hold("s", saved, "n1")

	// Both nodes are gone before any survivor reports the commit.
	for _, n := range []string{"n1", "n2"} {
		e.removeNode(n)
	}
	e.run(e.state, ns, "s")
	st = e.getState("s")
	if st.Status.Pending != nil {
		t.Fatalf("lost save still pending: %+v", st.Status.Pending)
	}
	if st.Status.Committed == nil || st.Status.Committed.ID != committed {
		t.Fatalf("lost save changed the committed version: %+v", st.Status.Committed)
	}
	if !strings.Contains(st.Status.Message, "lost") {
		t.Fatalf("lost save not reported: %q", st.Status.Message)
	}
	if !slices.ContainsFunc(st.Status.Seals, func(sr v1.SealResult) bool {
		return sr.AttachmentID == losing && sr.Error != ""
	}) {
		t.Fatalf("lost save has no failure seal: %+v", st.Status.Seals)
	}
}

func TestDrainRepair(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2", "n3")
	st := e.readyState("s", "n1", "n2")
	id := st.Status.Committed.ID
	drained := st.Status.Placements[0]
	kept := st.Status.Placements[1]
	spare := "n3"

	e.setDrain(drained)
	e.run(e.state, ns, "s")
	st = e.getState("s")
	if !slices.Equal(st.Status.Placements, []string{drained, kept, spare}) {
		t.Fatalf("placements during repair %v", st.Status.Placements)
	}
	if e.safeToRemove(drained) {
		t.Fatal("draining node safe before replacement holds the commit")
	}
	e.hold("s", id, spare)
	e.run(e.state, ns, "s")
	st = e.getState("s")
	if !slices.Equal(st.Status.Placements, []string{kept, spare}) {
		t.Fatalf("placements after repair %v", st.Status.Placements)
	}
	if !e.safeToRemove(drained) {
		t.Fatal("drained node not safe to remove")
	}

	// A running VM pod keeps a draining node.
	e.newPool("default", 0, 0)
	b := e.startBlip("b", spare, e.withImage("reg/img:v1"))
	e.setDrain(spare)
	if e.safeToRemove(spare) {
		t.Fatal("node with a running VM pod is safe to remove")
	}
	e.observe(b.Status.Pod, podapi.Observed{Phase: podapi.PhaseExited, Exit: &podapi.Exit{}})
	e.run(e.blip, ns, "b")
	e.saveWriter(b.Spec.State, newID())
	e.run(e.blip, ns, "b")
	expectPhase(t, e.getBlip("b"), v1.BlipSucceeded, "")
	if e.safeToRemove(spare) {
		t.Fatal("safe while still holding a placement without replacement")
	}
}

// TestRepairRecordsNodeFetchError surfaces why a placement is stuck
// replicating the committed version, not only the "replicating to" message.
func TestRepairRecordsNodeFetchError(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	st := e.readyState("s", "n1", "n2")
	id := st.Status.Committed.ID
	e.report("s", "n2", func(o *v1.NodeObservation) {
		o.Commits = slices.DeleteFunc(o.Commits, func(c string) bool { return c == id })
		o.Error = "fetch " + id + ": device or resource busy"
	})
	e.run(e.state, ns, "s")
	st = e.getState("s")
	if !strings.Contains(st.Status.Message, "replicating to n2") {
		t.Fatalf("repair message %q", st.Status.Message)
	}
	if !strings.Contains(st.Status.LastError, "device or resource busy") {
		t.Fatalf("lastError hid the node repair error: %q", st.Status.LastError)
	}

	// The error clears once the node catches up.
	e.report("s", "n2", func(o *v1.NodeObservation) {
		o.Commits = append(o.Commits, id)
		o.Error = ""
	})
	e.run(e.state, ns, "s")
	st = e.getState("s")
	if st.Status.LastError != "" || st.Status.Message != "" {
		t.Fatalf("resolved repair kept a stale error: %+v", st.Status)
	}
}

func TestUnhealthyNodeRepair(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2", "n3")
	st := e.readyState("s", "n1", "n2")
	dead := st.Status.Placements[0]

	e.now = e.now.Add(90 * time.Second)
	e.heartbeat(dead)
	res := e.run(e.state, ns, "s")
	if st = e.getState("s"); len(st.Status.Placements) != 2 {
		t.Fatalf("repaired before the unhealthy grace period: %v", st.Status.Placements)
	}
	if res.RequeueAfter == 0 || res.RequeueAfter > repairAfter {
		t.Errorf("requeue after %v", res.RequeueAfter)
	}
	e.now = e.now.Add(time.Minute)
	e.heartbeat(dead)
	e.run(e.state, ns, "s")
	if st = e.getState("s"); !slices.Contains(st.Status.Placements, "n3") {
		t.Fatalf("no replacement: %v", st.Status.Placements)
	}
}

func TestStateDeletionBlockedByBlip(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.readyState("s", "n1")
	b := e.startBlip("b", "n1", e.withImage("reg/img:v1"), e.withMount("s", "/s", false))

	e.must(e.c.Delete(e.ctx, e.getState("s")))
	e.run(e.state, ns, "s")
	st := e.getState("s")
	if !strings.Contains(st.Status.Message, "blip b") || len(st.Finalizers) == 0 {
		t.Fatalf("deletion not blocked: %+v", st.Status)
	}
	e.observe(b.Status.Pod, podapi.Observed{Phase: podapi.PhaseExited, Exit: &podapi.Exit{}})
	e.run(e.blip, ns, "b")
	e.saveWriter(b.Spec.State, newID())
	e.run(e.blip, ns, "b")
	expectPhase(t, e.getBlip("b"), v1.BlipSucceeded, "")
	root := e.getState(b.Spec.State)
	root.Spec.Mounts = nil
	root.Generation++
	e.must(e.c.Update(e.ctx, root))
	e.run(e.state, ns, "s")
	if err := e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: "s"}, &v1.BlipState{}); err == nil {
		t.Fatal("state not deleted after the blip finished")
	}
}

// TestStateDeletionBlockedByActiveWriter checks the safety side of the queued
// Blip deadlock fix: a state with a real writer (or a Blip still committing)
// must keep its finalizer.
func TestStateDeletionBlockedByActiveWriter(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.readyState("s", "n1")
	b := e.startBlip("b", "n1", withRoot("s"))

	e.must(e.c.Delete(e.ctx, e.getState("s")))
	e.run(e.state, ns, "s")
	if st := e.getState("s"); !strings.Contains(st.Status.Message, "writer b") || len(st.Finalizers) == 0 {
		t.Fatalf("deletion not blocked by active writer: %+v", st.Status)
	}

	// A deleting state does not keep the saving Blip alive: its seal can
	// never be recorded against the state, so the save is reported as
	// discarded. The state keeps its finalizer until the node reports the
	// seal, then the last save is discarded.
	e.observe(b.Status.Pod, podapi.Observed{Phase: podapi.PhaseExited, Exit: &podapi.Exit{Reason: ReasonStopped}})
	e.run(e.blip, ns, "b")
	expectPhase(t, e.getBlip("b"), v1.BlipFailed, ReasonSaveFailed)
	e.run(e.state, ns, "s")
	if st := e.getState("s"); !strings.Contains(st.Status.Message, "writer b") || len(st.Finalizers) == 0 {
		t.Fatalf("writer released without a seal: %+v", st.Status)
	}
	w := e.getState("s").Status.Writer
	e.seal("s", w.Node, v1.SealResult{AttachmentID: w.AttachmentID, CommitID: "c2c2c2c2c2c2c2c2"})
	e.hold("s", "c2c2c2c2c2c2c2c2", w.Node)
	e.run(e.state, ns, "s")
	if err := e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: "s"}, &v1.BlipState{}); err == nil {
		t.Fatal("state not deleted after its writer finished")
	}
}

// TestQueuedBlipDoesNotBlockStateDeletion reproduces the P1-1 deadlock: a
// Blip that is queued behind the state's writer only names the state in its
// spec, so it must not keep the deleting state alive. The state finalizer has
// to complete once the real writer is gone, without deleting the queued Blip.
func TestQueuedBlipDoesNotBlockStateDeletion(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.readyState("s", "n1")
	holder := e.startBlip("holder", "n1", withRoot("s"))

	e.newBlip("queued", withRoot("s"))
	e.run(e.blip, ns, "queued")
	e.run(e.pool, ns, "default")
	e.warmOn("n1")
	e.run(e.blip, ns, "queued")
	queued := e.getBlip("queued")
	expectPhase(t, queued, v1.BlipPending, ReasonStateBusy)
	if queued.Status.Pod != "" || len(queued.Status.Mounts) != 0 || queued.Status.RootAttachmentID != "" {
		t.Fatalf("queued blip acquired the state: %+v", queued.Status)
	}

	// The deleting state still waits for its writer.
	e.must(e.c.Delete(e.ctx, e.getState("s")))
	e.run(e.state, ns, "s")
	if st := e.getState("s"); !strings.Contains(st.Status.Message, "writer holder") || len(st.Finalizers) == 0 {
		t.Fatalf("deletion not blocked by the holder: %+v", st.Status)
	}

	// Stop the holder. A deleting root does not keep the saving Blip alive:
	// the discarded save fails it; the state still waits for its writer.
	e.observe(holder.Status.Pod, podapi.Observed{Phase: podapi.PhaseExited, Exit: &podapi.Exit{Reason: ReasonStopped}})
	e.run(e.blip, ns, "holder")
	expectPhase(t, e.getBlip("holder"), v1.BlipFailed, ReasonSaveFailed)
	e.run(e.state, ns, "s")
	if st := e.getState("s"); !strings.Contains(st.Status.Message, "writer holder") || len(st.Finalizers) == 0 {
		t.Fatalf("writer released without a seal: %+v", st.Status)
	}

	// The node seals the last version; the deleting state discards the
	// pending commit and its finalizer must not wait for the queued Blip.
	w := e.getState("s").Status.Writer
	e.seal("s", w.Node, v1.SealResult{AttachmentID: w.AttachmentID, CommitID: "d2d2d2d2d2d2d2d2"})
	e.hold("s", "d2d2d2d2d2d2d2d2", w.Node)
	e.run(e.state, ns, "s")
	if err := e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: "s"}, &v1.BlipState{}); err == nil {
		t.Fatal("state still waiting for the queued blip")
	}
	if b := e.getBlip("queued"); b.DeletionTimestamp != nil || v1.Finished(b) {
		t.Fatalf("test changed the queued blip: %+v", b.Status)
	}
}

// TestQueuedBlipFailsWhenStateIsBeingDeleted checks the Blip side of the
// deadlock: once the state terminates, a Blip that never acquired it must
// finish instead of waiting for it forever.
func TestQueuedBlipFailsWhenStateIsBeingDeleted(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	e.readyState("s", "n1")
	e.startBlip("holder", "n1", withRoot("s"))

	e.newBlip("queued", withRoot("s"))
	e.run(e.blip, ns, "queued")
	e.run(e.pool, ns, "default")
	e.warmOn("n1")
	e.run(e.blip, ns, "queued")
	expectPhase(t, e.getBlip("queued"), v1.BlipPending, ReasonStateBusy)

	e.must(e.c.Delete(e.ctx, e.getState("s")))
	e.run(e.blip, ns, "queued")
	b := e.getBlip("queued")
	if b.Status.Phase != v1.BlipFailed || b.Status.Reason != ReasonStateNotFound || !strings.Contains(b.Status.Message, "being deleted") {
		t.Fatalf("queued blip did not finish: %+v", b.Status)
	}
}

// TestPendingBlipWithMountBlocksStateDeletion covers the race where a Blip is
// about to reach Running when deletion starts: an attachment it already
// acquired must still protect the state until the Blip lets go.
func TestPendingBlipWithMountBlocksStateDeletion(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	st := e.readyState("s", "n1")
	e.newBlip("b", e.withImage("reg/img:v1"), e.withMount("s", "/s", false))
	e.setBlipStatus("b", func(b *v1.Blip) {
		b.Status.Phase = v1.BlipPending
		b.Status.Reason = ReasonWaitingForVM
		b.Status.Mounts = []v1.MountStatus{{
			State: "s", Path: "/s", StateUID: string(st.UID),
			CommitID: st.Status.Committed.ID, AttachmentID: "0000000000000001",
			Phase: v1.MountPending,
		}}
	})

	e.must(e.c.Delete(e.ctx, e.getState("s")))
	e.run(e.state, ns, "s")
	st = e.getState("s")
	if !strings.Contains(st.Status.Message, "blip b") || len(st.Finalizers) == 0 {
		t.Fatalf("deletion not blocked by pending mount: %+v", st.Status)
	}

	// Seeing the deletion, the Blip releases the attachment and fails.
	e.run(e.blip, ns, "b")
	b := e.getBlip("b")
	if b.Status.Phase != v1.BlipFailed || b.Status.Reason != ReasonStateNotFound {
		t.Fatalf("pending blip did not finish: %+v", b.Status)
	}
	if len(b.Status.Mounts) != 0 {
		t.Fatalf("pending blip kept its mounts: %+v", b.Status.Mounts)
	}
	root := e.getState(b.Spec.State)
	root.Spec.Mounts = nil
	root.Generation++
	e.must(e.c.Update(e.ctx, root))
	e.run(e.state, ns, "s")
	if err := e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: "s"}, &v1.BlipState{}); err == nil {
		t.Fatal("state not deleted after the pending blip failed")
	}
}

func TestWriterNodeDeletedRequiresForceRecover(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 0, 0)
	e.readyState("s", "n1", "n2")
	b := e.startBlip("b", "n1", withRoot("s"))

	e.now = e.now.Add(10 * time.Minute)
	e.heartbeat("n1")
	e.run(e.state, ns, "s")
	if w := e.getState("s").Status.Writer; w == nil {
		t.Fatal("writer released while its node may still run the VM")
	}
	e.must(e.c.Delete(e.ctx, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}}))
	e.must(e.c.Delete(e.ctx, e.getPod(b.Status.Pod)))
	e.run(e.state, ns, "s")
	st := e.getState("s")
	if st.Status.Writer == nil {
		t.Fatal("deleted node was treated as proof that the VM stopped")
	}
	if !strings.Contains(st.Status.Message, v1.AnnotationForceRecover) {
		t.Fatalf("no manual recovery message: %q", st.Status.Message)
	}
	e.run(e.blip, ns, "b")
	expectPhase(t, e.getBlip("b"), v1.BlipSaving, "")
	if w := e.getState("s").Status.Writer; w == nil {
		t.Fatal("writer released without force recovery")
	}

	// The explicit escape hatch clears the writer and records a failed
	// seal, so the Blip fails instead of reporting a successful save.
	st = e.getState("s")
	if st.Annotations == nil {
		st.Annotations = map[string]string{}
	}
	st.Annotations[v1.AnnotationForceRecover] = "true"
	e.must(e.c.Update(e.ctx, st))
	e.run(e.state, ns, "s")
	st = e.getState("s")
	if st.Status.Writer != nil {
		t.Fatalf("writer after force recovery: %+v", st.Status.Writer)
	}
	if len(st.Status.Seals) == 0 {
		t.Fatalf("no seal result after force recovery: %+v", st.Status.Seals)
	}
	if _, ok := st.Annotations[v1.AnnotationForceRecover]; ok {
		t.Error("force-recover annotation was not removed")
	}
	e.run(e.blip, ns, "b")
	expectPhase(t, e.getBlip("b"), v1.BlipFailed, ReasonSaveFailed)
}

func (e *env) label(key, value string, nodes ...string) {
	e.t.Helper()
	for _, n := range nodes {
		k := &corev1.Node{}
		e.must(e.c.Get(e.ctx, types.NamespacedName{Name: n}, k))
		k.Labels[key] = value
		e.must(e.c.Update(e.ctx, k))
	}
}

func TestImageStateOnEveryEligibleNode(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2", "n3", "n4")
	e.label("zone", "a", "n1", "n2", "n3")
	e.newState("s", func(st *v1.BlipState) {
		st.Spec.Image = "reg/img:v1"
		st.Spec.Replicas = 1
		st.Spec.NodeSelector = map[string]string{"zone": "a"}
	})
	e.run(e.state, ns, "s")
	p := e.getState("s").Status.Pending
	if p == nil || p.Generation != 1 || !slices.Equal(p.Replicas, []string{"n1", "n2", "n3"}) || p.SourceNode != "n1" {
		t.Fatalf("pending %+v", p)
	}
	e.hold("s", p.CommitID, "n2", "n3")
	e.run(e.state, ns, "s")
	if st := e.getState("s"); st.Status.Committed != nil || !strings.Contains(st.Status.Message, "waiting for n1") {
		t.Fatalf("committed before every eligible node built the image: %+v", st.Status)
	}
	e.hold("s", p.CommitID, "n1")
	e.run(e.state, ns, "s")
	st := e.getState("s")
	if st.Status.Committed == nil || !slices.Equal(st.Status.Placements, []string{"n1", "n2", "n3"}) || st.Status.Message != "" {
		t.Fatalf("commit %+v", st.Status)
	}

	// A new eligible node joins the placements; nothing changes once it holds.
	e.addNodes("n5")
	e.label("zone", "a", "n5")
	e.run(e.state, ns, "s")
	st = e.getState("s")
	if !slices.Equal(st.Status.Placements, []string{"n1", "n2", "n3", "n5"}) || st.Status.Message != "replicating to n5" {
		t.Fatalf("after join %+v", st.Status)
	}
	e.hold("s", p.CommitID, "n5")
	e.run(e.state, ns, "s")
	st = e.getState("s")
	e.run(e.state, ns, "s")
	if again := e.getState("s"); again.ResourceVersion != st.ResourceVersion || st.Status.Message != "" {
		t.Fatalf("status churn: %+v -> %+v", st.Status, again.Status)
	}

	// A drained node leaves the placements and is not added back.
	e.setDrain("n2")
	e.run(e.state, ns, "s")
	e.run(e.state, ns, "s")
	if st = e.getState("s"); !slices.Equal(st.Status.Placements, []string{"n1", "n3", "n5"}) || st.Status.Message != "" {
		t.Fatalf("after drain %+v", st.Status)
	}
}

// TestImageBuildSizeErrorIsTerminal: the converted image size and spec.size
// are immutable, so "needs more bytes" can never succeed on retry. Clear
// pending and fail, otherwise pull and copies wait forever.
func TestImageBuildSizeErrorIsTerminal(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newState("s", func(st *v1.BlipState) { st.Spec.Image = "reg/img:v1"; st.Spec.Replicas = 1 })
	e.run(e.state, ns, "s")
	if p := e.getState("s").Status.Pending; p == nil {
		t.Fatal("no pending initial version")
	}
	e.report("s", "n1", func(o *v1.NodeObservation) {
		o.Error = "storage: image sha256:ce60 needs 1186988032 bytes, more than the requested 536870912"
	})
	e.run(e.state, ns, "s")
	st := e.getState("s")
	if st.Status.Phase != v1.StateFailed || st.Status.Pending != nil {
		t.Fatalf("permanent size error not terminal: %+v", st.Status)
	}
	if !strings.Contains(st.Status.Message, "initial version failed: ") ||
		!strings.Contains(st.Status.Message, "needs 1186988032 bytes, more than the requested 536870912") {
		t.Fatalf("terminal message %q", st.Status.Message)
	}
	if !strings.Contains(st.Status.LastError, "needs 1186988032 bytes") {
		t.Fatalf("lastError %q", st.Status.LastError)
	}
	// It stays terminal instead of replanning the impossible build.
	e.run(e.state, ns, "s")
	if again := e.getState("s"); again.Status.Pending != nil || again.Status.Committed != nil {
		t.Fatalf("terminal failure retried: %+v", again.Status)
	}
}

// TestImageBuildTransientErrorKeepsPending: fetch and device errors can
// recover, so the initial version stays retryable with pending retained.
func TestImageBuildTransientErrorKeepsPending(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newState("s", func(st *v1.BlipState) { st.Spec.Image = "reg/img:v1"; st.Spec.Replicas = 1 })
	e.run(e.state, ns, "s")
	p := e.getState("s").Status.Pending
	if p == nil {
		t.Fatal("no pending initial version")
	}
	e.report("s", "n1", func(o *v1.NodeObservation) {
		o.Error = "fetch blip-n1: device-mapper: create ioctl failed: Device or resource busy"
	})
	e.run(e.state, ns, "s")
	st := e.getState("s")
	if st.Status.Phase != v1.StateFailed || st.Status.Pending == nil {
		t.Fatalf("transient error was made terminal: %+v", st.Status)
	}
	if !strings.Contains(st.Status.Message, "initial version failed: ") ||
		!strings.Contains(st.Status.Message, "Device or resource busy") {
		t.Fatalf("transient message %q", st.Status.Message)
	}
	e.hold("s", p.CommitID, "n1")
	e.run(e.state, ns, "s")
	if st = e.getState("s"); st.Status.Pending != nil || st.Status.Committed == nil || st.Status.Phase != v1.StateReady {
		t.Fatalf("retryable initial version did not recover: %+v", st.Status)
	}
}

func TestImageStatePendingDropsFailedNodes(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2", "n3")
	e.newState("s", func(st *v1.BlipState) { st.Spec.Image = "reg/img:v1"; st.Spec.Replicas = 0 })
	e.run(e.state, ns, "s")
	p := e.getState("s").Status.Pending
	if p == nil || p.SourceNode != "n1" || len(p.Replicas) != 3 {
		t.Fatalf("pending %+v", p)
	}
	e.hold("s", p.CommitID, "n3")
	e.must(e.c.Delete(e.ctx, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n2"}}))
	e.run(e.state, ns, "s")
	if q := e.getState("s").Status.Pending; q == nil || q.CommitID != p.CommitID || !slices.Equal(q.Replicas, []string{"n1", "n3"}) {
		t.Fatalf("pending after replica loss %+v", q)
	}
	// The source is not special: every node builds generation 1 itself.
	e.must(e.c.Delete(e.ctx, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}}))
	e.run(e.state, ns, "s")
	st := e.getState("s")
	if c := st.Status.Committed; c == nil || c.ID != p.CommitID || !slices.Equal(st.Status.Placements, []string{"n3"}) {
		t.Fatalf("commit after source loss %+v", st.Status)
	}
}
