package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/session"
	"github.com/Azure/blip/internal/session/fakeguest"
)

const ns = "ns"

type harness struct {
	t     *testing.T
	kube  client.WithWatch
	guest *fakeguest.Guest
	ctrl  *fakeController
	// connect overrides the fake guest connector when set, so tests can
	// inject transport failures.
	connect session.Connector
	// self is the blip the CLI runs in, if any.
	self string
}

func newHarness(t *testing.T, objs ...client.Object) *harness {
	// Running execution fixtures carry their initial mounts in status. Put
	// that configuration on a durable root unless a test supplied one.
	states := map[string]*v1alpha1.BlipState{}
	for _, obj := range objs {
		if st, ok := obj.(*v1alpha1.BlipState); ok {
			states[st.Name] = st
		}
	}
	for _, obj := range objs {
		b, ok := obj.(*v1alpha1.Blip)
		if !ok || b.Status.Phase != v1alpha1.BlipRunning || b.Spec.State == "" {
			continue
		}
		root := states[b.Spec.State]
		if root == nil {
			root = readyState(b.Spec.State)
			root.Labels = b.Labels
			states[root.Name] = root
			objs = append(objs, root)
		}
		if len(root.Spec.Mounts) == 0 {
			for _, mount := range b.Status.Mounts {
				root.Spec.Mounts = append(root.Spec.Mounts, v1alpha1.Mount{State: mount.State, Path: mount.Path, Writable: mount.Writable})
			}
		}
		if root.Status.Writer == nil {
			root.Status.Writer = &v1alpha1.Writer{BlipName: b.Name, BlipUID: string(b.UID)}
			root.Status.Phase = v1alpha1.StateInUse
		}
	}
	for _, pool := range []string{"default", "big"} {
		objs = append(objs, &v1alpha1.BlipPool{ObjectMeta: metav1.ObjectMeta{Name: pool, Namespace: ns}})
	}
	kube := fake.NewClientBuilder().WithScheme(Scheme).WithStatusSubresource(&v1alpha1.Blip{}, &v1alpha1.BlipState{}).WithObjects(objs...).Build()
	h := &harness{t: t, kube: kube, guest: &fakeguest.Guest{}, ctrl: &fakeController{kube: kube, exited: map[string]int32{}}}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go h.ctrl.loop(ctx)
	return h
}

// run executes the CLI and returns its exit code, stdout and stderr.
func (h *harness) run(stdin string, args ...string) (int, string, string) {
	h.t.Helper()
	var out, errb bytes.Buffer
	env := h.env(strings.NewReader(stdin), &out, &errb)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	code := Main(ctx, env, args)
	return code, out.String(), errb.String()
}

func (h *harness) env(in io.Reader, out, errOut io.Writer) *Env {
	connect := session.Connector(h.guest.Connect)
	if h.connect != nil {
		connect = h.connect
	}
	env := &Env{In: in, Out: out, Err: errOut, Connect: func(KubeFlags) (*Clients, error) {
		return &Clients{Kube: h.kube, Sessions: &session.Client{Connect: connect}, Namespace: ns}, nil
	}}
	if h.self != "" {
		env.NamespaceFile = filepath.Join(h.t.TempDir(), "namespace")
		if err := os.WriteFile(env.NamespaceFile, []byte(ns), 0o644); err != nil {
			h.t.Fatal(err)
		}
		env.Hostname = func() (string, error) { return h.self, nil }
	}
	return env
}

func (h *harness) state(name string) *v1alpha1.BlipState {
	h.t.Helper()
	var s v1alpha1.BlipState
	if err := h.kube.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: name}, &s); err != nil {
		h.t.Fatal(err)
	}
	return &s
}

func (h *harness) blip(name string) *v1alpha1.Blip {
	h.t.Helper()
	var b v1alpha1.Blip
	if err := h.kube.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: name}, &b); err != nil {
		h.t.Fatal(err)
	}
	return &b
}

func (h *harness) rootState(name string) *v1alpha1.BlipState {
	h.t.Helper()
	return h.state(h.blip(name).Spec.State)
}

// apply creates an object as `kubectl apply` would.
func (h *harness) apply(obj client.Object) {
	h.t.Helper()
	if err := h.kube.Create(context.Background(), obj); err != nil {
		h.t.Fatal(err)
	}
}

func runningBlip(name string, mounts ...v1alpha1.Mount) *v1alpha1.Blip {
	b := &v1alpha1.Blip{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, UID: types.UID("uid-" + name)}}
	b.Spec.State = name + "-root"
	b.Status.Phase = v1alpha1.BlipRunning
	b.Status.Pod = "pod-" + name
	for _, m := range mounts {
		b.Status.Mounts = append(b.Status.Mounts, v1alpha1.MountStatus{State: m.State, Path: m.Path, Writable: m.Writable, Phase: v1alpha1.MountMounted})
	}
	return b
}

func readyState(name string) *v1alpha1.BlipState {
	s := &v1alpha1.BlipState{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}}
	s.Status.Phase = v1alpha1.StateReady
	s.Status.Committed = &v1alpha1.Commit{ID: "0123456789abcdef", Generation: 1}
	return s
}

// fakeController moves objects through their lifecycle one step per tick,
// roughly like blip-controller and the nodes together.
type fakeController struct {
	kube client.WithWatch

	mu sync.Mutex
	// autoFinish ends command blips without a guest exit.
	autoFinish       bool
	paused           bool
	stateFail        string
	stateFailPending bool
	mountFail        string
	unmountFail      string
	exited           map[string]int32
}

func (c *fakeController) set(f func(c *fakeController)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f(c)
}

func (c *fakeController) loop(ctx context.Context) {
	for ctx.Err() == nil {
		c.tick(ctx)
		time.Sleep(2 * time.Millisecond)
	}
}

func (c *fakeController) tick(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.paused {
		return
	}
	var states v1alpha1.BlipStateList
	c.kube.List(ctx, &states)
	for i := range states.Items {
		s := &states.Items[i]
		switch {
		case s.Status.Phase == "":
			if c.stateFail != "" {
				s.Status.Phase, s.Status.Message = v1alpha1.StateFailed, c.stateFail
				if c.stateFailPending {
					s.Status.Pending = &v1alpha1.PendingCommit{CommitID: "fedcba9876543210", Generation: 1}
				}
			} else {
				s.Status.Phase = v1alpha1.StateReady
				s.Status.Committed = &v1alpha1.Commit{ID: "0123456789abcdef", Generation: 1}
			}
			c.kube.Status().Update(ctx, s)
		case s.Status.Phase == v1alpha1.StateFailed && s.Status.Pending != nil:
			s.Status.Phase = v1alpha1.StateReady
			s.Status.Pending = nil
			s.Status.Committed = &v1alpha1.Commit{ID: "0123456789abcdef", Generation: 1}
			c.kube.Status().Update(ctx, s)
		}
	}
	var blips v1alpha1.BlipList
	c.kube.List(ctx, &blips)
	for i := range blips.Items {
		b := &blips.Items[i]
		if c.step(b) {
			c.kube.Status().Update(ctx, b)
		}
	}
}

func (c *fakeController) step(b *v1alpha1.Blip) bool {
	st := &b.Status
	switch st.Phase {
	case "":
		st.Phase, st.Message = v1alpha1.BlipPending, "waiting for a VM"
		return true
	case v1alpha1.BlipPending:
		st.Phase, st.Message, st.Pod, st.Node = v1alpha1.BlipRunning, "", "pod-"+b.Name, "node-1"
		return true
	case v1alpha1.BlipSaving:
		st.Phase = v1alpha1.BlipSucceeded
		if st.ExitCode != nil && *st.ExitCode != 0 {
			st.Phase = v1alpha1.BlipFailed
		}
		st.Mounts = nil
		return true
	case v1alpha1.BlipRunning:
	default:
		return false
	}
	code, exited := c.exited[b.Name]
	if b.Spec.Stop || exited || (c.autoFinish && len(b.Spec.Command) > 0) {
		st.Phase = v1alpha1.BlipSaving
		st.ExitCode = &code
		return true
	}
	var root v1alpha1.BlipState
	_ = c.kube.Get(context.Background(), client.ObjectKey{Namespace: b.Namespace, Name: b.Spec.State}, &root)
	var mounts []v1alpha1.Mount
	for _, m := range root.Spec.Mounts {
		if m.BlipUID == "" || m.BlipUID == string(b.UID) {
			mounts = append(mounts, m)
		}
	}
	for _, m := range mounts {
		if findMount(st.Mounts, m.State) == nil {
			ms := v1alpha1.MountStatus{State: m.State, Path: m.Path, Writable: m.Writable, Phase: v1alpha1.MountPending}
			if !m.Writable {
				// Read-only mounts pin the committed version.
				var s v1alpha1.BlipState
				if err := c.kube.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: m.State}, &s); err == nil && s.Status.Committed != nil {
					ms.CommitID = s.Status.Committed.ID
				}
			}
			st.Mounts = append(st.Mounts, ms)
			return true
		}
	}
	for i := range st.Mounts {
		m := &st.Mounts[i]
		sm := specMount(mounts, m.State)
		switch {
		case sm != nil && m.Phase == v1alpha1.MountMounted && (sm.Path != m.Path || sm.Writable != m.Writable):
			m.Phase, m.Switching = v1alpha1.MountUnmounting, true
		case sm != nil && m.Phase == v1alpha1.MountFailed && strings.Contains(m.Message, "busy") &&
			sm.Path == m.Path && sm.Writable == m.Writable:
			// The switch failed and the spec was reverted: the old mount is
			// still usable.
			m.Phase, m.Message, m.Switching = v1alpha1.MountMounted, "", false
		case sm != nil && m.Phase == v1alpha1.MountUnmounting && m.Message != "" && sm.Path == m.Path && sm.Writable == m.Writable:
			// The unmount failed but the spec was restored: the mount never
			// left, so it is usable again.
			m.Phase, m.Message, m.Switching = v1alpha1.MountMounted, "", false
		case sm != nil && m.Phase == v1alpha1.MountUnmounting && m.Switching:
			if c.unmountFail != "" {
				m.Phase, m.Message = v1alpha1.MountFailed, c.unmountFail
			} else if m.Writable {
				m.Phase = v1alpha1.MountSaving
			} else {
				st.Mounts = append(st.Mounts[:i], st.Mounts[i+1:]...)
			}
		case sm != nil && m.Phase == v1alpha1.MountSaving && m.Switching:
			m.Writable, m.Phase, m.Switching = sm.Writable, v1alpha1.MountPending, false
			if !m.Writable {
				m.CommitID = "fedcba9876543210"
				var s v1alpha1.BlipState
				if err := c.kube.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: m.State}, &s); err == nil {
					s.Status.Pending = nil
					s.Status.Committed = &v1alpha1.Commit{ID: m.CommitID, Generation: 2}
					c.kube.Status().Update(context.Background(), &s)
				}
			}
		default:
			continue
		}
		return true
	}
	for i := range st.Mounts {
		m := &st.Mounts[i]
		inSpec := false
		for _, sm := range mounts {
			inSpec = inSpec || sm.State == m.State
		}
		switch {
		case inSpec && m.Phase == v1alpha1.MountPending && c.mountFail != "":
			m.Phase, m.Message = v1alpha1.MountFailed, c.mountFail
		case inSpec && m.Phase == v1alpha1.MountPending:
			m.Phase = v1alpha1.MountMounted
		case !inSpec && m.Phase == v1alpha1.MountMounted:
			m.Phase = v1alpha1.MountUnmounting
		case !inSpec && m.Phase == v1alpha1.MountUnmounting && c.unmountFail != "":
			m.Message = c.unmountFail
		case !inSpec && m.Phase == v1alpha1.MountUnmounting && m.Writable:
			m.Phase = v1alpha1.MountSaving
		case !inSpec && m.Phase == v1alpha1.MountFailed && !strings.Contains(m.Message, "save failed"):
			// A mount that never attached is forgotten with its spec entry.
			st.Mounts = append(st.Mounts[:i], st.Mounts[i+1:]...)
		case !inSpec && (m.Phase == v1alpha1.MountUnmounting || m.Phase == v1alpha1.MountSaving):
			st.Mounts = append(st.Mounts[:i], st.Mounts[i+1:]...)
		default:
			continue
		}
		return true
	}
	return false
}

func specMount(mounts []v1alpha1.Mount, state string) *v1alpha1.Mount {
	for i := range mounts {
		if mounts[i].State == state {
			return &mounts[i]
		}
	}
	return nil
}

func mustContain(t *testing.T, got string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Fatalf("output %q does not contain %q", got, w)
		}
	}
}

func state(name string) *v1alpha1.BlipState {
	return &v1alpha1.BlipState{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}}
}
