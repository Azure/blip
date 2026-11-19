package workspace

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/sim"
	"github.com/Azure/blip/internal/simtest"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// The fork simulation executes the production Fork against a fake API whose
// failures are explicit actions. Each action is one fault plan: an operation
// (Get, Create, Patch, or Delete), a 1-based call index, and an outcome
// (definitive rejection, transport error, server error, or a committed request
// whose response was lost). A plan may also fault the Delete that rolls back a
// failed fork, covering cleanup failures and a concurrently replaced object.
//
// The world is one fork attempt. Depth 1 is enough to enumerate every
// meaningful fault; after the attempt Fork has either finished or returned an
// error, and the model has no further actions.
//
// Assumptions about the fake API:
//   - Creates do not assign UIDs. The interceptor assigns deterministic UIDs,
//     so the simulation can reason about delete preconditions and identity.
//   - The fake client ignores Delete UID preconditions, so the interceptor
//     emulates a server that checks them. An unguarded delete removes whatever
//     object currently holds the name; a guarded delete with a stale UID
//     returns a conflict and leaves the replacement.
//   - A transport or server failure injected before forwarding did not commit;
//     a "lost" failure forwards first and then reports the response as lost.
//
// The fixture has one source root, two writable mounts, one read-only mount,
// and a durable fork (no owner reference). A second fixture pre-creates the
// destination, so every fault plan stops at the preflight collision.

const simNamespace = "ns"

var simStateResource = v1alpha1.GroupVersion.WithResource("blipstates").GroupResource()

// simUID is the UID the simulated API assigns to a state created by Fork.
func simUID(name string) types.UID { return types.UID("uid-" + name) }

// simReplacementUID is the UID a concurrent creator receives when it replaces
// a state during rollback.
func simReplacementUID(name string) types.UID { return types.UID("uid-" + name + "-replaced") }

// simObject is the canonical, comparison-only view of a state. It deliberately
// omits resourceVersion and timestamps, which the fake client maintains but
// Fork does not promise anything about.
type simObject struct {
	Namespace       string                    `json:"namespace"`
	Name            string                    `json:"name"`
	UID             string                    `json:"uid"`
	Labels          map[string]string         `json:"labels,omitempty"`
	OwnerReferences []metav1.OwnerReference   `json:"ownerReferences,omitempty"`
	CopyFrom        string                    `json:"copyFrom,omitempty"`
	Runtime         *v1alpha1.RuntimeDefaults `json:"runtime,omitempty"`
	Mounts          []v1alpha1.Mount          `json:"mounts,omitempty"`
	Replicas        int32                     `json:"replicas,omitempty"`
	NodeSelector    map[string]string         `json:"nodeSelector,omitempty"`
}

func captureState(st *v1alpha1.BlipState) simObject {
	return simObject{
		Namespace:       st.Namespace,
		Name:            st.Name,
		UID:             string(st.UID),
		Labels:          maps.Clone(st.Labels),
		OwnerReferences: slices.Clone(st.OwnerReferences),
		CopyFrom:        st.Spec.CopyFrom,
		Runtime:         st.Spec.Runtime.DeepCopy(),
		Mounts:          slices.Clone(st.Spec.Mounts),
		Replicas:        st.Spec.Replicas,
		NodeSelector:    maps.Clone(st.Spec.NodeSelector),
	}
}

// forkFixture describes the pre-existing world. It is immutable; Step rebuilds
// both the fake API and the destination object from it.
type forkFixture struct {
	name      string
	source    *v1alpha1.BlipState
	repo      *v1alpha1.BlipState
	cache     *v1alpha1.BlipState
	tools     *v1alpha1.BlipState
	collision bool
	existing  *v1alpha1.BlipState // pre-created destination, when collision
	dest      *v1alpha1.BlipState
	owner     *metav1.OwnerReference
}

func newForkFixture(collision bool) *forkFixture {
	source := &v1alpha1.BlipState{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: simNamespace,
			Name:      "shared",
			UID:       types.UID("uid-shared"),
			Labels:    map[string]string{"purpose": "source"},
		},
		Spec: v1alpha1.BlipStateSpec{
			Image: "registry.example/base:v1",
			Runtime: &v1alpha1.RuntimeDefaults{
				Env:        []v1alpha1.EnvVar{{Name: "A", Value: "original"}, {Name: "B", Value: "two"}},
				WorkingDir: "/work",
				User:       "dev",
				Network:    &v1alpha1.NetworkPolicy{},
			},
			Mounts: []v1alpha1.Mount{
				{State: "repo", Path: "/work", Writable: true},
				{State: "cache", Path: "/cache", Writable: true},
				{State: "tools", Path: "/tools"},
			},
		},
	}
	mountState := func(name, uid string, labels map[string]string) *v1alpha1.BlipState {
		return &v1alpha1.BlipState{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: simNamespace,
				Name:      name,
				UID:       types.UID(uid),
				Labels:    labels,
			},
			Spec: v1alpha1.BlipStateSpec{
				Image:    "registry.example/" + name + ":v1",
				Replicas: 1,
				Runtime:  &v1alpha1.RuntimeDefaults{User: "mounted-" + name},
				Mounts:   []v1alpha1.Mount{{State: "nested-" + name, Path: "/nested"}},
			},
		}
	}
	repo := mountState("repo", "uid-repo", map[string]string{"role": "repo"})
	cache := mountState("cache", "uid-cache", map[string]string{"role": "cache"})
	tools := mountState("tools", "uid-tools", map[string]string{"role": "tools"})
	dest := &v1alpha1.BlipState{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: simNamespace,
			Name:      "alice.worker",
			Labels:    map[string]string{v1alpha1.LabelOwner: "alice", "purpose": "fork"},
		},
		Spec: v1alpha1.BlipStateSpec{
			Replicas:     2,
			NodeSelector: map[string]string{"disk": "ssd"},
		},
	}
	f := &forkFixture{name: "durable", collision: collision, source: source, repo: repo, cache: cache, tools: tools, dest: dest}
	if collision {
		f.name = "collision"
		f.existing = &v1alpha1.BlipState{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: simNamespace,
				Name:      dest.Name,
				UID:       types.UID("uid-existing-destination"),
				Labels:    map[string]string{"existing": "keep"},
			},
			Spec: v1alpha1.BlipStateSpec{Image: "registry.example/existing:v1", Replicas: 3},
		}
	}
	return f
}

func (f *forkFixture) objects() []client.Object {
	objects := []client.Object{f.source.DeepCopy(), f.repo.DeepCopy(), f.cache.DeepCopy(), f.tools.DeepCopy()}
	if f.existing != nil {
		objects = append(objects, f.existing.DeepCopy())
	}
	return objects
}

func (f *forkFixture) preExisting() []simObject {
	states := []*v1alpha1.BlipState{f.source, f.repo, f.cache, f.tools}
	if f.existing != nil {
		states = append(states, f.existing)
	}
	out := make([]simObject, 0, len(states))
	for _, st := range states {
		out = append(out, captureState(st))
	}
	return out
}

// writableChildren returns the production child names in mount order, paired
// with the source mount they snapshot.
func (f *forkFixture) writableChildren() []struct {
	name  string
	mount v1alpha1.Mount
} {
	root := f.dest.DeepCopy()
	var out []struct {
		name  string
		mount v1alpha1.Mount
	}
	for _, mount := range f.source.Spec.Mounts {
		if mount.BlipUID != "" || !mount.Writable {
			continue
		}
		out = append(out, struct {
			name  string
			mount v1alpha1.Mount
		}{name: childName(root, mount), mount: mount})
	}
	return out
}

func (f *forkFixture) childNames() []string {
	children := f.writableChildren()
	out := make([]string, 0, len(children))
	for _, child := range children {
		out = append(out, child.name)
	}
	return out
}

// rootMounts is the mount list Fork promises for the returned root: writable
// references are rewritten to the created copies, read-only references are
// retained verbatim, and temporary mounts are not inherited.
func (f *forkFixture) rootMounts() []v1alpha1.Mount {
	root := f.dest.DeepCopy()
	var out []v1alpha1.Mount
	for _, mount := range f.source.Spec.Mounts {
		if mount.BlipUID != "" {
			continue
		}
		if mount.Writable {
			mount.State = childName(root, mount)
		}
		out = append(out, mount)
	}
	return out
}

func (f *forkFixture) baseClient() (client.WithWatch, error) {
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(f.objects()...).Build(), nil
}

// fault is one injected failure at a 1-based call index for an operation.
type fault struct {
	Op    string `json:"op"`
	Index int    `json:"index"`
	Mode  string `json:"mode"`
}

func faultAction(faults []fault) string {
	if len(faults) == 0 {
		return "normal"
	}
	parts := make([]string, 0, len(faults))
	for _, f := range faults {
		parts = append(parts, fmt.Sprintf("%s/%d/%s", f.Op, f.Index, f.Mode))
	}
	return strings.Join(parts, "+")
}

func faultClass(mode string) string {
	switch mode {
	case "notfound":
		return "notfound"
	case "reject":
		return "forbidden"
	case "transport", "lost":
		return "transport"
	case "server":
		return "internal"
	case "replaced":
		return "conflict"
	default:
		panic("unknown fault mode " + mode)
	}
}

func injectedError(mode, name string) error {
	switch mode {
	case "notfound":
		return apierrors.NewNotFound(simStateResource, name)
	case "reject":
		return apierrors.NewForbidden(simStateResource, name, errors.New("injected rejection"))
	case "transport", "lost":
		return io.ErrUnexpectedEOF
	case "server":
		return apierrors.NewInternalError(errors.New("injected server failure"))
	default:
		return fmt.Errorf("unknown fault mode %q", mode)
	}
}

// faultInjector applies one plan. Counters are per operation and are reset for
// every fork attempt, so the plan is independent of map iteration order.
type faultInjector struct {
	base   client.WithWatch
	faults []fault
	counts map[string]int
}

func newFaultInjector(base client.WithWatch, faults []fault) *faultInjector {
	return &faultInjector{base: base, faults: faults, counts: map[string]int{}}
}

func (in *faultInjector) next(op string) (int, *fault) {
	in.counts[op]++
	for i := range in.faults {
		if in.faults[i].Op == op && in.faults[i].Index == in.counts[op] {
			return in.counts[op], &in.faults[i]
		}
	}
	return in.counts[op], nil
}

func (in *faultInjector) client() client.WithWatch {
	return interceptor.NewClient(in.base, interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			_, f := in.next("get")
			if f == nil {
				return c.Get(ctx, key, obj, opts...)
			}
			return injectedError(f.Mode, key.Name)
		},
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			_, f := in.next("create")
			if f == nil {
				obj.SetUID(simUID(obj.GetName()))
				return c.Create(ctx, obj, opts...)
			}
			switch f.Mode {
			case "lost":
				// The server commits, but the client never sees the response.
				obj.SetUID(simUID(obj.GetName()))
				if err := c.Create(ctx, obj, opts...); err != nil {
					return err
				}
				return io.ErrUnexpectedEOF
			default:
				// The request never reached the server.
				return injectedError(f.Mode, obj.GetName())
			}
		},
		Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			_, f := in.next("patch")
			if f == nil {
				return c.Patch(ctx, obj, patch, opts...)
			}
			if f.Mode == "lost" {
				if err := c.Patch(ctx, obj, patch, opts...); err != nil {
					return err
				}
				return io.ErrUnexpectedEOF
			}
			return injectedError(f.Mode, obj.GetName())
		},
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			_, f := in.next("delete")
			if f == nil {
				return c.Delete(ctx, obj, opts...)
			}
			switch f.Mode {
			case "lost":
				if err := c.Delete(ctx, obj, opts...); err != nil {
					return err
				}
				return io.ErrUnexpectedEOF
			case "replaced":
				return in.replaceDuringDelete(ctx, c, obj, opts)
			default:
				return injectedError(f.Mode, obj.GetName())
			}
		},
	})
}

// replaceDuringDelete models a concurrent creator replacing the object before
// the API server evaluates the delete precondition. The replacement has a new
// UID. A delete that pins the old UID conflicts and leaves the replacement; a
// delete without a UID precondition removes whatever currently holds the name.
func (in *faultInjector) replaceDuringDelete(ctx context.Context, c client.WithWatch, obj client.Object, opts []client.DeleteOption) error {
	key := client.ObjectKeyFromObject(obj)
	var live v1alpha1.BlipState
	if err := c.Get(ctx, key, &live); err != nil {
		return err
	}
	replacement := live.DeepCopy()
	replacement.UID = simReplacementUID(obj.GetName())
	replacement.ResourceVersion = ""
	replacement.ManagedFields = nil
	if err := c.Delete(ctx, &live); err != nil {
		return err
	}
	if err := c.Create(ctx, replacement); err != nil {
		return err
	}
	options := &client.DeleteOptions{}
	options.ApplyOptions(opts)
	if options.Preconditions == nil || options.Preconditions.UID == nil {
		return c.Delete(ctx, replacement)
	}
	if *options.Preconditions.UID != replacement.UID {
		return apierrors.NewConflict(simStateResource, obj.GetName(), errors.New("UID precondition failed"))
	}
	return c.Delete(ctx, replacement)
}

type simRef struct {
	Name string `json:"name"`
	UID  string `json:"uid"`
}

type forkResult struct {
	ErrClass string     `json:"errClass"`
	ErrText  string     `json:"errText,omitempty"`
	Created  []simRef   `json:"created,omitempty"`
	Dest     *simObject `json:"dest,omitempty"`
}

func classifyError(err error) string {
	if err == nil {
		return "ok"
	}
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "transport"
	case apierrors.IsNotFound(err):
		return "notfound"
	case apierrors.IsAlreadyExists(err):
		return "alreadyexists"
	case apierrors.IsInvalid(err):
		return "invalid"
	case apierrors.IsUnauthorized(err):
		return "unauthorized"
	case apierrors.IsForbidden(err):
		return "forbidden"
	case apierrors.IsConflict(err):
		return "conflict"
	case apierrors.IsInternalError(err):
		return "internal"
	default:
		return "other"
	}
}

// forkWant is the expected outcome of one plan. Extras names every state that
// may exist in addition to the fixture; Replaced marks an extra whose UID was
// changed by a concurrent creator during rollback.
type forkWant struct {
	Success  bool
	ErrClass string
	Extras   []string
	Replaced []string
}

type forkCase struct {
	action string
	faults []fault
	want   forkWant
}

func newForkCases(f *forkFixture) []forkCase {
	var cases []forkCase
	add := func(want forkWant, faults ...fault) {
		cases = append(cases, forkCase{action: faultAction(faults), faults: faults, want: want})
	}
	getModes := func(mountRead bool) []string {
		if mountRead {
			return []string{"notfound", "transport", "server", "reject"}
		}
		return []string{"transport", "server", "reject"}
	}
	if f.collision {
		// Preflight sees the existing destination before any create. Only
		// reads can fail before the collision is reported.
		add(forkWant{ErrClass: "alreadyexists"})
		for i := 1; i <= 6; i++ {
			for _, mode := range getModes(i <= 3) {
				add(forkWant{ErrClass: faultClass(mode)}, fault{Op: "get", Index: i, Mode: mode})
			}
		}
		return cases
	}

	children := f.childNames()
	all := append(slices.Clone(children), f.dest.Name)
	add(forkWant{Success: true, ErrClass: "ok", Extras: all})

	// Every Get before the create loop is a preflight read. A failure there
	// leaves the world untouched.
	for i := 1; i <= 6; i++ {
		for _, mode := range getModes(i <= 3) {
			add(forkWant{ErrClass: faultClass(mode)}, fault{Op: "get", Index: i, Mode: mode})
		}
	}

	// Creates run in mount order and then the root.
	for _, index := range []int{1, 2, 3} {
		for _, mode := range []string{"reject", "transport", "server", "lost"} {
			want := forkWant{ErrClass: faultClass(mode)}
			switch mode {
			case "reject":
				// A definitive rejection proves this request created nothing,
				// so every earlier copy is rolled back.
			case "transport", "server":
				// The request never committed. A failed root create is still
				// ambiguous to Fork, which preserves the children because the
				// root may have persisted.
				if index == len(children)+1 {
					want.Extras = slices.Clone(children)
				}
			case "lost":
				// The create committed. The failed copy, or the root and all
				// its copies, survive. Earlier copies are rolled back.
				if index == len(children)+1 {
					want.Extras = all
				} else {
					want.Extras = []string{children[index-1]}
				}
			}
			add(want, fault{Op: "create", Index: index, Mode: mode})
		}
	}

	// A failed ownership patch rolls back every created state, root included.
	for _, index := range []int{1, 2} {
		for _, mode := range []string{"reject", "transport", "server", "lost"} {
			add(forkWant{ErrClass: faultClass(mode)}, fault{Op: "patch", Index: index, Mode: mode})
		}
	}

	// Cleanup failures. Delete order is newest first, so delete/1 removes the
	// last known created state.
	//
	// create/2/transport rolls back the first copy; the delete finds a
	// replacement and must not remove it.
	add(forkWant{ErrClass: "transport", Extras: []string{children[0]}, Replaced: []string{children[0]}},
		fault{Op: "create", Index: 2, Mode: "transport"}, fault{Op: "delete", Index: 1, Mode: "replaced"})
	// A rejected root create deletes both copies. A rejected first delete
	// leaves the second copy behind.
	add(forkWant{ErrClass: "forbidden", Extras: []string{children[1]}},
		fault{Op: "create", Index: 3, Mode: "reject"}, fault{Op: "delete", Index: 1, Mode: "reject"})
	// A committed delete whose response was lost removed the object; only the
	// reported error remains.
	add(forkWant{ErrClass: "transport"},
		fault{Op: "create", Index: 3, Mode: "reject"}, fault{Op: "delete", Index: 2, Mode: "lost"})
	// A failed ownership patch deletes root, then the second copy, then the
	// first. Rejecting the second delete leaves that copy.
	add(forkWant{ErrClass: "transport", Extras: []string{children[1]}},
		fault{Op: "patch", Index: 1, Mode: "transport"}, fault{Op: "delete", Index: 2, Mode: "reject"})
	// A committed second copy create is an orphan; its earlier sibling's
	// cleanup also fails, so both copies survive.
	add(forkWant{ErrClass: "transport", Extras: children},
		fault{Op: "create", Index: 2, Mode: "lost"}, fault{Op: "delete", Index: 1, Mode: "reject"})
	return cases
}

// forkSim is one fork attempt. Objects and Result are empty until Step runs.
type forkSim struct {
	fixture *forkFixture
	cases   []forkCase
	action  string
	ran     bool
	objects []simObject
	result  *forkResult
}

func newForkSim(collision bool) *forkSim {
	fixture := newForkFixture(collision)
	return &forkSim{fixture: fixture, cases: newForkCases(fixture)}
}

func cloneObjects(objects []simObject) []simObject {
	if objects == nil {
		return nil
	}
	out := make([]simObject, len(objects))
	for i, o := range objects {
		out[i] = o
		out[i].Labels = maps.Clone(o.Labels)
		out[i].OwnerReferences = slices.Clone(o.OwnerReferences)
		out[i].Runtime = o.Runtime.DeepCopy()
		out[i].Mounts = slices.Clone(o.Mounts)
		out[i].NodeSelector = maps.Clone(o.NodeSelector)
	}
	return out
}

func (m *forkSim) Clone() sim.Model {
	c := *m
	c.objects = cloneObjects(m.objects)
	if m.result != nil {
		r := *m.result
		r.Created = slices.Clone(m.result.Created)
		if m.result.Dest != nil {
			dest := *m.result.Dest
			dest.Labels = maps.Clone(dest.Labels)
			dest.OwnerReferences = slices.Clone(dest.OwnerReferences)
			dest.Runtime = dest.Runtime.DeepCopy()
			dest.Mounts = slices.Clone(dest.Mounts)
			dest.NodeSelector = maps.Clone(dest.NodeSelector)
			r.Dest = &dest
		}
		c.result = &r
	}
	return &c
}

func (m *forkSim) Key() string {
	encoded, err := json.Marshal(struct {
		Fixture string      `json:"fixture"`
		Action  string      `json:"action"`
		Ran     bool        `json:"ran"`
		Objects []simObject `json:"objects"`
		Result  *forkResult `json:"result,omitempty"`
	}{Fixture: m.fixture.name, Action: m.action, Ran: m.ran, Objects: m.objects, Result: m.result})
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

func (m *forkSim) Enabled() []string {
	if m.ran {
		return nil
	}
	actions := make([]string, 0, len(m.cases))
	for _, c := range m.cases {
		actions = append(actions, c.action)
	}
	return actions
}

func listStates(ctx context.Context, c client.Client) ([]simObject, error) {
	var list v1alpha1.BlipStateList
	if err := c.List(ctx, &list); err != nil {
		return nil, err
	}
	objects := make([]simObject, 0, len(list.Items))
	for i := range list.Items {
		objects = append(objects, captureState(&list.Items[i]))
	}
	slices.SortFunc(objects, func(a, b simObject) int {
		if a.Namespace != b.Namespace {
			return strings.Compare(a.Namespace, b.Namespace)
		}
		return strings.Compare(a.Name, b.Name)
	})
	return objects, nil
}

func (m *forkSim) Step(action string) error {
	if m.ran {
		return fmt.Errorf("fork simulation already ran action %q", m.action)
	}
	var chosen *forkCase
	for i := range m.cases {
		if m.cases[i].action == action {
			chosen = &m.cases[i]
			break
		}
	}
	if chosen == nil {
		return fmt.Errorf("unknown fork plan %q", action)
	}
	m.action = action

	base, err := m.fixture.baseClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	injector := newFaultInjector(base, chosen.faults)
	dest := m.fixture.dest.DeepCopy()
	source := m.fixture.source.DeepCopy()
	var opts *ForkOptions
	if m.fixture.owner != nil {
		owner := *m.fixture.owner
		opts = &ForkOptions{Owner: &owner}
	}
	created, forkErr := Fork(ctx, injector.client(), source, dest, opts)
	objects, err := listStates(ctx, base)
	if err != nil {
		return err
	}
	m.objects = objects
	destSnapshot := captureState(dest)
	m.result = &forkResult{ErrClass: classifyError(forkErr), Dest: &destSnapshot}
	if forkErr != nil {
		m.result.ErrText = forkErr.Error()
	}
	for _, st := range created {
		m.result.Created = append(m.result.Created, simRef{Name: st.Name, UID: string(st.UID)})
	}
	m.ran = true
	return nil
}

func (m *forkSim) wanted() (forkWant, error) {
	for _, c := range m.cases {
		if c.action == m.action {
			return c.want, nil
		}
	}
	return forkWant{}, fmt.Errorf("no expectation for action %q", m.action)
}

func objectKey(o simObject) string { return o.Namespace + "/" + o.Name }

func (m *forkSim) Check() error {
	if !m.ran {
		if len(m.cases) == 0 {
			return errors.New("initial model has no fork plans")
		}
		return nil
	}
	want, err := m.wanted()
	if err != nil {
		return err
	}
	if m.result == nil {
		return errors.New("fork ran without recording a result")
	}

	byKey := make(map[string]simObject, len(m.objects))
	for _, o := range m.objects {
		byKey[objectKey(o)] = o
	}

	preExisting := make(map[string]simObject)
	for _, o := range m.fixture.preExisting() {
		preExisting[objectKey(o)] = o
		got, ok := byKey[objectKey(o)]
		if !ok {
			return fmt.Errorf("pre-existing state %q was deleted", o.Name)
		}
		if !reflect.DeepEqual(got, o) {
			return fmt.Errorf("pre-existing state %q changed: got %+v, want %+v", o.Name, got, o)
		}
	}

	extras := make([]simObject, 0)
	for _, o := range m.objects {
		if _, ok := preExisting[objectKey(o)]; !ok {
			extras = append(extras, o)
		}
	}
	allowed := make(map[string]bool, len(want.Extras))
	for _, name := range want.Extras {
		allowed[simNamespace+"/"+name] = true
	}
	for _, o := range extras {
		if o.Namespace != simNamespace {
			return fmt.Errorf("state %q landed in namespace %q", o.Name, o.Namespace)
		}
		if !allowed[objectKey(o)] {
			return fmt.Errorf("unexpected state created by Fork: %s (uid %s)", o.Name, o.UID)
		}
		expectedUID := simUID(o.Name)
		if slices.Contains(want.Replaced, o.Name) {
			expectedUID = simReplacementUID(o.Name)
		}
		if o.UID != string(expectedUID) {
			return fmt.Errorf("state %q has UID %q, want %q", o.Name, o.UID, expectedUID)
		}
	}
	if len(extras) != len(want.Extras) {
		return fmt.Errorf("created %d states, want %d: got %+v", len(extras), len(want.Extras), extras)
	}
	for _, name := range want.Extras {
		if _, ok := byKey[simNamespace+"/"+name]; !ok {
			return fmt.Errorf("expected state %q is missing", name)
		}
	}

	children := m.fixture.writableChildren()
	for _, child := range children {
		o, ok := byKey[simNamespace+"/"+child.name]
		if !ok {
			continue
		}
		if o.CopyFrom != child.mount.State {
			return fmt.Errorf("copy %q copies %q, want %q", o.Name, o.CopyFrom, child.mount.State)
		}
		if o.Runtime != nil || len(o.Mounts) != 0 {
			return fmt.Errorf("copy %q inherited mounted configuration: %+v", o.Name, o)
		}
		if o.Replicas != m.fixture.dest.Spec.Replicas {
			return fmt.Errorf("copy %q has %d replicas, want %d", o.Name, o.Replicas, m.fixture.dest.Spec.Replicas)
		}
		if !maps.Equal(o.NodeSelector, m.fixture.dest.Spec.NodeSelector) {
			return fmt.Errorf("copy %q node selector: %+v", o.Name, o.NodeSelector)
		}
		if !maps.Equal(o.Labels, m.fixture.dest.Labels) {
			return fmt.Errorf("copy %q labels: %+v", o.Name, o.Labels)
		}
	}

	rootKey := simNamespace + "/" + m.fixture.dest.Name
	root, rootExists := byKey[rootKey]
	if _, createdRoot := allowed[rootKey]; createdRoot && rootExists {
		if err := m.checkRoot(root); err != nil {
			return err
		}
		// The root references either a fixture state or a copy this call
		// created. An ambiguous root create must not leave a dangling mount.
		for _, mount := range root.Mounts {
			if _, ok := byKey[simNamespace+"/"+mount.State]; !ok {
				return fmt.Errorf("root references missing mounted state %q", mount.State)
			}
		}
	}

	if want.Success {
		if m.result.ErrClass != "ok" || m.result.ErrText != "" {
			return fmt.Errorf("successful fork recorded error %s: %s", m.result.ErrClass, m.result.ErrText)
		}
		expectedCreated := append(slices.Clone(m.fixture.childNames()), m.fixture.dest.Name)
		if len(m.result.Created) != len(expectedCreated) {
			return fmt.Errorf("returned %d states, want %d: %+v", len(m.result.Created), len(expectedCreated), m.result.Created)
		}
		for i, name := range expectedCreated {
			ref := m.result.Created[i]
			if ref.Name != name || ref.UID != string(simUID(name)) {
				return fmt.Errorf("returned state %d is %+v, want %s with uid %s", i, ref, name, simUID(name))
			}
			live, ok := byKey[simNamespace+"/"+name]
			if !ok || live.UID != ref.UID {
				return fmt.Errorf("returned state %q does not exist with uid %q", name, ref.UID)
			}
		}
		if m.result.Created[len(m.result.Created)-1].Name != m.fixture.dest.Name {
			return fmt.Errorf("root is not last: %+v", m.result.Created)
		}
		if m.result.Dest == nil || !reflect.DeepEqual(*m.result.Dest, root) {
			return fmt.Errorf("destination does not match returned root")
		}
		for _, child := range children {
			o, ok := byKey[simNamespace+"/"+child.name]
			if !ok {
				return fmt.Errorf("returned copy %q does not exist", child.name)
			}
			wantOwner := metav1.OwnerReference{
				APIVersion: v1alpha1.GroupVersion.String(),
				Kind:       "BlipState",
				Name:       m.fixture.dest.Name,
				UID:        simUID(m.fixture.dest.Name),
			}
			if m.fixture.owner != nil {
				wantOwner = *m.fixture.owner
			}
			if len(o.OwnerReferences) != 1 || !reflect.DeepEqual(o.OwnerReferences[0], wantOwner) {
				return fmt.Errorf("copy %q owner references: %+v, want %+v", o.Name, o.OwnerReferences, wantOwner)
			}
		}
		return nil
	}

	if m.result.ErrClass != want.ErrClass {
		return fmt.Errorf("fork error class %q, want %q (error: %s)", m.result.ErrClass, want.ErrClass, m.result.ErrText)
	}
	if m.result.ErrText == "" {
		return errors.New("failed fork recorded no error text")
	}
	if len(m.result.Created) != 0 {
		return fmt.Errorf("failed fork returned created states: %+v", m.result.Created)
	}
	if m.result.Dest == nil || !reflect.DeepEqual(*m.result.Dest, captureState(m.fixture.dest)) {
		return errors.New("failed fork modified the destination object")
	}
	return nil
}

func (m *forkSim) checkRoot(root simObject) error {
	if root.CopyFrom != m.fixture.source.Name {
		return fmt.Errorf("root copies %q, want %q", root.CopyFrom, m.fixture.source.Name)
	}
	if !reflect.DeepEqual(root.Runtime, m.fixture.source.Spec.Runtime) {
		return fmt.Errorf("root runtime: %+v, want %+v", root.Runtime, m.fixture.source.Spec.Runtime)
	}
	wantMounts := m.fixture.rootMounts()
	if !reflect.DeepEqual(root.Mounts, wantMounts) {
		return fmt.Errorf("root mounts: %+v, want %+v", root.Mounts, wantMounts)
	}
	if root.Replicas != m.fixture.dest.Spec.Replicas {
		return fmt.Errorf("root has %d replicas, want %d", root.Replicas, m.fixture.dest.Spec.Replicas)
	}
	if !maps.Equal(root.NodeSelector, m.fixture.dest.Spec.NodeSelector) {
		return fmt.Errorf("root node selector: %+v", root.NodeSelector)
	}
	if !maps.Equal(root.Labels, m.fixture.dest.Labels) {
		return fmt.Errorf("root labels: %+v", root.Labels)
	}
	if m.fixture.owner == nil {
		if len(root.OwnerReferences) != 0 {
			return fmt.Errorf("durable root has owner references: %+v", root.OwnerReferences)
		}
	} else if len(root.OwnerReferences) != 1 || !reflect.DeepEqual(root.OwnerReferences[0], *m.fixture.owner) {
		return fmt.Errorf("root owner references: %+v", root.OwnerReferences)
	}
	return nil
}

// TestForkSimulationExploration exhausts every fault plan for a durable fork
// and for a destination collision. Depth is one: after the fork attempt there
// are no further actions.
func TestForkSimulationExploration(t *testing.T) {
	for _, collision := range []bool{false, true} {
		name := "durable"
		if collision {
			name = "collision"
		}
		t.Run(name, func(t *testing.T) {
			initial := newForkSim(collision)
			t.Logf("fault plans: %d", len(initial.cases))
			report := simtest.Explore(t, initial, sim.Limits{States: 500, Depth: 1})
			if !report.Complete {
				t.Fatalf("incomplete exploration: %+v", report)
			}
			t.Logf("%d states, %d transitions", report.States, report.Transitions)
		})
	}
}

// TestForkSimulationSeededReplay proves that the model and its fault plan
// matrix are deterministic: every seed replays to exactly the same keys.
func TestForkSimulationSeededReplay(t *testing.T) {
	for _, collision := range []bool{false, true} {
		name := "durable"
		if collision {
			name = "collision"
		}
		t.Run(name, func(t *testing.T) {
			initial := newForkSim(collision)
			seeds := make([]uint64, 20)
			for i := range seeds {
				seeds[i] = uint64(i)
			}
			simtest.Run(t, initial, seeds, 1)
			if initial.ran || len(initial.Enabled()) != len(initial.cases) {
				t.Fatal("Run or Replay mutated the initial model")
			}
		})
	}
}

// TestForkSimulationNegativeControl verifies that Check detects a corrupted
// pre-existing state rather than accepting every model.
func TestForkSimulationNegativeControl(t *testing.T) {
	model := newForkSim(false)
	if err := model.Step("normal"); err != nil {
		t.Fatal(err)
	}
	if err := model.Check(); err != nil {
		t.Fatalf("baseline model: %v", err)
	}
	broken := model.Clone().(*forkSim)
	for i := range broken.objects {
		if broken.objects[i].Name == "repo" {
			broken.objects[i].Labels = map[string]string{"mutated": "yes"}
		}
	}
	if err := broken.Check(); err == nil {
		t.Fatal("Check accepted a mutated pre-existing state")
	}
	if err := model.Check(); err != nil {
		t.Fatalf("negative control mutated the original model: %v", err)
	}
}
