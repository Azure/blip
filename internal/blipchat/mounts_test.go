// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

func demoMountSelector() metav1.LabelSelector {
	return metav1.LabelSelector{MatchLabels: map[string]string{
		v1.LabelShared:  "true",
		v1.LabelGitRepo: "demo",
	}}
}

func newMountServer(t *testing.T, c Cluster, profile Profile) *Server {
	t.Helper()
	s, err := New(Options{
		Namespace: "team",
		Cluster:   c,
		Wire:      newFakeWire(),
		Profiles:  Profiles{DefaultProfileName: profile},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// addMountSource inserts a state directly so a test controls the fields the
// selection rule reads.
func addMountSource(t *testing.T, fc *fakeCluster, name string, state v1.BlipState, deleting bool) *v1.BlipState {
	t.Helper()
	st := state.DeepCopy()
	st.Name = name
	st.Namespace = "team"
	if deleting {
		now := metav1.Now()
		st.DeletionTimestamp = &now
	}
	fc.mu.Lock()
	fc.states[key("team", name)] = st
	fc.mu.Unlock()
	return st
}

func committedState(committed time.Time) v1.BlipState {
	return v1.BlipState{
		Labels: map[string]string{v1.LabelShared: "true", v1.LabelGitRepo: "demo"},
		Status: v1.BlipStateStatus{
			Phase:     v1.StateReady,
			Committed: &v1.Commit{Time: metav1.NewTime(committed)},
		},
	}
}

func TestProfileParsesMounts(t *testing.T) {
	raw := `{"command":["agent"],"mounts":[{"path":"/src/demo","selector":{"matchLabels":{"git.blip.dev/repo":"demo"}}}]}`
	var p Profile
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatal(err)
	}
	if len(p.Mounts) != 1 || p.Mounts[0].Path != "/src/demo" {
		t.Fatalf("mounts = %+v", p.Mounts)
	}
	sel, err := p.Mounts[0].selector()
	if err != nil {
		t.Fatal(err)
	}
	if !sel.Matches(labels.Set{v1.LabelGitRepo: "demo"}) {
		t.Fatal("selector does not match the configured labels")
	}
	if sel.Matches(labels.Set{v1.LabelGitRepo: "demo", LabelSession: "true"}) {
		t.Fatal("selector matches a chat state")
	}
	if got := p.mountPaths(); len(got) != 1 || got[0] != "/src/demo" {
		t.Fatalf("mountPaths = %v", got)
	}
}

func TestProfileRejectsInvalidMounts(t *testing.T) {
	good := demoMountSelector()
	bad := metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
		Key: "app", Operator: "Bogus",
	}}}
	for _, tc := range []struct {
		name  string
		mount ProfileMount
		want  string
	}{
		{"relative path", ProfileMount{Path: "src/demo", Selector: good}, "must be absolute"},
		{"unclean path", ProfileMount{Path: "/src/../demo", Selector: good}, "is not clean"},
		{"guest root", ProfileMount{Path: "/", Selector: good}, "guest root"},
		{"reserved path", ProfileMount{Path: "/run/blip/state", Selector: good}, "reserved by the guest"},
		{"empty selector", ProfileMount{Path: "/src/demo"}, "needs a selector"},
		{"invalid selector", ProfileMount{Path: "/src/demo", Selector: bad}, "mount \"/src/demo\""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := (Profile{Workspace: WorkspaceBase, Mounts: []ProfileMount{tc.mount}}).validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}

	err := (Profile{Workspace: WorkspaceBase, Mounts: []ProfileMount{
		{Path: "/src/demo", Selector: good},
		{Path: "/src/demo", Selector: good},
	}}).validate()
	if err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("duplicate path error = %v", err)
	}
}

func TestMountStateNameStaysALabel(t *testing.T) {
	long := strings.Repeat("s", 63)
	name := mountStateName(long+".example", "/src/"+strings.Repeat("p", 100))
	if !validDNSLabel(name) || len(name) > 63 {
		t.Fatalf("mount name %q is not a legal DNS label", name)
	}
	if a, b := mountStateName(long, "/src/demo"), mountStateName(long, "/src/demo"); a != b {
		t.Fatalf("mount name is not stable: %q vs %q", a, b)
	}
	if a, b := mountStateName("chat-1", "/src/a"), mountStateName("chat-1", "/src/b"); a == b {
		t.Fatalf("distinct paths share the mount name %q", a)
	}
}

func TestNewestStateSelectsNewestUsable(t *testing.T) {
	fc := newFakeCluster()
	s := newMountServer(t, fc, Profile{Command: []string{"agent"}})
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	addMountSource(t, fc, "cache-old", committedState(base), false)
	newest := addMountSource(t, fc, "cache-new", committedState(base.Add(time.Hour)), false)
	addMountSource(t, fc, "cache-copying", v1.BlipState{
		Labels: map[string]string{v1.LabelShared: "true", v1.LabelGitRepo: "demo"},
		Status: v1.BlipStateStatus{Phase: v1.StatePending,
			Committed: &v1.Commit{Time: metav1.NewTime(base.Add(2 * time.Hour))}},
	}, false)
	addMountSource(t, fc, "cache-uncommitted", v1.BlipState{
		Labels: map[string]string{v1.LabelShared: "true", v1.LabelGitRepo: "demo"},
		Status: v1.BlipStateStatus{Phase: v1.StateReady},
	}, false)
	addMountSource(t, fc, "cache-deleting", committedState(base.Add(3*time.Hour)), true)
	addMountSource(t, fc, "cache-chat", v1.BlipState{
		Labels: map[string]string{v1.LabelShared: "true", v1.LabelGitRepo: "demo", LabelSession: "true"},
		Status: v1.BlipStateStatus{Phase: v1.StateReady,
			Committed: &v1.Commit{Time: metav1.NewTime(base.Add(4 * time.Hour))}},
	}, false)

	selector, err := ProfileMount{Selector: demoMountSelector()}.selector()
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.newestState(context.Background(), selector)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Name != newest.Name {
		t.Fatalf("newest = %+v, want %s", got, newest.Name)
	}

	// Equal commit times fall back to the name so the choice is stable.
	addMountSource(t, fc, "cache-aaa", committedState(base.Add(5*time.Hour)), false)
	last := addMountSource(t, fc, "cache-zzz", committedState(base.Add(5*time.Hour)), false)
	got, err = s.newestState(context.Background(), selector)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Name != last.Name {
		t.Fatalf("tie-break newest = %+v, want %s", got, last.Name)
	}

	// A selector that matches no state reports nil instead of an error.
	none, err := (ProfileMount{Selector: metav1.LabelSelector{
		MatchLabels: map[string]string{"git.blip.dev/repo": "missing"},
	}}).selector()
	if err != nil {
		t.Fatal(err)
	}
	got, err = s.newestState(context.Background(), none)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("newest for a missing selector = %+v", got)
	}
}

func TestCreateChatAttachesProfileMount(t *testing.T) {
	ctx := context.Background()
	fc := newFakeCluster()
	cache := addMountSource(t, fc, "gitcache-demo-1", committedState(time.Now()), false)
	profile := Profile{Command: []string{"agent"}, Mounts: []ProfileMount{{
		Path: "/src/demo", Selector: demoMountSelector(),
	}}}
	g := newGatewayWithCluster(t, fc, Options{Profiles: Profiles{DefaultProfileName: profile}})

	created, err := g.srv.createChat(ctx, chatRequest{})
	if err != nil {
		t.Fatal(err)
	}
	copyName := mountStateName(created.Name, "/src/demo")
	copied, err := fc.GetSession(ctx, "team", copyName)
	if err != nil {
		t.Fatalf("mount copy %s: %v", copyName, err)
	}
	if copied.Spec.CopyFrom != cache.Name {
		t.Fatalf("copyFrom = %q, want %q", copied.Spec.CopyFrom, cache.Name)
	}
	if copied.Labels[LabelSession] != "true" || copied.Labels[v1.LabelOwner] != created.Name {
		t.Fatalf("copy labels = %v", copied.Labels)
	}
	if len(copied.OwnerReferences) != 1 {
		t.Fatalf("copy owner references = %+v", copied.OwnerReferences)
	}
	ref := copied.OwnerReferences[0]
	if ref.Kind != "BlipState" || ref.Name != created.Name || ref.UID != created.UID {
		t.Fatalf("copy owner reference = %+v, want chat %s", ref, created.Name)
	}

	root, err := fc.GetSession(ctx, "team", created.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(root.Spec.Mounts) != 1 {
		t.Fatalf("root mounts = %+v", root.Spec.Mounts)
	}
	m := root.Spec.Mounts[0]
	if m.State != copyName || m.Path != "/src/demo" || !m.Writable {
		t.Fatalf("root mount = %+v, want writable %s at /src/demo", m, copyName)
	}

	chats, err := fc.ListSessions(ctx, "team")
	if err != nil {
		t.Fatal(err)
	}
	if len(chats) != 1 || chats[0].Name != created.Name {
		t.Fatalf("chats = %+v, want only %s", chats, created.Name)
	}

	text, err := g.srv.toolListProfiles()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "/src/demo") {
		t.Fatalf("list_profiles does not report the mount: %s", text)
	}
}

func TestCreateChatWithoutMountSourceLeavesNoChat(t *testing.T) {
	ctx := context.Background()
	fc := newFakeCluster()
	profile := Profile{Command: []string{"agent"}, Mounts: []ProfileMount{{
		Path: "/src/demo", Selector: demoMountSelector(),
	}}}
	g := newGatewayWithCluster(t, fc, Options{Profiles: Profiles{DefaultProfileName: profile}})

	_, err := g.srv.createChat(ctx, chatRequest{})
	var noBase noBaseError
	if !errors.As(err, &noBase) {
		t.Fatalf("error = %v, want noBaseError", err)
	}
	if !strings.Contains(err.Error(), "/src/demo") {
		t.Fatalf("error = %v, want the mount path", err)
	}
	chats, err := fc.ListSessions(ctx, "team")
	if err != nil {
		t.Fatal(err)
	}
	if len(chats) != 0 {
		t.Fatalf("created %d chats without a mount source", len(chats))
	}
}

// failingMountCluster rejects the private copy a mount creates, leaving the
// root creation to succeed so cleanup can be observed.
type failingMountCluster struct {
	*fakeCluster
}

func (c failingMountCluster) CreateSession(ctx context.Context, ns string, st *v1.BlipState) error {
	if strings.Contains(st.Name, "-m-") {
		return errors.New("no space for a mount copy")
	}
	return c.fakeCluster.CreateSession(ctx, ns, st)
}

func TestCreateChatRemovesChatWhenMountCopyFails(t *testing.T) {
	ctx := context.Background()
	fc := newFakeCluster()
	addMountSource(t, fc, "gitcache-demo-1", committedState(time.Now()), false)
	profile := Profile{Command: []string{"agent"}, Mounts: []ProfileMount{{
		Path: "/src/demo", Selector: demoMountSelector(),
	}}}
	s := newMountServer(t, failingMountCluster{fc}, profile)

	_, err := s.createChat(ctx, chatRequest{})
	if err == nil || !strings.Contains(err.Error(), "no space for a mount copy") {
		t.Fatalf("error = %v", err)
	}
	chats, err := fc.ListSessions(ctx, "team")
	if err != nil {
		t.Fatal(err)
	}
	if len(chats) != 0 {
		t.Fatalf("failed chat was not removed: %+v", chats)
	}
}

func TestForkChatSkipsInheritedMountPaths(t *testing.T) {
	ctx := context.Background()
	fc := newFakeCluster()
	other := addMountSource(t, fc, "gitcache-other-1", v1.BlipState{
		Labels: map[string]string{v1.LabelShared: "true", v1.LabelGitRepo: "other"},
		Status: v1.BlipStateStatus{Phase: v1.StateReady, Committed: &v1.Commit{Time: metav1.Now()}},
	}, false)
	parent := &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "chat-parent",
			Namespace: "team",
			UID:       "uid-parent",
			Labels:    map[string]string{LabelSession: "true", v1.LabelOwner: "chat-parent"},
			Annotations: map[string]string{
				AnnotationProfile: DefaultProfileName,
				AnnotationRoot:    "chat-parent",
				AnnotationDepth:   "0",
			},
		},
		Spec: v1.BlipStateSpec{Mounts: []v1.Mount{
			{State: "parent-copy", Path: "/src/demo", Writable: true},
		}},
		Status: v1.BlipStateStatus{Phase: v1.StateReady},
	}
	if err := fc.CreateSession(ctx, "team", parent); err != nil {
		t.Fatal(err)
	}

	profile := Profile{
		Command:   []string{"agent"},
		Workspace: WorkspaceFork,
		Mounts: []ProfileMount{
			// The fork already has this path, so its selector need not match.
			{Path: "/src/demo", Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "missing"}}},
			{Path: "/src/other", Selector: metav1.LabelSelector{MatchLabels: map[string]string{
				v1.LabelShared: "true", v1.LabelGitRepo: "other",
			}}},
		},
	}
	g := newGatewayWithCluster(t, fc, Options{Profiles: Profiles{
		DefaultProfileName: {Command: []string{"agent"}},
		"forked":           profile,
	}})

	created, err := g.srv.createChat(ctx, chatRequest{Profile: "forked", Parent: parent})
	if err != nil {
		t.Fatal(err)
	}
	root, err := fc.GetSession(ctx, "team", created.Name)
	if err != nil {
		t.Fatal(err)
	}
	var mounted []v1.Mount
	for _, m := range root.Spec.Mounts {
		if m.Path == "/src/other" {
			mounted = append(mounted, m)
		}
	}
	if len(mounted) != 1 || !mounted[0].Writable {
		t.Fatalf("root mounts = %+v, want a writable /src/other", root.Spec.Mounts)
	}
	copied, err := fc.GetSession(ctx, "team", mounted[0].State)
	if err != nil {
		t.Fatal(err)
	}
	if copied.Spec.CopyFrom != other.Name {
		t.Fatalf("copyFrom = %q, want %q", copied.Spec.CopyFrom, other.Name)
	}
	if _, err := fc.GetSession(ctx, "team", mountStateName(created.Name, "/src/demo")); err == nil {
		t.Fatal("created a copy for an inherited mount path")
	}
}
