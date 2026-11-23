// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

func newRepoServer(t *testing.T, fc *fakeCluster) *Server {
	t.Helper()
	s, err := New(Options{
		Namespace: "team",
		Cluster:   fc,
		Wire:      newFakeWire(),
		Log:       testLogger(),
		Profiles:  Profiles{DefaultProfileName: {Command: []string{"agent"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// newRepoCaller creates the chat state and its running blip, then returns the
// caller a token review would have produced.
func newRepoCaller(t *testing.T, fc *fakeCluster, name, owner string) *Caller {
	t.Helper()
	ctx := context.Background()
	st := &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "team",
			UID:       types.UID(name + "-uid"),
			Labels:    map[string]string{LabelSession: "true", v1.LabelOwner: owner},
			Annotations: map[string]string{
				AnnotationProfile: DefaultProfileName,
				AnnotationRoot:    name,
				AnnotationDepth:   "0",
			},
		},
		Status: v1.BlipStateStatus{Phase: v1.StateReady},
	}
	if err := fc.CreateSession(ctx, "team", st); err != nil {
		t.Fatal(err)
	}
	blip := &v1.Blip{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name + "-g1",
			Namespace: "team",
			Labels:    map[string]string{LabelSession: name},
		},
		Spec: v1.BlipSpec{State: name, Command: []string{"agent"}},
	}
	if err := fc.CreateBlip(ctx, "team", blip); err != nil {
		t.Fatal(err)
	}
	return refreshRepoCaller(t, fc, name)
}

// refreshRepoCaller re-reads the objects as a new MCP request would.
func refreshRepoCaller(t *testing.T, fc *fakeCluster, name string) *Caller {
	t.Helper()
	ctx := context.Background()
	st, err := fc.GetSession(ctx, "team", name)
	if err != nil {
		t.Fatal(err)
	}
	blip, err := fc.GetBlip(ctx, "team", name+"-g1")
	if err != nil {
		t.Fatal(err)
	}
	return &Caller{Namespace: "team", Session: st, Blip: blip}
}

func newRepoCache(t *testing.T, fc *fakeCluster, name, repo string, committed time.Time) *v1.BlipState {
	t.Helper()
	st := &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "team",
			Labels:    map[string]string{v1.LabelShared: "true", v1.LabelGitRepo: repo},
			Annotations: map[string]string{
				v1.AnnotationGitURL:    "https://example.com/" + repo + ".git",
				v1.AnnotationGitBranch: "main",
			},
		},
		Status: v1.BlipStateStatus{
			Phase:     v1.StateReady,
			Committed: &v1.Commit{ID: name + "-commit", Time: metav1.NewTime(committed)},
		},
	}
	fc.mu.Lock()
	fc.states[key("team", name)] = st
	fc.mu.Unlock()
	return st
}

func decodeRepoClaim(t *testing.T, text string) repoClaim {
	t.Helper()
	var out repoClaim
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("claim_repo result %q: %v", text, err)
	}
	return out
}

func findMount(mounts []v1.Mount, path string) *v1.Mount {
	for i := range mounts {
		if mounts[i].Path == path {
			return &mounts[i]
		}
	}
	return nil
}

func TestClaimRepoCreatesPrivateCopy(t *testing.T) {
	ctx := context.Background()
	fc := newFakeCluster()
	s := newRepoServer(t, fc)
	caller := newRepoCaller(t, fc, "chat-1", "alice")
	cache := newRepoCache(t, fc, "cache-demo-1", "demo", time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))

	text, err := s.toolClaimRepo(ctx, caller, " demo ", "")
	if err != nil {
		t.Fatal(err)
	}
	out := decodeRepoClaim(t, text)
	wantName := repoClaimName("chat-1", "demo")
	if out.Repo != "demo" || out.Path != "/src/demo" || out.State != wantName {
		t.Fatalf("claim = %+v, want repo demo at /src/demo as %s", out, wantName)
	}
	if !out.Mounted {
		t.Fatalf("claim reported not mounted: %+v", out)
	}
	if out.URL != cache.Annotations[v1.AnnotationGitURL] || out.Branch != "main" {
		t.Fatalf("cache metadata = %+v", out)
	}
	if out.CachedAt != "2026-01-02T03:04:05Z" {
		t.Fatalf("cachedAt = %q", out.CachedAt)
	}
	if !strings.Contains(out.Next, "git -C /src/demo fetch --prune origin") ||
		!strings.Contains(out.Next, "git -C /src/demo merge --ff-only origin/main") {
		t.Fatalf("next = %q", out.Next)
	}

	claim, err := fc.GetSession(ctx, "team", wantName)
	if err != nil {
		t.Fatal(err)
	}
	if claim.Spec.CopyFrom != cache.Name {
		t.Fatalf("copyFrom = %q, want %q", claim.Spec.CopyFrom, cache.Name)
	}
	if claim.Labels[v1.LabelChatSession] != "true" || claim.Labels[v1.LabelOwner] != "alice" {
		t.Fatalf("claim labels = %v", claim.Labels)
	}
	if claim.Annotations[v1.AnnotationGitSource] != cache.Name {
		t.Fatalf("source annotation = %q, want %q", claim.Annotations[v1.AnnotationGitSource], cache.Name)
	}
	if len(claim.OwnerReferences) != 1 {
		t.Fatalf("owner references = %+v", claim.OwnerReferences)
	}
	ref := claim.OwnerReferences[0]
	if ref.Kind != "BlipState" || ref.Name != caller.Session.Name || ref.UID != caller.Session.UID {
		t.Fatalf("owner reference = %+v, want the chat state", ref)
	}

	session, err := fc.GetSession(ctx, "team", caller.Session.Name)
	if err != nil {
		t.Fatal(err)
	}
	mount := findMount(session.Spec.Mounts, "/src/demo")
	if mount == nil {
		t.Fatalf("session mounts = %+v", session.Spec.Mounts)
	}
	if mount.State != wantName || !mount.Writable {
		t.Fatalf("mount = %+v, want writable %s", mount, wantName)
	}
}

func TestClaimRepoIsIdempotent(t *testing.T) {
	ctx := context.Background()
	fc := newFakeCluster()
	s := newRepoServer(t, fc)
	caller := newRepoCaller(t, fc, "chat-1", "alice")
	newRepoCache(t, fc, "cache-demo-1", "demo", time.Now().Add(-time.Minute))

	first, err := s.toolClaimRepo(ctx, caller, "demo", "")
	if err != nil {
		t.Fatal(err)
	}
	caller = refreshRepoCaller(t, fc, "chat-1")
	second, err := s.toolClaimRepo(ctx, caller, "demo", "")
	if err != nil {
		t.Fatal(err)
	}
	a, b := decodeRepoClaim(t, first), decodeRepoClaim(t, second)
	if a.Path != b.Path || a.State != b.State || !a.Mounted || !b.Mounted {
		t.Fatalf("claims differ: %+v vs %+v", a, b)
	}

	fc.mu.Lock()
	claims := 0
	for _, st := range fc.states {
		if st.Annotations[v1.AnnotationGitSource] != "" {
			claims++
		}
	}
	fc.mu.Unlock()
	if claims != 1 {
		t.Fatalf("created %d claims, want 1", claims)
	}
}

func TestClaimRepoUnknownRepoListsAvailable(t *testing.T) {
	ctx := context.Background()
	fc := newFakeCluster()
	s := newRepoServer(t, fc)
	caller := newRepoCaller(t, fc, "chat-1", "alice")
	newRepoCache(t, fc, "cache-beta", "beta", time.Now())
	newRepoCache(t, fc, "cache-alpha", "alpha", time.Now())

	_, err := s.toolClaimRepo(ctx, caller, "missing", "")
	if err == nil {
		t.Fatal("claim of an unknown repo succeeded")
	}
	if want := `unknown repo "missing"; available: alpha, beta`; err.Error() != want {
		t.Fatalf("error = %q, want %q", err, want)
	}
}

func TestClaimRepoRefusesUsedPath(t *testing.T) {
	ctx := context.Background()
	fc := newFakeCluster()
	s := newRepoServer(t, fc)
	caller := newRepoCaller(t, fc, "chat-1", "alice")
	newRepoCache(t, fc, "cache-demo-1", "demo", time.Now())
	fc.mu.Lock()
	fc.states[key("team", "other")] = &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: "team"},
		Status:     v1.BlipStateStatus{Phase: v1.StateReady},
	}
	fc.mu.Unlock()
	if _, err := fc.UpdateStateMounts(ctx, "team", "chat-1", v1.Mount{State: "other", Path: "/src/demo"}); err != nil {
		t.Fatal(err)
	}
	caller = refreshRepoCaller(t, fc, "chat-1")

	_, err := s.toolClaimRepo(ctx, caller, "demo", "")
	if err == nil {
		t.Fatal("claim over an occupied path succeeded")
	}
	if want := `path "/src/demo" is already mounted from "other"`; err.Error() != want {
		t.Fatalf("error = %q, want %q", err, want)
	}
}

func TestRepoClaimNameStaysALabel(t *testing.T) {
	longRepo := strings.Repeat("a", 63)
	name := repoClaimName(strings.Repeat("s", 63), longRepo)
	if !validDNSLabel(name) || len(name) > 63 {
		t.Fatalf("claim name %q is not a legal DNS label", name)
	}
	if got := repoClaimName("chat-1", "demo"); got != "chat-1-r-demo" {
		t.Fatalf("short claim name = %q", got)
	}
	if a, b := repoClaimName(strings.Repeat("s", 63), longRepo), repoClaimName(strings.Repeat("s", 63), longRepo); a != b {
		t.Fatalf("claim name is not stable: %q vs %q", a, b)
	}
}

func TestClaimRepoReusesClaimAfterCacheRefresh(t *testing.T) {
	ctx := context.Background()
	fc := newFakeCluster()
	s := newRepoServer(t, fc)
	caller := newRepoCaller(t, fc, "chat-1", "alice")
	older := newRepoCache(t, fc, "cache-demo-1", "demo", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	first, err := s.toolClaimRepo(ctx, caller, "demo", "")
	if err != nil {
		t.Fatal(err)
	}
	// The warmer publishes a newer generation while the chat is still alive.
	newer := newRepoCache(t, fc, "cache-demo-2", "demo", time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC))

	second, err := s.toolClaimRepo(ctx, refreshRepoCaller(t, fc, "chat-1"), "demo", "")
	if err != nil {
		t.Fatalf("claim after cache refresh: %v", err)
	}
	want := decodeRepoClaim(t, first)
	got := decodeRepoClaim(t, second)
	if got.State != want.State || got.Path != want.Path {
		t.Fatalf("second claim = %+v, want the original %+v", got, want)
	}
	if got.CachedAt != "2026-01-01T00:00:00Z" {
		t.Fatalf("cachedAt = %q, want the claimed generation's time", got.CachedAt)
	}
	claim, err := fc.GetSession(ctx, "team", want.State)
	if err != nil {
		t.Fatal(err)
	}
	if claim.Spec.CopyFrom != older.Name {
		t.Fatalf("copyFrom = %q, want the original generation %q", claim.Spec.CopyFrom, older.Name)
	}
	if claim.Labels[v1.LabelGitRepo] != "demo" {
		t.Fatalf("claim labels = %v, want the git repo label", claim.Labels)
	}
	if newer.Name == "" {
		t.Fatal("newer cache was not created")
	}
}
