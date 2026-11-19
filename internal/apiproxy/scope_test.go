// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package apiproxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

const scopeNamespace = "blip-sandbox"

// fakeObject is the small object shape the fake API server serves.
type fakeObject struct {
	Name        string
	UID         string
	Labels      map[string]string
	Annotations map[string]string
	Secret      string
	Image       string
}

func (o fakeObject) value(kind string) map[string]any {
	meta := map[string]any{"name": o.Name, "uid": o.UID}
	if len(o.Labels) > 0 {
		meta["labels"] = o.Labels
	}
	if len(o.Annotations) > 0 {
		meta["annotations"] = o.Annotations
	}
	out := map[string]any{"apiVersion": "v1", "kind": kind, "metadata": meta}
	spec := map[string]any{}
	if o.Image != "" {
		spec["image"] = o.Image
	}
	if o.Secret != "" {
		spec["env"] = []any{map[string]any{"name": "SECRET", "value": o.Secret}}
	}
	if len(spec) > 0 {
		out["spec"] = spec
	}
	return out
}

// fakeKube is an upstream API server that implements equality label
// selectors for the objects the scope tests use.
type fakeKube struct {
	mu       sync.Mutex
	requests []string
	pods     map[string]fakeObject
	blips    map[string]fakeObject
	states   map[string]fakeObject
}

func newFakeKube() *fakeKube {
	return &fakeKube{
		pods:   map[string]fakeObject{},
		blips:  map[string]fakeObject{},
		states: map[string]fakeObject{},
	}
}

func (f *fakeKube) record(r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, r.URL.RequestURI())
	f.mu.Unlock()
}

func (f *fakeKube) recorded() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...)
}

// resourceFromPath extracts a namespaced pods/blips/blipstates request. The
// legacy watch routes prefix the namespaced collection with "watch"; strip it
// so a watch is served like the corresponding list.
func resourceFromPath(namespace, path string) (resource, name string, list bool) {
	seg := strings.Split(strings.Trim(path, "/"), "/")
	if len(seg) > 2 && seg[0] == "api" && seg[2] == "watch" {
		seg = append(seg[:2], seg[3:]...)
	} else if len(seg) > 3 && seg[0] == "apis" && seg[3] == "watch" {
		seg = append(seg[:3], seg[4:]...)
	}
	if len(seg) >= 2 && seg[0] == "api" && len(seg) >= 5 && seg[2] == "namespaces" && seg[3] == namespace && seg[4] == "pods" {
		if len(seg) == 5 {
			return "pods", "", true
		}
		if len(seg) == 6 {
			return "pods", seg[5], false
		}
		return "", "", false
	}
	if len(seg) >= 3 && seg[0] == "apis" && seg[1] == "blip.dev" && len(seg) >= 6 &&
		seg[3] == "namespaces" && seg[4] == namespace &&
		(seg[5] == "blips" || seg[5] == "blipstates") {
		if len(seg) == 6 {
			return seg[5], "", true
		}
		if len(seg) == 7 {
			return seg[5], seg[6], false
		}
		return "", "", false
	}
	return "", "", false
}

func selectorMatches(selector string, labels map[string]string) bool {
	if selector == "" {
		return true
	}
	for _, term := range strings.Split(selector, ",") {
		key, value, ok := strings.Cut(term, "=")
		if !ok {
			return false
		}
		if labels[key] != value {
			return false
		}
	}
	return true
}

// fieldMatches implements the equality metadata.name field selector.
func fieldMatches(selector, name string) bool {
	if selector == "" {
		return true
	}
	for _, term := range strings.Split(selector, ",") {
		key, value, ok := strings.Cut(term, "=")
		if !ok {
			return false
		}
		if key != "metadata.name" || name != value {
			return false
		}
	}
	return true
}

func (f *fakeKube) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.record(r)
	resource, name, list := resourceFromPath(scopeNamespace, r.URL.Path)
	var objects map[string]fakeObject
	kind := ""
	switch resource {
	case "pods":
		objects, kind = f.pods, "Pod"
	case "blips":
		objects, kind = f.blips, "Blip"
	case "blipstates":
		objects, kind = f.states, "BlipState"
	default:
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "{}")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if list {
		selector := r.URL.Query().Get("labelSelector")
		fields := r.URL.Query().Get("fieldSelector")
		match := func(object fakeObject) bool {
			return selectorMatches(selector, object.Labels) && fieldMatches(fields, object.Name)
		}
		if r.URL.Query().Get("watch") == "true" {
			for _, object := range objects {
				if match(object) {
					_, _ = fmt.Fprintf(w, "{\"type\":\"ADDED\",\"object\":%s}\n", mustJSON(object.value(kind)))
				}
			}
			return
		}
		names := make([]string, 0, len(objects))
		for n, object := range objects {
			if match(object) {
				names = append(names, n)
			}
		}
		sort.Strings(names)
		items := make([]any, 0, len(names))
		for _, n := range names {
			items = append(items, objects[n].value(kind))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": kind + "List", "items": items})
		return
	}
	object, ok := objects[name]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"kind":"Status","apiVersion":"v1","reason":"NotFound","code":404}`)
		return
	}
	_ = json.NewEncoder(w).Encode(object.value(kind))
}

func mustJSON(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(data)
}

// scopedFixture builds a claimed alice VM, another owner's objects and a
// shared unlabelled state.
func scopedFixture() *fakeKube {
	kube := newFakeKube()
	kube.pods["alice-vm"] = fakeObject{
		Name: "alice-vm", UID: "pod-alice",
		Labels:      map[string]string{v1.LabelOwner: "alice", v1.LabelBlipUID: "uid-alice"},
		Annotations: map[string]string{v1.AnnotationBlip: "alice.a"},
	}
	kube.pods["bob-vm"] = fakeObject{
		Name: "bob-vm", UID: "pod-bob",
		Labels:      map[string]string{v1.LabelOwner: "bob", v1.LabelBlipUID: "uid-bob"},
		Annotations: map[string]string{v1.AnnotationBlip: "bob.b"},
	}
	kube.pods["warm-vm"] = fakeObject{Name: "warm-vm", UID: "pod-warm"}
	kube.blips["alice.a"] = fakeObject{Name: "alice.a", UID: "uid-alice", Labels: map[string]string{v1.LabelOwner: "alice"}, Secret: "alice-coffee"}
	kube.blips["bob.b"] = fakeObject{Name: "bob.b", UID: "uid-bob", Labels: map[string]string{v1.LabelOwner: "bob"}, Secret: "super-secret-bob-12345"}
	kube.blips["admin.a"] = fakeObject{Name: "admin.a", UID: "uid-admin", Secret: "admin-secret"}
	kube.states["alice.home"] = fakeObject{Name: "alice.home", UID: "state-alice", Labels: map[string]string{v1.LabelOwner: "alice"}}
	kube.states["bob.home"] = fakeObject{Name: "bob.home", UID: "state-bob", Labels: map[string]string{v1.LabelOwner: "bob"}}
	kube.states["shared-base"] = fakeObject{Name: "shared-base", UID: "state-base", Image: "reg/base:v1"}
	kube.states["legacy-copy"] = fakeObject{Name: "legacy-copy", UID: "state-legacy"}
	return kube
}

func startScoped(t *testing.T, kube *fakeKube, podName string) *runningProxy {
	t.Helper()
	upstream := tlsUpstream(t, kube.ServeHTTP)
	cfg := testConfig(t, upstream)
	cfg.PodName = podName
	cfg.PodNamespace = scopeNamespace
	return startProxy(t, cfg)
}

func proxyGet(t *testing.T, p *runningProxy, path string) (int, string) {
	t.Helper()
	resp, err := p.client.Get("http://kube-apiserver" + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return resp.StatusCode, responseBody(t, resp)
}

// lastQuery returns the query of the most recent upstream request to path.
func (f *fakeKube) lastQuery(t *testing.T, path string) url.Values {
	t.Helper()
	var out url.Values
	found := false
	for _, uri := range f.recorded() {
		parsed, err := url.ParseRequestURI(uri)
		if err != nil {
			continue
		}
		if parsed.Path == path {
			out, found = parsed.Query(), true
		}
	}
	if !found {
		t.Fatalf("upstream never saw %q; requests: %v", path, f.recorded())
	}
	return out
}

func pathsFor(f *fakeKube) []string {
	var out []string
	for _, uri := range f.recorded() {
		if parsed, err := url.ParseRequestURI(uri); err == nil {
			out = append(out, parsed.Path)
		}
	}
	return out
}

// TestOwnerScopeHidesOtherOwners is the regression test for the guest API
// proxy leaking every owner's Blips (including spec.env) and states/pods.
func TestOwnerScopeHidesOtherOwners(t *testing.T) {
	kube := scopedFixture()
	p := startScoped(t, kube, "alice-vm")

	if status, body := proxyGet(t, p, "/apis/blip.dev/v1alpha1/namespaces/blip-sandbox/blips/bob.b"); status != http.StatusNotFound {
		t.Fatalf("other owner's Blip status = %d, body %q", status, body)
	} else if strings.Contains(body, "super-secret") {
		t.Fatalf("other owner's secret leaked: %q", body)
	}
	status, body := proxyGet(t, p, "/apis/blip.dev/v1alpha1/namespaces/blip-sandbox/blips")
	if status != http.StatusOK || !strings.Contains(body, "alice.a") {
		t.Fatalf("own Blip list status = %d, body %q", status, body)
	}
	if strings.Contains(body, "bob.b") || strings.Contains(body, "super-secret") {
		t.Fatalf("Blip list leaked another owner: %q", body)
	}
	if status, _ := proxyGet(t, p, "/apis/blip.dev/v1alpha1/namespaces/blip-sandbox/blips/admin.a"); status != http.StatusNotFound {
		t.Fatalf("administrator Blip status = %d, want private", status)
	}
	if status, _ := proxyGet(t, p, "/apis/blip.dev/v1alpha1/namespaces/blip-sandbox/blipstates/bob.home"); status != http.StatusNotFound {
		t.Fatalf("other owner's state status = %d", status)
	}
	if status, _ := proxyGet(t, p, "/apis/blip.dev/v1alpha1/namespaces/blip-sandbox/blipstates/alice.home"); status != http.StatusOK {
		t.Fatalf("own state status = %d", status)
	}
	if status, _ := proxyGet(t, p, "/apis/blip.dev/v1alpha1/namespaces/blip-sandbox/blipstates/shared-base"); status != http.StatusOK {
		t.Fatalf("shared base status = %d", status)
	}
	// An ownerless state without an image is not a shared base; the same
	// object is private to the mount and copy policy.
	if status, _ := proxyGet(t, p, "/apis/blip.dev/v1alpha1/namespaces/blip-sandbox/blipstates/legacy-copy"); status != http.StatusNotFound {
		t.Fatalf("unowned non-image state status = %d, want 404", status)
	}
	if status, _ := proxyGet(t, p, "/api/v1/namespaces/blip-sandbox/pods/bob-vm"); status != http.StatusNotFound {
		t.Fatalf("other owner's pod status = %d", status)
	}
	if status, _ := proxyGet(t, p, "/api/v1/namespaces/blip-sandbox/pods/warm-vm"); status != http.StatusNotFound {
		t.Fatalf("warm pod status = %d", status)
	}
	if status, _ := proxyGet(t, p, "/api/v1/namespaces/blip-sandbox/pods/alice-vm"); status != http.StatusOK {
		t.Fatalf("own pod status = %d", status)
	}

	status, body = proxyGet(t, p, "/api/v1/namespaces/blip-sandbox/pods")
	if status != http.StatusOK || !strings.Contains(body, "alice-vm") {
		t.Fatalf("own pod list status = %d, body %q", status, body)
	}
	if strings.Contains(body, "bob-vm") || strings.Contains(body, "warm-vm") {
		t.Fatalf("pod list leaked other pods: %q", body)
	}
	status, body = proxyGet(t, p, "/apis/blip.dev/v1alpha1/namespaces/blip-sandbox/blipstates")
	if status != http.StatusOK || !strings.Contains(body, "alice.home") || strings.Contains(body, "bob.home") {
		t.Fatalf("state list status = %d, body %q", status, body)
	}
}

// TestOwnerScopeNamespacedWatchPaths is the regression test for the legacy
// namespaced watch routes. They must be scoped exactly like the corresponding
// list; forwarding them unscoped leaked every owner's objects in the namespace.
func TestOwnerScopeNamespacedWatchPaths(t *testing.T) {
	kube := scopedFixture()
	p := startScoped(t, kube, "alice-vm")

	for _, tc := range []struct {
		name     string
		path     string
		query    string
		selector string
		want     []string
		not      []string
	}{
		{
			name: "pods", path: "/api/v1/watch/namespaces/blip-sandbox/pods",
			query: "labelSelector", selector: v1.LabelOwner + "=alice",
			want: []string{"alice-vm"}, not: []string{"bob-vm", "warm-vm"},
		},
		{
			name: "blips", path: "/apis/blip.dev/v1alpha1/watch/namespaces/blip-sandbox/blips",
			query: "labelSelector", selector: v1.LabelOwner + "=alice",
			want: []string{"alice.a"}, not: []string{"bob.b", "admin.a"},
		},
		{
			name: "blipstates", path: "/apis/blip.dev/v1alpha1/watch/namespaces/blip-sandbox/blipstates",
			query: "labelSelector", selector: v1.LabelOwner + "=alice",
			want: []string{"alice.home"}, not: []string{"bob.home", "shared-base", "legacy-copy"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, body := proxyGet(t, p, tc.path+"?watch=true")
			if status != http.StatusOK {
				t.Fatalf("%s status = %d, body %q", tc.path, status, body)
			}
			if got := kube.lastQuery(t, tc.path).Get(tc.query); got != tc.selector {
				t.Errorf("%s %s = %q, want %q", tc.path, tc.query, got, tc.selector)
			}
			for _, name := range tc.want {
				if !strings.Contains(body, name) {
					t.Errorf("%s watch missing %q: %s", tc.path, name, body)
				}
			}
			for _, name := range tc.not {
				if strings.Contains(body, name) {
					t.Errorf("%s watch leaked %q: %s", tc.path, name, body)
				}
			}
		})
	}

	// Unknown watch shapes naming a scoped resource, and other namespaces,
	// are denied rather than forwarded unscoped.
	for _, path := range []string{
		"/api/v1/watch/pods",
		"/api/v1/watch/namespaces/blip-sandbox/pods/alice-vm",
		"/api/v1/watch/namespaces/other/pods",
		"/apis/blip.dev/v1alpha1/watch/blips",
		"/apis/blip.dev/v1alpha1/watch/blipstates",
		"/apis/blip.dev/v1alpha1/watch/namespaces/blip-sandbox/blips/bob.b",
		"/apis/blip.dev/v1alpha1/watch/namespaces/other/blips",
	} {
		if status, _ := proxyGet(t, p, path); status != http.StatusForbidden {
			t.Errorf("%s status = %d, want 403", path, status)
		}
	}
}

// The thread and turn API is gone, but stale objects may still exist from an
// older cluster. They must stay invisible for every path spelling.
func TestOwnerScopeDeniesThreadsAndTurns(t *testing.T) {
	kube := scopedFixture()
	p := startScoped(t, kube, "alice-vm")

	for _, path := range []string{
		"/apis/blip.dev/v1alpha1/namespaces/blip-sandbox/blipthreads",
		"/apis/blip.dev/v1alpha1/namespaces/blip-sandbox/blipthreads/old-thread",
		"/apis/blip.dev/v1alpha1/namespaces/blip-sandbox/blipturns",
		"/apis/blip.dev/v1alpha1/namespaces/blip-sandbox/blipturns/old-turn",
		"/apis/blip.dev/v1alpha1/blipthreads",
		"/apis/blip.dev/v1alpha1/blipturns",
		"/apis/blip.dev/v1alpha1/watch/blipthreads",
		"/apis/blip.dev/v1alpha1/watch/blipturns",
		"/apis/blip.dev/v1alpha1/watch/namespaces/blip-sandbox/blipthreads",
		"/apis/blip.dev/v1alpha1/watch/namespaces/blip-sandbox/blipturns",
		"/apis/blip.dev/v1alpha1/namespaces/blip-sandbox/blipthread/old-thread",
		"/apis/blip.dev/v1alpha1/namespaces/blip-sandbox/blipturn/old-turn",
	} {
		if status, _ := proxyGet(t, p, path); status != http.StatusForbidden {
			t.Errorf("%s status = %d, want 403", path, status)
		}
	}
	for _, path := range pathsFor(kube) {
		for _, resource := range []string{"/blipthreads", "/blipturns", "/blipthread/", "/blipturn/"} {
			if strings.Contains(path, resource) {
				t.Errorf("stale thread/turn path reached the upstream: %q", path)
			}
		}
	}
}

// Singular and short resource names are valid Kubernetes aliases for a
// scoped resource. The scope only understands the canonical plural routes, so
// it must deny an alias instead of forwarding it unscoped and relying on RBAC.
func TestParseScopePathDeniesResourceAliases(t *testing.T) {
	for _, tc := range []struct {
		name     string
		path     string
		action   scopeAction
		resource string
		target   string
	}{
		{"pod alias", "/api/v1/namespaces/blip-sandbox/pod/alice-vm", scopedDeny, "", ""},
		{"po alias", "/api/v1/namespaces/blip-sandbox/po/alice-vm", scopedDeny, "", ""},
		{"blip alias", "/apis/blip.dev/v1alpha1/namespaces/blip-sandbox/blip/alice.a", scopedDeny, "", ""},
		{"blipthread alias", "/apis/blip.dev/v1alpha1/namespaces/blip-sandbox/blipthread/alice-proj", scopedDeny, "", ""},
		{"blipturn alias", "/apis/blip.dev/v1alpha1/namespaces/blip-sandbox/blipturn/old-turn", scopedDeny, "", ""},
		{"blipstate alias", "/apis/blip.dev/v1alpha1/namespaces/blip-sandbox/blipstate/alice.home", scopedDeny, "", ""},
		{"bst short name", "/apis/blip.dev/v1alpha1/namespaces/blip-sandbox/bst/alice.home", scopedDeny, "", ""},
		{"all-namespace pod alias", "/api/v1/pod", scopedDeny, "", ""},
		{"all-namespace blip alias", "/apis/blip.dev/v1alpha1/blip", scopedDeny, "", ""},
		{"legacy watch pod alias", "/api/v1/watch/namespaces/blip-sandbox/pod", scopedDeny, "", ""},
		{"legacy watch blip alias", "/apis/blip.dev/v1alpha1/watch/namespaces/blip-sandbox/blip", scopedDeny, "", ""},
		{"control pod plural", "/api/v1/namespaces/blip-sandbox/pods/alice-vm", scopedRead, "pods", "alice-vm"},
		{"control blip plural", "/apis/blip.dev/v1alpha1/namespaces/blip-sandbox/blips/alice.a", scopedRead, "blips", "alice.a"},
		{"unrelated resource", "/apis/apps/v1/namespaces/blip-sandbox/deployments/x", passThrough, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, action := parseScopePath(tc.path)
			if action != tc.action || req.resource != tc.resource || req.name != tc.target {
				t.Fatalf("parseScopePath(%q) = (%+v, %v), want resource %q name %q action %v",
					tc.path, req, action, tc.resource, tc.target, tc.action)
			}
		})
	}
}

// The aliases must be stopped by the proxy itself, not only by RBAC, while
// the canonical plural routes keep their owner scope.
func TestOwnerScopeDeniesResourceAliases(t *testing.T) {
	kube := scopedFixture()
	p := startScoped(t, kube, "alice-vm")

	for _, path := range []string{
		"/api/v1/namespaces/blip-sandbox/pod/alice-vm",
		"/api/v1/namespaces/blip-sandbox/po/alice-vm",
		"/apis/blip.dev/v1alpha1/namespaces/blip-sandbox/blip/alice.a",
	} {
		if status, _ := proxyGet(t, p, path); status != http.StatusForbidden {
			t.Errorf("%s status = %d, want 403", path, status)
		}
	}
	if status, _ := proxyGet(t, p, "/apis/blip.dev/v1alpha1/namespaces/blip-sandbox/blips/alice.a"); status != http.StatusOK {
		t.Errorf("canonical own Blip status = %d, want 200", status)
	}
	if status, _ := proxyGet(t, p, "/apis/blip.dev/v1alpha1/namespaces/blip-sandbox/blips/bob.b"); status != http.StatusNotFound {
		t.Errorf("canonical other Blip status = %d, want 404", status)
	}
	for _, path := range pathsFor(kube) {
		for _, alias := range []string{"/pod/", "/po/", "/blip/"} {
			if strings.Contains(path, alias) {
				t.Errorf("alias path reached the upstream: %q", path)
			}
		}
	}
}

func TestOwnerScopeSelectorAndPaths(t *testing.T) {
	kube := scopedFixture()
	p := startScoped(t, kube, "alice-vm")

	if status, _ := proxyGet(t, p, "/apis/blip.dev/v1alpha1/namespaces/blip-sandbox/blips?labelSelector=app%3Ddemo"); status != http.StatusOK {
		t.Fatalf("list status = %d", status)
	}
	query := kube.lastQuery(t, "/apis/blip.dev/v1alpha1/namespaces/blip-sandbox/blips")
	if got := query.Get("labelSelector"); got != "app=demo,blip.dev/owner=alice" {
		t.Fatalf("merged selector = %q", got)
	}

	// Watches keep streaming and all other query parameters.
	if status, _ := proxyGet(t, p, "/apis/blip.dev/v1alpha1/namespaces/blip-sandbox/blips?watch=true&labelSelector=app%3Ddemo&resourceVersion=7&allowWatchBookmarks=true"); status != http.StatusOK {
		t.Fatalf("watch status = %d", status)
	}
	query = kube.lastQuery(t, "/apis/blip.dev/v1alpha1/namespaces/blip-sandbox/blips")
	if query.Get("watch") != "true" || query.Get("resourceVersion") != "7" || query.Get("allowWatchBookmarks") != "true" ||
		query.Get("labelSelector") != "app=demo,blip.dev/owner=alice" {
		t.Fatalf("watch parameters changed: %v", query)
	}

	// Discovery and version do not need identity or object lookups.
	for _, path := range []string{"/api", "/apis", "/apis/blip.dev", "/apis/blip.dev/v1alpha1", "/version"} {
		if status, _ := proxyGet(t, p, path); status != http.StatusOK {
			t.Errorf("%s status = %d", path, status)
		}
	}

	// exec is checked against the parent pod and forwarded byte-for-byte.
	exec := "/api/v1/namespaces/blip-sandbox/pods/alice-vm/exec?command=sh&command=-c&stdin=true"
	if status, _ := proxyGet(t, p, exec); status != http.StatusOK {
		t.Fatalf("own exec status = %d", status)
	}
	seen := false
	for _, uri := range kube.recorded() {
		if strings.HasSuffix(uri, exec) {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("exec request was rewritten: %v", kube.recorded())
	}
	if status, _ := proxyGet(t, p, "/api/v1/namespaces/blip-sandbox/pods/bob-vm/exec?command=sh"); status != http.StatusNotFound {
		t.Fatalf("other owner's exec status = %d", status)
	}
	if status, _ := proxyGet(t, p, "/api/v1/namespaces/blip-sandbox/pods/alice-vm/log?tailLines=10"); status != http.StatusOK {
		t.Fatalf("own log status = %d", status)
	}

	// Other namespaces, all-namespace lists and ambiguous paths are rejected.
	for _, path := range []string{
		"/api/v1/namespaces/other/pods",
		"/apis/blip.dev/v1alpha1/namespaces/other/blips",
		"/api/v1/pods",
		"/apis/blip.dev/v1alpha1/blips",
	} {
		if status, _ := proxyGet(t, p, path); status != http.StatusForbidden {
			t.Errorf("%s status = %d, want 403", path, status)
		}
	}
	if status, _ := proxyGet(t, p, "/api/v1/namespaces/blip-sandbox/pods/alice-vm/exec/extra"); status != http.StatusForbidden {
		t.Errorf("ambiguous path status = %d", status)
	}
	if status, _ := proxyGet(t, p, "/api/v1/namespaces/blip-sandbox/pods/alice-vm%2Fbob-vm"); status != http.StatusBadRequest {
		t.Errorf("encoded slash status = %d", status)
	}
	for _, path := range pathsFor(kube) {
		if strings.Contains(path, "/namespaces/other/") {
			t.Fatalf("forwarded a request for another namespace: %v", kube.recorded())
		}
	}

	// Writes are not read-scoped: they keep their exact query for RBAC and the
	// owner admission policy to decide.
	request, err := http.NewRequest(http.MethodPost, "http://kube-apiserver/apis/blip.dev/v1alpha1/namespaces/blip-sandbox/blips", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	response, err := p.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = responseBody(t, response)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("write status = %d", response.StatusCode)
	}
	if got := kube.lastQuery(t, "/apis/blip.dev/v1alpha1/namespaces/blip-sandbox/blips").Get("labelSelector"); got != "" {
		t.Fatalf("write was given a label selector: %q", got)
	}
}

func TestOwnerScopeWatchStreams(t *testing.T) {
	kube := scopedFixture()
	upstream := tlsUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("watch") != "true" {
			kube.ServeHTTP(w, r)
			return
		}
		kube.record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"type":"ADDED"}`+"\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	cfg := testConfig(t, upstream)
	cfg.PodName, cfg.PodNamespace = "alice-vm", scopeNamespace
	p := startProxy(t, cfg)

	resp, err := p.client.Get("http://kube-apiserver/apis/blip.dev/v1alpha1/namespaces/blip-sandbox/blips?watch=true")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	reader := bufio.NewReader(resp.Body)
	line, err := reader.ReadString('\n')
	if err != nil || line != "{\"type\":\"ADDED\"}\n" {
		t.Fatalf("first watch event: %q, %v", line, err)
	}
	if got := kube.lastQuery(t, "/apis/blip.dev/v1alpha1/namespaces/blip-sandbox/blips").Get("labelSelector"); got != "blip.dev/owner=alice" {
		t.Fatalf("watch selector = %q", got)
	}
	p.stop(t)
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("watch stream stayed open after shutdown")
	}
}

func TestOwnerScopeAdminIsUnrestricted(t *testing.T) {
	kube := newFakeKube()
	kube.pods["admin-vm"] = fakeObject{
		Name: "admin-vm", UID: "pod-admin",
		Labels:      map[string]string{v1.LabelBlipUID: "uid-admin"},
		Annotations: map[string]string{v1.AnnotationBlip: "admin.a"},
	}
	kube.blips["admin.a"] = fakeObject{Name: "admin.a", UID: "uid-admin", Secret: "admin-secret"}
	kube.blips["bob.b"] = fakeObject{Name: "bob.b", UID: "uid-bob", Labels: map[string]string{v1.LabelOwner: "bob"}, Secret: "bob-secret"}
	kube.pods["warm-vm"] = fakeObject{Name: "warm-vm", UID: "pod-warm"}
	p := startScoped(t, kube, "admin-vm")

	status, body := proxyGet(t, p, "/apis/blip.dev/v1alpha1/namespaces/blip-sandbox/blips/bob.b")
	if status != http.StatusOK || !strings.Contains(body, "bob-secret") {
		t.Fatalf("admin GET status = %d, body %q", status, body)
	}
	status, body = proxyGet(t, p, "/api/v1/namespaces/blip-sandbox/pods")
	if status != http.StatusOK || !strings.Contains(body, "warm-vm") {
		t.Fatalf("admin pod list status = %d, body %q", status, body)
	}
	if status, body = proxyGet(t, p, "/apis/blip.dev/v1alpha1/namespaces/blip-sandbox/blips"); status != http.StatusOK ||
		!strings.Contains(body, "admin.a") || !strings.Contains(body, "bob.b") {
		t.Fatalf("admin list status = %d, body %q", status, body)
	}
	for _, uri := range kube.recorded() {
		parsed, err := url.ParseRequestURI(uri)
		if err == nil && parsed.Path == "/apis/blip.dev/v1alpha1/namespaces/blip-sandbox/blips" && parsed.Query().Get("labelSelector") != "" {
			t.Fatalf("admin list was scoped: %q", uri)
		}
	}
	// Even an unrestricted VM remains confined to its own namespace.
	if status, _ := proxyGet(t, p, "/api/v1/namespaces/other/pods"); status != http.StatusForbidden {
		t.Fatalf("admin other namespace status = %d", status)
	}
}

func TestOwnerScopeVacantPodDenies(t *testing.T) {
	kube := newFakeKube()
	kube.pods["warm-vm"] = fakeObject{Name: "warm-vm", UID: "pod-warm"}
	kube.blips["alice.a"] = fakeObject{Name: "alice.a", UID: "uid-alice", Labels: map[string]string{v1.LabelOwner: "alice"}}
	p := startScoped(t, kube, "warm-vm")

	for _, path := range []string{
		"/apis/blip.dev/v1alpha1/namespaces/blip-sandbox/blips",
		"/apis/blip.dev/v1alpha1/namespaces/blip-sandbox/blips/alice.a",
		"/api/v1/namespaces/blip-sandbox/pods",
	} {
		if status, _ := proxyGet(t, p, path); status != http.StatusForbidden {
			t.Errorf("vacant pod %s status = %d, want 403", path, status)
		}
	}
	// Discovery remains available so guest tooling can start.
	if status, _ := proxyGet(t, p, "/apis/blip.dev/v1alpha1"); status != http.StatusOK {
		t.Fatalf("discovery status = %d", status)
	}
}

func TestOwnerScopeRejectsStaleBlipBinding(t *testing.T) {
	kube := newFakeKube()
	kube.pods["alice-vm"] = fakeObject{
		Name: "alice-vm", UID: "pod-alice",
		Labels:      map[string]string{v1.LabelOwner: "alice", v1.LabelBlipUID: "uid-stale"},
		Annotations: map[string]string{v1.AnnotationBlip: "alice.a"},
	}
	kube.blips["alice.a"] = fakeObject{Name: "alice.a", UID: "uid-new", Labels: map[string]string{v1.LabelOwner: "alice"}}
	p := startScoped(t, kube, "alice-vm")
	if status, _ := proxyGet(t, p, "/apis/blip.dev/v1alpha1/namespaces/blip-sandbox/blips"); status != http.StatusForbidden {
		t.Fatalf("stale pod/Blip binding status = %d, want 403", status)
	}
}
