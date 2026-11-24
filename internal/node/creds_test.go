// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package node

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"sigs.k8s.io/yaml"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/podapi"
	"github.com/Azure/blip/internal/storage"
)

// tokenRequest records one TokenRequest the fake API server received.
type tokenRequest struct {
	namespace  string
	sa         string
	audiences  []string
	expiration int64
	bound      *authenticationv1.BoundObjectReference
}

// tokenMinter serves serviceaccounts/token requests with a token that names
// its namespace, service account, and audience.
type tokenMinter struct {
	mu       sync.Mutex
	requests []tokenRequest
	expiry   time.Time
	err      error
}

func (m *tokenMinter) client() kubernetes.Interface {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("create", "serviceaccounts", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if action.GetSubresource() != "token" {
			return false, nil, nil
		}
		create := action.(k8stesting.CreateAction)
		req := create.GetObject().(*authenticationv1.TokenRequest)
		sa := ""
		if named, ok := action.(interface{ GetName() string }); ok {
			sa = named.GetName()
		} else if impl, ok := action.(k8stesting.CreateActionImpl); ok {
			// CreateAction does not expose the resource name, but the fake
			// passes the concrete value that holds it.
			sa = impl.Name
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		expiration := int64(0)
		if req.Spec.ExpirationSeconds != nil {
			expiration = *req.Spec.ExpirationSeconds
		}
		m.requests = append(m.requests, tokenRequest{
			namespace:  action.GetNamespace(),
			sa:         sa,
			audiences:  slices.Clone(req.Spec.Audiences),
			expiration: expiration,
			bound:      req.Spec.BoundObjectRef.DeepCopy(),
		})
		if m.err != nil {
			return true, nil, m.err
		}
		expiry := m.expiry
		if expiry.IsZero() {
			expiry = time.Now().Add(time.Hour)
		}
		return true, &authenticationv1.TokenRequest{Status: authenticationv1.TokenRequestStatus{
			Token:               m.token(action.GetNamespace(), sa, audience(req.Spec.Audiences)),
			ExpirationTimestamp: metav1.NewTime(expiry),
		}}, nil
	})
	return cs
}

func (m *tokenMinter) token(namespace, sa, aud string) string {
	return "token:" + namespace + "/" + sa + "/" + aud
}

func (m *tokenMinter) snapshot() []tokenRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.requests)
}

func audience(audiences []string) string {
	if len(audiences) == 0 {
		return ""
	}
	return audiences[0]
}

func newCredsAgent(t *testing.T, kube kubernetes.Interface, now func() time.Time) *Agent {
	t.Helper()
	return &Agent{
		cfg:        Config{DataDir: t.TempDir()},
		kube:       kube,
		now:        now,
		creds:      map[string]*podCreds{},
		credsReady: map[string]bool{},
		credsErr:   map[string]string{},
	}
}

// credsView returns a view holding one pool, one claimed pod, and its Blip.
func credsView(pool *v1alpha1.BlipPool, pod *corev1.Pod) *view {
	b := &v1alpha1.Blip{ObjectMeta: metav1.ObjectMeta{
		Namespace: pod.Namespace,
		Name:      "b",
		UID:       types.UID(pod.Labels[v1alpha1.LabelBlipUID]),
	}}
	key := podKey(pod.Namespace, pod.Name)
	v := &view{
		now:   testNow,
		node:  self,
		pools: map[string]*v1alpha1.BlipPool{},
		pods:  map[string]*corev1.Pod{key: pod},
		dirs:  map[string]*podDir{key: dir(podapi.PhaseWarm)},
		blips: []*v1alpha1.Blip{b},
	}
	if pool != nil {
		v.pools[pool.Namespace+"/"+pool.Name] = pool
	}
	return v
}

func testPool() *v1alpha1.BlipPool {
	return &v1alpha1.BlipPool{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "default"},
		Spec: v1alpha1.BlipPoolSpec{
			ServiceAccountName: "pool-sa",
			Endpoints: []v1alpha1.PoolEndpoint{
				{Name: "api", URL: "https://api.example.com", Audience: "aud-api"},
				{Name: "shared", URL: "https://shared.example.com", Audience: "aud-api"},
				{Name: "open", URL: "https://open.example.com"},
			},
		},
	}
}

type credDoc struct {
	Resources []struct {
		Type          string `json:"@type"`
		Name          string `json:"name"`
		GenericSecret struct {
			Secret struct {
				InlineString string `json:"inline_string"`
			} `json:"secret"`
		} `json:"generic_secret"`
	} `json:"resources"`
}

func readCred(t *testing.T, path string) credDoc {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc credDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse %s: %v\n%s", path, err, data)
	}
	if len(doc.Resources) != 1 {
		t.Fatalf("%s has %d resources", path, len(doc.Resources))
	}
	return doc
}

func TestEnsureCredsWritesPerUpstreamFiles(t *testing.T) {
	m := &tokenMinter{expiry: testNow.Add(time.Hour)}
	a := newCredsAgent(t, m.client(), func() time.Time { return testNow })
	pod := vmPod("p", "blipuid-b")
	v := credsView(testPool(), pod)

	a.ensureCreds(context.Background(), v)
	key := pkey("p")
	a.mu.Lock()
	ready, errText := a.credsReady[key], a.credsErr[key]
	a.mu.Unlock()
	if !ready || errText != "" {
		t.Fatalf("ready = %v, err = %q", ready, errText)
	}

	dir := filepath.Join(a.podDirFor(key), podapi.CredsDir)
	// The API server always has a credential. Endpoints appear only when they
	// authenticate with an audience; plain HTTPS endpoints need none.
	for name, aud := range map[string]string{
		"kube-apiserver": "",
		"api":            "aud-api",
		"shared":         "aud-api",
	} {
		path := filepath.Join(dir, name+".yaml")
		doc := readCred(t, path)
		res := doc.Resources[0]
		if res.Type != "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret" || res.Name != name {
			t.Errorf("%s resource = %+v", name, res)
		}
		if want := bearerPrefix + m.token(ns, "pool-sa", aud); res.GenericSecret.Secret.InlineString != want {
			t.Errorf("%s token = %q, want %q", name, res.GenericSecret.Secret.InlineString, want)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != credsFileMode {
			t.Errorf("%s mode = %o, want %o", name, info.Mode().Perm(), credsFileMode)
		}
		if os.Geteuid() == 0 {
			st := info.Sys().(*syscall.Stat_t)
			if st.Uid != credsUID || st.Gid != credsGID {
				t.Errorf("%s owner = %d:%d, want %d:%d", name, st.Uid, st.Gid, credsUID, credsGID)
			}
			dirInfo, err := os.Stat(dir)
			if err != nil {
				t.Fatal(err)
			}
			dst := dirInfo.Sys().(*syscall.Stat_t)
			if dst.Uid != credsUID || dst.Gid != credsGID {
				t.Errorf("creds dir owner = %d:%d, want %d:%d", dst.Uid, dst.Gid, credsUID, credsGID)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "open.yaml")); !os.IsNotExist(err) {
		t.Errorf("unauthenticated endpoint has a credential file: %v", err)
	}

	// One token request per distinct audience: the default and aud-api.
	reqs := m.snapshot()
	if len(reqs) != 2 {
		t.Fatalf("token requests = %+v", reqs)
	}
	got := map[string]tokenRequest{}
	for _, r := range reqs {
		got[audience(r.audiences)] = r
	}
	if _, ok := got[""]; !ok {
		t.Errorf("missing default-audience request: %+v", reqs)
	}
	if _, ok := got["aud-api"]; !ok {
		t.Errorf("missing aud-api request: %+v", reqs)
	}
	for aud, r := range got {
		if r.namespace != ns || r.sa != "pool-sa" {
			t.Errorf("%s request = %+v", aud, r)
		}
		if r.expiration != credsExpirationSeconds {
			t.Errorf("%s expiration = %d, want %d", aud, r.expiration, credsExpirationSeconds)
		}
		if r.bound == nil || r.bound.Kind != "Pod" || r.bound.APIVersion != "v1" ||
			r.bound.Name != "p" || r.bound.UID != pod.UID {
			t.Errorf("%s bound object = %+v", aud, r.bound)
		}
	}
}

func TestEnsureCredsReusesCacheAndRefreshes(t *testing.T) {
	m := &tokenMinter{expiry: testNow.Add(time.Hour)}
	now := testNow
	a := newCredsAgent(t, m.client(), func() time.Time { return now })
	pod := vmPod("p", "blipuid-b")
	v := credsView(testPool(), pod)
	key := pkey("p")

	a.ensureCreds(context.Background(), v)
	if got := len(m.snapshot()); got != 2 {
		t.Fatalf("first pass requests = %d, want 2", got)
	}
	a.ensureCreds(context.Background(), v)
	if got := len(m.snapshot()); got != 2 {
		t.Fatalf("cached pass requested tokens again: %d requests", got)
	}

	// Less than the refresh window remains: mint again.
	a.mu.Lock()
	a.creds[key].expires = now.Add(credsRefreshWindow - time.Second)
	a.mu.Unlock()
	a.ensureCreds(context.Background(), v)
	if got := len(m.snapshot()); got != 4 {
		t.Fatalf("near-expiry pass requests = %d, want 4", got)
	}

	// A changed identity invalidates the cached set even when it is fresh.
	pod.Annotations = map[string]string{v1alpha1.AnnotationServiceAccount: "other-sa"}
	a.ensureCreds(context.Background(), v)
	if got := len(m.snapshot()); got != 6 {
		t.Fatalf("identity-change pass requests = %d, want 6", got)
	}
	if _, err := os.Stat(filepath.Join(a.podDirFor(key), podapi.CredsDir, "api.yaml")); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureCredsNoIdentityPlaceholders(t *testing.T) {
	m := &tokenMinter{}
	a := newCredsAgent(t, m.client(), func() time.Time { return testNow })
	pool := testPool()
	pod := vmPod("p", "blipuid-b")
	pod.Annotations = map[string]string{v1alpha1.AnnotationServiceAccount: "-"}
	v := credsView(pool, pod)

	a.ensureCreds(context.Background(), v)
	key := pkey("p")
	a.mu.Lock()
	ready, errText := a.credsReady[key], a.credsErr[key]
	a.mu.Unlock()
	if !ready || errText != "" {
		t.Fatalf("ready = %v, err = %q", ready, errText)
	}
	if got := len(m.snapshot()); got != 0 {
		t.Fatalf("no-identity pod requested %d tokens", got)
	}

	dir := filepath.Join(a.podDirFor(key), podapi.CredsDir)
	apiPath := filepath.Join(dir, "kube-apiserver.yaml")
	doc := readCred(t, apiPath)
	if got := doc.Resources[0].GenericSecret.Secret.InlineString; got != bearerPrefix+noIdentity {
		t.Fatalf("placeholder = %q, want %q", got, bearerPrefix+noIdentity)
	}
	if _, err := os.Stat(filepath.Join(dir, "api.yaml")); err != nil {
		t.Fatalf("authenticated endpoint lacks a placeholder: %v", err)
	}

	// Existing placeholders are not rewritten every pass.
	before, err := os.Stat(apiPath)
	if err != nil {
		t.Fatal(err)
	}
	a.ensureCreds(context.Background(), v)
	after, err := os.Stat(apiPath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("placeholder was rewritten on a later pass")
	}
}

func TestCredsServiceAccount(t *testing.T) {
	pool := testPool()
	pod := vmPod("p", "blipuid-b")
	if got := credsServiceAccount(pod); got != "pool-sa" {
		t.Errorf("claimed annotation = %q, want pool-sa", got)
	}
	pod.Annotations = nil
	if got := credsServiceAccount(pod); got != "" {
		t.Errorf("unclaimed pod = %q, want no identity", got)
	}
	pod.Annotations = map[string]string{v1alpha1.AnnotationServiceAccount: ""}
	if got := credsServiceAccount(pod); got != "" {
		t.Errorf("empty annotation = %q, want no identity", got)
	}
	pod.Annotations = map[string]string{v1alpha1.AnnotationServiceAccount: "-"}
	if got := credsServiceAccount(pod); got != "-" {
		t.Errorf("dash annotation = %q, want -", got)
	}
	pod.Annotations = map[string]string{v1alpha1.AnnotationServiceAccount: "custom-sa"}
	if got := credsServiceAccount(pod); got != "custom-sa" {
		t.Errorf("annotation = %q, want custom-sa", got)
	}

	// The annotation wins over the pool when minting.
	m := &tokenMinter{expiry: testNow.Add(time.Hour)}
	a := newCredsAgent(t, m.client(), func() time.Time { return testNow })
	a.ensureCreds(context.Background(), credsView(pool, pod))
	for _, r := range m.snapshot() {
		if r.sa != "custom-sa" {
			t.Errorf("minted for %q, want custom-sa", r.sa)
		}
	}
}

func TestEnsureCredsTokenFailureIsReported(t *testing.T) {
	m := &tokenMinter{err: apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, "p")}
	a := newCredsAgent(t, m.client(), func() time.Time { return testNow })
	pod := vmPod("p", "blipuid-b")
	a.ensureCreds(context.Background(), credsView(testPool(), pod))
	key := pkey("p")
	a.mu.Lock()
	ready, errText, cached := a.credsReady[key], a.credsErr[key], a.creds[key]
	a.mu.Unlock()
	if ready || errText == "" || cached != nil {
		t.Fatalf("ready = %v, err = %q, cached = %+v", ready, errText, cached)
	}
}

func TestDesiredForWithholdsNewClaimUntilCredsReady(t *testing.T) {
	v := newView()
	b, s, d := stateRoot(v)
	v.index()
	s.Status.Writer.PodUID = "poduid-p"
	readyDev(v, d, storage.Volume{ID: "r1", StateUID: "uid-root"}, 7)
	pod := v.pods[pkey("p")]
	p := &plan{desired: map[string]podapi.Desired{}, needed: map[string]bool{}, errs: map[string]string{}}
	key := pkey("p")

	v.credsReady = map[string]bool{}
	got, _, perr := desiredFor(v, p, pod, d)
	if got.Claim != nil {
		t.Fatalf("claim handed out without credentials: %+v", got.Claim)
	}
	if perr != "credentials: pending" {
		t.Fatalf("prepare error = %q, want credentials: pending", perr)
	}

	v.credsErr = map[string]string{key: "credentials: token for sa: boom"}
	got, _, perr = desiredFor(v, p, pod, d)
	if got.Claim != nil || perr != "credentials: token for sa: boom" {
		t.Fatalf("withheld claim = %+v, error = %q", got.Claim, perr)
	}

	v.credsReady = map[string]bool{key: true}
	v.credsErr = nil
	got, _, perr = desiredFor(v, p, pod, d)
	if got.Claim == nil || perr != "" {
		t.Fatalf("ready credentials did not release the claim: %+v, %q", got.Claim, perr)
	}

	// An existing claim is never revoked because credentials are unavailable.
	v.credsReady = map[string]bool{}
	d.desired = &podapi.Desired{Claim: claimFor(b, disk("r1", false), nil, nil), Network: denyNetwork()}
	got, _, perr = desiredFor(v, p, pod, d)
	if got.Claim == nil || perr != "" {
		t.Fatalf("existing claim was withheld: %+v, %q", got.Claim, perr)
	}
}
