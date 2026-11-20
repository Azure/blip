// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package streamapi

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

const identityPath = "/apis/identity.blip.dev/v1alpha1/namespaces/team/podidentities/pod"

type identityBackendFunc func(context.Context, string, string, string) (*PodIdentity, error)

func (f identityBackendFunc) LookupPodIdentity(ctx context.Context, namespace, name, uid string) (*PodIdentity, error) {
	return f(ctx, namespace, name, uid)
}

func TestIdentityDiscovery(t *testing.T) {
	for _, configured := range []bool{false, true} {
		t.Run(fmt.Sprint(configured), func(t *testing.T) {
			opts := Options{}
			if configured {
				opts.IdentityBackend = identityBackendFunc(func(context.Context, string, string, string) (*PodIdentity, error) {
					t.Fatal("discovery called backend")
					return nil, nil
				})
			}
			s := New(opts)
			rec := serve(s, http.MethodGet, "/apis")
			var groups metav1.APIGroupList
			if err := json.Unmarshal(rec.Body.Bytes(), &groups); err != nil {
				t.Fatal(err)
			}
			wantGroups := 1
			if configured {
				wantGroups++
			}
			if rec.Code != http.StatusOK || len(groups.Groups) != wantGroups || groups.Groups[0].Name != GroupName {
				t.Fatalf("groups status %d: %+v", rec.Code, groups)
			}
			if configured && groups.Groups[1].Name != IdentityGroupName {
				t.Fatalf("identity group missing: %+v", groups.Groups)
			}
			for _, path := range []string{"/apis/" + IdentityGroupName, "/apis/" + IdentityGroupName + "/" + IdentityVersion} {
				rec = serve(s, http.MethodGet, path)
				if !configured {
					if rec.Code != http.StatusNotFound {
						t.Fatalf("disabled discovery %s: %d", path, rec.Code)
					}
					continue
				}
				if rec.Code != http.StatusOK {
					t.Fatalf("discovery %s: %d: %s", path, rec.Code, rec.Body)
				}
				if path == "/apis/"+IdentityGroupName {
					var group metav1.APIGroup
					if err := json.Unmarshal(rec.Body.Bytes(), &group); err != nil {
						t.Fatal(err)
					}
					gv := metav1.GroupVersionForDiscovery{GroupVersion: IdentityGroupName + "/" + IdentityVersion, Version: IdentityVersion}
					if group.Name != IdentityGroupName || len(group.Versions) != 1 || group.Versions[0] != gv || group.PreferredVersion != gv {
						t.Fatalf("group: %+v", group)
					}
				} else {
					var list metav1.APIResourceList
					if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
						t.Fatal(err)
					}
					want := metav1.APIResource{Name: IdentityResource, SingularName: "podidentity", Namespaced: true, Kind: "PodIdentity", Verbs: []string{"get"}}
					if list.GroupVersion != IdentityGroupName+"/"+IdentityVersion || len(list.APIResources) != 1 || !reflect.DeepEqual(list.APIResources[0], want) {
						t.Fatalf("resources: %+v", list)
					}
				}
				rec = serve(s, http.MethodPost, path)
				if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodGet {
					t.Fatalf("discovery method status %d: %s", rec.Code, rec.Body)
				}
			}
		})
	}
}

func TestIdentityLookup(t *testing.T) {
	identity := &PodIdentity{
		Metadata: IdentityMetadata{Namespace: "team", Name: "pod", UID: "pod-uid", Labels: map[string]string{"pod": "label"}, Annotations: map[string]string{"pod": "annotation"}},
		Blip: BlipIdentity{
			IdentityMetadata: IdentityMetadata{Namespace: "team", Name: "blip", UID: "blip-uid", Labels: map[string]string{"blip": "label"}, Annotations: map[string]string{"blip": "annotation"}},
			Phase:            "Running", Pool: "pool",
		},
		State: IdentityMetadata{Namespace: "team", Name: "state", UID: "state-uid", Labels: map[string]string{"state": "label"}, Annotations: map[string]string{"state": "annotation"}},
	}
	for _, uid := range []string{"", "pod-uid"} {
		t.Run("uid="+uid, func(t *testing.T) {
			type contextKey struct{}
			ctx := context.WithValue(context.Background(), contextKey{}, "request")
			calls := 0
			s := New(Options{Insecure: true, IdentityBackend: identityBackendFunc(func(got context.Context, namespace, name, gotUID string) (*PodIdentity, error) {
				calls++
				if namespace != "team" || name != "pod" || gotUID != uid || got.Value(contextKey{}) != "request" {
					t.Fatalf("lookup arguments: %q %q %q, context %v", namespace, name, gotUID, got)
				}
				return identity, nil
			})})
			req := httptest.NewRequest(http.MethodGet, identityPath+"?uid="+uid, nil).WithContext(ctx)
			rec := httptest.NewRecorder()
			s.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusOK || calls != 1 || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Content-Type") != "application/json" {
				t.Fatalf("status %d, calls %d, headers %v: %s", rec.Code, calls, rec.Header(), rec.Body)
			}
			var got PodIdentity
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			want := *identity
			want.TypeMeta = metav1.TypeMeta{APIVersion: IdentityGroupName + "/" + IdentityVersion, Kind: "PodIdentity"}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("identity = %+v, want %+v", got, want)
			}
			if identity.Kind != "" || identity.APIVersion != "" {
				t.Fatal("handler mutated backend identity")
			}
			var wire map[string]json.RawMessage
			if err := json.Unmarshal(rec.Body.Bytes(), &wire); err != nil {
				t.Fatal(err)
			}
			var blip map[string]json.RawMessage
			if err := json.Unmarshal(wire["blip"], &blip); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"namespace", "name", "uid", "labels", "annotations", "phase", "pool"} {
				if _, ok := blip[field]; !ok {
					t.Fatalf("missing inline blip field %q: %s", field, wire["blip"])
				}
			}
		})
	}
}

func TestIdentityErrors(t *testing.T) {
	for _, tc := range []struct {
		name       string
		nilBackend bool
		err        error
		code       int
		reason     metav1.StatusReason
	}{
		{name: "not configured", nilBackend: true, code: 503, reason: metav1.StatusReasonServiceUnavailable},
		{name: "not found", err: ErrNotFound, code: 404, reason: metav1.StatusReasonNotFound},
		{name: "wrapped not found", err: fmt.Errorf("claim: %w", ErrNotFound), code: 404, reason: metav1.StatusReasonNotFound},
		{name: "unavailable", err: errors.New("kubernetes unavailable"), code: 500, reason: metav1.StatusReasonInternalError},
		{name: "stream sentinel is not special", err: ErrNotReady, code: 500, reason: metav1.StatusReasonInternalError},
		{name: "nil result", code: 500, reason: metav1.StatusReasonInternalError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := Options{Insecure: true}
			if !tc.nilBackend {
				opts.IdentityBackend = identityBackendFunc(func(context.Context, string, string, string) (*PodIdentity, error) { return nil, tc.err })
			}
			rec := serve(New(opts), http.MethodGet, identityPath)
			st := decodeStatus(t, rec)
			if rec.Code != tc.code || st.Code != int32(tc.code) || st.Reason != tc.reason || rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("status %d, headers %v: %+v", rec.Code, rec.Header(), st)
			}
		})
	}
}

func TestIdentityMethodAndAuth(t *testing.T) {
	backend := identityBackendFunc(func(context.Context, string, string, string) (*PodIdentity, error) {
		t.Fatal("rejected request called backend")
		return nil, nil
	})
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodHead} {
		rec := serve(New(Options{IdentityBackend: backend}), method, identityPath)
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodGet || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: %d %v", method, rec.Code, rec.Header())
		}
	}
	for _, tc := range []struct {
		name      string
		opts      Options
		proxyUser string
		code      int
	}{
		{name: "no credentials", code: 401},
		{name: "untrusted proxy", proxyUser: "alice", code: 401},
		{name: "naked trusted proxy", opts: Options{TrustProxyHeaders: true}, proxyUser: "admin", code: 401},
		{name: "proxy without certificate", opts: Options{TrustProxyHeaders: true, ClientCA: x509.NewCertPool()}, proxyUser: "alice", code: 401},
		{name: "denied", opts: Options{Insecure: true, Authorizer: authorizer.AuthorizerFunc(func(context.Context, authorizer.Attributes) (authorizer.Decision, string, error) {
			return authorizer.DecisionDeny, "not yours", nil
		})}, code: 403},
		{name: "authorizer failure", opts: Options{Insecure: true, Authorizer: authorizer.AuthorizerFunc(func(context.Context, authorizer.Attributes) (authorizer.Decision, string, error) {
			return authorizer.DecisionNoOpinion, "", errors.New("SAR unavailable")
		})}, code: 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.opts.IdentityBackend = backend
			req := httptest.NewRequest(http.MethodGet, identityPath, nil)
			req.Header.Set("X-Remote-User", tc.proxyUser)
			rec := httptest.NewRecorder()
			New(tc.opts).Handler().ServeHTTP(rec, req)
			if rec.Code != tc.code || rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("status %d: %s", rec.Code, rec.Body)
			}
		})
	}
}

func TestIdentityDelegatedSAR(t *testing.T) {
	client := fake.NewClientset()
	client.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		review := action.(k8stesting.CreateAction).GetObject().(*authenticationv1.TokenReview)
		if review.Spec.Token != "good" {
			t.Fatalf("token = %q", review.Spec.Token)
		}
		return true, &authenticationv1.TokenReview{Status: authenticationv1.TokenReviewStatus{
			Authenticated: true, User: authenticationv1.UserInfo{Username: "alice", UID: "alice-uid", Groups: []string{"devs"}},
		}}, nil
	})
	var sar *authorizationv1.SubjectAccessReview
	client.PrependReactor("create", "subjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		sar = action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SubjectAccessReview)
		return true, &authorizationv1.SubjectAccessReview{Status: authorizationv1.SubjectAccessReviewStatus{Allowed: true}}, nil
	})
	s := New(Options{Client: client, TrustProxyHeaders: true, IdentityBackend: identityBackendFunc(func(context.Context, string, string, string) (*PodIdentity, error) {
		if sar == nil {
			t.Fatal("lookup before authorization")
		}
		return &PodIdentity{}, nil
	})})
	req := httptest.NewRequest(http.MethodGet, identityPath+"?uid=pod-uid", nil)
	req.Header.Set("Authorization", "Bearer good")
	req.Header.Set("X-Remote-User", "admin")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || sar == nil {
		t.Fatalf("status %d, SAR %+v: %s", rec.Code, sar, rec.Body)
	}
	want := &authorizationv1.ResourceAttributes{Namespace: "team", Verb: "get", Group: IdentityGroupName, Version: IdentityVersion, Resource: IdentityResource, Name: "pod"}
	if !reflect.DeepEqual(sar.Spec.ResourceAttributes, want) || sar.Spec.NonResourceAttributes != nil {
		t.Fatalf("SAR resource attributes = %+v", sar.Spec.ResourceAttributes)
	}
	if sar.Spec.User != "alice" || sar.Spec.UID != "alice-uid" || !reflect.DeepEqual(sar.Spec.Groups, []string{"devs"}) {
		t.Fatalf("SAR identity = %+v", sar.Spec)
	}
}

func TestIdentityProxyCertificateAuthentication(t *testing.T) {
	ca, key := newCA(t)
	cert, _ := newLeaf(t, ca, key, "proxy", nil)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	otherCA, otherKey := newCA(t)
	untrusted, _ := newLeaf(t, otherCA, otherKey, "proxy", nil)
	for _, tc := range []struct {
		name     string
		pool     *x509.CertPool
		cert     *x509.Certificate
		insecure bool
		code     int
	}{
		{name: "verified proxy", pool: pool, cert: cert, code: 200},
		{name: "untrusted proxy", pool: pool, cert: untrusted, code: 401},
		{name: "unconfigured CA", cert: cert, code: 401},
		{name: "unconfigured CA even insecure", cert: cert, insecure: true, code: 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			s := New(Options{
				ClientCA: tc.pool, TrustProxyHeaders: true, Insecure: tc.insecure,
				Authorizer: authorizer.AuthorizerFunc(func(_ context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, error) {
					if tc.code != 200 {
						t.Fatal("unauthenticated request reached authorizer")
					}
					if attrs.GetUser().GetName() != "alice" {
						t.Fatalf("user = %q", attrs.GetUser().GetName())
					}
					return authorizer.DecisionAllow, "", nil
				}),
				IdentityBackend: identityBackendFunc(func(context.Context, string, string, string) (*PodIdentity, error) {
					calls++
					return &PodIdentity{}, nil
				}),
			})
			req := requestWithTLS(http.MethodGet, identityPath, tc.cert)
			req.Header.Set("X-Remote-User", "alice")
			rec := httptest.NewRecorder()
			s.Handler().ServeHTTP(rec, req)
			if rec.Code != tc.code || (tc.code != 200 && calls != 0) {
				t.Fatalf("status %d, calls %d: %s", rec.Code, calls, rec.Body)
			}
		})
	}
}
