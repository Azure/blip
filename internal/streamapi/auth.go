// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package streamapi

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strings"

	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/client-go/kubernetes"
)

var errNoCredentials = errors.New("no credentials presented")

// authenticate returns the request's user. A TLS client certificate is
// verified against ClientCA and becomes user.DefaultInfo{Name: CN,
// Groups: Organizations}. Otherwise an Authorization: Bearer token is
// reviewed with Client. Without a client CA, Insecure is the only mode that
// accepts a certificate (used by tests).
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (user.Info, bool) {
	u, err := s.user(r)
	if err == nil {
		return u, true
	}
	if s.insecure && errors.Is(err, errNoCredentials) {
		return &user.DefaultInfo{
			Name:   user.Anonymous,
			Groups: []string{user.AllUnauthenticated},
		}, true
	}
	writeStatus(w, http.StatusUnauthorized, metav1.StatusReasonUnauthorized, err.Error())
	return nil, false
}

func (s *Server) user(r *http.Request) (user.Info, error) {
	hasCert := r.TLS != nil && len(r.TLS.PeerCertificates) > 0
	if s.proxyAuth && (s.clientCA == nil || hasCert) {
		if name := r.Header.Get("X-Remote-User"); name != "" {
			if hasCert {
				// A configured CA must verify the proxy certificate before
				// its identity headers are trusted.
				if _, err := s.certUser(r.TLS.PeerCertificates); err != nil {
					return nil, err
				}
			}
			return &user.DefaultInfo{Name: name, Groups: r.Header.Values("X-Remote-Group")}, nil
		}
	}
	if hasCert {
		return s.certUser(r.TLS.PeerCertificates)
	}
	if tok, ok := bearerToken(r); ok {
		return s.tokenUser(r.Context(), tok)
	}
	return nil, errNoCredentials
}

func (s *Server) certUser(chain []*x509.Certificate) (user.Info, error) {
	leaf := chain[0]
	if s.clientCA == nil {
		if !s.insecure {
			return nil, errors.New("client certificates are not configured")
		}
	} else {
		intermediates := x509.NewCertPool()
		for _, cert := range chain[1:] {
			intermediates.AddCert(cert)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:         s.clientCA,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}); err != nil {
			return nil, fmt.Errorf("client certificate: %w", err)
		}
	}
	return &user.DefaultInfo{
		Name:   leaf.Subject.CommonName,
		Groups: append([]string(nil), leaf.Subject.Organization...),
	}, nil
}

func bearerToken(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	tok := strings.TrimSpace(h[len(prefix):])
	return tok, tok != ""
}

func (s *Server) tokenUser(ctx context.Context, token string) (user.Info, error) {
	if s.client == nil {
		return nil, errors.New("bearer token review is not configured")
	}
	review, err := s.client.AuthenticationV1().TokenReviews().Create(ctx, &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{Token: token},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("token review: %w", err)
	}
	if !review.Status.Authenticated {
		return nil, errors.New("bearer token is not authenticated")
	}
	st := review.Status.User
	extra := make(map[string][]string, len(st.Extra))
	for k, v := range st.Extra {
		extra[k] = append([]string(nil), v...)
	}
	return &user.DefaultInfo{
		Name:   st.Username,
		UID:    st.UID,
		Groups: append([]string(nil), st.Groups...),
		Extra:  extra,
	}, nil
}

// authorize delegates to the configured authorizer. A missing authorizer
// denies by default; Insecure is the tests-only exception.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request, u user.Info, verb, subresource, namespace, name string) bool {
	if s.Authorizer == nil {
		if s.insecure {
			return true
		}
		writeStatus(w, http.StatusForbidden, metav1.StatusReasonForbidden,
			"no authorizer is configured")
		return false
	}
	attrs := authorizer.AttributesRecord{
		User:            u,
		Verb:            verb,
		Namespace:       namespace,
		APIGroup:        GroupName,
		APIVersion:      Version,
		Resource:        Resource,
		Subresource:     subresource,
		Name:            name,
		ResourceRequest: true,
		Path:            r.URL.Path,
	}
	decision, reason, err := s.Authorizer.Authorize(r.Context(), attrs)
	if err != nil {
		writeStatus(w, http.StatusForbidden, metav1.StatusReasonForbidden,
			fmt.Sprintf("authorization failed: %v", err))
		return false
	}
	if decision != authorizer.DecisionAllow {
		msg := "forbidden"
		if reason != "" {
			msg += ": " + reason
		}
		writeStatus(w, http.StatusForbidden, metav1.StatusReasonForbidden, msg)
		return false
	}
	return true
}

// sarAuthorizer delegates to SubjectAccessReview. It is the default when a
// Kubernetes client is configured and no authorizer is injected.
type sarAuthorizer struct {
	client kubernetes.Interface
}

func (a sarAuthorizer) Authorize(ctx context.Context, attr authorizer.Attributes) (authorizer.Decision, string, error) {
	u := attr.GetUser()
	review := &authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User:   u.GetName(),
			Groups: u.GetGroups(),
			UID:    u.GetUID(),
			Extra:  sarExtra(u.GetExtra()),
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace:   attr.GetNamespace(),
				Verb:        attr.GetVerb(),
				Group:       attr.GetAPIGroup(),
				Version:     attr.GetAPIVersion(),
				Resource:    attr.GetResource(),
				Subresource: attr.GetSubresource(),
				Name:        attr.GetName(),
			},
		},
	}
	resp, err := a.client.AuthorizationV1().SubjectAccessReviews().Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		return authorizer.DecisionNoOpinion, "", err
	}
	if resp.Status.Allowed {
		return authorizer.DecisionAllow, resp.Status.Reason, nil
	}
	return authorizer.DecisionDeny, resp.Status.Reason, nil
}

func sarExtra(extra map[string][]string) map[string]authorizationv1.ExtraValue {
	if len(extra) == 0 {
		return nil
	}
	out := make(map[string]authorizationv1.ExtraValue, len(extra))
	for k, v := range extra {
		out[k] = authorizationv1.ExtraValue(v)
	}
	return out
}
