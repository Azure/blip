// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package streamapi

import (
	"context"
	"errors"
	"net/http"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// IdentityGroupName is the pod identity API group.
	IdentityGroupName = "identity.blip.dev"
	// IdentityVersion is the served pod identity API version.
	IdentityVersion = "v1alpha1"
	// IdentityResource is the pod identity resource name.
	IdentityResource = "podidentities"
)

// IdentityBackend resolves the current claim for a pod. An empty uid skips the
// optional UID check. Invalid or absent current claims return ErrNotFound.
type IdentityBackend interface {
	LookupPodIdentity(ctx context.Context, namespace, name, uid string) (*PodIdentity, error)
}

// PodIdentity describes a pod's current Blip and durable state.
type PodIdentity struct {
	metav1.TypeMeta `json:",inline"`
	Metadata        IdentityMetadata `json:"metadata"`
	Blip            BlipIdentity     `json:"blip"`
	State           IdentityMetadata `json:"state"`
}

// IdentityMetadata contains the identity and all labels and annotations of an object.
type IdentityMetadata struct {
	Namespace   string            `json:"namespace"`
	Name        string            `json:"name"`
	UID         string            `json:"uid"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
}

// BlipIdentity adds the current phase and pool to Blip metadata.
type BlipIdentity struct {
	IdentityMetadata `json:",inline"`
	Phase            string `json:"phase"`
	Pool             string `json:"pool"`
}

func (s *Server) servePodIdentity(w http.ResponseWriter, r *http.Request, namespace, name string) {
	// Unlike the stream listener, identity lookups never trust naked proxy
	// headers. Without a CA, only bearer review can establish a supplied
	// identity; do not treat an unverified peer certificate as credentials.
	authServer := *s
	authRequest := r
	if s.clientCA == nil {
		authServer.proxyAuth = false
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			if _, ok := bearerToken(r); !ok {
				writeStatus(w, http.StatusUnauthorized, metav1.StatusReasonUnauthorized, "client certificates are not configured")
				return
			}
			authRequest = r.Clone(r.Context())
			authRequest.TLS = nil
		}
	}
	u, ok := authServer.authenticate(w, authRequest)
	if !ok {
		return
	}
	if !s.authorizeResource(w, r, u, "get", IdentityGroupName, IdentityVersion, IdentityResource, "", namespace, name) {
		return
	}
	if s.identityBackend == nil {
		writeStatus(w, http.StatusServiceUnavailable, metav1.StatusReasonServiceUnavailable, "pod identity backend is not configured")
		return
	}
	identity, err := s.identityBackend.LookupPodIdentity(r.Context(), namespace, name, r.URL.Query().Get("uid"))
	if errors.Is(err, ErrNotFound) {
		writeStatus(w, http.StatusNotFound, metav1.StatusReasonNotFound, err.Error())
		return
	}
	if err != nil {
		writeStatus(w, http.StatusInternalServerError, metav1.StatusReasonInternalError, err.Error())
		return
	}
	if identity == nil {
		writeStatus(w, http.StatusInternalServerError, metav1.StatusReasonInternalError, "pod identity backend returned no identity")
		return
	}
	result := *identity
	result.TypeMeta = metav1.TypeMeta{APIVersion: IdentityGroupName + "/" + IdentityVersion, Kind: "PodIdentity"}
	writeJSON(w, http.StatusOK, &result)
}

func identityGroup() *metav1.APIGroup {
	gv := metav1.GroupVersionForDiscovery{GroupVersion: IdentityGroupName + "/" + IdentityVersion, Version: IdentityVersion}
	return &metav1.APIGroup{
		TypeMeta:         metav1.TypeMeta{APIVersion: "v1", Kind: "APIGroup"},
		Name:             IdentityGroupName,
		Versions:         []metav1.GroupVersionForDiscovery{gv},
		PreferredVersion: gv,
	}
}

func identityResourceList() *metav1.APIResourceList {
	return &metav1.APIResourceList{
		TypeMeta:     metav1.TypeMeta{APIVersion: "v1", Kind: "APIResourceList"},
		GroupVersion: IdentityGroupName + "/" + IdentityVersion,
		APIResources: []metav1.APIResource{{
			Name:         IdentityResource,
			SingularName: "podidentity",
			Namespaced:   true,
			Kind:         "PodIdentity",
			Verbs:        []string{"get"},
		}},
	}
}
