// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"context"
	"errors"
	"fmt"
	"strings"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// tokenReviewCallers maps a guest's projected token back to its chat. The
// token is pod-bound, so the pod name in its extra claims identifies the VM,
// whose pod annotation names the Blip, whose label names the chat. This is
// authentication and identity mapping only; whether the chat may spawn a given
// profile is decided by the blip-chat-spawn admission policy when blipchat
// creates the child state.
type tokenReviewCallers struct {
	api      kubernetes.Interface
	cluster  Cluster
	audience string
}

// NewTokenReviewCallers returns a Callers that authenticates with the API
// server. audience must match the pool endpoint's projected token audience.
func NewTokenReviewCallers(cfg *rest.Config, cluster Cluster, audience string) (Callers, error) {
	if audience == "" {
		audience = "blipchat"
	}
	api, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &tokenReviewCallers{api: api, cluster: cluster, audience: audience}, nil
}

// Identify maps a token to its chat. namespace is the deployment-time chat
// namespace, not a caller-chosen value.
func (t *tokenReviewCallers) Identify(ctx context.Context, namespace, token string) (*Caller, error) {
	if token == "" {
		return nil, errors.New("missing token")
	}
	review := &authv1.TokenReview{
		Spec: authv1.TokenReviewSpec{Token: token, Audiences: []string{t.audience}},
	}
	resp, err := t.api.AuthenticationV1().TokenReviews().Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("token review: %w", err)
	}
	if !resp.Status.Authenticated || resp.Status.Error != "" {
		return nil, errors.New("invalid token")
	}
	if t.audience != "" && !contains(resp.Status.Audiences, t.audience) {
		return nil, fmt.Errorf("token was not issued for %q", t.audience)
	}
	// Only a service account in the chat's namespace may call.
	prefix := "system:serviceaccount:" + namespace + ":"
	if !strings.HasPrefix(resp.Status.User.Username, prefix) {
		return nil, errors.New("token does not belong to this namespace")
	}
	extra := resp.Status.User.Extra["authentication.kubernetes.io/pod-name"]
	if len(extra) == 0 || extra[0] == "" {
		return nil, errors.New("token is not pod-bound")
	}
	pod, err := t.cluster.GetPod(ctx, namespace, extra[0])
	if err != nil {
		return nil, fmt.Errorf("read caller pod: %w", err)
	}
	blipName := pod.Annotations[v1.AnnotationBlip]
	if blipName == "" {
		return nil, errors.New("caller pod does not belong to a blip")
	}
	blip, err := t.cluster.GetBlip(ctx, namespace, blipName)
	if err != nil {
		return nil, fmt.Errorf("read caller blip: %w", err)
	}
	if blip.Status.Pod != pod.Name || (blip.Status.PodUID != "" && blip.Status.PodUID != string(pod.UID)) {
		return nil, errors.New("caller pod is not the blip's current pod")
	}
	if pod.Labels[v1.LabelBlipUID] != string(blip.UID) {
		return nil, errors.New("caller pod does not belong to the blip")
	}
	session := blip.Labels[LabelSession]
	if session == "" {
		return nil, errors.New("only a chat blip may use agent tools")
	}
	state, err := t.cluster.GetSession(ctx, namespace, session)
	if err != nil {
		return nil, fmt.Errorf("read caller chat: %w", err)
	}
	if state.Labels[LabelSession] != "true" || !isChatState(state) {
		return nil, errors.New("only a chat blip may use agent tools")
	}
	return &Caller{Namespace: namespace, Session: state, Blip: blip}, nil
}

func contains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}
