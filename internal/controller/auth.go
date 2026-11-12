package controller

import (
	"context"
	"fmt"
	"slices"
	"strings"

	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/example/blip/internal/api"
)

// NodeServiceAccount is the service account of the node DaemonSet.
const NodeServiceAccount = "blip-node"

// TokenAuthenticator checks node tokens with TokenReview (design section 11).
type TokenAuthenticator struct {
	Client    client.Client // live client
	Namespace string
}

// Authenticate validates a projected token with audience "blip" from the
// blip-node service account and returns the node its pod runs on.
func (a *TokenAuthenticator) Authenticate(ctx context.Context, token string) (string, error) {
	tr := &authnv1.TokenReview{Spec: authnv1.TokenReviewSpec{Token: token, Audiences: []string{api.NodeTokenAudience}}}
	if err := a.Client.Create(ctx, tr); err != nil {
		return "", fmt.Errorf("token review: %w", err)
	}
	st := tr.Status
	if !st.Authenticated {
		return "", fmt.Errorf("token not authenticated: %s", st.Error)
	}
	if !slices.Contains(st.Audiences, api.NodeTokenAudience) {
		return "", fmt.Errorf("token audience is not %q", api.NodeTokenAudience)
	}
	want := "system:serviceaccount:" + a.Namespace + ":" + NodeServiceAccount
	if st.User.Username != want {
		return "", fmt.Errorf("token user %q is not %q", st.User.Username, want)
	}
	podName := first(st.User.Extra["authentication.kubernetes.io/pod-name"])
	podUID := first(st.User.Extra["authentication.kubernetes.io/pod-uid"])
	if podName == "" {
		return "", fmt.Errorf("token is not bound to a pod")
	}
	var pod corev1.Pod
	if err := a.Client.Get(ctx, types.NamespacedName{Namespace: a.Namespace, Name: podName}, &pod); err != nil {
		return "", fmt.Errorf("token pod: %w", err)
	}
	if podUID != "" && string(pod.UID) != podUID {
		return "", fmt.Errorf("token pod %s was replaced", podName)
	}
	if pod.Spec.NodeName == "" {
		return "", fmt.Errorf("token pod %s is not scheduled", podName)
	}
	if n := first(st.User.Extra["authentication.kubernetes.io/node-name"]); n != "" && !strings.EqualFold(n, pod.Spec.NodeName) {
		return "", fmt.Errorf("token node %q does not match pod node %q", n, pod.Spec.NodeName)
	}
	return pod.Spec.NodeName, nil
}

func first(v authnv1.ExtraValue) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}
