package auth

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// TokenReviewResult holds the validated information from a ServiceAccount token.
type TokenReviewResult struct {
	// ServiceAccountName is the name of the ServiceAccount.
	ServiceAccountName string
	// Namespace is the namespace of the ServiceAccount.
	Namespace string
	// PodName is the name of the pod the token is bound to (from
	// authentication.kubernetes.io/pod-name in the extra fields).
	PodName string
}

// TokenReviewer validates Kubernetes ServiceAccount tokens.
type TokenReviewer interface {
	// Review validates a token and returns information about the
	// authenticated identity. Returns an error if the token is invalid.
	Review(ctx context.Context, token string) (*TokenReviewResult, error)
}

// KubeTokenReviewer validates tokens via the Kubernetes TokenReview API.
type KubeTokenReviewer struct {
	client    kubernetes.Interface
	namespace string
	// expectedSA is the ServiceAccount name tokens must belong to.
	expectedSA string
}

// NewKubeTokenReviewer creates a TokenReviewer that validates tokens against
// the Kubernetes API server. It expects tokens from the given ServiceAccount
// in the given namespace.
func NewKubeTokenReviewer(namespace, expectedSA string) (*KubeTokenReviewer, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("in-cluster config for token reviewer: %w", err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create kubernetes client for token reviewer: %w", err)
	}
	return &KubeTokenReviewer{
		client:     client,
		namespace:  namespace,
		expectedSA: expectedSA,
	}, nil
}

// Review validates the token via TokenReview and checks that it belongs to
// the expected ServiceAccount. Returns the pod name from the token's extra
// fields so the caller can derive the VM name.
func (r *KubeTokenReviewer) Review(ctx context.Context, token string) (*TokenReviewResult, error) {
	review := &authv1.TokenReview{
		Spec: authv1.TokenReviewSpec{
			Token: token,
		},
	}

	result, err := r.client.AuthenticationV1().TokenReviews().Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("token review API call: %w", err)
	}

	if !result.Status.Authenticated {
		return nil, fmt.Errorf("token not authenticated: %s", result.Status.Error)
	}

	// Expect format: system:serviceaccount:<namespace>:<name>
	username := result.Status.User.Username
	parts := strings.Split(username, ":")
	if len(parts) != 4 || parts[0] != "system" || parts[1] != "serviceaccount" {
		return nil, fmt.Errorf("unexpected token subject: %s", username)
	}

	saNamespace := parts[2]
	saName := parts[3]

	if saNamespace != r.namespace {
		return nil, fmt.Errorf("token namespace %q does not match expected %q", saNamespace, r.namespace)
	}
	if saName != r.expectedSA {
		return nil, fmt.Errorf("token service account %q does not match expected %q", saName, r.expectedSA)
	}

	// Extract pod name from extra fields.
	podNames := result.Status.User.Extra["authentication.kubernetes.io/pod-name"]
	if len(podNames) == 0 {
		slog.Warn("token review: no pod-name in extra fields", "username", username)
		return nil, fmt.Errorf("token has no bound pod name")
	}

	return &TokenReviewResult{
		ServiceAccountName: saName,
		Namespace:          saNamespace,
		PodName:            string(podNames[0]),
	}, nil
}

// VMNameFromPodName extracts the VirtualMachine name from a virt-launcher
// pod name. KubeVirt names launcher pods as "virt-launcher-<vm-name>-<hash>".
// Returns the VM name or an error if the format doesn't match.
func VMNameFromPodName(podName string) (string, error) {
	const prefix = "virt-launcher-"
	if !strings.HasPrefix(podName, prefix) {
		return "", fmt.Errorf("pod name %q does not have virt-launcher prefix", podName)
	}
	suffix := podName[len(prefix):]
	// The last segment after the final hyphen is the random hash.
	lastDash := strings.LastIndex(suffix, "-")
	if lastDash <= 0 {
		return "", fmt.Errorf("cannot extract VM name from pod name %q", podName)
	}
	return suffix[:lastDash], nil
}
