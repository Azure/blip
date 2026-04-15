package auth

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/time/rate"
)

func TestVMNameFromPodName(t *testing.T) {
	tests := []struct {
		name    string
		podName string
		want    string
		wantErr string
	}{
		{
			name:    "standard virt-launcher pod",
			podName: "virt-launcher-blip-abcde-xyz12",
			want:    "blip-abcde",
		},
		{
			name:    "single-segment VM name",
			podName: "virt-launcher-myvm-abc12",
			want:    "myvm",
		},
		{
			name:    "multi-segment VM name with hyphens",
			podName: "virt-launcher-blip-pool-v2-test-abc12",
			want:    "blip-pool-v2-test",
		},
		{
			name:    "missing prefix",
			podName: "some-other-pod-abc12",
			wantErr: "does not have virt-launcher prefix",
		},
		{
			name:    "only prefix with no segments",
			podName: "virt-launcher-",
			wantErr: "cannot extract VM name",
		},
		{
			name:    "prefix with one segment (no hash separator)",
			podName: "virt-launcher-onlyhash",
			wantErr: "cannot extract VM name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := VMNameFromPodName(tt.podName)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// mockTokenReviewer implements TokenReviewer for testing.
type mockTokenReviewer struct {
	reviewFunc func(ctx context.Context, token string) (*TokenReviewResult, error)
}

func (m *mockTokenReviewer) Review(ctx context.Context, token string) (*TokenReviewResult, error) {
	return m.reviewFunc(ctx, token)
}

func TestRegisterPasswordCallback(t *testing.T) {
	validToken := "valid-sa-token"
	validResult := &TokenReviewResult{
		ServiceAccountName: "vm-register",
		Namespace:          "blip",
		PodName:            "virt-launcher-blip-abc12-xyz99",
	}

	reviewer := &mockTokenReviewer{
		reviewFunc: func(ctx context.Context, token string) (*TokenReviewResult, error) {
			if token == validToken {
				return validResult, nil
			}
			return nil, fmt.Errorf("token not authenticated")
		},
	}

	unlimitedLimiter := rate.NewLimiter(rate.Inf, 0)

	t.Run("rejects non-register user without original callback", func(t *testing.T) {
		cb := registerPasswordCallback(reviewer, unlimitedLimiter, nil)
		_, err := cb(fakeConnMeta{user: "runner"}, []byte("somepassword"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not supported for user")
	})

	t.Run("forwards non-register user to original callback", func(t *testing.T) {
		origCalled := false
		origCb := func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			origCalled = true
			return &ssh.Permissions{
				Extensions: map[string]string{ExtIdentity: "oidc:forwarded"},
			}, nil
		}
		cb := registerPasswordCallback(reviewer, unlimitedLimiter, origCb)
		perms, err := cb(fakeConnMeta{user: "runner"}, []byte("some-oidc-token"))
		require.NoError(t, err)
		assert.True(t, origCalled, "original callback should have been invoked")
		assert.Equal(t, "oidc:forwarded", perms.Extensions[ExtIdentity])
	})

	t.Run("rejects empty token for _register", func(t *testing.T) {
		cb := registerPasswordCallback(reviewer, unlimitedLimiter, nil)
		_, err := cb(fakeConnMeta{user: "_register"}, []byte(""))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ServiceAccount token")
	})

	t.Run("rejects invalid token for _register", func(t *testing.T) {
		cb := registerPasswordCallback(reviewer, unlimitedLimiter, nil)
		_, err := cb(fakeConnMeta{user: "_register"}, []byte("bad-token"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "validation failed")
	})

	t.Run("accepts valid token for _register", func(t *testing.T) {
		cb := registerPasswordCallback(reviewer, unlimitedLimiter, nil)
		perms, err := cb(fakeConnMeta{user: "_register"}, []byte(validToken))
		require.NoError(t, err)
		assert.Equal(t, "vm-register", perms.Extensions[ExtIdentity])
		assert.Equal(t, "blip-abc12", perms.Extensions[ExtVMName])
	})

	t.Run("rejects non-register user when no original callback", func(t *testing.T) {
		cb := registerPasswordCallback(reviewer, unlimitedLimiter, nil)
		_, err := cb(fakeConnMeta{user: "alice"}, []byte("some-oidc-token"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not supported for user")
	})

	t.Run("bad pod name in token review", func(t *testing.T) {
		badReviewer := &mockTokenReviewer{
			reviewFunc: func(ctx context.Context, token string) (*TokenReviewResult, error) {
				return &TokenReviewResult{
					ServiceAccountName: "vm-register",
					Namespace:          "blip",
					PodName:            "not-a-virt-launcher",
				}, nil
			},
		}
		cb := registerPasswordCallback(badReviewer, unlimitedLimiter, nil)
		// A non-virt-launcher pod name is no longer a hard error; the VM
		// name will be provided via the exec command instead.  Registration
		// succeeds but without ExtVMName in the permissions.
		perms, err := cb(fakeConnMeta{user: "_register"}, []byte("some-token"))
		require.NoError(t, err)
		assert.Empty(t, perms.Extensions[ExtVMName], "should not set ExtVMName for bad pod name")
	})
}
