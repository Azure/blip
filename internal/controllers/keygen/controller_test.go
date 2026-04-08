package keygen

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const testNamespace = "test-ns"

func testClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(s))
	return fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(objs...).
		Build()
}

func testClientWithInterceptor(t *testing.T, fns interceptor.Funcs, objs ...client.Object) client.Client {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(s))
	return fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(objs...).
		WithInterceptorFuncs(fns).
		Build()
}

func makeSecret(name string, data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       testNamespace,
			Name:            name,
			ResourceVersion: "1",
		},
		Data: data,
	}
}

// generateTestHostKeyPEM creates a valid ed25519 SSH private key in PEM format for tests.
func generateTestHostKeyPEM(t *testing.T) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	require.NoError(t, err)
	return pem.EncodeToMemory(pemBlock)
}

// ---------------------------------------------------------------------------
// ensureSecret
// ---------------------------------------------------------------------------

func TestEnsureSecret(t *testing.T) {
	tests := []struct {
		name      string
		existing  []client.Object
		intercept interceptor.Funcs
		wantErr   string
	}{
		{
			name: "creates secret when none exists",
		},
		{
			name:     "skips when secret already exists",
			existing: []client.Object{makeSecret("test-secret", map[string][]byte{"k": []byte("v")})},
		},
		{
			name: "handles concurrent create (AlreadyExists on Create)",
			intercept: interceptor.Funcs{
				Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
					return k8serrors.NewAlreadyExists(schema.GroupResource{Resource: "secrets"}, "test-secret")
				},
			},
		},
		{
			name: "propagates non-NotFound Get error",
			intercept: interceptor.Funcs{
				Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					return fmt.Errorf("connection refused")
				},
			},
			wantErr: "check secret",
		},
		{
			name: "propagates non-AlreadyExists Create error",
			intercept: interceptor.Funcs{
				Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
					return fmt.Errorf("forbidden")
				},
			},
			wantErr: "create secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cl client.Client
			if tt.intercept.Get != nil || tt.intercept.Create != nil {
				cl = testClientWithInterceptor(t, tt.intercept, tt.existing...)
			} else {
				cl = testClient(t, tt.existing...)
			}

			err := ensureSecret(context.Background(), cl, testNamespace, "test-secret", map[string][]byte{"k": []byte("v")})

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			assert.NoError(t, err)
		})
	}
}

// ---------------------------------------------------------------------------
// ensureHostKey
// ---------------------------------------------------------------------------

func TestEnsureHostKey(t *testing.T) {
	t.Run("creates host key secret", func(t *testing.T) {
		cl := testClient(t)
		err := ensureHostKey(context.Background(), cl, testNamespace)
		require.NoError(t, err)

		var secret corev1.Secret
		err = cl.Get(context.Background(), client.ObjectKey{Namespace: testNamespace, Name: "ssh-host-key"}, &secret)
		require.NoError(t, err)
		assert.Contains(t, secret.Data, "host_key")
		assert.Contains(t, string(secret.Data["host_key"]), "BEGIN OPENSSH PRIVATE KEY")
	})

	t.Run("idempotent: existing host key is preserved", func(t *testing.T) {
		originalKey := generateTestHostKeyPEM(t)
		existing := makeSecret("ssh-host-key", map[string][]byte{"host_key": originalKey})
		cl := testClient(t, existing)

		err := ensureHostKey(context.Background(), cl, testNamespace)
		require.NoError(t, err)

		var secret corev1.Secret
		err = cl.Get(context.Background(), client.ObjectKey{Namespace: testNamespace, Name: "ssh-host-key"}, &secret)
		require.NoError(t, err)
		assert.Equal(t, originalKey, secret.Data["host_key"])
	})
}

// ---------------------------------------------------------------------------
// initSecretsRunnable.Start – integration
// ---------------------------------------------------------------------------

func TestInitSecretsRunnableStart(t *testing.T) {
	t.Run("initializes host key then blocks until context is cancelled", func(t *testing.T) {
		cl := testClient(t)
		r := initSecretsRunnable{cl: cl, namespace: testNamespace}

		ctx, cancel := context.WithCancel(context.Background())

		done := make(chan error, 1)
		go func() {
			done <- r.Start(ctx)
		}()

		// Give the goroutine time to initialize and block on <-ctx.Done().
		select {
		case err := <-done:
			t.Fatalf("Start returned unexpectedly: %v", err)
		case <-time.After(200 * time.Millisecond):
			// Good – Start is blocking as expected.
		}

		cancel()

		select {
		case err := <-done:
			assert.NoError(t, err)
		case <-time.After(2 * time.Second):
			t.Fatal("Start did not return after context cancellation")
		}

		// Verify host key secret was created.
		var secret corev1.Secret
		err := cl.Get(context.Background(), client.ObjectKey{Namespace: testNamespace, Name: "ssh-host-key"}, &secret)
		assert.NoError(t, err)
	})

	t.Run("returns error when host key initialization fails", func(t *testing.T) {
		cl := testClientWithInterceptor(t, interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				return fmt.Errorf("api server down")
			},
		})
		r := initSecretsRunnable{cl: cl, namespace: testNamespace}

		err := r.Start(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ensure gateway host key")
	})
}
