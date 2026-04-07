package keygen

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/project-unbounded/blip/internal/sshca"
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

// generateTestKeypair returns a valid CA private key PEM and its public key string.
func generateTestKeypair(t *testing.T) ([]byte, string) {
	t.Helper()
	priv, pub, err := sshca.GenerateCAKeypair()
	require.NoError(t, err)
	return priv, pub
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

func makeConfigMap(name string, data map[string]string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       testNamespace,
			Name:            name,
			ResourceVersion: "1",
		},
		Data: data,
	}
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
// ensureConfigMap
// ---------------------------------------------------------------------------

func TestEnsureConfigMap(t *testing.T) {
	tests := []struct {
		name      string
		existing  []client.Object
		intercept interceptor.Funcs
		wantErr   string
	}{
		{
			name: "creates configmap when none exists",
		},
		{
			name:     "skips when configmap already exists",
			existing: []client.Object{makeConfigMap("test-cm", map[string]string{"k": "v"})},
		},
		{
			name: "propagates non-NotFound Get error",
			intercept: interceptor.Funcs{
				Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					return fmt.Errorf("connection refused")
				},
			},
			wantErr: "check configmap",
		},
		{
			name: "propagates non-AlreadyExists Create error",
			intercept: interceptor.Funcs{
				Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
					return fmt.Errorf("forbidden")
				},
			},
			wantErr: "create configmap",
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

			err := ensureConfigMap(context.Background(), cl, testNamespace, "test-cm", map[string]string{"k": "v"})

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
// resolvePublicKey
// ---------------------------------------------------------------------------

func TestResolvePublicKey(t *testing.T) {
	privPEM, expectedPub := generateTestKeypair(t)

	tests := []struct {
		name      string
		existing  []client.Object
		intercept interceptor.Funcs
		wantPub   string
		wantErr   string
	}{
		{
			name:     "returns parsed public key from persisted secret",
			existing: []client.Object{makeSecret("ca-secret", map[string][]byte{"ca": privPEM})},
			wantPub:  expectedPub,
		},
		{
			name:    "returns fallback when secret does not exist",
			wantPub: "fallback-key",
		},
		{
			name:     "returns fallback when data key is missing",
			existing: []client.Object{makeSecret("ca-secret", map[string][]byte{"other": []byte("x")})},
			wantPub:  "fallback-key",
		},
		{
			name:     "returns error for corrupt private key",
			existing: []client.Object{makeSecret("ca-secret", map[string][]byte{"ca": []byte("not-a-key")})},
			wantErr:  "parse private key",
		},
		{
			name: "propagates non-NotFound Get error",
			intercept: interceptor.Funcs{
				Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					return fmt.Errorf("timeout")
				},
			},
			wantErr: "get secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cl client.Client
			if tt.intercept.Get != nil {
				cl = testClientWithInterceptor(t, tt.intercept, tt.existing...)
			} else {
				cl = testClient(t, tt.existing...)
			}

			pub, err := resolvePublicKey(context.Background(), cl, testNamespace, "ca-secret", "ca", "fallback-key")

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantPub, pub)
		})
	}
}

// ---------------------------------------------------------------------------
// ensureCA – end-to-end scenarios
// ---------------------------------------------------------------------------

func TestEnsureCA(t *testing.T) {
	t.Run("fresh cluster: creates secret and configmap with consistent keys", func(t *testing.T) {
		cl := testClient(t)
		err := ensureCA(context.Background(), cl, testNamespace)
		require.NoError(t, err)

		// Verify the secret was created with a parseable private key.
		var secret corev1.Secret
		err = cl.Get(context.Background(), client.ObjectKey{Namespace: testNamespace, Name: "ssh-ca-keypair"}, &secret)
		require.NoError(t, err)
		assert.Contains(t, secret.Data, "ca")

		signer, err := sshca.ParseCAPrivateKey(secret.Data["ca"])
		require.NoError(t, err)

		// Verify the configmap was created and its public key matches the secret's key.
		var cm corev1.ConfigMap
		err = cl.Get(context.Background(), client.ObjectKey{Namespace: testNamespace, Name: "ssh-ca-pubkey"}, &cm)
		require.NoError(t, err)

		expectedPub := sshca.MarshalPublicKey(signer.PublicKey()) + "\n"
		assert.Equal(t, expectedPub, cm.Data["ca.pub"])
	})

	t.Run("idempotent: existing secret is preserved and configmap uses its key", func(t *testing.T) {
		// Pre-create a CA keypair and store it.
		origPriv, _ := generateTestKeypair(t)
		secret := makeSecret("ssh-ca-keypair", map[string][]byte{"ca": origPriv})
		cl := testClient(t, secret)

		err := ensureCA(context.Background(), cl, testNamespace)
		require.NoError(t, err)

		// The secret should still contain the original key, not a new one.
		var persisted corev1.Secret
		err = cl.Get(context.Background(), client.ObjectKey{Namespace: testNamespace, Name: "ssh-ca-keypair"}, &persisted)
		require.NoError(t, err)
		assert.Equal(t, origPriv, persisted.Data["ca"])

		// The configmap's public key should match the original secret.
		signer, err := sshca.ParseCAPrivateKey(origPriv)
		require.NoError(t, err)
		expectedPub := sshca.MarshalPublicKey(signer.PublicKey()) + "\n"

		var cm corev1.ConfigMap
		err = cl.Get(context.Background(), client.ObjectKey{Namespace: testNamespace, Name: "ssh-ca-pubkey"}, &cm)
		require.NoError(t, err)
		assert.Equal(t, expectedPub, cm.Data["ca.pub"])
	})

	t.Run("propagates error when secret creation fails", func(t *testing.T) {
		cl := testClientWithInterceptor(t, interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				// Let the first Get (for the secret existence check) return NotFound,
				// then the second Get (resolvePublicKey) also returns NotFound.
				return c.Get(ctx, key, obj, opts...)
			},
			Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if _, ok := obj.(*corev1.Secret); ok {
					return fmt.Errorf("disk full")
				}
				return c.Create(ctx, obj, opts...)
			},
		})

		err := ensureCA(context.Background(), cl, testNamespace)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "create secret")
	})
}

// ---------------------------------------------------------------------------
// initSecretsRunnable.Start – integration
// ---------------------------------------------------------------------------

func TestInitSecretsRunnableStart(t *testing.T) {
	t.Run("initializes CA then blocks until context is cancelled", func(t *testing.T) {
		cl := testClient(t)
		r := initSecretsRunnable{cl: cl, namespace: testNamespace}

		ctx, cancel := context.WithCancel(context.Background())

		done := make(chan error, 1)
		go func() {
			done <- r.Start(ctx)
		}()

		// Give the goroutine time to initialize the CA and block on <-ctx.Done().
		// If Start returns early with an error, the select will catch it.
		select {
		case err := <-done:
			// Start returned before we cancelled – that's only OK if there's no error
			// (shouldn't happen since it blocks on ctx.Done, but handle defensively).
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

		// Verify resources were created.
		var secret corev1.Secret
		err := cl.Get(context.Background(), client.ObjectKey{Namespace: testNamespace, Name: "ssh-ca-keypair"}, &secret)
		assert.NoError(t, err)

		var cm corev1.ConfigMap
		err = cl.Get(context.Background(), client.ObjectKey{Namespace: testNamespace, Name: "ssh-ca-pubkey"}, &cm)
		assert.NoError(t, err)
	})

	t.Run("returns error when CA initialization fails", func(t *testing.T) {
		cl := testClientWithInterceptor(t, interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				return fmt.Errorf("api server down")
			},
		})
		r := initSecretsRunnable{cl: cl, namespace: testNamespace}

		err := r.Start(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ensure SSH CA")
	})
}
