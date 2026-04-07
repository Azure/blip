package deallocation

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kubevirtv1 "kubevirt.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	testNamespace = "test-ns"
	testPool      = "default"
)

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, kubevirtv1.AddToScheme(s))
	return s
}

func newClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithObjects(objs...).
		Build()
}

func newClientWithInterceptor(t *testing.T, fns interceptor.Funcs, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithObjects(objs...).
		WithInterceptorFuncs(fns).
		Build()
}

func makeVM(name string, pool string, annotations map[string]string) *kubevirtv1.VirtualMachine {
	running := true
	return &kubevirtv1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       testNamespace,
			Labels:          map[string]string{"blip.io/pool": pool},
			Annotations:     annotations,
			ResourceVersion: "1",
		},
		Spec: kubevirtv1.VirtualMachineSpec{
			Running: &running,
		},
	}
}

func req(name string) reconcile.Request {
	return reconcile.Request{
		NamespacedName: types.NamespacedName{Namespace: testNamespace, Name: name},
	}
}

// ---------------------------------------------------------------------------
// Reconcile
// ---------------------------------------------------------------------------

func TestReconcile(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name           string
		vm             *kubevirtv1.VirtualMachine
		request        reconcile.Request
		intercept      interceptor.Funcs
		wantRequeue    bool
		wantErr        string
		wantDeleted    bool
		controllerNS   string
		controllerPool string
	}{
		{
			name:    "ignores VM in a different namespace",
			vm:      makeVM("vm1", testPool, map[string]string{"blip.io/session-id": "s1"}),
			request: reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "other-ns", Name: "vm1"}},
		},
		{
			name:    "ignores VM not found (already deleted)",
			request: req("gone"),
		},
		{
			name: "returns error on non-NotFound Get failure",
			intercept: interceptor.Funcs{
				Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					return fmt.Errorf("api unavailable")
				},
			},
			request: req("vm1"),
			wantErr: "get VM",
		},
		{
			name:    "ignores VM from a different pool",
			vm:      makeVM("vm1", "other-pool", map[string]string{"blip.io/session-id": "s1"}),
			request: req("vm1"),
		},
		{
			name:    "ignores unclaimed VM (no session-id annotation)",
			vm:      makeVM("vm1", testPool, nil),
			request: req("vm1"),
		},
		{
			name: "deletes VM when release annotation is set",
			vm: makeVM("vm1", testPool, map[string]string{
				"blip.io/session-id": "s1",
				"blip.io/release":    "true",
			}),
			request:     req("vm1"),
			wantDeleted: true,
		},
		{
			name: "deletes VM when claim has expired",
			vm: makeVM("vm1", testPool, map[string]string{
				"blip.io/session-id":   "s1",
				"blip.io/claimed-at":   now.Add(-2 * time.Hour).Format(time.RFC3339),
				"blip.io/max-duration": "3600",
			}),
			request:     req("vm1"),
			wantDeleted: true,
		},
		{
			name: "requeues VM that has not yet expired",
			vm: makeVM("vm1", testPool, map[string]string{
				"blip.io/session-id":   "s1",
				"blip.io/claimed-at":   now.Format(time.RFC3339),
				"blip.io/max-duration": "7200",
			}),
			request:     req("vm1"),
			wantRequeue: true,
		},
		{
			name: "no requeue for claimed VM without TTL annotations",
			vm: makeVM("vm1", testPool, map[string]string{
				"blip.io/session-id": "s1",
			}),
			request: req("vm1"),
		},
		{
			name: "handles already-deleted VM during Delete",
			vm: makeVM("vm1", testPool, map[string]string{
				"blip.io/session-id": "s1",
				"blip.io/release":    "true",
			}),
			intercept: interceptor.Funcs{
				Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
					// Simulate the object being gone between Get and Delete.
					_ = c.Delete(ctx, obj, opts...)
					return c.Delete(ctx, obj, opts...)
				},
			},
			request: req("vm1"),
			// Should succeed (NotFound on delete is swallowed).
		},
		{
			name: "returns error on non-NotFound Delete failure",
			vm: makeVM("vm1", testPool, map[string]string{
				"blip.io/session-id": "s1",
				"blip.io/release":    "true",
			}),
			intercept: interceptor.Funcs{
				Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
					return fmt.Errorf("forbidden")
				},
			},
			request: req("vm1"),
			wantErr: "delete VM",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var objs []client.Object
			if tt.vm != nil {
				objs = append(objs, tt.vm)
			}

			var cl client.Client
			if tt.intercept.Get != nil || tt.intercept.Delete != nil {
				cl = newClientWithInterceptor(t, tt.intercept, objs...)
			} else {
				cl = newClient(t, objs...)
			}

			ns := testNamespace
			if tt.controllerNS != "" {
				ns = tt.controllerNS
			}
			pool := testPool
			if tt.controllerPool != "" {
				pool = tt.controllerPool
			}

			r := &controller{Client: cl, Namespace: ns, PoolName: pool}
			result, err := r.Reconcile(context.Background(), tt.request)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)

			if tt.wantRequeue {
				assert.True(t, result.RequeueAfter > 0, "expected RequeueAfter > 0, got %v", result.RequeueAfter)
			} else {
				assert.Zero(t, result.RequeueAfter)
			}

			if tt.wantDeleted && tt.vm != nil {
				var check kubevirtv1.VirtualMachine
				getErr := cl.Get(context.Background(), types.NamespacedName{
					Namespace: tt.vm.Namespace,
					Name:      tt.vm.Name,
				}, &check)
				assert.Error(t, getErr, "VM should have been deleted")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parseClaimTTL
// ---------------------------------------------------------------------------

func TestParseClaimTTL(t *testing.T) {
	validTime := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name        string
		annotations map[string]string
		wantOK      bool
		wantAt      time.Time
		wantDur     time.Duration
	}{
		{
			name:        "valid annotations",
			annotations: map[string]string{"blip.io/claimed-at": validTime.Format(time.RFC3339), "blip.io/max-duration": "600"},
			wantOK:      true,
			wantAt:      validTime,
			wantDur:     600 * time.Second,
		},
		{
			name:        "missing claimed-at",
			annotations: map[string]string{"blip.io/max-duration": "600"},
		},
		{
			name:        "missing max-duration",
			annotations: map[string]string{"blip.io/claimed-at": validTime.Format(time.RFC3339)},
		},
		{
			name:        "nil annotations",
			annotations: nil,
		},
		{
			name:        "malformed claimed-at",
			annotations: map[string]string{"blip.io/claimed-at": "not-a-time", "blip.io/max-duration": "600"},
		},
		{
			name:        "non-numeric max-duration",
			annotations: map[string]string{"blip.io/claimed-at": validTime.Format(time.RFC3339), "blip.io/max-duration": "abc"},
		},
		{
			name:        "zero max-duration",
			annotations: map[string]string{"blip.io/claimed-at": validTime.Format(time.RFC3339), "blip.io/max-duration": "0"},
		},
		{
			name:        "negative max-duration",
			annotations: map[string]string{"blip.io/claimed-at": validTime.Format(time.RFC3339), "blip.io/max-duration": "-10"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := &metav1.ObjectMeta{Annotations: tt.annotations}
			claimedAt, dur, ok := parseClaimTTL(obj)

			assert.Equal(t, tt.wantOK, ok)
			if tt.wantOK {
				assert.True(t, claimedAt.Equal(tt.wantAt))
				assert.Equal(t, tt.wantDur, dur)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isExpired / timeUntilExpiry – tested together as they share the same logic
// ---------------------------------------------------------------------------

func TestExpiryBehavior(t *testing.T) {
	tests := []struct {
		name          string
		annotations   map[string]string
		wantExpired   bool
		wantRemaining bool // true if we expect timeUntilExpiry > 0
	}{
		{
			name: "claim in the past is expired",
			annotations: map[string]string{
				"blip.io/claimed-at":   time.Now().Add(-2 * time.Hour).Format(time.RFC3339),
				"blip.io/max-duration": "3600",
			},
			wantExpired: true,
		},
		{
			name: "claim in the future is not expired and has remaining time",
			annotations: map[string]string{
				"blip.io/claimed-at":   time.Now().Format(time.RFC3339),
				"blip.io/max-duration": "7200",
			},
			wantRemaining: true,
		},
		{
			name:        "missing annotations means not expired and no remaining time",
			annotations: map[string]string{"blip.io/session-id": "s1"},
		},
		{
			name: "malformed annotations means not expired and no remaining time",
			annotations: map[string]string{
				"blip.io/claimed-at":   "bad",
				"blip.io/max-duration": "also-bad",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := &metav1.ObjectMeta{Annotations: tt.annotations}

			assert.Equal(t, tt.wantExpired, isExpired(obj))

			remaining := timeUntilExpiry(obj)
			if tt.wantRemaining {
				assert.True(t, remaining > 0, "expected positive remaining time, got %v", remaining)
			} else {
				assert.Zero(t, remaining)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// End-to-end scenario: release flow
// ---------------------------------------------------------------------------

func TestReconcile_ReleaseFlow(t *testing.T) {
	// Simulate a full lifecycle: a claimed VM receives the release annotation
	// and is deleted on reconcile.
	vm := makeVM("session-vm", testPool, map[string]string{
		"blip.io/session-id":   "sess-abc",
		"blip.io/claimed-at":   time.Now().Format(time.RFC3339),
		"blip.io/max-duration": "7200",
		"blip.io/claimed-by":   "user@example.com",
		"blip.io/user":         "testuser",
	})

	cl := newClient(t, vm)
	r := &controller{Client: cl, Namespace: testNamespace, PoolName: testPool}

	// First reconcile: VM is claimed but not expired -> requeue.
	result, err := r.Reconcile(context.Background(), req("session-vm"))
	require.NoError(t, err)
	assert.True(t, result.RequeueAfter > 0, "should requeue for TTL")

	// Simulate setting the release annotation (like the gateway would).
	var current kubevirtv1.VirtualMachine
	require.NoError(t, cl.Get(context.Background(), types.NamespacedName{
		Namespace: testNamespace, Name: "session-vm",
	}, &current))
	current.Annotations["blip.io/release"] = "true"
	require.NoError(t, cl.Update(context.Background(), &current))

	// Second reconcile: VM has release=true -> deleted.
	result, err = r.Reconcile(context.Background(), req("session-vm"))
	require.NoError(t, err)
	assert.Zero(t, result.RequeueAfter)

	// Verify VM is gone.
	getErr := cl.Get(context.Background(), types.NamespacedName{
		Namespace: testNamespace, Name: "session-vm",
	}, &current)
	assert.Error(t, getErr, "VM should be deleted")
}

// ---------------------------------------------------------------------------
// End-to-end scenario: expiry flow
// ---------------------------------------------------------------------------

func TestReconcile_ExpiryFlow(t *testing.T) {
	// VM claimed 2 hours ago with max-duration of 1 hour -> should be deleted.
	vm := makeVM("expired-vm", testPool, map[string]string{
		"blip.io/session-id":   "sess-xyz",
		"blip.io/claimed-at":   time.Now().Add(-2 * time.Hour).Format(time.RFC3339),
		"blip.io/max-duration": "3600",
	})

	cl := newClient(t, vm)
	r := &controller{Client: cl, Namespace: testNamespace, PoolName: testPool}

	result, err := r.Reconcile(context.Background(), req("expired-vm"))
	require.NoError(t, err)
	assert.Zero(t, result.RequeueAfter)

	var check kubevirtv1.VirtualMachine
	getErr := cl.Get(context.Background(), types.NamespacedName{
		Namespace: testNamespace, Name: "expired-vm",
	}, &check)
	assert.Error(t, getErr, "expired VM should be deleted")
}
