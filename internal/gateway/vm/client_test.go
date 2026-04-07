package vm

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubevirtv1 "kubevirt.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const testNamespace = "test-ns"

// fakeCache wraps a fake client.WithWatch to satisfy the cache.Cache interface.
// Only Get and List are used by the code under test; the rest are stubs.
type fakeCache struct {
	client.WithWatch
}

func (fakeCache) GetInformer(context.Context, client.Object, ...cache.InformerGetOption) (cache.Informer, error) {
	return nil, nil
}
func (fakeCache) GetInformerForKind(context.Context, schema.GroupVersionKind, ...cache.InformerGetOption) (cache.Informer, error) {
	return nil, nil
}
func (fakeCache) RemoveInformer(context.Context, client.Object) error { return nil }
func (fakeCache) Start(context.Context) error                         { return nil }
func (fakeCache) WaitForCacheSync(context.Context) bool               { return true }
func (fakeCache) IndexField(context.Context, client.Object, string, client.IndexerFunc) error {
	return nil
}

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s, err := newScheme()
	require.NoError(t, err)
	return s
}

// newTestClient builds a Client with a fake cache and writer. Objects are
// shared between both so that writes via the writer are visible through the
// cache. Each call produces independent state.
func newTestClient(t *testing.T, objs ...client.Object) *Client {
	t.Helper()
	s := testScheme(t)
	mapper := newStaticRESTMapper()

	builder := fake.NewClientBuilder().
		WithScheme(s).
		WithRESTMapper(mapper).
		WithObjects(objs...).
		WithIndex(&kubevirtv1.VirtualMachine{}, indexVMPool, func(obj client.Object) []string {
			pool := obj.GetLabels()["blip.io/pool"]
			if pool == "" {
				return nil
			}
			return []string{pool}
		}).
		WithIndex(&kubevirtv1.VirtualMachine{}, indexVMSessionID, func(obj client.Object) []string {
			sid := obj.GetAnnotations()["blip.io/session-id"]
			if sid == "" {
				return nil
			}
			return []string{sid}
		}).
		WithIndex(&kubevirtv1.VirtualMachine{}, indexVMUser, func(obj client.Object) []string {
			user := obj.GetAnnotations()["blip.io/user"]
			if user == "" {
				return nil
			}
			if obj.GetAnnotations()["blip.io/session-id"] == "" {
				return nil
			}
			return []string{user}
		}).
		WithIndex(&kubevirtv1.VirtualMachine{}, indexVMSSHPublicKey, func(obj client.Object) []string {
			fp := obj.GetAnnotations()["blip.io/ssh-public-key"]
			if fp == "" {
				return nil
			}
			return []string{fp}
		})

	fc := builder.Build()

	return &Client{
		cache:     fakeCache{fc},
		writer:    fc,
		namespace: testNamespace,
	}
}

// newTestClientSplit builds a Client with separate cache and writer clients,
// allowing interceptors on the writer for error injection.
func newTestClientSplit(t *testing.T, writerInterceptor interceptor.Funcs, objs ...client.Object) *Client {
	t.Helper()
	s := testScheme(t)
	mapper := newStaticRESTMapper()

	cacheBuilder := fake.NewClientBuilder().
		WithScheme(s).
		WithRESTMapper(mapper).
		WithObjects(objs...).
		WithIndex(&kubevirtv1.VirtualMachine{}, indexVMPool, func(obj client.Object) []string {
			pool := obj.GetLabels()["blip.io/pool"]
			if pool == "" {
				return nil
			}
			return []string{pool}
		}).
		WithIndex(&kubevirtv1.VirtualMachine{}, indexVMSessionID, func(obj client.Object) []string {
			sid := obj.GetAnnotations()["blip.io/session-id"]
			if sid == "" {
				return nil
			}
			return []string{sid}
		}).
		WithIndex(&kubevirtv1.VirtualMachine{}, indexVMUser, func(obj client.Object) []string {
			user := obj.GetAnnotations()["blip.io/user"]
			if user == "" {
				return nil
			}
			if obj.GetAnnotations()["blip.io/session-id"] == "" {
				return nil
			}
			return []string{user}
		}).
		WithIndex(&kubevirtv1.VirtualMachine{}, indexVMSSHPublicKey, func(obj client.Object) []string {
			fp := obj.GetAnnotations()["blip.io/ssh-public-key"]
			if fp == "" {
				return nil
			}
			return []string{fp}
		})

	writerBuilder := fake.NewClientBuilder().
		WithScheme(s).
		WithRESTMapper(mapper).
		WithObjects(objs...).
		WithInterceptorFuncs(writerInterceptor)

	return &Client{
		cache:     fakeCache{cacheBuilder.Build()},
		writer:    writerBuilder.Build(),
		namespace: testNamespace,
	}
}

// makeVM creates a VirtualMachine in the test namespace with the given pool label.
func makeVM(name, pool string, createdAt time.Time, annotations map[string]string) *kubevirtv1.VirtualMachine {
	labels := map[string]string{"blip.io/pool": pool}
	if annotations == nil {
		annotations = map[string]string{}
	}
	// Simulate cloud-init having registered a host key so the VM is
	// eligible for claiming (Claim skips VMs without a host key).
	if _, ok := annotations["blip.io/host-key"]; !ok {
		annotations["blip.io/host-key"] = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeTestKeyData"
	}
	return &kubevirtv1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         testNamespace,
			Labels:            labels,
			Annotations:       annotations,
			CreationTimestamp: metav1.NewTime(createdAt),
			ResourceVersion:   "1",
		},
	}
}

// makeReadyVMI creates a ready VirtualMachineInstance with an IP.
func makeReadyVMI(name, podIP, nodeName string) *kubevirtv1.VirtualMachineInstance {
	return &kubevirtv1.VirtualMachineInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       testNamespace,
			ResourceVersion: "1",
		},
		Status: kubevirtv1.VirtualMachineInstanceStatus{
			NodeName: nodeName,
			Conditions: []kubevirtv1.VirtualMachineInstanceCondition{
				{
					Type:   kubevirtv1.VirtualMachineInstanceReady,
					Status: corev1.ConditionTrue,
				},
			},
			Interfaces: []kubevirtv1.VirtualMachineInstanceNetworkInterface{
				{IP: podIP},
			},
		},
	}
}

// makeUnreadyVMI creates a not-ready VirtualMachineInstance.
func makeUnreadyVMI(name, podIP string) *kubevirtv1.VirtualMachineInstance {
	return &kubevirtv1.VirtualMachineInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       testNamespace,
			ResourceVersion: "1",
		},
		Status: kubevirtv1.VirtualMachineInstanceStatus{
			Conditions: []kubevirtv1.VirtualMachineInstanceCondition{
				{
					Type:   kubevirtv1.VirtualMachineInstanceReady,
					Status: corev1.ConditionFalse,
				},
			},
			Interfaces: []kubevirtv1.VirtualMachineInstanceNetworkInterface{
				{IP: podIP},
			},
		},
	}
}

func makeNode(name string, labels map[string]string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Labels:          labels,
			ResourceVersion: "1",
		},
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestClaim(t *testing.T) {
	t.Run("success: claims an unclaimed ready VM and returns connection details", func(t *testing.T) {
		now := time.Now()
		vm := makeVM("vm-1", "default", now, nil)
		vmi := makeReadyVMI("vm-1", "10.0.0.1", "node-1")

		c := newTestClient(t, vm, vmi)
		result, err := c.Claim(context.Background(), "default", "sess-1", "gw-1", 3600, "", 0)

		require.NoError(t, err)
		assert.Equal(t, "vm-1", result.Name)
		assert.Equal(t, "10.0.0.1", result.PodIP)
		assert.Equal(t, "node-1", result.NodeName)
	})

	t.Run("no VMs available returns specific error", func(t *testing.T) {
		c := newTestClient(t)
		_, err := c.Claim(context.Background(), "default", "sess-1", "gw-1", 3600, "", 0)
		assert.ErrorIs(t, err, errNoVMsAvailable)
	})

	t.Run("skips already-claimed VMs", func(t *testing.T) {
		now := time.Now()
		claimed := makeVM("vm-claimed", "pool-a", now, map[string]string{
			"blip.io/session-id": "existing-session",
		})
		unclaimed := makeVM("vm-free", "pool-a", now, nil)
		vmiClaimed := makeReadyVMI("vm-claimed", "10.0.0.1", "node-1")
		vmiFree := makeReadyVMI("vm-free", "10.0.0.2", "node-2")

		c := newTestClient(t, claimed, unclaimed, vmiClaimed, vmiFree)
		result, err := c.Claim(context.Background(), "pool-a", "sess-2", "gw-1", 3600, "", 0)

		require.NoError(t, err)
		assert.Equal(t, "vm-free", result.Name)
		assert.Equal(t, "10.0.0.2", result.PodIP)
	})

	t.Run("skips unready VMs", func(t *testing.T) {
		now := time.Now()
		vmA := makeVM("vm-unready", "pool-b", now.Add(-time.Minute), nil)
		vmB := makeVM("vm-ready", "pool-b", now, nil)
		vmiA := makeUnreadyVMI("vm-unready", "10.0.0.1")
		vmiB := makeReadyVMI("vm-ready", "10.0.0.2", "node-2")

		c := newTestClient(t, vmA, vmB, vmiA, vmiB)
		result, err := c.Claim(context.Background(), "pool-b", "sess-3", "gw-1", 3600, "", 0)

		require.NoError(t, err)
		assert.Equal(t, "vm-ready", result.Name)
	})

	t.Run("quota exceeded blocks claim", func(t *testing.T) {
		now := time.Now()
		// One VM already claimed by this user.
		existing := makeVM("vm-existing", "pool-q", now, map[string]string{
			"blip.io/session-id": "old-sess",
			"blip.io/user":       "alice",
		})
		free := makeVM("vm-free", "pool-q", now, nil)
		vmiExisting := makeReadyVMI("vm-existing", "10.0.0.1", "node-1")
		vmiFree := makeReadyVMI("vm-free", "10.0.0.2", "node-2")

		c := newTestClient(t, existing, free, vmiExisting, vmiFree)
		_, err := c.Claim(context.Background(), "pool-q", "new-sess", "gw-1", 3600, "alice", 1)

		assert.ErrorIs(t, err, ErrQuotaExceeded)
	})

	t.Run("quota not enforced when maxBlips is 0", func(t *testing.T) {
		now := time.Now()
		existing := makeVM("vm-a", "pool-r", now, map[string]string{
			"blip.io/session-id": "old",
			"blip.io/user":       "bob",
		})
		free := makeVM("vm-b", "pool-r", now, nil)
		vmiA := makeReadyVMI("vm-a", "10.0.0.1", "node-1")
		vmiB := makeReadyVMI("vm-b", "10.0.0.2", "node-2")

		c := newTestClient(t, existing, free, vmiA, vmiB)
		result, err := c.Claim(context.Background(), "pool-r", "new-s", "gw-1", 3600, "bob", 0)

		require.NoError(t, err)
		assert.Equal(t, "vm-b", result.Name)
	})

	t.Run("all retries exhausted on persistent conflicts", func(t *testing.T) {
		now := time.Now()
		vm := makeVM("vm-conflict", "pool-c", now, nil)
		vmi := makeReadyVMI("vm-conflict", "10.0.0.1", "node-1")

		conflictErr := k8serrors.NewConflict(
			schema.GroupResource{Group: "kubevirt.io", Resource: "virtualmachines"},
			"vm-conflict",
			fmt.Errorf("conflict"),
		)
		c := newTestClientSplit(t, interceptor.Funcs{
			Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				return conflictErr
			},
		}, vm, vmi)

		_, err := c.Claim(context.Background(), "pool-c", "sess-c", "gw-1", 3600, "", 0)
		assert.ErrorIs(t, err, errAllocationFailed)
	})
}

func TestReconnect(t *testing.T) {
	t.Run("success: reconnects to a previously claimed VM", func(t *testing.T) {
		vm := makeVM("vm-recon", "pool-x", time.Now(), map[string]string{
			"blip.io/session-id":       "sess-r1",
			"blip.io/auth-fingerprint": "SHA256:abc123",
			"blip.io/claimed-by":       "gw-old",
		})
		vmi := makeReadyVMI("vm-recon", "10.0.0.5", "node-3")

		c := newTestClient(t, vm, vmi)
		result, err := c.Reconnect(context.Background(), "sess-r1", "SHA256:abc123", "gw-new", 3600)

		require.NoError(t, err)
		assert.Equal(t, "vm-recon", result.Name)
		assert.Equal(t, "10.0.0.5", result.PodIP)
		assert.Equal(t, "node-3", result.NodeName)
	})

	t.Run("session not found", func(t *testing.T) {
		c := newTestClient(t)
		_, err := c.Reconnect(context.Background(), "nonexistent", "fp", "gw-1", 3600)
		assert.ErrorIs(t, err, errSessionNotFound)
	})

	t.Run("auth fingerprint mismatch", func(t *testing.T) {
		vm := makeVM("vm-auth", "pool-y", time.Now(), map[string]string{
			"blip.io/session-id":       "sess-auth",
			"blip.io/auth-fingerprint": "SHA256:correct",
		})
		vmi := makeReadyVMI("vm-auth", "10.0.0.6", "node-4")

		c := newTestClient(t, vm, vmi)
		_, err := c.Reconnect(context.Background(), "sess-auth", "SHA256:wrong", "gw-1", 3600)
		assert.ErrorIs(t, err, errSessionAuthMismatch)
	})

	t.Run("VM not ready blocks reconnect", func(t *testing.T) {
		vm := makeVM("vm-notready", "pool-z", time.Now(), map[string]string{
			"blip.io/session-id":       "sess-nr",
			"blip.io/auth-fingerprint": "SHA256:fp",
		})
		vmi := makeUnreadyVMI("vm-notready", "10.0.0.7")

		c := newTestClient(t, vm, vmi)
		_, err := c.Reconnect(context.Background(), "sess-nr", "SHA256:fp", "gw-1", 3600)
		assert.ErrorIs(t, err, errSessionVMNotReady)
	})

	t.Run("missing auth fingerprint is rejected", func(t *testing.T) {
		vm := makeVM("vm-nofp", "pool-m", time.Now(), map[string]string{
			"blip.io/session-id": "sess-nofp",
			// no auth-fingerprint annotation
		})
		vmi := makeReadyVMI("vm-nofp", "10.0.0.8", "node-5")

		c := newTestClient(t, vm, vmi)
		_, err := c.Reconnect(context.Background(), "sess-nofp", "SHA256:any", "gw-1", 3600)
		assert.ErrorIs(t, err, errSessionAuthMismatch)
	})
}

func TestStoreAuthFingerprint(t *testing.T) {
	t.Run("stores fingerprint on claimed VM", func(t *testing.T) {
		vm := makeVM("vm-fp", "pool-f", time.Now(), map[string]string{
			"blip.io/session-id": "sess-fp",
		})

		c := newTestClient(t, vm)
		err := c.StoreAuthFingerprint(context.Background(), "sess-fp", "SHA256:newprint")
		require.NoError(t, err)

		// Verify the annotation was persisted.
		var updated kubevirtv1.VirtualMachine
		err = c.writer.Get(context.Background(), client.ObjectKey{
			Namespace: testNamespace,
			Name:      "vm-fp",
		}, &updated)
		require.NoError(t, err)
		assert.Equal(t, "SHA256:newprint", updated.Annotations["blip.io/auth-fingerprint"])
	})

	t.Run("returns error for unknown session", func(t *testing.T) {
		c := newTestClient(t)
		err := c.StoreAuthFingerprint(context.Background(), "no-such-session", "fp")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestGetHostKey(t *testing.T) {
	t.Run("returns host key from annotation", func(t *testing.T) {
		vm := &kubevirtv1.VirtualMachine{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "vm-hk",
				Namespace:       testNamespace,
				Annotations:     map[string]string{"blip.io/host-key": "ssh-ed25519 AAAA..."},
				ResourceVersion: "1",
			},
		}

		c := newTestClient(t, vm)
		key, err := c.GetHostKey(context.Background(), "vm-hk")
		require.NoError(t, err)
		assert.Equal(t, "ssh-ed25519 AAAA...", key)
	})

	t.Run("error when annotation is missing", func(t *testing.T) {
		vm := &kubevirtv1.VirtualMachine{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "vm-nokey",
				Namespace:       testNamespace,
				ResourceVersion: "1",
			},
		}

		c := newTestClient(t, vm)
		_, err := c.GetHostKey(context.Background(), "vm-nokey")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no blip.io/host-key")
	})

	t.Run("error when VM does not exist", func(t *testing.T) {
		c := newTestClient(t)
		_, err := c.GetHostKey(context.Background(), "nonexistent")
		assert.Error(t, err)
	})
}

func TestGetNodeLabel(t *testing.T) {
	tests := []struct {
		name     string
		node     *corev1.Node
		nodeName string
		label    string
		want     string
	}{
		{
			name:     "returns label value",
			node:     makeNode("node-a", map[string]string{"topology.kubernetes.io/zone": "us-east-1a"}),
			nodeName: "node-a",
			label:    "topology.kubernetes.io/zone",
			want:     "us-east-1a",
		},
		{
			name:     "returns empty for missing label",
			node:     makeNode("node-b", map[string]string{}),
			nodeName: "node-b",
			label:    "missing-label",
			want:     "",
		},
		{
			name:     "returns empty for nonexistent node",
			nodeName: "ghost-node",
			label:    "any",
			want:     "",
		},
		{
			name:     "returns empty for empty node name",
			nodeName: "",
			label:    "any",
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var objs []client.Object
			if tt.node != nil {
				objs = append(objs, tt.node)
			}
			c := newTestClient(t, objs...)
			got := c.GetNodeLabel(context.Background(), tt.nodeName, tt.label)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestWeightedOldestIndex(t *testing.T) {
	t.Run("always returns valid index", func(t *testing.T) {
		for _, n := range []int{1, 2, 5, 10, 100} {
			for range 200 {
				idx := weightedOldestIndex(n)
				assert.GreaterOrEqual(t, idx, 0, "n=%d", n)
				assert.Less(t, idx, n, "n=%d", n)
			}
		}
	})

	t.Run("biased toward lower indices", func(t *testing.T) {
		const n = 10
		const trials = 10_000
		counts := make([]int, n)
		for range trials {
			counts[weightedOldestIndex(n)]++
		}
		// The oldest (index 0) should be picked significantly more often
		// than the newest (index 9). With lambda=3, index 0 gets ~25%.
		assert.Greater(t, counts[0], counts[n-1],
			"oldest should be picked more often than newest: %v", counts)
		assert.Greater(t, counts[0], trials/n,
			"oldest should exceed uniform expectation: got %d, uniform=%d", counts[0], trials/n)
	})
}

func TestVmiInstance(t *testing.T) {
	tests := []struct {
		name    string
		vmi     *kubevirtv1.VirtualMachineInstance
		wantErr string
		ready   bool
		ip      string
	}{
		{
			name:  "ready VMI with IP",
			vmi:   makeReadyVMI("test-vm", "10.0.0.1", "node-1"),
			ready: true,
			ip:    "10.0.0.1",
		},
		{
			name: "not ready VMI with IP",
			vmi: &kubevirtv1.VirtualMachineInstance{
				ObjectMeta: metav1.ObjectMeta{Name: "vm-nr"},
				Status: kubevirtv1.VirtualMachineInstanceStatus{
					Conditions: []kubevirtv1.VirtualMachineInstanceCondition{
						{Type: kubevirtv1.VirtualMachineInstanceReady, Status: corev1.ConditionFalse},
					},
					Interfaces: []kubevirtv1.VirtualMachineInstanceNetworkInterface{{IP: "10.0.0.2"}},
				},
			},
			ready: false,
			ip:    "10.0.0.2",
		},
		{
			name: "no interfaces returns error",
			vmi: &kubevirtv1.VirtualMachineInstance{
				ObjectMeta: metav1.ObjectMeta{Name: "vm-noip"},
				Status:     kubevirtv1.VirtualMachineInstanceStatus{},
			},
			wantErr: "no IP address",
		},
		{
			name: "empty IP in interface returns error",
			vmi: &kubevirtv1.VirtualMachineInstance{
				ObjectMeta: metav1.ObjectMeta{Name: "vm-emptyip"},
				Status: kubevirtv1.VirtualMachineInstanceStatus{
					Interfaces: []kubevirtv1.VirtualMachineInstanceNetworkInterface{{IP: ""}},
				},
			},
			wantErr: "no IP address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inst, err := vmiInstance(tt.vmi)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.ready, inst.Ready)
			assert.Equal(t, tt.ip, inst.PodIP)
		})
	}
}

func TestSetClaimAnnotations(t *testing.T) {
	t.Run("sets all expected annotations including ephemeral", func(t *testing.T) {
		a := &allocation{}
		setClaimAnnotations(a, "sess-123", "gw-pod-1", 7200, "alice@example.com")

		assert.Equal(t, "sess-123", a.Annotations["blip.io/session-id"])
		assert.Equal(t, "gw-pod-1", a.Annotations["blip.io/claimed-by"])
		assert.Equal(t, "7200", a.Annotations["blip.io/max-duration"])
		assert.Equal(t, "alice@example.com", a.Annotations["blip.io/user"])
		assert.Equal(t, "true", a.Annotations["blip.io/ephemeral"])

		// claimed-at should be a valid RFC3339 timestamp.
		_, err := time.Parse(time.RFC3339, a.Annotations["blip.io/claimed-at"])
		assert.NoError(t, err)
	})

	t.Run("omits user annotation when empty", func(t *testing.T) {
		a := &allocation{}
		setClaimAnnotations(a, "sess-456", "gw-pod-2", 300, "")

		assert.Equal(t, "sess-456", a.Annotations["blip.io/session-id"])
		_, hasUser := a.Annotations["blip.io/user"]
		assert.False(t, hasUser)
		assert.Equal(t, "true", a.Annotations["blip.io/ephemeral"])
	})
}

func TestAllocationFromObject(t *testing.T) {
	t.Run("clones annotations to avoid mutation", func(t *testing.T) {
		vm := makeVM("vm-clone", "pool-cl", time.Now(), map[string]string{"key": "val"})
		alloc := allocationFromObject(vm)

		// Mutating the allocation should not change the original.
		alloc.Annotations["key"] = "changed"
		assert.Equal(t, "val", vm.Annotations["key"])
	})
}

func TestNewScheme(t *testing.T) {
	t.Run("registers core and kubevirt types", func(t *testing.T) {
		s, err := newScheme()
		require.NoError(t, err)

		// Verify core types are registered.
		assert.True(t, s.IsGroupRegistered(""), "core group should be registered")

		// Verify kubevirt types are registered.
		assert.True(t, s.IsGroupRegistered(kubevirtv1.SchemeGroupVersion.Group),
			"kubevirt group should be registered")
	})
}

func TestNewStaticRESTMapper(t *testing.T) {
	t.Run("maps expected resources", func(t *testing.T) {
		mapper := newStaticRESTMapper()

		tests := []struct {
			gvk        schema.GroupVersionKind
			wantPlural string
		}{
			{
				gvk:        schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"},
				wantPlural: "pods",
			},
			{
				gvk:        schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Node"},
				wantPlural: "nodes",
			},
			{
				gvk:        kubevirtv1.VirtualMachineGroupVersionKind,
				wantPlural: "virtualmachines",
			},
			{
				gvk: schema.GroupVersionKind{
					Group:   kubevirtv1.SchemeGroupVersion.Group,
					Version: kubevirtv1.SchemeGroupVersion.Version,
					Kind:    "VirtualMachineInstance",
				},
				wantPlural: "virtualmachineinstances",
			},
		}

		for _, tt := range tests {
			t.Run(tt.gvk.Kind, func(t *testing.T) {
				mapping, err := mapper.RESTMapping(tt.gvk.GroupKind(), tt.gvk.Version)
				require.NoError(t, err)
				assert.Equal(t, tt.wantPlural, mapping.Resource.Resource)
			})
		}
	})
}

func TestClaimEndToEnd(t *testing.T) {
	t.Run("claim then reconnect full lifecycle", func(t *testing.T) {
		now := time.Now()
		vm := makeVM("vm-e2e", "pool-e2e", now, nil)
		vmi := makeReadyVMI("vm-e2e", "10.0.0.99", "node-e2e")

		c := newTestClient(t, vm, vmi)

		// Step 1: Claim the VM.
		result, err := c.Claim(context.Background(), "pool-e2e", "sess-e2e", "gw-e2e", 3600, "user-e2e", 5)
		require.NoError(t, err)
		assert.Equal(t, "vm-e2e", result.Name)
		assert.Equal(t, "10.0.0.99", result.PodIP)

		// Step 2: Store auth fingerprint.
		err = c.StoreAuthFingerprint(context.Background(), "sess-e2e", "SHA256:e2efp")
		require.NoError(t, err)

		// Step 3: Reconnect with correct fingerprint.
		result2, err := c.Reconnect(context.Background(), "sess-e2e", "SHA256:e2efp", "gw-new", 3600)
		require.NoError(t, err)
		assert.Equal(t, "vm-e2e", result2.Name)
		assert.Equal(t, "10.0.0.99", result2.PodIP)

		// Step 4: Reconnect with wrong fingerprint fails.
		_, err = c.Reconnect(context.Background(), "sess-e2e", "SHA256:wrong", "gw-new", 3600)
		assert.ErrorIs(t, err, errSessionAuthMismatch)
	})

	t.Run("claim with quota allows up to limit then blocks", func(t *testing.T) {
		now := time.Now()
		vm1 := makeVM("vm-q1", "pool-quota", now, nil)
		vm2 := makeVM("vm-q2", "pool-quota", now, nil)
		vmi1 := makeReadyVMI("vm-q1", "10.0.1.1", "node-1")
		vmi2 := makeReadyVMI("vm-q2", "10.0.1.2", "node-2")

		c := newTestClient(t, vm1, vm2, vmi1, vmi2)

		// First claim succeeds (1/2 quota).
		_, err := c.Claim(context.Background(), "pool-quota", "s1", "gw", 3600, "quotauser", 2)
		require.NoError(t, err)

		// Second claim succeeds (2/2 quota).
		_, err = c.Claim(context.Background(), "pool-quota", "s2", "gw", 3600, "quotauser", 2)
		require.NoError(t, err)

		// Third claim blocked by quota.
		_, err = c.Claim(context.Background(), "pool-quota", "s3", "gw", 3600, "quotauser", 2)
		assert.ErrorIs(t, err, ErrQuotaExceeded)
	})
}

// ---------------------------------------------------------------------------
// ReleaseVM
// ---------------------------------------------------------------------------

func TestReleaseVM(t *testing.T) {
	t.Run("sets release annotation on VM", func(t *testing.T) {
		vm := makeVM("vm-rel", "pool-r", time.Now(), map[string]string{
			"blip.io/session-id": "sess-rel",
			"blip.io/ephemeral":  "true",
		})

		c := newTestClient(t, vm)
		err := c.ReleaseVM(context.Background(), "sess-rel")
		require.NoError(t, err)

		// Verify the release annotation was set.
		var updated kubevirtv1.VirtualMachine
		err = c.writer.Get(context.Background(), client.ObjectKey{
			Namespace: testNamespace,
			Name:      "vm-rel",
		}, &updated)
		require.NoError(t, err)
		assert.Equal(t, "true", updated.Annotations["blip.io/release"])
	})

	t.Run("returns error for unknown session", func(t *testing.T) {
		c := newTestClient(t)
		err := c.ReleaseVM(context.Background(), "nonexistent")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

// ---------------------------------------------------------------------------
// IsEphemeral
// ---------------------------------------------------------------------------

func TestIsEphemeral(t *testing.T) {
	t.Run("returns true for ephemeral VM", func(t *testing.T) {
		vm := makeVM("vm-eph", "pool-e", time.Now(), map[string]string{
			"blip.io/session-id": "sess-eph",
			"blip.io/ephemeral":  "true",
		})

		c := newTestClient(t, vm)
		eph, err := c.IsEphemeral(context.Background(), "sess-eph")
		require.NoError(t, err)
		assert.True(t, eph)
	})

	t.Run("returns false for retained VM", func(t *testing.T) {
		vm := makeVM("vm-ret", "pool-e", time.Now(), map[string]string{
			"blip.io/session-id": "sess-ret",
			"blip.io/ephemeral":  "false",
		})

		c := newTestClient(t, vm)
		eph, err := c.IsEphemeral(context.Background(), "sess-ret")
		require.NoError(t, err)
		assert.False(t, eph)
	})

	t.Run("returns false when annotation is missing", func(t *testing.T) {
		vm := makeVM("vm-noeph", "pool-e", time.Now(), map[string]string{
			"blip.io/session-id": "sess-noeph",
		})

		c := newTestClient(t, vm)
		eph, err := c.IsEphemeral(context.Background(), "sess-noeph")
		require.NoError(t, err)
		assert.False(t, eph)
	})

	t.Run("returns error for unknown session", func(t *testing.T) {
		c := newTestClient(t)
		_, err := c.IsEphemeral(context.Background(), "nonexistent")
		assert.Error(t, err)
	})
}

// ---------------------------------------------------------------------------
// Retain
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// StoreSSHPublicKey
// ---------------------------------------------------------------------------

func TestStoreSSHPublicKey(t *testing.T) {
	t.Run("stores fingerprint on claimed VM", func(t *testing.T) {
		vm := makeVM("vm-sshpk", "pool-s", time.Now(), map[string]string{
			"blip.io/session-id": "sess-sshpk",
		})

		c := newTestClient(t, vm)
		err := c.StoreSSHPublicKey(context.Background(), "sess-sshpk", "SHA256:vmfp123")
		require.NoError(t, err)

		// Verify the annotation was persisted.
		var updated kubevirtv1.VirtualMachine
		err = c.writer.Get(context.Background(), client.ObjectKey{
			Namespace: testNamespace,
			Name:      "vm-sshpk",
		}, &updated)
		require.NoError(t, err)
		assert.Equal(t, "SHA256:vmfp123", updated.Annotations["blip.io/ssh-public-key"])
	})

	t.Run("returns error for unknown session", func(t *testing.T) {
		c := newTestClient(t)
		err := c.StoreSSHPublicKey(context.Background(), "no-such-session", "fp")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

// ---------------------------------------------------------------------------
// ResolveRootIdentity
// ---------------------------------------------------------------------------

func TestResolveRootIdentity(t *testing.T) {
	t.Run("resolves root identity from SSH public key fingerprint", func(t *testing.T) {
		vm := makeVM("vm-resolve", "pool-res", time.Now(), map[string]string{
			"blip.io/session-id":     "sess-resolve",
			"blip.io/user":           "alice@example.com",
			"blip.io/ssh-public-key": "SHA256:vmkey123",
		})

		c := newTestClient(t, vm)
		identity, err := c.ResolveRootIdentity(context.Background(), "SHA256:vmkey123")
		require.NoError(t, err)
		assert.Equal(t, "alice@example.com", identity)
	})

	t.Run("returns error for unknown fingerprint", func(t *testing.T) {
		c := newTestClient(t)
		_, err := c.ResolveRootIdentity(context.Background(), "SHA256:unknown")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no VM found")
	})

	t.Run("returns error when VM has no user annotation", func(t *testing.T) {
		vm := makeVM("vm-nouser", "pool-res", time.Now(), map[string]string{
			"blip.io/session-id":     "sess-nouser",
			"blip.io/ssh-public-key": "SHA256:nouser",
		})
		// Remove the user annotation that makeVM doesn't set by default.
		delete(vm.Annotations, "blip.io/user")

		c := newTestClient(t, vm)
		_, err := c.ResolveRootIdentity(context.Background(), "SHA256:nouser")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no blip.io/user annotation")
	})

	t.Run("resolves identity for recursive blip (user was set to root)", func(t *testing.T) {
		// Simulate a recursive blip: the inner VM's user annotation points to
		// the root user (not another blip-vm identity), because the session
		// manager resolves the root identity before claiming.
		innerVM := makeVM("vm-inner", "pool-res", time.Now(), map[string]string{
			"blip.io/session-id":     "sess-inner",
			"blip.io/user":           "root-user@corp.com",
			"blip.io/ssh-public-key": "SHA256:innerkey",
		})

		c := newTestClient(t, innerVM)
		identity, err := c.ResolveRootIdentity(context.Background(), "SHA256:innerkey")
		require.NoError(t, err)
		assert.Equal(t, "root-user@corp.com", identity)
	})
}

// ---------------------------------------------------------------------------
// Retain
// ---------------------------------------------------------------------------

func TestRetain(t *testing.T) {
	t.Run("marks VM as non-ephemeral", func(t *testing.T) {
		vm := makeVM("vm-retain", "pool-rt", time.Now(), map[string]string{
			"blip.io/session-id":   "sess-retain",
			"blip.io/ephemeral":    "true",
			"blip.io/claimed-at":   time.Now().Format(time.RFC3339),
			"blip.io/max-duration": "28800",
		})

		c := newTestClient(t, vm)
		sid, err := c.Retain(context.Background(), "sess-retain", 0)
		require.NoError(t, err)
		assert.Equal(t, "sess-retain", sid)

		// Verify ephemeral is now false.
		var updated kubevirtv1.VirtualMachine
		err = c.writer.Get(context.Background(), client.ObjectKey{
			Namespace: testNamespace,
			Name:      "vm-retain",
		}, &updated)
		require.NoError(t, err)
		assert.Equal(t, "false", updated.Annotations["blip.io/ephemeral"])
		// max-duration should be unchanged since newTTLSeconds=0.
		assert.Equal(t, "28800", updated.Annotations["blip.io/max-duration"])
	})

	t.Run("updates TTL when specified", func(t *testing.T) {
		claimedAt := time.Now().Add(-1 * time.Hour)
		vm := makeVM("vm-ttl", "pool-rt", time.Now(), map[string]string{
			"blip.io/session-id":   "sess-ttl",
			"blip.io/ephemeral":    "true",
			"blip.io/claimed-at":   claimedAt.Format(time.RFC3339),
			"blip.io/max-duration": "28800",
		})

		c := newTestClient(t, vm)
		// Request 2 hours (7200s) TTL update.
		sid, err := c.Retain(context.Background(), "sess-ttl", 7200)
		require.NoError(t, err)
		assert.Equal(t, "sess-ttl", sid)

		var updated kubevirtv1.VirtualMachine
		err = c.writer.Get(context.Background(), client.ObjectKey{
			Namespace: testNamespace,
			Name:      "vm-ttl",
		}, &updated)
		require.NoError(t, err)
		assert.Equal(t, "false", updated.Annotations["blip.io/ephemeral"])
		assert.Equal(t, "7200", updated.Annotations["blip.io/max-duration"])
	})

	t.Run("caps TTL at MaxLifespan", func(t *testing.T) {
		// VM claimed 11 hours ago. Requesting 3 hours TTL should be capped
		// to ~1 hour remaining budget.
		claimedAt := time.Now().Add(-11 * time.Hour)
		vm := makeVM("vm-cap", "pool-rt", time.Now(), map[string]string{
			"blip.io/session-id":   "sess-cap",
			"blip.io/ephemeral":    "true",
			"blip.io/claimed-at":   claimedAt.Format(time.RFC3339),
			"blip.io/max-duration": "28800",
		})

		c := newTestClient(t, vm)
		sid, err := c.Retain(context.Background(), "sess-cap", 3*3600) // 3 hours
		require.NoError(t, err)
		assert.Equal(t, "sess-cap", sid)

		var updated kubevirtv1.VirtualMachine
		err = c.writer.Get(context.Background(), client.ObjectKey{
			Namespace: testNamespace,
			Name:      "vm-cap",
		}, &updated)
		require.NoError(t, err)

		// The max-duration should be capped: 12h - 11h = 1h = 3600s (approximately).
		maxDur, parseErr := strconv.Atoi(updated.Annotations["blip.io/max-duration"])
		require.NoError(t, parseErr)
		// Should be roughly 3600 (±60s for test timing).
		assert.InDelta(t, 3600, maxDur, 60, "TTL should be capped to remaining lifespan budget")
	})

	t.Run("returns error for unknown session", func(t *testing.T) {
		c := newTestClient(t)
		_, err := c.Retain(context.Background(), "nonexistent", 0)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}
