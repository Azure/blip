package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// configMapKeyLimit is the maximum ConfigMap key length enforced by the API
// server.
const configMapKeyLimit = 253

// longDNSName returns a valid DNS-subdomain name of exactly n characters.
func longDNSName(n int) string {
	var s string
	for len(s) < n {
		if s != "" {
			s += "."
		}
		label := min(63, n-len(s))
		s += strings.Repeat("a", label)
	}
	return s
}

// configMapKeyLimitClient rejects ConfigMap writes with keys the API server
// would reject. The fake client accepts them, so this wrapper keeps the
// regression honest; the real server rejects the whole patch.
type configMapKeyLimitClient struct{ client.Client }

func (c configMapKeyLimitClient) check(obj client.Object, p client.Patch) error {
	cm, ok := obj.(*corev1.ConfigMap)
	if !ok {
		return nil
	}
	var keys []string
	if p == nil {
		for k := range cm.Data {
			keys = append(keys, k)
		}
	} else {
		raw, err := p.Data(obj)
		if err != nil {
			return err
		}
		var body struct {
			Data map[string]json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			return nil
		}
		for k := range body.Data {
			keys = append(keys, k)
		}
	}
	for _, k := range keys {
		if errs := validation.IsConfigMapKey(k); len(errs) > 0 {
			return fmt.Errorf("ConfigMap %q is invalid: metadata.data: %s", cm.Name, strings.Join(errs, "; "))
		}
	}
	return nil
}

func (c configMapKeyLimitClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if err := c.check(obj, nil); err != nil {
		return err
	}
	return c.Client.Create(ctx, obj, opts...)
}

func (c configMapKeyLimitClient) Patch(ctx context.Context, obj client.Object, p client.Patch, opts ...client.PatchOption) error {
	if err := c.check(obj, p); err != nil {
		return err
	}
	return c.Client.Patch(ctx, obj, p, opts...)
}

func newLongSAPool(t *testing.T, sa string) *env {
	t.Helper()
	e := newEnv(t)
	e.addNodes("n1")
	e.create(&v1.BlipPool{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: v1.BlipPoolSpec{
			Hypervisor: "kvm", CPUs: 2, Memory: resource.MustParse("2Gi"),
			WarmCount: 1, ServiceAccountName: sa,
			NodeSelector: map[string]string{"blip.dev/node-pool": "default"},
		},
	})
	return e
}

// A legal 247-character BlipThread name used to make the whole owner-table
// patch invalid: syncVMOwners returned at the first pool reconcile, so every
// pool in the namespace stopped creating or replacing VMs. The hashed thread
// label must still be published and the pool must keep reconciling.
func TestVMOwnersLongThreadNameDoesNotWedgePool(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 1, 0)
	e.run(e.pool, ns, "default")
	if got := len(e.pods()); got != 1 {
		t.Fatalf("warm pods = %d, want 1", got)
	}

	long := longDNSName(247)
	if len(long+"thread.") <= configMapKeyLimit {
		t.Fatalf("test thread name %q does not exceed the key limit", long)
	}
	e.create(&v1.BlipThread{
		ObjectMeta: metav1.ObjectMeta{Name: long},
		Spec:       v1.BlipThreadSpec{Pool: "default"},
	})

	limit := configMapKeyLimitClient{Client: e.c}
	recorder := record.NewFakeRecorder(8)
	e.pool.Client = limit
	e.pool.Recorder = recorder

	// Before the fix this returns "not a valid key name for a ConfigMap".
	e.must(syncVMOwnersEvents(e.ctx, limit, ns, recorder))

	owner := v1.ThreadOwner(ns, long)
	owners := e.owners()
	if got := owners[ownersThreadHashPrefix+v1.ThreadLabel(long)]; got != owner {
		t.Errorf("hashed thread owner key = %q, want %q", got, owner)
	}
	if _, ok := owners["thread."+long]; ok {
		t.Errorf("table recorded over-long raw thread key for %q", long)
	}
	select {
	case event := <-recorder.Events:
		if !strings.Contains(event, "OwnerTableKeyUnrepresentable") {
			t.Errorf("event = %q, want OwnerTableKeyUnrepresentable", event)
		}
	default:
		t.Error("no event for the unrepresentable thread name")
	}

	// Replacing a warm VM must still work while the long thread exists.
	pods := e.pods()
	e.must(e.c.Delete(e.ctx, &pods[0]))
	// Let the pool's create expectation for the deleted warm pod expire, as
	// the cache would when its watch reports the deletion.
	e.now = e.now.Add(expectTimeout + time.Second)
	e.run(e.pool, ns, "default")
	if got := len(e.pods()); got != 1 {
		t.Fatalf("pool did not replace its warm VM: pods = %d", got)
	}
}

// An over-long or syntactically invalid service account name has the same
// effect through the "sa.<name>" key. The pool must keep reconciling, and the
// claim path must still write the pod's owner entry so the VM stays restricted.
func TestVMOwnersUnrepresentableServiceAccountDoesNotWedgePool(t *testing.T) {
	for _, tc := range []struct{ name, sa string }{
		{"long", longDNSName(251)},
		{"invalid characters", "bad/name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if errs := validation.IsConfigMapKey(ownersSAPrefix + tc.sa); len(errs) == 0 {
				t.Fatalf("%q is representable in the owner table", tc.sa)
			}
			e := newLongSAPool(t, tc.sa)
			limit := configMapKeyLimitClient{Client: e.c}
			recorder := record.NewFakeRecorder(8)
			e.pool.Client = limit
			e.pool.Recorder = recorder

			e.must(syncVMOwnersEvents(e.ctx, limit, ns, recorder))
			if _, ok := e.owners()["sa."+tc.sa]; ok {
				t.Errorf("table recorded unrepresentable service account key for %q", tc.sa)
			}
			select {
			case event := <-recorder.Events:
				if !strings.Contains(event, "OwnerTableKeyUnrepresentable") {
					t.Errorf("event = %q, want OwnerTableKeyUnrepresentable", event)
				}
			default:
				t.Error("no event for the unrepresentable service account name")
			}

			e.run(e.pool, ns, "default")
			if got := len(e.pods()); got != 1 {
				t.Fatalf("pool did not create its warm VM: pods = %d", got)
			}

			// A claim still records the pod owner, the entry that restricts
			// the VM.
			p := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "claimed", Namespace: ns},
				Spec:       corev1.PodSpec{ServiceAccountName: tc.sa},
			}
			b := &v1.Blip{
				ObjectMeta: metav1.ObjectMeta{Name: testOwner + ".a", Namespace: ns,
					Labels: map[string]string{v1.LabelOwner: testOwner}},
			}
			e.must(setVMOwner(e.ctx, limit, p, b))
			if got := e.owners()["claimed"]; got != testOwner {
				t.Errorf("claimed pod owner entry = %q, want %q", got, testOwner)
			}
		})
	}
}
