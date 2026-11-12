package controller

import (
	"context"
	"sync"
	"testing"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/example/blip/internal/api"
	v1 "github.com/example/blip/internal/api/v1alpha1"
	"github.com/example/blip/internal/proto/nodepb"
	"github.com/example/blip/internal/testing/fakenode"
)

// shortTTL holds namespaces whose tokens the test minter reports as
// expiring after a few seconds, to exercise rotation.
var shortTTL sync.Map

// testMinter mints real tokens (TokenRequest against envtest) and can
// shorten their reported lifetime.
type testMinter struct{ real TokenMinter }

func (m testMinter) Mint(ctx context.Context, ns, sa string, bound *authv1.BoundObjectReference) (string, time.Time, error) {
	tok, exp, err := m.real.Mint(ctx, ns, sa, bound)
	if err == nil {
		if _, ok := shortTTL.Load(ns); ok {
			exp = time.Now().Add(2 * time.Second)
		}
	}
	return tok, exp, err
}

func TestSlotsFromOwnNamespace(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	other := ns + "-o"
	if err := env.k.Create(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: other}}); err != nil {
		t.Fatal(err)
	}
	// A free slot of the SKU in another namespace is never used.
	pool(t, other, "ownns", "s1")
	emptyVol(t, ns, "ws")
	newBlip(t, ns, "b", "ws", "ownns", nil)
	waitBlip(t, ns, "b", 10*time.Second, func(b *v1.Blip) bool {
		return condReason(b.Status.Conditions, api.CondScheduled) == api.ReasonUnknownSKU
	})
	time.Sleep(time.Second)
	if b := getBlip(ns, "b"); b.Status.Allocation != nil {
		t.Fatalf("allocated from another namespace: %+v", b.Status.Allocation)
	}
	p := slot(t, ns, "ownns", "s2")
	b := complete(t, ns, "b")
	if b.Status.Allocation.PodName != p.Name || b.Status.Allocation.Node != "s2" {
		t.Fatalf("allocation %+v, want pod %s", b.Status.Allocation, p.Name)
	}
	eventually(t, 10*time.Second, "pod deleted", func() bool { return podGone(ns, p.Name) })
}

func TestServiceAccountNotFound(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	pool(t, ns, "sa", "s3")
	emptyVol(t, ns, "ws")
	newBlip(t, ns, "b", "ws", "sa", func(b *v1.Blip) { b.Spec.ServiceAccountName = "builder" })
	waitBlip(t, ns, "b", 10*time.Second, func(b *v1.Blip) bool {
		return condReason(b.Status.Conditions, api.CondScheduled) == api.ReasonServiceAccountNotFound && b.Status.Allocation == nil
	})
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "builder"}}
	if err := env.k.Create(context.Background(), sa); err != nil {
		t.Fatal(err)
	}
	complete(t, ns, "b")
}

func TestCredentialsAndRotation(t *testing.T) {
	skipNoEnv(t)
	ns := newNS(t, nil)
	shortTTL.Store(ns, true)
	defer shortTTL.Delete(ns)
	pool(t, ns, "creds", "s1")
	emptyVol(t, ns, "ws")
	setWork(ns, "b", fakenode.Hang())
	newBlip(t, ns, "b", "ws", "creds", func(b *v1.Blip) {
		b.Spec.Init = []string{"/sbin/init", "quiet"}
		b.Spec.Ports = []v1.BlipPort{{Port: 22, Name: "ssh"}}
	})
	b := waitBlip(t, ns, "b", 20*time.Second, func(b *v1.Blip) bool { return isTrue(b.Status.Conditions, api.CondStarted) })
	id := b.Status.Allocation.ID
	s1 := env.nodes["s1"]
	var start *nodepb.StartWorkload
	var assign *nodepb.AssignSlot
	for _, c := range s1.Commands() {
		if s := c.GetStartWorkload(); s != nil && s.AllocationId == id {
			start = s
		}
		if a := c.GetAssignSlot(); a != nil && a.AllocationId == id {
			assign = a
		}
	}
	if assign == nil || assign.Pod.GetNamespace() != ns || len(assign.Ports) != 1 || assign.Ports[0] != 22 {
		t.Fatalf("assign %+v", assign)
	}
	cr := start.GetCredentials()
	if cr == nil || len(cr.Token) == 0 || len(cr.CaCrt) == 0 || cr.Namespace != ns || cr.Expiration == nil {
		t.Fatalf("credentials %+v", cr)
	}
	if len(start.Params.Init) != 2 {
		t.Fatalf("params %+v", start.Params)
	}
	// The token lives 2s here: an update follows within ~1.6s.
	var upd *nodepb.UpdateCredentials
	eventually(t, 10*time.Second, "UpdateCredentials", func() bool {
		for _, c := range s1.Commands() {
			if u := c.GetUpdateCredentials(); u != nil && u.AllocationId == id {
				upd = u
				return true
			}
		}
		return false
	})
	if len(upd.Credentials.GetToken()) == 0 || upd.Credentials.Namespace != ns {
		t.Fatalf("update %+v", upd)
	}
	// Tokens are bound to the allocation's Secret.
	var sec corev1.Secret
	if err := env.k.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: "blip-token-" + id}, &sec); err != nil {
		t.Fatal(err)
	}
	if sec.Labels[api.LabelAllocation] != id || sec.Labels[api.LabelName] != "b" || len(sec.OwnerReferences) != 1 || sec.OwnerReferences[0].UID != b.UID {
		t.Fatalf("binding secret %+v", sec.ObjectMeta)
	}
	if !tokenValid(t, cr.Token) || !tokenValid(t, upd.Credentials.Token) {
		t.Fatal("token not valid while running")
	}
	if err := env.k.Delete(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	// Releasing the allocation revokes its tokens at once.
	eventually(t, 30*time.Second, "binding secret deleted", func() bool {
		err := env.k.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: sec.Name}, &corev1.Secret{})
		return apierrors.IsNotFound(err)
	})
	eventually(t, 10*time.Second, "token revoked", func() bool { return !tokenValid(t, cr.Token) && !tokenValid(t, upd.Credentials.Token) })
	eventually(t, 30*time.Second, "blip gone", func() bool { return getBlip(ns, "b") == nil })
}

// tokenValid reports whether the API server accepts a token.
func tokenValid(t *testing.T, tok []byte) bool {
	t.Helper()
	tr := &authv1.TokenReview{Spec: authv1.TokenReviewSpec{Token: string(tok)}}
	if err := env.k.Create(context.Background(), tr); err != nil {
		t.Fatal(err)
	}
	return tr.Status.Authenticated
}
