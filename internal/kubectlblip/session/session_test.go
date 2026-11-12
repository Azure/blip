package session

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/example/blip/internal/api"
	"github.com/example/blip/internal/api/v1alpha1"
)

const hostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ root@guest"

func TestValidateName(t *testing.T) {
	for _, n := range []string{"a", "dev-1", strings.Repeat("a", 57)} {
		if err := ValidateName(n); err != nil {
			t.Errorf("%q: %v", n, err)
		}
	}
	for _, n := range []string{"", "A", "a.b", "-a", strings.Repeat("a", 58)} {
		if err := ValidateName(n); err == nil {
			t.Errorf("%q accepted", n)
		}
	}
}

func TestBuildBlip(t *testing.T) {
	b, err := BuildBlip(Spec{Namespace: "ns", Name: "dev", Volume: "ubuntu", SKU: "big", TTL: 2 * time.Hour, AuthorizedKeys: "ssh-ed25519 K u", Owner: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if !IsSession(b) || b.Annotations[api.AnnotationSSHAuthorizedKeys] != "ssh-ed25519 K u" || b.Annotations[api.AnnotationSessionOwner] != "alice" {
		t.Fatalf("meta %+v", b.ObjectMeta)
	}
	s := b.Spec
	if s.SKU != "big" || s.MaxTTLSeconds != 7200 || s.ServiceAccountName != "blip-ssh" || s.RootVolume != "root" ||
		len(s.Volumes) != 1 || s.Volumes[0].Name != "root" || s.Volumes[0].BlipVolRef.Name != "ubuntu" ||
		len(s.Ports) != 1 || s.Ports[0].Port != 22 || s.Ports[0].Name != "ssh" {
		t.Fatalf("spec %+v", s)
	}
	if b, _ = BuildBlip(Spec{Name: "dev", Volume: "v", RootClone: "dev-abcde", TTL: time.Hour}); b.Spec.Volumes[0].BlipVolRef.Name != "dev-abcde" {
		t.Fatal(b.Spec.Volumes)
	}
	b, _ = BuildBlip(Spec{Name: "dev", Volume: "v", TTL: time.Hour})
	if _, ok := b.Annotations[api.AnnotationSessionOwner]; ok {
		t.Fatal("empty owner annotated")
	}
	if _, err := BuildBlip(Spec{Name: "dev", Volume: "v", TTL: 8 * 24 * time.Hour}); err == nil {
		t.Fatal("ttl too long accepted")
	}
	if _, err := BuildBlip(Spec{Name: "Dev", Volume: "v", TTL: time.Hour}); err == nil {
		t.Fatal("bad name accepted")
	}
}

func TestImageVolume(t *testing.T) {
	v := BuildImageVolume("ns", "reg/ubuntu@sha256:abc")
	if v.Name != ImageVolumeName("reg/ubuntu@sha256:abc") || !strings.HasPrefix(v.Name, "img-") || len(v.Name) != 16 {
		t.Fatal(v.Name)
	}
	if v.Spec.Image.Reference != "reg/ubuntu@sha256:abc" || v.Namespace != "ns" {
		t.Fatalf("%+v", v)
	}
	if ImageVolumeName("a") == ImageVolumeName("b") {
		t.Fatal("collision")
	}
}

func TestSSHArgs(t *testing.T) {
	got := strings.Join(SSHArgs("kb proxy %n", "/k", "/my dir/kh", "blip-n", []string{"uname", "-a"}), " ")
	want := `-o ProxyCommand=kb proxy %n -o User=root -o IdentityFile=/k -o IdentitiesOnly=yes -o UserKnownHostsFile="/my dir/kh" -o StrictHostKeyChecking=yes blip-n uname -a`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if SessionFromHost("blip-dev") != "dev" || SessionFromHost("dev") != "dev" {
		t.Fatal("alias")
	}
	if p := ProxyCommand(`"/a b/kubectl-blip"`, []string{"-n", "x y"}); p != `"/a b/kubectl-blip" proxy -n "x y" %n` {
		t.Fatal(p)
	}
	cfg := SSHConfig("kubectl blip", "/h/.blip/id_ed25519", "/h/my dir/known_hosts", []string{"--context", "kind"})
	for _, s := range []string{"Host blip-*", "ProxyCommand kubectl blip proxy --context kind %n", `UserKnownHostsFile "/h/my dir/known_hosts"`, "User root", "IdentityFile /h/.blip/id_ed25519"} {
		if !strings.Contains(cfg, s) {
			t.Errorf("missing %q in\n%s", s, cfg)
		}
	}
}

func newClient(objs ...client.Object) (*Client, client.WithWatch) {
	c := fake.NewClientBuilder().WithScheme(Scheme()).WithObjects(objs...).WithStatusSubresource(&v1alpha1.Blip{}, &v1alpha1.BlipVol{}).Build()
	return &Client{C: c, Poll: 5 * time.Millisecond}, c
}

func TestWaitReady(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	b := &v1alpha1.Blip{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "dev"}}
	c, raw := newClient(b)
	var logs bytes.Buffer
	c.Log = func(f string, a ...any) { logs.WriteString(strings.TrimSpace(strings.ReplaceAll(f, "%", "")) + "\n") }
	go func() {
		time.Sleep(20 * time.Millisecond)
		cur := &v1alpha1.Blip{}
		_ = raw.Get(ctx, client.ObjectKeyFromObject(b), cur)
		cur.Status.Phase = v1alpha1.BlipRunning
		cur.Status.Allocation = &v1alpha1.Allocation{ID: "x", PodName: "slot-1"}
		_ = raw.Status().Update(ctx, cur)
		time.Sleep(20 * time.Millisecond)
		_ = raw.Get(ctx, client.ObjectKeyFromObject(b), cur)
		cur.Annotations = map[string]string{api.AnnotationSSHHostKey: hostKey + "\n"}
		_ = raw.Update(ctx, cur)
	}()
	_, pod, hk, err := c.WaitReady(ctx, "ns", "dev")
	if err != nil || pod != "slot-1" || hk != hostKey {
		t.Fatal(pod, hk, err)
	}
}

func TestWaitReadyFailures(t *testing.T) {
	failed := &v1alpha1.Blip{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "f"}, Status: v1alpha1.BlipStatus{Phase: v1alpha1.BlipFailed, Message: "boom"}}
	sa := &v1alpha1.Blip{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "sa"}, Status: v1alpha1.BlipStatus{
		Phase:      v1alpha1.BlipPending,
		Conditions: []metav1.Condition{{Type: api.CondScheduled, Status: metav1.ConditionFalse, Reason: api.ReasonServiceAccountNotFound}},
	}}
	c, _ := newClient(failed, sa)
	ctx := context.Background()
	if _, _, _, err := c.WaitReady(ctx, "ns", "f"); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatal(err)
	}
	if _, _, _, err := c.WaitReady(ctx, "ns", "missing"); err == nil {
		t.Fatal("missing blip")
	}
	tctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if _, _, _, err := c.WaitReady(tctx, "ns", "sa"); !errors.Is(err, ErrServiceAccountNotFound) {
		t.Fatal(err)
	}
}

func TestEnsureImageVolume(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, raw := newClient()
	go func() {
		v := &v1alpha1.BlipVol{}
		for raw.Get(ctx, client.ObjectKey{Namespace: "ns", Name: ImageVolumeName("r/i:1")}, v) != nil {
			time.Sleep(5 * time.Millisecond)
		}
		v.Status.Conditions = []metav1.Condition{{Type: api.CondReady, Status: metav1.ConditionTrue, Reason: "Ready", LastTransitionTime: metav1.Now()}}
		_ = raw.Status().Update(ctx, v)
	}()
	name, err := c.EnsureImageVolume(ctx, "ns", "r/i:1")
	if err != nil || name != ImageVolumeName("r/i:1") {
		t.Fatal(name, err)
	}
	// Idempotent once Ready.
	if _, err := c.EnsureImageVolume(ctx, "ns", "r/i:1"); err != nil {
		t.Fatal(err)
	}
}

func TestListAndCreate(t *testing.T) {
	ctx := context.Background()
	other := &v1alpha1.Blip{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "other"}}
	c, _ := newClient(other)
	if _, err := c.Create(ctx, Spec{Namespace: "ns", Name: "dev", Volume: "v", SKU: "default", TTL: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Create(ctx, Spec{Namespace: "ns2", Name: "dev", Volume: "v", SKU: "default", TTL: time.Hour}); err != nil {
		t.Fatal(err)
	}
	l, err := c.List(ctx, "ns")
	if err != nil || len(l) != 1 || l[0].Name != "dev" {
		t.Fatal(l, err)
	}
	root := l[0].Spec.Volumes[0].BlipVolRef.Name
	if !strings.HasPrefix(root, "dev-") || len(root) != len("dev-")+5 {
		t.Fatal("root clone name", root)
	}
	v := &v1alpha1.BlipVol{}
	if err := c.C.Get(ctx, client.ObjectKey{Namespace: "ns", Name: root}, v); err != nil {
		t.Fatal(err)
	}
	if v.Spec.Parent == nil || v.Spec.Parent.Name != "v" || len(v.OwnerReferences) != 1 ||
		v.OwnerReferences[0].Kind != "Blip" || v.OwnerReferences[0].Name != "dev" || v.OwnerReferences[0].UID != l[0].UID {
		t.Fatalf("root clone %+v", v)
	}
	if l, _ = c.List(ctx, ""); len(l) != 2 {
		t.Fatal(l)
	}
	b, _ := c.Get(ctx, "ns", "dev")
	if err := c.Delete(ctx, b, true); err != nil {
		t.Fatal(err)
	}
	if b, _ = c.Get(ctx, "ns", "dev"); b != nil {
		t.Fatal("not deleted")
	}
}

func TestWhoami(t *testing.T) {
	c, _ := newClient()
	c.C = interceptor.NewClient(c.C, interceptor.Funcs{Create: func(ctx context.Context, cl client.WithWatch, o client.Object, _ ...client.CreateOption) error {
		if r, ok := o.(*authnv1.SelfSubjectReview); ok {
			r.Status.UserInfo.Username = "alice"
			return nil
		}
		return cl.Create(ctx, o)
	}})
	if u := c.Whoami(context.Background()); u != "alice" {
		t.Fatal(u)
	}
}

func TestSetup(t *testing.T) {
	ctx := context.Background()
	stale := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: ServiceAccount}}
	c, raw := newClient(stale)
	var out bytes.Buffer
	if err := c.Setup(ctx, "ns", false, &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != "serviceaccount/blip-ssh created\nrole/blip-ssh configured\nrolebinding/blip-ssh created\n" {
		t.Fatal(out.String())
	}
	r := &rbacv1.Role{}
	_ = raw.Get(ctx, client.ObjectKeyFromObject(stale), r)
	if len(r.Rules) != 1 || r.Rules[0].Verbs[1] != "patch" {
		t.Fatal(r.Rules)
	}
	out.Reset()
	if err := c.Setup(ctx, "ns", false, &out); err != nil {
		t.Fatal(err)
	}
	c.C = interceptor.NewClient(raw, interceptor.Funcs{Create: func(context.Context, client.WithWatch, client.Object, ...client.CreateOption) error {
		return apierrors.NewForbidden(schema.GroupResource{Resource: "serviceaccounts"}, "blip-ssh", errors.New("no"))
	}})
	if err := c.Setup(ctx, "ns", false, &out); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatal(err)
	}
}

func TestPendingReason(t *testing.T) {
	b := &v1alpha1.Blip{Status: v1alpha1.BlipStatus{Phase: v1alpha1.BlipPending, Conditions: []metav1.Condition{
		{Type: api.CondScheduled, Status: metav1.ConditionFalse, Reason: "VolumeInUse", Message: "blipvol x is attached to blip y"},
	}}}
	if got := pendingReason(b); got != "VolumeInUse: blipvol x is attached to blip y" {
		t.Fatal(got)
	}
	b.Status.Phase = v1alpha1.BlipRunning
	if got := pendingReason(b); got != "" {
		t.Fatal(got)
	}
}
