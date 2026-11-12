// Package session implements kubectl-blip sessions: Blips that the plugin
// creates and manages for interactive SSH access. A session is a Blip with
// the label blip.example.com/session=true. It is unrelated to the
// node-controller gRPC session of blipd (internal/node).
package session

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilrand "k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/wait"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sshexample "github.com/example/blip/examples/ssh"
	"github.com/example/blip/internal/api"
	"github.com/example/blip/internal/api/v1alpha1"
)

// Fixed parts of a session Blip, as in examples/ssh.
const (
	ServiceAccount = "blip-ssh"
	SSHPort        = 22
	RootVolume     = "root"
	// HostPrefix is the ssh host name prefix used by ssh-config/proxy.
	HostPrefix = "blip-"
	// MaxTTL is the Blip maxTTLSeconds limit.
	MaxTTL = 604800 * time.Second
)

// Scheme returns a scheme with the types the plugin uses.
func Scheme() *runtime.Scheme {
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, rbacv1.AddToScheme, authnv1.AddToScheme, v1alpha1.AddToScheme} {
		if err := add(s); err != nil {
			panic(err)
		}
	}
	return s
}

// ValidateName checks that name can be a session (Blip) name.
func ValidateName(name string) error {
	if errs := validation.IsDNS1123Label(name); len(errs) > 0 {
		return fmt.Errorf("invalid session name %q: %s", name, strings.Join(errs, "; "))
	}
	if len(name) > api.MaxBlipNameLength {
		return fmt.Errorf("invalid session name %q: at most %d characters", name, api.MaxBlipNameLength)
	}
	return nil
}

// ImageVolumeName is the deterministic BlipVol name for an image reference.
func ImageVolumeName(ref string) string {
	sum := sha256.Sum256([]byte(ref))
	return "img-" + hex.EncodeToString(sum[:])[:12]
}

// IsSession reports whether b carries the session label.
func IsSession(b *v1alpha1.Blip) bool { return b.Labels[api.LabelSession] == "true" }

// Spec describes a new session.
type Spec struct {
	Namespace, Name string
	Volume          string // BlipVol the root volume is cloned from
	RootClone       string // name of the root clone; Create picks one when empty
	SKU             string
	TTL             time.Duration
	AuthorizedKeys  string
	Owner           string
}

// TTLSeconds converts a TTL to maxTTLSeconds, validating the range.
func TTLSeconds(d time.Duration) (int64, error) {
	if d < time.Second || d > MaxTTL {
		return 0, fmt.Errorf("ttl %s out of range [1s, %s]", d, MaxTTL)
	}
	return int64(d / time.Second), nil
}

// BuildBlip returns the session Blip for s.
func BuildBlip(s Spec) (*v1alpha1.Blip, error) {
	if err := ValidateName(s.Name); err != nil {
		return nil, err
	}
	ttl, err := TTLSeconds(s.TTL)
	if err != nil {
		return nil, err
	}
	b := &v1alpha1.Blip{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   s.Namespace,
			Name:        s.Name,
			Labels:      map[string]string{api.LabelSession: "true"},
			Annotations: map[string]string{api.AnnotationSSHAuthorizedKeys: s.AuthorizedKeys},
		},
		Spec: v1alpha1.BlipSpec{
			SKU:                s.SKU,
			ServiceAccountName: ServiceAccount,
			RootVolume:         RootVolume,
			Volumes:            []v1alpha1.BlipVolume{{Name: RootVolume, BlipVolRef: v1alpha1.LocalObjectRef{Name: rootName(s)}}},
			MaxTTLSeconds:      ttl,
			Ports:              []v1alpha1.BlipPort{{Port: SSHPort, Name: "ssh"}},
		},
	}
	if s.Owner != "" {
		b.Annotations[api.AnnotationSessionOwner] = s.Owner
	}
	return b, nil
}

// BuildImageVolume returns the BlipVol importing ref.
func BuildImageVolume(namespace, ref string) *v1alpha1.BlipVol {
	return &v1alpha1.BlipVol{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: ImageVolumeName(ref)},
		Spec:       v1alpha1.BlipVolSpec{Image: &v1alpha1.ImageSource{Reference: ref}},
	}
}

// Logf prints progress messages.
type Logf func(format string, args ...any)

// Client wraps a controller-runtime client.
type Client struct {
	C   client.WithWatch
	Log Logf
	// Poll is the polling interval of the wait functions.
	Poll time.Duration
}

func (c *Client) logf(f string, a ...any) {
	if c.Log != nil {
		c.Log(f, a...)
	}
}

func (c *Client) poll() time.Duration {
	if c.Poll > 0 {
		return c.Poll
	}
	return 2 * time.Second
}

// Whoami returns the authenticated user name, or "" if unknown.
func (c *Client) Whoami(ctx context.Context) string {
	r := &authnv1.SelfSubjectReview{}
	if err := c.C.Create(ctx, r); err != nil {
		return ""
	}
	return r.Status.UserInfo.Username
}

// Get returns the Blip or nil if it does not exist.
func (c *Client) Get(ctx context.Context, ns, name string) (*v1alpha1.Blip, error) {
	b := &v1alpha1.Blip{}
	err := c.C.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, b)
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	return b, err
}

// EnsureImageVolume creates the BlipVol for ref if missing and waits for it
// to be Ready. It returns the BlipVol name.
func (c *Client) EnsureImageVolume(ctx context.Context, ns, ref string) (string, error) {
	v := BuildImageVolume(ns, ref)
	if err := c.C.Create(ctx, v); err == nil {
		c.logf("created blipvol/%s for %s", v.Name, ref)
	} else if !apierrors.IsAlreadyExists(err) {
		return "", fmt.Errorf("create blipvol %s: %w", v.Name, err)
	}
	c.logf("waiting for blipvol/%s to be Ready", v.Name)
	err := wait.PollUntilContextCancel(ctx, c.poll(), true, func(ctx context.Context) (bool, error) {
		got := &v1alpha1.BlipVol{}
		if err := c.C.Get(ctx, client.ObjectKeyFromObject(v), got); err != nil {
			return false, err
		}
		if got.Spec.Image == nil || got.Spec.Image.Reference != ref {
			return false, fmt.Errorf("blipvol %s exists but does not import %s", v.Name, ref)
		}
		if meta.IsStatusConditionTrue(got.Status.Conditions, api.CondReady) {
			return true, nil
		}
		if got.Status.Phase == v1alpha1.BlipVolFailed {
			msg := ""
			if cnd := meta.FindStatusCondition(got.Status.Conditions, api.CondReady); cnd != nil {
				msg = ": " + cnd.Message
			}
			return false, fmt.Errorf("blipvol %s failed%s", v.Name, msg)
		}
		return false, nil
	})
	if err != nil {
		return "", wrapCtx(err, "blipvol "+v.Name+" not Ready")
	}
	return v.Name, nil
}

func rootName(s Spec) string {
	if s.RootClone != "" {
		return s.RootClone
	}
	return s.Volume
}

// RootCloneName returns a fresh name for the root clone of session name.
func RootCloneName(name string) string { return name + "-" + utilrand.String(5) }

// BuildRootClone returns the BlipVol that clones source for the session b.
// It is owned by b, so deleting the session deletes it.
func BuildRootClone(b *v1alpha1.Blip, name, source string) *v1alpha1.BlipVol {
	return &v1alpha1.BlipVol{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: b.Namespace,
			Name:      name,
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: v1alpha1.GroupVersion.String(), Kind: "Blip", Name: b.Name, UID: b.UID,
			}},
		},
		Spec: v1alpha1.BlipVolSpec{Parent: &v1alpha1.ParentRef{Name: source}},
	}
}

// Create creates the session Blip and its root volume, a clone of s.Volume
// owned by the Blip. A BlipVol is used by one Blip at a time, so cloning
// lets several sessions boot the same image or volume, and leaves it as is.
func (c *Client) Create(ctx context.Context, s Spec) (*v1alpha1.Blip, error) {
	if s.RootClone == "" {
		s.RootClone = RootCloneName(s.Name)
	}
	b, err := BuildBlip(s)
	if err != nil {
		return nil, err
	}
	if err := c.C.Create(ctx, b); err != nil {
		return nil, fmt.Errorf("create blip %s: %w", s.Name, err)
	}
	if err := c.C.Create(ctx, BuildRootClone(b, s.RootClone, s.Volume)); err != nil {
		_ = c.C.Delete(context.WithoutCancel(ctx), b)
		return nil, fmt.Errorf("create root volume %s of blip %s: %w", s.RootClone, s.Name, err)
	}
	c.logf("created blip/%s with root blipvol/%s cloned from %s", s.Name, s.RootClone, s.Volume)
	return b, nil
}

// Delete deletes the Blip and, if wait is set, waits until it is gone.
func (c *Client) Delete(ctx context.Context, b *v1alpha1.Blip, waitGone bool) error {
	if err := c.C.Delete(ctx, b); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	if !waitGone {
		return nil
	}
	err := wait.PollUntilContextCancel(ctx, c.poll(), true, func(ctx context.Context) (bool, error) {
		got, err := c.Get(ctx, b.Namespace, b.Name)
		return got == nil || (err == nil && got.UID != b.UID), err
	})
	return wrapCtx(err, "blip "+b.Name+" still exists")
}

// ErrServiceAccountNotFound is returned while the Blip waits for its
// ServiceAccount.
var ErrServiceAccountNotFound = errors.New("service account " + ServiceAccount + " not found")

// Finished reports whether the Blip ended.
func Finished(b *v1alpha1.Blip) bool {
	return b.Status.Phase == v1alpha1.BlipSucceeded || b.Status.Phase == v1alpha1.BlipFailed
}

// Ready returns the slot pod name and host key once the session can be
// reached. It returns an error if the Blip finished.
func Ready(b *v1alpha1.Blip) (pod, hostKey string, err error) {
	if Finished(b) {
		return "", "", fmt.Errorf("blip %s is %s: %s", b.Name, b.Status.Phase, b.Status.Message)
	}
	if b.Status.Phase != v1alpha1.BlipRunning || b.Status.Allocation == nil {
		return "", "", nil
	}
	return b.Status.Allocation.PodName, strings.TrimSpace(b.Annotations[api.AnnotationSSHHostKey]), nil
}

func waitingForSA(b *v1alpha1.Blip) bool {
	if cnd := meta.FindStatusCondition(b.Status.Conditions, api.CondScheduled); cnd != nil && cnd.Reason == api.ReasonServiceAccountNotFound {
		return true
	}
	for _, cnd := range b.Status.Conditions {
		if cnd.Reason == api.ReasonServiceAccountNotFound {
			return true
		}
	}
	return false
}

// WaitReady waits until the session is Running with a slot pod and a
// published host key.
func (c *Client) WaitReady(ctx context.Context, ns, name string) (b *v1alpha1.Blip, pod, hostKey string, err error) {
	lastPhase, lastWhy, saWarned := v1alpha1.BlipPhase("?"), "", false
	err = wait.PollUntilContextCancel(ctx, c.poll(), true, func(ctx context.Context) (bool, error) {
		got, err := c.Get(ctx, ns, name)
		if err != nil {
			return false, err
		}
		if got == nil {
			return false, fmt.Errorf("blip %s/%s not found", ns, name)
		}
		b = got
		if got.Status.Phase != lastPhase {
			lastPhase = got.Status.Phase
			c.logf("blip/%s: phase %s", name, orPending(lastPhase))
		}
		if why := pendingReason(got); why != lastWhy {
			lastWhy = why
			if why != "" {
				c.logf("blip/%s: waiting: %s", name, why)
			}
		}
		if waitingForSA(got) && !saWarned {
			saWarned = true
			c.logf("blip/%s is waiting: %v. Run `kubectl blip setup -n %s` (or apply examples/ssh/rbac.yaml)", name, ErrServiceAccountNotFound, ns)
		}
		pod, hostKey, err = Ready(got)
		if err != nil {
			return false, err
		}
		return pod != "" && hostKey != "", nil
	})
	if err != nil {
		msg := "timed out waiting for blip " + name
		if b != nil && waitingForSA(b) {
			return b, "", "", fmt.Errorf("%s: %w; run `kubectl blip setup -n %s`", msg, ErrServiceAccountNotFound, ns)
		}
		if b != nil && b.Status.Phase == v1alpha1.BlipRunning {
			msg += " to publish its SSH host key (does the image run blip-ssh-bootstrap?)"
		}
		return b, "", "", wrapCtx(err, msg)
	}
	return b, pod, hostKey, nil
}

// pendingReason describes why a Blip that is not Running yet waits (the
// Scheduled=False condition), or "".
func pendingReason(b *v1alpha1.Blip) string {
	if b.Status.Phase != "" && b.Status.Phase != v1alpha1.BlipPending {
		return ""
	}
	cnd := meta.FindStatusCondition(b.Status.Conditions, api.CondScheduled)
	if cnd == nil || cnd.Status != metav1.ConditionFalse || cnd.Reason == "" {
		return ""
	}
	if cnd.Message == "" {
		return cnd.Reason
	}
	return cnd.Reason + ": " + cnd.Message
}

func orPending(p v1alpha1.BlipPhase) v1alpha1.BlipPhase {
	if p == "" {
		return v1alpha1.BlipPending
	}
	return p
}

func wrapCtx(err error, msg string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return fmt.Errorf("%s: %w", msg, err)
	}
	return err
}

// List returns the sessions in ns ("" for all namespaces).
func (c *Client) List(ctx context.Context, ns string) ([]v1alpha1.Blip, error) {
	l := &v1alpha1.BlipList{}
	opts := []client.ListOption{client.MatchingLabels{api.LabelSession: "true"}}
	if ns != "" {
		opts = append(opts, client.InNamespace(ns))
	}
	if err := c.C.List(ctx, l, opts...); err != nil {
		return nil, err
	}
	return l.Items, nil
}

// SessionFromHost maps an ssh host name (blip-<name>) to a session name.
func SessionFromHost(host string) string {
	return strings.TrimPrefix(host, HostPrefix)
}

// ProxyCommand is the ssh ProxyCommand that runs `self proxy` with args.
// self is used as is; args are quoted.
// ssh replaces %n with the host name, blip-<session>, which is also the
// known_hosts name the proxy records the host key under.
func ProxyCommand(self string, args []string) string {
	p := self + " proxy"
	for _, a := range args {
		p += " " + ShellQuote(a)
	}
	return p + " %n"
}

// SSHArgs builds the ssh argv (without "ssh") to reach host through proxy.
func SSHArgs(proxy, keyFile, knownHosts, host string, cmd []string) []string {
	a := []string{
		"-o", "ProxyCommand=" + proxy,
		"-o", "User=root",
		"-o", "IdentityFile=" + ShellQuote(keyFile),
		"-o", "IdentitiesOnly=yes",
		"-o", "UserKnownHostsFile=" + ShellQuote(knownHosts),
		"-o", "StrictHostKeyChecking=yes",
		host,
	}
	// Options end at the destination; the rest is the remote command.
	return append(a, cmd...)
}

// SSHConfig returns an ssh_config stanza for blip-* hosts using `self` as the
// plugin command. It sets the same options as SSHArgs.
func SSHConfig(self, keyFile, knownHosts string, extraArgs []string) string {
	return fmt.Sprintf(`Host %s*
  User root
  ProxyCommand %s
  IdentityFile %s
  IdentitiesOnly yes
  UserKnownHostsFile %s
  StrictHostKeyChecking yes
`, HostPrefix, ProxyCommand(self, extraArgs), ShellQuote(keyFile), ShellQuote(knownHosts))
}

// ShellQuote quotes s for sh and ssh_config if needed.
func ShellQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\"'\\$`;&|<>(){}*?!#~") {
		return s
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// NestedRole is the Role and RoleBinding that `setup --nested` adds so that
// guests can run kubectl blip themselves.
const NestedRole = ServiceAccount + "-nested"

// SetupObjects returns the objects of examples/ssh/rbac.yaml and, with
// nested, examples/ssh/nested-rbac.yaml, moved to namespace ns.
func SetupObjects(ns string, nested bool) ([]client.Object, error) {
	docs := [][]byte{sshexample.RBAC}
	if nested {
		docs = append(docs, sshexample.NestedRBAC)
	}
	dec := serializer.NewCodecFactory(Scheme()).UniversalDeserializer()
	var objs []client.Object
	for _, d := range docs {
		r := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(d)))
		for {
			doc, err := r.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			o, _, err := dec.Decode(doc, nil, nil)
			if err != nil {
				return nil, err
			}
			obj := o.(client.Object)
			obj.SetNamespace(ns)
			if rb, ok := obj.(*rbacv1.RoleBinding); ok {
				for i := range rb.Subjects {
					rb.Subjects[i].Namespace = ns
				}
			}
			objs = append(objs, obj)
		}
	}
	return objs, nil
}

// Setup creates or updates the SetupObjects in ns.
func (c *Client) Setup(ctx context.Context, ns string, nested bool, out io.Writer) error {
	objs, err := SetupObjects(ns, nested)
	if err != nil {
		return err
	}
	for _, o := range objs {
		kind := fmt.Sprintf("%T", o)
		kind = strings.ToLower(kind[strings.LastIndex(kind, ".")+1:])
		err := c.C.Create(ctx, o)
		switch {
		case err == nil:
			fmt.Fprintf(out, "%s/%s created\n", kind, o.GetName())
			continue
		case apierrors.IsAlreadyExists(err):
		default:
			return setupErr(err, kind, ns)
		}
		cur := o.DeepCopyObject().(client.Object)
		if err := c.C.Get(ctx, client.ObjectKeyFromObject(o), cur); err != nil {
			return setupErr(err, kind, ns)
		}
		switch want := o.(type) {
		case *corev1.ServiceAccount:
			fmt.Fprintf(out, "%s/%s unchanged\n", kind, o.GetName())
			continue
		case *rbacv1.Role:
			cur.(*rbacv1.Role).Rules = want.Rules
		case *rbacv1.RoleBinding:
			rb := cur.(*rbacv1.RoleBinding)
			if rb.RoleRef != want.RoleRef {
				// roleRef is immutable: replace the binding.
				if err := c.C.Delete(ctx, rb); err != nil {
					return setupErr(err, kind, ns)
				}
				if err := c.C.Create(ctx, want); err != nil {
					return setupErr(err, kind, ns)
				}
				fmt.Fprintf(out, "%s/%s replaced\n", kind, o.GetName())
				continue
			}
			rb.Subjects = want.Subjects
		}
		if err := c.C.Update(ctx, cur); err != nil {
			return setupErr(err, kind, ns)
		}
		fmt.Fprintf(out, "%s/%s configured\n", kind, o.GetName())
	}
	return nil
}

func setupErr(err error, kind, ns string) error {
	if apierrors.IsForbidden(err) {
		return fmt.Errorf("not allowed to manage %ss in namespace %s; ask a namespace admin to run `kubectl blip setup -n %s` or apply examples/ssh/rbac.yaml: %w", kind, ns, ns, err)
	}
	return err
}
