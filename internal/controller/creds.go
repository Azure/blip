package controller

import (
	"context"
	"fmt"
	"os"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/example/blip/internal/api"
	v1 "github.com/example/blip/internal/api/v1alpha1"
	"github.com/example/blip/internal/proto/nodepb"
)

// refreshAt is the fraction of a token's lifetime after which it is replaced.
const refreshAt = 0.8

// TokenMinter issues service account tokens bound to an object: the token
// becomes invalid as soon as that object is deleted.
type TokenMinter interface {
	Mint(ctx context.Context, ns, serviceAccount string, bound *authv1.BoundObjectReference) (token string, expires time.Time, err error)
}

// tokenRequestMinter mints tokens with the TokenRequest API.
type tokenRequestMinter struct {
	c   client.Client
	ttl time.Duration
}

func (m tokenRequestMinter) Mint(ctx context.Context, ns, sa string, bound *authv1.BoundObjectReference) (string, time.Time, error) {
	exp := int64(m.ttl / time.Second)
	tr := &authv1.TokenRequest{Spec: authv1.TokenRequestSpec{ExpirationSeconds: &exp, BoundObjectRef: bound}}
	sao := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: sa}}
	if err := m.c.SubResource("token").Create(ctx, sao, tr); err != nil {
		return "", time.Time{}, err
	}
	return tr.Status.Token, tr.Status.ExpirationTimestamp.Time, nil
}

// clusterCA returns the API server CA bundle of the controller's config.
func clusterCA(cfg *rest.Config) ([]byte, error) {
	if len(cfg.CAData) > 0 {
		return cfg.CAData, nil
	}
	if cfg.CAFile != "" {
		return os.ReadFile(cfg.CAFile)
	}
	return nil, nil
}

// credState is the token last minted for an allocation. It lives only in
// memory: after a controller restart every running allocation gets a new
// token promptly.
type credState struct {
	creds  *nodepb.Credentials
	issued time.Time
	due    time.Time // re-mint at or after
	seq    int
	op     string // pending UpdateCredentials operation
	cmd    *nodepb.Command
}

// mintCreds mints credentials for the allocation of b.
func (c *Controller) mintCreds(ctx context.Context, b *v1.Blip) (*nodepb.Credentials, time.Time, error) {
	sa := serviceAccountName(b)
	sec, err := c.bindingSecret(ctx, b)
	if err != nil {
		return nil, time.Time{}, err
	}
	bound := &authv1.BoundObjectReference{Kind: "Secret", APIVersion: "v1", Name: sec.Name, UID: sec.UID}
	tok, exp, err := c.minter.Mint(ctx, b.Namespace, sa, bound)
	if err != nil {
		return nil, time.Time{}, err
	}
	return &nodepb.Credentials{Token: []byte(tok), CaCrt: c.caCrt, Namespace: b.Namespace, Expiration: timestamppb.New(exp)}, exp, nil
}

// bindingSecretName is the name of the Secret that tokens of an allocation
// are bound to.
func bindingSecretName(allocID string) string { return "blip-token-" + allocID }

// bindingSecret returns the Secret that the allocation's tokens are bound
// to, creating it if needed. Deleting it revokes every token of the
// allocation at once. It is owned by the Blip, so garbage collection removes
// it should the controller miss the release.
func (c *Controller) bindingSecret(ctx context.Context, b *v1.Blip) (*corev1.Secret, error) {
	a := b.Status.Allocation
	key := types.NamespacedName{Namespace: b.Namespace, Name: bindingSecretName(a.ID)}
	var s corev1.Secret
	err := c.live.Get(ctx, key, &s)
	if err == nil {
		if s.Labels[api.LabelAllocation] != a.ID {
			return nil, fmt.Errorf("secret %s exists and is not a token binding", key)
		}
		return &s, nil
	}
	if !apierrors.IsNotFound(err) {
		return nil, err
	}
	f := false
	s = corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: key.Namespace, Name: key.Name,
			Labels: map[string]string{api.LabelName: b.Name, api.LabelAllocation: a.ID},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: v1.GroupVersion.String(), Kind: "Blip", Name: b.Name, UID: b.UID,
				Controller: &f, BlockOwnerDeletion: &f,
			}},
		},
		Type: api.SecretTypeTokenBinding,
	}
	if err := c.live.Create(ctx, &s); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil, fmt.Errorf("create token binding secret: %w", err)
		}
		return nil, err
	}
	return &s, nil
}

// deleteBindings deletes the token binding Secrets of Blip b except the one
// of allocation keep (if not empty), revoking their tokens.
func (c *Controller) deleteBindings(ctx context.Context, b *v1.Blip, keep string) error {
	var l corev1.SecretList
	if err := c.live.List(ctx, &l, client.InNamespace(b.Namespace), client.MatchingLabels{api.LabelName: b.Name}, client.HasLabels{api.LabelAllocation}); err != nil {
		return err
	}
	for i := range l.Items {
		s := &l.Items[i]
		if s.Type != api.SecretTypeTokenBinding || s.Labels[api.LabelAllocation] == keep {
			continue
		}
		uid := s.UID
		if err := c.live.Delete(ctx, s, client.Preconditions{UID: &uid}); client.IgnoreNotFound(err) != nil {
			return err
		}
	}
	return nil
}

// deleteBinding deletes the token binding Secret of an allocation.
func (c *Controller) deleteBinding(ctx context.Context, ns, allocID string) error {
	s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: bindingSecretName(allocID)}}
	return client.IgnoreNotFound(c.live.Delete(ctx, s))
}

func refreshTime(issued, exp time.Time) time.Time {
	return issued.Add(time.Duration(float64(exp.Sub(issued)) * refreshAt))
}

// startCreds returns the credentials for StartWorkload, minting them once
// per allocation.
func (c *Controller) startCreds(ctx context.Context, b *v1.Blip, now time.Time) (*nodepb.Credentials, error) {
	id := b.Status.Allocation.ID
	c.mu.Lock()
	st := c.creds[id]
	c.mu.Unlock()
	if st != nil {
		return st.creds, nil
	}
	// Revoke tokens of earlier allocations whose release was missed.
	if err := c.deleteBindings(ctx, b, id); err != nil {
		return nil, err
	}
	cr, exp, err := c.mintCreds(ctx, b)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.creds[id] = &credState{creds: cr, issued: now, due: refreshTime(now, exp)}
	c.mu.Unlock()
	return cr, nil
}

// rotateCreds replaces the token of a started allocation at ~80% of its
// lifetime, or at once if this controller has not minted one (restart).
// It returns when to look again.
func (c *Controller) rotateCreds(ctx context.Context, r *blipRun) time.Duration {
	b := r.b
	a := b.Status.Allocation
	c.mu.Lock()
	st := c.creds[a.ID]
	if st == nil {
		st = &credState{due: r.now}
		c.creds[a.ID] = st
	}
	op, cmd := st.op, st.cmd
	c.mu.Unlock()
	if op != "" {
		res := c.nodes.Do(a.Node, op, r.owner(), c.opts.CommandTimeout, cmd)
		if res == nil {
			return 2 * time.Second
		}
		c.nodes.Forget(op)
		c.mu.Lock()
		st.op, st.cmd = "", nil
		if !ok(res) {
			c.log.Info("credential update failed; retrying", "blip", r.key, "err", resultErr(res))
			st.due = r.now.Add(10 * time.Second)
		}
		c.mu.Unlock()
	}
	c.mu.Lock()
	due := st.due
	c.mu.Unlock()
	if r.now.Before(due) {
		return due.Sub(r.now)
	}
	cr, exp, err := c.mintCreds(ctx, b)
	if err != nil {
		if apierrors.IsNotFound(err) {
			c.log.Info("cannot refresh token", "blip", r.key, "err", err.Error())
		} else {
			c.log.Error(err, "mint token", "blip", r.key)
		}
		c.mu.Lock()
		st.due = r.now.Add(30 * time.Second)
		c.mu.Unlock()
		return 30 * time.Second
	}
	c.mu.Lock()
	st.seq++
	st.creds, st.issued, st.due = cr, r.now, refreshTime(r.now, exp)
	st.op = fmt.Sprintf("%s.creds.%d.%d", a.ID, r.now.UnixNano(), st.seq)
	st.cmd = &nodepb.Command{Op: &nodepb.Command_UpdateCredentials{UpdateCredentials: &nodepb.UpdateCredentials{AllocationId: a.ID, Credentials: cr}}}
	op, cmd = st.op, st.cmd
	c.mu.Unlock()
	c.nodes.Do(a.Node, op, r.owner(), c.opts.CommandTimeout, cmd)
	return 2 * time.Second
}

func (c *Controller) forgetCreds(id string) {
	c.mu.Lock()
	delete(c.creds, id)
	c.mu.Unlock()
}

func blipPorts(b *v1.Blip) []uint32 {
	var out []uint32
	for _, p := range b.Spec.Ports {
		out = append(out, uint32(p.Port))
	}
	return out
}
