// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package node

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/podapi"
)

const (
	// credsExpirationSeconds is the requested lifetime of a minted token.
	credsExpirationSeconds = int64(3600)
	// credsRefreshWindow is how much lifetime must remain for a cached token
	// to be reused. A pass re-mints once less than this is left.
	credsRefreshWindow = 1200 * time.Second
	// credsUID and credsGID own the credential directory and files so the
	// nonroot sidecar can read them.
	credsUID = 65532
	credsGID = 65532
	// apiServerUpstream is the fixed upstream for the Kubernetes API. Its
	// token uses the API server's default audience.
	apiServerUpstream = "kube-apiserver"
	// noIdentity is the placeholder written when the guest has no service
	// account. Envoy still injects it, and the upstream answers 401.
	noIdentity = "-"
	// bearerPrefix is the scheme the sidecar injects. Envoy 1.35's generic
	// credential cannot add a prefix, so the SDS value carries it.
	bearerPrefix = "Bearer "
	// credsDirMode and credsFileMode expose credentials only to their owner.
	credsDirMode  os.FileMode = 0o750
	credsFileMode os.FileMode = 0o440
)

// credUpstream is one endpoint the sidecar authenticates to and the audience
// of its token. An empty audience means the API server's default.
type credUpstream struct {
	name     string
	audience string
}

// podCreds is the token set minted for one pod. sa, podUID, and audiences
// identify the request a cached set answers; any change invalidates it.
type podCreds struct {
	sa        string
	podUID    string
	audiences []string
	tokens    map[string]string // audience -> token
	expires   time.Time
}

func (a *Agent) clock() time.Time {
	if a.now != nil {
		return a.now()
	}
	return time.Now()
}

// ensureCreds makes sure every claimed pod has a current credential file for
// the Kubernetes API and each authenticated pool endpoint. It runs before
// planning so a new claim can wait for the files its sidecar needs. Failures
// are recorded per pod; they never stop warm pods or existing VMs.
func (a *Agent) ensureCreds(ctx context.Context, v *view) {
	if a.kube == nil {
		// Planning-only callers have no API client. Credentials are not gated
		// then; a running agent always has one.
		return
	}
	ready := map[string]bool{}
	errs := map[string]string{}
	relevant := map[string]bool{}
	for _, key := range sortedKeys(v.pods) {
		pod := v.pods[key]
		if pod.Labels[v1alpha1.LabelBlipUID] == "" || podDone(pod, v.dirs[key]) {
			continue
		}
		if !v.hasBlip(pod) {
			continue
		}
		relevant[key] = true
		if err := a.ensurePodCreds(ctx, v, key, pod); err != nil {
			errs[key] = "credentials: " + err.Error()
			continue
		}
		ready[key] = true
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for key := range a.creds {
		if !relevant[key] {
			delete(a.creds, key)
		}
	}
	a.credsReady = ready
	a.credsErr = errs
}

// hasBlip reports whether the Blip that claimed pod is present in the same
// namespace.
func (v *view) hasBlip(pod *corev1.Pod) bool {
	uid := pod.Labels[v1alpha1.LabelBlipUID]
	for _, b := range v.blips {
		if string(b.UID) == uid && b.Namespace == pod.Namespace {
			return true
		}
	}
	return false
}

// ensurePodCreds writes the credential files of one claimed pod, reusing a
// cached token set while it is far enough from expiry and still matches the
// pod's identity and audiences.
func (a *Agent) ensurePodCreds(ctx context.Context, v *view, key string, pod *corev1.Pod) error {
	pool := v.pools[pod.Namespace+"/"+pod.Labels[v1alpha1.LabelPool]]
	upstreams := credsUpstreams(pool)
	dir := filepath.Join(a.podDirFor(key), podapi.CredsDir)
	if err := ensureCredsDir(dir); err != nil {
		return err
	}
	sa := credsServiceAccount(pod)
	if sa == "" || sa == noIdentity {
		return writePlaceholders(dir, upstreams)
	}
	audiences := credsAudiences(upstreams)
	now := a.clock()
	a.mu.Lock()
	cached := a.creds[key]
	a.mu.Unlock()
	if cached != nil && cached.sa == sa && cached.podUID == string(pod.UID) &&
		slices.Equal(cached.audiences, audiences) && cached.expires.Sub(now) > credsRefreshWindow {
		return writeTokens(dir, upstreams, cached.tokens)
	}
	tokens, expires, err := a.mintCreds(ctx, pod, sa, audiences)
	if err != nil {
		return err
	}
	a.mu.Lock()
	if a.creds == nil {
		a.creds = map[string]*podCreds{}
	}
	a.creds[key] = &podCreds{sa: sa, podUID: string(pod.UID), audiences: audiences, tokens: tokens, expires: expires}
	a.mu.Unlock()
	return writeTokens(dir, upstreams, tokens)
}

// credsServiceAccount returns the identity of the pod's guest. The controller
// resolves the Blip's identity and writes it at claim; a warm pod carries no
// annotation and must not mint tokens for the pool's account. "" and "-" both
// mean no identity.
func credsServiceAccount(pod *corev1.Pod) string {
	return pod.Annotations[v1alpha1.AnnotationServiceAccount]
}

// credsOK reports whether a new claim may be handed to the pod's guest. A nil
// map means credentials are not gated (only planning-only callers have one);
// the snapshot always supplies a map for a running agent.
func (v *view) credsOK(key string) bool {
	return v.credsReady == nil || v.credsReady[key]
}

// credsUpstreams returns every upstream the sidecar needs credentials for.
// The API server always has a placeholder even without an identity; pool
// endpoints appear only when they authenticate with an audience.
func credsUpstreams(pool *v1alpha1.BlipPool) []credUpstream {
	ups := []credUpstream{{name: apiServerUpstream}}
	if pool == nil {
		return ups
	}
	for _, e := range pool.Spec.Endpoints {
		if e.Audience == "" {
			continue
		}
		ups = append(ups, credUpstream{name: e.Name, audience: e.Audience})
	}
	return ups
}

// credsAudiences returns the distinct audiences to request, in a stable order
// so a cached set can be compared with the current requirement.
func credsAudiences(upstreams []credUpstream) []string {
	set := map[string]bool{}
	for _, u := range upstreams {
		set[u.audience] = true
	}
	audiences := make([]string, 0, len(set))
	for aud := range set {
		audiences = append(audiences, aud)
	}
	slices.Sort(audiences)
	return audiences
}

// mintCreds requests one bound token per audience. Several upstreams that
// share an audience share the token.
func (a *Agent) mintCreds(ctx context.Context, pod *corev1.Pod, sa string, audiences []string) (map[string]string, time.Time, error) {
	seconds := credsExpirationSeconds
	tokens := make(map[string]string, len(audiences))
	var expires time.Time
	for _, aud := range audiences {
		req := &authenticationv1.TokenRequest{Spec: authenticationv1.TokenRequestSpec{
			ExpirationSeconds: &seconds,
			BoundObjectRef: &authenticationv1.BoundObjectReference{
				Kind:       "Pod",
				APIVersion: "v1",
				Name:       pod.Name,
				UID:        pod.UID,
			},
		}}
		if aud != "" {
			req.Spec.Audiences = []string{aud}
		}
		tr, err := a.kube.CoreV1().ServiceAccounts(pod.Namespace).CreateToken(ctx, sa, req, metav1.CreateOptions{})
		if err != nil {
			// A pod deleted while its token is minted fails here. The error is
			// reported on the pod, not fatal to the agent.
			return nil, time.Time{}, fmt.Errorf("token for %s: %w", sa, err)
		}
		if tr.Status.Token == "" {
			return nil, time.Time{}, fmt.Errorf("token for %s: empty token", sa)
		}
		tokens[aud] = tr.Status.Token
		if t := tr.Status.ExpirationTimestamp; !t.IsZero() && (expires.IsZero() || t.Time.Before(expires)) {
			expires = t.Time
		}
	}
	if expires.IsZero() {
		expires = a.clock().Add(time.Duration(credsExpirationSeconds) * time.Second)
	}
	return tokens, expires, nil
}

// ensureCredsDir creates the sidecar's credential directory with the owner
// that the nonroot sidecar runs as. The controller's proxy-init creates the
// same directory, so an existing one is kept.
func ensureCredsDir(dir string) error {
	if err := os.MkdirAll(dir, credsDirMode); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(dir, credsUID, credsGID); err != nil {
			return err
		}
	}
	return nil
}

// writePlaceholders creates "-" credentials for upstreams without an identity.
// Existing files are left alone so a pass never rewrites them.
func writePlaceholders(dir string, upstreams []credUpstream) error {
	for _, u := range upstreams {
		path := filepath.Join(dir, u.name+".yaml")
		if _, err := os.Stat(path); err == nil {
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := writeCred(dir, u.name, noIdentity); err != nil {
			return err
		}
	}
	return nil
}

// writeTokens writes one file per upstream from a minted token set.
func writeTokens(dir string, upstreams []credUpstream, tokens map[string]string) error {
	for _, u := range upstreams {
		token, ok := tokens[u.audience]
		if !ok {
			return fmt.Errorf("no token for audience %q", u.audience)
		}
		if err := writeCred(dir, u.name, token); err != nil {
			return err
		}
	}
	return nil
}

// writeCred replaces one Envoy file SDS secret unless it already has the
// desired content.
func writeCred(dir, name, token string) error {
	path := filepath.Join(dir, name+".yaml")
	data := credFile(name, token)
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) {
		return nil
	}
	return replaceCredFile(path, data)
}

// replaceCredFile atomically replaces path with data: a temporary file in the
// same directory is written, given its final mode and owner, synced, and
// renamed over the destination.
func replaceCredFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	discard := func() {
		_ = f.Close()
		_ = os.Remove(tmp)
	}
	if _, err := f.Write(data); err != nil {
		discard()
		return err
	}
	if err := f.Chmod(credsFileMode); err != nil {
		discard()
		return err
	}
	if os.Geteuid() == 0 {
		if err := f.Chown(credsUID, credsGID); err != nil {
			discard()
			return err
		}
	}
	if err := f.Sync(); err != nil {
		discard()
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// credFile renders one Envoy file SDS generic secret. Envoy 1.35's generic
// credential has no header_value_prefix, so the document holds the complete
// header value including the Bearer scheme.
func credFile(name, token string) []byte {
	var b strings.Builder
	b.WriteString("resources:\n")
	b.WriteString("- \"@type\": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret\n")
	b.WriteString("  name: ")
	b.WriteString(name)
	b.WriteString("\n  generic_secret:\n    secret:\n      inline_string: ")
	b.WriteString(yamlQuote(bearerPrefix + token))
	b.WriteString("\n")
	return []byte(b.String())
}

// yamlQuote renders s as a YAML double-quoted scalar. Tokens are JWTs, which
// need no escapes, but quoting keeps any value valid.
func yamlQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&b, `\x%02x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}
