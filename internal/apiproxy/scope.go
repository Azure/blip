package apiproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

const (
	// adminOwner marks an unlabelled (unrestricted) Blip. Its VM is allowed
	// the same reads as before owner scoping existed.
	adminOwner = "-"
	// maxScopeObjectBytes bounds the metadata read used to authorize one
	// object. Kubernetes objects are capped well below this.
	maxScopeObjectBytes = 4 << 20
	// scopeTimeout bounds the trusted identity and object lookups. It is not
	// applied to the proxied request itself, so watches stay open.
	scopeTimeout = 10 * time.Second
)

// validPodIdentity rejects values that cannot be a pod or namespace name.
func validPodIdentity(value string) bool {
	if value == "" || len(value) > 253 {
		return false
	}
	for _, r := range value {
		if r <= ' ' || r > '~' || r == '/' || r == '\\' {
			return false
		}
	}
	return true
}

// identity is the trusted owner context of one API proxy.
type identity struct {
	namespace string
	// owner is the Blip's owner label, or adminOwner for an unlabelled Blip.
	owner string
	// thread is the Blip's thread, but only when the thread owner hash
	// matches owner. A caller cannot widen its scope by labelling its Blip
	// with another project's thread name.
	thread string
	// claimed is false until the controller has claimed this pod for a Blip.
	claimed bool
}

// scopeRequest describes a namespaced read of a resource that owner scoping
// covers.
type scopeRequest struct {
	namespace   string
	resource    string // pods, blips, blipstates, blipthreads or blipturns
	name        string // empty for a list or watch
	subresource string
	list        bool
}

type scopeAction int

const (
	passThrough scopeAction = iota
	scopedRead
	scopedDeny
)

// ownerScope enforces the security model of a claimed VM pod: the guest may
// only read its owner's objects in the sidecar's namespace. The guest never
// supplies its identity; the proxy derives it from its own pod and Blip with
// the sidecar's service account.
//
// Residual behavior:
//   - The API server implements the equality label selector injected into
//     lists and watches. A server without label-selector support would return
//     a broader list; requests remain namespace- and RBAC-bound, but owner
//     isolation would depend on upgrading the API server (Kubernetes has
//     always supported it).
//   - Objects created before owner labels existed are handled explicitly. An
//     unlabelled BlipState with spec.image set is a shared read-only base and
//     stays readable by name; an unlabelled writable or copied state is
//     private, matching the mount and copy policy. An unlabelled Blip is
//     administrator-owned and private. Scoped lists select the caller's owner
//     label, so shared bases do not appear in a restricted owner's list or
//     watch even though a GET by name works.
//   - VM pods created from a template older than this scope have no
//     POD_NAME/POD_NAMESPACE and keep the previous unscoped behavior until
//     their pool recreates them.
type ownerScope struct {
	namespace  string
	podName    string
	apiAddress string
	client     *http.Client
	next       http.Handler
}

func newOwnerScope(cfg Config, transport *http.Transport, next http.Handler) http.Handler {
	return &ownerScope{
		namespace:  cfg.PodNamespace,
		podName:    cfg.PodName,
		apiAddress: cfg.API.Address,
		client: &http.Client{
			Transport: tokenTransport{base: transport, tokenFile: cfg.API.TokenFile},
			Timeout:   scopeTimeout,
			// Never follow a redirect: it could leave the fixed upstream.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		next: next,
	}
}

func (s *ownerScope) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Writes keep their existing paths and are authorized by RBAC and the
	// owner admission policy. Scoping only changes reads.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		s.next.ServeHTTP(w, r)
		return
	}
	req, action := parseScopePath(r.URL.Path)
	switch action {
	case passThrough:
		s.next.ServeHTTP(w, r)
		return
	case scopedDeny:
		if !canonicalAPIPath(r.URL) {
			http.Error(w, "invalid request path", http.StatusBadRequest)
			return
		}
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// A non-canonical encoding could be interpreted differently by the API
	// server than by this scope check.
	if !canonicalAPIPath(r.URL) {
		http.Error(w, "invalid request path", http.StatusBadRequest)
		return
	}
	if req.namespace != s.namespace {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, err := s.identity(r.Context())
	if err != nil {
		// Fail closed without exposing transport or API-server details.
		http.Error(w, "Kubernetes API unavailable", http.StatusBadGateway)
		return
	}
	if !id.claimed {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if id.owner == adminOwner {
		s.next.ServeHTTP(w, r)
		return
	}
	if len(validation.IsValidLabelValue(id.owner)) != 0 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if req.list {
		next, ok := scopedList(r, id, req.resource)
		if !ok {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		s.next.ServeHTTP(w, next)
		return
	}
	allowed, status, err := s.allowed(r.Context(), id, req)
	if err != nil {
		http.Error(w, "Kubernetes API unavailable", http.StatusBadGateway)
		return
	}
	if !allowed {
		if status == http.StatusForbidden {
			status = http.StatusNotFound
		}
		http.Error(w, http.StatusText(status), status)
		return
	}
	// The original path, query, headers and body are forwarded unchanged so
	// upgrades, logs and large responses keep working.
	s.next.ServeHTTP(w, r)
}

// identity reads this proxy's own pod and Blip. Claiming sets the pod's Blip
// annotation and UID label in one patch, and the Blip's UID must match.
func (s *ownerScope) identity(ctx context.Context) (identity, error) {
	empty := identity{namespace: s.namespace}
	pod, status, err := s.object(ctx, "/api/v1/namespaces/"+url.PathEscape(s.namespace)+"/pods/"+url.PathEscape(s.podName))
	if err != nil {
		return identity{}, err
	}
	if status != http.StatusOK {
		if status == http.StatusNotFound || status == http.StatusForbidden {
			// Vacant pods are never exposed.
			return empty, nil
		}
		return identity{}, fmt.Errorf("read own pod: status %d", status)
	}
	blipName := pod.Metadata.Annotations[v1.AnnotationBlip]
	blipUID := pod.Metadata.Labels[v1.LabelBlipUID]
	if blipName == "" || blipUID == "" {
		return empty, nil
	}
	blip, status, err := s.object(ctx, "/apis/blip.dev/v1alpha1/namespaces/"+url.PathEscape(s.namespace)+"/blips/"+url.PathEscape(blipName))
	if err != nil {
		return identity{}, err
	}
	if status != http.StatusOK {
		if status == http.StatusNotFound || status == http.StatusForbidden {
			return empty, nil
		}
		return identity{}, fmt.Errorf("read own blip: status %d", status)
	}
	if blip.Metadata.UID != blipUID {
		return empty, nil
	}
	owner := blip.Metadata.Labels[v1.LabelOwner]
	if owner == "" {
		owner = adminOwner
	}
	// Threads and their turns carry the most sensitive text in the system.
	// The Blip's thread label is self-asserted (a guest may patch its own
	// Blip), so only trust it when the thread's derived owner equals the
	// Blip's owner. Otherwise the caller has no thread scope at all.
	thread := blip.Metadata.Annotations[v1.AnnotationThread]
	if thread == "" {
		thread = blip.Metadata.Labels[v1.LabelThread]
	}
	if thread == "" || owner == adminOwner || v1.ThreadOwner(s.namespace, thread) != owner {
		thread = ""
	}
	return identity{namespace: s.namespace, owner: owner, thread: thread, claimed: true}, nil
}

// allowed reports whether id may read req.name, and the status to return when
// it may not.
func (s *ownerScope) allowed(ctx context.Context, id identity, req scopeRequest) (bool, int, error) {
	var path string
	switch req.resource {
	case "pods":
		path = "/api/v1/namespaces/" + url.PathEscape(s.namespace) + "/pods/" + url.PathEscape(req.name)
	case "blips", "blipstates", "blipthreads", "blipturns":
		path = "/apis/blip.dev/v1alpha1/namespaces/" + url.PathEscape(s.namespace) + "/" + req.resource + "/" + url.PathEscape(req.name)
	default:
		return false, http.StatusNotFound, nil
	}
	obj, status, err := s.object(ctx, path)
	if err != nil {
		return false, 0, err
	}
	if status != http.StatusOK {
		if status == http.StatusNotFound || status == http.StatusForbidden {
			return false, http.StatusNotFound, nil
		}
		return false, status, nil
	}
	owner := obj.Metadata.Labels[v1.LabelOwner]
	switch req.resource {
	case "pods":
		// Warm and unknown pods have no owner label and are never exposed.
		return owner != "" && owner == id.owner, http.StatusNotFound, nil
	case "blipthreads":
		// A claimed VM sees only its own project's thread. Threads are not
		// owner-labelled, so the name derived from the caller's Blip is the
		// binding; an owner-labelled thread is also private to that owner.
		if id.thread != "" && req.name == id.thread {
			return true, http.StatusNotFound, nil
		}
		return owner != "" && owner == id.owner, http.StatusNotFound, nil
	case "blipturns":
		// Turns are scoped by the thread they belong to, plus any explicit
		// owner label. An untrusted thread label never reaches id.thread.
		if id.thread != "" && obj.Spec.Thread == id.thread {
			return true, http.StatusNotFound, nil
		}
		return owner != "" && owner == id.owner, http.StatusNotFound, nil
	default:
		// Owner-labelled objects are private. Only an unlabelled image
		// state is a shared base: the controller and mount policy treat an
		// ownerless state without spec.image as private, so the proxy must
		// not expose it by name. An unlabelled Blip is administrator-owned.
		if owner == "" {
			return req.resource == "blipstates" && obj.Spec.Image != "", http.StatusNotFound, nil
		}
		return owner == id.owner, http.StatusNotFound, nil
	}
}

// scopedList adds the selector that confines a list or watch to the caller's
// objects. Threads and turns are scoped to the caller's project; a caller
// without a project has no access to them at all.
func scopedList(r *http.Request, id identity, resource string) (*http.Request, bool) {
	switch resource {
	case "blipthreads":
		if id.thread == "" {
			return nil, false
		}
		return withFieldSelector(r, "metadata.name", id.thread), true
	case "blipturns":
		if id.thread == "" {
			return nil, false
		}
		return withLabelSelector(r, v1.LabelThread, v1.ThreadLabel(id.thread)), true
	default:
		return withOwnerSelector(r, id.owner), true
	}
}

// objectMeta is the small part of an object the scope may inspect.
type objectMeta struct {
	Metadata struct {
		Name        string            `json:"name"`
		UID         string            `json:"uid"`
		Labels      map[string]string `json:"labels"`
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
	Spec struct {
		// Image distinguishes a shared read-only base from an ownerless
		// writable state, which stays private.
		Image  string `json:"image"`
		Thread string `json:"thread"`
	} `json:"spec"`
}

// object performs a trusted GET of path. Only metadata is retained.
func (s *ownerScope) object(ctx context.Context, path string) (objectMeta, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+s.apiAddress+path, nil)
	if err != nil {
		return objectMeta{}, 0, err
	}
	req.Host = s.apiAddress
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return objectMeta{}, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return objectMeta{}, resp.StatusCode, nil
	}
	var obj objectMeta
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxScopeObjectBytes)).Decode(&obj); err != nil {
		return objectMeta{}, 0, err
	}
	return obj, http.StatusOK, nil
}

// withOwnerSelector merges an owner equality requirement into an existing
// label selector, leaving all other query parameters alone.
func withOwnerSelector(r *http.Request, owner string) *http.Request {
	return withLabelSelector(r, v1.LabelOwner, owner)
}

// withLabelSelector merges one equality label requirement into an existing
// label selector, leaving all other query parameters alone.
func withLabelSelector(r *http.Request, key, value string) *http.Request {
	return withSelector(r, "labelSelector", key, value)
}

// withFieldSelector merges one equality field requirement into an existing
// field selector.
func withFieldSelector(r *http.Request, key, value string) *http.Request {
	return withSelector(r, "fieldSelector", key, value)
}

func withSelector(r *http.Request, query, key, value string) *http.Request {
	out := r.Clone(r.Context())
	q := out.URL.Query()
	selector := q.Get(query)
	requirement := key + "=" + value
	if selector == "" {
		selector = requirement
	} else {
		selector += "," + requirement
	}
	q.Set(query, selector)
	out.URL.RawQuery = q.Encode()
	return out
}

// parseScopePath classifies a request path. Unrecognized API paths pass
// through so that discovery and version requests keep working; a path that
// names a scoped resource in a shape the proxy does not understand is denied
// rather than forwarded unchecked.
func parseScopePath(p string) (scopeRequest, scopeAction) {
	p = strings.TrimRight(p, "/")
	if p == "" {
		return scopeRequest{}, passThrough
	}
	seg := strings.Split(strings.TrimPrefix(p, "/"), "/")
	scopedResource := func(s string) bool {
		return s == "pods" || s == "blips" || s == "blipstates" || s == "blipthreads" || s == "blipturns"
	}
	namesScopedResource := func(parts []string) bool {
		for _, s := range parts {
			if scopedResource(s) {
				return true
			}
		}
		return false
	}
	namespaced := func(base int) (scopeRequest, scopeAction) {
		// seg[base] is the resource, seg[base-1] the namespace.
		res := seg[base]
		req := scopeRequest{namespace: seg[base-1], resource: res}
		switch len(seg) - base - 1 {
		case 0:
			req.list = true
			return req, scopedRead
		case 1:
			req.name = seg[base+1]
			return req, scopedRead
		case 2:
			req.name = seg[base+1]
			req.subresource = seg[base+2]
			return req, scopedRead
		default:
			return scopeRequest{}, scopedDeny
		}
	}
	if seg[0] == "api" {
		if len(seg) >= 5 && seg[2] == "namespaces" && scopedResource(seg[4]) {
			return namespaced(4)
		}
		// Legacy namespaced watches, /api/v1/watch/namespaces/{ns}/{res},
		// are reads of the same collection and must be scoped like the list.
		// Only the collection shape is a real route; any other watch shape
		// naming a scoped resource is denied rather than forwarded unscoped.
		if len(seg) > 2 && seg[2] == "watch" {
			if len(seg) == 6 && seg[3] == "namespaces" && scopedResource(seg[5]) {
				return namespaced(5)
			}
			if namesScopedResource(seg[3:]) {
				return scopeRequest{}, scopedDeny
			}
			return scopeRequest{}, passThrough
		}
		// /api/v1/pods (all namespaces) or another shape naming pods.
		if len(seg) >= 3 && seg[2] == "pods" {
			return scopeRequest{}, scopedDeny
		}
		return scopeRequest{}, passThrough
	}
	if seg[0] == "apis" && len(seg) >= 2 && seg[1] == "blip.dev" {
		if len(seg) >= 6 && seg[3] == "namespaces" && scopedResource(seg[5]) {
			return namespaced(5)
		}
		// Legacy namespaced watches,
		// /apis/blip.dev/v1alpha1/watch/namespaces/{ns}/{res}, are scoped like
		// the list. Unknown watch shapes naming a scoped resource are denied.
		if len(seg) > 3 && seg[3] == "watch" {
			if len(seg) == 7 && seg[4] == "namespaces" && scopedResource(seg[6]) {
				return namespaced(6)
			}
			if namesScopedResource(seg[4:]) {
				return scopeRequest{}, scopedDeny
			}
		}
		// /apis/blip.dev/v1alpha1/blips (all namespaces) or another shape.
		if len(seg) >= 4 && scopedResource(seg[3]) {
			return scopeRequest{}, scopedDeny
		}
	}
	return scopeRequest{}, passThrough
}

// canonicalAPIPath rejects path encodings that could make the API server see
// a different object or namespace than the scope check.
func canonicalAPIPath(u *url.URL) bool {
	escaped := strings.ToLower(u.EscapedPath())
	if strings.Contains(escaped, "%2f") || strings.Contains(escaped, "%5c") {
		return false
	}
	if u.RawPath != "" {
		p, err := url.PathUnescape(u.RawPath)
		if err != nil || p != u.Path {
			return false
		}
	}
	p := strings.TrimRight(u.Path, "/")
	if p == "" {
		p = "/"
	}
	if strings.Contains(p, "//") {
		return false
	}
	for _, s := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		if s == "" || s == "." || s == ".." {
			return false
		}
	}
	return true
}
