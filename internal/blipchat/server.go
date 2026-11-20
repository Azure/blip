// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// Options configures the stateless chat server.
type Options struct {
	// Namespace is the one Kubernetes namespace blipchat serves. It is fixed
	// at deployment time (--namespace); no request may choose another.
	Namespace string
	// BasePath is the URL prefix the UI and API are also served under, such as
	// "/blipchat". Empty serves only at the root.
	BasePath    string
	Profiles    Profiles
	DefaultPool string
	AutoApprove string
	Cluster     Cluster
	Wire        Wire
	Log         *slog.Logger
	// Callers identifies the chat behind an MCP request. Without it the MCP
	// endpoint refuses every call.
	Callers Callers
	// MCPURL is the URL an agent uses to reach the MCP endpoint. An empty
	// URL offers no MCP server to agents.
	MCPURL string
	// QuestionTimeout bounds how long ask_user waits for an answer. Zero uses
	// 30 seconds.
	QuestionTimeout time.Duration
}

// Server is the HTTP front end and the owner of the per-session drivers.
type Server struct {
	namespace   string
	basePath    string
	profiles    Profiles
	defaultPool string
	autoApprove string
	cluster     Cluster
	wire        Wire
	pending     PendingStore
	log         *slog.Logger
	callers     Callers
	mcpURL      string
	questionTTL time.Duration

	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	drivers map[string]*driver
	ready   atomic.Bool
}

func New(opts Options) (*Server, error) {
	if opts.Cluster == nil || opts.Wire == nil {
		return nil, errors.New("blipchat: cluster and wire are required")
	}
	switch opts.AutoApprove {
	case "", "always":
		opts.AutoApprove = "always"
	case "never":
	default:
		return nil, fmt.Errorf("--auto-approve must be always or never, got %q", opts.AutoApprove)
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.DefaultPool == "" {
		opts.DefaultPool = "default"
	}
	if opts.QuestionTimeout <= 0 {
		opts.QuestionTimeout = defaultQuestionTimeout
	}
	if opts.Profiles == nil {
		opts.Profiles = Profiles{}
	}
	if _, ok := opts.Profiles[DefaultProfileName]; !ok {
		opts.Profiles[DefaultProfileName] = Profile{}.normalized(opts.DefaultPool)
	}
	for name, p := range opts.Profiles {
		if !validProfileName(name) {
			return nil, fmt.Errorf("profile name %q is invalid", name)
		}
		if _, err := p.baseStateSelector(); err != nil {
			return nil, fmt.Errorf("profile %q baseSelector: %w", name, err)
		}
	}
	for name, p := range opts.Profiles {
		if err := p.normalized(opts.DefaultPool).validate(); err != nil {
			return nil, fmt.Errorf("profile %q: %w", name, err)
		}
		opts.Profiles[name] = p.normalized(opts.DefaultPool)
	}
	if opts.Namespace == "" {
		opts.Namespace = "default"
	}
	if !validDNSLabel(opts.Namespace) {
		return nil, fmt.Errorf("default namespace %q is not a DNS label", opts.Namespace)
	}
	basePath, err := normalizeBasePath(opts.BasePath)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		namespace:   opts.Namespace,
		basePath:    basePath,
		profiles:    opts.Profiles,
		defaultPool: opts.DefaultPool,
		autoApprove: opts.AutoApprove,
		cluster:     opts.Cluster,
		wire:        opts.Wire,
		pending:     pendingStore(opts.Cluster),
		log:         opts.Log,
		callers:     opts.Callers,
		mcpURL:      opts.MCPURL,
		questionTTL: opts.QuestionTimeout,
		ctx:         ctx,
		cancel:      cancel,
		drivers:     make(map[string]*driver),
	}
	s.ready.Store(true)
	return s, nil
}

func pendingStore(c Cluster) PendingStore {
	if p, ok := c.(PendingStore); ok {
		return p
	}
	return nil
}

// Start replaces the base context used by drivers. It is optional; New
// installs a background context so tests can use the handler directly.
func (s *Server) Start(ctx context.Context) {
	s.cancel()
	s.ctx, s.cancel = context.WithCancel(ctx)
}

func (s *Server) Close() {
	s.cancel()
	s.mu.Lock()
	drivers := make([]*driver, 0, len(s.drivers))
	for _, d := range s.drivers {
		drivers = append(drivers, d)
	}
	s.drivers = make(map[string]*driver)
	s.mu.Unlock()
	for _, d := range drivers {
		d.Close()
	}
}

func (s *Server) Handler() http.Handler {
	api := http.NewServeMux()
	api.HandleFunc("GET /api/me", s.handleMe)
	api.HandleFunc("GET /api/sessions", s.handleListSessions)
	api.HandleFunc("POST /api/sessions", s.handleCreateSession)
	api.HandleFunc("GET /api/profiles", s.handleProfiles)
	api.HandleFunc("GET /api/sessions/{name}", s.handleGetSession)
	api.HandleFunc("GET /api/sessions/{name}/events", s.handleEvents)
	api.HandleFunc("POST /api/sessions/{name}/message", s.handleMessage)
	api.HandleFunc("POST /api/sessions/{name}/cancel", s.handleCancel)
	api.HandleFunc("POST /api/sessions/{name}/stop", s.handleStop)
	// Method-less registrations for the known paths let ServeMux answer an
	// unsupported method with 405 and Allow instead of treating it as an
	// unknown path. The method-specific patterns above still take precedence.
	api.HandleFunc("/api/me", methodNotAllowed("GET"))
	api.HandleFunc("/api/sessions", methodNotAllowed("GET, POST"))
	api.HandleFunc("/api/profiles", methodNotAllowed("GET"))
	api.HandleFunc("/api/sessions/{name}", methodNotAllowed("GET"))
	api.HandleFunc("/api/sessions/{name}/events", methodNotAllowed("GET"))
	api.HandleFunc("/api/sessions/{name}/message", methodNotAllowed("POST"))
	api.HandleFunc("/api/sessions/{name}/cancel", methodNotAllowed("POST"))
	api.HandleFunc("/api/sessions/{name}/stop", methodNotAllowed("POST"))
	api.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not found")
	})

	root := http.NewServeMux()
	root.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	root.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !s.ready.Load() {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "starting"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	root.HandleFunc("/healthz", methodNotAllowed("GET, HEAD"))
	root.HandleFunc("/readyz", methodNotAllowed("GET, HEAD"))
	root.Handle("/api", s.identity(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not found")
	})))
	root.Handle("/api/", s.identity(s.sameOrigin(api)))
	root.HandleFunc("/", s.handleUI)
	if s.basePath == "" {
		return root
	}
	// Serve the same handler at the root too, so a proxy may either strip the
	// prefix before forwarding or pass it through. The UI builds its API URLs
	// from the configured base path in both cases. ServeMux redirects the bare
	// prefix to its trailing-slash form and preserves the query string.
	mux := http.NewServeMux()
	mux.Handle("/", root)
	mux.Handle(s.basePath+"/", http.StripPrefix(s.basePath, root))
	return mux
}

// MCPHandler serves only the agent MCP endpoint. The TLS listener uses this
// handler so a chat VM that can reach it cannot also call the browser API with
// a forged identity header.
func (s *Server) MCPHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST /mcp", s.handleMCP())
	mux.HandleFunc("/mcp", methodNotAllowed("POST"))
	return mux
}

// sameOrigin rejects browser POSTs that a cross-site page could trigger. A
// JSON content-type check in decodeJSON does the same for request bodies, but
// cancel/stop have no body, so Origin and Sec-Fetch-Site are checked here.
func (s *Server) sameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			site := r.Header.Get("Sec-Fetch-Site")
			if site == "cross-site" {
				writeError(w, http.StatusForbidden, "cross-site request rejected")
				return
			}
			if origin := r.Header.Get("Origin"); origin != "" {
				u, err := url.Parse(origin)
				ok := err == nil && u.Host != "" && u.User == nil &&
					(u.Scheme == "http" || u.Scheme == "https")
				if ok {
					// Even a page that claims Sec-Fetch-Site: same-origin must
					// present an Origin for the host we are actually serving.
					hosts := []string{r.Host}
					// A comma list or repeated header has no single trusted
					// value, so ignore X-Forwarded-Host in either case.
					xfh := r.Header.Values("X-Forwarded-Host")
					if len(xfh) == 1 && !strings.Contains(xfh[0], ",") {
						hosts = append(hosts, xfh[0])
					}
					ok = false
					for _, h := range hosts {
						if h == "" {
							continue
						}
						if strings.EqualFold(u.Host, h) {
							ok = true
							break
						}
						// A proxy that forwards Host without the external port
						// loses information sameOrigin needs. Fall back to a
						// hostname match only when the browser itself attests
						// that scheme, host, and port all match; a sibling port
						// sends same-site instead.
						if site == "same-origin" {
							if host, hasPort, valid := authorityHost(h); valid && !hasPort &&
								strings.EqualFold(host, u.Hostname()) {
								ok = true
								break
							}
						}
					}
				}
				if !ok {
					writeError(w, http.StatusForbidden, "cross-origin request rejected")
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// authorityHost splits an HTTP authority into its host and whether it carries
// an explicit port. ok is false for empty, ambiguous, or malformed values so
// callers fail closed. A bracketed IPv6 literal without a port is valid.
func authorityHost(authority string) (host string, hasPort, ok bool) {
	if authority == "" || strings.ContainsAny(authority, ", \t") {
		return "", false, false
	}
	if h, p, err := net.SplitHostPort(authority); err == nil {
		if p == "" {
			return "", false, false
		}
		return h, true, true
	}
	if strings.HasPrefix(authority, "[") && strings.HasSuffix(authority, "]") {
		h := authority[1 : len(authority)-1]
		if net.ParseIP(h) == nil {
			return "", false, false
		}
		return h, false, true
	}
	// An unbracketed colon is a malformed authority or an IPv6 literal we
	// refuse to interpret.
	if strings.Contains(authority, ":") {
		return "", false, false
	}
	return authority, false, true
}

// normalizeBasePath validates the optional URL prefix blipchat serves under.
// An empty path or "/" means the root. The result has no trailing slash.
func normalizeBasePath(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "/" {
		return "", nil
	}
	if !strings.HasPrefix(raw, "/") {
		return "", fmt.Errorf("--base-path must start with /, got %q", raw)
	}
	if strings.HasSuffix(raw, "/") || path.Clean(raw) != raw {
		return "", fmt.Errorf("--base-path must be a clean path without a trailing slash, got %q", raw)
	}
	// ServeMux treats braces as wildcards and rejects spaces, so limit the
	// path to the characters a subroute realistically uses.
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '-' || c == '_' || c == '.' || c == '~' || c == '/'
		if !ok {
			return "", fmt.Errorf("--base-path contains invalid character %q", c)
		}
	}
	switch {
	case raw == "/api", strings.HasPrefix(raw, "/api/"):
		return "", fmt.Errorf("--base-path %q conflicts with the API route", raw)
	case raw == "/mcp":
		return "", fmt.Errorf("--base-path %q conflicts with the MCP route", raw)
	case raw == "/healthz", raw == "/readyz":
		return "", fmt.Errorf("--base-path %q conflicts with a probe route", raw)
	}
	return raw, nil
}

func (s *Server) identity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		users := r.Header.Values("X-Forwarded-User")
		user := ""
		if len(users) == 1 {
			user = strings.TrimSpace(users[0])
		}
		if user == "" || strings.Contains(user, ",") {
			writeError(w, http.StatusUnauthorized, "exactly one X-Forwarded-User header is required")
			return
		}
		if !utf8.ValidString(user) {
			writeError(w, http.StatusBadRequest, "X-Forwarded-User must be valid UTF-8")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// forwardedUser returns the identity the gateway asserted for this request.
// Identity has already rejected missing or ambiguous headers.
func forwardedUser(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get("X-Forwarded-User"))
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Vary", "X-Forwarded-User")
	writeJSON(w, http.StatusOK, map[string]string{"user": forwardedUser(r)})
}

// uiBasePathPlaceholder is replaced in the embedded UI with the configured
// base path, so the browser sends API and event-stream requests through it.
const uiBasePathPlaceholder = "__BLIPCHAT_BASE_PATH__"

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed("GET, HEAD")(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	page := strings.ReplaceAll(uiHTML, uiBasePathPlaceholder, html.EscapeString(s.basePath))
	_, _ = w.Write([]byte(page))
}

func validDNSLabel(s string) bool {
	if len(s) == 0 || len(s) > 63 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-'
		if !ok {
			return false
		}
		if c == '-' && (i == 0 || i == len(s)-1) {
			return false
		}
	}
	return true
}

// Scopes a chat may have. A chat with no scope annotation is a team chat.
const (
	scopeTeam = "team"
	scopeUser = "user"
)

// scopeOf reports the chat's scope. Chats created before scopes existed carry
// no annotation and are team chats.
func scopeOf(st *v1.BlipState) string {
	if st.Annotations[AnnotationScope] == scopeUser {
		return scopeUser
	}
	return scopeTeam
}

// canAccess reports whether user may see or use the chat. Team chats are open
// to everyone; a private chat only to the owner it records.
func canAccess(st *v1.BlipState, user string) bool {
	if scopeOf(st) == scopeUser {
		return st.Annotations[AnnotationUser] == user
	}
	return true
}

type sessionSummary struct {
	Name          string      `json:"name"`
	Scope         string      `json:"scope"`
	Title         string      `json:"title"`
	Profile       string      `json:"profile"`
	Phase         string      `json:"phase"`
	Running       bool        `json:"running"`
	ACPSessionID  string      `json:"acpSessionId,omitempty"`
	Generation    int64       `json:"generation"`
	StatusMessage string      `json:"statusMessage,omitempty"`
	Parent        string      `json:"parent,omitempty"`
	Root          string      `json:"root,omitempty"`
	Depth         int         `json:"depth"`
	Created       metav1.Time `json:"created"`
	// Question is set while the agent waits for the user's answer.
	Question *Question `json:"question,omitempty"`
}

type sessionDetail struct {
	sessionSummary
	Transcript          []json.RawMessage `json:"transcript"`
	Offset              uint64            `json:"offset"`
	TranscriptTruncated bool              `json:"transcriptTruncated,omitempty"`
}

func summarize(st *v1.BlipState, blips []v1.Blip) sessionSummary {
	title := st.Annotations[AnnotationTitle]
	profile := st.Annotations[AnnotationProfile]
	if profile == "" {
		profile = DefaultProfileName
	}
	out := sessionSummary{
		Name:         st.Name,
		Scope:        scopeOf(st),
		Title:        title,
		Profile:      profile,
		Phase:        st.Status.Phase,
		ACPSessionID: st.Annotations[AnnotationACPSession],
		Parent:       st.Annotations[AnnotationParent],
		Root:         st.Annotations[AnnotationRoot],
		Created:      st.CreationTimestamp,
		Question:     questionFromAnnotation(st),
	}
	out.Depth = sessionDepth(st)
	if latest := latestBlip(blips); latest != nil {
		out.Running = latest.Status.Phase == v1.BlipRunning || latest.Status.Phase == v1.BlipPending
		// A newer terminal generation means an older Running blip is an
		// orphan from a timed-out retry, not the current turn.
		if latest.Status.Phase != "" {
			out.Phase = latest.Status.Phase
		}
		out.Generation = generationOf(latest)
		// Status messages carry useful failure detail, but successful and
		// in-progress blips use the same field for scheduler internals such as
		// node names. Only surface it when the turn actually failed.
		if latest.Status.Phase == v1.BlipFailed {
			out.StatusMessage = latest.Status.Message
			if out.StatusMessage == "" {
				out.StatusMessage = latest.Status.Reason
			}
		}
	}
	return out
}

// questionFromAnnotation reads the durable open question. A malformed value is
// treated as no question; the driver is the authority when it is live.
func questionFromAnnotation(st *v1.BlipState) *Question {
	raw := st.Annotations[AnnotationQuestion]
	if raw == "" {
		return nil
	}
	var q Question
	if err := json.Unmarshal([]byte(raw), &q); err != nil || q.ID == "" {
		return nil
	}
	return &q
}

// sessionDepth returns the distance from the root chat. A missing or invalid
// annotation means the chat is a root.
func sessionDepth(st *v1.BlipState) int {
	n, _ := strconv.Atoi(st.Annotations[AnnotationDepth])
	return n
}

// sessionCreated returns the chat's creation time for message templates. A
// zero time is left empty instead of rendering year 1.
func sessionCreated(st *v1.BlipState) string {
	if st.CreationTimestamp.IsZero() {
		return ""
	}
	return st.CreationTimestamp.UTC().Format(time.RFC3339)
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	states, err := s.cluster.ListSessions(r.Context(), s.namespace)
	if err != nil {
		writeClusterError(w, err)
		return
	}
	blips, err := s.cluster.ListSessionBlips(r.Context(), s.namespace)
	if err != nil {
		writeClusterError(w, err)
		return
	}
	byState := make(map[string][]v1.Blip)
	for _, b := range blips {
		name := b.Labels[LabelSession]
		byState[name] = append(byState[name], b)
	}
	user := forwardedUser(r)
	out := make([]sessionSummary, 0, len(states))
	for i := range states {
		// A private chat is invisible to everyone but its owner.
		if !canAccess(&states[i], user) {
			continue
		}
		out = append(out, summarize(&states[i], byState[states[i].Name]))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Created.Equal(&out[j].Created) {
			return out[j].Created.Before(&out[i].Created)
		}
		return out[i].Name < out[j].Name
	})
	writeJSON(w, http.StatusOK, out)
}

type createRequest struct {
	Profile string `json:"profile"`
	Scope   string `json:"scope"`
}

// noBaseError reports that a profile's selector matched no usable state.
type noBaseError struct{ message string }

func (e noBaseError) Error() string { return e.message }

// pickBase returns the name of the state a new chat copies, or "" for an
// empty state. The profile's selector chooses the newest Ready state; chat
// states themselves are never used as a base.
func (s *Server) pickBase(ctx context.Context, profileName string, profile Profile) (string, error) {
	selector, err := profile.baseStateSelector()
	if err != nil {
		return "", err
	}
	if selector == nil {
		return "", nil
	}
	states, err := s.cluster.ListStates(ctx, s.namespace, selector)
	if err != nil {
		return "", err
	}
	var best *v1.BlipState
	for i := range states {
		st := &states[i]
		if st.Status.Phase != v1.StateReady {
			continue
		}
		if best == nil || st.CreationTimestamp.After(best.CreationTimestamp.Time) ||
			(st.CreationTimestamp.Time.Equal(best.CreationTimestamp.Time) && st.Name > best.Name) {
			best = st
		}
	}
	if best == nil {
		return "", noBaseError{fmt.Sprintf("profile %q: no Ready BlipState matches %s in namespace %s", profileName, selector, s.namespace)}
	}
	return best.Name, nil
}

// httpError carries the status a handler returns for a request error.
type httpError struct {
	code    int
	message string
}

func (e httpError) Error() string { return e.message }

func badRequest(format string, args ...any) error {
	return httpError{code: http.StatusBadRequest, message: fmt.Sprintf(format, args...)}
}

// chatRequest creates a chat. A nil Parent makes a top-level chat; otherwise
// Parent spawned it and the new state records the tree and its owner. Scope
// and Owner come from the request for a top-level chat and are ignored for a
// child, which inherits them from its parent.
type chatRequest struct {
	Profile string
	Scope   string
	Owner   string
	Parent  *v1.BlipState
	Title   string
}

func (s *Server) createChat(ctx context.Context, req chatRequest) (*v1.BlipState, error) {
	profileName := req.Profile
	if profileName == "" {
		profileName = DefaultProfileName
	}
	profile, ok := s.profiles[profileName]
	if !ok {
		return nil, badRequest("unknown profile %s", profileName)
	}
	profile = profile.normalized(s.defaultPool)
	if len(profile.Command) == 0 {
		return nil, badRequest("profile %s has no command", profileName)
	}

	// Admission policy authorizes a chat from its tree annotations, so they
	// come from the reviewed parent state, never from tool arguments. A child
	// inherits the parent's scope and owner verbatim, so it is always exactly
	// as visible as the chat that spawned it.
	scope := req.Scope
	ownerUser := req.Owner
	if req.Parent != nil {
		scope = scopeOf(req.Parent)
		ownerUser = req.Parent.Annotations[AnnotationUser]
	} else {
		if scope == "" {
			scope = scopeTeam
		}
		if scope != scopeTeam && scope != scopeUser {
			return nil, badRequest("scope must be %q or %q", scopeTeam, scopeUser)
		}
		if scope == scopeTeam {
			ownerUser = ""
		}
	}
	if scope == scopeUser && ownerUser == "" {
		// The HTTP handler always supplies the forwarded user. An ownerless
		// private chat could never be opened by anyone.
		return nil, badRequest("a private chat requires an owner")
	}

	name := newSessionName()
	annotations := map[string]string{
		AnnotationProfile: profileName,
		AnnotationScope:   scope,
		AnnotationRoot:    name,
		AnnotationDepth:   "0",
	}
	if scope == scopeUser {
		annotations[AnnotationUser] = ownerUser
	}
	if req.Title != "" {
		annotations[AnnotationTitle] = req.Title
	}
	labels := map[string]string{
		LabelSession:  "true",
		v1.LabelOwner: name,
	}
	var owner *metav1.OwnerReference
	if req.Parent != nil {
		labels[LabelParent] = req.Parent.Name
		annotations[AnnotationParent] = req.Parent.Name
		parentProfile := req.Parent.Annotations[AnnotationProfile]
		if parentProfile == "" {
			parentProfile = DefaultProfileName
		}
		parentDepth := 0
		if v := req.Parent.Annotations[AnnotationDepth]; v != "" {
			parentDepth, _ = strconv.Atoi(v)
		}
		root := req.Parent.Annotations[AnnotationRoot]
		if root == "" {
			root = req.Parent.Name
		}
		labels[v1.LabelOwner] = root
		annotations[AnnotationRoot] = root
		annotations[AnnotationDepth] = strconv.Itoa(parentDepth + 1)
		annotations[AnnotationParentProfile] = parentProfile
		annotations[AnnotationParentDepth] = strconv.Itoa(parentDepth)
		owner = &metav1.OwnerReference{
			APIVersion: v1.GroupVersion.String(),
			Kind:       "BlipState",
			Name:       req.Parent.Name,
			UID:        req.Parent.UID,
		}
	}
	fork := req.Parent != nil && profile.Workspace == WorkspaceFork
	base := ""
	if !fork {
		var err error
		base, err = s.pickBase(ctx, profileName, profile)
		if err != nil {
			return nil, err
		}
		if base != "" {
			annotations[AnnotationBase] = base
		}
	}

	var created *v1.BlipState
	for attempt := 0; attempt < 5; attempt++ {
		state := &v1.BlipState{
			ObjectMeta: metav1.ObjectMeta{
				Name:        name,
				Namespace:   s.namespace,
				Labels:      labels,
				Annotations: annotations,
			},
			Spec: v1.BlipStateSpec{CopyFrom: base},
		}
		var err error
		if fork {
			err = s.cluster.ForkSession(ctx, s.namespace, req.Parent, state, owner)
		} else {
			if owner != nil {
				state.OwnerReferences = []metav1.OwnerReference{*owner}
			}
			err = s.cluster.CreateSession(ctx, s.namespace, state)
		}
		if apierrors.IsAlreadyExists(err) {
			// The name is random, so a collision is rare. A root's owner and
			// root annotation must follow the replacement name.
			name = newSessionName()
			if req.Parent == nil {
				labels[v1.LabelOwner] = name
				annotations[AnnotationRoot] = name
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		created = state
		break
	}
	if created == nil {
		return nil, httpError{code: http.StatusInternalServerError, message: "could not allocate a session name"}
	}
	return created, nil
}

func writeChatError(w http.ResponseWriter, err error) {
	var he httpError
	if errors.As(err, &he) {
		writeError(w, he.code, he.message)
		return
	}
	var noBase noBaseError
	if errors.As(err, &noBase) {
		writeError(w, http.StatusConflict, noBase.message)
		return
	}
	writeClusterError(w, err)
}

func (s *Server) handleCreateSession(w http.ResponseWriter, r *http.Request) {
	var req createRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	created, err := s.createChat(r.Context(), chatRequest{
		Profile: req.Profile,
		Scope:   req.Scope,
		Owner:   forwardedUser(r),
	})
	if err != nil {
		writeChatError(w, err)
		return
	}
	// Do not start an agent here. A chat with no messages has no turn to
	// run, and eager VMs make merely opening a chat consume a pool slot. The
	// first POST .../message creates the driver and starts the agent.
	writeJSON(w, http.StatusCreated, map[string]string{"name": created.Name, "namespace": created.Namespace})
}

// newSessionName returns a unique name that does not depend on a title: the
// agent names the chat once the conversation has started.
func newSessionName() string {
	var b [3]byte
	_, _ = rand.Read(b[:])
	return "chat-" + hex.EncodeToString(b[:])
}

func (s *Server) handleProfiles(w http.ResponseWriter, r *http.Request) {
	type info struct {
		Name        string `json:"name"`
		Title       string `json:"title"`
		Description string `json:"description,omitempty"`
		Pool        string `json:"pool"`
		Default     bool   `json:"default"`
	}
	out := make([]info, 0, len(s.profiles))
	for name, p := range s.profiles {
		out = append(out, info{Name: name, Title: p.Title, Description: p.Description, Pool: p.Pool, Default: name == DefaultProfileName})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Default != out[j].Default {
			return out[i].Default
		}
		return out[i].Name < out[j].Name
	})
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetSession(w http.ResponseWriter, r *http.Request) {
	name, ok := s.sessionArgs(w, r)
	if !ok {
		return
	}
	st, err := s.authorizedChat(r.Context(), forwardedUser(r), name)
	if err != nil {
		writeClusterError(w, err)
		return
	}
	blips, err := s.cluster.ListStateBlips(r.Context(), s.namespace, name)
	if err != nil {
		writeClusterError(w, err)
		return
	}
	detail := sessionDetail{sessionSummary: summarize(st, blips)}
	// Use the driver snapshot even when this is the first request for the chat.
	// Creating the driver here seeds its transcript from the durable log and
	// sets the offset to the hub's sequence. Returning a replay with offset 0
	// instead would make the UI open SSE at 0 while the driver starts reading
	// after the last record, losing the final events of a finished turn.
	d, err := s.driverFor(r.Context(), name)
	if err != nil {
		writeClusterError(w, err)
		return
	}
	var idle bool
	detail.Transcript, detail.Offset, idle = d.Snapshot()
	detail.TranscriptTruncated = d.TranscriptTruncated()
	// The live driver is the authority: the annotation can lag while it is
	// being cleared, and a just-restarted driver loads it before serving.
	detail.Question = d.Question()
	if detail.Transcript == nil {
		detail.Transcript = []json.RawMessage{}
	}
	// A Blip can remain Running briefly after the driver has already
	// delivered the terminal events. The SSE offset and transcript are
	// authoritative; clear the stale running flag so a freshly opened page
	// does not wait forever for a status event that is already behind it.
	if idle {
		detail.Running = false
		// The state can still be InUse/Saving while the last Blip finishes,
		// and an early snapshot can point past the driver's initial Stopped
		// status while the latest Blip is still Pending. Those are lifecycle
		// phases, not an active chat turn. Normalize anything that is not a
		// terminal success/failure to Saving so a freshly opened page is idle.
		switch detail.Phase {
		case string(v1.BlipFailed), "Error",
			string(v1.BlipSucceeded), "Stopped":
			// Keep terminal phases for status/detail.
		default:
			detail.Phase = string(v1.BlipSaving)
		}
	}
	writeJSON(w, http.StatusOK, detail)
}

func (s *Server) sessionArgs(w http.ResponseWriter, r *http.Request) (name string, ok bool) {
	name = r.PathValue("name")
	if !validDNSLabel(name) {
		writeError(w, http.StatusBadRequest, "session name must be a valid DNS label")
		return "", false
	}
	return name, true
}

// authorizedChat returns a chat if user may use it. A chat the user may not see
// is reported as not found so its existence does not leak.
func (s *Server) authorizedChat(ctx context.Context, user, name string) (*v1.BlipState, error) {
	st, err := s.chatState(ctx, s.namespace, name)
	if err != nil {
		return nil, err
	}
	if !canAccess(st, user) {
		return nil, apierrors.NewNotFound(v1.GroupVersion.WithResource("blipstates").GroupResource(), name)
	}
	return st, nil
}

func (s *Server) chatState(ctx context.Context, ns, name string) (*v1.BlipState, error) {
	st, err := s.cluster.GetSession(ctx, ns, name)
	if err != nil {
		return nil, err
	}
	if st.Labels[LabelSession] != "true" || !isChatState(st) {
		return nil, apierrors.NewNotFound(v1.GroupVersion.WithResource("blipstates").GroupResource(), name)
	}
	return st, nil
}

// backfillChat fills the tree metadata that older chats did not record. It is
// deliberately limited to a state that is already recognizably a chat; hidden
// fork mount states copy the session label but none of these annotations and
// must not become visible as chats.
func (s *Server) backfillChat(ctx context.Context, st *v1.BlipState) {
	if st.Labels[LabelSession] != "true" || !isChatState(st) {
		return
	}
	labels := map[string]string{}
	annotations := map[string]string{}
	if st.Annotations[AnnotationProfile] == "" {
		annotations[AnnotationProfile] = DefaultProfileName
	}
	if st.Annotations[AnnotationParent] == "" {
		if st.Labels[v1.LabelOwner] == "" {
			labels[v1.LabelOwner] = st.Name
		}
		if st.Annotations[AnnotationRoot] == "" {
			annotations[AnnotationRoot] = st.Name
		}
		if st.Annotations[AnnotationDepth] == "" {
			annotations[AnnotationDepth] = "0"
		}
	} else if st.Labels[v1.LabelOwner] == "" && st.Annotations[AnnotationRoot] != "" {
		labels[v1.LabelOwner] = st.Annotations[AnnotationRoot]
	}
	if len(labels) > 0 || len(annotations) > 0 {
		if err := s.cluster.PatchSession(ctx, st.Namespace, st.Name, labels, annotations); err != nil {
			s.log.Warn("backfill chat metadata", "session", st.Name, "err", err)
			return
		}
		for k, v := range labels {
			if st.Labels == nil {
				st.Labels = map[string]string{}
			}
			st.Labels[k] = v
		}
		for k, v := range annotations {
			if st.Annotations == nil {
				st.Annotations = map[string]string{}
			}
			st.Annotations[k] = v
		}
	}
	owner := st.Labels[v1.LabelOwner]
	if owner == "" {
		return
	}
	blips, err := s.cluster.ListStateBlips(ctx, st.Namespace, st.Name)
	if err != nil {
		s.log.Warn("list chat blips", "session", st.Name, "err", err)
		return
	}
	for i := range blips {
		if blips[i].Labels[v1.LabelOwner] == owner {
			continue
		}
		if err := s.cluster.PatchBlip(ctx, st.Namespace, blips[i].Name, map[string]string{v1.LabelOwner: owner}, nil); err != nil {
			s.log.Warn("backfill chat blip owner", "blip", blips[i].Name, "err", err)
		}
	}
}

func (s *Server) driverFor(ctx context.Context, name string) (*driver, error) {
	s.mu.Lock()
	if d := s.drivers[name]; d != nil {
		s.mu.Unlock()
		return d, nil
	}
	s.mu.Unlock()

	st, err := s.chatState(ctx, s.namespace, name)
	if err != nil {
		return nil, err
	}
	s.backfillChat(ctx, st)
	profileName := st.Annotations[AnnotationProfile]
	if profileName == "" {
		profileName = DefaultProfileName
	}
	offset, haveOffset := uint64(0), false
	if v := st.Annotations[AnnotationOffset]; v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			offset, haveOffset = n, true
		}
	}
	profile, configured := s.profiles[profileName]
	var unavailable error
	if configured {
		profile = profile.normalized(s.defaultPool)
	} else {
		unavailable = fmt.Errorf("%w: profile %q", errProfileUnavailable, profileName)
	}
	if !haveOffset {
		// Existing chats may predate the persisted offset annotation, and a
		// forked chat copies its parent's trajectory ring. Start after the
		// records already in the log instead of replaying them into the agent.
		if end, err := s.wire.LogEnd(ctx, s.namespace, name); err == nil && end > 0 {
			offset, haveOffset = end, true
			if err := s.cluster.PatchSession(ctx, s.namespace, name, nil, map[string]string{AnnotationOffset: strconv.FormatUint(end, 10)}); err != nil {
				s.log.Debug("save initial offset", "session", name, "err", err)
			}
		} else if err != nil {
			s.log.Warn("read log end", "session", name, "err", err)
		}
	}
	// Seed from the durable log so a driver created after a restart still
	// serves the conversation history. A forked chat's log begins with the
	// parent's records copied at fork time and showed those in its transcript
	// before the restart, so replay them too instead of losing the history.
	var transcript []json.RawMessage
	var transcriptTruncated bool
	if offset > 0 {
		transcript, transcriptTruncated = replayTranscript(ctx, s.wire, s.namespace, name)
	}
	var pending []PendingPrompt
	if s.pending != nil {
		pending, err = s.pending.LoadPending(ctx, s.namespace, name)
		if err != nil {
			s.log.Warn("load pending prompts", "session", name, "err", err)
		}
	}
	d := newDriver(driverOptions{
		Cluster:             s.cluster,
		Wire:                s.wire,
		Hub:                 NewHub(),
		Log:                 s.log,
		Namespace:           s.namespace,
		State:               name,
		ProfileName:         profileName,
		Profile:             profile,
		Unavailable:         unavailable,
		Base:                st.Annotations[AnnotationBase],
		Parent:              st.Annotations[AnnotationParent],
		Root:                st.Annotations[AnnotationRoot],
		Depth:               sessionDepth(st),
		Created:             sessionCreated(st),
		AutoApprove:         s.autoApprove,
		SessionID:           st.Annotations[AnnotationACPSession],
		Title:               st.Annotations[AnnotationTitle],
		Offset:              offset,
		HaveOffset:          haveOffset,
		MCPServers:          s.mcpServers(),
		Transcript:          transcript,
		TranscriptTruncated: transcriptTruncated,
		Pending:             s.pending,
		PendingPrompts:      pending,
		Question:            questionFromAnnotation(st),
		QuestionTimeout:     s.questionTTL,
	})

	s.mu.Lock()
	if existing := s.drivers[name]; existing != nil {
		s.mu.Unlock()
		d.Close()
		return existing, nil
	}
	s.drivers[name] = d
	s.mu.Unlock()
	d.start(s.ctx)
	d.resume()
	return d, nil
}

func (s *Server) lookupDriver(name string) *driver {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.drivers[name]
}

func (s *Server) handleMessage(w http.ResponseWriter, r *http.Request) {
	name, ok := s.sessionArgs(w, r)
	if !ok {
		return
	}
	if _, err := s.authorizedChat(r.Context(), forwardedUser(r), name); err != nil {
		writeClusterError(w, err)
		return
	}
	var req struct {
		Text string `json:"text"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	text := strings.TrimSpace(req.Text)
	if text == "" {
		writeError(w, http.StatusBadRequest, "text is required")
		return
	}
	if len(text) > 32000 {
		writeError(w, http.StatusBadRequest, "text is too long")
		return
	}
	d, err := s.driverFor(r.Context(), name)
	if err != nil {
		writeClusterError(w, err)
		return
	}
	// While a question is open, a message from the composer is its answer.
	// A message that arrives after the question was already answered is
	// handled as an ordinary prompt below.
	if d.Question() != nil {
		err := d.Answer(forwardedUser(r), text)
		if err == nil {
			writeJSON(w, http.StatusAccepted, map[string]bool{"accepted": true})
			return
		}
		if !errors.Is(err, errNoQuestion) {
			switch {
			case errors.Is(err, errSessionBusy):
				writeError(w, http.StatusServiceUnavailable, "session is busy")
			default:
				s.log.Error("answer question", "namespace", s.namespace, "session", name, "err", err)
				writeError(w, http.StatusInternalServerError, "could not deliver the answer")
			}
			return
		}
	}
	if err := d.SubmitAs(forwardedUser(r), text); err != nil {
		switch {
		case errors.Is(err, errSessionBusy):
			writeError(w, http.StatusServiceUnavailable, "session is busy")
		case errors.Is(err, errMessageTooLong):
			writeError(w, http.StatusBadRequest, "text is too long")
		case errors.Is(err, errProfileUnavailable):
			writeError(w, http.StatusConflict, err.Error())
		default:
			s.log.Error("prepare message", "namespace", s.namespace, "session", name, "err", err)
			writeError(w, http.StatusInternalServerError, "could not prepare message")
		}
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"accepted": true})
}

func (s *Server) handleCancel(w http.ResponseWriter, r *http.Request) {
	name, ok := s.sessionArgs(w, r)
	if !ok {
		return
	}
	if _, err := s.authorizedChat(r.Context(), forwardedUser(r), name); err != nil {
		writeClusterError(w, err)
		return
	}
	d, err := s.driverFor(r.Context(), name)
	if err != nil {
		writeClusterError(w, err)
		return
	}
	if !d.Cancel() {
		writeError(w, http.StatusServiceUnavailable, "session is busy")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"accepted": true})
}

func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	name, ok := s.sessionArgs(w, r)
	if !ok {
		return
	}
	if _, err := s.authorizedChat(r.Context(), forwardedUser(r), name); err != nil {
		writeClusterError(w, err)
		return
	}
	d, err := s.driverFor(r.Context(), name)
	if err != nil {
		writeClusterError(w, err)
		return
	}
	if !d.Stop() {
		writeError(w, http.StatusServiceUnavailable, "session is busy")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"accepted": true})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	name, ok := s.sessionArgs(w, r)
	if !ok {
		return
	}
	if _, err := s.authorizedChat(r.Context(), forwardedUser(r), name); err != nil {
		writeClusterError(w, err)
		return
	}
	d, err := s.driverFor(r.Context(), name)
	if err != nil {
		writeClusterError(w, err)
		return
	}
	after, err := eventOffset(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming is not supported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Vary", "X-Forwarded-User")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	// SSE outlives the server's normal write timeout. The heartbeat below
	// detects a dead client instead.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})

	replay, ch, cancel := d.hub.Subscribe(after)
	defer cancel()
	if _, err := fmt.Fprint(w, "retry: 3000\n\n"); err != nil {
		return
	}
	flusher.Flush()
	for _, ev := range replay {
		if !writeSSE(w, flusher, ev) {
			return
		}
	}
	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-d.ctx.Done():
			return
		case ev, open := <-ch:
			if !open {
				return
			}
			if !writeSSE(w, flusher, ev) {
				return
			}
		case <-heartbeat.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func eventOffset(r *http.Request) (uint64, error) {
	raw := r.URL.Query().Get("offset")
	if last := r.Header.Get("Last-Event-ID"); last != "" {
		raw = last
	}
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("offset must be a non-negative integer")
	}
	return n, nil
}

func writeSSE(w http.ResponseWriter, flusher http.Flusher, ev Event) bool {
	data, err := json.Marshal(ev)
	if err != nil {
		return false
	}
	if _, err := fmt.Fprintf(w, "id: %d\ndata: %s\n\n", ev.Offset, data); err != nil {
		return false
	}
	flusher.Flush()
	return true
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || (mediaType != "application/json" && !strings.HasSuffix(mediaType, "+json")) {
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
	var raw json.RawMessage
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&raw); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body is too large")
			return false
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body is too large")
			return false
		}
		writeError(w, http.StatusBadRequest, "body must contain one JSON value")
		return false
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Vary", "X-Forwarded-User")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, message string) {
	writeJSON(w, code, map[string]string{"error": message})
}

func methodNotAllowed(allow string) http.HandlerFunc {
	if strings.Contains(allow, "GET") && !strings.Contains(allow, "HEAD") {
		allow += ", HEAD"
	}
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Allow", allow)
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func writeClusterError(w http.ResponseWriter, err error) {
	switch {
	case apierrors.IsNotFound(err):
		writeError(w, http.StatusNotFound, "not found")
	case apierrors.IsForbidden(err):
		writeError(w, http.StatusForbidden, err.Error())
	case apierrors.IsConflict(err):
		writeError(w, http.StatusConflict, err.Error())
	default:
		writeError(w, http.StatusBadGateway, err.Error())
	}
}
