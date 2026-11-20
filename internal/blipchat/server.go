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
	// Service names the Kubernetes Service whose ready endpoints are the
	// blipchat replicas. Empty disables sharding: every replica drives every
	// chat, which the node's serialized appends make safe for a single pod.
	Service string
	// ServiceNamespace is the namespace of Service. Empty uses Namespace.
	ServiceNamespace string
	// PodName is this replica's name in the endpoint list. It comes from the
	// POD_NAME downward-API variable.
	PodName string
}

// Server is the HTTP front end and the owner of the per-chat engines.
type Server struct {
	namespace   string
	basePath    string
	profiles    Profiles
	defaultPool string
	autoApprove string
	cluster     Cluster
	wire        Wire
	log         *slog.Logger
	callers     Callers
	mcpURL      string
	questionTTL time.Duration
	shards      *sharder

	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	engines map[string]*chatEngine

	viewsMu sync.Mutex
	views   map[string]cachedChatView
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
	if opts.ServiceNamespace == "" {
		opts.ServiceNamespace = opts.Namespace
	}
	s := &Server{
		namespace:   opts.Namespace,
		basePath:    basePath,
		profiles:    opts.Profiles,
		defaultPool: opts.DefaultPool,
		autoApprove: opts.AutoApprove,
		cluster:     opts.Cluster,
		wire:        opts.Wire,
		log:         opts.Log,
		callers:     opts.Callers,
		mcpURL:      opts.MCPURL,
		questionTTL: opts.QuestionTimeout,
		ctx:         ctx,
		cancel:      cancel,
		engines:     make(map[string]*chatEngine),
		views:       make(map[string]cachedChatView),
	}
	if opts.Service != "" {
		if opts.PodName == "" {
			// Without knowing which endpoint this replica is, every replica
			// would think it owns every chat and duplicate work.
			return nil, fmt.Errorf("pod name is required when service is set")
		}
		s.shards = newSharder(opts.Cluster, opts.ServiceNamespace, opts.Service, opts.PodName, opts.Log)
	}
	s.ready.Store(true)
	return s, nil
}

// Start installs the serving context and starts the supervisor that keeps
// engines running for this replica's chats. It is optional; New installs a
// background context so tests can use the handler directly.
func (s *Server) Start(ctx context.Context) {
	s.cancel()
	s.ctx, s.cancel = context.WithCancel(ctx)
	if s.shards != nil {
		go s.shards.run(s.ctx)
	}
	go s.supervise(s.ctx)
}

func (s *Server) Close() {
	s.cancel()
	s.mu.Lock()
	engines := make([]*chatEngine, 0, len(s.engines))
	for _, e := range s.engines {
		engines = append(engines, e)
	}
	s.engines = make(map[string]*chatEngine)
	s.mu.Unlock()
	for _, e := range engines {
		e.cancel()
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

// reconcileSessionSummary refines a cluster summary with a trajectory snapshot.
// An end record can precede the controller's terminal status, but only ends its
// own generation. Terminal execution results (including failures on a Ready
// workspace) and summaries without a matching ended execution are unchanged.
// It performs no reads and does not change the supplied view.
func reconcileSessionSummary(summary sessionSummary, view *chatView) sessionSummary {
	if view != nil && summary.Running && summary.Generation == int64(view.Gen) && !view.Started && view.Ended {
		summary.Running = false
		summary.Phase = string(v1.BlipSaving)
	}
	return summary
}

// withQuestion fills in the open question for a live chat and reconciles an
// ended execution. The ring is the only source of truth for questions.
func withQuestion(ctx context.Context, s *Server, st *v1.BlipState, summary sessionSummary) sessionSummary {
	if !summary.Running {
		return summary
	}
	view := s.readView(ctx, st)
	summary.Question = view.Question
	return reconcileSessionSummary(summary, view)
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
		out = append(out, withQuestion(r.Context(), s, &states[i], summarize(&states[i], byState[states[i].Name])))
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
	Title   string `json:"title"`
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
	// A fork or a copy inherits the source's trajectory. Record where that
	// history ends, before the chat can accept a message, so the engine never
	// mistakes the source's prompts for this chat's work. The copy is
	// asynchronous, so wait for the state to be ready first: LogEnd fails
	// until the node has committed the copied volume.
	if fork || base != "" {
		if err := s.waitStateReady(ctx, s.namespace, created.Name); err != nil {
			return nil, err
		}
		var end uint64
		var err error
		for attempt := 0; attempt < 20; attempt++ {
			end, err = s.wire.LogEnd(ctx, s.namespace, created.Name)
			if err == nil {
				break
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			time.Sleep(100 * time.Millisecond)
		}
		if err != nil {
			// Starting the engine at zero would replay the source's prompts.
			return nil, fmt.Errorf("read inherited trajectory for %s: %w", created.Name, err)
		}
		if end > 0 {
			start := strconv.FormatUint(end, 10)
			if err := s.cluster.PatchSession(ctx, s.namespace, created.Name, nil, map[string]string{AnnotationStart: start}); err != nil {
				return nil, err
			}
			if created.Annotations == nil {
				created.Annotations = map[string]string{}
			}
			created.Annotations[AnnotationStart] = start
		}
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
		Title:   strings.TrimSpace(req.Title),
	})
	if err != nil {
		writeChatError(w, err)
		return
	}
	// Do not start an agent here. A chat with no messages has no turn to
	// run, and eager VMs make merely opening a chat consume a pool slot. The
	// first POST .../message writes a note and starts the agent.
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
	// The ring is the durable transcript and event log; there is no per-pod
	// driver state to lose. Offset is the newest record so a client can open
	// the event stream exactly where this snapshot ends.
	view := s.readView(r.Context(), st)
	detail.Transcript = view.Transcript
	if detail.Transcript == nil {
		detail.Transcript = []json.RawMessage{}
	}
	detail.Offset = view.Newest
	detail.TranscriptTruncated = view.Truncated || view.Gapped
	detail.Question = view.Question
	detail.sessionSummary = reconcileSessionSummary(detail.sessionSummary, view)
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

func (s *Server) handleMessage(w http.ResponseWriter, r *http.Request) {
	name, ok := s.sessionArgs(w, r)
	if !ok {
		return
	}
	user := forwardedUser(r)
	st, err := s.authorizedChat(r.Context(), user, name)
	if err != nil {
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
	profile, err := s.profileFor(st)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	view := s.readView(r.Context(), st)
	// Once accepted, the write must outlive the client connection: starting a
	// VM can take longer than the browser waits.
	writeCtx, cancel := messageContext(r)
	defer cancel()
	// While a question is open, a message from the composer is its answer.
	if view.Question != nil {
		note := noteRecord{Type: noteAnswer, QID: view.Question.ID, Text: text, Sender: user, Gen: view.questionGen(view.Question.ID)}
		if err := s.appendNote(writeCtx, st, profile, note); err != nil {
			s.writeNoteError(w, "answer question", name, err)
			return
		}
		s.ensureEngine(name)
		writeJSON(w, http.StatusAccepted, map[string]bool{"accepted": true})
		return
	}
	if len(view.Queued) >= maxQueue {
		writeError(w, http.StatusServiceUnavailable, "session is busy")
		return
	}
	note, err := s.promptNote(st, profile, user, text)
	if err != nil {
		if errors.Is(err, errMessageTooLong) {
			writeError(w, http.StatusBadRequest, "text is too long")
			return
		}
		s.log.Error("render message", "namespace", s.namespace, "session", name, "err", err)
		writeError(w, http.StatusInternalServerError, "could not prepare message")
		return
	}
	if err := s.appendNote(writeCtx, st, profile, note); err != nil {
		s.writeNoteError(w, "submit message", name, err)
		return
	}
	// The note and its running blip exist; start the driver now instead of
	// waiting for the next supervisor pass.
	s.ensureEngine(name)
	writeJSON(w, http.StatusAccepted, map[string]bool{"accepted": true})
}

// messageContext detaches an accepted message from the client connection. A
// note write can wait for a VM to start, and the client may disconnect (or the
// browser may abort) while that is in flight; the message has already been
// accepted and must still land in the ring.
func messageContext(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(r.Context()), startTimeout+30*time.Second)
}

func (s *Server) writeNoteError(w http.ResponseWriter, action, name string, err error) {
	switch {
	case errors.Is(err, errSessionBusy), errors.Is(err, ErrNotRunning):
		writeError(w, http.StatusServiceUnavailable, "session is busy")
	case errors.Is(err, errMessageTooLong):
		writeError(w, http.StatusBadRequest, "text is too long")
	case errors.Is(err, errProfileUnavailable):
		writeError(w, http.StatusConflict, err.Error())
	default:
		s.log.Error(action, "namespace", s.namespace, "session", name, "err", err)
		writeError(w, http.StatusInternalServerError, "could not deliver the message")
	}
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
	// A cancel is a note, so it is delivered by whichever replica drives the
	// chat. A chat that is not running has nothing to cancel.
	writeCtx, cancel := messageContext(r)
	defer cancel()
	if _, err := s.writeNote(writeCtx, name, noteRecord{Type: noteCancel}); err != nil && !errors.Is(err, ErrNotRunning) {
		s.log.Error("cancel turn", "namespace", s.namespace, "session", name, "err", err)
		writeError(w, http.StatusInternalServerError, "could not cancel the turn")
		return
	}
	s.ensureEngine(name)
	writeJSON(w, http.StatusAccepted, map[string]bool{"accepted": true})
}

func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	name, ok := s.sessionArgs(w, r)
	if !ok {
		return
	}
	st, err := s.authorizedChat(r.Context(), forwardedUser(r), name)
	if err != nil {
		writeClusterError(w, err)
		return
	}
	writeCtx, cancel := messageContext(r)
	defer cancel()
	if view := s.readView(r.Context(), st); view.hasWork() {
		// With queued work a blip may not be attached right now. Recording
		// the stop through appendNote starts one if needed, so the queued
		// prompts are actually dropped instead of running after the stop.
		if profile, perr := s.profileFor(st); perr == nil {
			if err := s.appendNote(writeCtx, st, profile, noteRecord{Type: noteStop}); err != nil {
				s.log.Warn("record stop", "session", name, "error", err)
			}
		}
	} else {
		if _, err := s.writeNote(writeCtx, name, noteRecord{Type: noteStop}); err != nil && !errors.Is(err, ErrNotRunning) {
			s.log.Warn("record stop", "session", name, "error", err)
		}
	}
	if err := s.stopBlip(writeCtx, name); err != nil {
		writeClusterError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"accepted": true})
}

// handleEvents follows the ring and converts each record to the same SSE event
// shape the UI has always received. Offsets are ring offsets, so a client can
// reconnect to any replica with its Last-Event-ID.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	name, ok := s.sessionArgs(w, r)
	if !ok {
		return
	}
	st, err := s.authorizedChat(r.Context(), forwardedUser(r), name)
	if err != nil {
		writeClusterError(w, err)
		return
	}
	after, err := eventOffset(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	seen := after != 0
	if !seen {
		// A client with no cursor starts at this chat's first record, not at
		// the base's records a fork inherited.
		after = chatStart(st)
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
	if _, err := fmt.Fprint(w, "retry: 3000\n\n"); err != nil {
		return
	}
	flusher.Flush()

	ctx := r.Context()
	view := newChatView(st.Annotations[AnnotationACPSession])
	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()
	next := after
	last := after
	for {
		rc, err := s.wire.OpenLog(ctx, s.namespace, name, next)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.log.Debug("open chat log", "session", name, "err", err)
			select {
			case <-ctx.Done():
				return
			case <-heartbeat.C:
				if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
					return
				}
				flusher.Flush()
			case <-time.After(readRetry):
			}
			continue
		}
		records := streamRecords(ctx, rc)
		for {
			select {
			case <-ctx.Done():
				return
			case <-heartbeat.C:
				if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
					return
				}
				flusher.Flush()
			case res, open := <-records:
				if !open {
					goto reconnect
				}
				if res.err != nil {
					continue
				}
				if seen && res.rec.Offset <= last {
					// The follow stream is inclusive: skip the event the
					// client already received.
					continue
				}
				view.observe(res.rec)
				for _, ev := range eventsFor(res.rec, view) {
					if !writeSSE(w, flusher, ev) {
						return
					}
				}
				seen = true
				last = res.rec.Offset
				next = res.rec.Offset
			}
		}
	reconnect:
		select {
		case <-ctx.Done():
			return
		case <-time.After(readRetry):
		}
	}
}

// eventsFor renders one record as SSE events. Input frames other than a
// session/prompt are client traffic the UI has never shown.
func eventsFor(rec streamLogRecord, view *chatView) []Event {
	switch rec.Type {
	case recordStart:
		return []Event{{Offset: rec.Offset, Type: "status", Status: &Status{Phase: string(v1.BlipRunning), Running: true}}}
	case recordEnd:
		return []Event{{Offset: rec.Offset, Type: "status", Status: &Status{Running: false}}}
	case recordGap:
		return []Event{{Offset: rec.Offset, Type: "gap"}}
	case recordNote:
		var note noteRecord
		if err := json.Unmarshal(rec.Data, &note); err != nil {
			return nil
		}
		out := make([]Event, 0, len(view.emitted)+1)
		for _, message := range view.emitted {
			out = append(out, Event{Offset: rec.Offset, Type: "acp", Message: message})
		}
		switch note.Type {
		case noteQuestion, noteAnswer, noteConsumed, noteExpire:
			out = append(out, Event{Offset: rec.Offset, Type: "status", Status: &Status{Running: view.Started, Question: view.Question}})
		}
		return out
	case recordIn, recordOut, recordErr:
		out := make([]Event, 0, len(view.emitted))
		for _, message := range view.emitted {
			out = append(out, Event{Offset: rec.Offset, Type: "acp", Message: message})
		}
		return out
	}
	return nil
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
