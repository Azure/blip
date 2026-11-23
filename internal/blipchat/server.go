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
	// ChatRetention is how long to keep a chat after its latest Blip finishes.
	// Zero disables automatic deletion.
	ChatRetention time.Duration
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
	namespace     string
	basePath      string
	profiles      Profiles
	defaultPool   string
	autoApprove   string
	cluster       Cluster
	wire          Wire
	log           *slog.Logger
	callers       Callers
	mcpURL        string
	questionTTL   time.Duration
	chatRetention time.Duration
	shards        *sharder

	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	engines map[string]*chatEngine

	viewsMu sync.Mutex
	views   map[string]cachedChatView
	ready   atomic.Bool
}

func New(opts Options) (*Server, error) {
	if opts.ChatRetention < 0 {
		return nil, errors.New("--chat-retention must not be negative")
	}
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
		namespace:     opts.Namespace,
		basePath:      basePath,
		profiles:      opts.Profiles,
		defaultPool:   opts.DefaultPool,
		autoApprove:   opts.AutoApprove,
		cluster:       opts.Cluster,
		wire:          opts.Wire,
		log:           opts.Log,
		callers:       opts.Callers,
		mcpURL:        opts.MCPURL,
		questionTTL:   opts.QuestionTimeout,
		chatRetention: opts.ChatRetention,
		ctx:           ctx,
		cancel:        cancel,
		engines:       make(map[string]*chatEngine),
		views:         make(map[string]cachedChatView),
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
	api.HandleFunc("DELETE /api/sessions/{name}", s.handleDeleteSession)
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
	api.HandleFunc("/api/sessions/{name}", methodNotAllowed("GET, DELETE"))
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
	// streamGen is the trajectory generation written by the latest execution.
	// Generation orders VM attempts and is not comparable to the stream's.
	streamGen uint64
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
		if gen, ok := writeGeneration(st, latest); ok {
			out.streamGen = gen
		}
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
	if view != nil && summary.Running && summary.streamGen != 0 && summary.streamGen == view.Gen && !view.Started && view.Ended {
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
	view, _ := s.readView(ctx, st)
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

// pickBase returns the state a new chat copies, or nil for an
// empty state. The profile's selector chooses the newest Ready state; chat
// states themselves are never used as a base.
func (s *Server) pickBase(ctx context.Context, profileName string, profile Profile) (*v1.BlipState, error) {
	selector, err := profile.baseStateSelector()
	if err != nil {
		return nil, err
	}
	if selector == nil {
		return nil, nil
	}
	states, err := s.cluster.ListStates(ctx, s.namespace, selector)
	if err != nil {
		return nil, err
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
		return nil, noBaseError{fmt.Sprintf("profile %q: no Ready BlipState matches %s in namespace %s", profileName, selector, s.namespace)}
	}
	return best, nil
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
	// Resolve every declared mount before creating anything, so a missing
	// source fails the request cleanly instead of leaving a half-built chat.
	// A fork already inherits its parent's mounts at the same paths, so those
	// profile mounts need no source and are left to the fork.
	fork := req.Parent != nil && profile.Workspace == WorkspaceFork
	mountProfile := profile
	if fork {
		inherited := map[string]bool{}
		for _, m := range req.Parent.Spec.Mounts {
			if m.BlipUID == "" {
				inherited[m.Path] = true
			}
		}
		mountProfile.Mounts = nil
		for _, m := range profile.Mounts {
			if !inherited[m.Path] {
				mountProfile.Mounts = append(mountProfile.Mounts, m)
			}
		}
	}
	mounts, err := s.resolveProfileMounts(ctx, profileName, mountProfile)
	if err != nil {
		return nil, err
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
	base := ""
	var runtime *v1.RuntimeDefaults
	if !fork {
		selected, err := s.pickBase(ctx, profileName, profile)
		if err != nil {
			return nil, err
		}
		if selected != nil {
			base = selected.Name
			runtime = selected.Spec.Runtime
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
			Spec: v1.BlipStateSpec{CopyFrom: base, Runtime: runtime.DeepCopy()},
		}
		var err error
		if req.Parent != nil {
			if err := s.touchChat(ctx, req.Parent); err != nil {
				return nil, err
			}
		}
		createCtx, cancel := context.WithTimeout(ctx, chatAdmissionTimeout)
		if fork {
			err = s.cluster.ForkSession(createCtx, s.namespace, req.Parent, state, owner)
		} else {
			if owner != nil {
				state.OwnerReferences = []metav1.OwnerReference{*owner}
			}
			err = s.cluster.CreateSession(createCtx, s.namespace, state)
		}
		cancel()
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
	if err := s.attachProfileMounts(ctx, created, mounts); err != nil {
		// The chat cannot provide the workspace its profile promises, and its
		// mount copies are owned by it, so remove it before returning.
		deleteCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		if delErr := s.cluster.DeleteSession(deleteCtx, s.namespace, created.Name, created.UID); delErr != nil && !apierrors.IsNotFound(delErr) {
			err = errors.Join(err, delErr)
		}
		cancel()
		return nil, err
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
// chat is named from its first message.
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
	view, ok := s.displayView(r.Context(), st)
	if !ok {
		// A failed, partial, or empty-despite-history replay must never be
		// presented as the conversation. The UI treats 5xx as transient and
		// retries; serving an empty transcript would instead claim the chat
		// has no messages and enable the composer against it.
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusServiceUnavailable, "the chat transcript is temporarily unavailable")
		return
	}
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
	// A chat that is being deleted is gone as far as the API is concerned, so
	// the UI stops reading it instead of racing the finalizer.
	if st.DeletionTimestamp != nil {
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

// fallbackTitle names a chat after the first non-empty line of a message.
// An agent title, when an agent sends one, replaces it.
func fallbackTitle(text string) string {
	for _, line := range strings.Split(text, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			return shorten(line, 80)
		}
	}
	return ""
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
	// Once accepted, the write must outlive the client connection: starting a
	// VM can take longer than the browser waits.
	writeCtx, cancel := messageContext(r)
	defer cancel()
	if err := s.appendMessage(writeCtx, st, profile, user, text); err != nil {
		s.writeNoteError(w, "submit message", name, err)
		return
	}
	if st.Annotations[AnnotationTitle] == "" {
		if title := fallbackTitle(text); title != "" {
			if err := s.cluster.PatchSession(writeCtx, st.Namespace, name, nil, map[string]string{AnnotationTitle: title}); err != nil {
				s.log.Warn("set chat title", "session", name, "err", err)
			}
		}
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
	if _, err := s.writeNote(writeCtx, name, noteRecord{Type: noteCancel}); err != nil {
		if !errors.Is(err, ErrNotRunning) {
			s.log.Error("cancel turn", "namespace", s.namespace, "session", name, "err", err)
			writeError(w, http.StatusInternalServerError, "could not cancel the turn")
			return
		}
		// No writer accepted the note because the message is still Pending.
		// Record the ring boundary a stop uses so the prompt submitted before
		// this cancel is dropped when the generation attaches, and stop that
		// generation instead of letting it run the turn.
		recordErr := s.recordOfflineStop(writeCtx, name)
		if stopErr := s.stopBlip(writeCtx, name); stopErr != nil {
			recordErr = errors.Join(recordErr, stopErr)
		}
		if recordErr != nil {
			s.log.Error("cancel pending turn", "namespace", s.namespace, "session", name, "err", recordErr)
			writeClusterError(w, recordErr)
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]bool{"accepted": true})
		return
	}
	s.ensureEngine(name)
	writeJSON(w, http.StatusAccepted, map[string]bool{"accepted": true})
}

// recordOfflineStop persists the ring boundary that drops queued work accepted
// before it. It is the stop and cancel fallback while no writer is attached to
// accept a note.
func (s *Server) recordOfflineStop(ctx context.Context, name string) error {
	before, err := s.wire.LogEnd(ctx, s.namespace, name)
	if err != nil {
		return err
	}
	if err := s.cluster.RecordStop(ctx, s.namespace, name, before); err != nil {
		return err
	}
	s.invalidateView(name)
	return nil
}

func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	name, ok := s.sessionArgs(w, r)
	if !ok {
		return
	}
	_, err := s.authorizedChat(r.Context(), forwardedUser(r), name)
	if err != nil {
		writeClusterError(w, err)
		return
	}
	writeCtx, cancel := messageContext(r)
	defer cancel()
	_, recordErr := s.writeNote(writeCtx, name, noteRecord{Type: noteStop})
	if errors.Is(recordErr, ErrNotRunning) {
		// No writer is attached. Persist the ring boundary instead of
		// starting (and waiting for) a VM just to cancel its queued work.
		var before uint64
		before, recordErr = s.wire.LogEnd(writeCtx, s.namespace, name)
		if recordErr == nil {
			recordErr = s.cluster.RecordStop(writeCtx, s.namespace, name, before)
			s.invalidateView(name)
		}
	}
	// A recording failure must not prevent the immediate stop, nor may it
	// be reported as success: without durable intent the queue could retry.
	if err := errors.Join(recordErr, s.stopBlip(writeCtx, name)); err != nil {
		writeClusterError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"accepted": true})
}

// handleDeleteSession deletes a chat and its owned child chats. It refuses
// while the agent is still running so the user stops it explicitly first.
func (s *Server) handleDeleteSession(w http.ResponseWriter, r *http.Request) {
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
	if summarize(st, blips).Running {
		writeError(w, http.StatusConflict, "stop the agent before deleting this chat")
		return
	}
	if err := s.cluster.DeleteSession(r.Context(), s.namespace, name, st.UID); err != nil && !apierrors.IsNotFound(err) {
		writeClusterError(w, err)
		return
	}
	if e := s.lookupEngine(name); e != nil {
		s.finishEngine(e)
	}
	s.invalidateView(name)
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

// eventHeartbeatInterval is how often an open event stream emits a heartbeat
// frame. It is a variable so tests do not have to wait the production cadence.
var eventHeartbeatInterval = 20 * time.Second

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
	cursor, seen, err := eventOffset(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	after, skip := cursor.offset, cursor.skip
	lastID := strconv.FormatUint(after, 10)
	if seen && skip > 0 {
		// The client stopped inside this record. The status frame we publish
		// before replaying the rest must not acknowledge the whole record, or
		// a second disconnect before the next frame would skip what remains.
		lastID = eventID(after, skip-1)
	}
	if !seen {
		// A client with no cursor starts at this chat's first record, not at
		// the base's records a fork inherited.
		after = chatStart(st)
		skip = 0
		lastID = strconv.FormatUint(after, 10)
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
	// SSE outlives the server's normal write timeout. The heartbeat below is
	// both a write probe for a dead client and the client's liveness signal.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
	if _, err := fmt.Fprint(w, "retry: 3000\n\n"); err != nil {
		return
	}
	flusher.Flush()

	ctx := r.Context()
	view := newChatView(st.Annotations[AnnotationACPSession])
	if seen {
		// Bound the backfill so an unavailable log cannot hold up the first
		// status frame. The UI also dedupes user messages by prompt ID, so a
		// failed seed degrades to a duplicate it will not render.
		seedCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		s.seedEventView(seedCtx, st, view, after)
		cancel()
	}
	heartbeat := time.NewTicker(eventHeartbeatInterval)
	defer heartbeat.Stop()
	next := after
	// The guest stops writing before Kubernetes finishes saving the state.
	// Refresh lifecycle independently of log traffic, including while the log
	// endpoint is unavailable. These snapshots retain the delivered ring cursor;
	// reading a newer snapshot must not acknowledge unread transcript records.
	poll := time.NewTicker(statusPoll)
	defer poll.Stop()
	var lastStatus string
	var statusNewest uint64
	// publishStatus writes the current lifecycle at id, the resume cursor the
	// client should present if this frame is the last one it receives.
	publishStatus := func(id string) bool {
		readCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		current, err := s.authorizedChat(readCtx, forwardedUser(r), name)
		if err != nil {
			if apierrors.IsNotFound(err) || apierrors.IsForbidden(err) || ctx.Err() != nil {
				return false
			}
			s.log.Debug("read event status", "session", name, "err", err)
			return true
		}
		blips, err := s.cluster.ListStateBlips(readCtx, s.namespace, name)
		if err != nil {
			if ctx.Err() != nil {
				return false
			}
			s.log.Debug("list event blips", "session", name, "err", err)
			return true
		}
		snapshot, ok := s.displayView(readCtx, current)
		if readCtx.Err() != nil {
			return ctx.Err() == nil
		}
		if !ok {
			// Keep the last published lifecycle snapshot instead of deriving
			// a phase, question, or cursor from an untrustworthy replay.
			s.log.Debug("event status snapshot unavailable", "session", name)
			return true
		}
		statusNewest = snapshot.Newest
		summary := reconcileSessionSummary(summarize(current, blips), snapshot)
		status := &Status{
			Phase: summary.Phase, Running: summary.Running,
			Detail: summary.StatusMessage, Question: snapshot.Question,
		}
		data, err := json.Marshal(status)
		if err != nil {
			return false
		}
		if string(data) == lastStatus {
			return true
		}
		if !writeSSE(w, flusher, Event{Offset: after, Cursor: id, Type: "status", Status: status}) {
			return false
		}
		lastStatus = string(data)
		lastID = id
		return true
	}
	if !publishStatus(lastID) {
		return
	}
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
			case <-poll.C:
				if !publishStatus(lastID) {
					return
				}
			case <-heartbeat.C:
				if !writeHeartbeat(w, flusher) {
					return
				}
			case <-time.After(readRetry):
			}
			continue
		}
		records := streamRecords(ctx, rc)
		for {
			select {
			case <-ctx.Done():
				return
			case <-poll.C:
				if !publishStatus(lastID) {
					return
				}
			case <-heartbeat.C:
				if !writeHeartbeat(w, flusher) {
					return
				}
			case res, open := <-records:
				if !open {
					goto reconnect
				}
				if res.err != nil {
					continue
				}
				// The follow stream is inclusive of the resume record. A
				// numeric cursor means the client has the whole record; a
				// frame cursor means it stopped part way through one and the
				// remaining frames must still be delivered.
				if seen && res.rec.Offset < after {
					continue
				}
				if seen && res.rec.Offset == after && skip < 0 {
					next = res.rec.Offset
					continue
				}
				view.observe(res.rec)
				events := eventsFor(res.rec, view)
				start := 0
				if seen && res.rec.Offset == after {
					if skip >= len(events) {
						next = res.rec.Offset
						continue
					}
					start = skip
				}
				seen = true
				after = res.rec.Offset
				next = res.rec.Offset
				for i := start; i < len(events); i++ {
					ev := events[i]
					if ev.Type == "status" {
						// Ring events wake lifecycle publication, but their
						// historical status must not replace the current one.
						if res.rec.Offset > statusNewest {
							s.invalidateView(name)
						}
						// Every transcript frame before this status is now
						// delivered, so the record offset acknowledges it.
						if !publishStatus(strconv.FormatUint(res.rec.Offset, 10)) {
							return
						}
						continue
					}
					ev.Cursor = eventID(res.rec.Offset, i)
					if !writeSSE(w, flusher, ev) {
						return
					}
					lastID = ev.Cursor
				}
				skip = len(events)
			}
		}
	reconnect:
		select {
		case <-ctx.Done():
			return
		case <-poll.C:
			if !publishStatus(lastID) {
				return
			}
		case <-time.After(readRetry):
		}
	}
}

// seedEventView folds the records the client's snapshot already contains into
// the event view before following new records. The stream view must know about
// earlier notes; otherwise a session/prompt whose note predates the cursor
// looks like a legacy prompt and re-emits the user message.
func (s *Server) seedEventView(ctx context.Context, st *v1.BlipState, view *chatView, cursor uint64) {
	rc, err := s.wire.ReadLog(ctx, s.namespace, st.Name, chatStart(st))
	if err != nil {
		s.log.Debug("seed chat event view", "session", st.Name, "err", err)
		return
	}
	defer rc.Close()
	dec := json.NewDecoder(rc)
	for {
		var rec streamLogRecord
		if err := dec.Decode(&rec); err != nil {
			if !errors.Is(err, io.EOF) {
				s.log.Debug("seed chat event view", "session", st.Name, "err", err)
			}
			return
		}
		if rec.Offset > cursor {
			return
		}
		view.observe(rec)
		if rec.Offset == cursor {
			return
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
		case noteQuestion, noteAnswer, noteConsumed, noteExpire, noteCancel, noteStop:
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

// eventCursor is a resume position in the event stream: the ring record and
// how many of its frames the client already received. A negative skip means
// the whole record was delivered, which is what a plain numeric offset has
// always meant.
type eventCursor struct {
	offset uint64
	skip   int
}

// eventID is the SSE id of one frame of a record. Frames of a record share a
// ring offset, so the record offset alone cannot resume between them.
func eventID(offset uint64, frame int) string {
	return strconv.FormatUint(offset, 10) + "." + strconv.Itoa(frame)
}

// parseEventCursor accepts "<offset>" and "<offset>.<frame>". The frame form
// is emitted as an SSE id and also works in the UI's ?offset= reconnect URL.
func parseEventCursor(raw string) (eventCursor, error) {
	offset, frame, hasFrame := strings.Cut(raw, ".")
	n, err := strconv.ParseUint(offset, 10, 64)
	if err != nil {
		return eventCursor{}, fmt.Errorf("offset must be a non-negative record offset")
	}
	if !hasFrame {
		return eventCursor{offset: n, skip: -1}, nil
	}
	idx, err := strconv.ParseUint(frame, 10, 31)
	if err != nil {
		return eventCursor{}, fmt.Errorf("offset frame must be a non-negative integer")
	}
	return eventCursor{offset: n, skip: int(idx) + 1}, nil
}

// eventOffset returns the client's resume position. seen is false when the
// client supplied no cursor, or the historical "0" that means "from the
// beginning of this chat".
func eventOffset(r *http.Request) (eventCursor, bool, error) {
	raw := r.URL.Query().Get("offset")
	if last := r.Header.Get("Last-Event-ID"); last != "" {
		raw = last
	}
	if raw == "" {
		return eventCursor{}, false, nil
	}
	cur, err := parseEventCursor(raw)
	if err != nil {
		return eventCursor{}, false, err
	}
	return cur, cur.offset != 0 || cur.skip >= 0, nil
}

func writeSSE(w http.ResponseWriter, flusher http.Flusher, ev Event) bool {
	data, err := json.Marshal(ev)
	if err != nil {
		return false
	}
	id := ev.Cursor
	if id == "" {
		id = strconv.FormatUint(ev.Offset, 10)
	}
	if _, err := fmt.Fprintf(w, "id: %s\ndata: %s\n\n", id, data); err != nil {
		return false
	}
	flusher.Flush()
	return true
}

// writeHeartbeat emits a data-only frame. EventSource delivers it to the
// default onmessage handler, which lets the UI distinguish a live stream from
// a half-open one that keeps sitting in OPEN. It deliberately has no id: line
// so it cannot move Last-Event-ID off the transcript cursor.
func writeHeartbeat(w http.ResponseWriter, flusher http.Flusher) bool {
	if _, err := fmt.Fprint(w, "data: {\"type\":\"hb\"}\n\n"); err != nil {
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
