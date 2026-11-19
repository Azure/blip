package blipchat

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// Options configures the stateless chat server.
type Options struct {
	Namespace   string
	Profiles    Profiles
	DefaultPool string
	AutoApprove string
	Cluster     Cluster
	Wire        Wire
	Log         *slog.Logger
}

// Server is the HTTP front end and the owner of the per-session drivers.
type Server struct {
	namespace   string
	profiles    Profiles
	defaultPool string
	autoApprove string
	cluster     Cluster
	wire        Wire
	log         *slog.Logger

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
	if opts.Profiles == nil {
		opts.Profiles = Profiles{}
	}
	if _, ok := opts.Profiles[DefaultProfileName]; !ok {
		opts.Profiles[DefaultProfileName] = Profile{}.normalized(opts.DefaultPool)
	}
	for name, p := range opts.Profiles {
		opts.Profiles[name] = p.normalized(opts.DefaultPool)
	}
	if opts.Namespace == "" {
		opts.Namespace = "default"
	}
	if !validDNSLabel(opts.Namespace) {
		return nil, fmt.Errorf("default namespace %q is not a DNS label", opts.Namespace)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		namespace:   opts.Namespace,
		profiles:    opts.Profiles,
		defaultPool: opts.DefaultPool,
		autoApprove: opts.AutoApprove,
		cluster:     opts.Cluster,
		wire:        opts.Wire,
		log:         opts.Log,
		ctx:         ctx,
		cancel:      cancel,
		drivers:     make(map[string]*driver),
	}
	s.ready.Store(true)
	return s, nil
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
	api.HandleFunc("GET /api/sessions", s.handleListSessions)
	api.HandleFunc("POST /api/sessions", s.handleCreateSession)
	api.HandleFunc("GET /api/profiles", s.handleProfiles)
	api.HandleFunc("GET /api/sessions/{name}", s.handleGetSession)
	api.HandleFunc("GET /api/sessions/{name}/events", s.handleEvents)
	api.HandleFunc("POST /api/sessions/{name}/message", s.handleMessage)
	api.HandleFunc("POST /api/sessions/{name}/cancel", s.handleCancel)
	api.HandleFunc("POST /api/sessions/{name}/stop", s.handleStop)

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
	root.Handle("/api", s.identity(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not found")
	})))
	root.Handle("/api/", s.identity(api))
	root.HandleFunc("/", s.handleUI)
	return root
}

func (s *Server) identity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		users := r.Header.Values("X-Forwarded-User")
		if len(users) != 1 || strings.TrimSpace(users[0]) == "" {
			writeError(w, http.StatusUnauthorized, "exactly one X-Forwarded-User header is required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(uiHTML))
}

func (s *Server) requestNamespace(r *http.Request) (string, error) {
	ns := r.URL.Query().Get("namespace")
	if ns == "" {
		ns = s.namespace
	}
	if !validDNSLabel(ns) {
		return "", fmt.Errorf("namespace must be a valid DNS label")
	}
	return ns, nil
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

func validDNSName(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if !validDNSLabel(part) {
			return false
		}
	}
	return true
}

type sessionSummary struct {
	Name         string      `json:"name"`
	Namespace    string      `json:"namespace"`
	Title        string      `json:"title"`
	Profile      string      `json:"profile"`
	Phase        string      `json:"phase"`
	Running      bool        `json:"running"`
	ACPSessionID string      `json:"acpSessionId,omitempty"`
	Generation   int64       `json:"generation"`
	Created      metav1.Time `json:"created"`
}

type sessionDetail struct {
	sessionSummary
	Transcript []json.RawMessage `json:"transcript"`
	Offset     uint64            `json:"offset"`
}

func summarize(st *v1.BlipState, blips []v1.Blip) sessionSummary {
	title := st.Annotations[AnnotationTitle]
	if title == "" {
		title = st.Name
	}
	profile := st.Annotations[AnnotationProfile]
	if profile == "" {
		profile = DefaultProfileName
	}
	out := sessionSummary{
		Name:         st.Name,
		Namespace:    st.Namespace,
		Title:        title,
		Profile:      profile,
		Phase:        st.Status.Phase,
		ACPSessionID: st.Annotations[AnnotationACPSession],
		Created:      st.CreationTimestamp,
		Running:      runningBlip(blips) != nil,
	}
	if latest := latestBlip(blips); latest != nil {
		if latest.Status.Phase != "" {
			out.Phase = latest.Status.Phase
		}
		out.Generation = generationOf(latest)
	}
	return out
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	ns, err := s.requestNamespace(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	states, err := s.cluster.ListSessions(r.Context(), ns)
	if err != nil {
		writeClusterError(w, err)
		return
	}
	blips, err := s.cluster.ListSessionBlips(r.Context(), ns)
	if err != nil {
		writeClusterError(w, err)
		return
	}
	byState := make(map[string][]v1.Blip)
	for _, b := range blips {
		name := b.Labels[LabelSession]
		byState[name] = append(byState[name], b)
	}
	out := make([]sessionSummary, 0, len(states))
	for i := range states {
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
	Namespace string `json:"namespace"`
	Profile   string `json:"profile"`
	Title     string `json:"title"`
	Base      string `json:"base"`
}

func (s *Server) handleCreateSession(w http.ResponseWriter, r *http.Request) {
	var req createRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ns := req.Namespace
	if ns == "" {
		ns = s.namespace
	}
	if !validDNSLabel(ns) {
		writeError(w, http.StatusBadRequest, "namespace must be a valid DNS label")
		return
	}
	profileName := req.Profile
	if profileName == "" {
		profileName = DefaultProfileName
	}
	profile, ok := s.profiles[profileName]
	if !ok {
		writeError(w, http.StatusBadRequest, "unknown profile "+profileName)
		return
	}
	profile = profile.normalized(s.defaultPool)
	if len(profile.Command) == 0 {
		writeError(w, http.StatusBadRequest, "profile "+profileName+" has no command")
		return
	}
	if req.Base != "" && !validDNSName(req.Base) {
		writeError(w, http.StatusBadRequest, "base must be a valid state name")
		return
	}
	title := strings.TrimSpace(req.Title)
	if len(title) > 200 {
		writeError(w, http.StatusBadRequest, "title is too long")
		return
	}
	if title == "" {
		title = "New chat"
	}
	annotations := map[string]string{
		AnnotationTitle:   title,
		AnnotationProfile: profileName,
	}
	if req.Base != "" {
		base, err := s.cluster.GetSession(r.Context(), ns, req.Base)
		if err != nil {
			if apierrors.IsNotFound(err) {
				writeError(w, http.StatusBadRequest, "base state not found")
			} else {
				writeClusterError(w, err)
			}
			return
		}
		// A fork inherits the copied filesystem and trajectory ring. Carrying
		// the ACP session id lets the agent load that conversation instead of
		// starting a new one.
		if id := base.Annotations[AnnotationACPSession]; id != "" {
			annotations[AnnotationACPSession] = id
		}
	}

	var created *v1.BlipState
	for attempt := 0; attempt < 5; attempt++ {
		name := newSessionName(title)
		state := &v1.BlipState{
			ObjectMeta: metav1.ObjectMeta{
				Name:        name,
				Namespace:   ns,
				Labels:      map[string]string{LabelSession: "true"},
				Annotations: annotations,
			},
			Spec: v1.BlipStateSpec{CopyFrom: req.Base},
		}
		err := s.cluster.CreateSession(r.Context(), ns, state)
		if apierrors.IsAlreadyExists(err) {
			continue
		}
		if err != nil {
			writeClusterError(w, err)
			return
		}
		created = state
		break
	}
	if created == nil {
		writeError(w, http.StatusInternalServerError, "could not allocate a session name")
		return
	}
	if d, err := s.driverFor(r.Context(), ns, created.Name); err != nil {
		s.log.Warn("start session driver", "namespace", ns, "session", created.Name, "err", err)
	} else {
		d.Ensure()
	}
	writeJSON(w, http.StatusCreated, map[string]string{"name": created.Name, "namespace": ns})
}

func newSessionName(title string) string {
	var b [3]byte
	_, _ = rand.Read(b[:])
	suffix := hex.EncodeToString(b[:])
	var slug strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(title) {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			slug.WriteRune(r)
			lastDash = false
		case !lastDash && slug.Len() > 0:
			slug.WriteByte('-')
			lastDash = true
		}
		if slug.Len() >= 32 {
			break
		}
	}
	base := strings.Trim(slug.String(), "-")
	if base == "" {
		return "chat-" + suffix
	}
	return "chat-" + base + "-" + suffix
}

func (s *Server) handleProfiles(w http.ResponseWriter, r *http.Request) {
	if _, err := s.requestNamespace(r); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	type info struct {
		Name    string `json:"name"`
		Title   string `json:"title"`
		Pool    string `json:"pool"`
		Default bool   `json:"default"`
	}
	out := make([]info, 0, len(s.profiles))
	for name, p := range s.profiles {
		out = append(out, info{Name: name, Title: p.Title, Pool: p.Pool, Default: name == DefaultProfileName})
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
	ns, name, ok := s.sessionArgs(w, r)
	if !ok {
		return
	}
	st, err := s.chatState(r.Context(), ns, name)
	if err != nil {
		writeClusterError(w, err)
		return
	}
	blips, err := s.cluster.ListStateBlips(r.Context(), ns, name)
	if err != nil {
		writeClusterError(w, err)
		return
	}
	detail := sessionDetail{sessionSummary: summarize(st, blips)}
	if d := s.lookupDriver(ns, name); d != nil {
		detail.Transcript, detail.Offset = d.Snapshot()
	}
	if detail.Transcript == nil {
		detail.Transcript = []json.RawMessage{}
	}
	writeJSON(w, http.StatusOK, detail)
}

func (s *Server) sessionArgs(w http.ResponseWriter, r *http.Request) (ns, name string, ok bool) {
	ns, err := s.requestNamespace(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return "", "", false
	}
	name = r.PathValue("name")
	if !validDNSLabel(name) {
		writeError(w, http.StatusBadRequest, "session name must be a valid DNS label")
		return "", "", false
	}
	return ns, name, true
}

func (s *Server) chatState(ctx context.Context, ns, name string) (*v1.BlipState, error) {
	st, err := s.cluster.GetSession(ctx, ns, name)
	if err != nil {
		return nil, err
	}
	if st.Labels[LabelSession] != "true" {
		return nil, apierrors.NewNotFound(v1.GroupVersion.WithResource("blipstates").GroupResource(), name)
	}
	return st, nil
}

func (s *Server) driverFor(ctx context.Context, ns, name string) (*driver, error) {
	key := ns + "/" + name
	s.mu.Lock()
	if d := s.drivers[key]; d != nil {
		s.mu.Unlock()
		return d, nil
	}
	s.mu.Unlock()

	st, err := s.chatState(ctx, ns, name)
	if err != nil {
		return nil, err
	}
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
	d := newDriver(driverOptions{
		Cluster:     s.cluster,
		Wire:        s.wire,
		Hub:         NewHub(),
		Log:         s.log,
		Namespace:   ns,
		State:       name,
		Profile:     s.profiles.get(profileName, s.defaultPool),
		AutoApprove: s.autoApprove,
		SessionID:   st.Annotations[AnnotationACPSession],
		Offset:      offset,
		HaveOffset:  haveOffset,
	})

	s.mu.Lock()
	if existing := s.drivers[key]; existing != nil {
		s.mu.Unlock()
		d.Close()
		return existing, nil
	}
	s.drivers[key] = d
	s.mu.Unlock()
	d.start(s.ctx)
	return d, nil
}

func (s *Server) lookupDriver(ns, name string) *driver {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.drivers[ns+"/"+name]
}

func (s *Server) handleMessage(w http.ResponseWriter, r *http.Request) {
	ns, name, ok := s.sessionArgs(w, r)
	if !ok {
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
	d, err := s.driverFor(r.Context(), ns, name)
	if err != nil {
		writeClusterError(w, err)
		return
	}
	if !d.Submit(text) {
		writeError(w, http.StatusServiceUnavailable, "session is busy")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"accepted": true})
}

func (s *Server) handleCancel(w http.ResponseWriter, r *http.Request) {
	ns, name, ok := s.sessionArgs(w, r)
	if !ok {
		return
	}
	d, err := s.driverFor(r.Context(), ns, name)
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
	ns, name, ok := s.sessionArgs(w, r)
	if !ok {
		return
	}
	d, err := s.driverFor(r.Context(), ns, name)
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
	ns, name, ok := s.sessionArgs(w, r)
	if !ok {
		return
	}
	d, err := s.driverFor(r.Context(), ns, name)
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
	w.Header().Set("Cache-Control", "no-cache")
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
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, message string) {
	writeJSON(w, code, map[string]string{"error": message})
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
