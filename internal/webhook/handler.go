package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/project-unbounded/blip/internal/gateway/vm"
)

// VMClaimer abstracts VM claim/release operations for testability.
type VMClaimer interface {
	Claim(ctx context.Context, poolName, sessionID, gatewayPodName string, maxDuration int, userIdentity string, maxBlips int) (*vm.ClaimResult, error)
	ReleaseVM(ctx context.Context, sessionID string) error
}

// RunnerConfigStore abstracts writing runner configuration onto a VM.
type RunnerConfigStore interface {
	StoreRunnerConfig(ctx context.Context, vmName string, cfg RunnerConfig) error
}

// HandlerConfig configures the webhook handler.
type HandlerConfig struct {
	// WebhookSecret is the shared secret for validating X-Hub-Signature-256.
	// Must be non-empty for production use.
	WebhookSecret []byte

	// VMClaimer provides VM claim/release operations.
	VMClaimer VMClaimer

	// RunnerConfigStore patches runner config annotations onto claimed VMs.
	RunnerConfigStore RunnerConfigStore

	// TokenProvider fetches runner registration tokens from the GitHub API.
	TokenProvider TokenProvider

	// VMPoolName is the KubeVirt pool to allocate VMs from.
	VMPoolName string

	// RunnerLabels are the self-hosted runner labels (e.g. ["self-hosted", "blip"]).
	// A workflow_job is only handled if its labels intersect with these.
	RunnerLabels []string

	// MaxSessionDuration is the TTL for claimed runner VMs in seconds.
	MaxSessionDuration int

	// PodName identifies this webhook pod (used as claimed-by).
	PodName string
}

// Handler is an http.Handler that processes GitHub workflow_job webhook events.
type Handler struct {
	cfg      HandlerConfig
	labelSet map[string]struct{}

	// mu guards activeSessions for idempotent handling.
	mu             sync.Mutex
	activeSessions map[string]string // workflow_job.id (string) -> session ID ("" = in-flight)

	// wg tracks in-flight async goroutines for graceful shutdown and testing.
	wg sync.WaitGroup
}

// NewHandler creates a new webhook handler.
func NewHandler(cfg HandlerConfig) *Handler {
	if len(cfg.WebhookSecret) == 0 {
		slog.Warn("SECURITY WARNING: webhook secret is not configured — webhook payloads will not be verified")
	}
	labels := make(map[string]struct{}, len(cfg.RunnerLabels))
	for _, l := range cfg.RunnerLabels {
		labels[strings.ToLower(l)] = struct{}{}
	}
	return &Handler{
		cfg:            cfg,
		labelSet:       labels,
		activeSessions: make(map[string]string),
	}
}

// workflowJobEvent represents the relevant fields of a GitHub workflow_job webhook payload.
type workflowJobEvent struct {
	Action      string      `json:"action"`
	WorkflowJob workflowJob `json:"workflow_job"`
	Repository  repository  `json:"repository"`
}

type workflowJob struct {
	ID     int64    `json:"id"`
	Labels []string `json:"labels"`
	RunID  int64    `json:"run_id"`
	Name   string   `json:"name"`
}

type repository struct {
	FullName string `json:"full_name"`
}

// ownerRepoRe validates GitHub owner/repo format.
// Each segment must start with an alphanumeric or underscore, preventing "." and ".." segments
// which would cause path traversal in GitHub API URLs.
var ownerRepoRe = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9._-]*/[a-zA-Z0-9_][a-zA-Z0-9._-]*$`)

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20)) // 10 MB limit.
	if err != nil {
		slog.Error("failed to read request body", "error", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Validate webhook signature.
	if len(h.cfg.WebhookSecret) > 0 {
		sig := r.Header.Get("X-Hub-Signature-256")
		if !VerifyWebhookSignature(body, sig, h.cfg.WebhookSecret) {
			slog.Warn("webhook signature verification failed")
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}

	deliveryID := r.Header.Get("X-GitHub-Delivery")
	eventType := r.Header.Get("X-GitHub-Event")

	// Only handle workflow_job events.
	if eventType != "workflow_job" {
		// Return 200 for other events (e.g. ping) to avoid GitHub flagging errors.
		if eventType == "ping" {
			slog.Info("received ping event", "delivery_id", deliveryID)
		}
		w.WriteHeader(http.StatusOK)
		return
	}

	var event workflowJobEvent
	if err := json.Unmarshal(body, &event); err != nil {
		slog.Error("failed to parse webhook payload", "error", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	log := slog.With(
		"delivery_id", deliveryID,
		"action", event.Action,
		"job_id", event.WorkflowJob.ID,
		"job_name", event.WorkflowJob.Name,
		"repo", event.Repository.FullName,
	)

	// Accept the webhook immediately — processing happens asynchronously
	// to avoid GitHub's 10-second delivery timeout on slow Kubernetes/GitHub API calls.
	switch event.Action {
	case "queued":
		// Start async processing. We respond 200 immediately.
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			if err := h.handleQueued(ctx, log, &event); err != nil {
				log.Error("failed to handle queued job", "error", err)
			}
		}()
	case "completed":
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := h.handleCompleted(ctx, log, &event); err != nil {
				log.Error("failed to handle completed job", "error", err)
			}
		}()
	default:
		log.Debug("ignoring workflow_job action")
	}

	w.WriteHeader(http.StatusOK)
}

// matchesLabels returns true if the job's labels include at least one of our configured runner labels.
func (h *Handler) matchesLabels(jobLabels []string) bool {
	for _, l := range jobLabels {
		if _, ok := h.labelSet[strings.ToLower(l)]; ok {
			return true
		}
	}
	return false
}

// sessionID returns a deterministic session ID for a workflow job.
// Uses 16 hex digits to cover the full int64 range.
func sessionID(jobID int64) string {
	return fmt.Sprintf("blip-%016x", jobID)
}

func (h *Handler) handleQueued(ctx context.Context, log *slog.Logger, event *workflowJobEvent) error {
	if !h.matchesLabels(event.WorkflowJob.Labels) {
		log.Debug("job labels do not match runner labels, skipping",
			"job_labels", event.WorkflowJob.Labels,
			"runner_labels", h.cfg.RunnerLabels,
		)
		return nil
	}

	// Validate repository format to prevent URL injection.
	if !ownerRepoRe.MatchString(event.Repository.FullName) {
		return fmt.Errorf("invalid repository format: %q", event.Repository.FullName)
	}

	jobIDStr := strconv.FormatInt(event.WorkflowJob.ID, 10)
	sid := sessionID(event.WorkflowJob.ID)

	// Idempotency: atomically check and reserve the session slot.
	// Set an empty string sentinel to block concurrent duplicates during claim.
	h.mu.Lock()
	if _, exists := h.activeSessions[jobIDStr]; exists {
		h.mu.Unlock()
		log.Info("job already has an active session, skipping duplicate", "session_id", sid)
		return nil
	}
	h.activeSessions[jobIDStr] = "" // sentinel: in-flight
	h.mu.Unlock()

	// On any failure, clean up the sentinel.
	success := false
	defer func() {
		if !success {
			h.mu.Lock()
			delete(h.activeSessions, jobIDStr)
			h.mu.Unlock()
		}
	}()

	log.Info("claiming VM for queued job", "session_id", sid)

	// Claim a VM from the pool.
	result, err := h.cfg.VMClaimer.Claim(
		ctx,
		h.cfg.VMPoolName,
		sid,
		h.cfg.PodName,
		h.cfg.MaxSessionDuration,
		"github-actions:"+event.Repository.FullName,
		0, // no per-user quota for actions
	)
	if err != nil {
		return fmt.Errorf("claim VM: %w", err)
	}

	log.Info("VM claimed for runner",
		"session_id", sid,
		"vm_name", result.Name,
		"vm_ip", result.PodIP,
	)

	// Fetch a runner registration token from GitHub.
	regToken, err := h.cfg.TokenProvider.CreateRegistrationToken(ctx, event.Repository.FullName)
	if err != nil {
		log.Error("failed to get registration token, releasing VM", "error", err)
		if releaseErr := h.cfg.VMClaimer.ReleaseVM(ctx, sid); releaseErr != nil {
			log.Error("failed to release VM after token failure", "error", releaseErr)
		}
		return fmt.Errorf("create registration token: %w", err)
	}

	// Patch the VM with runner configuration.
	// The VM's cloud-init polls for these annotations to start the runner agent.
	if err := h.cfg.RunnerConfigStore.StoreRunnerConfig(ctx, result.Name, RunnerConfig{
		Token:   regToken.Token,
		RepoURL: "https://github.com/" + event.Repository.FullName,
		Labels:  event.WorkflowJob.Labels,
	}); err != nil {
		log.Error("failed to store runner config on VM", "error", err)
		if releaseErr := h.cfg.VMClaimer.ReleaseVM(ctx, sid); releaseErr != nil {
			log.Error("failed to release VM after config failure", "error", releaseErr)
		}
		return fmt.Errorf("store runner config: %w", err)
	}

	// Mark fully successful — but only if the session wasn't already
	// released by a concurrent "completed" event that arrived while we were
	// still processing.
	h.mu.Lock()
	if _, stillActive := h.activeSessions[jobIDStr]; stillActive {
		h.activeSessions[jobIDStr] = sid
		h.mu.Unlock()
		success = true
	} else {
		h.mu.Unlock()
		log.Warn("session was released by a concurrent completed event during setup, releasing VM",
			"session_id", sid,
			"vm_name", result.Name,
		)
		if releaseErr := h.cfg.VMClaimer.ReleaseVM(ctx, sid); releaseErr != nil {
			log.Error("failed to release VM after concurrent completion", "error", releaseErr)
		}
		// success stays false — defer will not try to delete (already deleted).
		return nil
	}

	log.Info("runner config stored on VM, waiting for runner agent to start",
		"session_id", sid,
		"vm_name", result.Name,
	)

	return nil
}

func (h *Handler) handleCompleted(ctx context.Context, log *slog.Logger, event *workflowJobEvent) error {
	jobIDStr := strconv.FormatInt(event.WorkflowJob.ID, 10)
	sid := sessionID(event.WorkflowJob.ID)

	// Remove from active sessions.
	h.mu.Lock()
	_, tracked := h.activeSessions[jobIDStr]
	delete(h.activeSessions, jobIDStr)
	h.mu.Unlock()

	if !tracked {
		// This job may not have been handled by us (labels didn't match, or
		// we weren't the webhook receiver when it was queued). Try releasing
		// anyway — ReleaseVM is a no-op if the session doesn't exist.
		log.Debug("job not tracked, attempting release anyway", "session_id", sid)
	}

	log.Info("releasing VM for completed job", "session_id", sid)

	if err := h.cfg.VMClaimer.ReleaseVM(ctx, sid); err != nil {
		// Log but don't fail — the deallocation controller will clean up via TTL.
		log.Warn("failed to release VM (will be cleaned up by TTL)",
			"session_id", sid,
			"error", err,
		)
		return nil
	}

	log.Info("VM released for completed job", "session_id", sid)
	return nil
}

// ActiveSessionCount returns the number of currently tracked sessions.
// Useful for health checks and metrics.
func (h *Handler) ActiveSessionCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.activeSessions)
}

// WaitForPending blocks until all in-flight async goroutines have completed.
// This is primarily useful for testing and graceful shutdown.
func (h *Handler) WaitForPending() {
	h.wg.Wait()
}
