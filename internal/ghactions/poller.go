package ghactions

import (
	"context"
	"fmt"
	"log/slog"
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
	// ReleaseVM marks a previously claimed VM for deallocation. Must be
	// idempotent -- calling ReleaseVM on an already-released or non-existent
	// session must be a safe no-op.
	ReleaseVM(ctx context.Context, sessionID string) error
}

// RunnerConfigStore abstracts writing runner configuration onto a VM.
type RunnerConfigStore interface {
	StoreRunnerConfig(ctx context.Context, vmName string, cfg RunnerConfig) error
}

// RepoProvider returns the current list of repos to poll.
type RepoProvider interface {
	ActionsRepos() []string
}

// PollerConfig configures the polling-based Actions runner.
type PollerConfig struct {
	VMClaimer          VMClaimer
	RunnerConfigStore  RunnerConfigStore
	TokenProvider      TokenProvider
	JobsProvider       JobsProvider
	RepoProvider       RepoProvider
	VMPoolName         string
	RunnerLabels       []string
	MaxSessionDuration int
	PodName            string
	PollInterval       time.Duration
}

// Poller polls the GitHub API for queued workflow jobs and allocates VMs.
type Poller struct {
	cfg      PollerConfig
	labelSet map[string]struct{}

	mu             sync.Mutex
	activeSessions map[string]string // job ID (string) -> session ID ("" = in-flight)

	wg sync.WaitGroup
}

// ownerRepoRe validates GitHub owner/repo format.
var ownerRepoRe = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9._-]*/[a-zA-Z0-9_][a-zA-Z0-9._-]*$`)

// DefaultActionsTTL is the default TTL for Blips allocated for GitHub Actions
// runners. Acts as a safety net for cleanup.
const DefaultActionsTTL = 30 * time.Minute

// NewPoller creates a new polling-based Actions runner handler.
func NewPoller(cfg PollerConfig) *Poller {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 10 * time.Second
	}
	labels := make(map[string]struct{}, len(cfg.RunnerLabels))
	for _, l := range cfg.RunnerLabels {
		labels[strings.ToLower(l)] = struct{}{}
	}
	return &Poller{
		cfg:            cfg,
		labelSet:       labels,
		activeSessions: make(map[string]string),
	}
}

// sessionID returns a deterministic session ID for a workflow job.
func sessionID(jobID int64) string {
	return fmt.Sprintf("blip-%016x", jobID)
}

// Run starts the polling loop. Blocks until ctx is cancelled.
func (p *Poller) Run(ctx context.Context) {
	slog.Info("actions poller starting", "interval", p.cfg.PollInterval)
	ticker := time.NewTicker(p.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("actions poller stopping")
			return
		case <-ticker.C:
			p.poll(ctx)
		}
	}
}

// poll fetches queued jobs for all configured repos, handles new ones, and
// reconciles sessions for jobs that are no longer queued.
func (p *Poller) poll(ctx context.Context) {
	repos := p.cfg.RepoProvider.ActionsRepos()
	if len(repos) == 0 {
		return
	}

	// Collect all currently-queued job IDs so we can reconcile afterwards.
	// If any repo listing fails, skip reconciliation to avoid false cleanup.
	seenJobIDs := make(map[string]bool)
	listComplete := true

	for _, repo := range repos {
		if ctx.Err() != nil {
			return
		}
		if !ownerRepoRe.MatchString(repo) {
			slog.Warn("skipping invalid repo format", "repo", repo)
			continue
		}
		jobs, err := p.cfg.JobsProvider.ListQueuedJobs(ctx, repo)
		if err != nil {
			slog.Error("failed to list queued jobs", "repo", repo, "error", err)
			listComplete = false
			continue
		}
		for _, job := range jobs {
			if ctx.Err() != nil {
				return
			}
			seenJobIDs[strconv.FormatInt(job.ID, 10)] = true
			p.handleQueuedJob(ctx, repo, job)
		}
	}

	if !listComplete {
		return
	}
	p.reconcile(ctx, seenJobIDs)
}

// reconcile releases sessions for jobs no longer in the queued set.
func (p *Poller) reconcile(ctx context.Context, seenJobIDs map[string]bool) {
	type staleEntry struct{ jobID, sid string }

	p.mu.Lock()
	var stale []staleEntry
	for jobID, sid := range p.activeSessions {
		if sid != "" && !seenJobIDs[jobID] {
			stale = append(stale, staleEntry{jobID, sid})
			delete(p.activeSessions, jobID)
		}
	}
	p.mu.Unlock()

	for _, s := range stale {
		slog.Info("releasing VM for job no longer queued", "job_id", s.jobID, "session_id", s.sid)
		if err := p.cfg.VMClaimer.ReleaseVM(ctx, s.sid); err != nil {
			slog.Warn("failed to release VM (will be cleaned up by TTL)", "session_id", s.sid, "error", err)
		}
	}
}

// handleQueuedJob claims a VM for a queued job and sets it up.
func (p *Poller) handleQueuedJob(ctx context.Context, repo string, job WorkflowJob) {
	if !p.matchesLabels(job.Labels) {
		return
	}

	jobIDStr := strconv.FormatInt(job.ID, 10)
	sid := sessionID(job.ID)
	log := slog.With("job_id", job.ID, "job_name", job.Name, "repo", repo)

	// Idempotency: atomically check and reserve the session slot.
	p.mu.Lock()
	if _, exists := p.activeSessions[jobIDStr]; exists {
		p.mu.Unlock()
		return
	}
	p.activeSessions[jobIDStr] = "" // sentinel: in-flight
	p.mu.Unlock()

	success := false
	defer func() {
		if !success {
			p.mu.Lock()
			delete(p.activeSessions, jobIDStr)
			p.mu.Unlock()
		}
	}()

	log.Info("claiming VM for queued job", "session_id", sid)

	ttl := p.cfg.MaxSessionDuration
	if ttl <= 0 {
		ttl = int(DefaultActionsTTL.Seconds())
	}

	claimCtx, claimCancel := context.WithTimeout(ctx, 10*time.Second)
	defer claimCancel()

	result, err := p.cfg.VMClaimer.Claim(
		claimCtx, p.cfg.VMPoolName, sid, p.cfg.PodName,
		ttl, "github-actions:"+repo, 0,
	)
	if err != nil {
		log.Error("failed to claim VM", "error", err)
		return
	}

	log.Info("VM claimed", "session_id", sid, "vm_name", result.Name, "vm_ip", result.PodIP)
	success = true

	// Finish setup asynchronously.
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		setupCtx, setupCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer setupCancel()
		if err := p.finishSetup(setupCtx, log, repo, job, result); err != nil {
			log.Error("failed to finish job setup", "error", err)
		}
	}()
}

func (p *Poller) finishSetup(ctx context.Context, log *slog.Logger, repo string, job WorkflowJob, result *vm.ClaimResult) error {
	jobIDStr := strconv.FormatInt(job.ID, 10)
	sid := sessionID(job.ID)

	// Early check: if reconciliation already removed this session, bail out.
	p.mu.Lock()
	if _, stillActive := p.activeSessions[jobIDStr]; !stillActive {
		p.mu.Unlock()
		log.Warn("session removed before setup completed, releasing VM", "session_id", sid)
		if err := p.cfg.VMClaimer.ReleaseVM(ctx, sid); err != nil {
			log.Error("failed to release VM after early removal", "error", err)
		}
		return nil
	}
	p.mu.Unlock()

	regToken, err := p.cfg.TokenProvider.CreateRegistrationToken(ctx, repo)
	if err != nil {
		log.Error("failed to get registration token, releasing VM", "error", err)
		p.removeAndRelease(ctx, log, jobIDStr, sid)
		return fmt.Errorf("create registration token: %w", err)
	}

	if err := p.cfg.RunnerConfigStore.StoreRunnerConfig(ctx, result.Name, RunnerConfig{
		Token:   regToken.Token,
		RepoURL: "https://github.com/" + repo,
		Labels:  job.Labels,
	}); err != nil {
		log.Error("failed to store runner config", "error", err)
		p.removeAndRelease(ctx, log, jobIDStr, sid)
		return fmt.Errorf("store runner config: %w", err)
	}

	// Final check: if reconciliation removed the session while we were
	// setting up, release the VM.
	p.mu.Lock()
	if _, stillActive := p.activeSessions[jobIDStr]; stillActive {
		p.activeSessions[jobIDStr] = sid
		p.mu.Unlock()
	} else {
		p.mu.Unlock()
		log.Warn("session removed during setup, releasing VM", "session_id", sid)
		if err := p.cfg.VMClaimer.ReleaseVM(ctx, sid); err != nil {
			log.Error("failed to release VM after concurrent removal", "error", err)
		}
		return nil
	}

	log.Info("runner config stored, waiting for runner agent", "session_id", sid, "vm_name", result.Name)
	return nil
}

// removeAndRelease removes the session from tracking and releases the VM.
func (p *Poller) removeAndRelease(ctx context.Context, log *slog.Logger, jobIDStr, sid string) {
	p.mu.Lock()
	delete(p.activeSessions, jobIDStr)
	p.mu.Unlock()
	if err := p.cfg.VMClaimer.ReleaseVM(ctx, sid); err != nil {
		log.Error("failed to release VM", "session_id", sid, "error", err)
	}
}

// matchesLabels returns true if the job's labels include at least one of our
// configured runner labels (case-insensitive).
func (p *Poller) matchesLabels(jobLabels []string) bool {
	for _, l := range jobLabels {
		if _, ok := p.labelSet[strings.ToLower(l)]; ok {
			return true
		}
	}
	return false
}

// ActiveSessionCount returns the number of currently tracked sessions.
func (p *Poller) ActiveSessionCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.activeSessions)
}

// WaitForPending blocks until all in-flight async goroutines have completed.
func (p *Poller) WaitForPending() {
	p.wg.Wait()
}
