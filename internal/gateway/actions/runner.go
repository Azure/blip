// Package actions implements a GitHub Actions runner backend that polls the
// GitHub API for queued workflow jobs across a configured set of repositories,
// allocating ephemeral Blip VMs as self-hosted runners.
//
// After claiming a VM, the runner backend creates a JIT (just-in-time)
// runner configuration via the GitHub API and writes it to a VM annotation.
// The in-VM configure-runner service polls for this annotation and starts
// the runner agent. When the job completes, the VM is released for
// immediate deallocation.
package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/project-unbounded/blip/internal/gateway/vm"
)

const (
	// runnerMaxTTL is the maximum TTL for runner VMs (30 minutes).
	runnerMaxTTL = 1800

	// pollInterval is how often each repo loop checks for queued jobs.
	pollInterval = 10 * time.Second

	// jobMonitorInterval is how often to check if a job has completed.
	jobMonitorInterval = 15 * time.Second

	// jitConfigAnnotation is the VM annotation key for the JIT runner config.
	jitConfigAnnotation = "blip.io/runner-jitconfig"
)

// githubHTTPClient is used for GitHub API calls.
var githubHTTPClient = &http.Client{Timeout: 30 * time.Second}

// Config holds the configuration for the actions runner backend.
type Config struct {
	VMClient  *vm.Client
	Namespace string
	PoolName  string
	PodName   string

	// PAT is the provider for GitHub Personal Access Tokens, backed by a
	// Kubernetes Secret watched via an informer.
	PAT *PATProvider

	// Repos is the static list of GitHub repositories to poll for queued
	// workflow jobs. Each entry is in "owner/repo" format.
	Repos []string

	// RunnerLabels are the labels applied to JIT runners (e.g. ["self-hosted", "blip"]).
	RunnerLabels []string
}

// Runner polls GitHub for queued workflow jobs across a configured set of
// repositories and allocates VMs as self-hosted runners.
type Runner struct {
	cfg Config
}

// New creates a Runner. Call Start to begin polling.
func New(cfg Config) *Runner {
	return &Runner{cfg: cfg}
}

// Start launches per-repo polling goroutines and blocks until ctx is cancelled.
func (r *Runner) Start(ctx context.Context) error {
	if r.cfg.PAT == nil {
		return fmt.Errorf("PAT provider is required")
	}
	if len(r.cfg.Repos) == 0 {
		return fmt.Errorf("at least one repo is required")
	}

	var wg sync.WaitGroup
	for _, repo := range r.cfg.Repos {
		wg.Add(1)
		go func(repo string) {
			defer wg.Done()
			r.pollLoop(ctx, repo)
		}(repo)
	}

	slog.Info("actions runner backend started",
		"namespace", r.cfg.Namespace,
		"repos", r.cfg.Repos,
		"labels", r.cfg.RunnerLabels,
	)

	<-ctx.Done()
	wg.Wait()
	return nil
}

// ActiveSessionCount returns the number of repos being polled.
func (r *Runner) ActiveSessionCount() int {
	return len(r.cfg.Repos)
}

// pollLoop polls GitHub for queued workflow jobs for a single repo, allocating
// VMs as needed. It runs until ctx is cancelled.
func (r *Runner) pollLoop(ctx context.Context, repo string) {
	// Track jobs we've already allocated a VM for to avoid duplicates.
	type allocRecord struct {
		allocatedAt time.Time
	}
	allocated := make(map[int64]allocRecord)

	for {
		token, err := r.cfg.PAT.Token()
		if err != nil {
			slog.Error("failed to get PAT",
				"repo", repo,
				"error", err,
			)
			goto wait
		}

		{
			jobs, err := listQueuedJobs(ctx, repo, token)
			if err != nil {
				slog.Error("poll queued jobs failed",
					"repo", repo,
					"error", err,
				)
			} else {
				for _, job := range jobs {
					if _, done := allocated[job.ID]; done {
						continue
					}
					if r.allocateAndProvision(ctx, repo, job) {
						allocated[job.ID] = allocRecord{allocatedAt: time.Now()}
					}
				}
			}

			// Evict entries older than 2x runnerMaxTTL to prevent unbounded growth.
			evictBefore := time.Now().Add(-2 * runnerMaxTTL * time.Second)
			for id, rec := range allocated {
				if rec.allocatedAt.Before(evictBefore) {
					delete(allocated, id)
				}
			}
		}

	wait:
		select {
		case <-ctx.Done():
			return
		case <-time.After(pollInterval):
		}
	}
}

// allocateAndProvision claims a VM for the given job, creates a JIT runner
// config, writes it to the VM's annotations, and starts a background
// goroutine to monitor job completion for early deallocation.
func (r *Runner) allocateAndProvision(ctx context.Context, repo string, job workflowJob) bool {
	sessionID := fmt.Sprintf("actions-%d", job.ID)

	result, err := r.cfg.VMClient.Claim(
		ctx,
		r.cfg.PoolName,
		sessionID,
		r.cfg.PodName,
		runnerMaxTTL,
		fmt.Sprintf("actions:%s", repo),
		0, // no per-user quota for actions
	)
	if err != nil {
		slog.Error("failed to allocate runner VM",
			"repo", repo,
			"job_id", job.ID,
			"error", err,
		)
		return false
	}
	slog.Info("allocated runner VM",
		"repo", repo,
		"job_id", job.ID,
		"vm", result.Name,
	)

	token, err := r.cfg.PAT.Token()
	if err != nil {
		slog.Error("failed to get PAT for JIT config",
			"repo", repo,
			"job_id", job.ID,
			"error", err,
		)
		if releaseErr := r.cfg.VMClient.ReleaseVM(ctx, sessionID); releaseErr != nil {
			slog.Error("failed to release VM after PAT failure",
				"vm", result.Name,
				"error", releaseErr,
			)
		}
		return false
	}

	// Create a JIT runner config and write it to the VM's annotations.
	runnerName := fmt.Sprintf("blip-%d", job.ID)
	labels := r.cfg.RunnerLabels
	if len(labels) == 0 {
		labels = []string{"self-hosted", "blip"}
	}

	jitConfig, err := CreateJITRunnerConfig(ctx, token, repo, labels, runnerName)
	if err != nil {
		slog.Error("failed to create JIT runner config",
			"repo", repo,
			"job_id", job.ID,
			"vm", result.Name,
			"error", err,
		)
		if releaseErr := r.cfg.VMClient.ReleaseVM(ctx, sessionID); releaseErr != nil {
			slog.Error("failed to release VM after JIT config failure",
				"vm", result.Name,
				"error", releaseErr,
			)
		}
		return false
	}

	if err := r.cfg.VMClient.PatchVMAnnotations(ctx, result.Name, map[string]string{
		jitConfigAnnotation: jitConfig,
	}); err != nil {
		slog.Error("failed to set JIT config annotation on VM",
			"vm", result.Name,
			"job_id", job.ID,
			"error", err,
		)
		if releaseErr := r.cfg.VMClient.ReleaseVM(ctx, sessionID); releaseErr != nil {
			slog.Error("failed to release VM after annotation failure",
				"vm", result.Name,
				"error", releaseErr,
			)
		}
		return false
	}

	slog.Info("provisioned runner VM with JIT config",
		"repo", repo,
		"job_id", job.ID,
		"vm", result.Name,
		"runner_name", runnerName,
	)

	// Monitor job completion in the background.
	go r.monitorJobCompletion(ctx, repo, job.ID, sessionID, result.Name)
	return true
}

// monitorJobCompletion polls the GitHub API for job status and releases the
// VM when the job completes. Monitoring is capped at runnerMaxTTL + 5 minutes;
// the deallocation controller's TTL-based cleanup serves as the safety net.
func (r *Runner) monitorJobCompletion(ctx context.Context, repo string, jobID int64, sessionID, vmName string) {
	deadline := time.After(time.Duration(runnerMaxTTL+300) * time.Second)
	for {
		select {
		case <-ctx.Done():
			return
		case <-deadline:
			slog.Info("job monitor deadline reached, deferring to TTL cleanup",
				"repo", repo,
				"job_id", jobID,
				"vm", vmName,
			)
			return
		case <-time.After(jobMonitorInterval):
		}

		token, err := r.cfg.PAT.Token()
		if err != nil {
			slog.Debug("failed to get PAT for job status check",
				"repo", repo,
				"job_id", jobID,
				"error", err,
			)
			continue
		}

		status, err := GetJobStatus(ctx, token, repo, jobID)
		if err != nil {
			slog.Debug("failed to check job status",
				"repo", repo,
				"job_id", jobID,
				"error", err,
			)
			continue
		}

		if status == "completed" {
			slog.Info("job completed, releasing runner VM",
				"repo", repo,
				"job_id", jobID,
				"vm", vmName,
			)
			if err := r.cfg.VMClient.ReleaseVM(ctx, sessionID); err != nil {
				slog.Error("failed to release VM after job completion",
					"vm", vmName,
					"error", err,
				)
			}
			return
		}
	}
}

// GitHub API types and helpers.

type workflowJob struct {
	ID     int64  `json:"id"`
	Status string `json:"status"`
}

type jobsResponse struct {
	Jobs []workflowJob `json:"jobs"`
}

type runsResponse struct {
	WorkflowRuns []workflowRun `json:"workflow_runs"`
}

type workflowRun struct {
	ID int64 `json:"id"`
}

// listQueuedJobs returns queued workflow jobs for the given repo.
func listQueuedJobs(ctx context.Context, repo, token string) ([]workflowJob, error) {
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid repo format: %s", repo)
	}
	owner, repoName := parts[0], parts[1]

	// List queued workflow runs.
	runsURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/actions/runs?status=queued&per_page=100", owner, repoName)
	runs, err := ghGet[runsResponse](ctx, runsURL, token)
	if err != nil {
		return nil, fmt.Errorf("list runs: %w", err)
	}

	var queued []workflowJob
	for _, run := range runs.WorkflowRuns {
		jobsURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/actions/runs/%d/jobs?filter=latest&per_page=100", owner, repoName, run.ID)
		resp, err := ghGet[jobsResponse](ctx, jobsURL, token)
		if err != nil {
			slog.Debug("list jobs for run failed", "run_id", run.ID, "error", err)
			continue
		}
		for _, job := range resp.Jobs {
			if job.Status == "queued" {
				queued = append(queued, job)
			}
		}
	}
	return queued, nil
}

func ghGet[T any](ctx context.Context, url, token string) (T, error) {
	var zero T
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return zero, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := githubHTTPClient.Do(req)
	if err != nil {
		return zero, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return zero, fmt.Errorf("github api %s: %d %s", url, resp.StatusCode, string(body))
	}

	var result T
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return zero, fmt.Errorf("decode response: %w", err)
	}
	return result, nil
}
