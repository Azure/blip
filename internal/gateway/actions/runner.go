// Package actions implements a GitHub Actions runner backend that watches
// for bootstrap token secrets and polls the GitHub API for queued workflow
// jobs, allocating ephemeral Blip VMs as self-hosted runners.
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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
	crcache "sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/project-unbounded/blip/internal/gateway/vm"
)

const (
	// repoLabel is the label applied to secrets by the /auth/github handler.
	repoLabel = "blip.azure.com/repo"

	// repoAnnotation stores the original owner/repo value (before sanitization).
	repoAnnotation = "blip.azure.com/repo"

	// runnerMaxTTL is the maximum TTL for runner VMs (30 minutes).
	runnerMaxTTL = 1800

	// pollInterval is how often each repo loop checks for queued jobs.
	pollInterval = 10 * time.Second
)

// Config holds the configuration for the actions runner backend.
type Config struct {
	VMClient  *vm.Client
	KubeCache crcache.Cache
	Namespace string
	PoolName  string
	PodName   string
}

// Runner watches for GitHub token secrets and runs per-repo polling loops
// that discover queued workflow jobs and allocate VMs.
type Runner struct {
	cfg Config

	mu      sync.Mutex
	cancels map[string]context.CancelFunc // secret name -> cancel
}

// New creates a Runner. Call Start to begin watching secrets.
func New(cfg Config) *Runner {
	return &Runner{cfg: cfg, cancels: make(map[string]context.CancelFunc)}
}

// Start watches secrets with the blip.azure.com/repo label and manages
// per-repo polling goroutines. It blocks until ctx is cancelled.
func (r *Runner) Start(ctx context.Context) error {
	informer, err := r.cfg.KubeCache.GetInformer(ctx, &corev1.Secret{})
	if err != nil {
		return fmt.Errorf("get secret informer: %w", err)
	}

	if _, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { r.handleSecretEvent(ctx, obj) },
		UpdateFunc: func(_, obj interface{}) { r.handleSecretEvent(ctx, obj) },
		DeleteFunc: func(obj interface{}) { r.handleSecretDelete(obj) },
	}); err != nil {
		return fmt.Errorf("add secret event handler: %w", err)
	}

	// Reconcile existing secrets on startup.
	var secrets corev1.SecretList
	if err := r.cfg.KubeCache.List(ctx, &secrets,
		client.InNamespace(r.cfg.Namespace),
		client.HasLabels{repoLabel},
	); err != nil {
		return fmt.Errorf("list existing secrets: %w", err)
	}
	for i := range secrets.Items {
		r.handleSecretEvent(ctx, &secrets.Items[i])
	}

	slog.Info("actions runner backend started", "namespace", r.cfg.Namespace)
	<-ctx.Done()

	r.mu.Lock()
	for name, cancel := range r.cancels {
		cancel()
		delete(r.cancels, name)
	}
	r.mu.Unlock()

	return nil
}

func (r *Runner) handleSecretEvent(ctx context.Context, obj interface{}) {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		return
	}
	if secret.Namespace != r.cfg.Namespace {
		return
	}
	if _, hasLabel := secret.Labels[repoLabel]; !hasLabel {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Already tracking this secret.
	if _, exists := r.cancels[secret.Name]; exists {
		return
	}

	repo := secret.Annotations[repoAnnotation]
	if repo == "" {
		return
	}

	pollCtx, cancel := context.WithCancel(ctx)
	r.cancels[secret.Name] = cancel

	slog.Info("starting actions poll loop",
		"secret", secret.Name,
		"repo", repo,
	)
	go r.pollLoop(pollCtx, secret.Name, repo)
}

func (r *Runner) handleSecretDelete(obj interface{}) {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		// Handle deleted final state unknown (tombstone).
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		secret, ok = tombstone.Obj.(*corev1.Secret)
		if !ok {
			return
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if cancel, exists := r.cancels[secret.Name]; exists {
		cancel()
		delete(r.cancels, secret.Name)
		slog.Info("stopped actions poll loop", "secret", secret.Name)
	}
}

// pollLoop polls GitHub for queued workflow jobs for a single repo, allocating
// VMs as needed. It runs until ctx is cancelled (i.e. the secret is deleted or
// the runner is shutting down).
func (r *Runner) pollLoop(ctx context.Context, secretName, repo string) {
	// Track jobs we've already allocated a VM for to avoid duplicates.
	allocated := make(map[int64]struct{})

	for {
		token, err := r.readToken(ctx, secretName)
		if err != nil {
			slog.Debug("secret gone, stopping poll loop",
				"secret", secretName,
				"error", err,
			)
			return
		}

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
				result, err := r.cfg.VMClient.Claim(
					ctx,
					r.cfg.PoolName,
					fmt.Sprintf("actions-%d", job.ID),
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
					continue
				}
				allocated[job.ID] = struct{}{}
				slog.Info("allocated runner VM",
					"repo", repo,
					"job_id", job.ID,
					"vm", result.Name,
				)
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(pollInterval):
		}
	}
}

func (r *Runner) readToken(ctx context.Context, secretName string) (string, error) {
	var secret corev1.Secret
	if err := r.cfg.KubeCache.Get(ctx, client.ObjectKey{
		Namespace: r.cfg.Namespace,
		Name:      secretName,
	}, &secret); err != nil {
		return "", err
	}
	return string(secret.Data["token"]), nil
}

// ActiveSessionCount returns the number of active polling loops.
func (r *Runner) ActiveSessionCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.cancels)
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

	resp, err := http.DefaultClient.Do(req)
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
