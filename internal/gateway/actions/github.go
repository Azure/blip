// Package actions provides GitHub API helpers for the Actions runner backend
// and a PAT provider that watches a Kubernetes Secret. The polling and job
// monitoring logic lives in the actions controller
// (internal/controllers/actions).
package actions

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
	"log/slog"
	"net/http"
	crcache "sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"strings"
	"sync"
)

// PATProvider watches a Kubernetes Secret for a GitHub Personal Access Token
// and provides thread-safe access to the current token value. The token is
// updated automatically when the Secret changes.
type PATProvider struct {
	namespace  string
	secretName string
	cache      crcache.Cache

	mu    sync.RWMutex
	token string
}

// NewPATProvider creates a PATProvider that watches the named Secret for a
// "token" key. It performs an initial load from the cache (tolerating a missing
// Secret) and registers an event handler so token rotations and late creation
// are picked up immediately. The cache must already be started and synced.
func NewPATProvider(ctx context.Context, informerCache crcache.Cache, namespace, secretName string) (*PATProvider, error) {
	p := &PATProvider{
		namespace:  namespace,
		secretName: secretName,
		cache:      informerCache,
	}

	// Initial load from the cache — tolerate missing Secret so the
	// controller can start before the PAT Secret is created.
	var secret corev1.Secret
	if err := informerCache.Get(ctx, client.ObjectKey{Namespace: namespace, Name: secretName}, &secret); err == nil {
		p.updateFromSecret(&secret)
	} else {
		slog.Info("PAT secret not found, actions will activate when it is created",
			"namespace", namespace,
			"secret", secretName,
		)
	}

	// Register event handler for live updates.
	informer, err := informerCache.GetInformer(ctx, &corev1.Secret{})
	if err != nil {
		return nil, fmt.Errorf("get secret informer: %w", err)
	}

	if _, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { p.handleEvent(obj) },
		UpdateFunc: func(_, obj interface{}) { p.handleEvent(obj) },
		DeleteFunc: func(obj interface{}) {
			secret, ok := obj.(*corev1.Secret)
			if !ok {
				return
			}
			if secret.Name == p.secretName && secret.Namespace == p.namespace {
				p.mu.Lock()
				p.token = ""
				p.mu.Unlock()
				slog.Warn("PAT secret deleted, actions runner disabled until recreated",
					"namespace", p.namespace,
					"secret", p.secretName,
				)
			}
		},
	}); err != nil {
		return nil, fmt.Errorf("add PAT secret event handler: %w", err)
	}

	slog.Info("PAT provider started",
		"namespace", namespace,
		"secret", secretName,
	)
	return p, nil
}

// Token returns the current PAT. Returns an error if no token is available.
func (p *PATProvider) Token() (string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.token == "" {
		return "", fmt.Errorf("no PAT available from secret %s/%s", p.namespace, p.secretName)
	}
	return p.token, nil
}

func (p *PATProvider) handleEvent(obj interface{}) {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		return
	}
	if secret.Name != p.secretName || secret.Namespace != p.namespace {
		return
	}
	p.updateFromSecret(secret)
	slog.Info("PAT updated from secret",
		"namespace", p.namespace,
		"secret", p.secretName,
	)
}

func (p *PATProvider) updateFromSecret(secret *corev1.Secret) {
	token := string(secret.Data["token"])
	p.mu.Lock()
	p.token = token
	p.mu.Unlock()
}

// jitConfigRequest is the request body for POST /repos/{owner}/{repo}/actions/runners/generate-jitconfig.
type jitConfigRequest struct {
	Name          string   `json:"name"`
	RunnerGroupID int      `json:"runner_group_id"`
	Labels        []string `json:"labels"`
	WorkFolder    string   `json:"work_folder"`
}

// jitConfigResponse is the response from generate-jitconfig.
type jitConfigResponse struct {
	EncodedJITConfig string `json:"encoded_jit_config"`
	Runner           struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	} `json:"runner"`
}

// CreateJITRunnerConfig creates a just-in-time runner configuration for the
// given repository. The returned encoded config is passed directly to
// `run.sh --jitconfig <config>` inside the VM. The runner is automatically
// ephemeral (single job) and does not require separate registration.
func CreateJITRunnerConfig(ctx context.Context, token, repo string, labels []string, runnerName string) (string, error) {
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid repo format: %s (expected owner/repo)", repo)
	}

	reqBody := jitConfigRequest{
		Name:          runnerName,
		RunnerGroupID: 1, // Default runner group.
		Labels:        labels,
		WorkFolder:    "_work",
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal JIT config request: %w", err)
	}

	url := fmt.Sprintf("%s/repos/%s/%s/actions/runners/generate-jitconfig", githubAPIBase, parts[0], parts[1])
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := githubHTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request JIT config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("JIT config request failed: %d %s", resp.StatusCode, string(body))
	}

	var jitResp jitConfigResponse
	if err := json.NewDecoder(resp.Body).Decode(&jitResp); err != nil {
		return "", fmt.Errorf("decode JIT config response: %w", err)
	}

	slog.Info("created JIT runner config",
		"repo", repo,
		"runner_name", runnerName,
		"runner_id", jitResp.Runner.ID,
	)
	return jitResp.EncodedJITConfig, nil
}

// WorkflowJob represents a GitHub Actions workflow job.
type WorkflowJob struct {
	ID     int64    `json:"id"`
	Status string   `json:"status"`
	Labels []string `json:"labels"`
}

type jobsResponse struct {
	Jobs []WorkflowJob `json:"jobs"`
}

type runsResponse struct {
	WorkflowRuns []workflowRun `json:"workflow_runs"`
}

type workflowRun struct {
	ID int64 `json:"id"`
}

// ListQueuedJobs returns queued workflow jobs for the given repo.
func ListQueuedJobs(ctx context.Context, repo, token string) ([]WorkflowJob, error) {
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid repo format: %s", repo)
	}
	owner, repoName := parts[0], parts[1]

	runsURL := fmt.Sprintf("%s/repos/%s/%s/actions/runs?status=queued&per_page=100", githubAPIBase, owner, repoName)
	runs, err := ghGet[runsResponse](ctx, runsURL, token)
	if err != nil {
		return nil, fmt.Errorf("list runs: %w", err)
	}

	var queued []WorkflowJob
	for _, run := range runs.WorkflowRuns {
		jobsURL := fmt.Sprintf("%s/repos/%s/%s/actions/runs/%d/jobs?filter=latest&per_page=100", githubAPIBase, owner, repoName, run.ID)
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

// ghGet performs a GitHub API GET request and decodes the JSON response.
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

// GetJobStatus returns the status of a workflow job ("queued", "in_progress",
// "completed", etc.).
func GetJobStatus(ctx context.Context, token, repo string, jobID int64) (string, error) {
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid repo format: %s", repo)
	}

	url := fmt.Sprintf("%s/repos/%s/%s/actions/jobs/%d", githubAPIBase, parts[0], parts[1], jobID)
	type jobStatusResponse struct {
		Status string `json:"status"`
	}
	result, err := ghGet[jobStatusResponse](ctx, url, token)
	if err != nil {
		return "", err
	}
	return result.Status, nil
}
