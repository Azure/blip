// Package ghactions implements a GitHub Actions polling handler that provides
// just-in-time self-hosted runners backed by Blip VMs.
package ghactions

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxResponseBodySize = 1 << 20 // 1 MB

// WorkflowJob represents a GitHub Actions workflow job.
type WorkflowJob struct {
	ID     int64    `json:"id"`
	Name   string   `json:"name"`
	Labels []string `json:"labels"`
	RunID  int64    `json:"run_id"`
	Status string   `json:"status"`
}

// TokenProvider is an interface for obtaining runner registration tokens.
type TokenProvider interface {
	CreateRegistrationToken(ctx context.Context, ownerRepo string) (*RegistrationToken, error)
}

// JobsProvider lists queued workflow jobs for a repository.
type JobsProvider interface {
	ListQueuedJobs(ctx context.Context, ownerRepo string) ([]WorkflowJob, error)
}

// GitHubClient obtains runner registration tokens and lists workflow jobs
// using GitHub App authentication.
type GitHubClient struct {
	appID          int64
	installationID int64
	privateKey     *rsa.PrivateKey
	httpClient     *http.Client
	baseURL        string

	mu              sync.Mutex
	installToken    string
	installTokenExp time.Time
}

var _ TokenProvider = (*GitHubClient)(nil)
var _ JobsProvider = (*GitHubClient)(nil)

// NewGitHubClient creates a client that authenticates as a GitHub App.
func NewGitHubClient(appID, installationID int64, keyPath string) (*GitHubClient, error) {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", keyPath)
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		k, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parse private key (PKCS1: %v, PKCS8: %v)", err, err2)
		}
		var ok bool
		key, ok = k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not RSA")
		}
	}
	return &GitHubClient{
		appID:          appID,
		installationID: installationID,
		privateKey:     key,
		httpClient:     &http.Client{Timeout: 30 * time.Second},
		baseURL:        "https://api.github.com",
	}, nil
}

// RegistrationToken holds a just-in-time runner registration token.
type RegistrationToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// CreateRegistrationToken requests a new runner registration token.
func (c *GitHubClient) CreateRegistrationToken(ctx context.Context, ownerRepo string) (*RegistrationToken, error) {
	token, err := c.getInstallationToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("get installation token: %w", err)
	}

	var url string
	if strings.Contains(ownerRepo, "/") {
		url = fmt.Sprintf("%s/repos/%s/actions/runners/registration-token", c.baseURL, ownerRepo)
	} else {
		url = fmt.Sprintf("%s/orgs/%s/actions/runners/registration-token", c.baseURL, ownerRepo)
	}

	body, err := c.doAPI(ctx, http.MethodPost, url, token, http.StatusCreated)
	if err != nil {
		return nil, fmt.Errorf("request registration token: %w", err)
	}

	var rt RegistrationToken
	if err := json.Unmarshal(body, &rt); err != nil {
		return nil, fmt.Errorf("decode registration token: %w", err)
	}
	return &rt, nil
}

// ListQueuedJobs lists workflow jobs with status "queued" for a repository.
// It queries both queued and in_progress runs because a multi-job run moves
// to in_progress once its first job starts, but later jobs may still be queued.
func (c *GitHubClient) ListQueuedJobs(ctx context.Context, ownerRepo string) ([]WorkflowJob, error) {
	token, err := c.getInstallationToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("get installation token: %w", err)
	}

	var allRuns []int64
	for _, status := range []string{"queued", "in_progress"} {
		runs, err := c.listRunIDs(ctx, ownerRepo, status, token)
		if err != nil {
			return nil, fmt.Errorf("list %s runs: %w", status, err)
		}
		allRuns = append(allRuns, runs...)
	}

	// Deduplicate run IDs.
	seen := make(map[int64]bool, len(allRuns))
	var uniqueRuns []int64
	for _, id := range allRuns {
		if !seen[id] {
			seen[id] = true
			uniqueRuns = append(uniqueRuns, id)
		}
	}

	var jobs []WorkflowJob
	for _, runID := range uniqueRuns {
		runJobs, err := c.listJobsForRun(ctx, ownerRepo, runID, token)
		if err != nil {
			slog.Error("failed to list jobs for run, skipping", "repo", ownerRepo, "run_id", runID, "error", err)
			continue
		}
		for _, j := range runJobs {
			if j.Status == "queued" {
				jobs = append(jobs, j)
			}
		}
	}

	return jobs, nil
}

func (c *GitHubClient) listRunIDs(ctx context.Context, ownerRepo, status, token string) ([]int64, error) {
	url := fmt.Sprintf("%s/repos/%s/actions/runs?status=%s&per_page=100", c.baseURL, ownerRepo, status)

	body, err := c.doAPI(ctx, http.MethodGet, url, token, http.StatusOK)
	if err != nil {
		return nil, fmt.Errorf("list %s runs: %w", status, err)
	}

	var runsResp struct {
		WorkflowRuns []struct {
			ID int64 `json:"id"`
		} `json:"workflow_runs"`
	}
	if err := json.Unmarshal(body, &runsResp); err != nil {
		return nil, fmt.Errorf("decode runs response: %w", err)
	}

	ids := make([]int64, len(runsResp.WorkflowRuns))
	for i, r := range runsResp.WorkflowRuns {
		ids[i] = r.ID
	}
	return ids, nil
}

func (c *GitHubClient) listJobsForRun(ctx context.Context, ownerRepo string, runID int64, token string) ([]WorkflowJob, error) {
	url := fmt.Sprintf("%s/repos/%s/actions/runs/%d/jobs?filter=latest&per_page=100", c.baseURL, ownerRepo, runID)

	body, err := c.doAPI(ctx, http.MethodGet, url, token, http.StatusOK)
	if err != nil {
		return nil, fmt.Errorf("list jobs for run %d: %w", runID, err)
	}

	var result struct {
		Jobs []WorkflowJob `json:"jobs"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decode jobs response: %w", err)
	}

	return result.Jobs, nil
}

// doAPI performs an authenticated GitHub API request and returns the response body.
func (c *GitHubClient) doAPI(ctx context.Context, method, url, token string, expectStatus int) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode != expectStatus {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

// getInstallationToken returns a cached installation access token, refreshing if expired.
func (c *GitHubClient) getInstallationToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.installToken != "" && time.Now().Add(60*time.Second).Before(c.installTokenExp) {
		token := c.installToken
		c.mu.Unlock()
		return token, nil
	}
	c.mu.Unlock()

	jwt, err := c.createJWT()
	if err != nil {
		return "", fmt.Errorf("create JWT: %w", err)
	}

	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", c.baseURL, c.installationID)
	body, err := c.doAPI(ctx, http.MethodPost, url, jwt, http.StatusCreated)
	if err != nil {
		return "", fmt.Errorf("request installation token: %w", err)
	}

	var result struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("decode installation token: %w", err)
	}

	c.mu.Lock()
	c.installToken = result.Token
	c.installTokenExp = result.ExpiresAt
	c.mu.Unlock()

	return result.Token, nil
}

func (c *GitHubClient) createJWT() (string, error) {
	now := time.Now().Add(-30 * time.Second) // Clock skew tolerance.
	exp := now.Add(10 * time.Minute)

	headerBytes, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	claimsBytes, err := json.Marshal(map[string]any{
		"iat": now.Unix(),
		"exp": exp.Unix(),
		"iss": strconv.FormatInt(c.appID, 10),
	})
	if err != nil {
		return "", fmt.Errorf("marshal JWT claims: %w", err)
	}

	header := base64URLEncode(headerBytes)
	payload := base64URLEncode(claimsBytes)

	sigInput := header + "." + payload
	h := sha256.Sum256([]byte(sigInput))
	sig, err := rsa.SignPKCS1v15(nil, c.privateKey, crypto.SHA256, h[:])
	if err != nil {
		return "", fmt.Errorf("sign JWT: %w", err)
	}

	return sigInput + "." + base64URLEncode(sig), nil
}

func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
