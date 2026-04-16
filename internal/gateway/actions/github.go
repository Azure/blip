// Package actions implements a GitHub Actions runner backend.
//
// This file provides GitHub App authentication and API helpers for:
//   - Generating GitHub App JWTs
//   - Exchanging JWTs for installation access tokens (with caching)
//   - Creating JIT (just-in-time) runner configurations
//   - Checking workflow job completion status
package actions

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// GitHubApp handles authentication with GitHub using a GitHub App's private
// key. It generates JWTs, exchanges them for installation access tokens, and
// provides helpers for runner-related API calls.
type GitHubApp struct {
	appID      int64
	installID  int64
	signer     jose.Signer
	httpClient *http.Client

	// Installation access token cache. Tokens are valid for 1 hour;
	// we cache them and refresh 5 minutes before expiry.
	mu          sync.Mutex
	cachedToken string
	tokenExpiry time.Time
}

// NewGitHubApp creates a GitHubApp from a PEM-encoded RSA private key file.
func NewGitHubApp(appID, installID int64, keyPath string) (*GitHubApp, error) {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read github app key %s: %w", keyPath, err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", keyPath)
	}

	// Try PKCS#1 first (most GitHub App keys), then PKCS#8.
	var key crypto.Signer
	if rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		key = rsaKey
	} else if pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		signer, ok := pkcs8Key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key in %s is not a signing key", keyPath)
		}
		key = signer
	} else {
		return nil, fmt.Errorf("failed to parse private key in %s (tried PKCS#1 and PKCS#8)", keyPath)
	}

	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		return nil, fmt.Errorf("create JWT signer: %w", err)
	}

	return &GitHubApp{
		appID:      appID,
		installID:  installID,
		signer:     sig,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// appJWT generates a short-lived JWT for authenticating as the GitHub App.
// The JWT is valid for 10 minutes (GitHub's maximum).
func (g *GitHubApp) appJWT() (string, error) {
	now := time.Now()
	claims := jwt.Claims{
		Issuer:   fmt.Sprintf("%d", g.appID),
		IssuedAt: jwt.NewNumericDate(now.Add(-60 * time.Second)), // clock skew buffer
		Expiry:   jwt.NewNumericDate(now.Add(10 * time.Minute)),
	}
	token, err := jwt.Signed(g.signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("sign app JWT: %w", err)
	}
	return token, nil
}

// installationTokenResponse is the response from POST /app/installations/{id}/access_tokens.
type installationTokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// InstallationToken returns a cached installation access token, refreshing
// it when expired or about to expire (within 5 minutes of expiry).
// The mutex is only held for cache reads/writes, not during the HTTP call.
func (g *GitHubApp) InstallationToken(ctx context.Context) (string, error) {
	// Fast path: return cached token.
	g.mu.Lock()
	if g.cachedToken != "" && time.Until(g.tokenExpiry) > 5*time.Minute {
		token := g.cachedToken
		g.mu.Unlock()
		return token, nil
	}
	g.mu.Unlock()

	// Slow path: refresh token (no lock held during HTTP).
	appJWT, err := g.appJWT()
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("https://api.github.com/app/installations/%d/access_tokens", g.installID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+appJWT)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request installation token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("installation token request failed: %d %s", resp.StatusCode, string(body))
	}

	var tokenResp installationTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("decode installation token response: %w", err)
	}

	// Update cache.
	g.mu.Lock()
	g.cachedToken = tokenResp.Token
	g.tokenExpiry = tokenResp.ExpiresAt
	g.mu.Unlock()

	slog.Debug("github app installation token refreshed",
		"expires_at", tokenResp.ExpiresAt.Format(time.RFC3339),
	)
	return tokenResp.Token, nil
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
func (g *GitHubApp) CreateJITRunnerConfig(ctx context.Context, repo string, labels []string, runnerName string) (string, error) {
	token, err := g.InstallationToken(ctx)
	if err != nil {
		return "", fmt.Errorf("get installation token: %w", err)
	}

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

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/actions/runners/generate-jitconfig", parts[0], parts[1])
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := g.httpClient.Do(req)
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

// GetJobStatus returns the status of a workflow job ("queued", "in_progress",
// "completed", etc.).
func (g *GitHubApp) GetJobStatus(ctx context.Context, repo string, jobID int64) (string, error) {
	token, err := g.InstallationToken(ctx)
	if err != nil {
		return "", fmt.Errorf("get installation token: %w", err)
	}

	parts := strings.SplitN(repo, "/", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid repo format: %s", repo)
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/actions/jobs/%d", parts[0], parts[1], jobID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request job status: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("job status request failed: %d %s", resp.StatusCode, string(body))
	}

	var result struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode job status response: %w", err)
	}
	return result.Status, nil
}
