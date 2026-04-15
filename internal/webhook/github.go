// Package webhook implements a GitHub Actions webhook handler that provides
// just-in-time self-hosted runners backed by Blip VMs.
package webhook

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// maxResponseBodySize limits the size of GitHub API response bodies we read.
const maxResponseBodySize = 1 << 20 // 1 MB

// GitHubClient obtains runner registration tokens from the GitHub API using
// GitHub App authentication.
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

// NewGitHubClient creates a client that authenticates as a GitHub App.
// keyPath is the path to the PEM-encoded RSA private key.
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
		// Try PKCS8.
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

// CreateRegistrationToken requests a new runner registration token for the given
// repository (owner/repo format) or organization.
func (c *GitHubClient) CreateRegistrationToken(ctx context.Context, ownerRepo string) (*RegistrationToken, error) {
	token, err := c.getInstallationToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("get installation token: %w", err)
	}

	// Determine if this is an org or repo registration.
	var url string
	if strings.Contains(ownerRepo, "/") {
		url = fmt.Sprintf("%s/repos/%s/actions/runners/registration-token", c.baseURL, ownerRepo)
	} else {
		url = fmt.Sprintf("%s/orgs/%s/actions/runners/registration-token", c.baseURL, ownerRepo)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request registration token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("registration token request failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var rt RegistrationToken
	if err := json.Unmarshal(body, &rt); err != nil {
		return nil, fmt.Errorf("decode registration token: %w", err)
	}
	return &rt, nil
}

// getInstallationToken returns a cached installation access token, refreshing if expired.
// Uses a check-lock-check pattern to avoid holding the mutex during HTTP requests.
func (c *GitHubClient) getInstallationToken(ctx context.Context) (string, error) {
	// Fast path: check cache under read-like lock.
	c.mu.Lock()
	if c.installToken != "" && time.Now().Add(60*time.Second).Before(c.installTokenExp) {
		token := c.installToken
		c.mu.Unlock()
		return token, nil
	}
	c.mu.Unlock()

	// Slow path: fetch a new token (outside lock).
	jwt, err := c.createJWT()
	if err != nil {
		return "", fmt.Errorf("create JWT: %w", err)
	}

	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", c.baseURL, c.installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request installation token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return "", fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("installation token request failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var result struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("decode installation token: %w", err)
	}

	// Store under lock.
	c.mu.Lock()
	c.installToken = result.Token
	c.installTokenExp = result.ExpiresAt
	c.mu.Unlock()

	return result.Token, nil
}

// createJWT creates a short-lived JWT for GitHub App authentication.
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

// TokenProvider is an interface for obtaining runner registration tokens.
// This allows the handler to be tested with a mock implementation.
type TokenProvider interface {
	CreateRegistrationToken(ctx context.Context, ownerRepo string) (*RegistrationToken, error)
}

// Ensure GitHubClient implements TokenProvider.
var _ TokenProvider = (*GitHubClient)(nil)

// VerifyWebhookSignature verifies the X-Hub-Signature-256 header against the
// request body using the shared webhook secret.
func VerifyWebhookSignature(body []byte, signature string, secret []byte) bool {
	if !strings.HasPrefix(signature, "sha256=") {
		return false
	}
	sigBytes, err := hex.DecodeString(strings.TrimPrefix(signature, "sha256="))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	expected := mac.Sum(nil)
	return subtle.ConstantTimeCompare(expected, sigBytes) == 1
}
