package ghactions

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// ScaleSetClient communicates with the GitHub Actions Service using the
// Runner Scale Set protocol. It does not require a GitHub App -- only a
// registration token (obtained externally and stored in a K8s Secret).
type ScaleSetClient struct {
	configURL         string // e.g. "https://github.com/owner/repo"
	actionsServiceURL string // obtained from /actions/runner-registration
	adminToken        string // JWT for Actions Service, refreshed from registration token
	adminTokenExpiry  time.Time
	registrationToken string // current registration token from K8s Secret
	scaleSetID        int    // assigned by server on CreateScaleSet
	httpClient        *http.Client
	longPollClient    *http.Client // no timeout, for long-poll requests
	mu                sync.Mutex
}

// NewScaleSetClient creates a new client for the Actions Service scale set protocol.
// configURL is the GitHub URL for the repo or org (e.g. "https://github.com/owner/repo").
func NewScaleSetClient(configURL string) *ScaleSetClient {
	return &ScaleSetClient{
		configURL:  configURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		// longPollClient has no timeout — it relies on the per-request
		// context for cancellation. This is needed because long-poll
		// requests may be held by the server for 50+ seconds.
		longPollClient: &http.Client{},
	}
}

// UpdateRegistrationToken sets a new registration token. Called when the K8s
// Secret is updated by the external cron workflow.
func (c *ScaleSetClient) UpdateRegistrationToken(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.registrationToken = token
	// Invalidate the admin token so the next API call refreshes it using
	// the new registration token.
	c.adminToken = ""
	c.adminTokenExpiry = time.Time{}
	slog.Info("registration token updated")
}

// ScaleSetID returns the current scale set ID.
func (c *ScaleSetClient) ScaleSetID() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.scaleSetID
}

// SetScaleSetID sets the scale set ID (used after create/get).
func (c *ScaleSetClient) SetScaleSetID(id int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.scaleSetID = id
}

// ActionsServiceURL returns the current Actions Service URL.
func (c *ScaleSetClient) ActionsServiceURL() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.actionsServiceURL
}

// LongPollHTTPClient returns the HTTP client configured for long-poll requests
// (no timeout -- relies on per-request context for cancellation).
func (c *ScaleSetClient) LongPollHTTPClient() *http.Client {
	return c.longPollClient
}

// registrationResponse is the response from POST /actions/runner-registration.
type registrationResponse struct {
	URL   string `json:"url"`
	Token string `json:"token"`
	// TokenSchema is "OAuthAccessToken" for the admin JWT.
	TokenSchema string `json:"token_schema"`
}

// refreshAdminToken exchanges the registration token for an Actions Service
// URL and admin JWT via POST /actions/runner-registration.
//
// Note: The registration token is read under lock then used outside the lock.
// This is intentional: if UpdateRegistrationToken races with this method,
// the worst case is one request using a stale-but-valid token. The next call
// will pick up the new token since the admin token was invalidated.
func (c *ScaleSetClient) refreshAdminToken(ctx context.Context) error {
	c.mu.Lock()
	regToken := c.registrationToken
	// Check if the current admin token is still valid (with 60s buffer).
	if c.adminToken != "" && time.Now().Add(60*time.Second).Before(c.adminTokenExpiry) {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	if regToken == "" {
		return fmt.Errorf("no registration token available")
	}

	// The runner-registration endpoint is on the GitHub config URL, not
	// on api.github.com. For "https://github.com/owner/repo", the
	// endpoint is "https://github.com/owner/repo/actions/runner-registration".
	url := c.configURL + "/actions/runner-registration"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return fmt.Errorf("create registration request: %w", err)
	}
	req.Header.Set("Authorization", "RemoteAuth "+regToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("registration request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return fmt.Errorf("read registration response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("registration failed HTTP %d: %s", resp.StatusCode, string(body))
	}

	var regResp registrationResponse
	if err := json.Unmarshal(body, &regResp); err != nil {
		return fmt.Errorf("decode registration response: %w", err)
	}

	if regResp.URL == "" || regResp.Token == "" {
		return fmt.Errorf("registration response missing url or token")
	}

	c.mu.Lock()
	c.actionsServiceURL = regResp.URL
	c.adminToken = regResp.Token
	// Admin tokens typically last ~1 hour. We set expiry conservatively
	// to 50 minutes to ensure we refresh before actual expiry.
	c.adminTokenExpiry = time.Now().Add(50 * time.Minute)
	c.mu.Unlock()

	slog.Info("admin token refreshed",
		"actions_service_url", regResp.URL,
	)
	return nil
}

// getAdminAuth returns the current admin token and Actions Service URL,
// refreshing if necessary.
func (c *ScaleSetClient) getAdminAuth(ctx context.Context) (serviceURL, token string, err error) {
	if err := c.refreshAdminToken(ctx); err != nil {
		return "", "", fmt.Errorf("refresh admin token: %w", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.actionsServiceURL, c.adminToken, nil
}

// scaleSetRequest is the request body for creating a scale set.
type scaleSetRequest struct {
	Name          string                 `json:"name"`
	RunnerGroupID int                    `json:"runnerGroupId"`
	RunnerSetting scaleSetRunnerSettings `json:"runnerSetting"`
	Labels        []scaleSetLabel        `json:"labels"`
}

type scaleSetRunnerSettings struct {
	Ephemeral  bool   `json:"isEphemeral"`
	WorkFolder string `json:"workFolder"`
}

type scaleSetLabel struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// ScaleSet is the response from scale set create/get operations.
type ScaleSet struct {
	ID            int             `json:"id"`
	Name          string          `json:"name"`
	RunnerGroupID int             `json:"runnerGroupId"`
	Labels        []scaleSetLabel `json:"labels"`
}

// CreateScaleSet registers a new runner scale set with the Actions Service.
func (c *ScaleSetClient) CreateScaleSet(ctx context.Context, name string, labels []string, runnerGroupID int) (*ScaleSet, error) {
	serviceURL, token, err := c.getAdminAuth(ctx)
	if err != nil {
		return nil, err
	}

	ssLabels := make([]scaleSetLabel, len(labels))
	for i, l := range labels {
		ssLabels[i] = scaleSetLabel{Name: l, Type: "User"}
	}

	reqBody := scaleSetRequest{
		Name:          name,
		RunnerGroupID: runnerGroupID,
		RunnerSetting: scaleSetRunnerSettings{
			Ephemeral:  true,
			WorkFolder: "_work",
		},
		Labels: ssLabels,
	}

	url := fmt.Sprintf("%s/_apis/runtime/runnerscalesets", serviceURL)
	var result ScaleSet
	if err := c.doActionsAPI(ctx, http.MethodPost, url, token, reqBody, &result); err != nil {
		return nil, fmt.Errorf("create scale set: %w", err)
	}

	c.SetScaleSetID(result.ID)
	slog.Info("scale set created", "id", result.ID, "name", result.Name)
	return &result, nil
}

// GetScaleSet finds an existing scale set by name.
func (c *ScaleSetClient) GetScaleSet(ctx context.Context, name string) (*ScaleSet, error) {
	serviceURL, token, err := c.getAdminAuth(ctx)
	if err != nil {
		return nil, err
	}

	reqURL := fmt.Sprintf("%s/_apis/runtime/runnerscalesets?name=%s", serviceURL, url.QueryEscape(name))

	var result struct {
		Count     int        `json:"count"`
		ScaleSets []ScaleSet `json:"value"`
	}
	if err := c.doActionsAPI(ctx, http.MethodGet, reqURL, token, nil, &result); err != nil {
		return nil, fmt.Errorf("get scale set: %w", err)
	}

	if result.Count == 0 || len(result.ScaleSets) == 0 {
		return nil, nil // not found
	}

	ss := &result.ScaleSets[0]
	c.SetScaleSetID(ss.ID)
	return ss, nil
}

// GetOrCreateScaleSet finds an existing scale set by name, or creates a new one.
func (c *ScaleSetClient) GetOrCreateScaleSet(ctx context.Context, name string, labels []string, runnerGroupID int) (*ScaleSet, error) {
	existing, err := c.GetScaleSet(ctx, name)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		slog.Info("found existing scale set", "id", existing.ID, "name", existing.Name)
		return existing, nil
	}
	return c.CreateScaleSet(ctx, name, labels, runnerGroupID)
}

// Session represents a message queue session for the scale set.
type Session struct {
	SessionID               string `json:"sessionId"`
	OwnerName               string `json:"ownerName"`
	MessageQueueURL         string `json:"messageQueueUrl"`
	MessageQueueAccessToken string `json:"messageQueueAccessToken"`
}

// CreateSession opens a new message queue session for the scale set.
func (c *ScaleSetClient) CreateSession(ctx context.Context) (*Session, error) {
	serviceURL, token, err := c.getAdminAuth(ctx)
	if err != nil {
		return nil, err
	}

	ssID := c.ScaleSetID()
	if ssID == 0 {
		return nil, fmt.Errorf("scale set ID not set; call GetOrCreateScaleSet first")
	}

	url := fmt.Sprintf("%s/_apis/runtime/runnerscalesets/%d/sessions", serviceURL, ssID)

	reqBody := map[string]string{
		"ownerName": "blip-controller",
	}

	var session Session
	if err := c.doActionsAPI(ctx, http.MethodPost, url, token, reqBody, &session); err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	slog.Info("scale set session created",
		"session_id", session.SessionID,
		"scale_set_id", ssID,
	)
	return &session, nil
}

// RefreshSession refreshes the message queue access token for an existing session.
func (c *ScaleSetClient) RefreshSession(ctx context.Context, sessionID string) (*Session, error) {
	serviceURL, token, err := c.getAdminAuth(ctx)
	if err != nil {
		return nil, err
	}

	ssID := c.ScaleSetID()
	url := fmt.Sprintf("%s/_apis/runtime/runnerscalesets/%d/sessions/%s",
		serviceURL, ssID, sessionID)

	var session Session
	if err := c.doActionsAPI(ctx, http.MethodPatch, url, token, nil, &session); err != nil {
		return nil, fmt.Errorf("refresh session: %w", err)
	}
	return &session, nil
}

// DeleteSession deletes a message queue session.
func (c *ScaleSetClient) DeleteSession(ctx context.Context, sessionID string) error {
	serviceURL, token, err := c.getAdminAuth(ctx)
	if err != nil {
		return err
	}

	ssID := c.ScaleSetID()
	url := fmt.Sprintf("%s/_apis/runtime/runnerscalesets/%d/sessions/%s",
		serviceURL, ssID, sessionID)

	if err := c.doActionsAPI(ctx, http.MethodDelete, url, token, nil, nil); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

// AcquireJobsRequest is the request body for acquiring jobs.
type AcquireJobsRequest struct {
	RequestIDs []int64 `json:"requestIds"`
}

// AcquireJobsResponse is the response from acquiring jobs.
type AcquireJobsResponse struct {
	Count int               `json:"count"`
	Jobs  []AcquiredJobInfo `json:"value"`
}

// AcquiredJobInfo represents an acquired job.
type AcquiredJobInfo struct {
	RequestID       int64 `json:"requestId"`
	RunnerRequestID int64 `json:"runnerRequestId"`
}

// AcquireJobs claims jobs from the queue.
func (c *ScaleSetClient) AcquireJobs(ctx context.Context, requestIDs []int64) (*AcquireJobsResponse, error) {
	serviceURL, token, err := c.getAdminAuth(ctx)
	if err != nil {
		return nil, err
	}

	ssID := c.ScaleSetID()
	url := fmt.Sprintf("%s/_apis/runtime/runnerscalesets/%d/acquirejobs", serviceURL, ssID)

	reqBody := AcquireJobsRequest{RequestIDs: requestIDs}

	var result AcquireJobsResponse
	if err := c.doActionsAPI(ctx, http.MethodPost, url, token, reqBody, &result); err != nil {
		return nil, fmt.Errorf("acquire jobs: %w", err)
	}

	slog.Info("jobs acquired", "count", result.Count, "scale_set_id", ssID)
	return &result, nil
}

// JitRunnerConfigRequest is the request body for generating JIT runner config.
type JitRunnerConfigRequest struct {
	Name       string `json:"name"`
	WorkFolder string `json:"workFolder"`
}

// JitRunnerConfigResponse is the response from generating JIT runner config.
type JitRunnerConfigResponse struct {
	EncodedJITConfig string          `json:"encodedJITConfig"`
	Runner           json.RawMessage `json:"runner"`
}

// GenerateJitRunnerConfig generates a JIT config for a new ephemeral runner.
// The server generates an RSA keypair and credentials internally -- no
// pre-registration is needed.
func (c *ScaleSetClient) GenerateJitRunnerConfig(ctx context.Context, name string) (*JitRunnerConfigResponse, error) {
	serviceURL, token, err := c.getAdminAuth(ctx)
	if err != nil {
		return nil, err
	}

	ssID := c.ScaleSetID()
	url := fmt.Sprintf("%s/_apis/runtime/runnerscalesets/%d/generatejitconfig", serviceURL, ssID)

	reqBody := JitRunnerConfigRequest{
		Name:       name,
		WorkFolder: "_work",
	}

	var result JitRunnerConfigResponse
	if err := c.doActionsAPI(ctx, http.MethodPost, url, token, reqBody, &result); err != nil {
		return nil, fmt.Errorf("generate JIT config: %w", err)
	}

	slog.Info("JIT runner config generated", "runner_name", name, "scale_set_id", ssID)
	return &result, nil
}

// DeleteMessage acknowledges a message from the message queue by deleting it.
func (c *ScaleSetClient) DeleteMessage(ctx context.Context, sessionID string, messageID int64) error {
	serviceURL, token, err := c.getAdminAuth(ctx)
	if err != nil {
		return err
	}

	ssID := c.ScaleSetID()
	url := fmt.Sprintf("%s/_apis/runtime/runnerscalesets/%d/sessions/%s/messages/%d",
		serviceURL, ssID, sessionID, messageID)

	if err := c.doActionsAPI(ctx, http.MethodDelete, url, token, nil, nil); err != nil {
		return fmt.Errorf("delete message %d: %w", messageID, err)
	}
	return nil
}

// doActionsAPI performs an authenticated Actions Service API request.
func (c *ScaleSetClient) doActionsAPI(ctx context.Context, method, url, token string, reqBody any, result any) error {
	var bodyReader io.Reader
	if reqBody != nil {
		data, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	// DELETE may return 204 No Content.
	if method == http.MethodDelete && resp.StatusCode == http.StatusNoContent {
		return nil
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Actions Service HTTP %d: %s", resp.StatusCode, string(body))
	}

	if result != nil && len(body) > 0 {
		if err := json.Unmarshal(body, result); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}

	return nil
}
