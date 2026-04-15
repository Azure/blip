// Package auth — deviceflow.go implements the OAuth2 Device Authorization Grant
// (RFC 8628) for interactive SSH login. This allows users to connect to the
// gateway without pre-obtaining a token — they are presented with a URL and
// code in the SSH terminal, complete authentication in a browser, and the
// gateway exchanges the device code for an access token.
package auth

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// deviceFlowHTTPClient is used for all device flow HTTP requests.
// Separate from http.DefaultClient to allow timeout configuration
// and safe test overrides without global mutation.
var deviceFlowHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
}

// DeviceAuthResponse holds the response from the OAuth2 device authorization endpoint.
type DeviceAuthResponse struct {
	// DeviceCode is the device verification code (sent to the token endpoint).
	DeviceCode string `json:"device_code"`

	// UserCode is the code the user enters at the verification URI.
	UserCode string `json:"user_code"`

	// VerificationURI is the URL the user visits to authenticate.
	VerificationURI string `json:"verification_uri"`

	// VerificationURIComplete is the full URL with the user code embedded
	// (if supported by the provider). The user can visit this directly.
	VerificationURIComplete string `json:"verification_uri_complete"`

	// ExpiresIn is the lifetime of the device code in seconds.
	ExpiresIn int `json:"expires_in"`

	// Interval is the minimum polling interval in seconds (default: 5).
	Interval int `json:"interval"`
}

// DeviceTokenResponse holds a successful token response from polling.
type DeviceTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
}

// DeviceFlowError represents an OAuth2 error response during device flow polling.
type DeviceFlowError struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func (e *DeviceFlowError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Description)
	}
	return e.Code
}

// Standard device flow error codes from RFC 8628.
const (
	errAuthorizationPending = "authorization_pending"
	errSlowDown             = "slow_down"
	errAccessDenied         = "access_denied"
	errExpiredToken         = "expired_token"
)

// TokenFingerprint computes a SHA256 fingerprint of a token string.
// Used for auth fingerprint tracking without storing the raw token.
func TokenFingerprint(token string) string {
	h := sha256.Sum256([]byte(token))
	return fmt.Sprintf("SHA256:%x", h)
}

// RequestDeviceCode initiates the device authorization flow by calling the
// provider's device authorization endpoint. Returns the device code, user code,
// and verification URI.
func RequestDeviceCode(ctx context.Context, cfg OIDCProviderConfig) (*DeviceAuthResponse, error) {
	data := url.Values{
		"client_id": {cfg.ClientID},
	}
	// Always request offline_access for refresh token issuance when not
	// already included in the configured scopes. This is essential for the
	// identity store to maintain a strong OIDC binding via refresh tokens.
	scopes := cfg.Scopes
	hasOfflineAccess := false
	for _, s := range scopes {
		if s == "offline_access" {
			hasOfflineAccess = true
			break
		}
	}
	if !hasOfflineAccess && !isGitHubDeviceFlow(cfg) {
		scopes = append(scopes, "offline_access")
	}
	if len(scopes) > 0 {
		data.Set("scope", strings.Join(scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.DeviceAuthURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create device auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := deviceFlowHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("device auth request to %s: %w", cfg.DeviceAuthURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("read device auth response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp DeviceFlowError
		if json.Unmarshal(body, &errResp) == nil && errResp.Code != "" {
			return nil, fmt.Errorf("device auth endpoint %s returned error: %w", cfg.DeviceAuthURL, &errResp)
		}
		return nil, fmt.Errorf("device auth endpoint %s returned status %d: %s", cfg.DeviceAuthURL, resp.StatusCode, string(body))
	}

	var authResp DeviceAuthResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		return nil, fmt.Errorf("parse device auth response: %w", err)
	}

	if authResp.DeviceCode == "" || authResp.UserCode == "" {
		return nil, fmt.Errorf("device auth response missing device_code or user_code")
	}
	if authResp.VerificationURI == "" {
		return nil, fmt.Errorf("device auth response missing verification_uri")
	}

	// Validate that verification URIs use HTTPS to prevent phishing.
	if !strings.HasPrefix(authResp.VerificationURI, "https://") {
		return nil, fmt.Errorf("device auth response verification_uri is not HTTPS: %s", authResp.VerificationURI)
	}
	if authResp.VerificationURIComplete != "" && !strings.HasPrefix(authResp.VerificationURIComplete, "https://") {
		return nil, fmt.Errorf("device auth response verification_uri_complete is not HTTPS: %s", authResp.VerificationURIComplete)
	}

	// Default polling interval per RFC 8628.
	if authResp.Interval == 0 {
		authResp.Interval = 5
	}
	// Default expiry.
	if authResp.ExpiresIn == 0 {
		authResp.ExpiresIn = 900 // 15 minutes
	}

	return &authResp, nil
}

// PollForToken polls the token endpoint until the user completes authentication,
// the device code expires, or the context is cancelled. The sendStatus callback
// is called with user-facing progress messages.
func PollForToken(ctx context.Context, cfg OIDCProviderConfig, deviceCode string, interval int, expiresIn int, sendStatus func(string)) (*DeviceTokenResponse, error) {
	pollInterval := time.Duration(interval) * time.Second
	deadlineTimer := time.NewTimer(time.Duration(expiresIn) * time.Second)
	defer deadlineTimer.Stop()

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadlineTimer.C:
			return nil, fmt.Errorf("device code expired after %d seconds", expiresIn)
		case <-ticker.C:
			tokenResp, err := pollTokenEndpoint(ctx, cfg, deviceCode)
			if err == nil {
				return tokenResp, nil
			}

			var dfErr *DeviceFlowError
			if !isDeviceFlowError(err, &dfErr) {
				// Non-device-flow error (network error, etc.) — log and retry.
				slog.Debug("device flow poll error", "error", err)
				continue
			}

			switch dfErr.Code {
			case errAuthorizationPending:
				// Expected — user hasn't completed auth yet.
				continue
			case errSlowDown:
				// Server wants us to slow down.
				pollInterval += 5 * time.Second
				ticker.Reset(pollInterval)
				continue
			case errAccessDenied:
				return nil, fmt.Errorf("authentication denied by user or provider")
			case errExpiredToken:
				return nil, fmt.Errorf("device code expired — please try again")
			default:
				return nil, fmt.Errorf("device flow error: %w", dfErr)
			}
		}
	}
}

// pollTokenEndpoint makes a single request to the token endpoint.
func pollTokenEndpoint(ctx context.Context, cfg OIDCProviderConfig, deviceCode string) (*DeviceTokenResponse, error) {
	data := url.Values{
		"client_id":   {cfg.ClientID},
		"device_code": {deviceCode},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := deviceFlowHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request to %s: %w", cfg.TokenURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("read token response: %w", err)
	}

	// Check for error responses (HTTP 400 is normal during polling).
	if resp.StatusCode != http.StatusOK {
		var errResp DeviceFlowError
		if json.Unmarshal(body, &errResp) == nil && errResp.Code != "" {
			return nil, &errResp
		}
		return nil, fmt.Errorf("token endpoint %s returned status %d: %s", cfg.TokenURL, resp.StatusCode, string(body))
	}

	var tokenResp DeviceTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("parse token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("token response missing access_token")
	}

	return &tokenResp, nil
}

// isDeviceFlowError checks if err is (or wraps) a *DeviceFlowError and
// extracts it into target. Returns false if err is not a DeviceFlowError.
func isDeviceFlowError(err error, target **DeviceFlowError) bool {
	return errors.As(err, target)
}

// resolveGitHubIdentity fetches the authenticated user's identity from the
// GitHub API using an opaque OAuth access token. GitHub's device flow returns
// opaque tokens (not JWTs), so OIDC verification cannot be used. Instead we
// call the /user endpoint and use the user's login as the identity.
func resolveGitHubIdentity(ctx context.Context, accessToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		return "", fmt.Errorf("create GitHub user request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := deviceFlowHTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("GitHub user API request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", fmt.Errorf("read GitHub user response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub user API returned status %d: %s", resp.StatusCode, string(body))
	}

	var user struct {
		Login string `json:"login"`
		ID    int64  `json:"id"`
	}
	if err := json.Unmarshal(body, &user); err != nil {
		return "", fmt.Errorf("parse GitHub user response: %w", err)
	}

	if user.Login == "" {
		return "", fmt.Errorf("GitHub user response missing login field")
	}

	return fmt.Sprintf("oidc:%s", user.Login), nil
}

// isGitHubDeviceFlow reports whether the provider is a GitHub OAuth device flow
// (which returns opaque access tokens, not JWTs).
func isGitHubDeviceFlow(cfg OIDCProviderConfig) bool {
	return strings.Contains(cfg.DeviceAuthURL, "github.com/login/device")
}

// RunDeviceFlow performs the complete device authorization flow for the given
// provider configuration. It initiates the device code request, displays
// instructions to the user via sendMessage, polls for completion, and verifies
// the resulting token. Returns the verified OIDC identity, a token
// fingerprint (never the raw token), the refresh token (if issued by the
// provider), and the issuer URL.
//
// sendMessage is called to display text to the user (e.g. via SSH stderr).
func RunDeviceFlow(ctx context.Context, cfg OIDCProviderConfig, sendMessage func(string)) (identity string, fingerprint string, refreshToken string, issuer string, err error) {
	slog.Info("starting device flow",
		"issuer", cfg.Issuer,
		"client_id", cfg.ClientID,
	)

	authResp, err := RequestDeviceCode(ctx, cfg)
	if err != nil {
		return "", "", "", "", fmt.Errorf("request device code: %w", err)
	}

	// Display the verification instructions to the user.
	msg := formatDeviceFlowPrompt(authResp)
	sendMessage(msg)

	slog.Debug("device flow: waiting for user authentication",
		"issuer", cfg.Issuer,
		"expires_in", authResp.ExpiresIn,
	)

	// Poll for the token.
	tokenResp, err := PollForToken(ctx, cfg, authResp.DeviceCode, authResp.Interval, authResp.ExpiresIn, sendMessage)
	if err != nil {
		return "", "", "", "", fmt.Errorf("device flow poll: %w", err)
	}

	// Compute fingerprint from the access token for session tracking.
	// Done here so the raw token never leaves this function.
	fp := TokenFingerprint(tokenResp.AccessToken)

	// Resolve the user identity.
	if isGitHubDeviceFlow(cfg) {
		// GitHub OAuth returns opaque access tokens, not JWTs.
		// Use the GitHub API to resolve the user identity.
		identity, err = resolveGitHubIdentity(ctx, tokenResp.AccessToken)
		if err != nil {
			return "", "", "", "", fmt.Errorf("resolve GitHub identity: %w", err)
		}

		// Verify against allowed-subjects if configured.
		// Strip the "oidc:" prefix for the allowlist check.
		rawIdentity := strings.TrimPrefix(identity, "oidc:")
		if err := checkSubjectAllowed(rawIdentity, cfg.AllowedSubjects); err != nil {
			return "", "", "", "", fmt.Errorf("GitHub identity check: %w", err)
		}
	} else {
		// Standard OIDC flow: verify the token's JWT signature.
		// Prefer id_token (proper OIDC), fall back to access_token (Azure).
		tokenToVerify := tokenResp.IDToken
		if tokenToVerify == "" {
			tokenToVerify = tokenResp.AccessToken
		}

		identity, err = verifyTokenAgainstProvider(tokenToVerify, cfg)
		if err != nil {
			return "", "", "", "", fmt.Errorf("verify device flow token: %w", err)
		}
	}

	slog.Info("device flow authentication succeeded",
		"issuer", cfg.Issuer,
		"identity", identity,
		"has_refresh_token", tokenResp.RefreshToken != "",
	)

	return identity, fp, tokenResp.RefreshToken, cfg.Issuer, nil
}

// formatDeviceFlowPrompt builds the user-facing prompt shown in the SSH terminal.
func formatDeviceFlowPrompt(resp *DeviceAuthResponse) string {
	var b strings.Builder
	b.WriteString("\r\n")
	b.WriteString("  ┌──────────────────────────────────────────┐\r\n")
	b.WriteString("  │          Device Authentication            │\r\n")
	b.WriteString("  └──────────────────────────────────────────┘\r\n")
	b.WriteString("\r\n")

	if resp.VerificationURIComplete != "" {
		fmt.Fprintf(&b, "  Open this URL in your browser:\r\n")
		fmt.Fprintf(&b, "\r\n")
		fmt.Fprintf(&b, "    %s\r\n", resp.VerificationURIComplete)
		fmt.Fprintf(&b, "\r\n")
		fmt.Fprintf(&b, "  Or visit %s and enter code:\r\n", resp.VerificationURI)
	} else {
		fmt.Fprintf(&b, "  Visit this URL in your browser:\r\n")
		fmt.Fprintf(&b, "\r\n")
		fmt.Fprintf(&b, "    %s\r\n", resp.VerificationURI)
		fmt.Fprintf(&b, "\r\n")
		fmt.Fprintf(&b, "  Enter code:\r\n")
	}

	fmt.Fprintf(&b, "\r\n")
	fmt.Fprintf(&b, "    %s\r\n", resp.UserCode)
	fmt.Fprintf(&b, "\r\n")
	fmt.Fprintf(&b, "  Waiting for authentication...\r\n")
	fmt.Fprintf(&b, "\r\n")

	return b.String()
}
