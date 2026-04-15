package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestRequestDeviceCode(t *testing.T) {
	t.Run("successful request", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

			err := r.ParseForm()
			require.NoError(t, err)
			assert.Equal(t, "test-client-id", r.FormValue("client_id"))
			assert.Equal(t, "openid profile offline_access", r.FormValue("scope"))

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(DeviceAuthResponse{
				DeviceCode:              "device-123",
				UserCode:                "ABCD-1234",
				VerificationURI:         "https://example.com/device",
				VerificationURIComplete: "https://example.com/device?code=ABCD-1234",
				ExpiresIn:               900,
				Interval:                5,
			})
		}))
		defer srv.Close()

		// Use the test server's TLS client.
		origTransport := deviceFlowHTTPClient.Transport
		deviceFlowHTTPClient.Transport = srv.Client().Transport
		defer func() { deviceFlowHTTPClient.Transport = origTransport }()

		cfg := OIDCProviderConfig{
			ClientID:      "test-client-id",
			DeviceAuthURL: srv.URL,
			Scopes:        []string{"openid", "profile"},
		}

		resp, err := RequestDeviceCode(context.Background(), cfg)
		require.NoError(t, err)
		assert.Equal(t, "device-123", resp.DeviceCode)
		assert.Equal(t, "ABCD-1234", resp.UserCode)
		assert.Equal(t, "https://example.com/device", resp.VerificationURI)
		assert.Equal(t, "https://example.com/device?code=ABCD-1234", resp.VerificationURIComplete)
		assert.Equal(t, 900, resp.ExpiresIn)
		assert.Equal(t, 5, resp.Interval)
	})

	t.Run("server error", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("internal error"))
		}))
		defer srv.Close()

		origTransport := deviceFlowHTTPClient.Transport
		deviceFlowHTTPClient.Transport = srv.Client().Transport
		defer func() { deviceFlowHTTPClient.Transport = origTransport }()

		cfg := OIDCProviderConfig{
			ClientID:      "test-client-id",
			DeviceAuthURL: srv.URL,
		}

		resp, err := RequestDeviceCode(context.Background(), cfg)
		assert.Nil(t, resp)
		assert.ErrorContains(t, err, "status 500")
	})

	t.Run("OAuth error response", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(DeviceFlowError{
				Code:        "invalid_client",
				Description: "client not found",
			})
		}))
		defer srv.Close()

		origTransport := deviceFlowHTTPClient.Transport
		deviceFlowHTTPClient.Transport = srv.Client().Transport
		defer func() { deviceFlowHTTPClient.Transport = origTransport }()

		cfg := OIDCProviderConfig{
			ClientID:      "test-client-id",
			DeviceAuthURL: srv.URL,
		}

		resp, err := RequestDeviceCode(context.Background(), cfg)
		assert.Nil(t, resp)
		assert.ErrorContains(t, err, "invalid_client")
	})

	t.Run("missing fields in response", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"device_code": "abc",
				// missing user_code and verification_uri
			})
		}))
		defer srv.Close()

		origTransport := deviceFlowHTTPClient.Transport
		deviceFlowHTTPClient.Transport = srv.Client().Transport
		defer func() { deviceFlowHTTPClient.Transport = origTransport }()

		cfg := OIDCProviderConfig{
			ClientID:      "test-client-id",
			DeviceAuthURL: srv.URL,
		}

		resp, err := RequestDeviceCode(context.Background(), cfg)
		assert.Nil(t, resp)
		assert.ErrorContains(t, err, "missing")
	})

	t.Run("default interval and expiry", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(DeviceAuthResponse{
				DeviceCode:      "device-123",
				UserCode:        "ABCD",
				VerificationURI: "https://example.com/device",
				// No interval or expires_in — should get defaults.
			})
		}))
		defer srv.Close()

		origTransport := deviceFlowHTTPClient.Transport
		deviceFlowHTTPClient.Transport = srv.Client().Transport
		defer func() { deviceFlowHTTPClient.Transport = origTransport }()

		cfg := OIDCProviderConfig{
			ClientID:      "test-client-id",
			DeviceAuthURL: srv.URL,
		}

		resp, err := RequestDeviceCode(context.Background(), cfg)
		require.NoError(t, err)
		assert.Equal(t, 5, resp.Interval)
		assert.Equal(t, 900, resp.ExpiresIn)
	})
}

func TestPollForToken(t *testing.T) {
	t.Run("succeeds after pending", func(t *testing.T) {
		attempt := 0
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempt++
			if attempt < 3 {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(DeviceFlowError{
					Code: errAuthorizationPending,
				})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(DeviceTokenResponse{
				AccessToken: "access-token-123",
				TokenType:   "bearer",
				IDToken:     "id-token-123",
			})
		}))
		defer srv.Close()

		origTransport := deviceFlowHTTPClient.Transport
		deviceFlowHTTPClient.Transport = srv.Client().Transport
		defer func() { deviceFlowHTTPClient.Transport = origTransport }()

		cfg := OIDCProviderConfig{
			ClientID: "test-client-id",
			TokenURL: srv.URL,
		}

		var messages []string
		sendStatus := func(msg string) { messages = append(messages, msg) }

		resp, err := PollForToken(context.Background(), cfg, "device-code", 1, 30, sendStatus)
		require.NoError(t, err)
		assert.Equal(t, "access-token-123", resp.AccessToken)
		assert.Equal(t, "id-token-123", resp.IDToken)
		assert.Equal(t, 3, attempt)
	})

	t.Run("access denied", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(DeviceFlowError{
				Code:        errAccessDenied,
				Description: "user denied the request",
			})
		}))
		defer srv.Close()

		origTransport := deviceFlowHTTPClient.Transport
		deviceFlowHTTPClient.Transport = srv.Client().Transport
		defer func() { deviceFlowHTTPClient.Transport = origTransport }()

		cfg := OIDCProviderConfig{
			ClientID: "test-client-id",
			TokenURL: srv.URL,
		}

		resp, err := PollForToken(context.Background(), cfg, "device-code", 1, 30, func(string) {})
		assert.Nil(t, resp)
		assert.ErrorContains(t, err, "denied")
	})

	t.Run("expired token", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(DeviceFlowError{
				Code: errExpiredToken,
			})
		}))
		defer srv.Close()

		origTransport := deviceFlowHTTPClient.Transport
		deviceFlowHTTPClient.Transport = srv.Client().Transport
		defer func() { deviceFlowHTTPClient.Transport = origTransport }()

		cfg := OIDCProviderConfig{
			ClientID: "test-client-id",
			TokenURL: srv.URL,
		}

		resp, err := PollForToken(context.Background(), cfg, "device-code", 1, 30, func(string) {})
		assert.Nil(t, resp)
		assert.ErrorContains(t, err, "expired")
	})

	t.Run("context cancellation", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(DeviceFlowError{
				Code: errAuthorizationPending,
			})
		}))
		defer srv.Close()

		origTransport := deviceFlowHTTPClient.Transport
		deviceFlowHTTPClient.Transport = srv.Client().Transport
		defer func() { deviceFlowHTTPClient.Transport = origTransport }()

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		cfg := OIDCProviderConfig{
			ClientID: "test-client-id",
			TokenURL: srv.URL,
		}

		resp, err := PollForToken(ctx, cfg, "device-code", 1, 300, func(string) {})
		assert.Nil(t, resp)
		assert.Error(t, err)
	})

	t.Run("slow down increases interval", func(t *testing.T) {
		attempt := 0
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempt++
			if attempt == 1 {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(DeviceFlowError{
					Code: errSlowDown,
				})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(DeviceTokenResponse{
				AccessToken: "token",
			})
		}))
		defer srv.Close()

		origTransport := deviceFlowHTTPClient.Transport
		deviceFlowHTTPClient.Transport = srv.Client().Transport
		defer func() { deviceFlowHTTPClient.Transport = origTransport }()

		cfg := OIDCProviderConfig{
			ClientID: "test-client-id",
			TokenURL: srv.URL,
		}

		resp, err := PollForToken(context.Background(), cfg, "device-code", 1, 30, func(string) {})
		require.NoError(t, err)
		assert.Equal(t, "token", resp.AccessToken)
	})
}

func TestFormatDeviceFlowPrompt(t *testing.T) {
	t.Run("with complete URI", func(t *testing.T) {
		resp := &DeviceAuthResponse{
			UserCode:                "ABCD-1234",
			VerificationURI:         "https://github.com/login/device",
			VerificationURIComplete: "https://github.com/login/device?code=ABCD-1234",
		}

		prompt := formatDeviceFlowPrompt(resp)
		assert.Contains(t, prompt, "ABCD-1234")
		assert.Contains(t, prompt, "https://github.com/login/device?code=ABCD-1234")
		assert.Contains(t, prompt, "https://github.com/login/device")
		assert.Contains(t, prompt, "Waiting for authentication")
	})

	t.Run("without complete URI", func(t *testing.T) {
		resp := &DeviceAuthResponse{
			UserCode:        "ABCD-1234",
			VerificationURI: "https://github.com/login/device",
		}

		prompt := formatDeviceFlowPrompt(resp)
		assert.Contains(t, prompt, "ABCD-1234")
		assert.Contains(t, prompt, "https://github.com/login/device")
		assert.NotContains(t, prompt, "Or visit")
	})
}

func TestDeviceFlowKeyboardInteractive(t *testing.T) {
	conn := fakeConnMeta{user: "runner"}

	t.Run("rejects when no device-flow providers", func(t *testing.T) {
		watcher := NewTestAuthWatcher([]OIDCProviderConfig{
			{Issuer: "https://example.com", Audience: "blip"},
		}, nil)

		cb := deviceFlowKeyboardInteractive(watcher, nil)
		perms, err := cb(conn, func(name, instruction string, questions []string, echos []bool) ([]string, error) {
			return nil, nil
		})
		assert.Nil(t, perms)
		assert.ErrorContains(t, err, "no device-flow providers")
	})

	t.Run("accepts and marks pending when device-flow configured", func(t *testing.T) {
		watcher := NewTestAuthWatcher([]OIDCProviderConfig{
			{
				Issuer:        "https://example.com",
				Audience:      "blip",
				DeviceFlow:    true,
				ClientID:      "test-client",
				DeviceAuthURL: "https://example.com/device",
				TokenURL:      "https://example.com/token",
			},
		}, nil)

		var instructionReceived string
		cb := deviceFlowKeyboardInteractive(watcher, nil)
		perms, err := cb(conn, func(name, instruction string, questions []string, echos []bool) ([]string, error) {
			instructionReceived = instruction
			return nil, nil
		})

		require.NoError(t, err)
		require.NotNil(t, perms)
		assert.Equal(t, "true", perms.Extensions[ExtDeviceFlowPending])
		assert.Contains(t, instructionReceived, "device flow")
	})

	t.Run("captures offered pubkey", func(t *testing.T) {
		watcher := NewTestAuthWatcher([]OIDCProviderConfig{
			{
				Issuer:        "https://example.com",
				Audience:      "blip",
				DeviceFlow:    true,
				ClientID:      "test-client",
				DeviceAuthURL: "https://example.com/device",
				TokenURL:      "https://example.com/token",
			},
		}, nil)

		userPub, _ := generateUserKey(t)
		pending := newPendingPubkeys(context.Background())
		pending.Store(string(conn.SessionID()), userPub)

		cb := deviceFlowKeyboardInteractive(watcher, pending)
		perms, err := cb(conn, func(name, instruction string, questions []string, echos []bool) ([]string, error) {
			return nil, nil
		})

		require.NoError(t, err)
		require.NotNil(t, perms)
		assert.Equal(t, "true", perms.Extensions[ExtDeviceFlowPending])
		assert.NotEmpty(t, perms.Extensions[ExtOfferedPubkey])

		// Parse the stored key and verify it matches.
		storedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(perms.Extensions[ExtOfferedPubkey]))
		require.NoError(t, err)
		assert.Equal(t, ssh.FingerprintSHA256(userPub), ssh.FingerprintSHA256(storedKey))
	})
}

func TestDeviceFlowError(t *testing.T) {
	t.Run("with description", func(t *testing.T) {
		err := &DeviceFlowError{Code: "access_denied", Description: "user denied"}
		assert.Equal(t, "access_denied: user denied", err.Error())
	})

	t.Run("without description", func(t *testing.T) {
		err := &DeviceFlowError{Code: "expired_token"}
		assert.Equal(t, "expired_token", err.Error())
	})
}

func TestParseOIDCProvidersDeviceFlow(t *testing.T) {
	t.Run("parses device flow config", func(t *testing.T) {
		raw := `
- issuer: https://login.microsoftonline.com/tenant/v2.0
  audience: api://blip
  identity-claim: oid
  device-flow: true
  client-id: my-client-id
  device-auth-url: https://login.microsoftonline.com/tenant/oauth2/v2.0/devicecode
  token-url: https://login.microsoftonline.com/tenant/oauth2/v2.0/token
  scopes:
    - "api://blip/.default"
    - "openid"
`
		providers := parseOIDCProviders(raw)
		require.Len(t, providers, 1)
		assert.True(t, providers[0].DeviceFlow)
		assert.Equal(t, "my-client-id", providers[0].ClientID)
		assert.Equal(t, "https://login.microsoftonline.com/tenant/oauth2/v2.0/devicecode", providers[0].DeviceAuthURL)
		assert.Equal(t, "https://login.microsoftonline.com/tenant/oauth2/v2.0/token", providers[0].TokenURL)
		assert.Equal(t, []string{"api://blip/.default", "openid"}, providers[0].Scopes)
	})

	t.Run("skips device-flow without client-id", func(t *testing.T) {
		raw := `
- issuer: https://example.com
  audience: blip
  device-flow: true
  device-auth-url: https://example.com/device
  token-url: https://example.com/token
`
		providers := parseOIDCProviders(raw)
		assert.Empty(t, providers)
	})

	t.Run("skips device-flow without device-auth-url", func(t *testing.T) {
		raw := `
- issuer: https://example.com
  audience: blip
  device-flow: true
  client-id: my-client
  token-url: https://example.com/token
`
		providers := parseOIDCProviders(raw)
		assert.Empty(t, providers)
	})

	t.Run("skips device-flow without token-url", func(t *testing.T) {
		raw := `
- issuer: https://example.com
  audience: blip
  device-flow: true
  client-id: my-client
  device-auth-url: https://example.com/device
`
		providers := parseOIDCProviders(raw)
		assert.Empty(t, providers)
	})

	t.Run("skips device-flow with non-HTTPS device-auth-url", func(t *testing.T) {
		raw := `
- issuer: https://example.com
  audience: blip
  device-flow: true
  client-id: my-client
  device-auth-url: http://example.com/device
  token-url: https://example.com/token
`
		providers := parseOIDCProviders(raw)
		assert.Empty(t, providers)
	})

	t.Run("skips device-flow with non-HTTPS token-url", func(t *testing.T) {
		raw := `
- issuer: https://example.com
  audience: blip
  device-flow: true
  client-id: my-client
  device-auth-url: https://example.com/device
  token-url: http://example.com/token
`
		providers := parseOIDCProviders(raw)
		assert.Empty(t, providers)
	})

	t.Run("non-device-flow provider ignores device fields", func(t *testing.T) {
		raw := `
- issuer: https://token.actions.githubusercontent.com
  audience: blip
`
		providers := parseOIDCProviders(raw)
		require.Len(t, providers, 1)
		assert.False(t, providers[0].DeviceFlow)
		assert.Empty(t, providers[0].ClientID)
	})

	t.Run("mixed providers", func(t *testing.T) {
		raw := fmt.Sprintf(`
- issuer: https://token.actions.githubusercontent.com
  audience: blip
  allowed-subjects:
    - "repo:my-org/*:*"
- issuer: https://login.microsoftonline.com/tenant/v2.0
  audience: api://blip
  identity-claim: oid
  device-flow: true
  client-id: my-client
  device-auth-url: https://login.microsoftonline.com/tenant/oauth2/v2.0/devicecode
  token-url: https://login.microsoftonline.com/tenant/oauth2/v2.0/token
`)
		providers := parseOIDCProviders(raw)
		require.Len(t, providers, 2)
		assert.False(t, providers[0].DeviceFlow)
		assert.True(t, providers[1].DeviceFlow)
	})
}

func TestPendingPubkeys(t *testing.T) {
	t.Run("store and load", func(t *testing.T) {
		pending := newPendingPubkeys(context.Background())
		userPub, _ := generateUserKey(t)

		pending.Store("session-id-1", userPub)

		key, ok := pending.LoadAndDelete("session-id-1")
		assert.True(t, ok)
		assert.Equal(t, ssh.FingerprintSHA256(userPub), ssh.FingerprintSHA256(key))

		_, ok = pending.LoadAndDelete("session-id-1")
		assert.False(t, ok)
	})

	t.Run("load non-existent", func(t *testing.T) {
		pending := newPendingPubkeys(context.Background())
		_, ok := pending.LoadAndDelete("session-id-nonexistent")
		assert.False(t, ok)
	})

	t.Run("overwrite", func(t *testing.T) {
		pending := newPendingPubkeys(context.Background())
		key1, _ := generateUserKey(t)
		key2, _ := generateUserKey(t)

		pending.Store("session-id-1", key1)
		pending.Store("session-id-1", key2)

		key, ok := pending.LoadAndDelete("session-id-1")
		assert.True(t, ok)
		assert.Equal(t, ssh.FingerprintSHA256(key2), ssh.FingerprintSHA256(key))
	})
}

func TestDeviceFlowProviders(t *testing.T) {
	t.Run("filters device flow providers", func(t *testing.T) {
		watcher := NewTestAuthWatcher([]OIDCProviderConfig{
			{Issuer: "https://github.com", Audience: "blip"},
			{
				Issuer:        "https://azure.com",
				Audience:      "api://blip",
				DeviceFlow:    true,
				ClientID:      "client",
				DeviceAuthURL: "https://azure.com/device",
				TokenURL:      "https://azure.com/token",
			},
		}, nil)

		dfProviders := watcher.DeviceFlowProviders()
		require.Len(t, dfProviders, 1)
		assert.Equal(t, "https://azure.com", dfProviders[0].Issuer)
	})

	t.Run("returns nil when none configured", func(t *testing.T) {
		watcher := NewTestAuthWatcher([]OIDCProviderConfig{
			{Issuer: "https://github.com", Audience: "blip"},
		}, nil)

		assert.Nil(t, watcher.DeviceFlowProviders())
	})

	t.Run("has device flow providers", func(t *testing.T) {
		withDF := NewTestAuthWatcher([]OIDCProviderConfig{
			{Issuer: "https://example.com", Audience: "blip", DeviceFlow: true, ClientID: "c", DeviceAuthURL: "https://e.com/d", TokenURL: "https://e.com/t"},
		}, nil)
		assert.True(t, withDF.HasDeviceFlowProviders())

		withoutDF := NewTestAuthWatcher([]OIDCProviderConfig{
			{Issuer: "https://example.com", Audience: "blip"},
		}, nil)
		assert.False(t, withoutDF.HasDeviceFlowProviders())
	})
}

func TestTokenFingerprint(t *testing.T) {
	t.Run("deterministic", func(t *testing.T) {
		fp1 := TokenFingerprint("my-access-token")
		fp2 := TokenFingerprint("my-access-token")
		assert.Equal(t, fp1, fp2)
	})

	t.Run("different tokens produce different fingerprints", func(t *testing.T) {
		fp1 := TokenFingerprint("token-a")
		fp2 := TokenFingerprint("token-b")
		assert.NotEqual(t, fp1, fp2)
	})

	t.Run("starts with SHA256 prefix", func(t *testing.T) {
		fp := TokenFingerprint("some-token")
		assert.True(t, strings.HasPrefix(fp, "SHA256:"), "expected SHA256: prefix, got %s", fp)
	})

	t.Run("empty token", func(t *testing.T) {
		fp := TokenFingerprint("")
		assert.True(t, strings.HasPrefix(fp, "SHA256:"))
		assert.NotEqual(t, "SHA256:", fp) // should have hash content
	})
}
