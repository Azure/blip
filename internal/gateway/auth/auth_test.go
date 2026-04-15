package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	blipv1alpha1 "github.com/project-unbounded/blip/api/v1alpha1"
)

// generateHostKey creates a fresh host key signer for testing.
func generateHostKey(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	return signer
}

// generateUserKey creates a fresh ed25519 key pair for testing.
func generateUserKey(t *testing.T) (ssh.PublicKey, ssh.Signer) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	return sshPub, signer
}

// fakeConnMeta satisfies ssh.ConnMetadata for callback testing.
type fakeConnMeta struct {
	user string
}

func (f fakeConnMeta) User() string          { return f.user }
func (f fakeConnMeta) SessionID() []byte     { return []byte("test-session") }
func (f fakeConnMeta) ClientVersion() []byte { return []byte("SSH-2.0-test") }
func (f fakeConnMeta) ServerVersion() []byte { return []byte("SSH-2.0-test") }
func (f fakeConnMeta) RemoteAddr() net.Addr {
	addr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:1234")
	return addr
}
func (f fakeConnMeta) LocalAddr() net.Addr {
	addr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:22")
	return addr
}

func TestNewServerConfig(t *testing.T) {
	t.Run("with auth watcher enables both auth methods", func(t *testing.T) {
		hostKey := generateHostKey(t)

		cfg := NewServerConfig(context.Background(), Config{
			HostSigner:   hostKey,
			MaxAuthTries: 3,
			AuthWatcher: NewTestAuthWatcher([]OIDCProviderConfig{
				{Issuer: "https://example.com", Audience: "blip"},
			}, nil),
		})

		assert.NotNil(t, cfg.PublicKeyCallback, "PublicKeyCallback should be set")
		assert.NotNil(t, cfg.PasswordCallback, "PasswordCallback should be set for OIDC")
		assert.Equal(t, 3, cfg.MaxAuthTries)
	})

	t.Run("without auth watcher disables all auth", func(t *testing.T) {
		hostKey := generateHostKey(t)

		cfg := NewServerConfig(context.Background(), Config{
			HostSigner:   hostKey,
			MaxAuthTries: 5,
		})

		assert.Nil(t, cfg.PublicKeyCallback, "PublicKeyCallback should be nil when no auth watcher configured")
		assert.Nil(t, cfg.PasswordCallback, "PasswordCallback should be nil when no auth watcher configured")
		assert.Equal(t, 5, cfg.MaxAuthTries)
	})
}

func TestExplicitPubkeyAuth(t *testing.T) {
	conn := fakeConnMeta{user: "runner"}

	t.Run("accepts allowed pubkey", func(t *testing.T) {
		userPub, _ := generateUserKey(t)
		fp := ssh.FingerprintSHA256(userPub)

		watcher := NewTestAuthWatcher(nil, map[string]string{fp: "alice@laptop"})
		cb := pubkeyCallback(watcher, nil, nil, nil)

		perms, err := cb(conn, userPub)
		require.NoError(t, err)
		assert.Equal(t, fp, perms.Extensions[ExtFingerprint])
		assert.Equal(t, "pubkey:alice@laptop", perms.Extensions[ExtIdentity])
	})

	t.Run("rejects unknown pubkey", func(t *testing.T) {
		userPub, _ := generateUserKey(t)

		watcher := NewTestAuthWatcher(nil, map[string]string{"SHA256:other": "bob@desktop"})
		cb := pubkeyCallback(watcher, nil, nil, nil)

		perms, err := cb(conn, userPub)
		assert.Nil(t, perms)
		assert.ErrorContains(t, err, "not authorized")
	})

	t.Run("rejects pubkey when watcher has empty set", func(t *testing.T) {
		userPub, _ := generateUserKey(t)

		watcher := NewTestAuthWatcher(nil, nil)
		cb := pubkeyCallback(watcher, nil, nil, nil)

		perms, err := cb(conn, userPub)
		assert.Nil(t, perms)
		assert.ErrorContains(t, err, "not authorized")
	})

	t.Run("rejects pubkey with empty comment via callback", func(t *testing.T) {
		userPub, _ := generateUserKey(t)
		fp := ssh.FingerprintSHA256(userPub)

		watcher := NewTestAuthWatcher(nil, map[string]string{fp: ""})
		cb := pubkeyCallback(watcher, nil, nil, nil)

		perms, err := cb(conn, userPub)
		assert.Nil(t, perms)
		assert.ErrorContains(t, err, "not authorized")
	})

	t.Run("stores offered pubkey in pending when rejected", func(t *testing.T) {
		userPub, _ := generateUserKey(t)
		fp := ssh.FingerprintSHA256(userPub)

		watcher := NewTestAuthWatcher(nil, nil)
		pending := newPendingPubkeys(context.Background())
		cb := pubkeyCallback(watcher, nil, nil, pending)

		perms, err := cb(conn, userPub)
		assert.Nil(t, perms)
		assert.ErrorContains(t, err, "not authorized")

		// Verify the key was stored for later binding (keyed by session ID).
		stored, ok := pending.LoadAndDelete(string(conn.SessionID()))
		assert.True(t, ok, "offered pubkey should be stored")
		assert.Equal(t, fp, ssh.FingerprintSHA256(stored))

		// Second load should return nothing.
		_, ok = pending.LoadAndDelete(string(conn.SessionID()))
		assert.False(t, ok, "key should be consumed after LoadAndDelete")
	})

	t.Run("rejects pubkey with empty comment directly", func(t *testing.T) {
		userPub, _ := generateUserKey(t)
		fp := ssh.FingerprintSHA256(userPub)

		watcher := NewTestAuthWatcher(nil, map[string]string{fp: ""})

		perms, err := verifyExplicitPubkey(conn, userPub, watcher)
		assert.Nil(t, perms)
		assert.ErrorContains(t, err, "no comment")
	})
}

func TestCheckSubjectAllowed(t *testing.T) {
	tests := []struct {
		name            string
		subject         string
		allowedSubjects []string
		wantErr         bool
		errContains     string
	}{
		{
			name:            "empty allowlist permits any subject",
			subject:         "anything",
			allowedSubjects: nil,
			wantErr:         false,
		},
		{
			name:            "exact match is allowed",
			subject:         "repo:my-org/my-repo:ref:refs/heads/main",
			allowedSubjects: []string{"repo:my-org/my-repo:ref:refs/heads/main"},
			wantErr:         false,
		},
		{
			name:            "case-insensitive match",
			subject:         "Repo:My-Org/My-Repo:ref:refs/heads/main",
			allowedSubjects: []string{"repo:my-org/my-repo:ref:refs/heads/main"},
			wantErr:         false,
		},
		{
			name:            "glob wildcard match",
			subject:         "repo:my-org/my-repo:ref:refs/heads/main",
			allowedSubjects: []string{"repo:my-org/my-repo:*"},
			wantErr:         false,
		},
		{
			name:            "glob wildcard matches any repo in org",
			subject:         "repo:my-org/any-repo:ref:refs/heads/main",
			allowedSubjects: []string{"repo:my-org/*:*"},
			wantErr:         false,
		},
		{
			name:            "multiple allowed subjects matches second",
			subject:         "user-b-oid",
			allowedSubjects: []string{"user-a-oid", "user-b-oid", "user-c-oid"},
			wantErr:         false,
		},
		{
			name:            "subject not in list is rejected",
			subject:         "evil-subject",
			allowedSubjects: []string{"good-subject"},
			wantErr:         true,
			errContains:     "not in the allowed list",
		},
		{
			name:            "partial match is rejected",
			subject:         "repo:my-org/my-repo-fork:ref:refs/heads/main",
			allowedSubjects: []string{"repo:my-org/my-repo:*"},
			wantErr:         true,
			errContains:     "not in the allowed list",
		},
		{
			name:            "azure oid exact match",
			subject:         "00000000-0000-0000-0000-000000000001",
			allowedSubjects: []string{"00000000-0000-0000-0000-000000000001"},
			wantErr:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkSubjectAllowed(tt.subject, tt.allowedSubjects)
			if tt.wantErr {
				assert.ErrorContains(t, err, tt.errContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestOIDCCallback(t *testing.T) {
	conn := fakeConnMeta{user: "runner"}

	providers := []OIDCProviderConfig{
		{Issuer: "https://token.actions.githubusercontent.com", Audience: "blip"},
	}

	t.Run("rejects empty password", func(t *testing.T) {
		cb := oidcCallback(NewTestAuthWatcher(providers, nil))

		perms, err := cb(conn, []byte(""))
		assert.Nil(t, perms)
		assert.ErrorContains(t, err, "OIDC authentication failed")
	})

	t.Run("rejects whitespace-only password", func(t *testing.T) {
		cb := oidcCallback(NewTestAuthWatcher(providers, nil))

		perms, err := cb(conn, []byte("   \t\n  "))
		assert.Nil(t, perms)
		assert.ErrorContains(t, err, "OIDC authentication failed")
	})

	t.Run("rejects invalid JWT token", func(t *testing.T) {
		cb := oidcCallback(NewTestAuthWatcher(providers, nil))

		perms, err := cb(conn, []byte("not-a-valid-jwt-token"))
		assert.Nil(t, perms)
		assert.ErrorContains(t, err, "OIDC authentication failed")
	})

	t.Run("rejects when no providers configured", func(t *testing.T) {
		cb := oidcCallback(NewTestAuthWatcher(nil, nil))

		perms, err := cb(conn, []byte("some-token"))
		assert.Nil(t, perms)
		assert.ErrorContains(t, err, "OIDC authentication failed")
	})
}

func TestVerifyOIDCToken(t *testing.T) {
	providers := []OIDCProviderConfig{
		{Issuer: "https://token.actions.githubusercontent.com", Audience: "blip"},
	}

	t.Run("empty token returns error", func(t *testing.T) {
		identity, err := verifyOIDCToken("", providers)
		assert.Empty(t, identity)
		assert.ErrorContains(t, err, "empty token")
	})

	t.Run("whitespace-only token returns error", func(t *testing.T) {
		identity, err := verifyOIDCToken("   ", providers)
		assert.Empty(t, identity)
		assert.ErrorContains(t, err, "empty token")
	})

	t.Run("no providers returns error", func(t *testing.T) {
		identity, err := verifyOIDCToken("some-token", nil)
		assert.Empty(t, identity)
		assert.ErrorContains(t, err, "not accepted by any configured OIDC provider")
	})
}

func TestPubkeyAuthEndToEnd(t *testing.T) {
	// End-to-end test: configure the server with an AuthWatcher containing
	// an allowed pubkey, then verify auth succeeds through the full
	// NewServerConfig path.
	hostKey := generateHostKey(t)
	userPub, _ := generateUserKey(t)
	fp := ssh.FingerprintSHA256(userPub)

	sshCfg := NewServerConfig(context.Background(), Config{
		HostSigner:   hostKey,
		MaxAuthTries: 1,
		AuthWatcher:  NewTestAuthWatcher(nil, map[string]string{fp: "alice@laptop"}),
	})

	conn := fakeConnMeta{user: "runner"}
	perms, err := sshCfg.PublicKeyCallback(conn, userPub)
	require.NoError(t, err)
	assert.Equal(t, fp, perms.Extensions[ExtFingerprint])
	assert.Equal(t, "pubkey:alice@laptop", perms.Extensions[ExtIdentity])
}

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		pattern string
		str     string
		want    bool
	}{
		// Basic matching.
		{"", "", true},
		{"a", "a", true},
		{"a", "b", false},
		{"abc", "abc", true},
		{"abc", "ab", false},
		{"ab", "abc", false},

		// Star matches zero or more characters.
		{"*", "", true},
		{"*", "anything", true},
		{"a*", "a", true},
		{"a*", "abc", true},
		{"*c", "abc", true},
		{"a*c", "ac", true},
		{"a*c", "abc", true},
		{"a*c", "aXXc", true},
		{"a*c", "aXX", false},

		// Star matches "/" and ":" (unlike filepath.Match).
		{"repo:*", "repo:my-org/my-repo:ref:refs/heads/main", true},
		{"repo:my-org/*:*", "repo:my-org/any-repo:ref:refs/heads/main", true},
		{"repo:my-org/my-repo:*", "repo:my-org/my-repo:ref:refs/heads/main", true},
		{"*/foo", "bar/foo", true},

		// Multiple stars.
		{"*a*b*c*", "abc", true},
		{"*a*b*c*", "xaxbxcx", true},
		{"*a*b*c*", "xaxbx", false},
		{"**", "anything", true},
		{"a**b", "ab", true},
		{"a**b", "aXXb", true},

		// Consecutive stars.
		{"***", "", true},
		{"***", "abc", true},

		// No partial matching.
		{"repo:my-org/my-repo:*", "repo:my-org/my-repo-fork:ref:refs/heads/main", false},

		// Empty pattern vs non-empty string.
		{"", "a", false},

		// Performance: this should complete instantly with iterative algorithm.
		// Pattern with many stars against a non-matching string.
		{"*a*a*a*a*b", "aaaaaaaaaaaaaaaaaaaaaaaaaaa", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_vs_"+tt.str, func(t *testing.T) {
			got := globMatch(tt.pattern, tt.str)
			assert.Equal(t, tt.want, got, "globMatch(%q, %q)", tt.pattern, tt.str)
		})
	}
}

func TestValidateOIDCFromCR(t *testing.T) {
	t.Run("validates valid OIDC spec", func(t *testing.T) {
		spec := &blipv1alpha1.OIDCSpec{
			Issuer:          "https://token.actions.githubusercontent.com",
			Audience:        "blip",
			AllowedSubjects: []string{"repo:my-org/my-repo:*"},
		}
		p, ok := validateOIDCFromCR(spec)
		require.True(t, ok)
		assert.Equal(t, "https://token.actions.githubusercontent.com", p.Issuer)
		assert.Equal(t, "blip", p.Audience)
		assert.Equal(t, "", p.IdentityClaim)
		assert.Equal(t, []string{"repo:my-org/my-repo:*"}, p.AllowedSubjects)
	})

	t.Run("validates with identity claim", func(t *testing.T) {
		spec := &blipv1alpha1.OIDCSpec{
			Issuer:          "https://login.microsoftonline.com/tenant-id/v2.0",
			Audience:        "api://blip",
			IdentityClaim:   "oid",
			AllowedSubjects: []string{"00000000-0000-0000-0000-000000000001"},
		}
		p, ok := validateOIDCFromCR(spec)
		require.True(t, ok)
		assert.Equal(t, "https://login.microsoftonline.com/tenant-id/v2.0", p.Issuer)
		assert.Equal(t, "api://blip", p.Audience)
		assert.Equal(t, "oid", p.IdentityClaim)
		assert.Equal(t, []string{"00000000-0000-0000-0000-000000000001"}, p.AllowedSubjects)
	})

	t.Run("rejects empty issuer", func(t *testing.T) {
		spec := &blipv1alpha1.OIDCSpec{
			Issuer:   "",
			Audience: "blip",
		}
		_, ok := validateOIDCFromCR(spec)
		assert.False(t, ok)
	})

	t.Run("rejects empty audience", func(t *testing.T) {
		spec := &blipv1alpha1.OIDCSpec{
			Issuer:   "https://example.com",
			Audience: "",
		}
		_, ok := validateOIDCFromCR(spec)
		assert.False(t, ok)
	})

	t.Run("accepts provider with no allowed subjects", func(t *testing.T) {
		spec := &blipv1alpha1.OIDCSpec{
			Issuer:   "https://example.com",
			Audience: "blip",
		}
		p, ok := validateOIDCFromCR(spec)
		require.True(t, ok)
		assert.Nil(t, p.AllowedSubjects)
	})

	t.Run("rejects non-HTTPS issuer", func(t *testing.T) {
		spec := &blipv1alpha1.OIDCSpec{
			Issuer:   "http://insecure.example.com",
			Audience: "blip",
		}
		_, ok := validateOIDCFromCR(spec)
		assert.False(t, ok)

		spec2 := &blipv1alpha1.OIDCSpec{
			Issuer:   "not-a-url",
			Audience: "blip",
		}
		_, ok2 := validateOIDCFromCR(spec2)
		assert.False(t, ok2)
	})

	t.Run("normalizes trailing slash on issuer", func(t *testing.T) {
		spec := &blipv1alpha1.OIDCSpec{
			Issuer:   "https://example.com/",
			Audience: "blip",
		}
		p, ok := validateOIDCFromCR(spec)
		require.True(t, ok)
		assert.Equal(t, "https://example.com", p.Issuer)

		spec2 := &blipv1alpha1.OIDCSpec{
			Issuer:   "https://example2.com///",
			Audience: "blip",
		}
		p2, ok2 := validateOIDCFromCR(spec2)
		require.True(t, ok2)
		assert.Equal(t, "https://example2.com", p2.Issuer)
	})

	t.Run("trims whitespace from fields", func(t *testing.T) {
		spec := &blipv1alpha1.OIDCSpec{
			Issuer:        "  https://example.com  ",
			Audience:      "  blip  ",
			IdentityClaim: "  oid  ",
		}
		p, ok := validateOIDCFromCR(spec)
		require.True(t, ok)
		assert.Equal(t, "https://example.com", p.Issuer)
		assert.Equal(t, "blip", p.Audience)
		assert.Equal(t, "oid", p.IdentityClaim)
	})
}

func TestParseSSHKeyFromCR(t *testing.T) {
	// Generate a real ed25519 key to get a valid authorized_keys line.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	// MarshalAuthorizedKey produces "ssh-ed25519 AAAA...\n" without a comment.
	bareKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	// Add a comment to create a full authorized_keys line.
	authorizedKey := bareKey + " alice@laptop"
	expectedFP := ssh.FingerprintSHA256(sshPub)

	t.Run("parses valid key with comment", func(t *testing.T) {
		fp, comment := parseSSHKeyFromCR(authorizedKey)
		assert.Equal(t, expectedFP, fp)
		assert.Equal(t, "alice@laptop", comment)
	})

	t.Run("parses key without comment as empty string", func(t *testing.T) {
		fp, comment := parseSSHKeyFromCR(bareKey)
		assert.Equal(t, expectedFP, fp)
		assert.Equal(t, "", comment)
	})

	t.Run("returns empty for invalid key", func(t *testing.T) {
		fp, comment := parseSSHKeyFromCR("not-a-valid-key")
		assert.Equal(t, "", fp)
		assert.Equal(t, "", comment)
	})

	t.Run("returns empty for empty input", func(t *testing.T) {
		fp, comment := parseSSHKeyFromCR("")
		assert.Equal(t, "", fp)
		assert.Equal(t, "", comment)
	})

	t.Run("trims whitespace", func(t *testing.T) {
		fp, comment := parseSSHKeyFromCR("  " + authorizedKey + "  ")
		assert.Equal(t, expectedFP, fp)
		assert.Equal(t, "alice@laptop", comment)
	})
}
