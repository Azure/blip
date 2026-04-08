package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// newTestAuthWatcher creates an AuthWatcher pre-loaded with the given repos
// and pubkey fingerprints, without starting an informer cache. Suitable for
// unit tests only.
func newTestAuthWatcher(repos []string, pubkeyFingerprints map[string]bool) *AuthWatcher {
	if pubkeyFingerprints == nil {
		pubkeyFingerprints = make(map[string]bool)
	}
	return &AuthWatcher{repos: repos, pubkeys: pubkeyFingerprints}
}

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

		cfg := NewServerConfig(Config{
			HostSigner:   hostKey,
			MaxAuthTries: 3,
			AuthWatcher:  newTestAuthWatcher([]string{"org/repo"}, nil),
		})

		assert.NotNil(t, cfg.PublicKeyCallback, "PublicKeyCallback should be set")
		assert.NotNil(t, cfg.PasswordCallback, "PasswordCallback should be set for OIDC")
		assert.Equal(t, 3, cfg.MaxAuthTries)
	})

	t.Run("without auth watcher disables all auth", func(t *testing.T) {
		hostKey := generateHostKey(t)

		cfg := NewServerConfig(Config{
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

		watcher := newTestAuthWatcher(nil, map[string]bool{fp: true})
		cb := pubkeyCallback(watcher, nil)

		perms, err := cb(conn, userPub)
		require.NoError(t, err)
		assert.Equal(t, fp, perms.Extensions[ExtFingerprint])
		assert.Equal(t, "pubkey:"+fp, perms.Extensions[ExtIdentity])
	})

	t.Run("rejects unknown pubkey", func(t *testing.T) {
		userPub, _ := generateUserKey(t)

		watcher := newTestAuthWatcher(nil, map[string]bool{"SHA256:other": true})
		cb := pubkeyCallback(watcher, nil)

		perms, err := cb(conn, userPub)
		assert.Nil(t, perms)
		assert.ErrorContains(t, err, "not authorized")
	})

	t.Run("rejects pubkey when watcher has empty set", func(t *testing.T) {
		userPub, _ := generateUserKey(t)

		watcher := newTestAuthWatcher(nil, nil)
		cb := pubkeyCallback(watcher, nil)

		perms, err := cb(conn, userPub)
		assert.Nil(t, perms)
		assert.ErrorContains(t, err, "not authorized")
	})
}

func TestCheckRepoAllowed(t *testing.T) {
	tests := []struct {
		name         string
		repo         string
		allowedRepos []string
		wantErr      bool
		errContains  string
	}{
		{
			name:         "empty allowlist permits any repo",
			repo:         "any-org/any-repo",
			allowedRepos: nil,
			wantErr:      false,
		},
		{
			name:         "exact match is allowed",
			repo:         "my-org/my-repo",
			allowedRepos: []string{"my-org/my-repo"},
			wantErr:      false,
		},
		{
			name:         "case-insensitive match",
			repo:         "My-Org/My-Repo",
			allowedRepos: []string{"my-org/my-repo"},
			wantErr:      false,
		},
		{
			name:         "multiple allowed repos matches second",
			repo:         "org/second",
			allowedRepos: []string{"org/first", "org/second", "org/third"},
			wantErr:      false,
		},
		{
			name:         "repo not in list is rejected",
			repo:         "evil-org/evil-repo",
			allowedRepos: []string{"good-org/good-repo"},
			wantErr:      true,
			errContains:  "not in the allowed list",
		},
		{
			name:         "partial match is rejected",
			repo:         "my-org/my-repo-fork",
			allowedRepos: []string{"my-org/my-repo"},
			wantErr:      true,
			errContains:  "not in the allowed list",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkRepoAllowed(tt.repo, tt.allowedRepos)
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

	t.Run("rejects empty password", func(t *testing.T) {
		cb := oidcCallback(newTestAuthWatcher([]string{"org/repo"}, nil))

		perms, err := cb(conn, []byte(""))
		assert.Nil(t, perms)
		assert.ErrorContains(t, err, "GitHub Actions authentication failed")
	})

	t.Run("rejects whitespace-only password", func(t *testing.T) {
		cb := oidcCallback(newTestAuthWatcher([]string{"org/repo"}, nil))

		perms, err := cb(conn, []byte("   \t\n  "))
		assert.Nil(t, perms)
		assert.ErrorContains(t, err, "GitHub Actions authentication failed")
	})

	t.Run("rejects invalid JWT token", func(t *testing.T) {
		cb := oidcCallback(newTestAuthWatcher([]string{"org/repo"}, nil))

		perms, err := cb(conn, []byte("not-a-valid-jwt-token"))
		assert.Nil(t, perms)
		assert.ErrorContains(t, err, "GitHub Actions authentication failed")
	})
}

func TestVerifyGitHubActionsToken(t *testing.T) {
	t.Run("empty token returns error", func(t *testing.T) {
		identity, err := verifyGitHubActionsToken("", []string{"org/repo"})
		assert.Empty(t, identity)
		assert.ErrorContains(t, err, "empty token")
	})

	t.Run("whitespace-only token returns error", func(t *testing.T) {
		identity, err := verifyGitHubActionsToken("   ", []string{"org/repo"})
		assert.Empty(t, identity)
		assert.ErrorContains(t, err, "empty token")
	})
}

func TestPubkeyAuthEndToEnd(t *testing.T) {
	// End-to-end test: configure the server with an AuthWatcher containing
	// an allowed pubkey, then verify auth succeeds through the full
	// NewServerConfig path.
	hostKey := generateHostKey(t)
	userPub, _ := generateUserKey(t)
	fp := ssh.FingerprintSHA256(userPub)

	sshCfg := NewServerConfig(Config{
		HostSigner:   hostKey,
		MaxAuthTries: 1,
		AuthWatcher:  newTestAuthWatcher(nil, map[string]bool{fp: true}),
	})

	conn := fakeConnMeta{user: "runner"}
	perms, err := sshCfg.PublicKeyCallback(conn, userPub)
	require.NoError(t, err)
	assert.Equal(t, fp, perms.Extensions[ExtFingerprint])
	assert.Equal(t, "pubkey:"+fp, perms.Extensions[ExtIdentity])
}

func TestParseLineList(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{
			name: "simple list",
			raw:  "org/repo1\norg/repo2\n",
			want: []string{"org/repo1", "org/repo2"},
		},
		{
			name: "blank lines and comments",
			raw:  "# comment\norg/repo1\n\n  # another comment\norg/repo2\n",
			want: []string{"org/repo1", "org/repo2"},
		},
		{
			name: "whitespace trimmed",
			raw:  "  org/repo1  \n  org/repo2  ",
			want: []string{"org/repo1", "org/repo2"},
		},
		{
			name: "empty string",
			raw:  "",
			want: nil,
		},
		{
			name: "only whitespace and comments",
			raw:  "  \n# comment\n  \n",
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseLineList(tt.raw)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParsePubkeyList(t *testing.T) {
	// Generate a real ed25519 key to get a valid authorized_keys line.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	authorizedKey := string(ssh.MarshalAuthorizedKey(sshPub))
	expectedFP := ssh.FingerprintSHA256(sshPub)

	t.Run("parses valid key", func(t *testing.T) {
		fps := parsePubkeyList(authorizedKey)
		assert.True(t, fps[expectedFP])
		assert.Len(t, fps, 1)
	})

	t.Run("skips comments and blank lines", func(t *testing.T) {
		raw := "# this is a comment\n\n" + authorizedKey + "\n  \n# another comment\n"
		fps := parsePubkeyList(raw)
		assert.True(t, fps[expectedFP])
		assert.Len(t, fps, 1)
	})

	t.Run("skips invalid lines", func(t *testing.T) {
		raw := "not-a-valid-key\n" + authorizedKey
		fps := parsePubkeyList(raw)
		assert.True(t, fps[expectedFP])
		assert.Len(t, fps, 1)
	})

	t.Run("empty input returns empty map", func(t *testing.T) {
		fps := parsePubkeyList("")
		assert.Empty(t, fps)
	})

	t.Run("multiple keys", func(t *testing.T) {
		pub2, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		sshPub2, err := ssh.NewPublicKey(pub2)
		require.NoError(t, err)
		key2 := string(ssh.MarshalAuthorizedKey(sshPub2))
		fp2 := ssh.FingerprintSHA256(sshPub2)

		raw := authorizedKey + key2
		fps := parsePubkeyList(raw)
		assert.True(t, fps[expectedFP])
		assert.True(t, fps[fp2])
		assert.Len(t, fps, 2)
	})
}
