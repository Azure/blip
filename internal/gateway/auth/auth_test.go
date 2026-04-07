package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// newTestRepoWatcher creates a RepoWatcher pre-loaded with the given repos,
// without starting an informer cache. Suitable for unit tests only.
func newTestRepoWatcher(repos []string) *RepoWatcher {
	return &RepoWatcher{repos: repos}
}

// generateCA creates a fresh CA signer and its SSH public key for testing.
func generateCA(t *testing.T) (ssh.Signer, ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	return signer, signer.PublicKey()
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

// issueUserCert creates a valid SSH user certificate signed by caSigner.
func issueUserCert(t *testing.T, caSigner ssh.Signer, keyID string) (ssh.Signer, *ssh.Certificate) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)

	now := time.Now()
	cert := &ssh.Certificate{
		CertType:        ssh.UserCert,
		Key:             sshPub,
		KeyId:           keyID,
		ValidPrincipals: []string{"runner"},
		ValidAfter:      uint64(now.Add(-5 * time.Minute).Unix()),
		ValidBefore:     uint64(now.Add(1 * time.Hour).Unix()),
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-pty": "",
			},
		},
	}
	require.NoError(t, cert.SignCert(rand.Reader, caSigner))

	baseSigner, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	certSigner, err := ssh.NewCertSigner(cert, baseSigner)
	require.NoError(t, err)

	return certSigner, cert
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
	t.Run("with repo watcher enables both auth methods", func(t *testing.T) {
		caSigner, caPub := generateCA(t)
		hostKey := generateHostKey(t)
		_ = caSigner // CA used only for its public key here

		cfg := NewServerConfig(Config{
			CAPublicKey:  caPub,
			HostSigner:   hostKey,
			MaxAuthTries: 3,
			RepoWatcher:  newTestRepoWatcher([]string{"org/repo"}),
		})

		assert.NotNil(t, cfg.PublicKeyCallback, "PublicKeyCallback should be set")
		assert.NotNil(t, cfg.PasswordCallback, "PasswordCallback should be set for OIDC")
		assert.Equal(t, 3, cfg.MaxAuthTries)
	})

	t.Run("without repo watcher disables OIDC", func(t *testing.T) {
		_, caPub := generateCA(t)
		hostKey := generateHostKey(t)

		cfg := NewServerConfig(Config{
			CAPublicKey:  caPub,
			HostSigner:   hostKey,
			MaxAuthTries: 5,
		})

		assert.NotNil(t, cfg.PublicKeyCallback, "PublicKeyCallback should always be set")
		assert.Nil(t, cfg.PasswordCallback, "PasswordCallback should be nil when no repo watcher configured")
		assert.Equal(t, 5, cfg.MaxAuthTries)
	})
}

func TestCertCallback(t *testing.T) {
	conn := fakeConnMeta{user: "runner"}

	t.Run("valid certificate from trusted CA", func(t *testing.T) {
		caSigner, caPub := generateCA(t)
		cb := certCallback(caPub)

		_, cert := issueUserCert(t, caSigner, "test-key-id")

		perms, err := cb(conn, cert)
		require.NoError(t, err)
		assert.Equal(t, "test-key-id", perms.Extensions[ExtIdentity])
		assert.Contains(t, perms.Extensions[ExtFingerprint], "SHA256:")
	})

	t.Run("rejects plain public key without certificate", func(t *testing.T) {
		_, caPub := generateCA(t)
		cb := certCallback(caPub)

		pub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		sshPub, err := ssh.NewPublicKey(pub)
		require.NoError(t, err)

		perms, err := cb(conn, sshPub)
		assert.Nil(t, perms)
		assert.ErrorContains(t, err, "certificate")
	})

	t.Run("rejects certificate from untrusted CA", func(t *testing.T) {
		untrustedCA, _ := generateCA(t)
		_, trustedCAPub := generateCA(t)
		cb := certCallback(trustedCAPub)

		_, cert := issueUserCert(t, untrustedCA, "untrusted-id")

		perms, err := cb(conn, cert)
		assert.Nil(t, perms)
		assert.ErrorContains(t, err, "certificate verification failed")
	})

	t.Run("rejects certificate with wrong principal", func(t *testing.T) {
		caSigner, caPub := generateCA(t)
		cb := certCallback(caPub)

		// Issue a cert valid only for "other-user", not "runner".
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		sshPub, err := ssh.NewPublicKey(pub)
		require.NoError(t, err)

		now := time.Now()
		cert := &ssh.Certificate{
			CertType:        ssh.UserCert,
			Key:             sshPub,
			KeyId:           "wrong-principal",
			ValidPrincipals: []string{"other-user"},
			ValidAfter:      uint64(now.Add(-5 * time.Minute).Unix()),
			ValidBefore:     uint64(now.Add(1 * time.Hour).Unix()),
		}
		require.NoError(t, cert.SignCert(rand.Reader, caSigner))

		perms, err := cb(conn, cert)
		assert.Nil(t, perms)
		assert.ErrorContains(t, err, "certificate verification failed")
	})

	t.Run("rejects expired certificate", func(t *testing.T) {
		caSigner, caPub := generateCA(t)
		cb := certCallback(caPub)

		pub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		sshPub, err := ssh.NewPublicKey(pub)
		require.NoError(t, err)

		past := time.Now().Add(-2 * time.Hour)
		cert := &ssh.Certificate{
			CertType:        ssh.UserCert,
			Key:             sshPub,
			KeyId:           "expired",
			ValidPrincipals: []string{"runner"},
			ValidAfter:      uint64(past.Add(-1 * time.Hour).Unix()),
			ValidBefore:     uint64(past.Unix()),
		}
		require.NoError(t, cert.SignCert(rand.Reader, caSigner))

		perms, err := cb(conn, cert)
		assert.Nil(t, perms)
		assert.Error(t, err)
	})

	t.Run("identity and fingerprint differ per certificate", func(t *testing.T) {
		caSigner, caPub := generateCA(t)
		cb := certCallback(caPub)

		_, certA := issueUserCert(t, caSigner, "id-alpha")
		_, certB := issueUserCert(t, caSigner, "id-beta")

		permsA, err := cb(conn, certA)
		require.NoError(t, err)
		permsB, err := cb(conn, certB)
		require.NoError(t, err)

		assert.NotEqual(t, permsA.Extensions[ExtFingerprint], permsB.Extensions[ExtFingerprint],
			"different keys should produce different fingerprints")
		assert.NotEqual(t, permsA.Extensions[ExtIdentity], permsB.Extensions[ExtIdentity])
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
		cb := oidcCallback(newTestRepoWatcher([]string{"org/repo"}))

		perms, err := cb(conn, []byte(""))
		assert.Nil(t, perms)
		assert.ErrorContains(t, err, "GitHub Actions authentication failed")
	})

	t.Run("rejects whitespace-only password", func(t *testing.T) {
		cb := oidcCallback(newTestRepoWatcher([]string{"org/repo"}))

		perms, err := cb(conn, []byte("   \t\n  "))
		assert.Nil(t, perms)
		assert.ErrorContains(t, err, "GitHub Actions authentication failed")
	})

	t.Run("rejects invalid JWT token", func(t *testing.T) {
		cb := oidcCallback(newTestRepoWatcher([]string{"org/repo"}))

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

func TestCertCallbackEndToEnd(t *testing.T) {
	// Simulates the full flow: create a CA, configure the server, authenticate
	// with a valid certificate, and verify the resulting permissions are usable.
	caSigner, caPub := generateCA(t)
	hostKey := generateHostKey(t)

	sshCfg := NewServerConfig(Config{
		CAPublicKey:  caPub,
		HostSigner:   hostKey,
		MaxAuthTries: 1,
	})

	// Use the configured callback directly (since we can't do a full SSH
	// handshake without a real TCP connection).
	_, cert := issueUserCert(t, caSigner, "deploy-key-42")
	conn := fakeConnMeta{user: "runner"}

	perms, err := sshCfg.PublicKeyCallback(conn, cert)
	require.NoError(t, err)

	// Verify we get the same extensions downstream code relies on.
	assert.Equal(t, "deploy-key-42", perms.Extensions[ExtIdentity])
	fp := perms.Extensions[ExtFingerprint]
	assert.NotEmpty(t, fp)
	assert.Contains(t, fp, "SHA256:")
	// Regular certs should NOT have the blip-vm extension.
	assert.Empty(t, perms.Extensions[ExtBlipVM])
}

func TestIsBlipVMIdentity(t *testing.T) {
	tests := []struct {
		identity string
		want     bool
	}{
		{"blip-vm:blip-abc1234567", true},
		{"blip-vm:sess-123", true},
		{"blip-vm:", true},
		{"blip:SHA256:abc", false},
		{"blip-vmx:something", false},
		{"", false},
		{"runner", false},
		{"oidc:repo:owner/repo:ref:refs/heads/main", false},
	}
	for _, tt := range tests {
		t.Run(tt.identity, func(t *testing.T) {
			assert.Equal(t, tt.want, IsBlipVMIdentity(tt.identity))
		})
	}
}

func TestCertCallback_BlipVMCert(t *testing.T) {
	// A certificate with a blip-vm: KeyId should get the ExtBlipVM extension.
	caSigner, caPub := generateCA(t)
	cb := certCallback(caPub)

	_, cert := issueUserCert(t, caSigner, "blip-vm:blip-a1b2c3d4e5")
	conn := fakeConnMeta{user: "runner"}

	perms, err := cb(conn, cert)
	require.NoError(t, err)
	assert.Equal(t, "blip-vm:blip-a1b2c3d4e5", perms.Extensions[ExtIdentity])
	assert.Equal(t, "true", perms.Extensions[ExtBlipVM])
	assert.Contains(t, perms.Extensions[ExtFingerprint], "SHA256:")
}

func TestCertCallback_RegularCertNoBlipVM(t *testing.T) {
	// A regular certificate should NOT get the ExtBlipVM extension.
	caSigner, caPub := generateCA(t)
	cb := certCallback(caPub)

	_, cert := issueUserCert(t, caSigner, "regular-user")
	conn := fakeConnMeta{user: "runner"}

	perms, err := cb(conn, cert)
	require.NoError(t, err)
	assert.Equal(t, "regular-user", perms.Extensions[ExtIdentity])
	assert.Empty(t, perms.Extensions[ExtBlipVM])
}

func TestParseRepoList(t *testing.T) {
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
			got := parseRepoList(tt.raw)
			assert.Equal(t, tt.want, got)
		})
	}
}
