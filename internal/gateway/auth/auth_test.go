package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
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
	t.Run("with auth watcher enables pubkey auth", func(t *testing.T) {
		hostKey := generateHostKey(t)

		cfg := NewServerConfig(context.Background(), Config{
			HostSigner:   hostKey,
			MaxAuthTries: 3,
			AuthWatcher:  NewTestAuthWatcher(map[string]string{"SHA256:test": "alice"}),
		})

		assert.NotNil(t, cfg.PublicKeyCallback, "PublicKeyCallback should be set")
		assert.Equal(t, 3, cfg.MaxAuthTries)
	})

	t.Run("without auth watcher disables all auth", func(t *testing.T) {
		hostKey := generateHostKey(t)

		cfg := NewServerConfig(context.Background(), Config{
			HostSigner:   hostKey,
			MaxAuthTries: 5,
		})

		assert.Nil(t, cfg.PublicKeyCallback, "PublicKeyCallback should be nil when no auth watcher configured")
		assert.Equal(t, 5, cfg.MaxAuthTries)
	})
}

func TestExplicitPubkeyAuth(t *testing.T) {
	conn := fakeConnMeta{user: "runner"}

	t.Run("accepts allowed pubkey", func(t *testing.T) {
		userPub, _ := generateUserKey(t)
		fp := ssh.FingerprintSHA256(userPub)

		watcher := NewTestAuthWatcher(map[string]string{fp: "alice"})
		cb := pubkeyCallback(watcher, nil)

		perms, err := cb(conn, userPub)
		require.NoError(t, err)
		assert.Equal(t, fp, perms.Extensions[ExtFingerprint])
		assert.Equal(t, "pubkey:alice", perms.Extensions[ExtIdentity])
	})

	t.Run("rejects unknown pubkey", func(t *testing.T) {
		userPub, _ := generateUserKey(t)

		watcher := NewTestAuthWatcher(map[string]string{"SHA256:other": "bob"})
		cb := pubkeyCallback(watcher, nil)

		perms, err := cb(conn, userPub)
		assert.Nil(t, perms)
		assert.ErrorContains(t, err, "not authorized")
	})

	t.Run("rejects pubkey when watcher has empty set", func(t *testing.T) {
		userPub, _ := generateUserKey(t)

		watcher := NewTestAuthWatcher(nil)
		cb := pubkeyCallback(watcher, nil)

		perms, err := cb(conn, userPub)
		assert.Nil(t, perms)
		assert.ErrorContains(t, err, "not authorized")
	})

	t.Run("rejects pubkey with empty user identity", func(t *testing.T) {
		userPub, _ := generateUserKey(t)
		fp := ssh.FingerprintSHA256(userPub)

		watcher := NewTestAuthWatcher(map[string]string{fp: ""})
		cb := pubkeyCallback(watcher, nil)

		perms, err := cb(conn, userPub)
		assert.Nil(t, perms)
		assert.ErrorContains(t, err, "not authorized")
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
		AuthWatcher:  NewTestAuthWatcher(map[string]string{fp: "alice"}),
	})

	conn := fakeConnMeta{user: "runner"}
	perms, err := sshCfg.PublicKeyCallback(conn, userPub)
	require.NoError(t, err)
	assert.Equal(t, fp, perms.Extensions[ExtFingerprint])
	assert.Equal(t, "pubkey:alice", perms.Extensions[ExtIdentity])
}
