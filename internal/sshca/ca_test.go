package sshca

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

// newCASigner creates a fresh CA signer for testing.
func newCASigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	return signer
}

// newSSHPublicKey creates a fresh SSH public key for testing.
func newSSHPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	return sshPub
}

func TestGenerateCAKeypairAndRoundTrip(t *testing.T) {
	// Generate a CA keypair, parse the private key back, and verify the
	// public key matches — covering the full generate → serialize → parse
	// → use lifecycle.
	privPEM, pubAuthorized, err := GenerateCAKeypair()
	require.NoError(t, err)

	// Private key should be valid PEM that ParseCAPrivateKey accepts.
	signer, err := ParseCAPrivateKey(privPEM)
	require.NoError(t, err)

	// Public key string should be parseable and match the signer's public key.
	parsedPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubAuthorized))
	require.NoError(t, err)
	assert.Equal(t, signer.PublicKey().Marshal(), parsedPub.Marshal(),
		"parsed public key should match the signer derived from the private key")

	// No trailing newline in the public key string.
	assert.NotContains(t, pubAuthorized, "\n")

	// Two calls produce distinct keypairs.
	privPEM2, pubAuthorized2, err := GenerateCAKeypair()
	require.NoError(t, err)
	assert.NotEqual(t, privPEM, privPEM2)
	assert.NotEqual(t, pubAuthorized, pubAuthorized2)
}

func TestParseCAPrivateKey(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr string
	}{
		{
			name:    "empty input",
			input:   []byte{},
			wantErr: "parse CA private key",
		},
		{
			name:    "garbage input",
			input:   []byte("not-a-pem-key"),
			wantErr: "parse CA private key",
		},
		{
			name:    "truncated PEM",
			input:   []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"),
			wantErr: "parse CA private key",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseCAPrivateKey(tt.input)
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestSignUserKey(t *testing.T) {
	ca := newCASigner(t)
	userPub := newSSHPublicKey(t)

	t.Run("produces a valid user certificate", func(t *testing.T) {
		cert, err := SignUserKey(ca, userPub, "user-42", []string{"deploy", "admin"}, 1*time.Hour)
		require.NoError(t, err)

		assert.Equal(t, uint32(ssh.UserCert), cert.CertType)
		assert.Equal(t, "user-42", cert.KeyId)
		assert.Equal(t, []string{"deploy", "admin"}, cert.ValidPrincipals)
		assert.NotZero(t, cert.Serial)

		// Validity window: ValidAfter should be ~5 min in the past,
		// ValidBefore should be ~1 hour in the future.
		now := time.Now()
		assert.InDelta(t, now.Add(-5*time.Minute).Unix(), int64(cert.ValidAfter), 5)
		assert.InDelta(t, now.Add(1*time.Hour).Unix(), int64(cert.ValidBefore), 5)

		// Standard user extensions should all be present.
		for _, ext := range []string{
			"permit-pty",
			"permit-agent-forwarding",
			"permit-port-forwarding",
			"permit-X11-forwarding",
			"permit-user-rc",
		} {
			assert.Contains(t, cert.Permissions.Extensions, ext)
		}
	})

	t.Run("certificate verifies against the CA", func(t *testing.T) {
		cert, err := SignUserKey(ca, userPub, "verify-test", []string{"runner"}, 30*time.Minute)
		require.NoError(t, err)

		checker := &ssh.CertChecker{
			IsUserAuthority: func(auth ssh.PublicKey) bool {
				return assert.ObjectsAreEqual(ca.PublicKey().Marshal(), auth.Marshal())
			},
		}
		err = checker.CheckCert("runner", cert)
		assert.NoError(t, err)
	})

	t.Run("allows empty principals", func(t *testing.T) {
		cert, err := SignUserKey(ca, userPub, "no-principals", nil, 1*time.Hour)
		require.NoError(t, err)
		assert.Empty(t, cert.ValidPrincipals)
	})

	t.Run("serial numbers are unique across calls", func(t *testing.T) {
		cert1, err := SignUserKey(ca, userPub, "s1", []string{"a"}, time.Hour)
		require.NoError(t, err)
		cert2, err := SignUserKey(ca, userPub, "s2", []string{"a"}, time.Hour)
		require.NoError(t, err)
		assert.NotEqual(t, cert1.Serial, cert2.Serial)
	})
}

func TestSignHostKey(t *testing.T) {
	ca := newCASigner(t)
	hostPub := newSSHPublicKey(t)

	t.Run("produces a valid host certificate", func(t *testing.T) {
		cert, err := SignHostKey(ca, hostPub, "host-1", []string{"10.0.0.1", "myhost.internal"}, 24*time.Hour)
		require.NoError(t, err)

		assert.Equal(t, uint32(ssh.HostCert), cert.CertType)
		assert.Equal(t, "host-1", cert.KeyId)
		assert.Equal(t, []string{"10.0.0.1", "myhost.internal"}, cert.ValidPrincipals)
		assert.NotZero(t, cert.Serial)

		now := time.Now()
		assert.InDelta(t, now.Add(-5*time.Minute).Unix(), int64(cert.ValidAfter), 5)
		assert.InDelta(t, now.Add(24*time.Hour).Unix(), int64(cert.ValidBefore), 5)

		// Host certs should have no extensions (unlike user certs).
		assert.Empty(t, cert.Permissions.Extensions)
	})

	t.Run("rejects empty principals", func(t *testing.T) {
		_, err := SignHostKey(ca, hostPub, "bad-host", nil, time.Hour)
		assert.ErrorContains(t, err, "at least one principal")

		_, err = SignHostKey(ca, hostPub, "bad-host", []string{}, time.Hour)
		assert.ErrorContains(t, err, "at least one principal")
	})

	t.Run("certificate verifies against the CA", func(t *testing.T) {
		cert, err := SignHostKey(ca, hostPub, "verify-host", []string{"myhost"}, time.Hour)
		require.NoError(t, err)

		checker := &ssh.CertChecker{
			IsHostAuthority: func(auth ssh.PublicKey, address string) bool {
				return assert.ObjectsAreEqual(ca.PublicKey().Marshal(), auth.Marshal())
			},
		}
		// CheckHostKey requires a host:port address.
		addr, _ := net.ResolveTCPAddr("tcp", "myhost:22")
		err = checker.CheckHostKey("myhost:22", addr, cert)
		assert.NoError(t, err)
	})
}

func TestGenerateAndSignEphemeralKey(t *testing.T) {
	ca := newCASigner(t)

	t.Run("end-to-end ephemeral key generation and signing", func(t *testing.T) {
		signer, cert, err := GenerateAndSignEphemeralKey(ca, "ephemeral-42", []string{"runner"}, 1*time.Hour)
		require.NoError(t, err)

		// Certificate is a user cert with correct metadata.
		assert.Equal(t, uint32(ssh.UserCert), cert.CertType)
		assert.Equal(t, "ephemeral-42", cert.KeyId)
		assert.Equal(t, []string{"runner"}, cert.ValidPrincipals)

		// The returned signer should be a cert signer whose public key
		// is a certificate (not a plain key).
		pubKey := signer.PublicKey()
		_, ok := pubKey.(*ssh.Certificate)
		assert.True(t, ok, "signer's public key should be a certificate")

		// The signer's certificate should match the returned certificate.
		signerCert := pubKey.(*ssh.Certificate)
		assert.Equal(t, cert.KeyId, signerCert.KeyId)
		assert.Equal(t, cert.Serial, signerCert.Serial)

		// The certificate verifies against the CA.
		checker := &ssh.CertChecker{
			IsUserAuthority: func(auth ssh.PublicKey) bool {
				return assert.ObjectsAreEqual(ca.PublicKey().Marshal(), auth.Marshal())
			},
		}
		assert.NoError(t, checker.CheckCert("runner", cert))
	})

	t.Run("each call produces distinct keys", func(t *testing.T) {
		signer1, cert1, err := GenerateAndSignEphemeralKey(ca, "eph-1", []string{"a"}, time.Hour)
		require.NoError(t, err)
		signer2, cert2, err := GenerateAndSignEphemeralKey(ca, "eph-2", []string{"a"}, time.Hour)
		require.NoError(t, err)

		assert.NotEqual(t, cert1.Key.Marshal(), cert2.Key.Marshal(),
			"ephemeral keys should be unique")
		assert.NotEqual(t, signer1.PublicKey().Marshal(), signer2.PublicKey().Marshal())
		assert.NotEqual(t, cert1.Serial, cert2.Serial)
	})
}

func TestMarshalCertificate(t *testing.T) {
	ca := newCASigner(t)
	userPub := newSSHPublicKey(t)

	cert, err := SignUserKey(ca, userPub, "marshal-test", []string{"user"}, time.Hour)
	require.NoError(t, err)

	marshaled := MarshalCertificate(cert)
	assert.NotEmpty(t, marshaled)

	// Should be parseable back.
	parsed, _, _, _, err := ssh.ParseAuthorizedKey(marshaled)
	require.NoError(t, err)

	parsedCert, ok := parsed.(*ssh.Certificate)
	require.True(t, ok, "parsed key should be a certificate")
	assert.Equal(t, cert.KeyId, parsedCert.KeyId)
	assert.Equal(t, cert.Serial, parsedCert.Serial)
}

func TestMarshalPublicKey(t *testing.T) {
	pub := newSSHPublicKey(t)
	marshaled := MarshalPublicKey(pub)

	// No trailing newline.
	assert.NotContains(t, marshaled, "\n")

	// Should round-trip via ParseAuthorizedKey.
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(marshaled))
	require.NoError(t, err)
	assert.Equal(t, pub.Marshal(), parsed.Marshal())
}

func TestCrossCAIsolation(t *testing.T) {
	// A certificate signed by one CA must not verify when the authority
	// callback only trusts a different CA.
	ca1 := newCASigner(t)
	ca2 := newCASigner(t)
	userPub := newSSHPublicKey(t)

	cert, err := SignUserKey(ca1, userPub, "cross-ca", []string{"runner"}, time.Hour)
	require.NoError(t, err)

	// The cert's SignatureKey should be ca1's public key, not ca2's.
	assert.Equal(t, ca1.PublicKey().Marshal(), cert.SignatureKey.Marshal())
	assert.NotEqual(t, ca2.PublicKey().Marshal(), cert.SignatureKey.Marshal(),
		"certificate signature key should differ from untrusted CA")
}

func TestGenerateVMIdentity(t *testing.T) {
	ca := newCASigner(t)

	t.Run("produces valid identity material", func(t *testing.T) {
		ident, err := GenerateVMIdentity(ca, "blip-abc1234567", []string{"runner"}, 8*time.Hour)
		require.NoError(t, err)

		// Private key should be valid PEM.
		assert.Contains(t, string(ident.PrivateKeyPEM), "BEGIN OPENSSH PRIVATE KEY")
		signer, err := ssh.ParsePrivateKey(ident.PrivateKeyPEM)
		require.NoError(t, err)
		assert.Equal(t, "ssh-ed25519", signer.PublicKey().Type())

		// Certificate should be parseable.
		parsed, _, _, _, err := ssh.ParseAuthorizedKey(ident.CertAuthorizedKey)
		require.NoError(t, err)
		parsedCert, ok := parsed.(*ssh.Certificate)
		require.True(t, ok, "should be a certificate")
		assert.Equal(t, "blip-vm:blip-abc1234567", parsedCert.KeyId)
		assert.Equal(t, []string{"runner"}, parsedCert.ValidPrincipals)
		assert.Equal(t, uint32(ssh.UserCert), parsedCert.CertType)

		// Certificate should verify against the CA.
		checker := &ssh.CertChecker{
			IsUserAuthority: func(auth ssh.PublicKey) bool {
				return assert.ObjectsAreEqual(ca.PublicKey().Marshal(), auth.Marshal())
			},
		}
		assert.NoError(t, checker.CheckCert("runner", parsedCert))

		// Fingerprint should be a SHA256 fingerprint.
		assert.Contains(t, ident.Fingerprint, "SHA256:")
	})

	t.Run("each call produces unique identities", func(t *testing.T) {
		id1, err := GenerateVMIdentity(ca, "sess-1", []string{"runner"}, time.Hour)
		require.NoError(t, err)
		id2, err := GenerateVMIdentity(ca, "sess-2", []string{"runner"}, time.Hour)
		require.NoError(t, err)

		assert.NotEqual(t, id1.PrivateKeyPEM, id2.PrivateKeyPEM)
		assert.NotEqual(t, id1.CertAuthorizedKey, id2.CertAuthorizedKey)
		assert.NotEqual(t, id1.Fingerprint, id2.Fingerprint)
	})

	t.Run("fingerprint matches the certificate's underlying key", func(t *testing.T) {
		ident, err := GenerateVMIdentity(ca, "sess-fp", []string{"runner"}, time.Hour)
		require.NoError(t, err)

		// Parse the private key and verify its public key fingerprint
		// matches the stored fingerprint.
		signer, err := ssh.ParsePrivateKey(ident.PrivateKeyPEM)
		require.NoError(t, err)
		assert.Equal(t, ident.Fingerprint, ssh.FingerprintSHA256(signer.PublicKey()))
	})
}
