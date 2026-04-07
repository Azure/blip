// Package sshca implements an SSH Certificate Authority for Blip.
package sshca

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

// GenerateCAKeypair creates a new Ed25519 CA keypair, returning the private key in PEM format and the public key in authorized_keys format.
func GenerateCAKeypair() (privPEM []byte, pubAuthorizedKey string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate ed25519 CA key: %w", err)
	}
	privBytes, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, "", fmt.Errorf("marshal CA private key: %w", err)
	}
	privPEM = pem.EncodeToMemory(privBytes)

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, "", fmt.Errorf("create SSH CA public key: %w", err)
	}
	pubStr := string(ssh.MarshalAuthorizedKey(sshPub))
	pubAuthorizedKey = pubStr[:len(pubStr)-1]

	return privPEM, pubAuthorizedKey, nil
}

// ParseCAPrivateKey parses a PEM-encoded private key into an ssh.Signer.
func ParseCAPrivateKey(pemData []byte) (ssh.Signer, error) {
	signer, err := ssh.ParsePrivateKey(pemData)
	if err != nil {
		return nil, fmt.Errorf("parse CA private key: %w", err)
	}
	return signer, nil
}

// serialNumber returns a random uint64 certificate serial.
func serialNumber() uint64 {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return binary.BigEndian.Uint64(buf[:])
}

// SignUserKey signs a user's SSH public key with the CA, returning a user certificate.
func SignUserKey(caSigner ssh.Signer, userPub ssh.PublicKey, keyID string, principals []string, validity time.Duration) (*ssh.Certificate, error) {
	now := time.Now()
	cert := &ssh.Certificate{
		CertType:        ssh.UserCert,
		Key:             userPub,
		KeyId:           keyID,
		ValidPrincipals: principals,
		// 5 min clock-skew grace.
		ValidAfter:  uint64(now.Add(-5 * time.Minute).Unix()),
		ValidBefore: uint64(now.Add(validity).Unix()),
		Serial:      serialNumber(),
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-pty":              "",
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
				"permit-X11-forwarding":   "",
				"permit-user-rc":          "",
			},
		},
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		return nil, fmt.Errorf("sign user certificate: %w", err)
	}
	return cert, nil
}

// SignHostKey signs a host's SSH public key with the CA, returning a host certificate.
func SignHostKey(caSigner ssh.Signer, hostPub ssh.PublicKey, keyID string, principals []string, validity time.Duration) (*ssh.Certificate, error) {
	if len(principals) == 0 {
		return nil, fmt.Errorf("host certificate requires at least one principal")
	}
	now := time.Now()
	cert := &ssh.Certificate{
		CertType:        ssh.HostCert,
		Key:             hostPub,
		KeyId:           keyID,
		ValidPrincipals: principals,
		ValidAfter:      uint64(now.Add(-5 * time.Minute).Unix()),
		ValidBefore:     uint64(now.Add(validity).Unix()),
		Serial:          serialNumber(),
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		return nil, fmt.Errorf("sign host certificate: %w", err)
	}
	return cert, nil
}

// GenerateAndSignEphemeralKey creates a fresh Ed25519 keypair and signs it as a user certificate with the CA.
func GenerateAndSignEphemeralKey(caSigner ssh.Signer, keyID string, principals []string, validity time.Duration) (ssh.Signer, *ssh.Certificate, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ephemeral key: %w", err)
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("create ephemeral SSH public key: %w", err)
	}

	cert, err := SignUserKey(caSigner, sshPub, keyID, principals, validity)
	if err != nil {
		return nil, nil, err
	}

	baseSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("create ephemeral signer: %w", err)
	}

	certSigner, err := ssh.NewCertSigner(cert, baseSigner)
	if err != nil {
		return nil, nil, fmt.Errorf("create cert signer: %w", err)
	}

	return certSigner, cert, nil
}

// VMIdentity holds the SSH key material generated for a VM.
type VMIdentity struct {
	// PrivateKeyPEM is the PEM-encoded Ed25519 private key injected into the VM.
	PrivateKeyPEM []byte

	// CertAuthorizedKey is the signed SSH user certificate in authorized_keys wire format.
	CertAuthorizedKey []byte

	// Fingerprint is the SHA256 fingerprint used to map incoming certificates back to a VM.
	Fingerprint string
}

// GenerateVMIdentity creates a fresh Ed25519 keypair for a VM, signs it with the CA,
// and returns the material needed to inject the identity into the VM.
func GenerateVMIdentity(caSigner ssh.Signer, sessionID string, principals []string, validity time.Duration) (*VMIdentity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate VM identity key: %w", err)
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("create VM identity SSH public key: %w", err)
	}

	keyID := "blip-vm:" + sessionID
	cert, err := SignUserKey(caSigner, sshPub, keyID, principals, validity)
	if err != nil {
		return nil, err
	}

	privBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, fmt.Errorf("marshal VM identity private key: %w", err)
	}

	return &VMIdentity{
		PrivateKeyPEM:     pem.EncodeToMemory(privBlock),
		CertAuthorizedKey: MarshalCertificate(cert),
		Fingerprint:       ssh.FingerprintSHA256(sshPub),
	}, nil
}

// MarshalCertificate returns the certificate in authorized_keys format.
func MarshalCertificate(cert *ssh.Certificate) []byte {
	return ssh.MarshalAuthorizedKey(cert)
}

// MarshalPublicKey returns the public key in authorized_keys format without a trailing newline.
func MarshalPublicKey(pub ssh.PublicKey) string {
	s := string(ssh.MarshalAuthorizedKey(pub))
	return s[:len(s)-1]
}
