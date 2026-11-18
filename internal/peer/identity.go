package peer

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Identity is a node's persistent signing key, independent of the cluster disk
// key. Its short-lived self-signed certificate is renewed without changing the
// public key published in Kubernetes.
type Identity struct {
	key  ed25519.PrivateKey
	mu   sync.Mutex
	cert *tls.Certificate
}

// LoadIdentity loads or atomically creates dataDir/identity.key (an Ed25519
// seed, mode 0600). A damaged identity is an error, never silently replaced.
func LoadIdentity(dataDir string) (*Identity, error) {
	if dataDir == "" {
		return nil, errors.New("peer: missing identity directory")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dataDir, "identity.key")
	seed, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		seed = make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		var f *os.File
		f, err = os.CreateTemp(dataDir, ".identity-*")
		if err != nil {
			return nil, err
		}
		defer os.Remove(f.Name())
		if _, err = f.Write(seed); err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
		// Link publishes the complete key without replacing a concurrent
		// creator's identity.
		if err := os.Link(f.Name(), path); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		seed, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("peer: invalid identity key in %s", path)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, err
	}
	return &Identity{key: ed25519.NewKeyFromSeed(seed)}, nil
}

func (i *Identity) PublicKey() string {
	return base64.StdEncoding.EncodeToString(i.key.Public().(ed25519.PublicKey))
}

func (i *Identity) certificate() (*tls.Certificate, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	now := time.Now()
	if i.cert != nil && now.After(i.cert.Leaf.NotBefore) && now.Add(6*time.Hour).Before(i.cert.Leaf.NotAfter) {
		return i.cert, nil
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "blip-peer"},
		NotBefore:    now.Add(-5 * time.Minute), NotAfter: now.Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, i.key.Public(), i.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	i.cert = &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: i.key, Leaf: leaf}
	return i.cert, nil
}

// certificateKey validates the self-signed leaf. Trust is established only by
// looking up this key in the current registry, not by subject, SAN, IP, or CA.
func certificateKey(certs []*x509.Certificate) (string, error) {
	if len(certs) != 1 {
		return "", errors.New("peer: expected one self-signed certificate")
	}
	cert := certs[0]
	key, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok || len(key) != ed25519.PublicKeySize {
		return "", errors.New("peer: certificate must use Ed25519")
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return "", errors.New("peer: certificate is not currently valid")
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		return "", fmt.Errorf("peer: invalid self-signature: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

func (i *Identity) serverTLS(peers *Registry) *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		ClientAuth:             tls.RequireAnyClientCert,
		SessionTicketsDisabled: true,
		GetCertificate:         func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return i.certificate() },
		VerifyConnection: func(cs tls.ConnectionState) error {
			key, err := certificateKey(cs.PeerCertificates)
			if err != nil {
				return err
			}
			if _, ok := peers.NodeForKey(key); !ok {
				return errors.New("peer: unregistered client key")
			}
			return nil
		},
	}
}

func (i *Identity) clientTLS(peers *Registry, node string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		// There is no CA or hostname identity. VerifyConnection below replaces
		// PKI verification with an exact, current key pin for the named node.
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		GetClientCertificate:   func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return i.certificate() },
		VerifyConnection: func(cs tls.ConnectionState) error {
			key, err := certificateKey(cs.PeerCertificates)
			if err != nil {
				return err
			}
			p, ok := peers.Lookup(node)
			if !ok || p.PublicKey != key {
				return fmt.Errorf("peer: server key does not match node %q", node)
			}
			return nil
		},
	}
}
