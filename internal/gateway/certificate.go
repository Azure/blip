package gateway

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// CertificatePath is the HTTPS endpoint that exchanges an authenticated user
// identity and a public key for a short-lived SSH user certificate.
const CertificatePath = "/v1/ssh/certificate"

// certTTL is the lifetime of issued certificates.
const certTTL = 10 * time.Minute

// Handler serves the certificate API. Envoy terminates user TLS, presents a
// client certificate, and overwrites the identity header; the server itself
// requires that client certificate when ClientCAs is configured.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(CertificatePath, s.handleCertificate)
	return mux
}

type certificateResponse struct {
	Certificate string `json:"certificate"`
	HostKey     string `json:"host_key"`
}

func (s *Server) handleCertificate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.CA == nil {
		http.Error(w, "certificate authentication is not configured", http.StatusServiceUnavailable)
		return
	}
	// Defense in depth: TLSConfig already requires a verified client
	// certificate. Reject requests that did not present one, so reaching the
	// handler directly cannot forge the identity header.
	if s.ClientCAs != nil && (r.TLS == nil || len(r.TLS.VerifiedChains) == 0) {
		s.Log.Warn("rejected certificate request", "remote", r.RemoteAddr, "reason", "no verified client certificate")
		http.Error(w, "client certificate required", http.StatusForbidden)
		return
	}
	identities := r.Header.Values(s.IdentityHeader)
	if len(identities) != 1 {
		s.Log.Warn("rejected certificate request", "remote", r.RemoteAddr, "reason", "missing or repeated identity header")
		http.Error(w, "missing identity", http.StatusUnauthorized)
		return
	}
	identity := strings.TrimSpace(identities[0])
	if identity == "" {
		s.Log.Warn("rejected certificate request", "remote", r.RemoteAddr, "reason", "empty identity header")
		http.Error(w, "missing identity", http.StatusUnauthorized)
		return
	}
	line, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<10))
	if err != nil {
		http.Error(w, "cannot read body", http.StatusBadRequest)
		return
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey(line)
	if err != nil {
		http.Error(w, "invalid public key", http.StatusBadRequest)
		return
	}
	if _, ok := key.(*ssh.Certificate); ok {
		http.Error(w, "expected a plain public key", http.StatusBadRequest)
		return
	}

	owner := ownerFor(identity)
	cert, err := s.signCert(key, owner, certTTL)
	if err != nil {
		s.Log.Error("signing ssh certificate", "owner", owner, "error", err)
		http.Error(w, "cannot sign certificate", http.StatusInternalServerError)
		return
	}
	s.Log.Info("issued ssh certificate", "owner", owner, "remote", r.RemoteAddr)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(certificateResponse{
		Certificate: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert))),
		HostKey:     strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.HostKey.PublicKey()))),
	})
}

// ownerFor derives a stable, DNS-safe owner from the identity that the Envoy
// gateway authenticated. Owners are 34 characters, leaving room for a
// 28-character sandbox name within the 63-character limit.
func ownerFor(identity string) string {
	sum := sha256.Sum256([]byte(identity))
	return "u-" + hex.EncodeToString(sum[:16])
}

func (s *Server) signCert(key ssh.PublicKey, owner string, ttl time.Duration) (*ssh.Certificate, error) {
	if ttl <= 0 {
		return nil, errors.New("certificate lifetime must be positive")
	}
	var serial [8]byte
	if _, err := rand.Read(serial[:]); err != nil {
		return nil, err
	}
	cert := &ssh.Certificate{
		Key:             key,
		Serial:          binary.BigEndian.Uint64(serial[:]),
		CertType:        ssh.UserCert,
		ValidPrincipals: []string{owner},
		ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()),
		ValidBefore:     uint64(time.Now().Add(ttl).Unix()),
		Permissions: ssh.Permissions{Extensions: map[string]string{
			"permit-pty":             "",
			"permit-port-forwarding": "",
		}},
	}
	if err := cert.SignCert(rand.Reader, s.CA); err != nil {
		return nil, fmt.Errorf("sign certificate: %w", err)
	}
	return cert, nil
}
