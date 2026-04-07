// Package server manages the SSH server lifecycle for the gateway.
package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/project-unbounded/blip/internal/gateway/auth"
	"github.com/project-unbounded/blip/internal/sshca"
)

// Config holds the parameters needed to run the SSH server.
type Config struct {
	ListenAddr string

	// Path to the SSH CA private key (PEM) for signing the host certificate.
	CAKeyPath string

	// Path to the SSH CA public key for verifying client certificates.
	CAPubKeyPath string

	// Shared host key (PEM) loaded by all replicas for a stable fingerprint.
	HostKeyPath string

	PodName string

	// Hostnames/IPs embedded in the CA-signed host certificate.
	HostPrincipals []string

	// Maximum lifetime of a single session; also drives host cert validity.
	MaxSessionDuration time.Duration

	// Deadline for completing the SSH handshake.
	LoginGraceTime time.Duration

	MaxAuthTries int

	// RepoWatcher provides the dynamic allowed-repos list from a ConfigMap; nil disables OIDC auth.
	RepoWatcher *auth.RepoWatcher
}

// ConnHandler is called for each successfully authenticated SSH connection.
type ConnHandler func(ctx context.Context, serverConn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request)

// Server is a TCP-based SSH server with a CA-signed host certificate.
type Server struct {
	listener       net.Listener
	sshConfig      *ssh.ServerConfig
	loginGraceTime time.Duration
}

// New creates a Server ready to accept SSH connections.
func New(cfg Config) (*Server, error) {
	caSigner, err := loadSigner(cfg.CAKeyPath, "CA key")
	if err != nil {
		return nil, err
	}

	hostSigner, err := newHostCertSigner(caSigner, cfg)
	if err != nil {
		return nil, err
	}

	caPublicKey, err := loadCAPublicKey(cfg.CAPubKeyPath)
	if err != nil {
		return nil, err
	}

	sshConfig := auth.NewServerConfig(auth.Config{
		CAPublicKey:  caPublicKey,
		HostSigner:   hostSigner,
		MaxAuthTries: cfg.MaxAuthTries,
		RepoWatcher:  cfg.RepoWatcher,
	})

	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", cfg.ListenAddr, err)
	}

	return &Server{
		listener:       listener,
		sshConfig:      sshConfig,
		loginGraceTime: cfg.LoginGraceTime,
	}, nil
}

// Addr returns the listener's network address.
func (s *Server) Addr() net.Addr { return s.listener.Addr() }

// Serve runs the accept loop, dispatching authenticated connections to handler.
func (s *Server) Serve(ctx context.Context, handler ConnHandler) error {
	var wg sync.WaitGroup

	// When the context is cancelled, close the listener to unblock Accept.
	context.AfterFunc(ctx, func() { s.listener.Close() })

	for {
		tcpConn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				slog.Info("listener closed, waiting for connections to drain")
				wg.Wait()
				slog.Info("ssh server stopped")
				return nil
			default:
				slog.Error("accept failed", "error", err)
				continue
			}
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			serverConn, chans, reqs, err := s.handshake(tcpConn)
			if err != nil {
				slog.Debug("SSH handshake failed",
					"remote", tcpConn.RemoteAddr().String(),
					"error", err,
				)
				tcpConn.Close()
				return
			}
			handler(ctx, serverConn, chans, reqs)
		}()
	}
}

// Close immediately closes the listener.
func (s *Server) Close() error { return s.listener.Close() }

// newHostCertSigner loads the host key, signs it with the CA, and returns a cert signer.
func newHostCertSigner(caSigner ssh.Signer, cfg Config) (ssh.Signer, error) {
	baseSigner, err := loadSigner(cfg.HostKeyPath, "host key")
	if err != nil {
		return nil, fmt.Errorf("load host key: %w", err)
	}

	keyID := fmt.Sprintf("gateway-host:%s", cfg.PodName)
	cert, err := sshca.SignHostKey(
		caSigner,
		baseSigner.PublicKey(),
		keyID,
		cfg.HostPrincipals,
		cfg.MaxSessionDuration+1*time.Hour,
	)
	if err != nil {
		return nil, fmt.Errorf("sign host key: %w", err)
	}

	hostSigner, err := ssh.NewCertSigner(cert, baseSigner)
	if err != nil {
		return nil, fmt.Errorf("create host cert signer: %w", err)
	}

	slog.Info("host certificate generated",
		"key_id", cert.KeyId,
		"principals", cfg.HostPrincipals,
		"serial", cert.Serial,
		"fingerprint", ssh.FingerprintSHA256(baseSigner.PublicKey()),
		"valid_before", time.Unix(int64(cert.ValidBefore), 0).UTC().Format(time.RFC3339),
	)

	return hostSigner, nil
}

// loadSigner reads a PEM-encoded SSH private key from path.
func loadSigner(path, label string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s %s: %w", label, path, err)
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", label, err)
	}
	return signer, nil
}

// loadCAPublicKey reads an SSH public key in authorized_keys format.
func loadCAPublicKey(path string) (ssh.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA public key %s: %w", path, err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse CA public key: %w", err)
	}
	slog.Info("CA public key loaded for client certificate verification")
	return pub, nil
}

// handshake performs the SSH handshake, enforcing the login grace time.
func (s *Server) handshake(tcpConn net.Conn) (*ssh.ServerConn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	if err := tcpConn.SetDeadline(time.Now().Add(s.loginGraceTime)); err != nil {
		tcpConn.Close()
		return nil, nil, nil, err
	}

	serverConn, chans, reqs, err := ssh.NewServerConn(tcpConn, s.sshConfig)
	if err != nil {
		return nil, nil, nil, err
	}

	if err := tcpConn.SetDeadline(time.Time{}); err != nil {
		slog.Debug("failed to clear deadline",
			"remote", tcpConn.RemoteAddr().String(),
			"error", err,
		)
	}

	return serverConn, chans, reqs, nil
}
