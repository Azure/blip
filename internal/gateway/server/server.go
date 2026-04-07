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
)

// Config holds the parameters needed to run the SSH server.
type Config struct {
	ListenAddr string

	// Shared host key (PEM) loaded by all replicas for a stable fingerprint.
	HostKeyPath string

	PodName string

	// Maximum lifetime of a single session.
	MaxSessionDuration time.Duration

	// Deadline for completing the SSH handshake.
	LoginGraceTime time.Duration

	MaxAuthTries int

	// AuthWatcher provides the dynamic allowed-repos and allowed-pubkeys
	// lists from a ConfigMap; nil disables OIDC and explicit pubkey auth.
	AuthWatcher *auth.AuthWatcher
}

// ConnHandler is called for each successfully authenticated SSH connection.
type ConnHandler func(ctx context.Context, serverConn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request)

// Server is a TCP-based SSH server.
type Server struct {
	listener       net.Listener
	sshConfig      *ssh.ServerConfig
	loginGraceTime time.Duration
}

// New creates a Server ready to accept SSH connections.
func New(cfg Config) (*Server, error) {
	hostSigner, err := loadSigner(cfg.HostKeyPath, "host key")
	if err != nil {
		return nil, err
	}

	slog.Info("host key loaded",
		"fingerprint", ssh.FingerprintSHA256(hostSigner.PublicKey()),
	)

	sshConfig := auth.NewServerConfig(auth.Config{
		HostSigner:   hostSigner,
		MaxAuthTries: cfg.MaxAuthTries,
		AuthWatcher:  cfg.AuthWatcher,
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
