// Package gateway is the SSH gateway: public keys map to owners, interactive
// shells launch a state menu, and other SSH channels reach the named sandbox.
package gateway

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"regexp"
	"time"

	"golang.org/x/crypto/ssh"
	"k8s.io/apimachinery/pkg/api/resource"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Azure/blip/internal/session"
)

// Config is the gateway's sandbox configuration.
type Config struct {
	Namespace   string
	BaseState   string
	Pool        string
	StateSize   resource.Quantity
	IdleTimeout time.Duration
	// StartNoticeDelay is how long an interactive session waits before saying
	// its sandbox is still starting. Zero disables the notice.
	StartNoticeDelay time.Duration
}

type Server struct {
	Config
	Kube     client.WithWatch
	Catalog  *Catalog
	Sessions *session.Client
	Users    *Users
	HostKey  ssh.Signer
	CA       ssh.Signer // signs SSH user certificates; nil disables certificates
	// ClientCAs verifies client certificates on the certificate API. When set,
	// requests without a verified client certificate are rejected. cmd sets it
	// from --tls-client-ca.
	ClientCAs *x509.CertPool
	// IdentityHeader is the request header set by the authenticated Envoy
	// gateway. Its value names the certificate owner.
	IdentityHeader string
	Log            *slog.Logger
}

const (
	extOwner   = "owner"
	extSandbox = "sandbox"
	extName    = "name"
)

// ownerPrincipal is the shape of the single principal in an issued user
// certificate. The SSH user name selects the sandbox, so the principal carries
// the owner instead.
var ownerPrincipal = regexp.MustCompile(`^u-[0-9a-f]{32}$`)

func (s *Server) sshConfig() *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			owner, err := s.owner(key)
			if err != nil {
				return nil, err
			}
			name, err := SandboxName(meta.User())
			if err != nil {
				return nil, err
			}
			full, err := fullSandboxName(owner, name)
			if err != nil {
				return nil, err
			}
			return &ssh.Permissions{Extensions: map[string]string{extOwner: owner, extSandbox: full, extName: name}}, nil
		},
	}
	cfg.AddHostKey(s.HostKey)
	return cfg
}

// owner returns the owner authenticated by key. Plain keys are looked up in
// the users ConfigMap; SSH user certificates must be signed by the gateway CA
// and carry exactly one owner principal.
func (s *Server) owner(key ssh.PublicKey) (string, error) {
	cert, ok := key.(*ssh.Certificate)
	if !ok {
		owner, ok := s.Users.Owner(key)
		if !ok {
			return "", errors.New("unknown public key")
		}
		return owner, nil
	}
	if s.CA == nil {
		return "", errors.New("certificate authentication is not configured")
	}
	if cert.CertType != ssh.UserCert {
		return "", errors.New("not a user certificate")
	}
	if len(cert.ValidPrincipals) != 1 || !ownerPrincipal.MatchString(cert.ValidPrincipals[0]) {
		return "", errors.New("certificate does not name one owner principal")
	}
	if !bytes.Equal(cert.SignatureKey.Marshal(), s.CA.PublicKey().Marshal()) {
		return "", errors.New("certificate was not signed by the gateway CA")
	}
	owner := cert.ValidPrincipals[0]
	if err := (&ssh.CertChecker{}).CheckCert(owner, cert); err != nil {
		return "", err
	}
	return owner, nil
}

// Serve accepts connections until ctx is done.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.ServeConn(ctx, c)
	}
}

// ServeConn handles one SSH connection.
func (s *Server) ServeConn(ctx context.Context, nc net.Conn) {
	defer nc.Close()
	nc.SetDeadline(time.Now().Add(30 * time.Second))
	conn, chans, reqs, err := ssh.NewServerConn(nc, s.sshConfig())
	if err != nil {
		s.Log.Debug("handshake failed", "remote", nc.RemoteAddr(), "error", err)
		return
	}
	nc.SetDeadline(time.Time{})
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		conn.Close()
	}()
	go ssh.DiscardRequests(reqs)
	owner := conn.Permissions.Extensions[extOwner]
	sandbox := conn.Permissions.Extensions[extSandbox]
	name := conn.Permissions.Extensions[extName]
	log := s.Log.With("owner", owner, "sandbox", sandbox, "remote", conn.RemoteAddr())
	log.Info("connected")
	defer log.Info("disconnected")
	for nch := range chans {
		switch nch.ChannelType() {
		case "session":
			go s.handleSession(ctx, owner, sandbox, name, nch)
		case "direct-tcpip":
			go s.handleDirectTCPIP(ctx, owner, sandbox, nch, log)
		default:
			nch.Reject(ssh.UnknownChannelType, "unsupported channel type")
		}
	}
}
