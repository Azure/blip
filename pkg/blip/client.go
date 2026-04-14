// Package blip provides a Go SDK for allocating and managing blip VMs.
//
// A blip is an instant VM allocated from a pool on Kubernetes. The SDK
// communicates with the blip gateway over SSH — no Kubernetes access is
// required on the client side.
//
// # Authentication
//
// Authentication is resolved automatically in this order:
//  1. GitHub Actions OIDC token from GITHUB_TOKEN env var (or [WithGitHubToken])
//  2. SSH keys from ssh-agent (via SSH_AUTH_SOCK)
//  3. SSH keys from ~/.ssh/ (id_ed25519, id_rsa, id_ecdsa)
//
// # Lifecycle
//
// A blip starts ephemeral — it is destroyed when the connection closes.
// Call [Blip.Retain] to make it persistent, then reconnect later with
// [Client.Reconnect] using the session ID from [Blip.ID].
//
// # File Transfer
//
// Files can be transferred to and from the VM using SFTP:
//
//	b.Upload(ctx, "local.tar.gz", "/tmp/local.tar.gz")
//	b.Download(ctx, "/var/log/syslog", "syslog.log")
//	b.UploadDir(ctx, "./build", "/home/runner/build")
//
// For advanced operations use [Blip.SFTPClient] to get a full
// [github.com/pkg/sftp.Client].
//
// # Example
//
//	client, err := blip.NewClient("gateway.example.com")
//	if err != nil { ... }
//
//	b, err := client.Allocate(ctx)
//	if err != nil { ... }
//	defer b.Close()
//
//	// Run a command on the blip VM.
//	sess, _ := b.NewSession()
//	output, _ := sess.CombinedOutput("uname -a")
//
//	// Upload a file, then run it.
//	b.Upload(ctx, "./script.sh", "/tmp/script.sh")
//	sess2, _ := b.NewSession()
//	sess2.Run("bash /tmp/script.sh")
//
//	// Keep the blip alive after disconnect.
//	b.Retain(ctx, blip.WithTTL(2 * time.Hour))
//	fmt.Println("reconnect with:", b.ID())
package blip

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const defaultTimeout = 30 * time.Second

// Client connects to a blip gateway to allocate and manage VMs.
// A Client is safe for concurrent use by multiple goroutines.
type Client struct {
	addr      string
	sshConfig *ssh.ClientConfig
}

type clientConfig struct {
	githubToken    string
	sshKeyPath     string
	knownHostsPath string
	user           string
	port           string
	timeout        time.Duration
}

// Option configures a [Client].
type Option func(*clientConfig)

// WithGitHubToken sets an explicit GitHub Actions OIDC token for authentication.
// The gateway validates this JWT against the GitHub Actions OIDC provider.
// If not set, the GITHUB_TOKEN environment variable is checked.
//
// Note: this expects a GitHub Actions OIDC JWT, not a personal access token.
func WithGitHubToken(token string) Option {
	return func(c *clientConfig) {
		c.githubToken = token
	}
}

// WithSSHKey sets an explicit path to an SSH private key for authentication.
// If not set, ssh-agent and then default keys from ~/.ssh/ are tried.
func WithSSHKey(path string) Option {
	return func(c *clientConfig) {
		c.sshKeyPath = path
	}
}

// WithKnownHosts sets the path to a known_hosts file for host key verification.
// If not set, the gateway's host key is accepted on first use (TOFU).
func WithKnownHosts(path string) Option {
	return func(c *clientConfig) {
		c.knownHostsPath = path
	}
}

// WithPort sets the SSH port for the gateway connection.
// Defaults to "22".
func WithPort(port string) Option {
	return func(c *clientConfig) {
		c.port = port
	}
}

// WithTimeout sets the TCP connection timeout for dialing the gateway.
// Defaults to 30 seconds.
func WithTimeout(d time.Duration) Option {
	return func(c *clientConfig) {
		c.timeout = d
	}
}

// NewClient creates a Client that connects to the given gateway host.
// The addr should be just the hostname (e.g. "gateway.example.com").
// Use [WithPort] to override the default SSH port (22).
//
// Authentication is resolved automatically from the environment. See
// [WithGitHubToken] and [WithSSHKey] for explicit overrides.
func NewClient(addr string, opts ...Option) (*Client, error) {
	cfg := &clientConfig{
		user:    "runner",
		port:    "22",
		timeout: defaultTimeout,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	auth, err := resolveAuth(cfg)
	if err != nil {
		return nil, fmt.Errorf("resolve authentication: %w", err)
	}

	hostKeyCallback, err := resolveHostKeyCallback(cfg)
	if err != nil {
		return nil, fmt.Errorf("resolve host key verification: %w", err)
	}

	sshConfig := &ssh.ClientConfig{
		User:            cfg.user,
		Auth:            auth,
		HostKeyCallback: hostKeyCallback,
		Timeout:         cfg.timeout,
	}

	return &Client{
		addr:      net.JoinHostPort(addr, cfg.port),
		sshConfig: sshConfig,
	}, nil
}

// resolveHostKeyCallback returns the appropriate host key callback.
func resolveHostKeyCallback(cfg *clientConfig) (ssh.HostKeyCallback, error) {
	if cfg.knownHostsPath != "" {
		cb, err := knownhosts.New(cfg.knownHostsPath)
		if err != nil {
			return nil, fmt.Errorf("parse known_hosts %s: %w", cfg.knownHostsPath, err)
		}
		return cb, nil
	}
	// Trust on first use: accept any host key.
	// The gateway has a stable host key shared across replicas.
	return ssh.InsecureIgnoreHostKey(), nil
}

// dial opens a raw SSH connection to the gateway with the given username.
// The TCP dial phase respects the provided context for cancellation.
func (c *Client) dial(ctx context.Context, user string) (*ssh.Client, error) {
	cfg := *c.sshConfig // shallow copy
	cfg.User = user

	d := net.Dialer{Timeout: cfg.Timeout}
	tcpConn, err := d.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial %s: %w", c.addr, err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(tcpConn, c.addr, &cfg)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("ssh handshake %s: %w", c.addr, err)
	}

	return ssh.NewClient(sshConn, chans, reqs), nil
}
