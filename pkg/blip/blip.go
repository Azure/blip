package blip

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Sentinel errors returned by SDK operations.
var (
	// ErrClosed is returned when operating on a closed [Blip].
	ErrClosed = errors.New("blip is closed")

	// ErrAllocationFailed is returned when the gateway cannot allocate a VM.
	ErrAllocationFailed = errors.New("allocation failed")

	// ErrReconnectFailed is returned when the gateway cannot reconnect to a session.
	ErrReconnectFailed = errors.New("reconnect failed")

	// ErrInvalidSessionID is returned when a session ID does not match the
	// expected format (blip-<10 hex chars>).
	ErrInvalidSessionID = errors.New("invalid session ID")
)

// sessionIDPattern matches blip session IDs like "blip-a3f29c04b1" in banner text.
var sessionIDPattern = regexp.MustCompile(`blip-[0-9a-f]{10}`)

// Blip is a handle to an allocated VM. It holds the SSH connection to the
// gateway, which proxies traffic to the underlying VM.
//
// Use [Client.Allocate] or [Client.Reconnect] to obtain a Blip.
type Blip struct {
	id          string
	client      *Client
	conn        *ssh.Client
	initSession *ssh.Session // the shell session used for allocation/banner

	mu     sync.Mutex
	closed bool
}

// ID returns the session ID (e.g. "blip-a3f29c04b1"). This can be used
// to reconnect to a retained blip via [Client.Reconnect].
func (b *Blip) ID() string {
	return b.id
}

// RetainOption configures the [Blip.Retain] operation.
type RetainOption func(*retainConfig)

type retainConfig struct {
	ttl time.Duration
}

// WithTTL sets a custom time-to-live for the retained blip.
// The maximum TTL is 12 hours from the original allocation time.
// The duration must be positive.
func WithTTL(d time.Duration) RetainOption {
	return func(c *retainConfig) {
		c.ttl = d
	}
}

// Retain marks the blip as non-ephemeral so it persists after disconnect.
// By default the blip keeps its original TTL. Use [WithTTL] to set a
// custom duration.
//
// After retaining, you can reconnect to the blip using [Client.Reconnect]
// with the session ID from [Blip.ID].
func (b *Blip) Retain(ctx context.Context, opts ...RetainOption) error {
	conn, err := b.sshConn()
	if err != nil {
		return err
	}

	cfg := &retainConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	cmd := "blip retain"
	if cfg.ttl > 0 {
		cmd = fmt.Sprintf("blip retain --ttl %s", formatDuration(cfg.ttl))
	}

	session, err := conn.NewSession()
	if err != nil {
		return fmt.Errorf("open session for retain: %w", err)
	}

	// Run the command with context cancellation support.
	type cmdResult struct {
		output []byte
		err    error
	}
	ch := make(chan cmdResult, 1)
	go func() {
		// blip retain writes status to stderr and the session ID to stdout.
		out, err := session.CombinedOutput(cmd)
		ch <- cmdResult{out, err}
	}()

	select {
	case <-ctx.Done():
		session.Close()
		return ctx.Err()
	case res := <-ch:
		session.Close()
		if res.err != nil {
			return fmt.Errorf("retain command failed: %w: %s", res.err, string(res.output))
		}
		return nil
	}
}

// NewSession opens a new SSH session on the blip VM. The returned session
// can be used to run commands, start shells, or set up port forwarding.
//
// Callers are responsible for closing the returned session.
func (b *Blip) NewSession() (*ssh.Session, error) {
	conn, err := b.sshConn()
	if err != nil {
		return nil, err
	}
	return conn.NewSession()
}

// SSHClient returns the underlying SSH client connected to the blip VM.
// The connection is proxied through the gateway — it supports opening
// sessions, running commands, and forwarding ports.
//
// The returned client shares the connection with the Blip. Do not close
// it directly; use [Blip.Close] instead.
func (b *Blip) SSHClient() (*ssh.Client, error) {
	return b.sshConn()
}

// Close disconnects from the blip. If the blip is still ephemeral (not
// retained), the VM will be destroyed by the gateway. If the blip has
// been retained, it will persist and can be reconnected to later.
//
// Close is safe to call multiple times.
func (b *Blip) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil
	}
	b.closed = true
	if b.initSession != nil {
		b.initSession.Close()
	}
	return b.conn.Close()
}

// Allocate requests a new blip VM from the pool. The returned [Blip]
// holds a live SSH connection proxied through the gateway to the VM.
//
// The blip is ephemeral by default and will be destroyed when the
// connection is closed. Call [Blip.Retain] to preserve it.
func (c *Client) Allocate(ctx context.Context) (*Blip, error) {
	return c.connectToGateway(ctx, "runner")
}

// Reconnect reattaches to a previously retained blip by session ID.
// The session ID is available from [Blip.ID] before disconnecting.
func (c *Client) Reconnect(ctx context.Context, sessionID string) (*Blip, error) {
	if !isValidSessionID(sessionID) {
		return nil, fmt.Errorf("%w: %q (must match blip-<10 hex chars>)", ErrInvalidSessionID, sessionID)
	}
	return c.connectToGateway(ctx, sessionID)
}

// connectToGateway dials the gateway, opens a session channel to trigger VM
// allocation, and parses the banner to extract the session ID.
func (c *Client) connectToGateway(ctx context.Context, user string) (*Blip, error) {
	conn, err := c.dial(ctx, user)
	if err != nil {
		return nil, err
	}

	// Open a session channel. The gateway uses this as the trigger
	// to allocate a VM and start proxying.
	session, err := conn.NewSession()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("open initial session: %w", err)
	}

	// The gateway writes banners to stderr. We need to read them
	// to extract the session ID.
	stderrPipe, err := session.StderrPipe()
	if err != nil {
		session.Close()
		conn.Close()
		return nil, fmt.Errorf("get stderr pipe: %w", err)
	}

	// Request a PTY to trigger the gateway's banner flow.
	if err := session.RequestPty("xterm", 40, 80, ssh.TerminalModes{}); err != nil {
		session.Close()
		conn.Close()
		return nil, fmt.Errorf("request pty: %w", err)
	}

	if err := session.Shell(); err != nil {
		session.Close()
		conn.Close()
		return nil, fmt.Errorf("start shell: %w", err)
	}

	// Parse the banner to extract the session ID.
	sessionID, err := parseSessionID(ctx, stderrPipe)
	if err != nil {
		session.Close()
		conn.Close()
		return nil, fmt.Errorf("parse session ID from banner: %w", err)
	}

	return &Blip{
		id:          sessionID,
		client:      c,
		conn:        conn,
		initSession: session,
	}, nil
}

// parseSessionID reads from the banner stream until it finds a session ID
// or the context is cancelled.
func parseSessionID(ctx context.Context, r io.Reader) (string, error) {
	type result struct {
		id  string
		err error
	}

	ch := make(chan result, 1)
	go func() {
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			line := strings.TrimRight(scanner.Text(), "\r") // handle CRLF from gateway

			// Look for "Session : blip-..." in the banner.
			if strings.Contains(line, "Session") {
				if id := sessionIDPattern.FindString(line); id != "" {
					ch <- result{id: id}
					return
				}
			}
			// Also check for allocation errors.
			if strings.Contains(line, "allocation failed") {
				ch <- result{err: fmt.Errorf("%w: %s", ErrAllocationFailed, strings.TrimSpace(line))}
				return
			}
			if strings.Contains(line, "Reconnect failed") {
				ch <- result{err: fmt.Errorf("%w: %s", ErrReconnectFailed, strings.TrimSpace(line))}
				return
			}
		}
		if err := scanner.Err(); err != nil {
			ch <- result{err: fmt.Errorf("read banner: %w", err)}
		} else {
			ch <- result{err: fmt.Errorf("banner stream ended without session ID")}
		}
	}()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case res := <-ch:
		return res.id, res.err
	}
}

// isValidSessionID checks whether id matches the blip session ID format
// (blip- followed by exactly 10 lowercase hex characters).
func isValidSessionID(id string) bool {
	suffix, ok := strings.CutPrefix(id, "blip-")
	if !ok || len(suffix) != 10 {
		return false
	}
	_, err := hex.DecodeString(suffix)
	return err == nil && suffix == strings.ToLower(suffix)
}

// formatDuration converts a time.Duration to the format expected by the
// blip retain command (e.g. "2h", "30m", "1h30m").
func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60

	var parts []string
	if h > 0 {
		parts = append(parts, fmt.Sprintf("%dh", h))
	}
	if m > 0 {
		parts = append(parts, fmt.Sprintf("%dm", m))
	}
	if s > 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%ds", s))
	}
	return strings.Join(parts, "")
}
