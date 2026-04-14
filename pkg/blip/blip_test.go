package blip

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{30 * time.Second, "30s"},
		{5 * time.Minute, "5m"},
		{2 * time.Hour, "2h"},
		{90 * time.Minute, "1h30m"},
		{2*time.Hour + 30*time.Minute, "2h30m"},
		{time.Hour + 30*time.Minute + 45*time.Second, "1h30m45s"},
		{0, "0s"},
		{-5 * time.Minute, "0s"}, // negative clamped to zero
	}
	for _, tt := range tests {
		t.Run(tt.d.String(), func(t *testing.T) {
			got := formatDuration(tt.d)
			if got != tt.want {
				t.Errorf("formatDuration(%v) = %q, want %q", tt.d, got, tt.want)
			}
		})
	}
}

func TestParseSessionID(t *testing.T) {
	tests := []struct {
		name    string
		banner  string
		want    string
		wantErr string
	}{
		{
			name: "standard banner",
			banner: `
  ____  _ _
 | __ )| (_)_ __
 |  _ \| | | '_ \
 | |_) | | | |_) |
 |____/|_|_| .__/
            |_|

  >>> Allocating blip...
  >>> Connected to gateway
  Session : blip-a3f29c04b1
  Blip    : pool-blip-abcdef
  Lease   : ephemeral (8h TTL)
`,
			want: "blip-a3f29c04b1",
		},
		{
			name: "reconnect banner",
			banner: `
  >>> Reconnecting...
  >>> Reconnected to gateway
  Session : blip-ff00112233
  Blip    : pool-blip-xyz123
`,
			want: "blip-ff00112233",
		},
		{
			name:   "CRLF banner",
			banner: "  Session : blip-a3f29c04b1\r\n  Blip    : pool-blip-abc\r\n",
			want:   "blip-a3f29c04b1",
		},
		{
			name:    "allocation failure",
			banner:  "  >>> Blip allocation failed: no unclaimed ready blips available\n",
			wantErr: "allocation failed",
		},
		{
			name:    "reconnect failure",
			banner:  "  >>> Reconnect failed: auth fingerprint does not match\n",
			wantErr: "Reconnect failed",
		},
		{
			name:    "empty stream",
			banner:  "",
			wantErr: "banner stream ended without session ID",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			r := strings.NewReader(tt.banner)
			got, err := parseSessionID(ctx, r)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("parseSessionID() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseSessionIDSentinelErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("allocation failed wraps ErrAllocationFailed", func(t *testing.T) {
		r := strings.NewReader("  >>> Blip allocation failed: no blips\n")
		_, err := parseSessionID(ctx, r)
		if !errors.Is(err, ErrAllocationFailed) {
			t.Fatalf("expected ErrAllocationFailed, got %v", err)
		}
	})

	t.Run("reconnect failed wraps ErrReconnectFailed", func(t *testing.T) {
		r := strings.NewReader("  >>> Reconnect failed: mismatch\n")
		_, err := parseSessionID(ctx, r)
		if !errors.Is(err, ErrReconnectFailed) {
			t.Fatalf("expected ErrReconnectFailed, got %v", err)
		}
	})
}

func TestParseSessionIDContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Use a pipe that blocks on read (unlike bytes.Buffer which returns EOF immediately).
	r, w := io.Pipe()
	defer w.Close()
	defer r.Close()

	_, err := parseSessionID(ctx, r)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestIsValidSessionID(t *testing.T) {
	tests := []struct {
		input string
		valid bool
	}{
		{"blip-a3f29c04b1", true},
		{"blip-0000000000", true},
		{"blip-ffffffffff", true},
		{"blip-short", false},
		{"blip-AABBCCDDEE", false},      // uppercase
		{"not-a-blip-id", false},        // wrong prefix
		{"blip-a3f29c04b1extra", false}, // too long
		{"blip-", false},                // no suffix
		{"", false},                     // empty
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isValidSessionID(tt.input)
			if got != tt.valid {
				t.Errorf("isValidSessionID(%q) = %v, want %v", tt.input, got, tt.valid)
			}
		})
	}
}

func TestResolveAuthGitHubToken(t *testing.T) {
	cfg := &clientConfig{githubToken: "test-token"}
	methods, err := resolveAuth(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(methods) != 1 {
		t.Fatalf("expected 1 auth method, got %d", len(methods))
	}
}

func TestResolveAuthNoMethods(t *testing.T) {
	cfg := &clientConfig{sshKeyPath: "/nonexistent/key"}
	_, err := resolveAuth(cfg)
	if err == nil {
		t.Fatal("expected error for nonexistent key")
	}
}

func TestNewClientWithGitHubToken(t *testing.T) {
	c, err := NewClient("example.com", WithGitHubToken("test-token"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.addr != "example.com:22" {
		t.Errorf("addr = %q, want %q", c.addr, "example.com:22")
	}
}

func TestNewClientWithPort(t *testing.T) {
	c, err := NewClient("example.com", WithGitHubToken("tok"), WithPort("2222"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.addr != "example.com:2222" {
		t.Errorf("addr = %q, want %q", c.addr, "example.com:2222")
	}
}

func TestNewClientWithTimeout(t *testing.T) {
	c, err := NewClient("example.com", WithGitHubToken("tok"), WithTimeout(5*time.Second))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.sshConfig.Timeout != 5*time.Second {
		t.Errorf("timeout = %v, want %v", c.sshConfig.Timeout, 5*time.Second)
	}
}

func TestNewClientDefaultTimeout(t *testing.T) {
	c, err := NewClient("example.com", WithGitHubToken("tok"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.sshConfig.Timeout != defaultTimeout {
		t.Errorf("timeout = %v, want %v", c.sshConfig.Timeout, defaultTimeout)
	}
}

func TestBlipCloseTwice(t *testing.T) {
	// Closing a blip twice should not panic.
	b := &Blip{closed: true}
	if err := b.Close(); err != nil {
		t.Errorf("second close should return nil, got %v", err)
	}
}

func TestBlipSSHClientAfterClose(t *testing.T) {
	b := &Blip{closed: true}
	_, err := b.SSHClient()
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("expected ErrClosed, got %v", err)
	}
}

func TestBlipNewSessionAfterClose(t *testing.T) {
	b := &Blip{closed: true}
	_, err := b.NewSession()
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("expected ErrClosed, got %v", err)
	}
}

func TestBlipRetainAfterClose(t *testing.T) {
	b := &Blip{closed: true}
	err := b.Retain(context.Background())
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("expected ErrClosed, got %v", err)
	}
}

func TestReconnectInvalidSessionID(t *testing.T) {
	c, err := NewClient("example.com", WithGitHubToken("tok"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Reconnect(context.Background(), "invalid-id")
	if !errors.Is(err, ErrInvalidSessionID) {
		t.Fatalf("expected ErrInvalidSessionID, got %v", err)
	}
}
