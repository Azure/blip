package session

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// CRLF conversion
// ---------------------------------------------------------------------------

func TestCRLF(t *testing.T) {
	assert.Equal(t, "a\r\nb\r\nc", crlf("a\nb\nc"))
	assert.Equal(t, "no newlines", crlf("no newlines"))
	assert.Equal(t, "\r\n\r\n", crlf("\n\n"))
	assert.Equal(t, "", crlf(""))
}

// ---------------------------------------------------------------------------
// Banner generation
// ---------------------------------------------------------------------------

func TestBanners(t *testing.T) {
	t.Run("welcome banner differentiates new vs reconnect", func(t *testing.T) {
		newBanner := welcomeBanner(false)
		reconnectBanner := welcomeBanner(true)

		assert.Contains(t, newBanner, "Allocating VM")
		assert.NotContains(t, newBanner, "Reconnecting")

		assert.Contains(t, reconnectBanner, "Reconnecting")
		assert.NotContains(t, reconnectBanner, "Allocating VM")

		for _, b := range []string{newBanner, reconnectBanner} {
			assert.Contains(t, b, "____")
			assert.Contains(t, b, "\r\n", "banner should use CRLF")
		}
	})

	t.Run("vmInfo banner includes session details", func(t *testing.T) {
		banner := vmInfoBanner("blip-abc1234567", "vm-test-01", "eastus2", false, 8*time.Hour)
		assert.Contains(t, banner, "blip-abc1234567")
		assert.Contains(t, banner, "vm-test-01")
		assert.Contains(t, banner, "eastus2")
		assert.Contains(t, banner, "Connected to gateway")
		assert.NotContains(t, banner, "Reconnected")
		assert.Contains(t, banner, "ephemeral")
		assert.Contains(t, banner, "blip retain")
		assert.Contains(t, banner, "8h")
	})

	t.Run("vmInfo banner reconnecting", func(t *testing.T) {
		banner := vmInfoBanner("blip-abc1234567", "vm-test-01", "", true, 30*time.Minute)
		assert.Contains(t, banner, "Reconnected to gateway")
		assert.NotContains(t, banner, "Site", "site line should be omitted when empty")
		assert.Contains(t, banner, "30m")
	})

	t.Run("shutdown banner", func(t *testing.T) {
		banner := shutdownBanner()
		assert.Contains(t, banner, "shutting down")
		assert.Contains(t, banner, "Reconnect")
		assert.Contains(t, banner, "\r\n")
	})
}

// ---------------------------------------------------------------------------
// writeBanner
// ---------------------------------------------------------------------------

func TestWriteBanner(t *testing.T) {
	ep := sshPipe(t)
	clientCh, serverCh := openAndAcceptChannel(t, ep)

	msg := "Hello from the gateway\r\n"
	writeBanner(serverCh, msg)

	buf := make([]byte, 256)
	n, err := clientCh.Stderr().Read(buf)
	require.NoError(t, err)
	assert.Equal(t, msg, string(buf[:n]))
}

func TestWriteBanner_ClosedChannel(t *testing.T) {
	ep := sshPipe(t)
	clientCh, serverCh := openAndAcceptChannel(t, ep)

	clientCh.Close()
	time.Sleep(10 * time.Millisecond)

	assert.NotPanics(t, func() {
		writeBanner(serverCh, "should not crash")
	})
}

// ---------------------------------------------------------------------------
// formatDuration
// ---------------------------------------------------------------------------

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name string
		d    time.Duration
		want string
	}{
		{"8 hours", 8 * time.Hour, "8h"},
		{"30 minutes", 30 * time.Minute, "30m"},
		{"2h30m", 2*time.Hour + 30*time.Minute, "2h30m"},
		{"0 minutes", 0, "0m"},
		{"1h1m", 1*time.Hour + 1*time.Minute, "1h1m"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, formatDuration(tt.d))
		})
	}
}
