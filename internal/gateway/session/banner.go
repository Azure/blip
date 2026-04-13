package session

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const bannerSpacer = "\n\n\n-----------------------------------\n\n\n"

// crlf converts Unix newlines to CRLF for SSH terminal compatibility.
func crlf(s string) string {
	return strings.ReplaceAll(s, "\n", "\r\n")
}

// writeBanner writes a banner string to the SSH channel's stderr stream.
func writeBanner(ch ssh.Channel, banner string) {
	if _, err := ch.Stderr().Write([]byte(banner)); err != nil {
		slog.Debug("failed to write banner", "error", err)
	}
}

func welcomeBanner(reconnecting bool) string {
	status := ">>> Allocating blip..."
	if reconnecting {
		status = ">>> Reconnecting..."
	}
	banner := fmt.Sprintf(`
  ____  _ _
 | __ )| (_)_ __
 |  _ \| | | '_ \
 | |_) | | | |_) |
 |____/|_|_| .__/
            |_|

  %s
`, status)
	return crlf(banner)
}

func vmInfoBanner(sessionID, vmName, site string, reconnecting bool, ttl time.Duration) string {
	connMsg := ">>> Connected to gateway"
	if reconnecting {
		connMsg = ">>> Reconnected to gateway"
	}
	banner := fmt.Sprintf(`  %s
  Session : %s
  Blip    : %s
  Lease   : ephemeral (%s TTL)`, connMsg, sessionID, vmName, formatDuration(ttl))
	if site != "" {
		banner += fmt.Sprintf("\n  Site    : %s", site)
	}
	banner += fmt.Sprintf(`

  This blip is ephemeral and will be destroyed when you
  disconnect. Run 'blip retain' to preserve it.`)
	banner += bannerSpacer
	return crlf(banner)
}

// formatDuration produces a human-friendly duration string like "8h" or "2h30m".
func formatDuration(d time.Duration) string {
	d = d.Round(time.Minute)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h > 0 && m > 0 {
		return fmt.Sprintf("%dh%dm", h, m)
	}
	if h > 0 {
		return fmt.Sprintf("%dh", h)
	}
	return fmt.Sprintf("%dm", m)
}

func shutdownBanner() string {
	banner := `

-----------------------------------

  >>> Gateway is shutting down.
  >>> Your blip is still running.
  >>> Reconnect with your session ID.

-----------------------------------

`
	return crlf(banner)
}

func goodbyeBanner(sessionID string, ephemeral bool, remainingTTL time.Duration, gatewayHost string) string {
	banner := bannerSpacer
	banner += `  ____
 | __ ) _   _  ___
 |  _ \| | | |/ _ \
 | |_) | |_| |  __/
 |____/ \__, |\___|
        |___/

`
	if ephemeral {
		banner += "  >>> Blip terminated. This session was ephemeral.\n"
	} else if remainingTTL > 0 {
		banner += fmt.Sprintf("  >>> Disconnected. Blip retained for %s.\n", formatDuration(remainingTTL))
		if gatewayHost != "" {
			banner += fmt.Sprintf("  >>> Reconnect: ssh %s@%s\n", sessionID, gatewayHost)
		} else {
			banner += fmt.Sprintf("  >>> Reconnect: ssh %s@<gateway>\n", sessionID)
		}
	} else {
		banner += "  >>> Disconnected. Blip lease has expired.\n"
	}
	banner += "\n"
	return crlf(banner)
}

// allocErrorBanner returns the user-facing banner text for an allocation or reconnection failure.
func allocErrorBanner(reconnecting bool, err error) string {
	if reconnecting {
		return crlf("\n  >>> Reconnect failed: " + err.Error() + "\n\n")
	}
	return crlf("\n  >>> Blip allocation failed: " + err.Error() + "\n\n")
}

// hostKeyErrorBanner returns the user-facing banner text shown when the blip's
// host key cannot be retrieved.
func hostKeyErrorBanner() string {
	return crlf("\n  >>> Failed to verify blip identity\n\n")
}
