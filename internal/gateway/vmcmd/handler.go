// Package vmcmd handles SSH exec commands from VMs back to the gateway.
//
// VMs execute management commands (e.g. "retain", "register-keys") via SSH
// instead of calling the Kubernetes API directly, so VMs need no access to
// the API server or internal cluster network.
package vmcmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/project-unbounded/blip/internal/gateway/vm"
)

// Handler processes management commands from VMs received over SSH exec
// channels. Commands are authenticated via the VM's client key — the
// gateway resolves the key to a session and applies the operation.
type Handler struct {
	vmClient     *vm.Client
	externalHost string
}

// New creates a Handler backed by the given VM client.
// externalHost is the public gateway hostname shown in reconnect instructions.
func New(vmClient *vm.Client, externalHost string) *Handler {
	return &Handler{vmClient: vmClient, externalHost: externalHost}
}

// registerResponse is the JSON response for a register-keys command.
type registerResponse struct {
	OK bool `json:"ok"`
}

// HandleExec processes an exec request from a VM. Commands may be prefixed
// with "blip" (e.g. "blip retain") or bare (e.g. "retain").
// Returns the response bytes and an exit status code.
func (h *Handler) HandleExec(ctx context.Context, command string, vmName string) ([]byte, int) {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return []byte("usage: blip <command>\n"), 1
	}

	// Strip optional "blip" prefix for backward compatibility.
	if parts[0] == "blip" {
		parts = parts[1:]
	}
	if len(parts) == 0 {
		return []byte("usage: blip <command>\n"), 1
	}

	subcmd := parts[0]
	args := parts[1:]

	switch subcmd {
	case "retain":
		return h.handleRetain(ctx, vmName, args)
	case "register-keys":
		return h.handleRegisterKeys(ctx, vmName, args)
	case "status":
		return h.handleStatus(ctx, vmName)
	default:
		return []byte(fmt.Sprintf("unknown command: %s\n", subcmd)), 1
	}
}

func (h *Handler) handleRetain(ctx context.Context, vmName string, args []string) ([]byte, int) {
	sessionID := h.vmClient.GetSessionIDByVMName(ctx, vmName)
	if sessionID == "" {
		return []byte("error: no active session for this VM\n"), 1
	}

	var newTTLSeconds int
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--ttl" && i+1 < len(args):
			secs, err := parseDuration(args[i+1])
			if err != nil {
				return []byte(fmt.Sprintf("error: invalid --ttl: %s\n", err)), 1
			}
			newTTLSeconds = secs
			i++
		case strings.HasPrefix(args[i], "--ttl="):
			secs, err := parseDuration(strings.TrimPrefix(args[i], "--ttl="))
			if err != nil {
				return []byte(fmt.Sprintf("error: invalid --ttl: %s\n", err)), 1
			}
			newTTLSeconds = secs
		default:
			return []byte(fmt.Sprintf("error: unknown argument: %s\n", args[i])), 1
		}
	}

	retainedSessionID, err := h.vmClient.Retain(ctx, sessionID, newTTLSeconds)
	if err != nil {
		slog.Error("retain failed", "session_id", sessionID, "vm_name", vmName, "error", err)
		return []byte(fmt.Sprintf("error: %s\n", err)), 1
	}

	// Build human-readable output with reconnect instructions.
	var out strings.Builder
	out.WriteString("Blip retained successfully.\n\n")

	reconnectHost := h.externalHost
	if reconnectHost == "" {
		reconnectHost = "<gateway>"
	}
	fmt.Fprintf(&out, "  Reconnect: ssh %s@%s\n", retainedSessionID, reconnectHost)

	if newTTLSeconds > 0 {
		status, err := h.vmClient.GetSessionStatus(ctx, retainedSessionID)
		if err != nil {
			slog.Warn("retain succeeded but failed to fetch status for TTL",
				"session_id", retainedSessionID, "error", err)
		} else if status.RemainingTTL > 0 {
			fmt.Fprintf(&out, "  TTL: %s\n", formatDuration(status.RemainingTTL))
		}
	}

	out.WriteString("\n")
	return []byte(out.String()), 0
}

func (h *Handler) handleRegisterKeys(ctx context.Context, vmName string, args []string) ([]byte, int) {
	var hostKey, clientKey string
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--host-key" && i+1 < len(args):
			hostKey = args[i+1]
			i++
		case args[i] == "--client-key" && i+1 < len(args):
			clientKey = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--host-key="):
			hostKey = strings.TrimPrefix(args[i], "--host-key=")
		case strings.HasPrefix(args[i], "--client-key="):
			clientKey = strings.TrimPrefix(args[i], "--client-key=")
		default:
			return []byte(fmt.Sprintf("error: unknown argument: %s\n", args[i])), 1
		}
	}

	if hostKey == "" || clientKey == "" {
		return []byte("error: --host-key and --client-key are required\n"), 1
	}

	// Keys are transmitted colon-joined (e.g. "ssh-ed25519:AAAA...") because
	// the SSH exec protocol splits on spaces.
	hostKey = strings.Replace(hostKey, ":", " ", 1)
	clientKey = strings.Replace(clientKey, ":", " ", 1)

	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hostKey)); err != nil {
		return []byte(fmt.Sprintf("error: invalid host key: %s\n", err)), 1
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(clientKey)); err != nil {
		return []byte(fmt.Sprintf("error: invalid client key: %s\n", err)), 1
	}

	if err := h.vmClient.RegisterKeys(ctx, vmName, hostKey, clientKey); err != nil {
		slog.Error("register-keys failed", "vm_name", vmName, "error", err)
		return []byte(fmt.Sprintf("error: %s\n", err)), 1
	}

	slog.Info("vm keys registered via SSH", "vm_name", vmName)

	data, _ := json.Marshal(registerResponse{OK: true})
	data = append(data, '\n')
	return data, 0
}

func (h *Handler) handleStatus(ctx context.Context, vmName string) ([]byte, int) {
	sessionID := h.vmClient.GetSessionIDByVMName(ctx, vmName)
	if sessionID == "" {
		return []byte("error: no active session for this VM\n"), 1
	}

	status, err := h.vmClient.GetSessionStatus(ctx, sessionID)
	if err != nil {
		return []byte(fmt.Sprintf("error: %s\n", err)), 1
	}

	var out strings.Builder
	fmt.Fprintf(&out, "Session: %s\n", sessionID)
	if status.Ephemeral {
		out.WriteString("Mode:    ephemeral\n")
	} else {
		out.WriteString("Mode:    retained\n")
	}
	if status.RemainingTTL > 0 {
		fmt.Fprintf(&out, "TTL:     %s\n", formatDuration(status.RemainingTTL))
	}
	return []byte(out.String()), 0
}

// formatDuration returns a compact human-readable duration string.
func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60

	switch {
	case h > 0 && m > 0:
		return fmt.Sprintf("%dh%dm", h, m)
	case h > 0:
		return fmt.Sprintf("%dh", h)
	case m > 0 && s > 0:
		return fmt.Sprintf("%dm%ds", m, s)
	case m > 0:
		return fmt.Sprintf("%dm", m)
	default:
		return fmt.Sprintf("%ds", s)
	}
}

// parseDuration parses a duration string like "5m", "2h", "1h30m", "30s".
func parseDuration(s string) (int, error) {
	total := 0
	current := ""

	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
			current += string(c)
		case c == 'h':
			if current == "" {
				return 0, fmt.Errorf("missing number before 'h'")
			}
			n, err := strconv.Atoi(current)
			if err != nil {
				return 0, fmt.Errorf("invalid number %q: %w", current, err)
			}
			total += n * 3600
			current = ""
		case c == 'm':
			if current == "" {
				return 0, fmt.Errorf("missing number before 'm'")
			}
			n, err := strconv.Atoi(current)
			if err != nil {
				return 0, fmt.Errorf("invalid number %q: %w", current, err)
			}
			total += n * 60
			current = ""
		case c == 's':
			if current == "" {
				return 0, fmt.Errorf("missing number before 's'")
			}
			n, err := strconv.Atoi(current)
			if err != nil {
				return 0, fmt.Errorf("invalid number %q: %w", current, err)
			}
			total += n
			current = ""
		default:
			return 0, fmt.Errorf("unexpected character %q", c)
		}
	}

	if current != "" {
		return 0, fmt.Errorf("missing unit suffix (use h, m, or s)")
	}
	if total == 0 {
		return 0, fmt.Errorf("duration must be > 0")
	}

	return total, nil
}
