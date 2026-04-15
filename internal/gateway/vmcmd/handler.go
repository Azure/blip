// Package vmcmd handles SSH exec commands from VMs back to the gateway.
//
// VMs use their SSH connection to the gateway to execute management commands
// (e.g. "blip retain", "blip register-keys") instead of calling the
// Kubernetes API directly. This eliminates the need for VMs to have any
// access to the API server or internal cluster network.
package vmcmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/project-unbounded/blip/internal/gateway/vm"
)

// Handler processes management commands from VMs received over SSH exec
// channels. Commands are authenticated via the VM's client key — the
// gateway resolves the key to a session and applies the operation.
type Handler struct {
	vmClient *vm.Client
}

// New creates a Handler backed by the given VM client.
func New(vmClient *vm.Client) *Handler {
	return &Handler{vmClient: vmClient}
}

// retainResponse is the JSON response sent back to the VM for a retain command.
type retainResponse struct {
	SessionID string `json:"session_id"`
	TTL       string `json:"ttl,omitempty"`
}

// registerResponse is the JSON response sent back to the VM for a register-keys command.
type registerResponse struct {
	OK bool `json:"ok"`
}

// sessionStatusResponse is the JSON response for a status command.
type sessionStatusResponse struct {
	SessionID    string `json:"session_id"`
	Ephemeral    bool   `json:"ephemeral"`
	RemainingTTL int    `json:"remaining_ttl_seconds"`
}

// HandleExec processes a "blip <subcommand>" exec request from a VM.
// The identity and sessionID are resolved from the VM's client key.
// Returns the response bytes and an exit status code.
func (h *Handler) HandleExec(ctx context.Context, command string, vmName string) ([]byte, int) {
	parts := strings.Fields(command)
	if len(parts) == 0 || parts[0] != "blip" {
		return []byte("unknown command\n"), 1
	}

	if len(parts) < 2 {
		return []byte("usage: blip <command>\n"), 1
	}

	subcmd := parts[1]
	args := parts[2:]

	switch subcmd {
	case "retain":
		return h.handleRetain(ctx, vmName, args)
	case "register-keys":
		return h.handleRegisterKeys(ctx, vmName, args)
	case "status":
		return h.handleStatus(ctx, vmName)
	default:
		return []byte(fmt.Sprintf("unknown command: blip %s\n", subcmd)), 1
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

	// Return the actual capped TTL (which may differ from the requested value
	// if it was capped by MaxLifespan) so the user sees what they actually got.
	resp := retainResponse{SessionID: retainedSessionID}
	if newTTLSeconds > 0 {
		// Fetch the remaining TTL from the VM annotations to show the actual
		// value after MaxLifespan capping, not the originally requested value.
		status, err := h.vmClient.GetSessionStatus(ctx, retainedSessionID)
		if err != nil {
			slog.Warn("retain succeeded but failed to fetch status for TTL",
				"session_id", retainedSessionID, "error", err)
			resp.TTL = "unknown"
		} else if status.RemainingTTL > 0 {
			resp.TTL = fmt.Sprintf("%ds", int(status.RemainingTTL.Seconds()))
		}
	}

	data, _ := json.Marshal(resp)
	data = append(data, '\n')
	return data, 0
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

	// Keys are transmitted in colon-joined format (e.g. "ssh-ed25519:AAAA...")
	// because the SSH exec protocol splits on spaces. Reconstruct the
	// standard space-separated format before validation.
	hostKey = strings.Replace(hostKey, ":", " ", 1)
	clientKey = strings.Replace(clientKey, ":", " ", 1)

	// Validate SSH public key format.
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

	resp := sessionStatusResponse{
		SessionID:    sessionID,
		Ephemeral:    status.Ephemeral,
		RemainingTTL: int(status.RemainingTTL.Seconds()),
	}

	data, _ := json.Marshal(resp)
	data = append(data, '\n')
	return data, 0
}

// parseDuration parses a Go-style duration string like "5m", "2h", "1h30m", "30s".
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
