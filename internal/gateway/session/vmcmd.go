package session

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net"

	"golang.org/x/crypto/ssh"

	"github.com/project-unbounded/blip/internal/gateway/auth"
	"github.com/project-unbounded/blip/internal/gateway/vmcmd"
)

// VMCommandUser is the SSH username used by VMs to execute management
// commands (e.g. "blip retain") without allocating a new session.
const VMCommandUser = "_blip"

// VMRegisterUser is the SSH username used by VMs to register their
// host/client keys during boot, before a session is assigned.
const VMRegisterUser = "_register"

// IsVMCommandConnection reports whether the SSH connection is a VM
// management command (as opposed to a regular or recursive session).
func IsVMCommandConnection(conn *ssh.ServerConn) bool {
	return conn.User() == VMCommandUser || conn.User() == VMRegisterUser
}

// HandleVMCommand processes an SSH connection from a VM executing a
// management command. It reads the exec request from the session channel,
// dispatches it to the vmcmd handler, and returns the result.
func (m *Manager) HandleVMCommand(ctx context.Context, serverConn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
	remoteAddr := serverConn.RemoteAddr().String()

	// Discard global requests.
	go ssh.DiscardRequests(reqs)

	// Resolve the VM name from the connection context.
	vmName := m.resolveVMName(ctx, serverConn)
	if vmName == "" {
		slog.Warn("vm command: could not resolve VM name",
			"remote", remoteAddr,
			"user", serverConn.User(),
		)
		serverConn.Close()
		return
	}

	handler := vmcmd.New(m.cfg.VMClient, m.cfg.ExternalHost, m.cfg.TokenReviewer)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			newChan.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}

		ch, channelReqs, err := newChan.Accept()
		if err != nil {
			slog.Debug("vm command: failed to accept channel", "error", err)
			continue
		}

		go m.handleVMCommandChannel(ctx, ch, channelReqs, handler, vmName, remoteAddr)
	}
}

func (m *Manager) handleVMCommandChannel(ctx context.Context, ch ssh.Channel, reqs <-chan *ssh.Request, handler *vmcmd.Handler, vmName, remoteAddr string) {
	defer ch.Close()

	for req := range reqs {
		if req.Type != "exec" {
			if req.WantReply {
				req.Reply(false, nil)
			}
			continue
		}

		// Parse the exec payload: uint32 length + command string.
		if len(req.Payload) < 4 {
			if req.WantReply {
				req.Reply(false, nil)
			}
			continue
		}
		cmdLen := binary.BigEndian.Uint32(req.Payload[:4])
		if int(cmdLen) > len(req.Payload)-4 {
			if req.WantReply {
				req.Reply(false, nil)
			}
			continue
		}
		command := string(req.Payload[4 : 4+cmdLen])

		slog.Info("vm command: exec",
			"remote", remoteAddr,
			"vm_name", vmName,
			"command", command,
		)

		if req.WantReply {
			req.Reply(true, nil)
		}

		// Execute the command.
		output, exitCode := handler.HandleExec(ctx, command, vmName)
		if _, err := ch.Write(output); err != nil {
			slog.Debug("vm command: failed to write response",
				"vm_name", vmName,
				"error", err,
			)
		}

		// Send exit-status.
		exitPayload := make([]byte, 4)
		binary.BigEndian.PutUint32(exitPayload, uint32(exitCode))
		ch.SendRequest("exit-status", false, exitPayload)

		return
	}
}

// resolveVMName determines the VM name for a VM command connection.
// For _register connections, the VM name is first checked in the auth
// extensions (set by SA token validation during the SSH handshake when
// the token is bound to a pod). If not present (e.g. when using an
// unbound token), the VM name will be resolved later from the exec
// command's --vm-name flag.
// For _blip connections (VM client key auth), the VM is identified by
// its source IP address.
func (m *Manager) resolveVMName(ctx context.Context, conn *ssh.ServerConn) string {
	// For _register connections, the token reviewer may have set the VM name.
	// If not (unbound token), return a sentinel so the handler can extract
	// the VM name from the exec command's --vm-name flag.
	if conn.User() == VMRegisterUser {
		if conn.Permissions != nil && conn.Permissions.Extensions != nil {
			if vmName := conn.Permissions.Extensions[auth.ExtVMName]; vmName != "" {
				return vmName
			}
		}
		// Return a sentinel value — the actual VM name will be provided in
		// the register-keys command via --vm-name.
		return "_pending"
	}

	// For _blip connections, resolve by source IP.
	remoteAddr := conn.RemoteAddr().String()
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}

	vmName := m.cfg.VMClient.ResolveVMNameByIP(ctx, host)
	if vmName != "" {
		return vmName
	}

	// Fallback: check auth extensions for VM client key auth.
	if conn.Permissions != nil && conn.Permissions.Extensions != nil {
		if conn.Permissions.Extensions[auth.ExtIsVMClient] == "true" {
			slog.Debug("vm command: VM client key auth but IP lookup failed",
				"remote", remoteAddr,
			)
		}
	}

	return ""
}
