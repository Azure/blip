// Package wire is the framed protocol between the host and the guest init
// over virtio-vsock. Every message is one frame:
//
//	[1 byte type][4 byte big-endian length][payload]
//
// Data frames (Stdin, Stdout, Stderr) carry raw bytes. All other frames carry
// one JSON object. There are two guest ports:
//
//   - ControlPort: the in-pod runtime only (claim, mounts, shutdown).
//   - SessionPort: command and exec sessions.
//
// APIPort is a host listener for credential-free Kubernetes API streams from
// the guest. The runtime authenticates those requests on the host side.
//
// GatewayPort is a host listener for streams from the guest to a configured
// cluster gateway. The sidecar adds the gateway credential on the host side.
//
// The guest accepts connections only from the host CID (2). Anyone who can
// reach the Cloud Hypervisor vsock socket already controls the VM, so there
// is no further authentication.
package wire

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	Version            = 1
	ControlPort        = 1024
	SessionPort        = 1025
	APIPort     uint32 = 1026
	GatewayPort uint32 = 1027
	// MaxFrame bounds one frame payload.
	MaxFrame = 1 << 20
)

type Type byte

const (
	// Control: guest -> host
	THello         Type = 1 // Hello
	TClaimResult   Type = 2 // Result
	TMountResult   Type = 3 // Result
	TUnmountResult Type = 4 // Result
	TStatus        Type = 5 // Status
	TExit          Type = 6 // Exit: primary command exited; guest is shutting down
	TShutdownDone  Type = 7 // ShutdownDone: sent right before power off
	TFreezeResult  Type = 8 // FreezeResult: answers Freeze and Thaw, or reports a timed-out thaw

	// Control: host -> guest
	TClaim    Type = 20 // Claim
	TMount    Type = 21 // Mount
	TUnmount  Type = 22 // Unmount
	TShutdown Type = 24 // Shutdown
	TFreeze   Type = 25 // Freeze
	TThaw     Type = 26 // Freeze
	// 27 is reserved for the removed service account token message.

	// Session
	TOpen     Type = 40 // client -> guest: Open
	TOpened   Type = 41 // guest -> client: Opened
	TStdin    Type = 42 // client -> guest: raw bytes
	TStdinEOF Type = 43 // client -> guest: {}
	TResize   Type = 44 // client -> guest: Resize
	TSignal   Type = 45 // client -> guest: Signal
	TStdout   Type = 46 // guest -> client: raw bytes
	TStderr   Type = 47 // guest -> client: raw bytes
	TExited   Type = 48 // guest -> client: Exit
	TNotice   Type = 49 // guest -> client: Notice (e.g. replay gap)
)

// ---- control payloads ----

type Hello struct {
	Version int `json:"version"`
	// ClaimID is the accepted claim's root disk ID, if any. A runtime that
	// reconnects uses Hello to resynchronize.
	ClaimID string   `json:"claimID,omitempty"`
	Mounts  []string `json:"mounts,omitempty"` // IDs of mounted disks
	Frozen  []string `json:"frozen,omitempty"` // IDs of frozen disks
	Exit    *Exit    `json:"exit,omitempty"`
}

type Claim struct {
	ID         string   `json:"id"`     // root disk ID
	Serial     string   `json:"serial"` // root disk serial
	Hostname   string   `json:"hostname"`
	Command    []string `json:"command,omitempty"`
	TTY        bool     `json:"tty,omitempty"`
	Env        []string `json:"env,omitempty"`
	WorkingDir string   `json:"workingDir,omitempty"`
	User       string   `json:"user,omitempty"`
	// WaitForClient asks the guest to hold the command's output until a
	// client attaches. Without it the pumps start immediately, so a fast
	// command can overflow the replay ring before the caller connects.
	WaitForClient bool `json:"waitForClient,omitempty"`
	// Mounts are mounted before Command starts. The guest answers each with
	// a TMountResult; if one fails, Command does not run.
	Mounts []Mount `json:"mounts,omitempty"`
}

type Mount struct {
	ID       string `json:"id"`
	Serial   string `json:"serial"`
	Path     string `json:"path"`
	ReadOnly bool   `json:"readOnly,omitempty"`
}

type Unmount struct {
	ID string `json:"id"`
}

// Freeze names a disk (the claim ID or a mount ID) whose filesystem is
// frozen (TFreeze) or thawed (TThaw). The guest bounds the freeze with an
// automatic thaw timeout.
type Freeze struct {
	ID string `json:"id"`
}

// FreezeResult reports whether disk ID is frozen now.
type FreezeResult struct {
	ID     string `json:"id"`
	Frozen bool   `json:"frozen"`
	Error  string `json:"error,omitempty"`
}

type Shutdown struct {
	Reason string `json:"reason,omitempty"`
}

// Result answers Claim, Mount and Unmount. Error is empty on success.
type Result struct {
	ID    string `json:"id"`
	Error string `json:"error,omitempty"`
}

type Status struct {
	Sessions int `json:"sessions"`
}

// Exit reasons shared by the guest, the runtime, and their clients. The
// controller compares the same strings when it interprets Blip status.
const (
	// ReasonCompleted marks a primary command that finished on its own.
	ReasonCompleted = "Completed"
	// ReasonStopped marks a session ended because the VM is shutting down.
	ReasonStopped = "Stopped"
	// ReasonGuestCrashed marks a VM that exited without a shutdown request.
	ReasonGuestCrashed = "GuestCrashed"
)

type Exit struct {
	Code   int    `json:"code"`
	Signal string `json:"signal,omitempty"`
	Reason string `json:"reason,omitempty"`
	// Output is the end of the command's output when it failed.
	Output string `json:"output,omitempty"`
}

type ShutdownDone struct {
	// Clean is true when every filesystem unmounted cleanly.
	Clean bool   `json:"clean"`
	Error string `json:"error,omitempty"`
}

// ---- session payloads ----

const (
	// OpenExec starts a new session.
	OpenExec = "exec"
	// OpenAttach joins an existing session (Session empty = primary).
	OpenAttach = "attach"
)

// PrimarySession is the ID of the claim's primary command session.
const PrimarySession = "main"

type Open struct {
	Mode       string   `json:"mode"`
	Session    string   `json:"session,omitempty"`
	Argv       []string `json:"argv,omitempty"` // empty = login shell
	Env        []string `json:"env,omitempty"`
	WorkingDir string   `json:"workingDir,omitempty"`
	User       string   `json:"user,omitempty"`
	TTY        bool     `json:"tty,omitempty"`
	Rows       uint16   `json:"rows,omitempty"`
	Cols       uint16   `json:"cols,omitempty"`
	// OpenID identifies one logical exec/attach attempt. A client that
	// retries after a transport failure reuses it so the guest can attach to
	// a session it may already have started instead of running the command
	// twice. Old clients leave it empty, which preserves the old behavior.
	OpenID string `json:"openID,omitempty"`
	// Follow tails the session without holding it open: the client receives
	// retained output but never pins the replay ring or blocks the command.
	Follow bool `json:"follow,omitempty"`
}

type Opened struct {
	Session string `json:"session,omitempty"`
	TTY     bool   `json:"tty,omitempty"`
	Error   string `json:"error,omitempty"`
}

type Resize struct {
	Rows uint16 `json:"rows"`
	Cols uint16 `json:"cols"`
}

type Signal struct {
	Name string `json:"name"` // e.g. "HUP", "INT", "TERM", "KILL"
}

type Notice struct {
	Message string `json:"message"`
}

// ---- codec ----

// Conn frames a stream. Writes are safe for concurrent use; reads are not.
type Conn struct {
	rw   io.ReadWriter
	br   *bufio.Reader
	mu   sync.Mutex
	werr error // a failed frame write makes further framing unsafe
}

func NewConn(rw io.ReadWriter) *Conn {
	return &Conn{rw: rw, br: bufio.NewReaderSize(rw, 64<<10)}
}

// Write sends one frame with a raw payload.
func (c *Conn) Write(t Type, payload []byte) error {
	if len(payload) > MaxFrame {
		return fmt.Errorf("frame too large: %d", len(payload))
	}
	var hdr [5]byte
	hdr[0] = byte(t)
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(payload)))
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.werr != nil {
		return c.werr
	}
	n, err := c.rw.Write(append(hdr[:], payload...))
	if err == nil && n != len(hdr)+len(payload) {
		err = io.ErrShortWrite
	}
	c.werr = err
	return err
}

// WriteJSON sends one frame with v encoded as JSON.
func (c *Conn) WriteJSON(t Type, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.Write(t, data)
}

// Read returns the next frame. The payload is a fresh slice.
func (c *Conn) Read() (Type, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	if n > MaxFrame {
		return 0, nil, fmt.Errorf("frame too large: %d", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(c.br, payload); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return 0, nil, err
	}
	return Type(hdr[0]), payload, nil
}

// Decode unmarshals a control payload, which must be a JSON object. Empty or
// null payloads must not silently turn into zero-valued success/exit results.
func Decode(payload []byte, v any) error {
	payload = bytes.TrimSpace(payload)
	if len(payload) == 0 || payload[0] != '{' {
		return errors.New("expected a JSON object")
	}
	return json.Unmarshal(payload, v)
}

// DialVsock connects to a guest port through a Cloud Hypervisor vsock unix
// socket using its "CONNECT <port>" handshake.
func DialVsock(socketPath string, port uint32, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("unix", socketPath, timeout)
	if err != nil {
		return nil, err
	}
	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %d\n", port); err != nil {
		conn.Close()
		return nil, err
	}
	// Read the "OK <port>\n" reply one byte at a time so no stream data is
	// buffered away from the caller.
	var line []byte
	var b [1]byte
	for len(line) < 64 {
		if _, err := conn.Read(b[:]); err != nil {
			conn.Close()
			return nil, fmt.Errorf("vsock handshake: %w", err)
		}
		if b[0] == '\n' {
			break
		}
		line = append(line, b[0])
	}
	if !strings.HasPrefix(string(line), "OK ") {
		conn.Close()
		return nil, fmt.Errorf("vsock handshake: unexpected reply %q", line)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}
