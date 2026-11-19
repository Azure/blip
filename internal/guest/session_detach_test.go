package guest

import (
	"net"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/Azure/blip/internal/wire"
)

// detachedProc is a real child process started in its own process group, as
// startProc does for an exec command. done closes when the process is reaped.
type detachedProc struct{ done chan struct{} }

// startDetachedSession registers a session running a real sleep process. Tests
// use it to observe whether a client disconnect terminates the command.
func startDetachedSession(t *testing.T, g *Guest, id string) (*detachedProc, *session) {
	t.Helper()
	cmd := exec.Command("/bin/sleep", "30")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()

	s := newSession(g, id, []string{"sleep", "30"}, false)
	s.proc = &proc{pid: cmd.Process.Pid}
	s.releasePumps()
	g.mu.Lock()
	g.sessions[id] = s
	g.mu.Unlock()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		s.closeInput()
	})
	return &detachedProc{done: done}, s
}

// attachDetachedClient serves one client and waits until want clients are
// registered on the session.
func attachDetachedClient(t *testing.T, s *session, want int) net.Conn {
	t.Helper()
	srv, cli := net.Pipe()
	go s.serve(wire.NewConn(srv), srv, false)
	waitFor(t, "clients to attach", func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.clients == want
	})
	return cli
}

// A client that goes away (pipeline closed by head, SIGKILL to the CLI) must
// not leave its exec command running, unreachable, in the guest. Once the last
// client detaches the guest terminates the process group.
func TestExecClientDetachKillsProcessGroup(t *testing.T) {
	g := testGuest(t)
	p, s := startDetachedSession(t, g, "detached-exec")

	first := attachDetachedClient(t, s, 1)
	second := attachDetachedClient(t, s, 2)
	first.Close()
	waitFor(t, "the first client to detach", func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.clients == 1
	})
	select {
	case <-p.done:
		t.Fatal("exec command was killed while another client was attached")
	case <-time.After(200 * time.Millisecond):
	}

	second.Close()
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		t.Fatal("exec command survived its last client disconnect")
	}
}

// A detached primary command is the normal `blip run -d` case and must keep
// running after its observer disconnects.
func TestPrimaryClientDetachKeepsCommand(t *testing.T) {
	g := testGuest(t)
	p, s := startDetachedSession(t, g, wire.PrimarySession)

	c := attachDetachedClient(t, s, 1)
	c.Close()
	select {
	case <-p.done:
		t.Fatal("primary command was killed when its client detached")
	case <-time.After(300 * time.Millisecond):
	}
}
