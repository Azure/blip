package guest

import (
	"bytes"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

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

// startGroupLeaderSession starts script as the leader of a new process group,
// like startProc does for an exec command. The script gets a readiness path in
// $1 and must write it only once its background child is running and the
// leader has closed its inherited pipe. The child holds the write end of a
// pipe: childGone closes when the child dies, whether or not it has been
// reaped yet. leaderDone closes when the leader exits.
func startGroupLeaderSession(t *testing.T, g *Guest, id, script string) (leaderDone, childGone <-chan struct{}, s *session) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	ready := filepath.Join(t.TempDir(), "ready")
	cmd := exec.Command("/bin/sh", "-c", script, "sh", ready)
	// The child inherits fd 3. The leader closes it before writing ready, so
	// EOF on the read side means the child is gone.
	cmd.ExtraFiles = []*os.File{w}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		r.Close()
		w.Close()
		t.Fatal(err)
	}
	w.Close()

	s = newSession(g, id, []string{"sh", "-c", script}, false)
	s.proc = &proc{pid: cmd.Process.Pid}
	s.releasePumps()
	g.mu.Lock()
	g.sessions[id] = s
	g.mu.Unlock()

	leader := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(leader)
		s.finish(wire.Exit{Code: 0})
	}()
	gone := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, r)
		close(gone)
	}()

	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Process.Kill()
		r.Close()
		s.closeInput()
	})

	waitFor(t, "the group leader's child to be ready", func() bool {
		_, err := os.Stat(ready)
		return err == nil
	})
	return leader, gone, s
}

// A background child outlives the group leader when the leader exits on
// SIGTERM but the child ignores it. The detach SIGKILL must still reach the
// process group: gating it on the leader is the bug.
func TestDetachedExecKillsGroupAfterLeaderExit(t *testing.T) {
	g := testGuest(t)
	script := `trap 'exit 0' TERM
(trap '' TERM; exec sleep 30) &
exec 3>&-
echo ready > "$1"
wait`
	leaderDone, childGone, s := startGroupLeaderSession(t, g, "detached-grace", script)

	c := attachDetachedClient(t, s, 1)
	c.Close()
	select {
	case <-leaderDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the group leader did not exit after SIGTERM")
	}
	waitFor(t, "the session to record the leader's exit", func() bool {
		info := s.info()
		return info.Exited
	})
	select {
	case <-childGone:
	case <-time.After(5 * time.Second):
		t.Fatal("background child survived the detach grace period after its group leader exited")
	}
}

// A group leader can exit before the guest handles the client's disconnect.
// That must not suppress the detach cleanup either.
func TestDetachedExecKillsGroupAfterLeaderExitedBeforeDetach(t *testing.T) {
	g := testGuest(t)
	script := `(trap '' TERM; exec sleep 30) &
exec 3>&-
echo ready > "$1"
exit 0`
	leaderDone, childGone, s := startGroupLeaderSession(t, g, "detached-grace", script)

	c := attachDetachedClient(t, s, 1)
	select {
	case <-leaderDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the group leader did not exit")
	}
	waitFor(t, "the session to record the leader's exit", func() bool {
		info := s.info()
		return info.Exited
	})
	c.Close()
	select {
	case <-childGone:
	case <-time.After(5 * time.Second):
		t.Fatal("background child survived after its group leader exited before the client detached")
	}
}

// openThenFailConn serves one encoded frame and fails every write, so the
// guest's TOpened reply fails after the exec command has already started.
type openThenFailConn struct{ r io.Reader }

func (c *openThenFailConn) Read(p []byte) (int, error) { return c.r.Read(p) }
func (c *openThenFailConn) Write([]byte) (int, error)  { return 0, os.ErrClosed }
func (c *openThenFailConn) Close() error               { return nil }

func encodeOpen(t *testing.T, o wire.Open) []byte {
	t.Helper()
	var buf bytes.Buffer
	c := wire.NewConn(struct {
		io.Reader
		io.Writer
	}{strings.NewReader(""), &buf})
	if err := c.WriteJSON(wire.TOpen, o); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// An exec command whose TOpened reply cannot be written has no client and,
// with no OpenID, no possible retry. It must not keep running unreachable.
func TestExecOpenReplyFailureKillsCommand(t *testing.T) {
	g := testGuest(t)
	g.claim = &wire.Claim{ID: "root"}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", "-c", `trap '' TERM; exec sleep 30`)
	// Keep a pipe open in the command so the test sees it exit even when it is
	// killed and not reaped.
	cmd.ExtraFiles = []*os.File{w}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		r.Close()
		w.Close()
		t.Fatal(err)
	}
	w.Close()
	gone := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, r)
		close(gone)
	}()
	wait := make(chan unix.WaitStatus, 1)
	go func() {
		_ = cmd.Wait()
		wait <- unix.WaitStatus(0)
	}()

	devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	g.startProcess = func(spec procSpec, _ []string) (*proc, []string, error) {
		return &proc{pid: cmd.Process.Pid, wait: wait, stdin: devnull, stdout: devnull, stderr: devnull}, spec.argv, nil
	}
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Process.Kill()
		r.Close()
	})

	conn := &openThenFailConn{r: bytes.NewReader(encodeOpen(t, wire.Open{Mode: wire.OpenExec, Argv: []string{"sh"}}))}
	g.serveSession(conn)

	select {
	case <-gone:
	case <-time.After(5 * time.Second):
		t.Fatal("exec command survived a failed TOpened reply with no way to attach")
	}
}
