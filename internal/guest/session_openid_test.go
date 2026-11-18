package guest

import (
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Azure/blip/internal/wire"
)

// fakeExecProcs replaces startProcess with pipes whose exit the test controls
// and counts how many times an exec actually started a process.
type fakeExecProcs struct {
	g      *Guest
	starts atomic.Int32

	mu    sync.Mutex
	outs  []*os.File
	waits []chan unix.WaitStatus
}

func newFakeExecProcs(t *testing.T, g *Guest) *fakeExecProcs {
	t.Helper()
	f := &fakeExecProcs{g: g}
	g.startProcess = func(s procSpec, base []string) (*proc, []string, error) {
		r, w, err := os.Pipe()
		if err != nil {
			return nil, nil, err
		}
		wait := make(chan unix.WaitStatus, 1)
		f.mu.Lock()
		f.outs = append(f.outs, w)
		f.waits = append(f.waits, wait)
		f.mu.Unlock()
		f.starts.Add(1)
		return &proc{wait: wait, tty: r}, s.argv, nil
	}
	t.Cleanup(f.finish)
	return f
}

func (f *fakeExecProcs) out(i int) *os.File {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.outs[i]
}

func (f *fakeExecProcs) wait(i int) chan unix.WaitStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.waits[i]
}

// finish closes every output pipe, reports exit, and releases any pumps still
// held so the session goroutines cannot outlive the test.
func (f *fakeExecProcs) finish() {
	f.mu.Lock()
	outs := append([]*os.File(nil), f.outs...)
	waits := append([]chan unix.WaitStatus(nil), f.waits...)
	f.mu.Unlock()
	for _, w := range outs {
		w.Close()
	}
	for _, wait := range waits {
		select {
		case wait <- unix.WaitStatus(0):
		default:
		}
	}
	f.g.mu.Lock()
	for _, s := range f.g.sessions {
		s.releasePumps()
	}
	f.g.mu.Unlock()
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// execConn keeps the client side of one session connection so tests can close
// it and detach from the guest.
type execConn struct {
	*wire.Conn
	f *os.File
}

func (e *execConn) Close() error { return e.f.Close() }

// openExecConn sends one exec open and returns the decoded answer.
func openExecConn(t *testing.T, g *Guest, openID string) (*execConn, wire.Opened) {
	t.Helper()
	srv, cli := sessionPair(t)
	_ = cli.SetDeadline(time.Now().Add(10 * time.Second))
	go g.serveSession(srv)
	c := wire.NewConn(cli)
	if err := c.WriteJSON(wire.TOpen, wire.Open{Mode: wire.OpenExec, Argv: []string{"sh"}, OpenID: openID}); err != nil {
		t.Fatal(err)
	}
	typ, payload, err := c.Read()
	if err != nil {
		t.Fatalf("read opened: %v", err)
	}
	var o wire.Opened
	if err := wire.Decode(payload, &o); typ != wire.TOpened || err != nil {
		t.Fatalf("open answered with frame %d, %v", typ, err)
	}
	return &execConn{Conn: c, f: cli}, o
}

func sessionForOpenID(g *Guest, openID string) *session {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, s := range g.sessions {
		if s.openID == openID {
			return s
		}
	}
	return nil
}

// A retry after the guest received TOpen but the client never saw TOpened
// must attach to the first session (including its replay), not start the
// command again. Once that session is gone, a third retry must not rerun it.
func TestExecOpenIDDeduplicatesRetries(t *testing.T) {
	g := testGuest(t)
	g.claim = &wire.Claim{ID: "root"}
	procs := newFakeExecProcs(t, g)

	const openID = "exec-open-1"

	// First attempt: the guest gets TOpen, but the client goes away before it
	// can read TOpened.
	firstSrv, firstCli := sessionPair(t)
	_ = firstCli.SetDeadline(time.Now().Add(5 * time.Second))
	go g.serveSession(firstSrv)
	if err := wire.NewConn(firstCli).WriteJSON(wire.TOpen, wire.Open{Mode: wire.OpenExec, Argv: []string{"sh"}, OpenID: openID}); err != nil {
		t.Fatal(err)
	}
	firstCli.Close()

	var first *session
	waitFor(t, "the first exec session", func() bool {
		first = sessionForOpenID(g, openID)
		return first != nil
	})
	id := first.id
	waitFor(t, "the first session's pumps", func() bool {
		select {
		case <-first.pumpsReady:
			return true
		default:
			return false
		}
	})
	if n := procs.starts.Load(); n != 1 {
		t.Fatalf("first open started %d processes, want 1", n)
	}

	// Output produced before the retry attaches must be replayed, not lost.
	if _, err := procs.out(0).Write([]byte("hello\n")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "output in the replay ring", func() bool {
		first.mu.Lock()
		defer first.mu.Unlock()
		return first.out.next() > 0
	})

	// Second attempt with the same ID attaches to the first session.
	c2, opened := openExecConn(t, g, openID)
	if opened.Error != "" {
		t.Fatalf("retry failed: %s", opened.Error)
	}
	if opened.Session != id {
		t.Fatalf("retry attached to session %q, want %q", opened.Session, id)
	}
	var replay strings.Builder
	for replay.String() != "hello\n" {
		typ, payload, err := c2.Read()
		if err != nil {
			t.Fatalf("read replay: %v", err)
		}
		if typ != wire.TStdout {
			t.Fatalf("replay = frame %d %q, want stdout", typ, payload)
		}
		replay.Write(payload)
	}
	if n := procs.starts.Load(); n != 1 {
		t.Fatalf("retry started %d processes, want 1 total", n)
	}

	// Let the command finish and be removed.
	procs.out(0).Close()
	procs.wait(0) <- unix.WaitStatus(0)
	var output strings.Builder
	output.WriteString(replay.String())
	for {
		typ, payload, err := c2.Read()
		if err != nil {
			t.Fatalf("read exit: %v", err)
		}
		if typ == wire.TStdout {
			output.Write(payload)
			continue
		}
		if typ != wire.TExited {
			t.Fatalf("frame %d, want exit status", typ)
		}
		break
	}
	if got := output.String(); got != "hello\n" {
		t.Fatalf("output = %q, want exactly one copy of %q", got, "hello\n")
	}
	c2.Close()
	waitFor(t, "the completed session to leave the list", func() bool {
		g.mu.Lock()
		defer g.mu.Unlock()
		return g.sessions[id] == nil
	})

	// A third retry after removal must report completion, not start again.
	_, opened = openExecConn(t, g, openID)
	if !strings.Contains(opened.Error, "already completed") {
		t.Fatalf("retry after exit = %q, want a completion error", opened.Error)
	}
	if n := procs.starts.Load(); n != 1 {
		t.Fatalf("third open started %d processes, want 1 total", n)
	}
}

// Clients that do not send an OpenID keep the old behavior: every open starts
// its own process.
func TestExecWithoutOpenIDStartsEveryTime(t *testing.T) {
	g := testGuest(t)
	g.claim = &wire.Claim{ID: "root"}
	procs := newFakeExecProcs(t, g)

	var ids []string
	for range 2 {
		_, opened := openExecConn(t, g, "")
		if opened.Error != "" {
			t.Fatalf("open failed: %s", opened.Error)
		}
		ids = append(ids, opened.Session)
	}
	if len(ids) != 2 || ids[0] == ids[1] {
		t.Fatalf("session ids = %v, want two distinct sessions", ids)
	}
	if n := procs.starts.Load(); n != 2 {
		t.Fatalf("empty OpenID started %d processes, want 2", n)
	}
}
