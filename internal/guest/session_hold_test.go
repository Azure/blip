package guest

import (
	"bytes"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Azure/blip/internal/wire"
)

// fakePrimary starts a primary command whose output is the returned pipe's
// write end. Tests run outside the guest and cannot chroot, so startPrimary
// uses this instead of starting a real workload.
func fakePrimary(t *testing.T, g *Guest) (*os.File, chan unix.WaitStatus) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	wait := make(chan unix.WaitStatus, 1)
	g.startProcess = func(s procSpec, base []string) (*proc, []string, error) {
		return &proc{wait: wait, tty: r}, s.argv, nil
	}
	t.Cleanup(func() {
		w.Close()
		r.Close()
		select {
		case wait <- unix.WaitStatus(0):
		default:
		}
		// Never leave a pump blocked on a release that will not come.
		g.mu.Lock()
		for _, s := range g.sessions {
			s.releasePumps()
		}
		g.mu.Unlock()
	})
	return w, wait
}

func primarySession(t *testing.T, g *Guest) *session {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	s := g.sessions[wire.PrimarySession]
	if s == nil {
		t.Fatal("primary session is not registered")
	}
	return s
}

// started reports whether the session's output pumps were released.
func started(s *session) bool {
	select {
	case <-s.pumpsReady:
		return true
	default:
		return false
	}
}

// A primary command that expects a client must not pump output before the
// client attaches: a burst larger than the replay ring would otherwise be
// trimmed (and silently lost) during the attach handshake.
func TestPrimaryHoldsOutputUntilClientAttaches(t *testing.T) {
	g := testGuest(t)
	out, wait := fakePrimary(t, g)
	g.claim = &wire.Claim{ID: "root", Command: []string{"seq"}, WaitForClient: true}
	g.startPrimary()
	s := primarySession(t, g)
	if started(s) {
		t.Fatal("output pumps started before a client attached")
	}

	chunk := bytes.Repeat([]byte("0123456789abcdef\n"), 1024)
	chunks := (2<<20 + len(chunk) - 1) / len(chunk)
	total := chunks * len(chunk)
	go func() {
		for range chunks {
			if _, err := out.Write(chunk); err != nil {
				return
			}
		}
		out.Close()
		wait <- unix.WaitStatus(0)
	}()
	time.Sleep(100 * time.Millisecond)
	s.mu.Lock()
	frames := len(s.out.frames)
	s.mu.Unlock()
	if frames != 0 {
		t.Fatalf("%d output frames were pumped before the client attached", frames)
	}

	got, ex := attachAndRead(t, s)
	if len(got) != total {
		t.Fatalf("client received %d bytes, want %d", len(got), total)
	}
	if ex.Code != 0 {
		t.Fatalf("exit code = %d, want 0", ex.Code)
	}
}

// Without WaitForClient the command starts immediately, as detached runs rely
// on, and its early output is recorded for a late caller.
func TestPrimaryStartsWithPumpsWithoutWaitForClient(t *testing.T) {
	g := testGuest(t)
	out, _ := fakePrimary(t, g)
	g.claim = &wire.Claim{ID: "root", Command: []string{"seq"}}
	g.startPrimary()
	s := primarySession(t, g)
	if !started(s) {
		t.Fatal("output pumps were held without WaitForClient")
	}
	if _, err := out.Write([]byte("early\n")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.Lock()
		frames := len(s.out.frames)
		s.mu.Unlock()
		if frames > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("early output was not pumped without a client")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A caller that never arrives must not keep the command blocked on its output
// pipe forever.
func TestPrimaryPumpHoldFallback(t *testing.T) {
	old := waitForClientTimeout
	waitForClientTimeout = 100 * time.Millisecond
	t.Cleanup(func() { waitForClientTimeout = old })

	g := testGuest(t)
	fakePrimary(t, g)
	g.claim = &wire.Claim{ID: "root", Command: []string{"seq"}, WaitForClient: true}
	g.startPrimary()
	s := primarySession(t, g)
	select {
	case <-s.pumpsReady:
	case <-time.After(3 * time.Second):
		t.Fatal("pumps stayed held after the fallback timeout")
	}
}

// Shutdown must release held pumps so a terminating process cannot stay
// blocked writing output.
func TestShutdownReleasesHeldPumps(t *testing.T) {
	old := waitForClientTimeout
	waitForClientTimeout = time.Hour
	t.Cleanup(func() { waitForClientTimeout = old })

	g := testGuest(t)
	fakePrimary(t, g)
	g.claim = &wire.Claim{ID: "root", Command: []string{"seq"}, WaitForClient: true}
	g.startPrimary()
	s := primarySession(t, g)
	if started(s) {
		t.Fatal("output pumps started before a client attached")
	}
	g.shutdown()
	if !started(s) {
		t.Fatal("shutdown did not release held pumps")
	}
}
