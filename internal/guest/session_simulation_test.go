package guest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"

	sessionclient "github.com/Azure/blip/internal/session"
	"github.com/Azure/blip/internal/wire"
	"golang.org/x/sys/unix"
)

// Only process creation is substituted. The real open deduplication, process
// completion, replay, input, attach/detach, client, and wire paths run in the
// synctest bubble. Nil OS descriptors behave as closed pipes; output events
// enter appendOutput, the same backpressure path called by the OS read pump.
func lifecycleGuest(t *testing.T) (*Guest, *[]chan unix.WaitStatus) {
	t.Helper()
	g := &Guest{
		claim: &wire.Claim{ID: "root"}, sessions: map[string]*session{},
		openIDs: map[string]*openRecord{},
	}
	var waits []chan unix.WaitStatus
	g.startProcess = func(spec procSpec, _ []string) (*proc, []string, error) {
		wait := make(chan unix.WaitStatus, 1)
		waits = append(waits, wait)
		return &proc{wait: wait}, spec.argv, nil
	}
	t.Cleanup(func() {
		for _, wait := range waits {
			select {
			case wait <- 0:
			default:
			}
		}
	})
	return g, &waits
}

func lifecycleConnector(t *testing.T, g *Guest) sessionclient.Connector {
	t.Helper()
	return func(context.Context, string, string) (io.ReadWriteCloser, error) {
		host, guest := net.Pipe()
		t.Cleanup(func() { host.Close() })
		go g.serveSession(guest)
		return host, nil
	}
}

// cutOpenReply lets the guest parse and execute the entire request, then
// disconnects after exactly keep bytes of its first response reach the client.
type cutOpenReply struct {
	io.ReadWriteCloser
	keep int
}

func (c cutOpenReply) Write(p []byte) (int, error) {
	n := 0
	if c.keep > 0 {
		n, _ = c.ReadWriteCloser.Write(p[:min(c.keep, len(p))])
	}
	c.Close()
	return n, io.ErrClosedPipe
}

func TestSessionLostOpenAckFaults(t *testing.T) {
	for _, keep := range []int{0, 1, 4, 5, 8} {
		t.Run(fmt.Sprintf("response-prefix-%d", keep), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g, waits := lifecycleGuest(t)
				attempt := 0
				c := &sessionclient.Client{Connect: func(context.Context, string, string) (io.ReadWriteCloser, error) {
					host, guest := net.Pipe()
					t.Cleanup(func() { host.Close() })
					attempt++
					if attempt == 1 {
						go g.serveSession(cutOpenReply{guest, keep})
					} else {
						go g.serveSession(guest)
					}
					return host, nil
				}}
				o := wire.Open{Mode: wire.OpenExec, OpenID: "same-command", Argv: []string{"charge-once"}}
				if _, err := c.Open(context.Background(), "ns", "pod", o); !errors.Is(err, sessionclient.ErrUnreachable) {
					t.Fatalf("lost reply: %v", err)
				}
				synctest.Wait()
				s := g.openIDs[o.OpenID].session
				s.appendOutput(wire.TStdout, []byte("committed once\n"))
				retry, err := c.Open(context.Background(), "ns", "pod", o)
				if err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				if retry.Opened.Session != s.id || len(*waits) != 1 || s.clients != 1 {
					t.Fatalf("retry duplicated or leaked session: id=%s starts=%d clients=%d", retry.Opened.Session, len(*waits), s.clients)
				}
				(*waits)[0] <- unix.WaitStatus(7 << 8)
				var out bytes.Buffer
				exit, err := retry.Copy(&out, io.Discard, nil)
				if err != nil || exit.Code != 7 || out.String() != "committed once\n" {
					t.Fatalf("retry replay: output=%q exit=%+v err=%v", out.String(), exit, err)
				}
				retry.Close()
				synctest.Wait()
				if len(g.sessions) != 0 || s.out.size != 0 || g.clients != 0 {
					t.Fatal("finished client retained session, replay, or client count")
				}
				if _, err := c.Open(context.Background(), "ns", "pod", o); err == nil || err.Error() != errOpenCompleted.Error() {
					t.Fatalf("completed retry: %v", err)
				}
				if len(*waits) != 1 {
					t.Fatal("completed retry reran command")
				}
			})
		})
	}
}

func TestSessionExitDuringBackpressuredOpenAck(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g, waits := lifecycleGuest(t)
		host, guest := net.Pipe()
		defer host.Close()
		go g.serveSession(guest)
		c := wire.NewConn(host)
		if err := c.WriteJSON(wire.TOpen, wire.Open{Mode: wire.OpenExec, OpenID: "fast"}); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		s := g.openIDs["fast"].session
		s.appendOutput(wire.TStdout, []byte("done before ack"))
		(*waits)[0] <- 0
		synctest.Wait()
		if len(g.sessions) != 0 || !g.openIDs["fast"].completed || s.out.size == 0 {
			t.Fatal("fast exit must tombstone the open and retain the original caller's replay")
		}
		readFrame(t, c, wire.TOpened, &wire.Opened{})
		typ, payload, err := c.Read()
		if typ != wire.TStdout || string(payload) != "done before ack" || err != nil {
			t.Fatalf("late original caller lost replay: type=%d data=%q err=%v", typ, payload, err)
		}
		readFrame(t, c, wire.TExited, &wire.Exit{})
		synctest.Wait()
		if s.out.size != 0 || g.clients != 0 {
			t.Fatal("late caller did not release its replay and client count")
		}
	})
}

func TestSessionConcurrentRetryWaitsForStart(t *testing.T) {
	for _, failFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("first-start-fails-%v", failFirst), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g, waits := lifecycleGuest(t)
				start := g.startProcess
				gate := make(chan struct{})
				attempts := 0
				g.startProcess = func(spec procSpec, base []string) (*proc, []string, error) {
					attempts++
					if attempts == 1 {
						<-gate
						if failFirst {
							return nil, nil, errors.New("temporary start failure")
						}
					}
					return start(spec, base)
				}
				c := &sessionclient.Client{Connect: lifecycleConnector(t, g)}
				type result struct {
					s   *sessionclient.Session
					err error
				}
				results := make(chan result, 2)
				open := func() {
					s, err := c.Open(context.Background(), "ns", "pod", wire.Open{Mode: wire.OpenExec, OpenID: "concurrent"})
					results <- result{s, err}
				}
				go open()
				synctest.Wait()
				go open()
				synctest.Wait()
				if attempts != 1 {
					t.Fatal("duplicate open started while the first start was unresolved")
				}
				close(gate)
				a, b := <-results, <-results
				failures := 0
				for _, r := range []result{a, b} {
					if r.err != nil {
						failures++
					} else {
						r.s.Close()
					}
				}
				synctest.Wait()
				wantFailures := 0
				if failFirst {
					wantFailures = 1
				}
				if failures != wantFailures || len(*waits) != 1 {
					t.Fatalf("failures=%d starts=%d", failures, len(*waits))
				}
				if !failFirst && a.s.Opened.Session != b.s.Opened.Session {
					t.Fatal("concurrent opens received different sessions")
				}
			})
		})
	}
}

// Both callers can pass openExec's optimistic lookup before either reserves
// the OpenID. Exercise the production reservation boundary directly to force
// this ordering rather than relying on the goroutine scheduler to hit it.
func TestSessionConcurrentReservationAndBoundedTombstones(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g, waits := lifecycleGuest(t)
		start := g.startProcess
		gate := make(chan struct{})
		g.startProcess = func(spec procSpec, base []string) (*proc, []string, error) {
			<-gate
			return start(spec, base)
		}
		type result struct {
			s   *session
			err error
		}
		results := make(chan result, 2)
		for _, id := range []string{"winner", "duplicate"} {
			go func() {
				s, err := g.startExec("single", id, procSpec{}, nil)
				results <- result{s, err}
			}()
			synctest.Wait()
		}
		close(gate)
		a, b := <-results, <-results
		if a.err != nil || b.err != nil || a.s != b.s || len(*waits) != 1 {
			t.Fatalf("reservation duplicated start: a=%+v b=%+v starts=%d", a, b, len(*waits))
		}
		if again, err := g.startExec("single", "unused", procSpec{}, nil); err != nil || again != a.s {
			t.Fatalf("live reservation was not reused: %v", err)
		}
		// Keep that session active while more than a window of other opens
		// complete. Eviction may discard only completed IDs, never this one.
		for i := 0; i <= maxOpenTombstones; i++ {
			id := fmt.Sprintf("completed-%03d", i)
			s, err := g.startExec(id, id, procSpec{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			(*waits)[len(*waits)-1] <- 0
			synctest.Wait()
			if _, err := g.startExec(id, "unused", procSpec{}, nil); !errors.Is(err, errOpenCompleted) {
				t.Fatalf("completed ID restarted: %v", err)
			}
			g.removeSession(s) // repeated cleanup must not add another tombstone
		}
		if len(g.openOrder) != maxOpenTombstones || len(g.openIDs) != maxOpenTombstones+1 || g.openIDs["completed-000"] != nil {
			t.Fatalf("unbounded/incorrect tombstones: order=%d records=%d", len(g.openOrder), len(g.openIDs))
		}
		if s, err, found := g.lookupOpen("single"); !found || err != nil || s != a.s {
			t.Fatal("tombstone eviction discarded an active session")
		}
	})
}

func TestSessionCompletionDecisionIsIdempotent(t *testing.T) {
	r := &openRecord{session: &session{}}
	if !r.complete() || r.session != nil || r.disposition() != openCompleted {
		t.Fatal("completion did not prevent reuse")
	}
	if r.complete() {
		t.Fatal("repeated completion would extend tombstone history")
	}
}

func TestSessionExitBeforeOpenRecordLink(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g, waits := lifecycleGuest(t)
		const id = "already-exited"
		rec := &openRecord{done: make(chan struct{})}
		g.openIDs[id] = rec
		// Force the real process completion path to finish between process
		// registration and startExec's finalization of the OpenID reservation.
		s, err := g.startSessionOpen(id, id, procSpec{}, nil, true)
		if err != nil {
			t.Fatal(err)
		}
		s.appendOutput(wire.TStdout, []byte("ran once"))
		retry := make(chan error, 1)
		go func() {
			_, err, found := g.lookupOpen(id)
			if !found {
				err = errors.New("reservation disappeared")
			}
			retry <- err
		}()
		(*waits)[0] <- unix.WaitStatus(3 << 8)
		synctest.Wait()
		if len(g.sessions) != 0 || !s.exited {
			t.Fatal("process did not finish before OpenID linking")
		}
		select {
		case <-retry:
			t.Fatal("retry did not wait for the open reservation")
		default:
		}
		g.finishOpen(id, rec, s, nil)
		if err := <-retry; !errors.Is(err, errOpenCompleted) {
			t.Fatalf("retry after early exit: %v", err)
		}
		g.removeSession(s)
		if !rec.completed || rec.session != nil || len(g.openOrder) != 1 || len(*waits) != 1 {
			t.Fatal("early completion resurrected a session or duplicated its tombstone")
		}
		// The original caller still owns s and must receive its replay/status.
		host, guest := net.Pipe()
		defer host.Close()
		go s.serve(wire.NewConn(guest), guest, false)
		c := wire.NewConn(host)
		typ, data, err := c.Read()
		if err != nil || typ != wire.TStdout || string(data) != "ran once" {
			t.Fatalf("original caller lost output: type=%d data=%q err=%v", typ, data, err)
		}
		var exit wire.Exit
		readFrame(t, c, wire.TExited, &exit)
		if exit.Code != 3 {
			t.Fatalf("original caller lost exit: %+v", exit)
		}
	})
}

func TestSessionMalformedOpensDoNotStartProcesses(t *testing.T) {
	for _, tc := range []struct {
		name    string
		typ     wire.Type
		payload []byte
		reject  bool
	}{
		{"wrong-first-type", wire.TStdin, []byte("hello"), false},
		{"torn-json", wire.TOpen, []byte(`{"mode":`), true},
		{"wrong-json-type", wire.TOpen, []byte(`{"mode":7}`), true},
		{"unknown-mode", wire.TOpen, []byte(`{"mode":"bogus"}`), true},
		{"missing-attach", wire.TOpen, []byte(`{"mode":"attach","session":"absent"}`), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g, waits := lifecycleGuest(t)
				host, guest := net.Pipe()
				defer host.Close()
				go g.serveSession(guest)
				c := wire.NewConn(host)
				if err := c.Write(tc.typ, tc.payload); err != nil {
					t.Fatal(err)
				}
				if tc.reject {
					var opened wire.Opened
					readFrame(t, c, wire.TOpened, &opened)
					if opened.Error == "" {
						t.Fatal("invalid open was accepted")
					}
				}
				if _, _, err := c.Read(); !errors.Is(err, io.EOF) {
					t.Fatalf("rejected connection stayed open: %v", err)
				}
				synctest.Wait()
				if len(*waits) != 0 || len(g.sessions) != 0 || len(g.openIDs) != 0 {
					t.Fatal("malformed open changed process/session state")
				}
			})
		})
	}
}

func TestSessionBackpressureDetachAndReplayGap(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g, _ := lifecycleGuest(t)
		s := newSession(g, "output", nil, false)
		s.out.max = 8
		g.sessions[s.id] = s
		c := &sessionclient.Client{Connect: lifecycleConnector(t, g)}
		attached, err := c.Open(context.Background(), "ns", "pod", wire.Open{Mode: wire.OpenAttach, Session: s.id})
		if err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		done := make(chan struct{})
		go func() {
			s.appendOutput(wire.TStdout, []byte("first123"))
			s.appendOutput(wire.TStdout, []byte("second45"))
			close(done)
		}()
		synctest.Wait()
		select {
		case <-done:
			t.Fatal("slow client did not backpressure the output pump")
		default:
		}
		if s.out.first != 0 || s.out.size != 16 {
			t.Fatal("unsent output was evicted")
		}
		attached.Close()
		<-done
		synctest.Wait()
		if s.out.size > s.out.max || g.clients != 0 {
			t.Fatal("detach failed to release backpressure")
		}
		retry, err := c.Open(context.Background(), "ns", "pod", wire.Open{Mode: wire.OpenAttach, Session: s.id})
		if err != nil {
			t.Fatal(err)
		}
		f, err := retry.Recv()
		if err != nil || f.Type != wire.TNotice || f.Notice != "earlier output was dropped" {
			t.Fatalf("replay gap was silent: %+v %v", f, err)
		}
		f, err = retry.Recv()
		if err != nil || string(f.Data) != "second45" {
			t.Fatalf("retained replay: %+v %v", f, err)
		}
		s.finish(wire.Exit{})
		if _, err := retry.Copy(io.Discard, io.Discard, nil); err != nil {
			t.Fatal(err)
		}
		retry.Close()
	})
}

// A follower tails the session without pinning its output: a burst larger
// than the ring is trimmed instead of blocking the command, and the follower
// still receives the retained tail after a replay-gap notice.
func TestSessionFollowDoesNotPinRing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g, _ := lifecycleGuest(t)
		s := newSession(g, "output", nil, false)
		s.out.max = 8
		g.sessions[s.id] = s
		c := &sessionclient.Client{Connect: lifecycleConnector(t, g)}
		follower, err := c.Open(context.Background(), "ns", "pod", wire.Open{Mode: wire.OpenAttach, Session: s.id, Follow: true})
		if err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		s.mu.Lock()
		readers := len(s.readers)
		s.mu.Unlock()
		if readers != 0 {
			t.Fatalf("follower was registered as a ring reader: %d", readers)
		}

		done := make(chan struct{})
		go func() {
			s.appendOutput(wire.TStdout, []byte("first123"))
			s.appendOutput(wire.TStdout, []byte("second45"))
			close(done)
		}()
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("follower backpressured the output pump")
		}
		s.mu.Lock()
		first, size := s.out.first, s.out.size
		s.mu.Unlock()
		if first == 0 || size > s.out.max {
			t.Fatalf("follower pinned trimmed output: first=%d size=%d", first, size)
		}

		f, err := follower.Recv()
		if err != nil || f.Type != wire.TNotice || f.Notice != "earlier output was dropped" {
			t.Fatalf("follower replay gap was silent: %+v %v", f, err)
		}
		f, err = follower.Recv()
		if err != nil || string(f.Data) != "second45" {
			t.Fatalf("follower retained replay: %+v %v", f, err)
		}
		s.finish(wire.Exit{})
		if _, err := follower.Copy(io.Discard, io.Discard, nil); err != nil {
			t.Fatal(err)
		}
		follower.Close()
	})
}

func TestSessionInputCloseWakesBackpressuredWriter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g, _ := lifecycleGuest(t)
		s := newSession(g, "input", nil, false)
		if err := s.queueInput(make([]byte, maxQueuedInput)); err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() { _ = s.queueInput([]byte("late")); close(done) }()
		synctest.Wait()
		s.closeInput()
		<-done
		if s.inBytes != 0 || len(s.inQueue) != 0 || s.inDropped {
			t.Fatal("writer resurrected input after close")
		}
	})
}

func TestSessionInputWaitsForReaderThroughWire(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g, _ := lifecycleGuest(t)
		s := newSession(g, "input", nil, false)
		s.proc = &proc{} // process with no running input pump: never reads
		g.sessions[s.id] = s
		c := &sessionclient.Client{Connect: lifecycleConnector(t, g)}
		attached, err := c.Open(context.Background(), "ns", "pod", wire.Open{Mode: wire.OpenAttach, Session: s.id})
		if err != nil {
			t.Fatal(err)
		}
		defer attached.Close()
		if _, err := attached.Write(make([]byte, maxQueuedInput)); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if s.inBytes != maxQueuedInput {
			t.Fatalf("queued %d bytes, want %d", s.inBytes, maxQueuedInput)
		}
		// The guest keeps the queue bounded instead of dropping the excess:
		// the next frame waits for the pump to make space. No notice about
		// discarded input may be sent for a byte stream.
		written := make(chan error, 1)
		go func() {
			_, err := attached.Write([]byte("overflow"))
			written <- err
		}()
		synctest.Wait()
		if s.takeDropped() {
			t.Fatal("a non-terminal byte stream was dropped")
		}
		if s.inBytes != maxQueuedInput {
			t.Fatalf("queue grew past its limit: %d bytes", s.inBytes)
		}
		// A process that exits releases the waiter so the session cannot wedge.
		s.closeInput()
		select {
		case <-written:
		case <-time.After(time.Second):
			t.Fatal("write did not return after the session closed")
		}
	})
}
