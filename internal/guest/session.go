package guest

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/Azure/blip/internal/wire"
	"golang.org/x/sys/unix"
)

// session is one process with replayable output and any number of attached
// clients.
type session struct {
	g      *Guest
	id     string
	openID string // client-generated exec open ID, for retry deduplication
	argv   []string
	tty    bool
	proc   *proc

	mu        sync.Mutex
	cond      *sync.Cond
	out       ring
	clients   int
	attached  bool                 // a client has ever attached
	readers   map[*client]struct{} // clients whose output cursor must be preserved
	delivered bool                 // a client has received the exit status
	exited    bool
	status    wire.Exit

	// Stdin is queued and written by a dedicated goroutine. Writing a pipe
	// or PTY blocks when the process does not read it; doing that in the
	// frame loop would also block resize and signal frames, so a command
	// like `sleep` could not be interrupted after its stdin filled up.
	inMu      sync.Mutex
	inCond    *sync.Cond
	inQueue   [][]byte
	inBytes   int
	inEOF     bool
	inDone    bool // no more input will be queued
	inDropped bool // input was discarded because the process is not reading

	// Exec sessions hold output pumps until the client is attached (right
	// after TOpened), so output produced during the open handshake cannot
	// overflow the replay ring before anyone can read it.
	pumpsReady chan struct{}
	pumpsOnce  sync.Once
}

// maxPendingInput bounds stdin queued for a process that is not reading it.
// The SSH channel window is smaller, so this leaves room for a control frame
// (resize or signal) behind a burst of input without buffering without limit.
const maxPendingInput = 8 << 20

type client struct {
	closed bool
	cursor uint64 // next output frame the client has not received
}

// maxOpenTombstones bounds the completed open IDs remembered so a retry that
// arrives after a fast command exited cannot start it again. Exec opens are
// short-lived, so a small window covers the gateway's single retry.
const maxOpenTombstones = 256

// errOpenCompleted reports a retry for a command that already ran and left the
// session list. Rerunning it could repeat a non-idempotent operation, so the
// caller gets an error instead.
var errOpenCompleted = errors.New("session already completed")

// openRecord tracks one client-generated OpenID. session is nil while the
// process is starting and after the session is gone; done closes once the
// start attempt has resolved either way.
type openRecord struct {
	session   *session
	completed bool
	done      chan struct{}
}

func newID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// newSession allocates a session with every channel and condition variable
// initialized. Both a session with a running process and a session recording a
// failed start must have a usable pumpsReady: a client attaching to a nil
// channel would panic, which kills PID 1 and reboots the whole VM.
func newSession(g *Guest, id string, argv []string, tty bool) *session {
	s := &session{g: g, id: id, argv: argv, tty: tty, out: ring{max: RingSize}}
	s.cond = sync.NewCond(&s.mu)
	s.inCond = sync.NewCond(&s.inMu)
	s.pumpsReady = make(chan struct{})
	return s
}

// startSession starts a process and registers its session. base is the
// environment applied before s.env.
func (g *Guest) startSession(id string, s procSpec, base []string, holdOutput bool) (*session, error) {
	return g.startSessionOpen(id, "", s, base, holdOutput)
}

// startSessionOpen is startSession with a client OpenID recorded on the
// session before it becomes visible, so removeSession can tombstone it.
func (g *Guest) startSessionOpen(id, openID string, s procSpec, base []string, holdOutput bool) (*session, error) {
	start := g.startProc
	if g.startProcess != nil {
		start = g.startProcess
	}
	p, argv, err := start(s, base)
	if err != nil {
		return nil, err
	}
	ss := newSession(g, id, argv, s.tty)
	ss.openID = openID
	ss.proc = p
	if !holdOutput {
		ss.releasePumps()
	}
	g.mu.Lock()
	g.sessions[id] = ss
	g.lastActive = time.Now()
	g.mu.Unlock()
	go ss.pumpInput()
	var pumps sync.WaitGroup
	pump := func(f *os.File, t wire.Type) {
		pumps.Add(1)
		go func() {
			defer pumps.Done()
			<-ss.pumpsReady
			ss.pump(f, t)
		}()
	}
	if p.tty != nil {
		pump(p.tty, wire.TStdout)
	} else {
		pump(p.stdout, wire.TStdout)
		pump(p.stderr, wire.TStderr)
	}
	go func() {
		ws := <-p.wait
		// The process can no longer write. Let pumps that were held for a
		// client drain the rest of the pipe (or PTY) into the replay ring,
		// so a caller that attaches after the command exited still sees its
		// final output.
		ss.releasePumps()
		// Output written right before exit is still in the pipe or PTY;
		// give the pumps a moment to drain it. Background processes may keep
		// the PTY open, so do not wait for EOF forever.
		done := make(chan struct{})
		go func() { pumps.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
		p.close()
		code, sig := exitOf(ws)
		e := wire.Exit{Code: code, Signal: sig}
		g.mu.Lock()
		if g.stopping {
			e.Reason = wire.ReasonStopped
		}
		g.mu.Unlock()
		ss.finish(e)
	}()
	return ss, nil
}

// openExec validates and starts an exec session, deduplicating client retries
// by OpenID. An empty OpenID keeps the old behavior: every open is a new
// process.
func (g *Guest) openExec(o wire.Open) (*session, error) {
	if o.OpenID != "" {
		if s, err, found := g.lookupOpen(o.OpenID); found {
			return s, err
		}
	}
	g.mu.Lock()
	claim, stopping, exited := g.claim, g.stopping, g.exit != nil
	g.mu.Unlock()
	if claim == nil || stopping {
		return nil, errors.New("blip is not running")
	}
	if exited {
		// The primary command has finished and the guest is only keeping its
		// session replayable. A new command could still write a durable root
		// after it was supposed to be sealed.
		return nil, errors.New("blip primary command has exited")
	}
	spec := execProcSpec(claim, o)
	return g.startExec(o.OpenID, newID(), spec, claim.Env)
}

// lookupOpen returns the session recorded for openID. If another connection
// with the same ID is still starting its process, lookupOpen waits for it
// rather than letting a retry start a duplicate. found is false only for an
// unknown ID.
func (g *Guest) lookupOpen(openID string) (*session, error, bool) {
	for {
		g.mu.Lock()
		rec, ok := g.openIDs[openID]
		if !ok {
			g.mu.Unlock()
			return nil, nil, false
		}
		if rec.completed {
			g.mu.Unlock()
			return nil, errOpenCompleted, true
		}
		if rec.session != nil {
			s := rec.session
			g.mu.Unlock()
			return s, nil, true
		}
		done := rec.done
		g.mu.Unlock()
		<-done
	}
}

// startExec is the single-flight path for an exec OpenID: exactly one process
// starts per ID, concurrent duplicates attach to its session, and an ID kept
// as a tombstone is never rerun.
func (g *Guest) startExec(openID, id string, spec procSpec, base []string) (*session, error) {
	if openID == "" {
		return g.startSessionOpen(id, "", spec, base, true)
	}
	for {
		g.mu.Lock()
		if rec, ok := g.openIDs[openID]; ok {
			switch {
			case rec.completed:
				g.mu.Unlock()
				return nil, errOpenCompleted
			case rec.session != nil:
				s := rec.session
				g.mu.Unlock()
				return s, nil
			}
			done := rec.done
			g.mu.Unlock()
			<-done
			continue
		}
		rec := &openRecord{done: make(chan struct{})}
		g.openIDs[openID] = rec
		g.mu.Unlock()

		s, err := g.startSessionOpen(id, openID, spec, base, true)

		g.mu.Lock()
		if err != nil {
			// No process started, so a retry may safely try again.
			delete(g.openIDs, openID)
		} else {
			rec.session = s
			if g.sessions[s.id] != s {
				// The command exited and was removed before the open could
				// link it. Tombstone it now instead of leaving a session
				// pointer that no one can attach to.
				rec.session = nil
				rec.completed = true
				g.rememberOpenLocked(openID)
			}
		}
		close(rec.done)
		g.mu.Unlock()
		return s, err
	}
}

// rememberOpenLocked keeps a completed OpenID as a bounded tombstone.
func (g *Guest) rememberOpenLocked(openID string) {
	g.openOrder = append(g.openOrder, openID)
	for len(g.openOrder) > maxOpenTombstones {
		old := g.openOrder[0]
		g.openOrder = g.openOrder[1:]
		if rec := g.openIDs[old]; rec != nil && rec.completed {
			delete(g.openIDs, old)
		}
	}
}

// failedSession records a session whose process could not start, so a
// client sees the error and an exit status.
func (g *Guest) failedSession(id string, argv []string, err error) *session {
	ss := newSession(g, id, argv, false)
	ss.out.add(wire.TStderr, []byte(err.Error()+"\n"))
	g.mu.Lock()
	g.sessions[id] = ss
	g.mu.Unlock()
	ss.finish(wire.Exit{Code: 127})
	return ss
}

func (s *session) pump(f *os.File, t wire.Type) {
	buf := make([]byte, 32<<10)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			// The read buffer is reused; a ring frame must own its bytes
			// until every reader has consumed it.
			data := append([]byte(nil), buf[:n]...)
			s.mu.Lock()
			s.out.addPinned(t, data, s.pinLocked())
			s.cond.Broadcast()
			// A client that is not keeping up pins its unsent frames.
			// Stop reading until it makes room; the process then blocks
			// on its output pipe, which is the backpressure we want.
			for s.out.size > s.out.max && len(s.readers) > 0 && !s.exited {
				s.cond.Wait()
				s.out.trim(s.pinLocked())
			}
			s.mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

// pinLocked is the oldest frame an attached client still needs.
func (s *session) pinLocked() uint64 {
	pin := s.out.next()
	for c := range s.readers {
		if c.cursor < pin {
			pin = c.cursor
		}
	}
	return pin
}

func (s *session) releasePumps() {
	s.pumpsOnce.Do(func() {
		// newSession always creates the channel. Keep the nil check as a
		// last-resort guard: closing a nil channel panics, and in the guest
		// that panic takes down init and the whole VM.
		if s.pumpsReady != nil {
			close(s.pumpsReady)
		}
	})
}

// pumpInput writes queued stdin to the process. It is the only writer of the
// process's stdin, so frames it cannot deliver yet never stall the session's
// control frames.
func (s *session) pumpInput() {
	for {
		s.inMu.Lock()
		for len(s.inQueue) == 0 && !s.inEOF && !s.inDone {
			s.inCond.Wait()
		}
		if s.inDone {
			s.inMu.Unlock()
			return
		}
		queue, eof := s.inQueue, s.inEOF
		s.inQueue, s.inBytes, s.inEOF = nil, 0, false
		s.inCond.Broadcast() // space is available again
		s.inMu.Unlock()
		for _, b := range queue {
			s.writeInput(b)
		}
		if eof {
			s.endInput()
			// Stdin stays closed: input a later client sends cannot be
			// delivered, and queueing it would only block the frame loop.
			s.closeInput()
			return
		}
	}
}

func (s *session) writeInput(b []byte) {
	p := s.proc
	if p == nil {
		return
	}
	if p.tty != nil {
		_, _ = p.tty.Write(b)
	} else {
		_, _ = p.stdin.Write(b)
	}
}

func (s *session) endInput() {
	p := s.proc
	if p == nil {
		return
	}
	if p.tty != nil {
		_, _ = p.tty.Write([]byte{4})
	} else {
		_ = p.stdin.Close()
	}
}

// queueInput appends stdin.
//
// A terminal session's input is best-effort: if the process stops reading,
// maxPendingInput is queued and further stdin is dropped rather than closing
// the client. An SSH client may keep writing (for example a redirected
// /dev/zero) while the user presses Ctrl-C, and the signal has to reach the
// process instead of failing on a dead session. An interactive client never
// sends megabytes without the process reading them.
//
// A non-terminal session is a byte stream, not a person typing: sftp, scp and
// git upload data through it. Dropping a frame would corrupt the stream, so
// wait for the input pump to make space instead. The wait propagates through
// the client's SSH window as normal backpressure.
func (s *session) queueInput(payload []byte) error {
	s.inMu.Lock()
	defer s.inMu.Unlock()
	if s.inDone {
		return nil
	}
	if s.tty {
		if len(payload) > maxPendingInput-s.inBytes {
			s.inDropped = true
			return nil
		}
	} else {
		for len(payload) > maxPendingInput-s.inBytes && !s.inDone {
			s.inCond.Wait()
		}
		if s.inDone {
			return nil
		}
	}
	s.inQueue = append(s.inQueue, payload)
	s.inBytes += len(payload)
	s.inCond.Signal()
	return nil
}

func (s *session) queueEOF() {
	s.inMu.Lock()
	if !s.inDone {
		s.inEOF = true
		s.inCond.Broadcast()
	}
	s.inMu.Unlock()
}

// closeInput stops the input pump after the process has exited.
func (s *session) closeInput() {
	if s.inCond == nil {
		s.inDone = true
		return
	}
	s.inMu.Lock()
	s.inDone = true
	s.inQueue, s.inBytes, s.inEOF = nil, 0, false
	s.inCond.Broadcast()
	s.inMu.Unlock()
}

// clearReplayLocked drops a finished non-primary session's replay output. It
// is called when the last client detaches; a session that no client ever
// attached to keeps its output (bounded by the ring) for a late caller.
func (s *session) clearReplayLocked() {
	if s.exited && s.clients == 0 && s.id != wire.PrimarySession {
		s.out.clear()
	}
}

func (s *session) finish(st wire.Exit) {
	s.closeInput()
	s.mu.Lock()
	s.exited, s.status = true, st
	// A command that fails or finishes before its caller attaches keeps its
	// output: only a client that has already consumed the session may drop it.
	if s.attached {
		s.clearReplayLocked()
	}
	drop := s.clients == 0
	s.cond.Broadcast()
	s.mu.Unlock()
	if drop {
		s.g.removeSession(s)
	}
	s.g.sessionExited(s)
}

// removeSession forgets a finished command session once no client can attach
// to it. Every non-primary session is one command, so keeping them would grow
// the session list (and memory) without bound in a long-lived blip. An exec
// open ID becomes a bounded tombstone so a delayed retry cannot run the
// command a second time.
func (g *Guest) removeSession(s *session) {
	if s.id == wire.PrimarySession {
		return
	}
	g.mu.Lock()
	if g.sessions[s.id] == s {
		delete(g.sessions, s.id)
	}
	if s.openID != "" {
		if rec := g.openIDs[s.openID]; rec != nil && rec.session == s && !rec.completed {
			rec.session = nil
			rec.completed = true
			g.rememberOpenLocked(s.openID)
		}
	}
	g.mu.Unlock()
}

// deliveryDeadline bounds waitDelivered. The wait starts with unattached, or
// with attached when a client is already connected, and switches once to
// attached when the first client arrives. It is never extended again, so a
// client that stops reading cannot hold the guest up.
type deliveryDeadline struct {
	attached time.Duration
	deadline time.Time
	switched bool
}

func newDeliveryDeadline(unattached, attached time.Duration, clients int, now time.Time) deliveryDeadline {
	d := deliveryDeadline{attached: attached, switched: clients > 0}
	timeout := unattached
	if d.switched {
		timeout = attached
	}
	d.deadline = now.Add(timeout)
	return d
}

// expired reports whether the wait is over. done ends it immediately; the
// first client seen moves the deadline to now+attached, at most once.
func (d *deliveryDeadline) expired(now time.Time, clients int, done bool) bool {
	if done {
		return true
	}
	if !d.switched && clients > 0 {
		d.switched = true
		d.deadline = now.Add(d.attached)
	}
	return !now.Before(d.deadline)
}

// waitDelivered waits until a client has received the exit status, so a
// command that finishes before its caller attaches keeps its output. It waits
// up to unattached for a first client, and up to attached from the moment one
// attaches; the deadline is monotonic, so a stalled client cannot extend it.
func (s *session) waitDelivered(unattached, attached time.Duration) {
	s.mu.Lock()
	d := newDeliveryDeadline(unattached, attached, s.clients, time.Now())
	s.mu.Unlock()
	for {
		s.mu.Lock()
		done := s.delivered || (s.attached && s.clients == 0)
		clients := s.clients
		s.mu.Unlock()
		if d.expired(time.Now(), clients, done) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (s *session) info() wire.SessionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	return wire.SessionInfo{ID: s.id, Argv: s.argv, TTY: s.tty, Clients: s.clients, Exited: s.exited}
}

// serve attaches a client until it disconnects or the session ends.
func (s *session) serve(c *wire.Conn, conn io.Closer) {
	cl := &client{}
	s.mu.Lock()
	s.clients++
	s.attached = true
	if s.readers == nil {
		s.readers = map[*client]struct{}{}
	}
	s.readers[cl] = struct{}{}
	s.mu.Unlock()
	s.g.addClients(1)
	// Register the reader before releasing held pumps. pinLocked must see
	// it, or output produced during the handshake could overflow the replay
	// ring before write starts draining it.
	s.releasePumps()
	defer func() {
		conn.Close()
		s.mu.Lock()
		cl.closed = true
		s.clients--
		delete(s.readers, cl)
		s.clearReplayLocked()
		drop := s.exited && s.clients == 0
		s.cond.Broadcast()
		s.mu.Unlock()
		s.g.addClients(-1)
		if drop {
			s.g.removeSession(s)
		}
	}()
	go s.write(c, conn, cl)
	for {
		t, payload, err := c.Read()
		if err != nil {
			return
		}
		if err := s.input(t, payload); err != nil {
			return
		}
		if s.takeDropped() {
			_ = c.WriteJSON(wire.TNotice, wire.Notice{
				Message: "stdin was discarded: the command is not reading it",
			})
		}
	}
}

// takeDropped reports and clears a pending input-overflow notice.
func (s *session) takeDropped() bool {
	s.inMu.Lock()
	defer s.inMu.Unlock()
	dropped := s.inDropped
	s.inDropped = false
	return dropped
}

// write streams output from the start of the ring, then live output, then
// the exit status.
func (s *session) write(c *wire.Conn, conn io.Closer, cl *client) {
	var cursor uint64
	for {
		s.mu.Lock()
		for !cl.closed && !s.exited && cursor == s.out.next() {
			s.cond.Wait()
		}
		if cl.closed {
			s.mu.Unlock()
			return
		}
		frames, next, gap := s.out.since(cursor)
		exited, status := s.exited, s.status
		if gap {
			// The ring no longer has the client's oldest frame.
			cursor = next - uint64(len(frames))
		}
		s.mu.Unlock()
		if gap {
			if c.WriteJSON(wire.TNotice, wire.Notice{Message: "earlier output was dropped"}) != nil {
				conn.Close()
				return
			}
		}
		for _, f := range frames {
			if c.Write(f.t, f.data) != nil {
				conn.Close()
				return
			}
			cursor++
		}
		// Only now is it safe to let the ring evict these frames.
		s.mu.Lock()
		cl.cursor = cursor
		s.out.trim(s.pinLocked())
		s.cond.Broadcast()
		s.mu.Unlock()
		if exited && len(frames) == 0 {
			if c.WriteJSON(wire.TExited, status) == nil {
				s.mu.Lock()
				s.delivered = true
				s.cond.Broadcast()
				s.mu.Unlock()
			}
			conn.Close()
			return
		}
	}
}

func (s *session) input(t wire.Type, payload []byte) error {
	p := s.proc
	if p == nil {
		return nil
	}
	switch t {
	case wire.TStdin:
		return s.queueInput(payload)
	case wire.TStdinEOF:
		s.queueEOF()
	case wire.TResize:
		var r wire.Resize
		if wire.Decode(payload, &r) == nil && p.tty != nil && r.Rows > 0 && r.Cols > 0 {
			setWinsize(p.tty, r.Rows, r.Cols)
		}
	case wire.TSignal:
		var sg wire.Signal
		if wire.Decode(payload, &sg) != nil {
			return nil
		}
		sig, err := parseSignal(sg.Name)
		if err != nil {
			return nil
		}
		s.mu.Lock()
		exited := s.exited
		s.mu.Unlock()
		if !exited {
			if unix.Kill(-p.pid, sig) != nil {
				_ = unix.Kill(p.pid, sig)
			}
		}
	}
	return nil
}

// serveSession handles one connection on the session port.
func (g *Guest) serveSession(f *os.File) {
	c := wire.NewConn(f)
	t, payload, err := c.Read()
	if err != nil || t != wire.TOpen {
		f.Close()
		return
	}
	var o wire.Open
	if err := wire.Decode(payload, &o); err != nil {
		reject(c, f, err)
		return
	}
	switch o.Mode {
	case wire.OpenList:
		_ = c.WriteJSON(wire.TOpened, wire.Opened{Sessions: g.sessionList()})
		f.Close()
	case wire.OpenAttach:
		id := o.Session
		if id == "" {
			id = wire.PrimarySession
		}
		g.mu.Lock()
		s := g.sessions[id]
		g.mu.Unlock()
		if s == nil {
			reject(c, f, errors.New("no session "+strconv.Quote(id)))
			return
		}
		if s.tty && s.proc != nil && o.Rows > 0 && o.Cols > 0 {
			setWinsize(s.proc.tty, o.Rows, o.Cols)
		}
		if c.WriteJSON(wire.TOpened, wire.Opened{Session: id, TTY: s.tty}) != nil {
			f.Close()
			return
		}
		s.serve(c, f)
	case wire.OpenExec:
		s, err := g.openExec(o)
		if err != nil {
			reject(c, f, err)
			return
		}
		if c.WriteJSON(wire.TOpened, wire.Opened{Session: s.id, TTY: s.tty}) != nil {
			f.Close()
			s.releasePumps()
			return
		}
		s.serve(c, f)
	case wire.OpenDial:
		g.dial(c, f, o)
	default:
		reject(c, f, errors.New("unknown mode "+strconv.Quote(o.Mode)))
	}
}

// execProcSpec applies the blip's defaults to a new exec session. An exec
// without -w or -u uses the working directory and user the blip was created
// with, just like the primary command.
func execProcSpec(claim *wire.Claim, o wire.Open) procSpec {
	user := o.User
	if user == "" {
		user = claim.User
	}
	dir := o.WorkingDir
	if dir == "" {
		dir = claim.WorkingDir
	}
	return procSpec{argv: o.Argv, env: o.Env, dir: dir, user: user, tty: o.TTY, rows: o.Rows, cols: o.Cols}
}

func reject(c *wire.Conn, f io.Closer, err error) {
	_ = c.WriteJSON(wire.TOpened, wire.Opened{Error: err.Error()})
	f.Close()
}

// dial relays a TCP connection opened from inside the guest. When the remote
// side closes, the guest sends Exited and closes the stream.
func (g *Guest) dial(c *wire.Conn, f *os.File, o wire.Open) {
	g.mu.Lock()
	stopping := g.stopping
	g.mu.Unlock()
	if stopping {
		reject(c, f, errors.New("blip is stopping"))
		return
	}
	tc, err := net.DialTimeout("tcp", net.JoinHostPort(o.Host, strconv.Itoa(o.Port)), 10*time.Second)
	if err != nil {
		reject(c, f, err)
		return
	}
	defer tc.Close()
	defer f.Close()
	if c.WriteJSON(wire.TOpened, wire.Opened{}) != nil {
		return
	}
	g.addClients(1)
	defer g.addClients(-1)
	go func() {
		defer tc.Close()
		defer f.Close()
		buf := make([]byte, 32<<10)
		for {
			n, err := tc.Read(buf)
			if n > 0 && c.Write(wire.TStdout, buf[:n]) != nil {
				return
			}
			if err != nil {
				_ = c.WriteJSON(wire.TExited, wire.Exit{})
				return
			}
		}
	}()
	for {
		t, payload, err := c.Read()
		if err != nil {
			return
		}
		switch t {
		case wire.TStdin:
			if _, err := tc.Write(payload); err != nil {
				return
			}
		case wire.TStdinEOF:
			_ = tc.(*net.TCPConn).CloseWrite()
		}
	}
}

func (s *session) tail(max int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.out.tail(max)
}
