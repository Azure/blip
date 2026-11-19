package guest

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

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
	procDone  bool                 // the process has been reaped (output may still drain)
	exited    bool
	status    wire.Exit

	// Stdin is queued and written by a dedicated goroutine. Writing a pipe
	// or PTY blocks when the process does not read it; doing that in the
	// frame loop would also block resize and signal frames, so a command
	// like `sleep` could not be interrupted after its stdin filled up.
	inMu        sync.Mutex
	inCond      *sync.Cond
	inQueue     [][]byte
	inBytes     int       // queued but not yet handed to the pump
	inFlight    int       // dequeued and being written by the pump
	inFullSince time.Time // when the hard bound last became full without progress
	inEOF       bool
	inDone      bool      // no more input will be queued
	inStalled   bool      // the process is not reading, so input is being shed
	inDropped   bool      // input was discarded because the process is not reading
	inTruncated bool      // at least one non-terminal input frame was shed
	inNotice    time.Time // when the stdin-discarded notice was last sent

	// Exec sessions hold output pumps until the client is attached (right
	// after TOpened), so output produced during the open handshake cannot
	// overflow the replay ring before anyone can read it.
	pumpsReady chan struct{}
	pumpsOnce  sync.Once

	// mirror copies the primary command's output to the VM serial console.
	// It is nil for other sessions and when /dev/console cannot be opened.
	mirror *consoleMirror
}

// maxPendingInput is the stdin budget that is always accepted without waiting.
// A client write burst is smaller, so this leaves room for a control frame
// (resize or signal) behind a burst of input without buffering without limit.
const maxPendingInput = 8 << 20

// maxInputBacklog is extra in-memory stdin accepted beyond maxPendingInput.
// A non-terminal upload that pauses (or a command that is still starting up)
// is absorbed here instead of being dropped, without blocking the frame loop
// long enough for a forwarded signal to be lost. The total covers a 32 MiB
// redirected upload, the size used by the stdin-backpressure regression.
const maxInputBacklog = 24 << 20

// maxQueuedInput is the hard bound on queued plus in-flight stdin.
const maxQueuedInput = maxPendingInput + maxInputBacklog

// inputStallTimeout is how long the hard-input bound may stay full without
// the pump writing anything before the process is treated as not reading.
// Only then is input shed, so a slow but steadily reading process (and a
// command that pauses for a few seconds before reading) is never truncated.
var inputStallTimeout = 5 * time.Second

const (
	// inputNoticeInterval throttles the stdin-discarded warning so a flood
	// produces one notice rather than one per dropped frame.
	inputNoticeInterval = time.Second
	// detachGrace is how long a detached exec command gets between SIGTERM
	// and SIGKILL after its last client goes away.
	detachGrace = 2 * time.Second
	// inputWriteChunk bounds one stdin write. Counting progress at this
	// granularity keeps a slow reader from looking stalled while it drains
	// a large dequeued batch.
	inputWriteChunk = 32 << 10
	// ttyEOFPoll is how often the guest samples whether the command is
	// blocked reading its terminal.
	ttyEOFPoll = 10 * time.Millisecond
	// ttyEOFGap keeps one VEOF from being queued before the read it woke had
	// a chance to consume it. A queued marker that survives a later raw-mode
	// switch is delivered as NUL data, so at most one is outstanding.
	ttyEOFGap = 20 * time.Millisecond
	// ttyEOFDeliveries bounds how many markers are queued for a command that
	// keeps reading after end of input, so it is not stopped and resumed
	// forever.
	ttyEOFDeliveries = 8
	// ttyEOFTimeout bounds the wait for a command that never waits on its
	// terminal in a way the guest can observe (for example one waiting in
	// epoll). It must exceed any startup delay after which a program may
	// still switch to raw mode.
	ttyEOFTimeout = 5 * time.Second
	// ttyEOFSettle is the fallback wait when /proc cannot report the
	// command's state. The guest behaves as it did before the state check:
	// give a startup raw-mode switch a short chance, then queue the marker.
	ttyEOFSettle = 500 * time.Millisecond
	// ttyEOFStopDelay lets SIGSTOP reach the whole process group before the
	// VEOF is queued. A SIGCONT that overtakes the pending stop would leave
	// the command stopped forever.
	ttyEOFStopDelay = 5 * time.Millisecond
	// ttyEOFWriteTimeout bounds the VEOF write. A stopped process cannot
	// drain a full terminal input queue, so an unbounded write would leave
	// the group stopped forever.
	ttyEOFWriteTimeout = 100 * time.Millisecond
)

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
	s := &session{g: g, id: id, argv: argv, tty: tty, out: ring{max: ringSize}}
	s.cond = sync.NewCond(&s.mu)
	s.inCond = sync.NewCond(&s.inMu)
	s.pumpsReady = make(chan struct{})
	if id == wire.PrimarySession {
		// The pod log is the VM serial console; mirroring the primary
		// command's output there makes it readable without an attached
		// client. A guest that cannot open the console simply disables it.
		s.mirror = openConsoleMirror()
	}
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
		ss.mu.Lock()
		ss.procDone = true
		ss.mu.Unlock()
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
		rec := g.openIDs[openID]
		switch rec.disposition() {
		case openStart:
			g.mu.Unlock()
			return nil, nil, false
		case openCompleted:
			g.mu.Unlock()
			return nil, errOpenCompleted, true
		case openReuse:
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
		if rec := g.openIDs[openID]; rec.disposition() != openStart {
			switch rec.disposition() {
			case openCompleted:
				g.mu.Unlock()
				return nil, errOpenCompleted
			case openReuse:
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
		g.finishOpen(openID, rec, s, err)
		return s, err
	}
}

// finishOpen links a resolved start and wakes duplicates. A fast process can
// finish and leave the session list before startSessionOpen returns; finalize
// against that list under the same lock used by removal.
func (g *Guest) finishOpen(openID string, rec *openRecord, s *session, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err != nil {
		// No process started, so a retry may safely try again.
		delete(g.openIDs, openID)
	} else {
		rec.session = s
		if g.sessions[s.id] != s && rec.complete() {
			g.rememberOpenLocked(openID)
		}
	}
	close(rec.done)
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
	ss.out.add(wire.TStderr, []byte(boundErrorText(err.Error())+"\n"))
	g.mu.Lock()
	g.sessions[id] = ss
	g.mu.Unlock()
	// A start failure has a conventional shell status: 127 for a missing
	// command, 126 for a command that cannot be executed or a bad workdir.
	ss.finish(wire.Exit{Code: startExitCode(err)})
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
			s.appendOutput(t, data)
		}
		if err != nil {
			return
		}
	}
}

// appendOutput accepts an owned frame from an output pump. A slow attached
// client pins unsent frames; waiting here propagates backpressure to the
// process's output pipe without coupling it to session control/input frames.
func (s *session) appendOutput(t wire.Type, data []byte) {
	// Mirror at the byte level before the ring takes ownership. feed never
	// blocks: when the console queue is full it drops lines instead of
	// propagating backpressure to the command.
	s.mirror.feed(data)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.out.addPinned(t, data, s.pinLocked())
	s.cond.Broadcast()
	for s.out.size > s.out.max && len(s.readers) > 0 && !s.exited {
		s.cond.Wait()
		s.out.trim(s.pinLocked())
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
		// A dequeued frame is still occupying the byte budget: writing it
		// can block for as long as the reader takes. Count it as in flight
		// until each chunk is written, or a slow reader looks like it made
		// no progress while the pump sits in write.
		for _, b := range queue {
			s.inFlight += len(b)
		}
		s.inCond.Broadcast()
		s.inMu.Unlock()
		for _, b := range queue {
			s.writeInput(b)
		}
		s.inMu.Lock()
		s.inFlight = 0 // writeInput accounts per chunk; be safe after errors
		s.inCond.Broadcast()
		s.inMu.Unlock()
		if eof {
			s.endInput()
			// Stdin stays closed: input a later client sends cannot be
			// delivered, and queueing it would only block the frame loop.
			s.closeInput()
			return
		}
	}
}

// writeInput writes one queued frame in chunks, releasing its byte-budget
// reservation and reporting progress after each chunk. The per-chunk progress
// is what lets queueInput tell a slow reader (which keeps freeing pipe space)
// from a process that stopped reading (which frees nothing).
func (s *session) writeInput(b []byte) {
	p := s.proc
	if p == nil {
		return
	}
	for len(b) > 0 {
		n := min(len(b), inputWriteChunk)
		if p.tty != nil {
			_, _ = p.tty.Write(b[:n])
		} else {
			_, _ = p.stdin.Write(b[:n])
		}
		b = b[n:]

		s.inMu.Lock()
		s.inFlight -= n
		if s.inFlight < 0 {
			s.inFlight = 0
		}
		// Progress is what tells a slow reader from a stuck one: any chunk
		// written resets a waiting writer's stall clock.
		s.inFullSince = time.Time{}
		s.inStalled = false
		s.inCond.Broadcast()
		s.inMu.Unlock()
	}
}

func (s *session) endInput() {
	p := s.proc
	if p == nil {
		return
	}
	if p.tty == nil {
		_ = p.stdin.Close()
		return
	}
	s.endTTYInput(p.tty)
}

// endTTYInput delivers end of input to a terminal session. Closing the master
// would hang up the foreground process group and cut off output, so EOF is
// delivered in-band with a canonical VEOF instead.
//
// A VEOF is only an EOF marker while the terminal is canonical; in raw mode it
// is stored as NUL data. A program that is about to enter raw mode may have
// already received the client's input and end of input, so a marker queued too
// early would be consumed as data after it switches. Instead of guessing when
// the program is done starting up, the guest waits until a task in the
// command's session is waiting for terminal input. A blocked read is the
// safest form: the read itself consumes the marker, and only one marker is
// queued at a time, so none is left behind for a later raw-mode read. A
// select or poll waiter is also served; the marker makes the descriptor
// readable and the read that follows consumes it.
//
// A VEOF is queued only while the process group is stopped, so a read that was
// blocked in raw mode restarts with the terminal canonical and observes EOF
// instead of the marker as data.
func (s *session) endTTYInput(master *os.File) {
	// Hold our own descriptor: the process reaper closes the session's master
	// as soon as the command exits. Writing to a closed descriptor could hit a
	// reused fd, and the duplicate keeps the PTY object alive while EOF is
	// being delivered. withFD avoids switching the master to blocking mode
	// while the output pump is reading it.
	var fd int
	err := withFD(master, func(mfd int) error {
		var err error
		fd, err = unix.Dup(mfd)
		return err
	})
	if err != nil {
		return
	}
	f := os.NewFile(uintptr(fd), "pty-eof")
	if f == nil {
		_ = unix.Close(fd)
		return
	}
	defer f.Close()
	started := time.Now()
	var last time.Time
	deliveries := 0
	probed := false
	// The command is started with setsid, so its process id is the session
	// id of every task that shares its terminal.
	sid := s.proc.pid
	for !s.processDone() && deliveries < ttyEOFDeliveries {
		blocked, ok := ttyReaderBlocked(sid)
		if ok {
			probed = true
		}
		// Without a readable state, keep the pre-existing behavior: give a
		// startup raw-mode switch a short chance, then queue markers.
		if !probed && time.Since(started) >= ttyEOFSettle {
			blocked = true
		}
		if blocked {
			if time.Since(last) < ttyEOFGap {
				time.Sleep(ttyEOFPoll)
				continue
			}
			s.deliverTTYEOF(f)
			deliveries++
			last = time.Now()
			continue
		}
		// A command that waits in some other way (epoll, wait) may still
		// need EOF, but it cannot be relied on to consume a marker before a
		// later raw-mode switch. Queue one after the bound and stop.
		if time.Since(started) >= ttyEOFTimeout {
			s.deliverTTYEOF(f)
			return
		}
		time.Sleep(ttyEOFPoll)
	}
}

// ttyReaderBlocked reports whether a task in the session sid is waiting for
// its standard input to become readable. ok is false when the process table
// cannot be inspected, in which case the caller falls back to the timed path.
func ttyReaderBlocked(sid int) (blocked, ok bool) {
	if sid <= 0 {
		return false, false
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false, false
	}
	probes := 0
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		base := "/proc/" + e.Name()
		stat, err := os.ReadFile(base + "/stat")
		if err != nil {
			continue
		}
		fields, ok := procStatFields(stat)
		if !ok || len(fields) < 4 {
			continue
		}
		session, err := strconv.Atoi(fields[3])
		if err != nil || session != sid {
			continue
		}
		tasks, err := os.ReadDir(base + "/task")
		if err != nil {
			continue
		}
		for _, task := range tasks {
			call, err := os.ReadFile(base + "/task/" + task.Name() + "/syscall")
			if err != nil {
				continue
			}
			probes++
			if blockedOnStdin(call) {
				return true, true
			}
		}
	}
	return false, probes > 0
}

// procStatFields returns the fields after the comm field of /proc/PID/stat.
// comm can contain spaces and parentheses, so it is skipped by its last ')'.
func procStatFields(stat []byte) ([]string, bool) {
	i := bytes.LastIndexByte(stat, ')')
	if i < 0 || i+1 >= len(stat) {
		return nil, false
	}
	return strings.Fields(string(stat[i+1:])), true
}

// blockedOnStdin reports whether a /proc/PID/syscall line is waiting for
// input on fd 0. Besides read, this covers the select/poll forms used by
// programs (and shells) that wait for terminal readability before reading.
func blockedOnStdin(call []byte) bool {
	fields := strings.Fields(string(call))
	if len(fields) < 2 {
		return false
	}
	nr, err := strconv.Atoi(fields[0])
	if err != nil {
		return false
	}
	arg := func(i int) int64 {
		if i+1 >= len(fields) {
			return -1
		}
		n, err := strconv.ParseInt(fields[i+1], 0, 64)
		if err != nil {
			return -1
		}
		return n
	}
	switch nr {
	case int(unix.SYS_READ), int(unix.SYS_READV):
		return arg(0) == 0
	case int(unix.SYS_PSELECT6):
		// pselect6(nfds, readfds, ...): fd 0 is in range when nfds > 0.
		return arg(0) > 0
	case int(unix.SYS_PPOLL):
		// ppoll(fds, nfds, ...).
		return arg(1) > 0
	}
	return false
}

// processDone reports whether the process has been reaped.
func (s *session) processDone() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.procDone
}

// deliverTTYEOF queues a canonical VEOF for the reader. The process group is
// stopped first so no raw-mode read can turn the byte into data; resuming it
// restarts a blocked read in canonical mode, where the VEOF means EOF.
func (s *session) deliverTTYEOF(f *os.File) {
	stopped := s.signalGroup(unix.SIGSTOP)
	if stopped {
		// A SIGCONT that overtakes the pending stop can leave the group
		// stopped forever; give the stop a moment to take effect before
		// queueing bytes the readers must not consume as data.
		time.Sleep(ttyEOFStopDelay)
	}
	if !ttySetCanonical(f) {
		if stopped {
			s.signalGroup(unix.SIGCONT)
		}
		return
	}
	// Queue one marker. A partial line needs a second marker to reach EOF,
	// but endTTYInput waits until the read that consumes this one blocks
	// again before sending it: a marker left in the queue when a program
	// switches to raw mode is delivered as NUL data.
	_ = f.SetWriteDeadline(time.Now().Add(ttyEOFWriteTimeout))
	_, _ = f.Write([]byte{4})
	_ = f.SetWriteDeadline(time.Time{})
	if stopped {
		s.signalGroup(unix.SIGCONT)
	}
}

// ttySetCanonical switches a terminal to canonical input so a VEOF is
// interpreted as end-of-file. It reports whether the setting was applied.
func ttySetCanonical(f *os.File) bool {
	err := withFD(f, func(fd int) error {
		st, err := unix.IoctlGetTermios(fd, unix.TCGETS)
		if err != nil {
			return err
		}
		st.Lflag |= unix.ICANON
		return unix.IoctlSetTermios(fd, unix.TCSETS, st)
	})
	return err == nil
}

// queueInput appends stdin.
//
// A terminal session's input is best-effort: if the process stops reading,
// maxPendingInput is queued and further stdin is dropped rather than closing
// the client. A terminal client may keep writing (for example a redirected
// /dev/zero) while the user presses Ctrl-C, and the signal has to reach the
// process instead of failing on a dead session. A person typing never sends
// megabytes without the process reading them.
//
// A non-terminal session is a byte stream, not a person typing: commands
// upload data through it and dropping a frame would corrupt the stream. The
// first maxQueuedInput bytes are accepted without waiting, so a burst or a
// multi-second pause before the reader starts is absorbed and the frame loop
// keeps reading control frames. Beyond that the writer waits for the pump to
// make space; the wait propagates through the client's transport as
// backpressure. If the hard bound stays full and the pump writes nothing for
// inputStallTimeout, the process is not reading: further input is shed (with
// one throttled notice) so a forwarded signal or a client disconnect can
// still be read. closeInput wakes the wait when the process exits.
func (s *session) queueInput(payload []byte) error {
	s.inMu.Lock()
	defer s.inMu.Unlock()
	if s.inDone {
		return nil
	}
	// Bytes dequeued by the pump are still in flight to the process and
	// must count against the limit too. inBytes alone made the queue look
	// empty while the pump was blocked writing a batch.
	space := func() int {
		n := maxQueuedInput - s.inBytes - s.inFlight
		if n < 0 {
			return 0
		}
		return n
	}
	if s.tty {
		if len(payload) > maxPendingInput-s.inBytes-s.inFlight {
			s.dropInputLocked()
			return nil
		}
		s.inQueue = append(s.inQueue, payload)
		s.inBytes += len(payload)
		s.inCond.Signal()
		return nil
	}
	// The process is reading again (or was never stalled): accept input that
	// now fits instead of continuing to shed it.
	if s.inStalled && len(payload) <= space() {
		s.inStalled = false
	}
	if s.inStalled {
		s.inTruncated = true
		s.dropInputLocked()
		return nil
	}
	if len(payload) <= space() {
		s.inQueue = append(s.inQueue, payload)
		s.inBytes += len(payload)
		s.inCond.Signal()
		return nil
	}
	// The hard bound is full. Wait for the pump, but time out when it makes
	// no write progress at all: a reader that is merely slow frees budget
	// after every chunk and resets the stall clock.
	if s.inFullSince.IsZero() {
		s.inFullSince = time.Now()
	}
	var timer *time.Timer
	arm := func() {
		if timer != nil {
			timer.Stop()
		}
		timer = time.AfterFunc(inputStallTimeout, func() {
			s.inMu.Lock()
			s.inCond.Broadcast()
			s.inMu.Unlock()
		})
	}
	arm()
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for !s.inDone && len(payload) > space() {
		s.inCond.Wait()
		if s.inDone || len(payload) <= space() {
			break
		}
		if !s.inFullSince.IsZero() && time.Since(s.inFullSince) >= inputStallTimeout {
			// The hard bound stayed full with no write progress long
			// enough to call the reader stuck. Shed the frame so the
			// frame loop can read the signal, EOF or transport close
			// behind it.
			s.inStalled = true
			s.inTruncated = true
			s.dropInputLocked()
			return nil
		}
		if s.inFullSince.IsZero() {
			// The pump made progress; the clock starts over from here.
			s.inFullSince = time.Now()
		}
		arm()
	}
	// closeInput may have woken a writer waiting for queue space. Do not
	// resurrect the queue after EOF or process exit.
	if s.inDone {
		return nil
	}
	s.inQueue = append(s.inQueue, payload)
	s.inBytes += len(payload)
	s.inCond.Signal()
	return nil
}

// dropInputLocked records discarded terminal stdin. Notices are throttled: a
// client flooding input must not produce one warning per frame.
func (s *session) dropInputLocked() {
	if s.inDropped {
		return
	}
	if !s.inNotice.IsZero() && time.Since(s.inNotice) < inputNoticeInterval {
		return
	}
	s.inDropped = true
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
	s.inStalled = false
	s.inFullSince = time.Time{}
	s.inCond.Broadcast()
	s.inMu.Unlock()
}

// clearReplayLocked drops a finished non-primary session's replay output. It
// is called when the last client detaches; a session that no client ever
// attached to keeps its output (bounded by the ring) for a late caller.
func (s *session) clearReplayLocked() {
	if clear, _ := sessionRetention(s.id == wire.PrimarySession, s.exited, s.attached, s.clients); clear {
		s.out.clear()
	}
}

func (s *session) finish(st wire.Exit) {
	s.closeInput()
	// The process can no longer write, so the mirror has nothing left to
	// follow. stop drains the console queue and joins its goroutine.
	s.mirror.stop()
	s.mu.Lock()
	s.exited, s.status = true, st
	// A command that fails or finishes before its caller attaches keeps its
	// output: only a client that has already consumed the session may drop it.
	s.clearReplayLocked()
	_, drop := sessionRetention(s.id == wire.PrimarySession, s.exited, s.attached, s.clients)
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
		if rec := g.openIDs[s.openID]; rec != nil && rec.session == s && rec.complete() {
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

// sessionInfo is a consistent snapshot of a session for tests and diagnostics.
type sessionInfo struct {
	ID      string
	Argv    []string
	TTY     bool
	Clients int
	Exited  bool
}

func (s *session) info() sessionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	return sessionInfo{ID: s.id, Argv: s.argv, TTY: s.tty, Clients: s.clients, Exited: s.exited}
}

// signal sends sig to the command's process group, falling back to the process
// itself. It reports whether a signal was attempted.
func (s *session) signal(sig unix.Signal) bool {
	p := s.proc
	if p == nil || p.pid <= 0 {
		return false
	}
	if unix.Kill(-p.pid, sig) != nil {
		_ = unix.Kill(p.pid, sig)
	}
	return true
}

// signalGroup sends sig to the command's process group only. Once the group
// leader may have been reaped its PID can be reused, so falling back to
// signalling the PID alone could hit an unrelated process. A missing group
// reports false: there is nothing left to signal.
func (s *session) signalGroup(sig unix.Signal) bool {
	p := s.proc
	if p == nil || p.pid <= 0 {
		return false
	}
	return unix.Kill(-p.pid, sig) == nil
}

// terminate ends a detached exec command. Its last client is gone, so no one
// can reach the session to signal it or ever attach to it again. The command
// gets detachGrace to clean up before the process group is killed.
func (s *session) terminate() {
	s.mu.Lock()
	detached := s.clients == 0
	s.mu.Unlock()
	if !detached {
		return
	}
	// Signal the group rather than the leader: the leader may already have
	// exited on SIGTERM while a background child in its group ignored it. A
	// group that no longer exists has nothing left to clean up.
	if !s.signalGroup(unix.SIGTERM) {
		return
	}
	go func() {
		time.Sleep(detachGrace)
		s.mu.Lock()
		detached := s.clients == 0
		s.mu.Unlock()
		if detached {
			// The leader may have been reaped during the grace period. Its
			// process group ID is still valid while any member survives, so
			// do not skip the kill because s.exited is set: only the group's
			// disappearance makes it unnecessary.
			s.signalGroup(unix.SIGKILL)
		}
	}()
}

// watchPeerClose calls gone when the peer closes the stream, even while the
// session frame loop is blocked waiting for stdin queue space. Polling for a
// hangup does not consume buffered frames, so it can distinguish a closed
// transport from data that is merely waiting to be read. Connections without a
// file descriptor (for example net.Pipe in tests) fall back to the frame loop
// noticing the close after it is unblocked.
func watchPeerClose(conn io.Closer, stop <-chan struct{}, gone func()) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return
	}
	var fd int
	if err := raw.Control(func(f uintptr) { fd = int(f) }); err != nil {
		return
	}
	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLRDHUP}}
	for {
		select {
		case <-stop:
			return
		default:
		}
		pfd[0].Revents = 0
		n, err := unix.Poll(pfd, 100)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return
		}
		if n > 0 && pfd[0].Revents&(unix.POLLRDHUP|unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
			gone()
			return
		}
	}
}

// serve attaches a client until it disconnects or the session ends. A
// follower receives retained and live output but is not registered as a
// reader, so its cursor never pins the replay ring and never backpressures
// the command.
func (s *session) serve(c *wire.Conn, conn io.Closer, follow bool) {
	cl := &client{}
	s.mu.Lock()
	s.clients++
	s.attached = true
	if !follow {
		if s.readers == nil {
			s.readers = map[*client]struct{}{}
		}
		s.readers[cl] = struct{}{}
	}
	s.mu.Unlock()
	s.g.addClients(1)
	// A stdin frame can block the frame loop when the hard input bound is
	// full. An exec client may close the transport while that happens (it
	// detached after its signal grace, or was killed). Watching for the
	// close independently wakes the loop and stops input so the deferred
	// detach below runs instead of leaving the command draining an
	// unwatched upload. A primary session stays attached by design and
	// keeps its stdin for a later client, so it is not watched.
	stopWatch := make(chan struct{})
	watchDone := make(chan struct{})
	if s.id != wire.PrimarySession {
		go func() {
			defer close(watchDone)
			watchPeerClose(conn, stopWatch, s.closeInput)
		}()
	} else {
		close(watchDone)
	}
	// Register the reader before releasing held pumps. pinLocked must see
	// it, or output produced during the handshake could overflow the replay
	// ring before write starts draining it. A follower deliberately has no
	// such pin, so held pumps still release but output may be trimmed.
	s.releasePumps()
	defer func() {
		close(stopWatch)
		<-watchDone
		conn.Close()
		s.mu.Lock()
		cl.closed = true
		s.clients--
		delete(s.readers, cl)
		s.clearReplayLocked()
		_, drop := sessionRetention(s.id == wire.PrimarySession, s.exited, s.attached, s.clients)
		// Exec sessions have no way to reattach from the CLI, so a command
		// whose last client vanished would keep running unreachable. Primary
		// commands stay detached by design. This applies even when the group
		// leader has already exited: a background child may still be in the
		// command's process group.
		detach := s.id != wire.PrimarySession && s.clients == 0
		s.cond.Broadcast()
		s.mu.Unlock()
		s.g.addClients(-1)
		if drop {
			s.g.removeSession(s)
		}
		if detach {
			s.terminate()
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
				Message: "stdin was discarded because the command is not reading it; interrupt the command or close the connection to stop sending",
			})
		}
	}
}

// takeDropped reports and clears a pending input-overflow notice. It records
// when the notice was sent so dropInputLocked can throttle the next one.
func (s *session) takeDropped() bool {
	s.inMu.Lock()
	defer s.inMu.Unlock()
	if !s.inDropped {
		return false
	}
	s.inDropped = false
	s.inNotice = time.Now()
	return true
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
			s.signal(sig)
		}
	}
	return nil
}

// serveSession handles one connection on the session port.
func (g *Guest) serveSession(f io.ReadWriteCloser) {
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
		s.serve(c, f, o.Follow)
	case wire.OpenExec:
		s, err := g.openExec(o)
		if err != nil {
			rejectStart(c, f, err)
			return
		}
		if c.WriteJSON(wire.TOpened, wire.Opened{Session: s.id, TTY: s.tty}) != nil {
			f.Close()
			s.releasePumps()
			// Without an OpenID, no client can retry and attach to this
			// session: the session ID only travels in the TOpened that
			// failed. Treat that like a detach so the just-started group
			// cannot run unreachable. With an OpenID the client is expected
			// to retry and attach to this very session (see
			// TestExecOpenIDDeduplicatesRetries), so it must survive.
			if s.openID == "" {
				s.terminate()
			}
			return
		}
		s.serve(c, f, o.Follow)
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
	_ = c.WriteJSON(wire.TOpened, wire.Opened{Error: boundErrorText(err.Error())})
	f.Close()
}

// rejectStart rejects an exec open. If the failure happened while starting the
// command, the conventional exit status travels with the error so the client
// can return 126/127 instead of a plain exit 1 that is indistinguishable from
// a command that ran and exited 1.
func rejectStart(c *wire.Conn, f io.Closer, err error) {
	var se *startError
	if errors.As(err, &se) {
		_ = c.WriteJSON(wire.TOpened, wire.Opened{Error: boundErrorText(err.Error()), Code: se.code})
	} else {
		_ = c.WriteJSON(wire.TOpened, wire.Opened{Error: boundErrorText(err.Error())})
	}
	f.Close()
}

// maxErrorText bounds start and open error text sent in one frame. A single
// client argument can be nearly 128 KiB and JSON escapes control bytes six
// times, so an unbounded start error can exceed wire.MaxFrame. The TOpened
// write would then fail, the connection would close, and the client would
// report a VM lifecycle failure instead of the real 126.
const maxErrorText = 4 << 10

const truncatedMarker = "... (truncated)"

// boundErrorText shortens s to maxErrorText bytes without splitting a UTF-8
// sequence. Invalid bytes are replaced only here, in the human-readable error,
// so the frame is always valid JSON and deterministic in size.
func boundErrorText(s string) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	if len(s) <= maxErrorText {
		return s
	}
	limit := maxErrorText - len(truncatedMarker)
	for limit > 0 && !utf8.RuneStart(s[limit]) {
		limit--
	}
	return s[:limit] + truncatedMarker
}

func (s *session) tail(max int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.out.tail(max)
}
