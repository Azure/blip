// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package guest

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Azure/blip/internal/wire"
)

// stdioConnect starts a guest stdio server and returns a connected client
// after reading the initial StdioHello.
func stdioConnect(t *testing.T, g *Guest) (*wire.Conn, net.Conn, wire.StdioHello) {
	t.Helper()
	host, guest := net.Pipe()
	t.Cleanup(func() { host.Close() })
	go g.serveStdio(guest)
	_ = host.SetDeadline(time.Now().Add(10 * time.Second))
	c := wire.NewConn(host)
	var h wire.StdioHello
	readFrame(t, c, wire.TStdioHello, &h)
	return c, host, h
}

func readStdioData(t *testing.T, c *wire.Conn, want wire.Type) (uint64, []byte) {
	t.Helper()
	typ, payload, err := c.Read()
	if err != nil {
		t.Fatalf("read %d: %v", want, err)
	}
	if typ != want {
		t.Fatalf("frame type = %d, want %d", typ, want)
	}
	off, data, err := wire.DecodeData(payload)
	if err != nil {
		t.Fatal(err)
	}
	return off, data
}

func TestStdioConnectSendsHello(t *testing.T) {
	g := &Guest{stdio: newStdio()}
	_, host, h := stdioConnect(t, g)
	if h.Exit != nil {
		t.Fatalf("hello reported an exit: %+v", h.Exit)
	}
	host.Close()
}

// Output frames carry absolute offsets, so a client can resume without
// duplicating or losing a byte.
func TestStdioOutputOffsets(t *testing.T) {
	s := newStdio()
	s.append(wire.TStdout, []byte("hello "))
	s.append(wire.TStderr, []byte("oops"))
	g := &Guest{stdio: s}

	c, _, _ := stdioConnect(t, g)
	if off, data := readStdioData(t, c, wire.TStdout); off != 0 || string(data) != "hello " {
		t.Fatalf("stdout = %q at %d", data, off)
	}
	if off, data := readStdioData(t, c, wire.TStderr); off != 0 || string(data) != "oops" {
		t.Fatalf("stderr = %q at %d", data, off)
	}

	s.append(wire.TStdout, []byte("world"))
	if off, data := readStdioData(t, c, wire.TStdout); off != 6 || string(data) != "world" {
		t.Fatalf("live stdout = %q at %d, want %q at 6", data, off, "world")
	}
}

// A connection that arrives after the command wrote output replays the
// retained bytes from the start, so early output is never lost.
func TestStdioReplaysBeforeConnect(t *testing.T) {
	s := newStdio()
	s.append(wire.TStdout, []byte("abcdef"))
	g := &Guest{stdio: s}

	c, _, _ := stdioConnect(t, g)
	if off, data := readStdioData(t, c, wire.TStdout); off != 0 || string(data) != "abcdef" {
		t.Fatalf("stdout = %q at %d", data, off)
	}
}

func TestStdioBackpressureWithoutConnection(t *testing.T) {
	s := newStdio()
	s.append(wire.TStdout, bytes.Repeat([]byte("x"), stdioBufferMax))
	done := make(chan struct{})
	go func() {
		s.append(wire.TStdout, []byte("more"))
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("append did not block on a full buffer without a connection")
	case <-time.After(40 * time.Millisecond):
	}

	g := &Guest{stdio: s}
	c, _, _ := stdioConnect(t, g)
	off, data := readStdioData(t, c, wire.TStdout)
	if off != 0 || len(data) != stdioBufferMax {
		t.Fatalf("first frame = %d bytes at %d", len(data), off)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("append stayed blocked after the connection drained")
	}
	off, data = readStdioData(t, c, wire.TStdout)
	if off != stdioBufferMax || string(data) != "more" {
		t.Fatalf("released output = %q at %d", data, off)
	}
}

// stdioGuest is a guest that can run a primary command outside the VM.
func stdioGuest(t *testing.T) *Guest {
	t.Helper()
	return &Guest{
		root:     t.TempDir(),
		cgroupFD: -1,
		mounts:   map[string]*mount{},
		frozen:   map[string]*frozenFS{},
		stdio:    newStdio(),
	}
}

// stdin frames are written to the command's pipe and StdinEOF closes it, so
// cat-like commands see end of input.
func TestStdioStdinAndEOF(t *testing.T) {
	g := stdioGuest(t)
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer inR.Close()
	defer outW.Close()
	defer errW.Close()
	wait := make(chan unix.WaitStatus, 1)

	g.startProcess = func(procSpec, []string) (*proc, error) {
		return &proc{stdin: inW, stdout: outR, stderr: errR, wait: wait}, nil
	}
	g.claim = &wire.Claim{ID: "root", Command: []string{"fake"}}
	g.startPrimary()

	c, _, _ := stdioConnect(t, g)
	if err := c.Write(wire.TStdin, []byte("ping")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(inR, got); err != nil || string(got) != "ping" {
		t.Fatalf("stdin = %q, %v", got, err)
	}

	if err := c.WriteJSON(wire.TStdinEOF, struct{}{}); err != nil {
		t.Fatal(err)
	}
	_ = inR.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 1)
	if n, err := inR.Read(buf); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("stdin after EOF = %d, %v; want 0, EOF", n, err)
	}
}

// The exit status is delivered after the last output, and the guest retains
// it for a later connection.
func TestStdioExit(t *testing.T) {
	g := stdioGuest(t)
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer inR.Close()
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	wait := make(chan unix.WaitStatus, 1)
	g.startProcess = func(procSpec, []string) (*proc, error) {
		return &proc{stdin: inW, stdout: outR, stderr: errR, wait: wait}, nil
	}
	g.claim = &wire.Claim{ID: "root", Command: []string{"fake"}}
	g.startPrimary()

	c, _, h := stdioConnect(t, g)
	if h.Exit != nil {
		t.Fatalf("hello before exit reported %+v", h.Exit)
	}
	if _, err := outW.Write([]byte("done\n")); err != nil {
		t.Fatal(err)
	}
	if err := outW.Close(); err != nil {
		t.Fatal(err)
	}
	if err := errW.Close(); err != nil {
		t.Fatal(err)
	}
	wait <- unix.WaitStatus(3 << 8)

	var out bytes.Buffer
	var ex wire.Exit
	for {
		typ, payload, err := c.Read()
		if err != nil {
			t.Fatalf("read after exit: %v", err)
		}
		switch typ {
		case wire.TStdout:
			_, data, _ := wire.DecodeData(payload)
			out.Write(data)
		case wire.TExited:
			if err := wire.Decode(payload, &ex); err != nil {
				t.Fatal(err)
			}
			goto exited
		default:
			t.Fatalf("unexpected frame %d", typ)
		}
	}
exited:
	if out.String() != "done\n" {
		t.Fatalf("output = %q", out.String())
	}
	if ex.Code != 3 || ex.Reason != wire.ReasonCompleted {
		t.Fatalf("exit = %+v, want code 3 Completed", ex)
	}
	g.mu.Lock()
	stored := g.exit
	g.mu.Unlock()
	if stored == nil || stored.Code != 3 {
		t.Fatalf("stored exit = %+v", stored)
	}

	// A later connection learns the exit and the retained output.
	c2, _, h2 := stdioConnect(t, g)
	if h2.Exit == nil || h2.Exit.Code != 3 {
		t.Fatalf("reconnect hello = %+v", h2)
	}
	if off, data := readStdioData(t, c2, wire.TStdout); off != 0 || string(data) != "done\n" {
		t.Fatalf("replayed output = %q at %d", data, off)
	}
	var rex wire.Exit
	readFrame(t, c2, wire.TExited, &rex)
	if rex.Code != 3 {
		t.Fatalf("replayed exit = %+v", rex)
	}
}

// A command that cannot start reports its stderr and conventional 127.
func TestStdioStartFailure(t *testing.T) {
	g := stdioGuest(t)
	g.startProcess = func(procSpec, []string) (*proc, error) {
		return nil, startFail(127, errors.New("fake: command not found"))
	}
	g.claim = &wire.Claim{ID: "root", Command: []string{"fake"}}
	g.startPrimary()

	c, _, h := stdioConnect(t, g)
	if h.Exit == nil || h.Exit.Code != 127 {
		t.Fatalf("hello = %+v, want a failed exit", h)
	}
	if _, data := readStdioData(t, c, wire.TStderr); !bytes.Contains(data, []byte("command not found")) {
		t.Fatalf("stderr = %q", data)
	}
	var ex wire.Exit
	readFrame(t, c, wire.TExited, &ex)
	if ex.Code != 127 {
		t.Fatalf("exit = %+v, want 127", ex)
	}
}
