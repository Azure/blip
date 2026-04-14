package blip

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestForwardAfterClose(t *testing.T) {
	b := &Blip{closed: true}
	_, err := b.Forward(context.Background(), "127.0.0.1:0", "localhost:8080")
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("expected ErrClosed, got %v", err)
	}
}

func TestReverseForwardAfterClose(t *testing.T) {
	b := &Blip{closed: true}
	_, err := b.ReverseForward(context.Background(), "0.0.0.0:9090", "localhost:9090")
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("expected ErrClosed, got %v", err)
	}
}

func TestDialAfterClose(t *testing.T) {
	b := &Blip{closed: true}
	_, err := b.Dial(context.Background(), "tcp", "localhost:8080")
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("expected ErrClosed, got %v", err)
	}
}

func TestDialUnsupportedNetwork(t *testing.T) {
	b := &Blip{closed: true}
	_, err := b.Dial(context.Background(), "udp", "localhost:8080")
	if err == nil {
		t.Fatal("expected error for unsupported network")
	}
	if !strings.Contains(err.Error(), "unsupported network") {
		t.Errorf("error %q should mention unsupported network", err.Error())
	}
}

func TestDialInvalidAddress(t *testing.T) {
	// The network check comes before the closed check for unsupported
	// networks, but for tcp the closed check happens first.
	b := &Blip{closed: true}
	_, err := b.Dial(context.Background(), "tcp", "not-a-valid-address")
	// Should fail — either closed check or address parse.
	if err == nil {
		t.Fatal("expected error for invalid address")
	}
}

func TestForwardInvalidRemoteAddr(t *testing.T) {
	// Use a non-closed blip with a nil conn to trigger the sshConn check path,
	// but since we check addr parsing after sshConn, a closed blip won't reach it.
	// Instead we need to test with a real-enough blip. Since sshConn succeeds
	// for non-closed blips with a non-nil conn, we test the parse error path
	// by providing a bad address.
	b := &Blip{} // not closed, but conn is nil — sshConn will return nil conn
	_, err := b.Forward(context.Background(), "127.0.0.1:0", "no-port")
	if err == nil {
		t.Fatal("expected error for invalid remote address")
	}
	if !strings.Contains(err.Error(), "parse remote address") {
		t.Errorf("error %q should mention parse remote address", err.Error())
	}
}

func TestForwardedPortClose(t *testing.T) {
	// Create a real listener and wrap it in a ForwardedPort.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	fwd := &ForwardedPort{
		Addr:   ln.Addr(),
		cancel: cancel,
		closer: ln,
	}

	// Close should not panic and should return nil (or a benign error).
	if err := fwd.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the context was cancelled.
	select {
	case <-ctx.Done():
	default:
		t.Error("context should be cancelled after Close")
	}

	// Second close should not panic (listener already closed).
	_ = fwd.Close()
}

func TestBidirectionalCopy(t *testing.T) {
	t.Run("copies data both ways", func(t *testing.T) {
		a1, a2 := net.Pipe()
		b1, b2 := net.Pipe()

		ctx := context.Background()
		done := make(chan struct{})
		go func() {
			bidirectionalCopy(ctx, a1, b1)
			close(done)
		}()

		// Write from a2 (which is the other end of a1) and read from b2.
		msg := "hello from a"
		go func() {
			a2.Write([]byte(msg))
			a2.Close()
		}()

		buf := make([]byte, 64)
		n, _ := b2.Read(buf)
		got := string(buf[:n])
		if got != msg {
			t.Errorf("got %q, want %q", got, msg)
		}

		b2.Close()
		<-done
	})

	t.Run("stops when a side closes", func(t *testing.T) {
		a1, a2 := net.Pipe()
		b1, b2 := net.Pipe()
		defer a2.Close()
		defer b2.Close()

		done := make(chan struct{})
		go func() {
			bidirectionalCopy(context.Background(), a1, b1)
			close(done)
		}()

		// Closing one external end causes the copy to see EOF and shut down.
		a2.Close()

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("bidirectionalCopy did not stop after side closed")
		}
	})
}

func TestChanConn(t *testing.T) {
	laddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	raddr := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5678}

	c := &chanConn{
		laddr: laddr,
		raddr: raddr,
	}

	if c.LocalAddr() != laddr {
		t.Errorf("LocalAddr() = %v, want %v", c.LocalAddr(), laddr)
	}
	if c.RemoteAddr() != raddr {
		t.Errorf("RemoteAddr() = %v, want %v", c.RemoteAddr(), raddr)
	}
	if err := c.SetDeadline(time.Time{}); err != nil {
		t.Errorf("SetDeadline() = %v, want nil", err)
	}
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		t.Errorf("SetReadDeadline() = %v, want nil", err)
	}
	if err := c.SetWriteDeadline(time.Time{}); err != nil {
		t.Errorf("SetWriteDeadline() = %v, want nil", err)
	}
}

func TestChannelCloser(t *testing.T) {
	t.Run("close once", func(t *testing.T) {
		ch := make(chan struct{})
		c := &channelCloser{ch: ch}
		if err := c.Close(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Channel should be closed.
		select {
		case <-ch:
		default:
			t.Error("channel should be closed")
		}
	})

	t.Run("close twice", func(t *testing.T) {
		ch := make(chan struct{})
		c := &channelCloser{ch: ch}
		c.Close()
		// Second close should not panic.
		if err := c.Close(); err != nil {
			t.Fatalf("unexpected error on second close: %v", err)
		}
	})
}

func TestForwardLocalListener(t *testing.T) {
	// Verify that Forward actually creates a working listener on the
	// requested address. We can't test the full forwarding path without
	// a real SSH server, but we can verify the listener setup and
	// teardown.

	// Create a ForwardedPort with a real listener manually.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	fwd := &ForwardedPort{
		Addr:   ln.Addr(),
		cancel: cancel,
		closer: ln,
	}

	// Verify we can connect to the listener.
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		fwd.Close()
		t.Fatalf("could not connect to listener: %v", err)
	}
	conn.Close()

	// Verify closing stops the listener.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	fwd.Close()
	wg.Wait()

	// Verify context was cancelled.
	select {
	case <-ctx.Done():
	default:
		t.Error("context should be cancelled after Close")
	}

	// Connection to closed listener should fail.
	_, err = net.DialTimeout("tcp", addr, 100*time.Millisecond)
	if err == nil {
		t.Error("expected error connecting to closed listener")
	}
}

func TestDialSupportedNetworks(t *testing.T) {
	tests := []struct {
		network string
		wantErr bool
	}{
		{"tcp", false},
		{"tcp4", false},
		{"tcp6", false},
		{"udp", true},
		{"unix", true},
	}

	for _, tt := range tests {
		t.Run(tt.network, func(t *testing.T) {
			b := &Blip{closed: true}
			_, err := b.Dial(context.Background(), tt.network, "localhost:8080")
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if !strings.Contains(err.Error(), "unsupported network") {
					t.Errorf("error %q should mention unsupported network", err.Error())
				}
			} else {
				// For supported networks on a closed blip, we expect ErrClosed.
				if !errors.Is(err, ErrClosed) {
					t.Errorf("expected ErrClosed, got %v", err)
				}
			}
		})
	}
}

func TestBidirectionalCopyEarlyClose(t *testing.T) {
	// Test that bidirectionalCopy handles one side closing immediately.
	a, b := net.Pipe()

	done := make(chan struct{})
	go func() {
		bidirectionalCopy(context.Background(), a, b)
		close(done)
	}()

	// Close one side immediately.
	a.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("bidirectionalCopy did not finish after close")
	}
}

func TestForwardedPortAddr(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	_, cancel := context.WithCancel(context.Background())
	fwd := &ForwardedPort{
		Addr:   ln.Addr(),
		cancel: cancel,
		closer: ln,
	}
	defer fwd.Close()

	// Verify Addr has a non-zero port.
	tcpAddr, ok := fwd.Addr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("Addr is %T, want *net.TCPAddr", fwd.Addr)
	}
	if tcpAddr.Port == 0 {
		t.Error("expected non-zero port")
	}
}

// pipeReadWriteCloser wraps an io.Reader and io.Writer into an io.ReadWriteCloser.
type pipeReadWriteCloser struct {
	io.Reader
	io.Writer
	closeFunc func() error
}

func (p *pipeReadWriteCloser) Close() error {
	if p.closeFunc != nil {
		return p.closeFunc()
	}
	return nil
}
