package slot

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Port forwarding (Blip spec.ports). blipd slot listens on the pod
// loopback (127.0.0.1 and, best effort, [::1]) on each port of the
// assignment, so `kubectl port-forward pod/<slot-pod> L:P` reaches it, and
// proxies each connection to the same port number on the guest's AF_VSOCK
// side through the hybrid vsock socket: "CONNECT <port>\n" -> "OK <n>\n",
// then raw bytes both ways. Guest services listen on vsock (for example
// systemd ListenStream=vsock::22).

// forwardDialRetry is how long a connection waits for the guest to accept.
const forwardDialRetry = 500 * time.Millisecond

// forwardPorts waits for the assignment in runDir, then forwards its ports
// until ctx ends. It returns once all listeners are closed.
func forwardPorts(ctx context.Context, runDir string, poll time.Duration) {
	var a *Assignment
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		if as, err := readAssignment(runDir); err == nil {
			a = as
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
	if len(a.Ports) == 0 {
		return
	}
	f := &forwarder{socket: filepath.Join(runDir, FileVsock)}
	var lns []net.Listener
	for _, p := range a.Ports {
		ln, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(p))))
		if err != nil {
			logf("forward port %d: %v", p, err)
			continue
		}
		lns = append(lns, ln)
		if ln6, err := net.Listen("tcp6", net.JoinHostPort("::1", strconv.Itoa(int(p)))); err == nil {
			lns = append(lns, ln6)
		}
		logf("forwarding pod loopback port %d to the guest", p)
	}
	var wg sync.WaitGroup
	for _, ln := range lns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f.serve(ctx, ln)
		}()
	}
	<-ctx.Done()
	for _, ln := range lns {
		ln.Close()
	}
	wg.Wait()
}

type forwarder struct {
	socket string
}

// serve accepts on ln until it is closed, forwarding each connection to
// the guest port of ln.
func (f *forwarder) serve(ctx context.Context, ln net.Listener) {
	port := uint32(ln.Addr().(*net.TCPAddr).Port)
	for {
		c, err := ln.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				logf("forward port %d: accept: %v", port, err)
			}
			return
		}
		go func() {
			if err := f.forward(ctx, c, port); err != nil {
				logf("forward port %d: %v", port, err)
			}
		}()
	}
}

func (f *forwarder) forward(ctx context.Context, c net.Conn, port uint32) error {
	defer c.Close()
	var g net.Conn
	var err error
	end := time.Now().Add(forwardDialRetry)
	for {
		g, err = dialGuestPort(ctx, f.socket, port)
		if err == nil || time.Now().After(end) || ctx.Err() != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		return err
	}
	defer g.Close()
	Splice(c, g)
	return nil
}

// dialGuestPort opens a stream to the guest's vsock port through the
// hybrid vsock socket. A port without a listener closes without a reply.
func dialGuestPort(ctx context.Context, socket string, port uint32) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprintf(c, "CONNECT %d\n", port); err != nil {
		c.Close()
		return nil, err
	}
	line, err := readLine(c)
	if err != nil || !strings.HasPrefix(line, "OK ") {
		c.Close()
		return nil, fmt.Errorf("vsock handshake: %q %v", line, err)
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

// readLine reads one line byte by byte, so no stream data is buffered away.
func readLine(c io.Reader) (string, error) {
	var line []byte
	b := make([]byte, 1)
	for {
		if _, err := io.ReadFull(c, b); err != nil {
			return string(line), err
		}
		if b[0] == '\n' {
			return string(line), nil
		}
		line = append(line, b[0])
		if len(line) > 256 {
			return string(line), errors.New("line too long")
		}
	}
}

// Splice copies a to b and b to a until both directions end. When one
// side reaches EOF the other side's write half is closed (if it supports
// CloseWrite), so half-closed streams work. It closes neither connection.
func Splice(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, err := io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok && err == nil {
			_ = cw.CloseWrite()
		} else {
			// Error, or no half-close: end both directions.
			_ = dst.Close()
			_ = src.Close()
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}
