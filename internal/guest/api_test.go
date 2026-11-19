// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package guest

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Azure/blip/internal/wire"
	"golang.org/x/sys/unix"
)

// TestAPIForwarderStream exercises the same nonblocking file wrapper as
// AF_VSOCK with a local TCP backend. The response is visible before request
// EOF, and arbitrary upgraded bytes and half-closes survive both directions.
func TestAPIForwarderStream(t *testing.T) {
	backend, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	p, err := startForwarder("Kubernetes API", "127.0.0.1:0", func() (apiStream, error) {
		return dialAPISocket(unix.AF_INET, &unix.SockaddrInet4{
			Addr: [4]byte{127, 0, 0, 1}, Port: backend.Addr().(*net.TCPAddr).Port,
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if addr := p.listener.Addr().(*net.TCPAddr); !addr.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("API listener is not loopback-only: %v", addr)
	}
	request := "GET /api/v1/namespaces/sandbox/pods?watch=true HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
	response := "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nstreaming"
	payload := []byte{0, 255, 13, 10, 0, 1, 2, 3}
	done := make(chan error, 1)
	go func() {
		conn, err := backend.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		got := make([]byte, len(request))
		if _, err := io.ReadFull(conn, got); err != nil {
			done <- err
			return
		}
		if string(got) != request {
			done <- fmt.Errorf("request changed (including headers): %q", got)
			return
		}
		if _, err := io.WriteString(conn, response); err != nil {
			done <- err
			return
		}
		got, err = io.ReadAll(conn)
		if err != nil || !bytes.Equal(got, payload) {
			done <- fmt.Errorf("upgraded request = %q, %v", got, err)
			return
		}
		_, err = conn.Write(payload)
		done <- err
	}()
	client, err := net.Dial("tcp4", p.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(client, request); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(response))
	if _, err := io.ReadFull(client, got); err != nil || string(got) != response {
		t.Fatalf("streamed response = %q, %v", got, err)
	}
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := client.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err = io.ReadAll(client)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("upgraded response = %q, %v", got, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// testForwarderConfig shortens keepalive detection so tests do not wait for
// the production timings.
func testForwarderConfig() forwarderConfig {
	return forwarderConfig{
		keepAlive: net.KeepAliveConfig{
			Enable:   true,
			Idle:     time.Second,
			Interval: time.Second,
			Count:    1,
		},
		pollInterval: 20 * time.Millisecond,
	}
}

func forwarderConnections(p *apiForwarder) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.conns)
}

// fileHungUp reports whether the peer of an AF_UNIX socket has fully closed
// it. POLLRDHUP alone is a half-close and must not count.
func fileHungUp(t *testing.T, f *os.File) bool {
	t.Helper()
	raw, err := f.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	hungUp := false
	if err := raw.Control(func(fd uintptr) {
		fds := []unix.PollFd{{Fd: int32(fd)}}
		if n, _ := unix.Poll(fds, 0); n > 0 {
			hungUp = fds[0].Revents&unix.POLLHUP != 0
		}
	}); err != nil {
		t.Fatal(err)
	}
	return hungUp
}

func abortOnClose(t *testing.T, conn net.Conn) {
	t.Helper()
	raw, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.Control(func(fd uintptr) {
		if err := unix.SetsockoptLinger(int(fd), unix.SOL_SOCKET, unix.SO_LINGER, &unix.Linger{Onoff: 1}); err != nil {
			t.Errorf("set SO_LINGER: %v", err)
		}
	}); err != nil {
		t.Fatal(err)
	}
}

// TestAPIForwarderFullCloseAfterHalfCloseClosesHost covers an abandoned idle
// stream: the workload half-closes after its request, reads the headers, then
// goes away without any further response traffic. TCP reveals that only by
// reset or keepalive, so the forwarder must keep the host for a live
// half-close but close it once the client socket is dead. The sidecar can then
// cancel the upstream watch instead of holding it forever.
func TestAPIForwarderFullCloseAfterHalfCloseClosesHost(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	host := &apiSocket{File: os.NewFile(uintptr(fds[0]), "host")}
	peer := &apiSocket{File: os.NewFile(uintptr(fds[1]), "peer")}
	defer peer.Close()
	p, err := startForwarderConfig("Kubernetes API", "127.0.0.1:0", func() (apiStream, error) { return host, nil }, testForwarderConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	client, err := net.Dial("tcp4", p.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	_ = peer.SetDeadline(time.Now().Add(10 * time.Second))

	request := "GET /api/v1/pods?watch=true HTTP/1.1\r\nHost: kube-apiserver\r\n\r\n"
	if _, err := io.WriteString(client, request); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(peer, make([]byte, len(request))); err != nil {
		t.Fatalf("host read request: %v", err)
	}
	response := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
	if _, err := io.WriteString(peer, response); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, make([]byte, len(response))); err != nil {
		t.Fatalf("client read headers: %v", err)
	}

	// Half-close: the client is still reading, so the host must not be
	// fully closed. Wait past a keepalive round so the live client's kernel
	// is the one answering the probes.
	if err := client.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2500 * time.Millisecond)
	if fileHungUp(t, peer.File) {
		t.Fatal("forwarder fully closed the host after a half-close")
	}
	if n := forwarderConnections(p); n != 2 {
		t.Fatalf("forwarder tracks %d connection(s) after a half-close, want 2", n)
	}

	// The client is really gone. A reset is how the kernel reports a close
	// that follows a half-close once probing reveals it.
	abortOnClose(t, client)
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for !fileHungUp(t, peer.File) {
		if time.Now().After(deadline) {
			t.Fatal("forwarder kept the host open after the client was fully gone")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for forwarderConnections(p) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("forwarder kept %d connection(s) after the client was fully gone", forwarderConnections(p))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestAPIForwarderClientKeepAlive checks the liveness probe that bounds an
// abandoned idle stream. Only keepalive can reveal a full close that follows
// a half-close, so the accepted workload connection must carry short timings
// rather than the system defaults.
func TestAPIForwarderClientKeepAlive(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	host := &apiSocket{File: os.NewFile(uintptr(fds[0]), "host")}
	peer := &apiSocket{File: os.NewFile(uintptr(fds[1]), "peer")}
	defer peer.Close()
	p, err := startForwarder("Kubernetes API", "127.0.0.1:0", func() (apiStream, error) { return host, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	client, err := net.Dial("tcp4", p.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(client, "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(peer, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}

	var accepted *net.TCPConn
	deadline := time.Now().Add(5 * time.Second)
	for accepted == nil && time.Now().Before(deadline) {
		p.mu.Lock()
		for conn := range p.conns {
			if tc, ok := conn.(*net.TCPConn); ok {
				accepted = tc
				break
			}
		}
		p.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	if accepted == nil {
		t.Fatal("forwarder did not accept the client connection")
	}

	want := defaultForwarderConfig().keepAlive
	raw, err := accepted.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.Control(func(fd uintptr) {
		check := func(name string, level, opt, expected int) {
			got, err := unix.GetsockoptInt(int(fd), level, opt)
			if err != nil {
				t.Errorf("get %s: %v", name, err)
			} else if got != expected {
				t.Errorf("%s = %d, want %d", name, got, expected)
			}
		}
		check("SO_KEEPALIVE", unix.SOL_SOCKET, unix.SO_KEEPALIVE, 1)
		check("TCP_KEEPIDLE", unix.IPPROTO_TCP, unix.TCP_KEEPIDLE, int(want.Idle/time.Second))
		check("TCP_KEEPINTVL", unix.IPPROTO_TCP, unix.TCP_KEEPINTVL, int(want.Interval/time.Second))
		check("TCP_KEEPCNT", unix.IPPROTO_TCP, unix.TCP_KEEPCNT, want.Count)
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAPIForwarderFailureBlocksClaim(t *testing.T) {
	g := &Guest{kubeNamespace: "sandbox"}
	claim := wire.Claim{ID: "root"}
	if err := g.doClaim(claim); err == nil || !strings.Contains(err.Error(), "forwarding is unavailable") {
		t.Fatalf("claim with missing API = %v", err)
	}
	p, err := startForwarder("Kubernetes API", "127.0.0.1:0", func() (apiStream, error) { return nil, errors.New("unused") })
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	addr := p.listener.Addr().String()
	if other, err := startForwarder("Kubernetes API", addr, nil); err == nil {
		other.Close()
		t.Fatal("listener startup ignored an occupied address")
	}
	g.proxy = p
	p.Close()
	if err := g.doClaim(claim); err == nil || !strings.Contains(err.Error(), "forwarding is unavailable") {
		t.Fatalf("claim with closed API = %v", err)
	}
	if g.claim != nil {
		t.Fatal("claim accepted without a working API listener")
	}
}

func TestAPIForwarderDialFailureClosesClient(t *testing.T) {
	p, err := startForwarder("Kubernetes API", "127.0.0.1:0", func() (apiStream, error) { return nil, errors.New("unavailable") })
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	c, err := net.Dial("tcp4", p.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("failed upstream did not close client: %v", err)
	}
}

func TestGatewayForwarderStream(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	host := &apiSocket{File: os.NewFile(uintptr(fds[0]), "host")}
	peer := &apiSocket{File: os.NewFile(uintptr(fds[1]), "peer")}
	defer peer.Close()
	p, err := startForwarder("gateway", "127.0.0.1:0", func() (apiStream, error) { return host, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if p.name != "gateway" {
		t.Fatalf("forwarder label = %q", p.name)
	}
	if addr := p.listener.Addr().(*net.TCPAddr); !addr.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("gateway listener is not loopback-only: %v", addr)
	}
	c, err := net.Dial("tcp4", p.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	req := make([]byte, len("GET / HTTP/1.1\r\n\r\n"))
	if _, err := io.ReadFull(peer, req); err != nil || string(req) != "GET / HTTP/1.1\r\n\r\n" {
		t.Fatalf("upstream request = %q, %v", req, err)
	}
	if _, err := peer.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, len("HTTP/1.1 200 OK\r\n\r\n"))
	if _, err := io.ReadFull(c, resp); err != nil || string(resp) != "HTTP/1.1 200 OK\r\n\r\n" {
		t.Fatalf("downstream response = %q, %v", resp, err)
	}
}

func TestAPIForwarderCloseInterruptsStreams(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	host := &apiSocket{File: os.NewFile(uintptr(fds[0]), "host")}
	peer := &apiSocket{File: os.NewFile(uintptr(fds[1]), "peer")}
	defer host.Close()
	defer peer.Close()
	p, err := startForwarder("Kubernetes API", "127.0.0.1:0", func() (apiStream, error) { return host, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	c, err := net.Dial("tcp4", p.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	_ = peer.SetDeadline(time.Now().Add(time.Second))
	// This round trip ensures both streams are registered and copying.
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(peer, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	p.Close()
	for name, stream := range map[string]io.Reader{"client": c, "host peer": peer} {
		if _, err := stream.Read(make([]byte, 1)); err != io.EOF {
			t.Errorf("%s not closed: %v", name, err)
		}
	}
}
