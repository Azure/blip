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
	p, err := startForwarder("Kubernetes API", 0, func() (apiStream, error) {
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

func TestAPIForwarderFailureBlocksClaim(t *testing.T) {
	g := &Guest{kubeNamespace: "sandbox"}
	claim := wire.Claim{ID: "root"}
	if err := g.doClaim(claim); err == nil || !strings.Contains(err.Error(), "forwarding is unavailable") {
		t.Fatalf("claim with missing API = %v", err)
	}
	p, err := startForwarder("Kubernetes API", 0, func() (apiStream, error) { return nil, errors.New("unused") })
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	port := p.listener.Addr().(*net.TCPAddr).Port
	if other, err := startForwarder("Kubernetes API", port, nil); err == nil {
		other.Close()
		t.Fatal("listener startup ignored an occupied port")
	}
	g.api = p
	p.Close()
	if err := g.doClaim(claim); err == nil || !strings.Contains(err.Error(), "forwarding is unavailable") {
		t.Fatalf("claim with closed API = %v", err)
	}
	if g.claim != nil {
		t.Fatal("claim accepted without a working API listener")
	}
}

func TestAPIForwarderDialFailureClosesClient(t *testing.T) {
	p, err := startForwarder("Kubernetes API", 0, func() (apiStream, error) { return nil, errors.New("unavailable") })
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
	p, err := startForwarder("gateway", 0, func() (apiStream, error) { return host, nil })
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

func TestGatewayForwarderFailureBlocksClaim(t *testing.T) {
	g := &Guest{}
	claim := wire.Claim{ID: "root"}
	if err := g.doClaim(claim); err != errNotInit {
		t.Fatalf("claim without gateway = %v, want %v", err, errNotInit)
	}
	p, err := startForwarder("gateway", 0, func() (apiStream, error) { return nil, errors.New("unused") })
	if err != nil {
		t.Fatal(err)
	}
	g.gateway = p
	p.Close()
	if err := g.doClaim(claim); err == nil || !strings.Contains(err.Error(), "gateway forwarding is unavailable") {
		t.Fatalf("claim with closed gateway = %v", err)
	}
	if g.claim != nil {
		t.Fatal("claim accepted without a working gateway listener")
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
	p, err := startForwarder("Kubernetes API", 0, func() (apiStream, error) { return host, nil })
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
