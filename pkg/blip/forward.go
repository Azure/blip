package blip

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// ForwardedPort represents an active port-forwarding listener.
// It is returned by [Blip.Forward] and [Blip.ReverseForward].
//
// Call [ForwardedPort.Close] to stop the listener and tear down all
// forwarded connections.
type ForwardedPort struct {
	// Addr is the address the listener is bound to. For local forwarding
	// this is a local address; for reverse forwarding it is the address
	// on the blip VM.
	Addr net.Addr

	cancel context.CancelFunc
	wg     sync.WaitGroup

	// closer is the resource to close when shutting down.
	// For local forwarding it is the net.Listener; for reverse
	// forwarding it is a channel-close sentinel.
	closer io.Closer
}

// Close stops the port-forwarding listener and waits for all in-flight
// connections to finish. Close is safe to call multiple times.
func (f *ForwardedPort) Close() error {
	f.cancel()
	err := f.closer.Close()
	f.wg.Wait()
	return err
}

// Forward starts local port forwarding, analogous to ssh -L.
//
// It listens on localAddr (e.g. "127.0.0.1:8080" or ":0" for a random port)
// and forwards each accepted connection to remoteAddr (e.g. "localhost:5432")
// on the blip VM via an SSH direct-tcpip channel.
//
// The returned [ForwardedPort] contains the actual bound address (useful
// when localAddr uses port 0) and must be closed to release resources.
//
// The forwarding runs until ctx is cancelled or [ForwardedPort.Close] is
// called.
//
//	fwd, err := b.Forward(ctx, "127.0.0.1:0", "localhost:5432")
//	if err != nil { ... }
//	defer fwd.Close()
//	fmt.Println("forwarding on", fwd.Addr)
func (b *Blip) Forward(ctx context.Context, localAddr, remoteAddr string) (*ForwardedPort, error) {
	conn, err := b.sshConn()
	if err != nil {
		return nil, err
	}

	remoteHost, remotePortStr, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("parse remote address %q: %w", remoteAddr, err)
	}

	ln, err := net.Listen("tcp", localAddr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", localAddr, err)
	}

	ctx, cancel := context.WithCancel(ctx)
	fwd := &ForwardedPort{
		Addr:   ln.Addr(),
		cancel: cancel,
		closer: ln,
	}

	fwd.wg.Add(1)
	go func() {
		defer fwd.wg.Done()
		forwardLocalAcceptLoop(ctx, ln, conn, remoteHost, remotePortStr, &fwd.wg)
	}()

	return fwd, nil
}

// forwardLocalAcceptLoop accepts connections on ln and forwards each to
// remoteHost:remotePort via the SSH connection.
func forwardLocalAcceptLoop(ctx context.Context, ln net.Listener, conn *ssh.Client, remoteHost, remotePort string, wg *sync.WaitGroup) {
	remotePortInt, _ := net.LookupPort("tcp", remotePort)

	for {
		local, err := ln.Accept()
		if err != nil {
			// Listener closed — normal shutdown.
			return
		}

		select {
		case <-ctx.Done():
			local.Close()
			return
		default:
		}

		originAddr, originPortStr, _ := net.SplitHostPort(local.LocalAddr().String())
		originPort, _ := net.LookupPort("tcp", originPortStr)

		wg.Add(1)
		go func() {
			defer wg.Done()
			defer local.Close()

			ch, err := dialDirectTCP(conn, remoteHost, uint32(remotePortInt), originAddr, uint32(originPort))
			if err != nil {
				return
			}
			defer ch.Close()

			bidirectionalCopy(ctx, local, ch)
		}()
	}
}

// Dial opens a direct-tcpip connection through the blip VM to the given
// address. This is the programmatic equivalent of ssh -W.
//
// The returned [net.Conn] tunnels TCP traffic through the SSH connection.
// Callers are responsible for closing it.
//
//	conn, err := b.Dial(ctx, "tcp", "internal-service:8080")
//	if err != nil { ... }
//	defer conn.Close()
func (b *Blip) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("unsupported network %q; only tcp is supported", network)
	}

	conn, err := b.sshConn()
	if err != nil {
		return nil, err
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("parse address %q: %w", addr, err)
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return nil, fmt.Errorf("resolve port %q: %w", portStr, err)
	}

	ch, err := dialDirectTCP(conn, host, uint32(port), "127.0.0.1", 0)
	if err != nil {
		return nil, err
	}

	return &chanConn{Channel: ch, laddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}, raddr: &net.TCPAddr{IP: net.ParseIP(host), Port: port}}, nil
}

// ReverseForward starts remote port forwarding, analogous to ssh -R.
//
// It requests the blip VM to listen on remoteAddr (e.g. "0.0.0.0:9090")
// and forwards each connection back to localAddr (e.g. "localhost:9090")
// on the machine running this code.
//
// The returned [ForwardedPort] must be closed to cancel the forwarding.
//
//	fwd, err := b.ReverseForward(ctx, "0.0.0.0:9090", "localhost:9090")
//	if err != nil { ... }
//	defer fwd.Close()
func (b *Blip) ReverseForward(ctx context.Context, remoteAddr, localAddr string) (*ForwardedPort, error) {
	conn, err := b.sshConn()
	if err != nil {
		return nil, err
	}

	remoteHost, remotePortStr, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("parse remote address %q: %w", remoteAddr, err)
	}
	remotePort, err := net.LookupPort("tcp", remotePortStr)
	if err != nil {
		return nil, fmt.Errorf("resolve remote port %q: %w", remotePortStr, err)
	}

	// Send a tcpip-forward global request to the SSH server.
	payload := ssh.Marshal(struct {
		Addr string
		Port uint32
	}{
		Addr: remoteHost,
		Port: uint32(remotePort),
	})

	ok, resp, err := conn.SendRequest("tcpip-forward", true, payload)
	if err != nil {
		return nil, fmt.Errorf("tcpip-forward request: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("tcpip-forward request rejected by server")
	}

	// If we requested port 0, the server tells us the actual port.
	actualPort := uint32(remotePort)
	if remotePort == 0 && len(resp) >= 4 {
		actualPort = uint32(resp[0])<<24 | uint32(resp[1])<<16 | uint32(resp[2])<<8 | uint32(resp[3])
	}

	ctx, cancel := context.WithCancel(ctx)
	closeCh := make(chan struct{})
	fwd := &ForwardedPort{
		Addr: &net.TCPAddr{
			IP:   net.ParseIP(remoteHost),
			Port: int(actualPort),
		},
		cancel: cancel,
		closer: &channelCloser{ch: closeCh},
	}

	// Listen for forwarded-tcpip channels from the server.
	// Note: ssh.Client only allows one HandleChannelOpen per type, and the
	// gateway may already be forwarding channels. We use the existing
	// connection's channel mechanism.
	forwardedChans := conn.HandleChannelOpen("forwarded-tcpip")

	fwd.wg.Add(1)
	go func() {
		defer fwd.wg.Done()
		reverseForwardLoop(ctx, forwardedChans, localAddr, remoteHost, actualPort, &fwd.wg)
	}()

	return fwd, nil
}

// reverseForwardLoop handles incoming forwarded-tcpip channels, connecting
// each to localAddr.
func reverseForwardLoop(ctx context.Context, chans <-chan ssh.NewChannel, localAddr string, boundHost string, boundPort uint32, wg *sync.WaitGroup) {
	for {
		select {
		case <-ctx.Done():
			return
		case newCh, ok := <-chans:
			if !ok {
				return
			}

			wg.Add(1)
			go func() {
				defer wg.Done()
				handleReverseForwardChannel(ctx, newCh, localAddr)
			}()
		}
	}
}

// handleReverseForwardChannel accepts a forwarded-tcpip channel and bridges
// it with a local TCP connection.
func handleReverseForwardChannel(ctx context.Context, newCh ssh.NewChannel, localAddr string) {
	ch, _, err := newCh.Accept()
	if err != nil {
		return
	}
	defer ch.Close()

	local, err := net.Dial("tcp", localAddr)
	if err != nil {
		return
	}
	defer local.Close()

	bidirectionalCopy(ctx, local, ch)
}

// bidirectionalCopy copies data between a and b until one side closes or
// ctx is cancelled.
func bidirectionalCopy(ctx context.Context, a io.ReadWriteCloser, b io.ReadWriteCloser) {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{}, 2)

	go func() {
		io.Copy(a, b)
		cancel()
		done <- struct{}{}
	}()

	go func() {
		io.Copy(b, a)
		cancel()
		done <- struct{}{}
	}()

	<-done
	// Close both sides to unblock the remaining copy.
	a.Close()
	b.Close()
	<-done
}

// dialDirectTCP opens a direct-tcpip channel through the SSH connection.
func dialDirectTCP(conn *ssh.Client, host string, port uint32, originAddr string, originPort uint32) (ssh.Channel, error) {
	payload := ssh.Marshal(struct {
		Host       string
		Port       uint32
		OriginAddr string
		OriginPort uint32
	}{
		Host:       host,
		Port:       port,
		OriginAddr: originAddr,
		OriginPort: originPort,
	})

	ch, reqs, err := conn.OpenChannel("direct-tcpip", payload)
	if err != nil {
		return nil, fmt.Errorf("open direct-tcpip channel to %s:%d: %w", host, port, err)
	}
	go ssh.DiscardRequests(reqs)
	return ch, nil
}

// chanConn wraps an ssh.Channel to satisfy net.Conn.
type chanConn struct {
	ssh.Channel
	laddr net.Addr
	raddr net.Addr
}

func (c *chanConn) LocalAddr() net.Addr                { return c.laddr }
func (c *chanConn) RemoteAddr() net.Addr               { return c.raddr }
func (c *chanConn) SetDeadline(_ time.Time) error      { return nil }
func (c *chanConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *chanConn) SetWriteDeadline(_ time.Time) error { return nil }

// channelCloser is an io.Closer backed by a channel for signalling.
type channelCloser struct {
	once sync.Once
	ch   chan struct{}
}

func (c *channelCloser) Close() error {
	c.once.Do(func() { close(c.ch) })
	return nil
}
