// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package guest

import (
	"errors"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type apiStream interface {
	io.ReadWriteCloser
	CloseWrite() error
}

// apiForwarder carries byte streams so HTTP watches and upgraded connections
// need no special handling. It never sees the runtime's API credentials.
type apiForwarder struct {
	name     string // log label, e.g. "Kubernetes API" or "gateway"
	listener net.Listener
	dial     func() (apiStream, error)
	// keepAlive is applied to accepted workload connections. A workload may
	// half-close its request side and keep reading a streamed response; the
	// kernel answers keepalive probes for it. A workload that is really gone
	// cannot answer, which is the only way TCP can reveal a full close after
	// the peer's FIN.
	keepAlive    net.KeepAliveConfig
	pollInterval time.Duration
	mu           sync.Mutex
	closed       bool
	conns        map[apiStream]struct{}
}

// forwarderConfig tunes connection lifetime detection. Production uses
// defaultForwarderConfig; tests shorten the keepalive timings.
type forwarderConfig struct {
	keepAlive    net.KeepAliveConfig
	pollInterval time.Duration
}

func defaultForwarderConfig() forwarderConfig {
	return forwarderConfig{
		keepAlive: net.KeepAliveConfig{
			Enable:   true,
			Idle:     15 * time.Second,
			Interval: 5 * time.Second,
			Count:    3,
		},
		pollInterval: 500 * time.Millisecond,
	}
}

// startForwarder binds the requested IPv4 address, including port 0 in tests.
func startForwarder(name, address string, dial func() (apiStream, error)) (*apiForwarder, error) {
	return startForwarderConfig(name, address, dial, defaultForwarderConfig())
}

func startForwarderConfig(name, address string, dial func() (apiStream, error), cfg forwarderConfig) (*apiForwarder, error) {
	l, err := net.Listen("tcp4", address)
	if err != nil {
		return nil, err
	}
	p := &apiForwarder{
		name: name, listener: l, dial: dial, conns: map[apiStream]struct{}{},
		keepAlive: cfg.keepAlive, pollInterval: cfg.pollInterval,
	}
	if p.pollInterval <= 0 {
		p.pollInterval = 500 * time.Millisecond
	}
	go p.serve()
	return p, nil
}

func (p *apiForwarder) ready() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.closed
}

func (p *apiForwarder) serve() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.Printf("%s accept: %v", p.name, err)
			}
			p.Close()
			return
		}
		c := conn.(*net.TCPConn)
		// Best effort: if keepalive cannot be configured an abandoned idle
		// stream may outlive its workload, but forwarding still works.
		_ = c.SetKeepAliveConfig(p.keepAlive)
		if !p.track(c) {
			c.Close()
			return
		}
		go p.forward(c)
	}
}

func (p *apiForwarder) track(c apiStream) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	p.conns[c] = struct{}{}
	return true
}

func (p *apiForwarder) release(c apiStream) {
	c.Close()
	p.mu.Lock()
	delete(p.conns, c)
	p.mu.Unlock()
}

func (p *apiForwarder) forward(client apiStream) {
	defer p.release(client)
	host, err := p.dial()
	if err != nil {
		log.Printf("%s dial: %v", p.name, err)
		return
	}
	if !p.track(host) {
		host.Close()
		return
	}
	defer p.release(host)

	responseDone := make(chan struct{})
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		_, err := io.Copy(host, client)
		if err == nil {
			err = host.CloseWrite()
		}
		if err != nil {
			// An error must also wake the other copy, which may be waiting
			// indefinitely on a watch or upgraded stream.
			client.Close()
			host.Close()
			return
		}
		// The client's request direction is complete. Keep the host open so
		// a half-closed client can still read the response, but do not hold
		// it forever: a full close after a half-close sends no further TCP
		// segment, so only keepalive can notice that the client is gone.
		if p.clientGone(client, responseDone) {
			client.Close()
			host.Close()
		}
	}()
	_, err = io.Copy(client, host)
	if err == nil {
		err = client.CloseWrite()
	}
	if err != nil {
		client.Close()
		host.Close()
	}
	close(responseDone)
	<-requestDone
}

// clientGone waits until the peer of conn is fully gone. done reports that the
// response direction finished, after which there is nothing left to protect.
//
// It must only be called after the request direction reached EOF and the host
// write side was half-closed. A client that only half-closed is still reading
// the response and answers keepalive probes, so its socket stays healthy. A
// client that fully closed has no process to answer them, so the kernel marks
// this socket with an error once the peer's orphaned FIN_WAIT2 socket expires
// (tcp_fin_timeout) and the next probe fails. That bounds an abandoned idle
// stream instead of leaking it for the life of the VM.
func (p *apiForwarder) clientGone(conn apiStream, done <-chan struct{}) bool {
	ticker := time.NewTicker(p.pollInterval)
	defer ticker.Stop()
	for {
		if streamGone(conn) {
			return true
		}
		select {
		case <-done:
			return false
		case <-ticker.C:
		}
	}
}

// streamGone reports whether the kernel has marked conn as failed. POLLERR
// covers a keepalive timeout and a reset; POLLHUP and POLLNVAL cover a socket
// that is already closed. POLLRDHUP is deliberately ignored: it only means
// the peer half-closed its write side, which must keep working.
func streamGone(conn io.Closer) bool {
	sysc, ok := conn.(syscall.Conn)
	if !ok {
		return false
	}
	raw, err := sysc.SyscallConn()
	if err != nil {
		return true
	}
	gone := false
	err = raw.Control(func(fd uintptr) {
		fds := []unix.PollFd{{Fd: int32(fd)}}
		if n, _ := unix.Poll(fds, 0); n > 0 {
			gone = fds[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0
		}
	})
	return err != nil || gone
}

func (p *apiForwarder) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	conns := make([]apiStream, 0, len(p.conns))
	for c := range p.conns {
		conns = append(conns, c)
	}
	p.mu.Unlock()
	p.listener.Close()
	for _, c := range conns {
		c.Close()
	}
}

func dialHost(port uint32) func() (apiStream, error) {
	return func() (apiStream, error) {
		return dialAPISocket(unix.AF_VSOCK, &unix.SockaddrVM{CID: unix.VMADDR_CID_HOST, Port: port})
	}
}

// dialAPISocket leaves the descriptor nonblocking before os.NewFile adopts
// it. Go's poller then supports deadlines and Close interrupts blocked I/O.
// net.FileConn cannot wrap AF_VSOCK, so retain the pollable file instead.
func dialAPISocket(family int, addr unix.Sockaddr) (_ apiStream, err error) {
	fd, err := unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "api-vsock")
	defer func() {
		if err != nil {
			f.Close()
		}
	}()
	if err = unix.Connect(fd, addr); err != nil {
		if err != unix.EINPROGRESS && err != unix.EINTR {
			return nil, err
		}
		if err = f.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
			return nil, err
		}
		raw, rawErr := f.SyscallConn()
		if rawErr != nil {
			return nil, rawErr
		}
		var connectErr error
		err = raw.Write(func(fd uintptr) bool {
			code, e := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_ERROR)
			if e != nil {
				connectErr = e
				return true
			}
			if code != 0 {
				connectErr = unix.Errno(code)
				return true
			}
			// SO_ERROR can be zero while connect is still pending.
			_, e = unix.Getpeername(int(fd))
			if e == unix.ENOTCONN {
				return false
			}
			connectErr = e
			return true
		})
		if err != nil {
			return nil, err
		}
		if connectErr != nil {
			return nil, connectErr
		}
		if err = f.SetWriteDeadline(time.Time{}); err != nil {
			return nil, err
		}
	}
	return &apiSocket{File: f}, nil
}

type apiSocket struct{ *os.File }

func (s *apiSocket) CloseWrite() error {
	return withFD(s.File, func(fd int) error { return unix.Shutdown(fd, unix.SHUT_WR) })
}
