package guest

import (
	"errors"
	"io"
	"log"
	"net"
	"os"
	"sync"
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
	mu       sync.Mutex
	closed   bool
	conns    map[apiStream]struct{}
}

// startForwarder binds the requested IPv4 address, including port 0 in tests.
func startForwarder(name, address string, dial func() (apiStream, error)) (*apiForwarder, error) {
	l, err := net.Listen("tcp4", address)
	if err != nil {
		return nil, err
	}
	p := &apiForwarder{name: name, listener: l, dial: dial, conns: map[apiStream]struct{}{}}
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
	pump := func(dst, src apiStream) {
		_, err := io.Copy(dst, src)
		if err == nil {
			err = dst.CloseWrite()
		}
		if err != nil {
			// An error must also wake the other copy, which may be waiting
			// indefinitely on a watch or upgraded stream.
			client.Close()
			host.Close()
		}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		pump(host, client)
	}()
	pump(client, host)
	<-done
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
