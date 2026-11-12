package dhcp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"golang.org/x/sys/unix"
)

// Server serves one Config on one interface.
type Server struct {
	mu  sync.Mutex
	cfg Config
	Log *slog.Logger
}

// New returns a server for cfg.
func New(cfg Config) *Server { return &Server{cfg: cfg} }

// SetConfig replaces the config; it applies to the next request.
func (s *Server) SetConfig(cfg Config) {
	s.mu.Lock()
	s.cfg = cfg
	s.mu.Unlock()
}

// Config returns a copy of the current config.
func (s *Server) Config() Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

// Serve runs a server for cfg on ifname until ctx is done.
func Serve(ctx context.Context, ifname string, cfg Config) error {
	return New(cfg).Serve(ctx, ifname)
}

// filter is a classic BPF program accepting IPv4 UDP to port 67, not
// fragmented.
var filter = []unix.SockFilter{
	{Code: 0x28, K: 12},                    // ldh [12]
	{Code: 0x15, Jt: 0, Jf: 8, K: 0x0800},  // jeq IPv4
	{Code: 0x30, K: 23},                    // ldb [23]
	{Code: 0x15, Jt: 0, Jf: 6, K: 17},      // jeq UDP
	{Code: 0x28, K: 20},                    // ldh [20]
	{Code: 0x45, Jt: 4, Jf: 0, K: 0x1fff},  // jset fragment offset -> drop
	{Code: 0xb1, K: 14},                    // ldxb 4*([14]&0xf)
	{Code: 0x48, K: 16},                    // ldh [x+16]
	{Code: 0x15, Jt: 0, Jf: 1, K: portSrv}, // jeq 67
	{Code: 0x06, K: 0xffff},                // ret accept
	{Code: 0x06, K: 0},                     // ret drop
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// Conn is an open packet socket on one interface.
type Conn struct {
	f   *os.File
	ifi *net.Interface
}

// Close closes the socket.
func (c *Conn) Close() error { return c.f.Close() }

// Listen opens the packet socket on ifname (needs CAP_NET_RAW). It uses
// an ETH_P_ALL packet socket: those see frames before tc ingress runs,
// so a mirred redirect on the interface does not hide DHCP requests from
// it. Open it before dropping capabilities, serve it later.
func Listen(ifname string) (*Conn, error) {
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("packet socket: %w", err)
	}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("attach filter: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifi.Index}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind %s: %w", ifname, err)
	}
	return &Conn{f: os.NewFile(uintptr(fd), "dhcp-"+ifname), ifi: ifi}, nil
}

// Serve listens on ifname and serves until ctx is done.
func (s *Server) Serve(ctx context.Context, ifname string) error {
	c, err := Listen(ifname)
	if err != nil {
		return err
	}
	return s.ServeConn(ctx, c)
}

// ServeConn serves on c until ctx is done, then closes c.
func (s *Server) ServeConn(ctx context.Context, c *Conn) error {
	f, ifi, ifname := c.f, c.ifi, c.ifi.Name
	defer f.Close()
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { f.SetReadDeadline(time.Unix(1, 0)) })
	defer stop()
	log := s.Log
	if log == nil {
		log = slog.Default()
	}
	buf := make([]byte, 65536)
	for {
		var n int
		var from unix.Sockaddr
		var rerr error
		err := rc.Read(func(fd uintptr) bool {
			n, from, rerr = unix.Recvfrom(int(fd), buf, 0)
			return rerr != unix.EAGAIN
		})
		if ctx.Err() != nil {
			return nil
		}
		if err == nil {
			err = rerr
		}
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("read %s: %w", ifname, err)
		}
		if ll, ok := from.(*unix.SockaddrLinklayer); ok && ll.Pkttype == unix.PACKET_OUTGOING {
			continue
		}
		frame, err := s.handleFrame(buf[:n], ifi.HardwareAddr, log)
		if frame == nil || err != nil {
			continue
		}
		var werr error
		dst := &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_IP), Ifindex: ifi.Index, Halen: 6}
		copy(dst.Addr[:], frame[0:6])
		err = rc.Write(func(fd uintptr) bool {
			werr = unix.Sendto(int(fd), frame, 0, dst)
			return werr != unix.EAGAIN
		})
		if err == nil {
			err = werr
		}
		if err != nil {
			log.Warn("dhcp: send", "err", err)
		}
	}
}

// handleFrame returns the reply frame for one received frame, or nil.
func (s *Server) handleFrame(b []byte, srcMAC net.HardwareAddr, log *slog.Logger) ([]byte, error) {
	payload, _, err := ParseFrame(b)
	if err != nil {
		return nil, err
	}
	req, err := dhcpv4.FromBytes(payload)
	if err != nil {
		return nil, err
	}
	cfg := s.Config()
	r, note := Handle(&cfg, req)
	if note != "" {
		log.Info("dhcp: "+note, "xid", req.TransactionID.String(), "mac", req.ClientHWAddr.String())
	}
	if r == nil {
		return nil, nil
	}
	if len(srcMAC) != 6 {
		// A tap always has a MAC; use a locally administered one otherwise.
		srcMAC = net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	}
	return ReplyFrame(&cfg, r, srcMAC, maxSize(req)), nil
}
