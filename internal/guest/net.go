package guest

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// setupNetwork configures lo and eth0 from c and writes /etc/resolv.conf and
// /etc/hosts for later bind mounting into the root.
func setupNetwork(c Config) error {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		return fmt.Errorf("lo: %w", err)
	}
	if err := setLink(lo.Index, 0, nil); err != nil {
		return fmt.Errorf("lo up: %w", err)
	}
	writeEtc(c)
	if c.IP == "" {
		return nil
	}
	ip := net.ParseIP(c.IP).To4()
	if ip == nil || c.Prefix < 0 || c.Prefix > 32 {
		return fmt.Errorf("bad address %s/%d", c.IP, c.Prefix)
	}
	var ifi *net.Interface
	for i := 0; i < 200; i++ {
		if ifi, err = net.InterfaceByName("eth0"); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		return fmt.Errorf("eth0: %w", err)
	}
	var mac net.HardwareAddr
	if c.MAC != "" {
		if mac, err = net.ParseMAC(c.MAC); err != nil {
			return fmt.Errorf("bad mac: %w", err)
		}
	}
	if err := setLink(ifi.Index, c.MTU, mac); err != nil {
		return fmt.Errorf("eth0 up: %w", err)
	}
	if err := addAddr(ifi.Index, ip, c.Prefix); err != nil {
		return fmt.Errorf("eth0 address: %w", err)
	}
	if c.Gateway == "" {
		return nil
	}
	gw := net.ParseIP(c.Gateway).To4()
	if gw == nil {
		return fmt.Errorf("bad gateway %q", c.Gateway)
	}
	subnet := net.IPNet{IP: ip.Mask(net.CIDRMask(c.Prefix, 32)), Mask: net.CIDRMask(c.Prefix, 32)}
	if !subnet.Contains(gw) {
		if err := addRoute(ifi.Index, gw, 32, nil); err != nil {
			return fmt.Errorf("gateway route: %w", err)
		}
	}
	if err := addRoute(ifi.Index, net.IPv4zero.To4(), 0, gw); err != nil {
		return fmt.Errorf("default route: %w", err)
	}
	return nil
}

func writeEtc(c Config) {
	var rc strings.Builder
	for _, s := range c.DNS {
		fmt.Fprintf(&rc, "nameserver %s\n", s)
	}
	if len(c.Search) > 0 {
		fmt.Fprintf(&rc, "search %s\n", strings.Join(c.Search, " "))
	}
	if len(c.Options) > 0 {
		fmt.Fprintf(&rc, "options %s\n", strings.Join(c.Options, " "))
	}
	_ = os.WriteFile("/etc/resolv.conf", []byte(rc.String()), 0o644)
	hosts := "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n"
	if c.IP != "" && c.Hostname != "" {
		hosts += fmt.Sprintf("%s\t%s\n", c.IP, c.Hostname)
	}
	_ = os.WriteFile("/etc/hosts", []byte(hosts), 0o644)
}

func nlAttr(typ uint16, val []byte) []byte {
	l := 4 + len(val)
	b := make([]byte, (l+3)&^3)
	binary.NativeEndian.PutUint16(b[0:2], uint16(l))
	binary.NativeEndian.PutUint16(b[2:4], typ)
	copy(b[4:], val)
	return b
}

func nlU32(v uint32) []byte {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, v)
	return b
}

// nlRequest sends one rtnetlink request and waits for its acknowledgement.
func nlRequest(typ, flags uint16, payload []byte) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 5})
	msg := make([]byte, unix.NLMSG_HDRLEN, unix.NLMSG_HDRLEN+len(payload))
	msg = append(msg, payload...)
	binary.NativeEndian.PutUint32(msg[0:4], uint32(len(msg)))
	binary.NativeEndian.PutUint16(msg[4:6], typ)
	binary.NativeEndian.PutUint16(msg[6:8], flags|unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	binary.NativeEndian.PutUint32(msg[8:12], 1)
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	buf := make([]byte, 8192)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return err
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return err
		}
		for _, m := range msgs {
			if m.Header.Type == unix.NLMSG_ERROR && len(m.Data) >= 4 {
				if code := int32(binary.NativeEndian.Uint32(m.Data[0:4])); code != 0 {
					return unix.Errno(-code)
				}
				return nil
			}
		}
	}
}

// setLink brings a link up, optionally setting MTU and MAC address.
func setLink(index, mtu int, mac net.HardwareAddr) error {
	p := make([]byte, unix.SizeofIfInfomsg)
	binary.NativeEndian.PutUint32(p[4:8], uint32(index))
	binary.NativeEndian.PutUint32(p[8:12], unix.IFF_UP)
	binary.NativeEndian.PutUint32(p[12:16], unix.IFF_UP)
	if mtu > 0 {
		p = append(p, nlAttr(unix.IFLA_MTU, nlU32(uint32(mtu)))...)
	}
	if len(mac) > 0 {
		p = append(p, nlAttr(unix.IFLA_ADDRESS, mac)...)
	}
	return nlRequest(unix.RTM_NEWLINK, 0, p)
}

func addAddr(index int, ip net.IP, prefix int) error {
	p := make([]byte, unix.SizeofIfAddrmsg)
	p[0] = unix.AF_INET
	p[1] = byte(prefix)
	binary.NativeEndian.PutUint32(p[4:8], uint32(index))
	p = append(p, nlAttr(unix.IFA_LOCAL, ip)...)
	p = append(p, nlAttr(unix.IFA_ADDRESS, ip)...)
	return nlRequest(unix.RTM_NEWADDR, unix.NLM_F_CREATE|unix.NLM_F_REPLACE, p)
}

// addRoute adds dst/prefix via gw, or an on-link route when gw is nil.
func addRoute(index int, dst net.IP, prefix int, gw net.IP) error {
	p := make([]byte, unix.SizeofRtMsg)
	p[0] = unix.AF_INET
	p[1] = byte(prefix)
	p[4] = unix.RT_TABLE_MAIN
	p[5] = unix.RTPROT_BOOT
	p[6] = unix.RT_SCOPE_UNIVERSE
	if gw == nil {
		p[6] = unix.RT_SCOPE_LINK
	}
	p[7] = unix.RTN_UNICAST
	if prefix > 0 {
		p = append(p, nlAttr(unix.RTA_DST, dst)...)
	}
	if gw != nil {
		p = append(p, nlAttr(unix.RTA_GATEWAY, gw)...)
	}
	p = append(p, nlAttr(unix.RTA_OIF, nlU32(uint32(index)))...)
	return nlRequest(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_REPLACE, p)
}
