package dhcp

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
)

const (
	ethHdr  = 14
	ipHdr   = 20
	udpHdr  = 8
	portSrv = 67
	portCli = 68
)

var bcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// ParseFrame extracts the DHCP payload of an Ethernet frame carrying
// IPv4/UDP to port 67. It returns the source MAC as well.
func ParseFrame(f []byte) (payload []byte, src net.HardwareAddr, err error) {
	if len(f) < ethHdr+ipHdr+udpHdr {
		return nil, nil, errors.New("short frame")
	}
	if binary.BigEndian.Uint16(f[12:14]) != 0x0800 {
		return nil, nil, errors.New("not ipv4")
	}
	ip := f[ethHdr:]
	ihl := int(ip[0]&0x0f) * 4
	if ip[0]>>4 != 4 || ihl < ipHdr || len(ip) < ihl+udpHdr {
		return nil, nil, errors.New("bad ipv4 header")
	}
	if ip[9] != 17 {
		return nil, nil, errors.New("not udp")
	}
	if binary.BigEndian.Uint16(ip[6:8])&0x3fff != 0 {
		return nil, nil, errors.New("fragment")
	}
	total := int(binary.BigEndian.Uint16(ip[2:4]))
	if total > len(ip) || total < ihl+udpHdr {
		return nil, nil, errors.New("bad ipv4 length")
	}
	udp := ip[ihl:total]
	if binary.BigEndian.Uint16(udp[2:4]) != portSrv {
		return nil, nil, errors.New("not dhcp server port")
	}
	ul := int(binary.BigEndian.Uint16(udp[4:6]))
	if ul < udpHdr || ul > len(udp) {
		return nil, nil, errors.New("bad udp length")
	}
	return udp[udpHdr:ul], net.HardwareAddr(f[6:12]), nil
}

// BuildFrame wraps a DHCP payload in Ethernet/IPv4/UDP (67 -> 68). The
// UDP checksum is left 0.
func BuildFrame(dstMAC, srcMAC net.HardwareAddr, src, dst netip.Addr, payload []byte) []byte {
	n := ethHdr + ipHdr + udpHdr + len(payload)
	f := make([]byte, n)
	copy(f[0:6], dstMAC)
	copy(f[6:12], srcMAC)
	binary.BigEndian.PutUint16(f[12:14], 0x0800)
	ip := f[ethHdr:]
	ip[0] = 0x45
	ip[1] = 0xc0 // DSCP CS6, as other DHCP servers do
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipHdr+udpHdr+len(payload)))
	ip[8] = 64
	ip[9] = 17
	s, d := src.As4(), dst.As4()
	copy(ip[12:16], s[:])
	copy(ip[16:20], d[:])
	binary.BigEndian.PutUint16(ip[10:12], Checksum(ip[:ipHdr]))
	udp := ip[ipHdr:]
	binary.BigEndian.PutUint16(udp[0:2], portSrv)
	binary.BigEndian.PutUint16(udp[2:4], portCli)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpHdr+len(payload)))
	copy(udp[udpHdr:], payload)
	return f
}

// Checksum is the Internet checksum (RFC 1071).
func Checksum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s > 0xffff {
		s = s>>16 + s&0xffff
	}
	return ^uint16(s)
}

// ReplyFrame builds the frame for r, sent from srcMAC.
func ReplyFrame(c *Config, r *Reply, srcMAC net.HardwareAddr, max int) []byte {
	dstMAC, dst := c.ClientMAC, r.Dst
	if r.Broadcast || !dst.IsValid() || dst.IsUnspecified() {
		dstMAC, dst = bcastMAC, netip.AddrFrom4([4]byte{255, 255, 255, 255})
	}
	return BuildFrame(dstMAC, srcMAC, c.serverID(), dst, marshal(r.Msg, max))
}
