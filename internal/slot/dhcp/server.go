// Package dhcp is a minimal DHCPv4 server for exactly one client on a
// tap device. The host side has no IP address: frames are read and
// written with an AF_PACKET socket. DHCP messages are encoded and decoded
// with github.com/insomniacslk/dhcp/dhcpv4; the Ethernet, IPv4 and UDP
// headers are built here (frame.go).
package dhcp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/iana"
	"github.com/insomniacslk/dhcp/rfc1035label"
)

// DefaultLease is the lease time when Config.Lease is zero.
const DefaultLease = 24 * time.Hour

// Route is a static route given to the client. A zero Gateway means the
// destination is on the link.
type Route struct {
	Dst     netip.Prefix
	Gateway netip.Addr
}

// Config is what the server offers to its single client.
type Config struct {
	ClientMAC net.HardwareAddr // only this chaddr gets answers
	Addr      netip.Prefix     // client IPv4 address and prefix length
	Gateway   netip.Addr       // default gateway; may be outside Addr
	Routes    []Route          // more routes; a default route here overrides Gateway
	MTU       int
	DNS       []netip.Addr
	Search    []string
	Domain    string // option 15; defaults to the first search domain
	Hostname  string
	Lease     time.Duration // 0: DefaultLease
	ServerID  netip.Addr    // option 54; defaults to Gateway
	Broadcast netip.Addr    // option 28, optional
}

// Validate checks the fields the server cannot work without.
func (c *Config) Validate() error {
	if len(c.ClientMAC) != 6 {
		return errors.New("dhcp: client MAC must be 6 bytes")
	}
	if !c.Addr.IsValid() || !c.Addr.Addr().Is4() {
		return errors.New("dhcp: need an IPv4 address")
	}
	if !c.serverID().Is4() {
		return errors.New("dhcp: need an IPv4 server identifier or gateway")
	}
	return nil
}

func (c *Config) serverID() netip.Addr {
	if c.ServerID.IsValid() {
		return c.ServerID
	}
	return c.Gateway
}

func (c *Config) lease() time.Duration {
	if c.Lease > 0 {
		return c.Lease
	}
	return DefaultLease
}

// routes returns all routes to send in option 121, or nil when option 3
// alone describes them (a default route via a gateway in the subnet).
func (c *Config) routes() []Route {
	var rs []Route
	hasDefault := false
	for _, r := range c.Routes {
		if !r.Dst.Addr().Is4() {
			continue
		}
		if r.Dst.Bits() == 0 {
			hasDefault = true
		}
		rs = append(rs, Route{r.Dst.Masked(), r.Gateway})
	}
	gw := c.Gateway
	if gw.Is4() && !hasDefault {
		rs = append(rs, Route{netip.PrefixFrom(netip.IPv4Unspecified(), 0), gw})
	}
	simple := len(rs) == 0 || (len(rs) == 1 && rs[0].Dst.Bits() == 0 && c.Addr.Masked().Contains(rs[0].Gateway))
	if simple {
		return nil
	}
	// Routes to gateways outside the subnet (ptp, /32 addressing) need a
	// link route to the gateway first.
	var out []Route
	onLink := func(a netip.Addr) bool {
		if c.Addr.Masked().Contains(a) {
			return true
		}
		for _, r := range out {
			if !r.Gateway.IsValid() || r.Gateway.IsUnspecified() {
				if r.Dst.Contains(a) {
					return true
				}
			}
		}
		return false
	}
	for _, r := range rs {
		if r.Gateway.Is4() && !r.Gateway.IsUnspecified() && !onLink(r.Gateway) {
			out = append(out, Route{netip.PrefixFrom(r.Gateway, 32), netip.Addr{}})
		}
		out = append(out, r)
	}
	return out
}

// router returns the gateway for option 3.
func (c *Config) router() netip.Addr {
	for _, r := range c.Routes {
		if r.Dst.Addr().Is4() && r.Dst.Bits() == 0 && r.Gateway.Is4() {
			return r.Gateway
		}
	}
	if c.Gateway.Is4() {
		return c.Gateway
	}
	return netip.Addr{}
}

// classlessRoutes converts rs for option 121 (RFC 3442).
func classlessRoutes(rs []Route) []*dhcpv4.Route {
	out := make([]*dhcpv4.Route, 0, len(rs))
	for _, r := range rs {
		gw := net.IPv4zero.To4()
		if r.Gateway.Is4() {
			gw = ip4(r.Gateway)
		}
		dst := r.Dst.Masked()
		out = append(out, &dhcpv4.Route{
			Dest:   &net.IPNet{IP: ip4(dst.Addr()), Mask: net.CIDRMask(dst.Bits(), 32)},
			Router: gw,
		})
	}
	return out
}

func ip4(a netip.Addr) net.IP { v := a.As4(); return net.IP(v[:]) }

func addr4(ip net.IP) netip.Addr {
	a, _ := netip.AddrFromSlice(ip.To4())
	return a
}

// leaseOptions sets the options of an OFFER/ACK; withLease is false for
// an ACK to INFORM.
func (c *Config) leaseOptions(m *dhcpv4.DHCPv4, withLease bool) {
	m.UpdateOption(dhcpv4.OptServerIdentifier(ip4(c.serverID())))
	if withLease {
		l := uint32(c.lease() / time.Second)
		m.UpdateOption(dhcpv4.OptIPAddressLeaseTime(time.Duration(l) * time.Second))
		m.UpdateOption(dhcpv4.OptRenewTimeValue(time.Duration(l/2) * time.Second))
		m.UpdateOption(dhcpv4.OptRebindingTimeValue(time.Duration(l/8*7) * time.Second))
	}
	m.UpdateOption(dhcpv4.OptSubnetMask(net.CIDRMask(c.Addr.Bits(), 32)))
	if rs := c.routes(); rs != nil {
		m.UpdateOption(dhcpv4.OptClasslessStaticRoute(classlessRoutes(rs)...))
	}
	if gw := c.router(); gw.IsValid() {
		m.UpdateOption(dhcpv4.OptRouter(ip4(gw)))
	}
	if c.MTU >= 68 {
		m.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionInterfaceMTU, binary.BigEndian.AppendUint16(nil, uint16(c.MTU))))
	}
	var dns []net.IP
	for _, a := range c.DNS {
		if a.Is4() {
			dns = append(dns, ip4(a))
		}
	}
	if len(dns) > 0 {
		m.UpdateOption(dhcpv4.OptDNS(dns...))
	}
	if c.Hostname != "" {
		m.UpdateOption(dhcpv4.OptHostName(c.Hostname))
	}
	domain := c.Domain
	if domain == "" && len(c.Search) > 0 {
		domain = c.Search[0]
	}
	if domain != "" {
		m.UpdateOption(dhcpv4.OptDomainName(strings.TrimSuffix(domain, ".")))
	}
	var search []string
	for _, d := range c.Search {
		if d = strings.TrimSuffix(strings.ToLower(d), "."); d != "" {
			search = append(search, d)
		}
	}
	if len(search) > 0 {
		m.UpdateOption(dhcpv4.OptDomainSearch(&rfc1035label.Labels{Labels: search}))
	}
	if c.Broadcast.Is4() {
		m.UpdateOption(dhcpv4.OptBroadcastAddress(ip4(c.Broadcast)))
	}
}

// Reply is the server's answer to one request.
type Reply struct {
	Msg *dhcpv4.DHCPv4
	// Broadcast: send to ff:ff:ff:ff:ff:ff and 255.255.255.255.
	Broadcast bool
	// Dst is the IP destination when not broadcast.
	Dst netip.Addr
}

// Handle returns the reply to req, or nil if there is none, and a note
// for the log (may be empty). It is pure.
func Handle(c *Config, req *dhcpv4.DHCPv4) (*Reply, string) {
	if req.OpCode != dhcpv4.OpcodeBootRequest || !bytes.Equal(req.ClientHWAddr, c.ClientMAC) {
		return nil, ""
	}
	our := c.Addr.Addr()
	ciaddr := addr4(req.ClientIPAddr)
	if !ciaddr.IsValid() {
		ciaddr = netip.IPv4Unspecified()
	}
	reply := func(t dhcpv4.MessageType) *dhcpv4.DHCPv4 {
		return &dhcpv4.DHCPv4{
			OpCode:        dhcpv4.OpcodeBootReply,
			HWType:        iana.HWTypeEthernet,
			TransactionID: req.TransactionID,
			Flags:         req.Flags,
			ClientIPAddr:  net.IPv4zero,
			YourIPAddr:    net.IPv4zero,
			ServerIPAddr:  net.IPv4zero,
			GatewayIPAddr: req.GatewayIPAddr,
			ClientHWAddr:  req.ClientHWAddr,
			Options:       dhcpv4.OptionsFromList(dhcpv4.OptMessageType(t)),
		}
	}
	dst := func(m *dhcpv4.DHCPv4) *Reply {
		r := &Reply{Msg: m, Broadcast: req.IsBroadcast()}
		if !r.Broadcast {
			r.Dst = our
			if !ciaddr.IsUnspecified() {
				r.Dst = ciaddr
			}
		}
		return r
	}
	switch t := req.MessageType(); t {
	case dhcpv4.MessageTypeDiscover:
		if req.Options.Has(dhcpv4.OptionRapidCommit) {
			m := reply(dhcpv4.MessageTypeAck)
			m.YourIPAddr = ip4(our)
			c.leaseOptions(m, true)
			m.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionRapidCommit, nil))
			return dst(m), "discover: rapid commit ack"
		}
		m := reply(dhcpv4.MessageTypeOffer)
		m.YourIPAddr = ip4(our)
		c.leaseOptions(m, true)
		return dst(m), "discover: offer"
	case dhcpv4.MessageTypeRequest:
		// Selecting: only answer if the client chose us.
		if sid := req.Options.Get(dhcpv4.OptionServerIdentifier); sid != nil && !bytes.Equal(sid, ip4(c.serverID())) {
			return nil, "request for another server"
		}
		want := ciaddr
		if v := req.Options.Get(dhcpv4.OptionRequestedIPAddress); len(v) == 4 {
			want = netip.AddrFrom4([4]byte(v))
		}
		if want != our {
			m := reply(dhcpv4.MessageTypeNak)
			m.UpdateOption(dhcpv4.OptServerIdentifier(ip4(c.serverID())))
			m.UpdateOption(dhcpv4.OptMessage("address not available"))
			// A NAK is broadcast: the client has no usable address.
			return &Reply{Msg: m, Broadcast: true}, fmt.Sprintf("request for %s: nak", want)
		}
		m := reply(dhcpv4.MessageTypeAck)
		m.YourIPAddr = ip4(our)
		m.ClientIPAddr = ip4(ciaddr)
		c.leaseOptions(m, true)
		return dst(m), "request: ack"
	case dhcpv4.MessageTypeInform:
		m := reply(dhcpv4.MessageTypeAck)
		m.ClientIPAddr = ip4(ciaddr)
		c.leaseOptions(m, false)
		r := &Reply{Msg: m, Broadcast: req.IsBroadcast() || ciaddr.IsUnspecified()}
		if !r.Broadcast {
			r.Dst = ciaddr
		}
		return r, "inform: ack"
	case dhcpv4.MessageTypeDecline:
		var a [4]byte
		copy(a[:], req.Options.Get(dhcpv4.OptionRequestedIPAddress))
		return nil, fmt.Sprintf("decline of %s", netip.AddrFrom4(a))
	case dhcpv4.MessageTypeRelease:
		return nil, fmt.Sprintf("release of %s", ciaddr)
	default:
		return nil, fmt.Sprintf("ignored message type %d", byte(t))
	}
}

// dropOrder is the order options are left out of a reply that does not
// fit in the client's maximum message size.
var dropOrder = []dhcpv4.OptionCode{
	dhcpv4.OptionBroadcastAddress,
	dhcpv4.OptionDNSDomainSearchList,
	dhcpv4.OptionDomainName,
	dhcpv4.OptionHostName,
	dhcpv4.OptionDomainNameServer,
	dhcpv4.OptionInterfaceMTU,
	dhcpv4.OptionRouter,
	dhcpv4.OptionClasslessStaticRoute,
}

// defaultMax is the reply size limit without option 57: an IP packet of
// 576 bytes minus the IP and UDP headers.
const defaultMax = 576 - 28

// maxSize is the largest reply the client accepts (option 57).
func maxSize(req *dhcpv4.DHCPv4) int {
	if v, err := req.MaxMessageSize(); err == nil {
		// Option 57 counts the whole IP packet.
		if n := int(v) - 28; n >= 300 {
			return n
		}
	}
	return defaultMax
}

// marshal encodes m, leaving out options in dropOrder until it fits in
// max bytes.
func marshal(m *dhcpv4.DHCPv4, max int) []byte {
	b := m.ToBytes()
	for _, code := range dropOrder {
		if len(b) <= max {
			break
		}
		if m.Options.Has(code) {
			m.Options.Del(code)
			b = m.ToBytes()
		}
	}
	return b
}
