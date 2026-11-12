package dhcp

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/iana"
)

var (
	clientMAC = net.HardwareAddr{0x52, 0x54, 0, 0x12, 0x34, 0x56}
	srvMAC    = net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
)

func testConfig() Config {
	return Config{
		ClientMAC: clientMAC,
		Addr:      netip.MustParsePrefix("10.244.1.5/24"),
		Gateway:   netip.MustParseAddr("10.244.1.1"),
		MTU:       1450,
		DNS:       []netip.Addr{netip.MustParseAddr("10.96.0.10")},
		Search:    []string{"default.svc.cluster.local", "svc.cluster.local", "cluster.local"},
		Hostname:  "myblip",
	}
}

func request(t dhcpv4.MessageType, opts ...dhcpv4.Option) *dhcpv4.DHCPv4 {
	m := &dhcpv4.DHCPv4{
		OpCode:        dhcpv4.OpcodeBootRequest,
		HWType:        iana.HWTypeEthernet,
		TransactionID: dhcpv4.TransactionID{0xde, 0xad, 0xbe, 0xef},
		ClientIPAddr:  net.IPv4zero,
		YourIPAddr:    net.IPv4zero,
		ServerIPAddr:  net.IPv4zero,
		GatewayIPAddr: net.IPv4zero,
		ClientHWAddr:  clientMAC,
		Options:       dhcpv4.OptionsFromList(append([]dhcpv4.Option{dhcpv4.OptMessageType(t)}, opts...)...),
	}
	return m
}

// roundTrip encodes m as the server does and decodes it again.
func roundTrip(t *testing.T, m *dhcpv4.DHCPv4) *dhcpv4.DHCPv4 {
	t.Helper()
	b := marshal(m, defaultMax)
	if len(b) < 300 {
		t.Fatalf("message %d bytes, want >= 300", len(b))
	}
	out, err := dhcpv4.FromBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func optHex(m *dhcpv4.DHCPv4, code uint8) string {
	return hex.EncodeToString(m.Options.Get(dhcpv4.GenericOptionCode(code)))
}

func TestMaxSizeDropsOptions(t *testing.T) {
	m := request(dhcpv4.MessageTypeAck,
		dhcpv4.OptHostName(strings.Repeat("h", 250)),
		dhcpv4.OptDomainName(strings.Repeat("d", 250)),
		dhcpv4.OptBroadcastAddress(net.IPv4(1, 2, 3, 4)))
	b := marshal(m, defaultMax)
	if len(b) > defaultMax {
		t.Fatalf("message %d bytes", len(b))
	}
	out, err := dhcpv4.FromBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	if out.MessageType() != dhcpv4.MessageTypeAck || out.HostName() == "" || out.DomainName() != "" || out.Options.Has(dhcpv4.OptionBroadcastAddress) {
		t.Fatalf("unexpected options kept: %v", out.Options)
	}
}

func TestDiscoverOffer(t *testing.T) {
	c := testConfig()
	r, _ := Handle(&c, roundTrip(t, request(dhcpv4.MessageTypeDiscover)))
	if r == nil {
		t.Fatal("no reply")
	}
	m := roundTrip(t, r.Msg)
	if m.MessageType() != dhcpv4.MessageTypeOffer || addr4(m.YourIPAddr) != c.Addr.Addr() || m.TransactionID != (dhcpv4.TransactionID{0xde, 0xad, 0xbe, 0xef}) {
		t.Fatalf("bad offer: %v", m)
	}
	check := map[uint8]string{
		1:  "ffffff00",
		3:  "0af40101",
		54: "0af40101",
		6:  "0a60000a",
		26: "05aa",
		12: hex.EncodeToString([]byte("myblip")),
		15: hex.EncodeToString([]byte("default.svc.cluster.local")),
		51: "00015180",
		58: "0000a8c0",
		59: "00012750",
	}
	for code, want := range check {
		if got := optHex(m, code); got != want {
			t.Errorf("option %d = %s, want %s", code, got, want)
		}
	}
	if got := m.DomainSearch(); got == nil || strings.Join(got.Labels, " ") != "default.svc.cluster.local svc.cluster.local cluster.local" {
		t.Errorf("search = %v", got)
	}
	if m.Options.Has(dhcpv4.OptionClasslessStaticRoute) {
		t.Error("option 121 for a simple default route")
	}
	if m.Options.Has(dhcpv4.OptionRapidCommit) {
		t.Error("rapid commit in offer")
	}
	if r.Broadcast || r.Dst != c.Addr.Addr() {
		t.Errorf("dst %v broadcast %v", r.Dst, r.Broadcast)
	}
}

func TestRapidCommit(t *testing.T) {
	c := testConfig()
	r, _ := Handle(&c, request(dhcpv4.MessageTypeDiscover, dhcpv4.OptGeneric(dhcpv4.OptionRapidCommit, nil)))
	m := roundTrip(t, r.Msg)
	if m.MessageType() != dhcpv4.MessageTypeAck {
		t.Fatalf("type %v", m.MessageType())
	}
	if !m.Options.Has(dhcpv4.OptionRapidCommit) || len(m.Options.Get(dhcpv4.OptionRapidCommit)) != 0 {
		t.Fatal("no rapid commit option in ack")
	}
}

func TestRequest(t *testing.T) {
	c := testConfig()
	our := ip4(c.Addr.Addr())
	other := net.IPv4(10, 244, 7, 9).To4()
	sid := dhcpv4.OptServerIdentifier(ip4(c.Gateway))
	withCI := func(ip net.IP) *dhcpv4.DHCPv4 { m := request(dhcpv4.MessageTypeRequest); m.ClientIPAddr = ip; return m }
	cases := []struct {
		name string
		req  *dhcpv4.DHCPv4
		want dhcpv4.MessageType // 0: no reply
	}{
		{"selecting", request(dhcpv4.MessageTypeRequest, dhcpv4.OptRequestedIPAddress(our), sid), dhcpv4.MessageTypeAck},
		{"selecting other server", request(dhcpv4.MessageTypeRequest, dhcpv4.OptRequestedIPAddress(our), dhcpv4.OptServerIdentifier(net.IPv4(1, 2, 3, 4))), 0},
		{"init-reboot", request(dhcpv4.MessageTypeRequest, dhcpv4.OptRequestedIPAddress(our)), dhcpv4.MessageTypeAck},
		{"init-reboot stale", request(dhcpv4.MessageTypeRequest, dhcpv4.OptRequestedIPAddress(other)), dhcpv4.MessageTypeNak},
		{"renewing", withCI(our), dhcpv4.MessageTypeAck},
		{"renewing stale", withCI(other), dhcpv4.MessageTypeNak},
		{"no address", request(dhcpv4.MessageTypeRequest), dhcpv4.MessageTypeNak},
		{"other mac", func() *dhcpv4.DHCPv4 { m := request(dhcpv4.MessageTypeRequest); m.ClientHWAddr = srvMAC; return m }(), 0},
		{"reply op", func() *dhcpv4.DHCPv4 {
			m := request(dhcpv4.MessageTypeRequest)
			m.OpCode = dhcpv4.OpcodeBootReply
			return m
		}(), 0},
		{"decline", request(dhcpv4.MessageTypeDecline, dhcpv4.OptRequestedIPAddress(our)), 0},
		{"release", request(dhcpv4.MessageTypeRelease), 0},
	}
	for _, tc := range cases {
		r, _ := Handle(&c, roundTrip(t, tc.req))
		var got dhcpv4.MessageType
		if r != nil {
			got = roundTrip(t, r.Msg).MessageType()
		}
		if got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
		if got == dhcpv4.MessageTypeNak {
			m := roundTrip(t, r.Msg)
			if !r.Broadcast || !m.YourIPAddr.Equal(net.IPv4zero) || m.Options.Has(dhcpv4.OptionIPAddressLeaseTime) {
				t.Errorf("%s: bad nak %v", tc.name, m)
			}
		}
	}
}

func TestInform(t *testing.T) {
	c := testConfig()
	m := request(dhcpv4.MessageTypeInform)
	m.ClientIPAddr = ip4(c.Addr.Addr())
	r, _ := Handle(&c, m)
	out := roundTrip(t, r.Msg)
	if out.MessageType() != dhcpv4.MessageTypeAck || !out.YourIPAddr.Equal(net.IPv4zero) ||
		out.Options.Has(dhcpv4.OptionIPAddressLeaseTime) || len(out.DNS()) == 0 {
		t.Fatalf("bad inform ack: %v", out)
	}
	if r.Broadcast || r.Dst != c.Addr.Addr() {
		t.Fatal("inform ack should be unicast to ciaddr")
	}
}

func TestPointToPointRoutes(t *testing.T) {
	// Calico: /32 address, gateway 169.254.1.1 outside the subnet.
	c := testConfig()
	c.Addr = netip.MustParsePrefix("192.168.10.7/32")
	c.Gateway = netip.MustParseAddr("169.254.1.1")
	c.Lease = time.Hour
	r, _ := Handle(&c, request(dhcpv4.MessageTypeDiscover))
	m := roundTrip(t, r.Msg)
	want := "20a9fe010100000000" + "00a9fe0101"
	if got := optHex(m, 121); got != want {
		t.Fatalf("121 = %s, want %s", got, want)
	}
	if optHex(m, 1) != "ffffffff" || optHex(m, 3) != "a9fe0101" {
		t.Fatal("bad mask or router")
	}
	if m.IPAddressLeaseTime(0) != time.Hour {
		t.Fatal("lease")
	}
	// Extra route with the default.
	c = testConfig()
	c.Routes = []Route{{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParseAddr("10.244.1.254")}}
	r, _ = Handle(&c, request(dhcpv4.MessageTypeDiscover))
	want = "080a0af401fe" + "000af40101"
	if got := optHex(r.Msg, 121); got != want {
		t.Fatalf("121 = %s, want %s", got, want)
	}
}

func TestClasslessRoutesGolden(t *testing.T) {
	rs := []Route{
		{netip.MustParsePrefix("169.254.1.1/32"), netip.Addr{}},
		{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParseAddr("169.254.1.1")},
		{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParseAddr("10.244.1.1")},
		{netip.MustParsePrefix("192.168.128.0/17"), netip.MustParseAddr("10.244.1.1")},
	}
	got := hex.EncodeToString(dhcpv4.OptClasslessStaticRoute(classlessRoutes(rs)...).Value.ToBytes())
	want := "20a9fe010100000000" + "00a9fe0101" + "080a0af40101" + "11c0a8800af40101"
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

// clientFrame is a client's frame 0.0.0.0:68 -> 255.255.255.255:67.
func clientFrame(req *dhcpv4.DHCPv4) []byte {
	f := BuildFrame(bcastMAC, clientMAC, netip.IPv4Unspecified(), netip.AddrFrom4([4]byte{255, 255, 255, 255}), req.ToBytes())
	binary.BigEndian.PutUint16(f[ethHdr+ipHdr:], portCli)
	binary.BigEndian.PutUint16(f[ethHdr+ipHdr+2:], portSrv)
	return f
}

// TestOfferFrameGolden pins the whole OFFER frame for a ptp network
// (option 121 with an on-link route to the gateway).
func TestOfferFrameGolden(t *testing.T) {
	c := testConfig()
	c.Addr = netip.MustParsePrefix("192.168.10.7/32")
	c.Gateway = netip.MustParseAddr("169.254.1.1")
	c.Search = []string{"svc.cluster.local"}
	req := request(dhcpv4.MessageTypeDiscover)
	req.Flags = 0x8000
	out, err := New(c).handleFrame(clientFrame(req), srvMAC, discardLog())
	if err != nil || out == nil {
		t.Fatalf("no reply: %v", err)
	}
	want := strings.Join([]string{
		// Ethernet: broadcast <- server, IPv4.
		"ffffffffffff" + "020000000001" + "0800",
		// IPv4: tos 0xc0, ttl 64, UDP, 169.254.1.1 -> 255.255.255.255.
		"45c0" + "017e" + "00000000" + "4011" + "cdb0" + "a9fe0101" + "ffffffff",
		// UDP 67 -> 68, no checksum.
		"0043" + "0044" + "016a" + "0000",
		// BOOTP: reply, ethernet, xid, broadcast flag, yiaddr.
		"02010600" + "deadbeef" + "0000" + "8000" + "00000000" + "c0a80a07" + "00000000" + "00000000",
		"525400123456" + strings.Repeat("00", 10) + strings.Repeat("00", 192) + "63825363",
		// Options, sorted by code.
		"0104ffffffff" + "0304a9fe0101" + "06040a60000a" + "0c066d79626c6970" +
			"0f11" + hex.EncodeToString([]byte("svc.cluster.local")) + "1a0205aa" +
			"330400015180" + "350102" + "3604a9fe0101" + "3a040000a8c0" + "3b0400012750" +
			"7713" + "037376630763" + "6c757374657205" + "6c6f63616c00" +
			"790e" + "20a9fe010100000000" + "00a9fe0101" + "ff",
	}, "")
	if got := hex.EncodeToString(out); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestFrameRoundTrip(t *testing.T) {
	c := testConfig()
	req := request(dhcpv4.MessageTypeDiscover, dhcpv4.OptMaxMessageSize(1500))
	req.Flags = 0x8000
	s := New(c)
	out, err := s.handleFrame(clientFrame(req), srvMAC, discardLog())
	if err != nil || out == nil {
		t.Fatalf("no reply: %v", err)
	}
	if !bytes.Equal(out[0:6], bcastMAC) || !bytes.Equal(out[6:12], srvMAC) {
		t.Fatal("bad ethernet addresses")
	}
	ip := out[ethHdr : ethHdr+ipHdr]
	if Checksum(ip) != 0 {
		t.Fatal("bad ip checksum")
	}
	if !bytes.Equal(ip[12:16], []byte{10, 244, 1, 1}) || !bytes.Equal(ip[16:20], []byte{255, 255, 255, 255}) {
		t.Fatal("bad ip addresses")
	}
	udp := out[ethHdr+ipHdr:]
	if binary.BigEndian.Uint16(udp[0:2]) != 67 || binary.BigEndian.Uint16(udp[2:4]) != 68 {
		t.Fatal("bad ports")
	}
	m, err := dhcpv4.FromBytes(udp[udpHdr:])
	if err != nil || m.MessageType() != dhcpv4.MessageTypeOffer {
		t.Fatalf("bad offer: %v", err)
	}
	// Unicast when no broadcast flag.
	req.Flags = 0
	f := clientFrame(req)
	out, _ = s.handleFrame(f, srvMAC, discardLog())
	if !bytes.Equal(out[0:6], clientMAC) || !bytes.Equal(out[ethHdr+16:ethHdr+20], []byte{10, 244, 1, 5}) {
		t.Fatal("want unicast reply")
	}
	// SetConfig takes effect.
	c.Hostname = "renamed"
	s.SetConfig(c)
	out, _ = s.handleFrame(f, srvMAC, discardLog())
	m, _ = dhcpv4.FromBytes(out[ethHdr+ipHdr+udpHdr:])
	if m.HostName() != "renamed" {
		t.Fatal("SetConfig not applied")
	}
}

func TestParseResolvConf(t *testing.T) {
	r := ParseResolvConf([]byte("# c\nsearch a.b c.d\nnameserver 10.96.0.10\nnameserver fd00::a ; x\noptions ndots:5\n"))
	if len(r.Servers) != 2 || r.Servers[0].String() != "10.96.0.10" || len(r.Search) != 2 || r.Search[1] != "c.d" {
		t.Fatalf("%+v", r)
	}
}

func discardLog() *slog.Logger { return slog.New(slog.DiscardHandler) }
