package runtime

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/blip/internal/guest"
	"github.com/Azure/blip/internal/network"
)

const (
	tapName  = "blip-tap0"
	nftTable = "blip_vm"
)

// podNet owns only its TAP, its nftables table, and interface forwarding
// settings in the pod network namespace. The pod keeps its IP and MAC.
type podNet struct {
	iface, podIP, guestIP, mac string
	run                        commandRunner
	tapCreated, tableCreated   bool
	disabled, unsafe           bool
	sysctls                    map[string][]byte
}

type commandRunner func(input, name string, args ...string) ([]byte, error)

func networkCommand(input, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// setupNetwork installs default deny before bringing up the routed TAP or
// starting the VMM. It never removes or redirects the pod interface's IP.
func setupNetwork(cfg *guest.Config) (*podNet, error) {
	iface, _ := defaultRoute()
	if iface == "" {
		return nil, fmt.Errorf("no IPv4 default route")
	}
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, err
	}
	var podIP string
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
			podIP = ipn.IP.String()
			break
		}
	}
	if podIP == "" {
		return nil, fmt.Errorf("%s has no IPv4 address", iface)
	}
	// Avoid all explicit routes, including CNI link-local gateways, and all
	// interface addresses. A default route does not reserve address space.
	out, err := networkCommand("", "ip", "-j", "-4", "route", "show", "table", "all")
	if err != nil {
		return nil, err
	}
	var routes []struct {
		Dst     string `json:"dst"`
		Dev     string `json:"dev"`
		Gateway string `json:"gateway"`
	}
	if err := json.Unmarshal(out, &routes); err != nil {
		return nil, fmt.Errorf("read IPv4 routes: %w", err)
	}
	var occupied []netip.Prefix
	for _, rt := range routes {
		if rt.Dev == tapName { // a TAP left by a previous runtime
			continue
		}
		if gw, err := netip.ParseAddr(rt.Gateway); err == nil && gw.Is4() {
			occupied = append(occupied, netip.PrefixFrom(gw, 32))
		}
		prefix, err := netip.ParsePrefix(rt.Dst)
		if err != nil {
			if addr, err := netip.ParseAddr(rt.Dst); err == nil {
				prefix = netip.PrefixFrom(addr, addr.BitLen())
			}
		}
		if prefix.IsValid() && prefix.Bits() != 0 {
			occupied = append(occupied, prefix)
		}
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, in := range interfaces {
		if in.Name == tapName {
			continue
		}
		as, err := in.Addrs()
		if err != nil {
			return nil, err
		}
		for _, a := range as {
			if prefix, err := netip.ParsePrefix(a.String()); err == nil && prefix.Addr().Is4() {
				occupied = append(occupied, prefix.Masked())
			}
		}
	}
	cfg.DNS, cfg.Search, cfg.Options = readResolvConf("/etc/resolv.conf")
	for _, value := range cfg.DNS {
		// Node-local DNS can be link-local without an explicit pod route.
		if addr, err := netip.ParseAddr(value); err == nil && addr.Is4() {
			occupied = append(occupied, netip.PrefixFrom(addr, 32))
		}
	}
	link, err := privateLink(podIP, occupied)
	if err != nil {
		return nil, err
	}
	cfg.Gateway = link.Addr().Next().String()
	cfg.IP, cfg.Prefix = link.Addr().Next().Next().String(), 30
	cfg.MTU = ifi.MTU
	cfg.MAC = guestMAC(netip.MustParseAddr(cfg.IP), ifi.HardwareAddr.String())
	p := &podNet{iface: iface, podIP: podIP, guestIP: cfg.IP, mac: cfg.MAC, run: networkCommand, sysctls: map[string][]byte{}}
	complete := false
	defer func() {
		if !complete {
			p.teardown()
		}
	}()
	if err := p.install(nil, false); err != nil {
		return nil, err
	}
	p.tableCreated = true
	if _, err := net.InterfaceByName(tapName); err == nil {
		p.tapCreated = true
		if _, err := p.run("", "ip", "link", "del", tapName); err != nil {
			return nil, err
		}
		p.tapCreated = false
	}
	if _, err := p.run("", "ip", "tuntap", "add", "dev", tapName, "mode", "tap"); err != nil {
		return nil, err
	}
	p.tapCreated = true
	steps := [][]string{
		{"ip", "link", "set", tapName, "mtu", strconv.Itoa(ifi.MTU), "up"},
		{"ip", "addr", "add", cfg.Gateway + "/30", "dev", tapName},
	}
	for _, s := range steps {
		if _, err := p.run("", s[0], s[1:]...); err != nil {
			return nil, err
		}
	}
	// Redirects can change routing independently of normal forwarding. Both
	// 'all' and the interface settings matter (send_redirects uses OR).
	for _, dev := range []string{"all", iface, tapName} {
		for _, key := range []string{"accept_redirects", "send_redirects", "accept_source_route"} {
			if err := p.setSysctl("ipv4/conf/"+dev+"/"+key, "0", dev != tapName); err != nil {
				return nil, err
			}
		}
	}
	for _, dev := range []string{iface, tapName} {
		if err := p.setSysctl("ipv4/conf/"+dev+"/forwarding", "1", dev != tapName); err != nil {
			return nil, err
		}
	}
	// IPv6 is unsupported for the guest; inet filtering also blocks it if
	// someone subsequently reenables the interface's IPv6 stack.
	if _, err := os.Stat("/proc/sys/net/ipv6/conf/" + tapName + "/disable_ipv6"); err == nil {
		if err := p.setSysctl("ipv6/conf/"+tapName+"/disable_ipv6", "1", false); err != nil {
			return nil, err
		}
	}
	complete = true
	return p, nil
}

func (p *podNet) teardown() {
	if p.tapCreated {
		if _, err := p.run("", "ip", "link", "del", tapName); err != nil {
			// Keep the firewall if the interface might still carry traffic.
			log.Printf("network cleanup: %v", err)
			return
		}
		p.tapCreated = false
	}
	if p.tableCreated {
		if _, err := p.run("delete table inet "+nftTable+"\n", "nft", "-f", "-"); err != nil {
			log.Printf("network cleanup: %v", err)
		} else {
			p.tableCreated = false
		}
	}
	for path, value := range p.sysctls {
		if err := os.WriteFile(path, value, 0o644); err != nil {
			log.Printf("network cleanup: %v", err)
		}
	}
}

func (p *podNet) setSysctl(key, value string, restore bool) error {
	path := "/proc/sys/net/" + key
	old, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(old)) == value {
		return nil
	}
	if err := os.WriteFile(path, []byte(value+"\n"), 0o644); err != nil {
		return err
	}
	if restore {
		p.sysctls[path] = old
	}
	return nil
}

// privateLink deterministically searches /30s in usable IPv4 link-local space.
// Refusing an exhausted range is safer than stealing a pod/CNI route.
func privateLink(seed string, occupied []netip.Prefix) (netip.Prefix, error) {
	const count = 254 * 64 // skip 169.254.0/24 and 169.254.255/24
	h := fnv.New32a()
	_, _ = h.Write([]byte(seed))
	for i := 0; i < count; i++ {
		n := (int(h.Sum32()%count) + i) % count
		prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{169, 254, byte(n/64 + 1), byte(n % 64 * 4)}), 30)
		conflict := false
		for _, other := range occupied {
			if prefix.Overlaps(other) {
				conflict = true
				break
			}
		}
		if !conflict {
			return prefix, nil
		}
	}
	return netip.Prefix{}, fmt.Errorf("no private link-local /30 avoids pod routes")
}

func guestMAC(ip netip.Addr, podMAC string) string {
	a := ip.As4()
	m := net.HardwareAddr{0x02, 0x62, a[0], a[1], a[2], a[3]}
	if strings.EqualFold(m.String(), podMAC) {
		m[0] = 0x06
	}
	return m.String()
}

func (p *podNet) install(policy *network.Policy, active bool) error {
	script, err := p.policyScript(policy, active)
	if err != nil {
		return err
	}
	_, err = p.run(script, "nft", "-f", "-")
	return err
}

// apply uses one nft transaction. Old conntrack entries never bypass the new
// policy: both original packets and replies traverse the current layer chains.
// Even invalid desired policy revokes the previously installed allow rules.
func (p *podNet) apply(policy *network.Policy, active bool) error {
	err := p.install(policy, active)
	if err == nil && p.disabled {
		_, err = p.run("", "ip", "link", "set", tapName, "up")
		if err == nil {
			p.disabled = false
		}
	}
	if err == nil {
		p.unsafe = false
		return nil
	}
	if denyErr := p.install(nil, false); denyErr != nil {
		// A failed nft binary/kernel transaction must not leave the old allow
		// rules usable. Lowering the TAP is independent of nftables.
		p.disabled = true
		p.unsafe = false
		if _, downErr := p.run("", "ip", "link", "set", tapName, "down"); downErr != nil {
			if _, delErr := p.run("", "ip", "link", "del", tapName); delErr != nil {
				p.unsafe = true
				return fmt.Errorf("%w; default deny failed: %v; disable TAP: %v; remove TAP: %v", err, denyErr, downErr, delErr)
			}
			p.tapCreated = false
		}
		return fmt.Errorf("%w; default deny failed: %v (TAP disabled)", err, denyErr)
	}
	p.unsafe = false
	return err
}

// defaultRoute returns the interface and gateway of the IPv4 default route.
func defaultRoute() (string, string) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", ""
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		x := strings.Fields(s.Text())
		if len(x) < 8 || x[1] != "00000000" || x[7] != "00000000" {
			continue
		}
		v, err := strconv.ParseUint(x[2], 16, 32)
		if err != nil {
			continue
		}
		gw := ""
		if v != 0 {
			gw = net.IPv4(byte(v), byte(v>>8), byte(v>>16), byte(v>>24)).String()
		}
		return x[0], gw
	}
	return "", ""
}

func readResolvConf(path string) (dns, search, options []string) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, nil
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		x := strings.Fields(s.Text())
		if len(x) < 2 {
			continue
		}
		switch x[0] {
		case "nameserver":
			dns = append(dns, x[1])
		case "search":
			search = x[1:]
		case "options":
			options = append(options, x[1:]...)
		}
	}
	return dns, search, options
}
