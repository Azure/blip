// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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

	"github.com/Azure/blip/internal/bootconfig"
	"github.com/Azure/blip/internal/netpolicy"
	"github.com/Azure/blip/internal/podapi"
)

const (
	tapName  = "blip-tap0"
	nftTable = "blip_vm"
)

// podNet owns only its TAP, its nftables table, and interface forwarding
// settings in the pod network namespace. The pod keeps its IP and MAC.
type podNet struct {
	iface, podIP, guestIP, gateway, mac string
	run                                 commandRunner
	tapCreated, tableCreated            bool
	disabled, unsafe                    bool
	sysctls                             map[string][]byte
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
func setupNetwork(cfg *bootconfig.Config) (*podNet, error) {
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
	// The controller writes the pool's resolvers into the pod environment. The
	// node agent reads the same value to compile DNS rules, so filtering and
	// the guest's resolv.conf cannot disagree.
	cfg.DNS = parseNameservers(os.Getenv(podapi.NameserversEnv))
	link, err := privateLink(podIP, occupied)
	if err != nil {
		return nil, err
	}
	cfg.Gateway = link.Addr().Next().String()
	cfg.IP, cfg.Prefix = link.Addr().Next().Next().String(), 30
	cfg.MTU = ifi.MTU
	cfg.MAC = guestMAC(netip.MustParseAddr(cfg.IP), ifi.HardwareAddr.String())
	p := &podNet{iface: iface, podIP: podIP, guestIP: cfg.IP, gateway: cfg.Gateway, mac: cfg.MAC, run: networkCommand, sysctls: map[string][]byte{}}
	complete := false
	defer func() {
		if !complete {
			p.teardown()
		}
	}()
	if _, err := p.install(nil, false); err != nil {
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
	// The guest reaches the Envoy sidecar through the TAP gateway address. The
	// prerouting DNAT rewrites that flow to the sidecar's loopback listener,
	// which the kernel only accepts from a non-loopback interface when
	// route_localnet is enabled. Recording the old value restores it on
	// teardown.
	if err := p.setSysctl("ipv4/conf/"+tapName+"/route_localnet", "1", true); err != nil {
		return nil, err
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
		// A deleted interface takes its per-interface sysctls with it.
		if err := os.WriteFile(path, value, 0o644); err != nil && !os.IsNotExist(err) {
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

func (p *podNet) install(policy *netpolicy.Policy, active bool) (unsafe bool, err error) {
	script, err := p.policyScript(policy, active)
	if err != nil {
		// An invalid desired policy still revokes the previous allow rules.
		return p.denyAll(err)
	}
	if _, err := p.run(script, "nft", "-f", "-"); err != nil {
		return p.denyAll(err)
	}
	return false, nil
}

// denyAll falls back to default deny after a failed nft transaction and, when
// even that cannot be installed, lowers or removes the TAP. unsafe reports
// that traffic may still reach the old allow rules.
func (p *podNet) denyAll(cause error) (unsafe bool, err error) {
	script, denyErr := p.policyScript(nil, false)
	if denyErr == nil {
		_, denyErr = p.run(script, "nft", "-f", "-")
	}
	if denyErr == nil {
		p.unsafe = false
		return false, cause
	}
	// A failed nft binary/kernel transaction must not leave the old allow
	// rules usable. Lowering the TAP is independent of nftables.
	p.disabled = true
	p.unsafe = false
	if _, downErr := p.run("", "ip", "link", "set", tapName, "down"); downErr != nil {
		if _, delErr := p.run("", "ip", "link", "del", tapName); delErr != nil {
			p.unsafe = true
			return true, fmt.Errorf("%w; default deny failed: %v; disable TAP: %v; remove TAP: %v", cause, denyErr, downErr, delErr)
		}
		p.tapCreated = false
	}
	return false, fmt.Errorf("%w; default deny failed: %v (TAP disabled)", cause, denyErr)
}

// apply uses one nft transaction. Old conntrack entries never bypass the new
// policy: both original packets and replies traverse the current layer chains,
// and related ICMP errors are gated through those same layers on the conntrack
// entry's original destination. Even an invalid desired policy revokes the
// previously installed allow rules.
func (p *podNet) apply(policy *netpolicy.Policy, active bool) (unsafe bool, err error) {
	unsafe, err = p.install(policy, active)
	if err == nil && p.disabled {
		_, err = p.run("", "ip", "link", "set", tapName, "up")
		if err == nil {
			p.disabled = false
		}
	}
	p.unsafe = unsafe
	return unsafe, err
}

// defaultRoute returns the interface and gateway of the main table's IPv4
// default route.
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

// parseNameservers turns the comma-separated pool setting into resolvers.
// Invalid entries are dropped: the controller validates the pool, and a guest
// without a usable resolver fails closed.
func parseNameservers(value string) []string {
	var nameservers []string
	for _, entry := range strings.Split(value, ",") {
		addr, err := netip.ParseAddr(strings.TrimSpace(entry))
		if err != nil || !addr.Is4() {
			continue
		}
		nameservers = append(nameservers, addr.String())
	}
	return nameservers
}
