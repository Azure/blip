package slot

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/example/blip/internal/slot/dhcp"
)

// DHCPConfig builds the DHCP server config for the guest from the saved
// pod network and the pod's resolv.conf content.
func DHCPConfig(n *PodNetwork, resolvConf []byte, hostname string) (dhcp.Config, error) {
	mac, err := net.ParseMAC(n.MAC)
	if err != nil {
		return dhcp.Config{}, fmt.Errorf("pod MAC: %w", err)
	}
	c := dhcp.Config{ClientMAC: mac, MTU: n.MTU, Hostname: hostname}
	for _, a := range n.Addresses {
		if p, err := netip.ParsePrefix(a); err == nil && p.Addr().Is4() {
			c.Addr = p
			break
		}
	}
	if !c.Addr.IsValid() {
		return dhcp.Config{}, errors.New("pod network has no IPv4 address")
	}
	for _, r := range n.Routes {
		if r.IPv6 {
			continue
		}
		var gw netip.Addr
		if r.Gateway != "" {
			if gw, err = netip.ParseAddr(r.Gateway); err != nil || !gw.Is4() {
				continue
			}
		}
		if r.Destination == "" || r.Destination == "0.0.0.0/0" {
			if gw.IsValid() && !c.Gateway.IsValid() {
				c.Gateway = gw
			}
			continue
		}
		dst, err := netip.ParsePrefix(r.Destination)
		if err != nil || !dst.Addr().Is4() {
			continue
		}
		c.Routes = append(c.Routes, dhcp.Route{Dst: dst, Gateway: gw})
	}
	c.ServerID = c.Gateway
	if !c.ServerID.IsValid() {
		// No default route: any valid address on the link will do.
		c.ServerID = netip.MustParseAddr("169.254.0.1")
	}
	rc := dhcp.ParseResolvConf(resolvConf)
	c.DNS, c.Search, c.Domain = rc.Servers, rc.Search, rc.Domain
	return c, nil
}
