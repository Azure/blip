package slot

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// PodNetwork is the pod interface as the CNI plugin set it up. blipd slot
// saves it in network.json before it moves the pod IP to the guest. The
// DHCP server gives it to the guest; the node daemon copies it to the
// metadata disk (informational).
type PodNetwork struct {
	Iface     string   `json:"iface"`
	MAC       string   `json:"mac"`
	MTU       int      `json:"mtu"`
	Addresses []string `json:"addresses"` // CIDR
	Routes    []Route  `json:"routes"`    // in the order to add them
}

// Route is one route of the pod interface.
type Route struct {
	Destination string `json:"destination,omitempty"` // CIDR; empty for default
	Gateway     string `json:"gateway,omitempty"`
	Source      string `json:"source,omitempty"`
	Onlink      bool   `json:"onlink,omitempty"`
	Metric      int    `json:"metric,omitempty"`
	IPv6        bool   `json:"ipv6,omitempty"`
}

// ReadNetwork reads network.json from a slot directory.
func ReadNetwork(dir string) (*PodNetwork, error) {
	b, err := os.ReadFile(filepath.Join(dir, FileNetwork))
	if err != nil {
		return nil, err
	}
	var n PodNetwork
	if err := json.Unmarshal(b, &n); err != nil {
		return nil, fmt.Errorf("parse %s: %w", FileNetwork, err)
	}
	return &n, nil
}

// netConfig says how to set up the guest network inside the pod.
type netConfig struct {
	Tap      string // TAP device name
	PodIface string // pod interface, usually eth0
	RunDir   string // where network.json goes
}

// setupNetwork gives the pod's network identity to the guest:
//
//  1. read MAC, MTU, addresses and routes of the pod interface;
//  2. create the TAP device, owned by the current user so Cloud
//     Hypervisor can open it without CAP_NET_ADMIN;
//  3. redirect every frame between the pod interface and the TAP device
//     with tc (ingress qdisc, matchall filter, mirred redirect);
//  4. remove the addresses from the pod interface, so the pod's own
//     stack does not answer ARP or send traffic.
//
// The guest uses the same MAC and sets the same addresses and routes, so
// the CNI plugin and the rest of the cluster see no change. No NAT and no
// IP forwarding are needed.
func setupNetwork(c netConfig) (*PodNetwork, error) {
	pod, err := netlink.LinkByName(c.PodIface)
	if err != nil {
		return nil, fmt.Errorf("pod interface %s: %w", c.PodIface, err)
	}
	pn, err := podNetwork(pod)
	if err != nil {
		return nil, err
	}
	if len(pn.Addresses) == 0 {
		// A restarted container: an earlier run already moved the
		// addresses to the guest. Use what it saved, if it is for this
		// interface (a slot directory outlives its pod).
		saved, err := ReadNetwork(c.RunDir)
		if err != nil || saved.MAC != pn.MAC || len(saved.Addresses) == 0 {
			return nil, fmt.Errorf("pod interface %s has no IP address", c.PodIface)
		}
		pn = saved
	}
	b, _ := json.Marshal(pn)
	if err := writeAtomic(filepath.Join(c.RunDir, FileNetwork), b); err != nil {
		return nil, err
	}
	tap, err := createTap(c.Tap, pn.MTU)
	if err != nil {
		return nil, err
	}
	if err := redirect(pod, tap); err != nil {
		return nil, fmt.Errorf("redirect %s to %s: %w", c.PodIface, c.Tap, err)
	}
	if err := redirect(tap, pod); err != nil {
		return nil, fmt.Errorf("redirect %s to %s: %w", c.Tap, c.PodIface, err)
	}
	if err := dropDHCP(tap); err != nil {
		return nil, fmt.Errorf("drop guest DHCP on %s: %w", c.Tap, err)
	}
	if err := flushAddrs(pod); err != nil {
		return nil, err
	}
	// Best effort: /proc/sys is read-only in most containers. With all
	// addresses gone and every frame redirected, the pod stack is quiet
	// anyway.
	_ = os.WriteFile("/proc/sys/net/ipv6/conf/"+c.PodIface+"/disable_ipv6", []byte("1"), 0)
	return pn, nil
}

// podNetwork reads the settings of the pod interface. Link-local IPv6
// addresses and routes the kernel adds for addresses are left out; the
// guest kernel creates its own.
func podNetwork(link netlink.Link) (*PodNetwork, error) {
	a := link.Attrs()
	pn := &PodNetwork{Iface: a.Name, MAC: a.HardwareAddr.String(), MTU: a.MTU}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("list addresses of %s: %w", a.Name, err)
	}
	for _, ad := range addrs {
		if ad.IP.IsLinkLocalUnicast() {
			continue
		}
		pn.Addresses = append(pn.Addresses, ad.IPNet.String())
	}
	routes, err := netlink.RouteList(link, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("list routes of %s: %w", a.Name, err)
	}
	for _, r := range routes {
		if r.Protocol == unix.RTPROT_KERNEL || r.Type != unix.RTN_UNICAST {
			continue
		}
		if r.Dst != nil && (r.Dst.IP.IsLinkLocalUnicast() || r.Dst.IP.IsMulticast()) {
			continue
		}
		pn.Routes = append(pn.Routes, toRoute(r))
	}
	sortRoutes(pn.Routes)
	return pn, nil
}

func toRoute(r netlink.Route) Route {
	out := Route{
		Onlink: r.Flags&unix.RTNH_F_ONLINK != 0,
		Metric: r.Priority,
		IPv6:   r.Family == unix.AF_INET6,
	}
	if r.Dst != nil {
		ones, _ := r.Dst.Mask.Size()
		if !(r.Dst.IP.IsUnspecified() && ones == 0) {
			out.Destination = r.Dst.String()
		}
	}
	if r.Gw != nil {
		out.Gateway = r.Gw.String()
	}
	if r.Src != nil {
		out.Source = r.Src.String()
	}
	return out
}

// sortRoutes puts routes on the link (no gateway) first, so the gateways
// of the other routes are reachable when they are added. The order is
// otherwise kept.
func sortRoutes(rs []Route) {
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].Gateway == "" && rs[j].Gateway != "" })
}

func createTap(name string, mtu int) (netlink.Link, error) {
	if old, err := netlink.LinkByName(name); err == nil {
		// Left over from a previous container in the same pod.
		_ = netlink.LinkDel(old)
	}
	tap := &netlink.Tuntap{
		LinkAttrs: netlink.LinkAttrs{Name: name, MTU: mtu},
		Mode:      netlink.TUNTAP_MODE_TAP,
		// Must match what Cloud Hypervisor asks for with one queue pair.
		Flags: netlink.TUNTAP_NO_PI | netlink.TUNTAP_VNET_HDR,
		Owner: uint32(os.Getuid()),
		Group: uint32(os.Getgid()),
	}
	if err := netlink.LinkAdd(tap); err != nil {
		return nil, fmt.Errorf("create tap %s: %w", name, err)
	}
	// netlink keeps the creating fds open; close them so only the
	// persistent device remains.
	for _, f := range tap.Fds {
		f.Close()
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, err
	}
	if mtu > 0 {
		if err := netlink.LinkSetMTU(link, mtu); err != nil {
			return nil, fmt.Errorf("tap mtu: %w", err)
		}
	}
	// Bring it up now: Cloud Hypervisor skips SIOCSIFFLAGS for an up
	// device, which it could not do without CAP_NET_ADMIN.
	if err := netlink.LinkSetUp(link); err != nil {
		return nil, fmt.Errorf("tap up: %w", err)
	}
	return link, nil
}

// redirect sends every frame received on from out of to.
func redirect(from, to netlink.Link) error {
	idx := from.Attrs().Index
	ingress := &netlink.Ingress{QdiscAttrs: netlink.QdiscAttrs{
		LinkIndex: idx, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_INGRESS,
	}}
	_ = netlink.QdiscDel(ingress) // left over from a previous container
	if err := netlink.QdiscAdd(ingress); err != nil {
		return fmt.Errorf("add ingress qdisc (needs sch_ingress): %w", err)
	}
	f := &netlink.MatchAll{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: idx, Parent: netlink.MakeHandle(0xffff, 0), Priority: 2, Protocol: unix.ETH_P_ALL,
		},
		Actions: []netlink.Action{netlink.NewMirredAction(to.Attrs().Index)},
	}
	if err := netlink.FilterAdd(f); err != nil {
		return fmt.Errorf("add matchall filter (needs cls_matchall, act_mirred): %w", err)
	}
	return nil
}

// dropDHCP adds a prio 1 filter on the ingress of link (the TAP device)
// that drops UDP to port 67, ahead of the redirect, so the guest's DHCP
// requests do not leak into the pod network. The DHCP server still gets
// them: ETH_P_ALL packet sockets see frames before tc ingress runs.
func dropDHCP(link netlink.Link) error {
	udp := nl.IPProto(unix.IPPROTO_UDP)
	f := &netlink.Flower{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index, Parent: netlink.MakeHandle(0xffff, 0), Priority: 1, Protocol: unix.ETH_P_IP,
		},
		EthType:  unix.ETH_P_IP,
		IPProto:  &udp,
		DestPort: 67,
		Actions:  []netlink.Action{&netlink.GenericAction{ActionAttrs: netlink.ActionAttrs{Action: netlink.TC_ACT_SHOT}}},
	}
	if err := netlink.FilterAdd(f); err != nil {
		return fmt.Errorf("add flower filter (needs cls_flower, act_gact): %w", err)
	}
	return nil
}

// flushAddrs removes every address of link, IPv4 and IPv6.
func flushAddrs(link netlink.Link) error {
	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	var errs []error
	for _, a := range addrs {
		if err := netlink.AddrDel(link, &a); err != nil && !errors.Is(err, unix.EADDRNOTAVAIL) {
			errs = append(errs, fmt.Errorf("remove %s from %s: %w", a.IPNet, link.Attrs().Name, err))
		}
	}
	return errors.Join(errs...)
}

// FirstIP returns the first address of n without the prefix length, or "".
func (n *PodNetwork) FirstIP() string {
	for _, a := range n.Addresses {
		if ip, _, err := net.ParseCIDR(a); err == nil {
			return ip.String()
		}
	}
	return ""
}
