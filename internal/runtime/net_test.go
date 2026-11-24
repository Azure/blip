// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package runtime

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	v1alpha1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/netpolicy"
	"github.com/Azure/blip/internal/network"
	corev1 "k8s.io/api/core/v1"
)

func testPodNet(run commandRunner) *podNet {
	return &podNet{iface: "eth0", podIP: "192.0.2.2", guestIP: "169.254.10.2", gateway: "169.254.10.1", mac: "02:62:a9:fe:0a:02", run: run}
}

func TestPrivateLinkAvoidsRoutes(t *testing.T) {
	first, err := privateLink("192.0.2.2", nil)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := privateLink("192.0.2.2", nil)
	if first != again || first.Bits() != 30 || !first.Addr().IsLinkLocalUnicast() {
		t.Fatalf("unstable or invalid link %s/%s", first, again)
	}
	second, err := privateLink("192.0.2.2", []netip.Prefix{first, netip.MustParsePrefix("169.254.1.1/32")})
	if err != nil || second.Overlaps(first) {
		t.Fatalf("conflicting link %s: %v", second, err)
	}
	if _, err := privateLink("192.0.2.2", []netip.Prefix{netip.MustParsePrefix("169.254.0.0/16")}); err == nil {
		t.Fatal("exhausted link-local space was accepted")
	}
	ip := first.Addr().Next().Next()
	mac := guestMAC(ip, "")
	hw, err := net.ParseMAC(mac)
	if err != nil || hw[0]&3 != 2 || guestMAC(ip, mac) == mac {
		t.Fatalf("guest MAC not local/unicast/distinct: %s", mac)
	}
}

func TestPolicyValidation(t *testing.T) {
	valid := netpolicy.Rule{CIDR: "10.0.0.0/8", Except: []string{"10.2.0.0/16"}, Protocol: "TCP", Port: 80, EndPort: 90}
	for _, reverse := range []bool{false, true} {
		match := ruleMatch(valid, reverse)
		want := "tcp dport 80-90"
		if reverse {
			want = "tcp sport 80-90"
		}
		if !strings.Contains(match, want) || !strings.Contains(match, "!= 10.2.0.0/16") {
			t.Fatalf("match %q", match)
		}
	}
	for _, rule := range []netpolicy.Rule{
		{CIDR: "::/0"}, {CIDR: "10.0.0.1"}, {CIDR: "0.0.0.0/0; accept"},
		{CIDR: "10.0.0.0/8", Except: []string{"11.0.0.0/8"}},
		{CIDR: "10.0.0.0/8", Except: []string{"0.0.0.0/0"}},
		{CIDR: "0.0.0.0/0", Except: []string{"::/0"}},
		{CIDR: "0.0.0.0/0", Protocol: "icmp"},
		{CIDR: "0.0.0.0/0", Protocol: "SCTP"},
		{CIDR: "0.0.0.0/0", Protocol: "tcp; accept"},
		{CIDR: "0.0.0.0/0", Port: 80},
		{CIDR: "0.0.0.0/0", Protocol: "UDP", Port: -1},
		{CIDR: "0.0.0.0/0", Protocol: "TCP", Port: 65536},
		{CIDR: "0.0.0.0/0", Protocol: "UDP", EndPort: 53},
		{CIDR: "0.0.0.0/0", Protocol: "TCP", Port: 90, EndPort: 80},
	} {
		if err := rule.Validate(); err == nil {
			t.Errorf("accepted invalid rule %+v", rule)
		}
	}
	if _, err := testPodNet(nil).policyScript(&netpolicy.Policy{}, true); err == nil {
		t.Fatal("accepted empty revision")
	}
}

// scriptChain returns the body of one generated nftables chain.
func scriptChain(t *testing.T, script, name string) string {
	t.Helper()
	marker := "chain " + name + " {"
	start := strings.Index(script, marker)
	if start < 0 {
		t.Fatalf("script has no %s chain:\n%s", name, script)
	}
	end := strings.Index(script[start:], "\n }")
	if end < 0 {
		t.Fatalf("%s chain is unterminated:\n%s", name, script)
	}
	return script[start : start+end]
}

// relatedChainAllows evaluates a generated related_<i> chain for the ORIGINAL
// destination of a conntrack entry. The chains only match the egress
// destination, so an ICMP error is admitted only when it quotes a flow the
// guest originated to an address the layer allows.
func relatedChainAllows(t *testing.T, chain, dst string) bool {
	t.Helper()
	dstIP := netip.MustParseAddr(dst)
	for _, line := range strings.Split(chain, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasSuffix(line, "counter return") || !strings.Contains(line, "ct original ip daddr") {
			continue
		}
		fields := strings.Fields(line)
		allowed, positive := true, false
		for i := 0; i+3 < len(fields); i++ {
			if fields[i] != "ct" || fields[i+1] != "original" || fields[i+2] != "ip" || fields[i+3] != "daddr" {
				continue
			}
			negative, at := false, i+4
			if at < len(fields) && fields[at] == "!=" {
				negative, at = true, at+1
			}
			if at >= len(fields) {
				t.Fatalf("malformed original destination match: %q", line)
			}
			var prefix netip.Prefix
			if p, err := netip.ParsePrefix(fields[at]); err == nil {
				prefix = p
			} else {
				addr, err := netip.ParseAddr(fields[at])
				if err != nil {
					t.Fatalf("malformed address in %q: %v", line, err)
				}
				prefix = netip.PrefixFrom(addr, addr.BitLen())
			}
			if negative {
				if prefix.Contains(dstIP) {
					allowed = false
				}
			} else {
				positive = true
				if !prefix.Contains(dstIP) {
					allowed = false
				}
			}
			i = at
		}
		if positive && allowed {
			return true
		}
	}
	return false
}

// TestPolicyAllowsRelatedICMPErrors covers PMTUD and related transport
// errors: router ICMP destination-unreachable replies (type 3: fragmentation
// needed, port/host/net/protocol unreachable) and time-exceeded (type 11) are
// RELATED to a permitted flow, but the guest gate used to admit only
// established TCP/UDP replies and frag-needed, so the guest never lowered its
// path MTU and UDP sockets never learned that an allowed port was closed.
// General ICMP (echo, router advertisements) stays denied. The errors are
// admitted only through the policy layers, so a revoked flow loses them.
func TestPolicyAllowsRelatedICMPErrors(t *testing.T) {
	policy := &netpolicy.Policy{Revision: "allow", Layers: [][]netpolicy.Rule{
		{{CIDR: "198.51.100.0/24", Protocol: "UDP", Port: 53}},
	}}
	script, err := testPodNet(nil).policyScript(policy, true)
	if err != nil {
		t.Fatal(err)
	}
	toGuest := scriptChain(t, script, "to_guest")
	for _, code := range []string{
		"net-unreachable", "host-unreachable", "prot-unreachable",
		"port-unreachable", "frag-needed",
	} {
		rule := "ct state related icmp type destination-unreachable icmp code " + code + " jump related"
		if !strings.Contains(toGuest, rule) {
			t.Errorf("to_guest does not admit %q:\n%s", rule, toGuest)
		}
	}
	if rule := "ct state related icmp type time-exceeded jump related"; !strings.Contains(toGuest, rule) {
		t.Errorf("to_guest does not admit %q:\n%s", rule, toGuest)
	}
	// No ICMP accept may bypass the layer chains: every RELATED error must go
	// through the dispatcher, and the dispatcher accepts only after all layer
	// chains return. The DNAT rules use `meta l4proto != icmp`, so select only
	// the related-error rules here.
	for _, line := range strings.Split(toGuest, "\n") {
		if !strings.Contains(line, "ct state related icmp type") {
			continue
		}
		if strings.Contains(line, "counter accept") {
			t.Errorf("to_guest accepts an ICMP error without a layer gate: %s", strings.TrimSpace(line))
		}
		if !strings.Contains(line, "jump related") {
			t.Errorf("to_guest has an ICMP path that bypasses the layer gate: %s", strings.TrimSpace(line))
		}
	}
	related := scriptChain(t, script, "related")
	if !strings.Contains(related, "jump related_0") || !strings.Contains(related, "counter accept") {
		t.Errorf("related dispatcher is not layer gated:\n%s", related)
	}
	layer := scriptChain(t, script, "related_0")
	if !strings.Contains(layer, "ct original ip daddr 198.51.100.0/24 ct original ip daddr != 192.0.2.2 counter return") {
		t.Errorf("related_0 does not match the allowed original destination:\n%s", layer)
	}
	// PMTUD/ECONNREFUSED for the allowed flow remains reachable: the original
	// destination of the quoted packet passes every layer.
	if !relatedChainAllows(t, layer, "198.51.100.10") {
		t.Errorf("related_0 denies a permitted flow:\n%s", layer)
	}
	// Symbolic types/codes only: numeric selectors are not portable across
	// nftables versions, and echo (8), echo-reply (0), and router
	// advertisement (9) must never be admitted.
	for _, rule := range []string{
		"icmp type 8", "icmp type 0", "icmp type 9", "meta l4proto icmp",
		"icmp type 3", "icmp code 0", "icmp code 1", "icmp code 3", "icmp code 4",
	} {
		if strings.Contains(script, rule) {
			t.Errorf("script uses a numeric or general ICMP selector %q:\n%s", rule, script)
		}
	}
	// A warm VM or deny-all gate must not open the ICMP path before a policy.
	closed, err := testPodNet(nil).policyScript(policy, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(scriptChain(t, closed, "to_guest"), "icmp") {
		t.Errorf("inactive gate admits ICMP:\n%s", closed)
	}
}

// TestPolicyDenyAllHasNoRelatedICMPPath is the live-revocation regression:
// `spec.network.egress: []` compiles to an empty layer, and a stale
// conntrack entry must not keep delivering related ICMP errors (PMTUD or
// ECONNREFUSED) to the guest. With any empty layer the whole related-ICMP
// path is omitted; the data path falls through to drop as well.
func TestPolicyDenyAllHasNoRelatedICMPPath(t *testing.T) {
	for _, tt := range []struct {
		name   string
		policy *netpolicy.Policy
	}{
		{"no layers", &netpolicy.Policy{Revision: "deny"}},
		{"empty layer", &netpolicy.Policy{Revision: "deny", Layers: [][]netpolicy.Rule{{}}}},
		{"pool allow plus empty blip layer", &netpolicy.Policy{Revision: "deny", Layers: [][]netpolicy.Rule{
			{{CIDR: "10.96.0.0/12", Protocol: "UDP", Port: 53}},
			{},
		}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			script, err := testPodNet(nil).policyScript(tt.policy, true)
			if err != nil {
				t.Fatal(err)
			}
			toGuest := scriptChain(t, script, "to_guest")
			if strings.Contains(toGuest, "ct state related icmp") {
				t.Errorf("deny-all to_guest still has a related ICMP path:\n%s", toGuest)
			}
			// No reply path either: the jump may remain, but the reply chain
			// must drop every packet so an established flow cannot survive a
			// policy that revokes everything.
			if strings.Contains(toGuest, "counter accept") {
				t.Errorf("deny-all to_guest has an accept:\n%s", toGuest)
			}
			if len(tt.policy.Layers) == 0 {
				if reply := scriptChain(t, script, "reply"); strings.Contains(reply, "counter return") ||
					!strings.Contains(reply, "counter drop") {
					t.Errorf("deny-all reply chain does not drop every reply:\n%s", reply)
				}
			}
			for i, layer := range tt.policy.Layers {
				if len(layer) != 0 {
					continue
				}
				if reply := scriptChain(t, script, "reply_"+strconv.Itoa(i)); strings.Contains(reply, "counter return") ||
					!strings.Contains(reply, "counter drop") {
					t.Errorf("empty reply layer %d does not drop every reply:\n%s", i, reply)
				}
			}
			if strings.Contains(script, "inbound") {
				t.Errorf("deny-all generates inbound chains:\n%s", script)
			}
			for _, chain := range []string{"related", "related_0", "related_1"} {
				if strings.Contains(script, "chain "+chain+" {") {
					t.Errorf("deny-all generates %s:\n%s", chain, script)
				}
			}
		})
	}
}

// TestPolicyRelatedICMPMatchesOriginalDestination pins the revocation check:
// the layer must match the ICMP error's ORIGINAL flow destination, including
// the rule's private exceptions, so an error for a stale flow to a now-denied
// address is dropped even when the outer ICMP source would pass a public
// wildcard.
func TestPolicyRelatedICMPMatchesOriginalDestination(t *testing.T) {
	policy := &netpolicy.Policy{Revision: "allow", Layers: [][]netpolicy.Rule{{
		{CIDR: "0.0.0.0/0", Except: []string{"10.0.0.0/8"}, Protocol: "TCP", Port: 443},
	}}}
	script, err := testPodNet(nil).policyScript(policy, true)
	if err != nil {
		t.Fatal(err)
	}
	layer := scriptChain(t, script, "related_0")
	if !strings.Contains(layer, "ct original ip daddr 0.0.0.0/0 ct original ip daddr != 10.0.0.0/8 ct original ip daddr != 192.0.2.2 counter return") {
		t.Errorf("related_0 does not carry the rule's exceptions:\n%s", layer)
	}
	if !relatedChainAllows(t, layer, "203.0.113.10") {
		t.Errorf("related_0 denies a public original destination:\n%s", layer)
	}
	// The hunt's post-SNAT DNS peer is private and excluded, so its stale
	// ICMP port-unreachable/frag-needed must no longer match.
	if relatedChainAllows(t, layer, "10.96.0.10") {
		t.Errorf("related_0 still admits an excluded private destination:\n%s", layer)
	}

	// A policy naming only public CIDRs must not match a private original
	// destination either.
	public := &netpolicy.Policy{Revision: "allow", Layers: [][]netpolicy.Rule{{
		{CIDR: "203.0.113.0/24", Protocol: "UDP", Port: 53},
	}}}
	script, err = testPodNet(nil).policyScript(public, true)
	if err != nil {
		t.Fatal(err)
	}
	publicLayer := scriptChain(t, script, "related_0")
	if relatedChainAllows(t, publicLayer, "10.96.0.10") || relatedChainAllows(t, publicLayer, "192.0.2.2") {
		t.Errorf("public-only related_0 admits a private original destination:\n%s", publicLayer)
	}
	if !relatedChainAllows(t, publicLayer, "203.0.113.53") {
		t.Errorf("public-only related_0 denies its own peer:\n%s", publicLayer)
	}

	// The AND still applies: every layer must return before the dispatcher
	// accepts, so a layer that excludes the original destination revokes the
	// ICMP path even if an earlier layer would have allowed it.
	layered := &netpolicy.Policy{Revision: "allow", Layers: [][]netpolicy.Rule{
		{{CIDR: "0.0.0.0/0", Except: []string{"10.0.0.0/8"}}},
		{{CIDR: "10.0.0.0/8"}},
	}}
	script, err = testPodNet(nil).policyScript(layered, true)
	if err != nil {
		t.Fatal(err)
	}
	first := scriptChain(t, script, "related_0")
	second := scriptChain(t, script, "related_1")
	if relatedChainAllows(t, first, "10.96.0.10") || !relatedChainAllows(t, second, "10.96.0.10") {
		t.Errorf("layer AND is not preserved for related ICMP:\n%s\n%s", first, second)
	}
	related := scriptChain(t, script, "related")
	if !strings.Contains(related, "jump related_0\n  jump related_1") ||
		!strings.HasSuffix(strings.TrimSpace(related), "counter accept") {
		t.Errorf("related dispatcher does not require every layer:\n%s", related)
	}
}

// TestPolicyRelatedICMPIgnoresInboundFlow pins the egress-only design: the
// related chains match the ORIGINAL destination of the quoted flow, which for
// an inbound DNAT connection is the pod itself. Because inbound connections
// are never admitted, an allowed peer's address must not be substituted for
// the destination, and the pod IP is always excluded.
func TestPolicyRelatedICMPIgnoresInboundFlow(t *testing.T) {
	policy := &netpolicy.Policy{Revision: "allow", Layers: [][]netpolicy.Rule{{
		{CIDR: "10.244.2.93/32", Protocol: "TCP", Port: 8443},
	}}}
	script, err := testPodNet(nil).policyScript(policy, true)
	if err != nil {
		t.Fatal(err)
	}
	layer := scriptChain(t, script, "related_0")
	if strings.Contains(script, "ct original ip saddr") {
		t.Errorf("related chains match an original source:\n%s", script)
	}
	want := "ct original ip daddr 10.244.2.93/32 ct original ip daddr != 192.0.2.2 counter return"
	if !strings.Contains(layer, want) {
		t.Errorf("related_0 does not match only the original destination:\n%s", layer)
	}
	// An ICMP error quoting an inbound connection has the pod as its original
	// destination, so it never matches, even though the peer is allowed.
	if relatedChainAllows(t, layer, "192.0.2.2") {
		t.Errorf("related_0 admits an inbound flow to the pod:\n%s", layer)
	}
	if !relatedChainAllows(t, layer, "10.244.2.93") {
		t.Errorf("related_0 denies an allowed egress destination:\n%s", layer)
	}
	if relatedChainAllows(t, layer, "10.244.2.94") {
		t.Errorf("related_0 admits an unlisted egress destination:\n%s", layer)
	}

	// A rule that covers the pod IP grants no related path either: matching it
	// would also match the inbound form, so the pod exclusion wins.
	podEgress := &netpolicy.Policy{Revision: "allow", Layers: [][]netpolicy.Rule{{
		{CIDR: "192.0.2.2/32"},
	}}}
	script, err = testPodNet(nil).policyScript(podEgress, true)
	if err != nil {
		t.Fatal(err)
	}
	podLayer := scriptChain(t, script, "related_0")
	if relatedChainAllows(t, podLayer, "192.0.2.2") || relatedChainAllows(t, podLayer, "10.244.9.9") {
		t.Errorf("pod-IP egress rule grants a related path:\n%s", podLayer)
	}
}

// TestPolicyRelatedICMPKeepsLayerAND pins the layer AND for related errors:
// every layer must return for the original destination before the dispatcher
// accepts, so narrowing the Blip layer revokes errors for an otherwise
// allowed flow.
func TestPolicyRelatedICMPKeepsLayerAND(t *testing.T) {
	dst := "10.244.2.93"
	policy := &netpolicy.Policy{Revision: "allow", Layers: [][]netpolicy.Rule{
		{{CIDR: "10.244.0.0/16"}},
		{{CIDR: dst + "/32"}},
	}}
	script, err := testPodNet(nil).policyScript(policy, true)
	if err != nil {
		t.Fatal(err)
	}
	for i := range policy.Layers {
		if !relatedChainAllows(t, scriptChain(t, script, "related_"+strconv.Itoa(i)), dst) {
			t.Errorf("related_%d denies a destination allowed by every layer:\n%s", i, script)
		}
	}

	narrowed := &netpolicy.Policy{Revision: "allow", Layers: [][]netpolicy.Rule{
		{{CIDR: dst + "/32"}},
		{{CIDR: "203.0.113.0/24"}},
	}}
	script, err = testPodNet(nil).policyScript(narrowed, true)
	if err != nil {
		t.Fatal(err)
	}
	first := scriptChain(t, script, "related_0")
	second := scriptChain(t, script, "related_1")
	if !relatedChainAllows(t, first, dst) || relatedChainAllows(t, second, dst) {
		t.Errorf("related layer AND is not preserved:\n%s\n%s", first, second)
	}
	related := scriptChain(t, script, "related")
	if !strings.Contains(related, "jump related_0\n  jump related_1") ||
		!strings.HasSuffix(strings.TrimSpace(related), "counter accept") {
		t.Errorf("related dispatcher does not require every layer:\n%s", related)
	}
}

// TestPolicyHasNoInboundAdmission pins the egress-only data path: there are no
// inbound chains, to_guest admits only related ICMP errors and replies to
// guest-originated flows, and from_guest only runs the anti-spoof checks and
// the egress chain. In particular a new inbound connection, unsolicited echo,
// and the DNAT-reply bypass are all dropped.
func TestPolicyHasNoInboundAdmission(t *testing.T) {
	policy := &netpolicy.Policy{Revision: "allow", Layers: [][]netpolicy.Rule{
		{{CIDR: "0.0.0.0/0", Protocol: "TCP", Port: 443}},
	}}
	script, err := testPodNet(nil).policyScript(policy, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"inbound_", "inbound_reply_"} {
		if strings.Contains(script, name) {
			t.Errorf("script still generates %s chains:\n%s", name, script)
		}
	}
	toGuest := scriptChain(t, script, "to_guest")
	if !strings.Contains(toGuest, "ct direction reply ct state established jump reply") {
		t.Errorf("to_guest does not admit replies through the layer chains:\n%s", toGuest)
	}
	for _, line := range strings.Split(toGuest, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "counter accept") {
			continue
		}
		t.Errorf("to_guest has an unconditional accept: %s", line)
	}
	// The only accepts on this path are inside the reply dispatcher and the
	// related dispatcher, both reached from to_guest.
	reply := scriptChain(t, script, "reply")
	if !strings.Contains(reply, "jump reply_0") || !strings.HasSuffix(strings.TrimSpace(reply), "counter accept") {
		t.Errorf("reply dispatcher does not run every layer:\n%s", reply)
	}
	fromGuest := scriptChain(t, script, "from_guest")
	if !strings.Contains(fromGuest, "ct direction original jump egress") {
		t.Errorf("from_guest does not gate new flows through egress:\n%s", fromGuest)
	}
	if strings.Contains(fromGuest, "ct direction reply") || strings.Contains(fromGuest, "ct state established") {
		t.Errorf("from_guest has a reply bypass:\n%s", fromGuest)
	}
	if strings.Contains(fromGuest, "counter accept") {
		t.Errorf("from_guest accepts without consulting egress policy:\n%s", fromGuest)
	}
	if !strings.HasSuffix(strings.TrimSpace(fromGuest), "counter drop") {
		t.Errorf("from_guest does not end in drop:\n%s", fromGuest)
	}
	// Unsupported protocols, spoofed sources, and the wrong interface are
	// dropped before the egress jump is reachable.
	for _, want := range []string{
		"meta nfproto != ipv4 counter drop",
		"ip saddr != 169.254.10.2 counter drop",
		"ct state invalid counter drop",
	} {
		if !strings.Contains(fromGuest, want) {
			t.Errorf("from_guest lacks %q:\n%s", want, fromGuest)
		}
	}
}

// TestPolicyAllowsSidecarAPIFailClosed covers the guest's path to the Envoy
// sidecar: the guest sends HTTP to the TAP gateway, prerouting DNATs it to the
// sidecar's loopback listener, and local input accepts exactly that flow. The
// rules do not require egress permission, but a warm, deny-all, or explicit
// empty-layer policy must not open them.
func TestPolicyAllowsSidecarAPIFailClosed(t *testing.T) {
	policy := &netpolicy.Policy{Revision: "allow", Layers: [][]netpolicy.Rule{
		{{CIDR: "0.0.0.0/0", Protocol: "TCP", Port: 443}},
	}}
	script, err := testPodNet(nil).policyScript(policy, true)
	if err != nil {
		t.Fatal(err)
	}
	accept := `iifname "blip-tap0" ip saddr 169.254.10.2 ip daddr 127.0.0.1 tcp dport 15080 counter accept`
	drop := `iifname "blip-tap0" counter drop`
	input := scriptChain(t, script, "input")
	at, dropAt := strings.Index(input, accept), strings.Index(input, drop)
	if at < 0 || dropAt < 0 || at > dropAt {
		t.Fatalf("input does not accept the sidecar flow before the TAP drop:\n%s", input)
	}
	dnat := `iifname "blip-tap0" ip saddr 169.254.10.2 ip daddr 169.254.10.1 tcp dport 80 dnat ip to 127.0.0.1:15080`
	redirect := `iifname "blip-tap0" ip daddr 169.254.10.1 dnat ip to 169.254.10.2`
	prerouting := scriptChain(t, script, "prerouting")
	at, redirectAt := strings.Index(prerouting, dnat), strings.Index(prerouting, redirect)
	if at < 0 || redirectAt < 0 || at > redirectAt {
		t.Fatalf("prerouting does not DNAT the sidecar flow before the general redirect:\n%s", prerouting)
	}

	for _, tt := range []struct {
		name   string
		policy *netpolicy.Policy
		active bool
	}{
		{"warm policy", policy, false},
		{"missing policy", nil, true},
		{"no layers", &netpolicy.Policy{Revision: "deny"}, true},
		{"empty layer", &netpolicy.Policy{Revision: "deny", Layers: [][]netpolicy.Rule{{}}}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			script, err := testPodNet(nil).policyScript(tt.policy, tt.active)
			if err != nil {
				t.Fatal(err)
			}
			if at := strings.Index(script, "127.0.0.1 tcp dport 15080"); at >= 0 {
				t.Errorf("closed policy still admits the sidecar flow:\n%s", script)
			}
			if at := strings.Index(script, "tcp dport 80 dnat"); at >= 0 {
				t.Errorf("closed policy still DNATs the sidecar flow:\n%s", script)
			}
			if input := scriptChain(t, script, "input"); !strings.Contains(input, drop) {
				t.Errorf("closed policy does not drop TAP input:\n%s", input)
			}
		})
	}
}

// TestPolicyReplyChainsMatchCurrentSourceAndPort pins the reply side: a reply
// to a guest-originated flow must match the CURRENT remote source address and
// the rule's protocol and port, in every layer. Replies use ephemeral source
// ports on the guest side, so only the remote (source) port is checked.
func TestPolicyReplyChainsMatchCurrentSourceAndPort(t *testing.T) {
	policy := &netpolicy.Policy{Revision: "allow", Layers: [][]netpolicy.Rule{
		{
			{CIDR: "10.0.0.0/8", Protocol: "TCP", Port: 4444},
			{CIDR: "10.1.0.0/16", Protocol: "UDP", Port: 53, EndPort: 54},
			{CIDR: "192.0.2.0/24", Protocol: "TCP"},
		},
		{{CIDR: "0.0.0.0/0", Except: []string{"10.0.0.0/8"}, Protocol: "TCP", Port: 443}},
	}}
	script, err := testPodNet(nil).policyScript(policy, true)
	if err != nil {
		t.Fatal(err)
	}
	reply := scriptChain(t, script, "reply_0")
	for _, want := range []string{
		"ip saddr 10.0.0.0/8 meta l4proto tcp tcp sport 4444 counter return",
		"ip saddr 10.1.0.0/16 meta l4proto udp udp sport 53-54 counter return",
		"ip saddr 192.0.2.0/24 meta l4proto tcp counter return",
	} {
		if !strings.Contains(reply, want) {
			t.Errorf("reply_0 lacks %q:\n%s", want, reply)
		}
	}
	if strings.Contains(reply, "dport") {
		t.Errorf("reply_0 checks a destination port that is ephemeral on the guest side:\n%s", reply)
	}
	if strings.Contains(reply, "ip saddr 10.0.0.0/8 meta l4proto tcp counter return") {
		t.Errorf("port-scoped rule admits every reply from the peer:\n%s", reply)
	}
	wildcard := scriptChain(t, script, "reply_1")
	want := "ip saddr 0.0.0.0/0 ip saddr != 10.0.0.0/8 meta l4proto tcp tcp sport 443 counter return"
	if !strings.Contains(wildcard, want) {
		t.Errorf("reply_1 lacks %q:\n%s", want, wildcard)
	}
	// The dispatcher ANDs every layer before accepting: a rule that matches in
	// one layer cannot bypass a narrower layer.
	dispatcher := scriptChain(t, script, "reply")
	if !strings.Contains(dispatcher, "jump reply_0\n  jump reply_1") ||
		!strings.HasSuffix(strings.TrimSpace(dispatcher), "counter accept") {
		t.Errorf("reply dispatcher does not require every layer:\n%s", dispatcher)
	}
	// Egress keeps checking destination address and destination port.
	egress := scriptChain(t, script, "egress_0")
	if !strings.Contains(egress, "ip daddr 10.0.0.0/8 meta l4proto tcp tcp dport 4444 counter return") {
		t.Errorf("egress_0 does not check the destination port:\n%s", egress)
	}
}

// TestPolicyCompiledPoliciesStayEgressOnly compiles a pool and Blip policy
// with explicit IP blocks, as the node agent does, and checks the resulting
// script: DNS rules are present, the always-on hard-deny layer is last, and
// the reply chains still enforce every layer.
func TestPolicyCompiledPoliciesStayEgressOnly(t *testing.T) {
	pool := &v1alpha1.NetworkPolicy{Egress: []v1alpha1.NetworkEgressRule{{
		To:    []v1alpha1.NetworkPeer{{IPBlock: &v1alpha1.NetworkIPBlock{CIDR: "0.0.0.0/0", Except: []string{"10.0.0.0/8"}}}},
		Ports: []v1alpha1.NetworkPort{{Protocol: corev1.ProtocolTCP, Port: 443}},
	}}}
	blip := &v1alpha1.NetworkPolicy{Egress: []v1alpha1.NetworkEgressRule{{
		To: []v1alpha1.NetworkPeer{{IPBlock: &v1alpha1.NetworkIPBlock{CIDR: "198.51.100.0/24"}}},
	}}}
	policy, err := network.Compile(pool, blip, network.DefaultNameservers)
	if err != nil {
		t.Fatal(err)
	}
	script, err := testPodNet(nil).policyScript(&policy, true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(script, "inbound") {
		t.Errorf("compiled policy generates inbound chains:\n%s", script)
	}
	egress := scriptChain(t, script, "egress_0")
	if !strings.Contains(egress, "ip daddr 0.0.0.0/0 ip daddr != 10.0.0.0/8 meta l4proto tcp tcp dport 443 counter return") {
		t.Errorf("pool egress layer lost its public rule:\n%s", egress)
	}
	for _, nameserver := range network.DefaultNameservers {
		for _, proto := range []string{"udp", "tcp"} {
			want := "ip daddr " + nameserver + "/32 meta l4proto " + proto + " " + proto + " dport 53 counter return"
			if !strings.Contains(egress, want) {
				t.Errorf("pool egress layer lacks DNS rule %q:\n%s", want, egress)
			}
		}
	}
	blipLayer := scriptChain(t, script, "egress_1")
	if !strings.Contains(blipLayer, "ip daddr 198.51.100.0/24 counter return") {
		t.Errorf("blip egress layer lost its IP block:\n%s", blipLayer)
	}
	// The compiler appends the blocked-destination layer last; every rule
	// matches 0.0.0.0/0 minus the blocked ranges.
	hardDeny := scriptChain(t, script, "egress_2")
	for _, blocked := range []string{
		"0.0.0.0/8", "127.0.0.0/8", "168.63.129.16/32",
		"169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
	} {
		if !strings.Contains(hardDeny, "ip daddr != "+blocked) {
			t.Errorf("hard-deny layer does not exclude %s:\n%s", blocked, hardDeny)
		}
	}
	// Replies check the CURRENT remote source and port in every layer.
	reply := scriptChain(t, script, "reply")
	if !strings.Contains(reply, "jump reply_0\n  jump reply_1\n  jump reply_2") ||
		!strings.HasSuffix(strings.TrimSpace(reply), "counter accept") {
		t.Errorf("compiled reply dispatcher does not require every layer:\n%s", reply)
	}
	if !strings.Contains(scriptChain(t, script, "reply_0"), "ip saddr 0.0.0.0/0 ip saddr != 10.0.0.0/8 meta l4proto tcp tcp sport 443 counter return") {
		t.Errorf("compiled reply_0 does not check the current source and port:\n%s", script)
	}
}

func TestApplyInvalidPolicyRevokesAndNftFailureDisablesTap(t *testing.T) {
	var calls []string
	nftFails, ipFails := false, false
	p := testPodNet(func(input, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " ")+"\n"+input)
		if (name == "nft" && nftFails) || (name == "ip" && ipFails) {
			return nil, errors.New("unavailable")
		}
		return nil, nil
	})
	invalid := &netpolicy.Policy{Revision: "bad", Layers: [][]netpolicy.Rule{{{CIDR: "garbage"}}}}
	if _, err := p.apply(invalid, true); err == nil {
		t.Fatal("invalid policy applied")
	}
	if len(calls) != 1 || !strings.Contains(calls[0], "chain egress {\n  counter drop") || strings.Contains(calls[0], "jump egress\n") {
		t.Fatalf("invalid policy did not install closed gate: %v", calls)
	}
	nftFails = true
	calls = nil
	if _, err := p.apply(&netpolicy.Policy{Revision: "deny"}, true); err == nil {
		t.Fatal("nft failure ignored")
	}
	if !p.disabled || p.unsafe || len(calls) != 3 || !strings.Contains(calls[2], "ip link set blip-tap0 down") {
		t.Fatalf("TAP not safely disabled: %+v %v", p, calls)
	}
	nftFails = false
	if unsafe, err := p.apply(&netpolicy.Policy{Revision: "recovered"}, true); err != nil || unsafe || p.disabled {
		t.Fatalf("failed to recover: %v", err)
	}
	nftFails, ipFails = true, true
	if unsafe, err := p.apply(invalid, true); err == nil || !unsafe || !p.unsafe {
		t.Fatal("uncontainable failure not reported")
	}
}

func TestCleanupKeepsDenyUntilTapRemoved(t *testing.T) {
	var calls []string
	fail := true
	p := testPodNet(func(input, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " ")+input)
		if name == "ip" && fail {
			return nil, errors.New("busy")
		}
		return nil, nil
	})
	p.tapCreated, p.tableCreated = true, true
	p.teardown()
	if len(calls) != 1 || !p.tableCreated {
		t.Fatalf("firewall removed before TAP: %v", calls)
	}
	fail = false
	p.teardown()
	if p.tableCreated || p.tapCreated || !strings.Contains(calls[len(calls)-1], "delete table inet blip_vm") {
		t.Fatalf("cleanup incomplete: %v", calls)
	}
}
