package runtime

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/Azure/blip/internal/netpolicy"
	"github.com/Azure/blip/internal/network"
)

func testPodNet(run commandRunner) *podNet {
	return &podNet{iface: "eth0", podIP: "192.0.2.2", guestIP: "169.254.10.2", mac: "02:62:a9:fe:0a:02", run: run}
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

// relatedChainAllows evaluates the simple address match that a generated
// related_<i> chain emits. The chains contain only positive
// `ct original ip daddr CIDR` terms and negative `!=` exceptions, so an
// address matches the layer when it is inside a positive prefix and outside
// every exception.
func relatedChainAllows(t *testing.T, chain, addr string) bool {
	t.Helper()
	ip := netip.MustParseAddr(addr)
	for _, line := range strings.Split(chain, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "ct original ip daddr") || !strings.HasSuffix(line, "counter return") {
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
			prefix := netip.MustParsePrefix(fields[at])
			if negative {
				if prefix.Contains(ip) {
					allowed = false
				}
			} else {
				positive = true
				if !prefix.Contains(ip) {
					allowed = false
				}
			}
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
	if !strings.Contains(layer, "ct original ip daddr 198.51.100.0/24 counter return") {
		t.Errorf("related_0 does not match the allowed original destination:\n%s", layer)
	}
	// PMTUD/ECONNREFUSED for the allowed flow remains reachable: the original
	// destination of the quoted packet passes every layer.
	if !relatedChainAllows(t, layer, "198.51.100.10") {
		t.Errorf("related_0 denies a permitted flow:\n%s", layer)
	}
	// The pod-IP DNAT accepts carry non-ICMP traffic only. In particular the
	// reply rule must not accept the echo reply that an unsolicited, spoofed
	// echo request would provoke.
	if !strings.Contains(toGuest, "ct status dnat ct original ip daddr 192.0.2.2 meta l4proto != icmp counter accept") {
		t.Errorf("to_guest DNAT accept does not exclude ICMP:\n%s", toGuest)
	}
	if body := scriptChain(t, script, "from_guest"); !strings.Contains(body, "ct state established meta l4proto != icmp counter accept") {
		t.Errorf("from_guest DNAT reply accept does not exclude ICMP:\n%s", body)
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
	if !strings.Contains(layer, "ct original ip daddr 0.0.0.0/0 ct original ip daddr != 10.0.0.0/8 counter return") {
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

// TestPolicyDropsNewInboundICMPEcho guards the reflection bypass: an
// unsolicited echo request addressed to the pod IP was DNATed to the guest,
// and the guest's echo reply matched the pod-IP DNAT reply accept, reaching a
// spoofed (possibly denied) source without consulting egress policy. Every
// accept rule must either exclude ICMP or be the RELATED-error rule, so a new
// echo request and its reply fall through to drop.
func TestPolicyDropsNewInboundICMPEcho(t *testing.T) {
	policy := &netpolicy.Policy{Revision: "allow", Layers: [][]netpolicy.Rule{
		{{CIDR: "0.0.0.0/0", Protocol: "TCP", Port: 443}},
	}}
	script, err := testPodNet(nil).policyScript(policy, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"to_guest", "from_guest"} {
		for _, line := range strings.Split(scriptChain(t, script, name), "\n") {
			if !strings.Contains(line, "counter accept") {
				continue
			}
			// A non-ICMP rule cannot match an echo. The RELATED rules only
			// match ICMP errors tied to an allowed conntrack entry, never a
			// new echo request or its reply.
			if strings.Contains(line, "meta l4proto != icmp") ||
				strings.Contains(line, "ct state related icmp type") {
				continue
			}
			t.Errorf("%s can accept an unsolicited ICMP echo: %s", name, strings.TrimSpace(line))
		}
	}
}

// TestPolicyInboundTrafficRequiresAllowedPeer guards the remaining
// TCP/UDP reflection bypass: the to_guest DNAT accept delivered a new
// connection from any source, and the guest's kernel RST/SYN-ACK or an
// application UDP reply then matched the from_guest DNAT accept before the
// egress chain. Both the new inbound connection and its return path now
// check the peer against every policy layer.
func TestPolicyInboundTrafficRequiresAllowedPeer(t *testing.T) {
	policy := &netpolicy.Policy{Revision: "allow", Layers: [][]netpolicy.Rule{
		{{CIDR: "198.51.100.0/24"}},
		{{CIDR: "0.0.0.0/0", Except: []string{"10.0.0.0/8"}, Protocol: "TCP", Port: 443}},
	}}
	script, err := testPodNet(nil).policyScript(policy, true)
	if err != nil {
		t.Fatal(err)
	}
	toGuest := scriptChain(t, script, "to_guest")
	inbound := "ct direction original ct status dnat ct original ip daddr 192.0.2.2 meta l4proto != icmp"
	for _, jump := range []string{"jump inbound_0", "jump inbound_1"} {
		if !strings.Contains(toGuest, inbound+" "+jump) {
			t.Errorf("to_guest does not check the peer before accepting: missing %q\n%s", jump, toGuest)
		}
	}
	if accept := strings.Index(toGuest, inbound+" counter accept"); accept < 0 ||
		accept < strings.Index(toGuest, inbound+" jump inbound_1") {
		t.Errorf("to_guest accepts a new inbound connection before the last peer layer:\n%s", toGuest)
	}
	// Inbound checks match the peer and the rule's destination port, but a
	// wildcard (0.0.0.0/0) rule names no peer and therefore grants no new
	// inbound connection. The rule still admits replies to the guest's own
	// egress, which carries an ephemeral source port.
	first := scriptChain(t, script, "inbound_0")
	if !strings.Contains(first, "ip saddr 198.51.100.0/24 counter return") {
		t.Errorf("inbound_0 does not allow the first layer's peer:\n%s", first)
	}
	second := scriptChain(t, script, "inbound_1")
	if strings.Contains(second, "counter return") {
		t.Errorf("wildcard public egress rule granted new inbound connections:\n%s", second)
	}
	if !strings.Contains(second, "counter drop") {
		t.Errorf("inbound_1 does not deny unmatched peers:\n%s", second)
	}
	// The reply path checks the reply's destination (the original peer) with
	// the same layers, so narrowing a policy stops established reflections.
	fromGuest := scriptChain(t, script, "from_guest")
	reply := "ct direction reply ct status dnat ct original ip daddr 192.0.2.2 ct state established meta l4proto != icmp"
	for _, jump := range []string{"jump inbound_reply_0", "jump inbound_reply_1"} {
		if !strings.Contains(fromGuest, reply+" "+jump) {
			t.Errorf("from_guest does not check the reply peer: missing %q\n%s", jump, fromGuest)
		}
	}
	if accept := strings.Index(fromGuest, reply+" counter accept"); accept < 0 ||
		accept < strings.Index(fromGuest, reply+" jump inbound_reply_1") {
		t.Errorf("from_guest returns to any peer before the last layer:\n%s", fromGuest)
	}
	replyChain := scriptChain(t, script, "inbound_reply_0")
	if !strings.Contains(replyChain, "ip daddr 198.51.100.0/24 counter return") {
		t.Errorf("inbound_reply_0 does not allow the peer:\n%s", replyChain)
	}
	// Replies to an inbound connection have an ephemeral destination port, so
	// they keep the broad peer and protocol check, including the wildcard
	// rule that no longer admits a new inbound connection.
	replyWildcard := scriptChain(t, script, "inbound_reply_1")
	wantReply := "ip daddr 0.0.0.0/0 ip daddr != 10.0.0.0/8 meta l4proto tcp counter return"
	if !strings.Contains(replyWildcard, wantReply) {
		t.Errorf("inbound_reply_1 lacks %q:\n%s", wantReply, replyWildcard)
	}
	if strings.Contains(first+second+replyWildcard, "dport") || strings.Contains(first+second+replyWildcard, "sport") {
		t.Errorf("address-only inbound peer check uses a port:\n%s\n%s\n%s", first, second, replyWildcard)
	}

	// An empty layer is default deny: the peer chain drops, so the accept
	// after the jump is unreachable and no DNAT reply is returned.
	closed, err := testPodNet(nil).policyScript(&netpolicy.Policy{Revision: "deny", Layers: [][]netpolicy.Rule{{}}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if body := scriptChain(t, closed, "inbound_0"); !strings.Contains(body, "counter drop") ||
		strings.Contains(body, "counter return") {
		t.Errorf("empty layer does not deny inbound peers:\n%s", body)
	}
	for _, chain := range []string{"to_guest", "from_guest"} {
		if body := scriptChain(t, closed, chain); !strings.Contains(body, "ct status dnat") {
			t.Errorf("%s lost its DNAT gate:\n%s", chain, body)
		}
	}
	// A policy with no layers has no peer set, so nothing inbound is accepted.
	empty, err := testPodNet(nil).policyScript(&netpolicy.Policy{Revision: "deny"}, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, chain := range []string{"to_guest", "from_guest"} {
		if body := scriptChain(t, empty, chain); strings.Contains(body, "ct status dnat") {
			t.Errorf("%s accepts inbound traffic without a policy layer:\n%s", chain, body)
		}
	}
	if strings.Contains(empty, "inbound_") {
		t.Errorf("peer chains generated without policy layers:\n%s", empty)
	}
}

// TestPolicyInboundMatchesRuleProtocolAndPort pins the ingress half of the
// egress peer gate: an allow for one remote port must not open every guest
// port to that peer. New inbound connections match the peer address, the
// protocol, and the rule's destination port (or range). A rule without ports
// still describes any port, and a wildcard rule still describes no peer, so it
// grants no new inbound connection at all.
func TestPolicyInboundMatchesRuleProtocolAndPort(t *testing.T) {
	policy := &netpolicy.Policy{Revision: "allow", Layers: [][]netpolicy.Rule{{
		{CIDR: "10.0.0.0/8", Protocol: "TCP", Port: 4444},
		{CIDR: "10.1.0.0/16", Protocol: "UDP", Port: 53, EndPort: 54},
		{CIDR: "192.0.2.0/24", Protocol: "TCP"},
	}}}
	script, err := testPodNet(nil).policyScript(policy, true)
	if err != nil {
		t.Fatal(err)
	}
	inbound := scriptChain(t, script, "inbound_0")
	for _, want := range []string{
		"ip saddr 10.0.0.0/8 meta l4proto tcp tcp dport 4444 counter return",
		"ip saddr 10.1.0.0/16 meta l4proto udp udp dport 53-54 counter return",
		"ip saddr 192.0.2.0/24 meta l4proto tcp counter return",
	} {
		if !strings.Contains(inbound, want) {
			t.Errorf("inbound_0 lacks %q:\n%s", want, inbound)
		}
	}
	if strings.Contains(inbound, "ip saddr 10.0.0.0/8 meta l4proto tcp counter return") {
		t.Errorf("port-scoped rule admits every guest TCP port:\n%s", inbound)
	}

	// A wildcard public allow (with private exceptions) is an egress rule,
	// not an ingress allowlist. Its peers are still checked for replies.
	wildcard := &netpolicy.Policy{Revision: "allow", Layers: [][]netpolicy.Rule{{
		{CIDR: "0.0.0.0/0", Except: []string{"10.0.0.0/8"}, Protocol: "TCP", Port: 443},
	}}}
	script, err = testPodNet(nil).policyScript(wildcard, true)
	if err != nil {
		t.Fatal(err)
	}
	if body := scriptChain(t, script, "inbound_0"); strings.Contains(body, "counter return") {
		t.Errorf("wildcard public rule grants a new inbound connection:\n%s", body)
	}
	if body := scriptChain(t, script, "inbound_reply_0"); !strings.Contains(body, "counter return") {
		t.Errorf("wildcard public rule no longer admits replies to allowed egress:\n%s", body)
	}
}

// TestPolicyDefaultPublicEgressGrantsNoNewInbound is the default-policy
// regression: its public wildcard is the most common egress allow, but it must
// not turn every public address into an ingress peer. Private and DNS rules
// that name a peer still admit their matching inbound traffic.
func TestPolicyDefaultPublicEgressGrantsNoNewInbound(t *testing.T) {
	policy, err := network.Compile("apps", network.Default(), nil, network.Destinations{})
	if err != nil {
		t.Fatal(err)
	}
	script, err := testPodNet(nil).policyScript(&policy, true)
	if err != nil {
		t.Fatal(err)
	}
	inbound := scriptChain(t, script, "inbound_0")
	if strings.Contains(inbound, "0.0.0.0/0") {
		t.Errorf("default public egress wildcard grants new inbound connections:\n%s", inbound)
	}
	if !strings.Contains(inbound, "ip saddr 169.254.10.10/32") {
		t.Errorf("default inbound chain is missing its named DNS peers:\n%s", inbound)
	}
	// Replies to the guest's own public egress still use the wildcard.
	reply := scriptChain(t, script, "inbound_reply_0")
	if !strings.Contains(reply, "ip daddr 0.0.0.0/0") {
		t.Errorf("default public egress no longer admits replies:\n%s", reply)
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
