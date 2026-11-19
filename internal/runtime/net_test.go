package runtime

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/Azure/blip/internal/netpolicy"
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

// TestPolicyAllowsRelatedICMPErrors covers PMTUD and related transport
// errors: router ICMP destination-unreachable replies (type 3: fragmentation
// needed, port/host/net/protocol unreachable) and time-exceeded (type 11) are
// RELATED to a permitted flow, but the guest gate used to admit only
// established TCP/UDP replies and frag-needed, so the guest never lowered its
// path MTU and UDP sockets never learned that an allowed port was closed.
// General ICMP (echo, router advertisements) stays denied.
func TestPolicyAllowsRelatedICMPErrors(t *testing.T) {
	policy := &netpolicy.Policy{Revision: "allow", Layers: [][]netpolicy.Rule{
		{{CIDR: "0.0.0.0/0", Protocol: "TCP", Port: 443}},
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
		rule := "ct state related icmp type destination-unreachable icmp code " + code + " counter accept"
		if !strings.Contains(toGuest, rule) {
			t.Errorf("to_guest does not admit %q:\n%s", rule, toGuest)
		}
	}
	if rule := "ct state related icmp type time-exceeded counter accept"; !strings.Contains(toGuest, rule) {
		t.Errorf("to_guest does not admit %q:\n%s", rule, toGuest)
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
	// Inbound checks ignore ports: the source port of a new connection is
	// ephemeral. They still honor the address exception and protocol.
	first := scriptChain(t, script, "inbound_0")
	if !strings.Contains(first, "ip saddr 198.51.100.0/24 counter return") {
		t.Errorf("inbound_0 does not allow the first layer's peer:\n%s", first)
	}
	second := scriptChain(t, script, "inbound_1")
	want := "ip saddr 0.0.0.0/0 ip saddr != 10.0.0.0/8 meta l4proto tcp counter return"
	if !strings.Contains(second, want) {
		t.Errorf("inbound_1 lacks %q:\n%s", want, second)
	}
	if strings.Contains(first+second, "dport") || strings.Contains(first+second, "sport") {
		t.Errorf("inbound peer check uses a port:\n%s\n%s", first, second)
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
