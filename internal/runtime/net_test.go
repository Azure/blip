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

// TestPolicyAllowsRelatedICMPErrors covers PMTUD: a router's ICMP
// fragmentation-needed (type 3 code 4) and time-exceeded (type 11) replies are
// RELATED to a permitted flow, but the guest gate used to admit only
// established TCP/UDP replies, so the guest never lowered its path MTU.
// General ICMP (including echo) stays denied.
func TestPolicyAllowsRelatedICMPErrors(t *testing.T) {
	policy := &netpolicy.Policy{Revision: "allow", Layers: [][]netpolicy.Rule{
		{{CIDR: "0.0.0.0/0", Protocol: "TCP", Port: 443}},
	}}
	script, err := testPodNet(nil).policyScript(policy, true)
	if err != nil {
		t.Fatal(err)
	}
	toGuest := scriptChain(t, script, "to_guest")
	for _, rule := range []string{
		"ct state related icmp type destination-unreachable icmp code frag-needed counter accept",
		"ct state related icmp type time-exceeded counter accept",
	} {
		if !strings.Contains(toGuest, rule) {
			t.Errorf("to_guest does not admit %q:\n%s", rule, toGuest)
		}
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
	for _, rule := range []string{"icmp type 8", "icmp type 0", "meta l4proto icmp", "icmp type 3"} {
		if strings.Contains(script, rule) {
			t.Errorf("script admits general ICMP with %q:\n%s", rule, script)
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
