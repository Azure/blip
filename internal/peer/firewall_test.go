// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package peer

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestFirewallInvalidHost(t *testing.T) {
	for _, host := range []string{"", "hostname", "::1", "192.0.2.1/24", "192.0.2.1 }; flush ruleset; #"} {
		if _, err := NewFirewall(host); err == nil {
			t.Fatalf("accepted host %q", host)
		}
	}
}

func TestFirewallPeerRules(t *testing.T) {
	id, err := LoadIdentity(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := &Firewall{hostIP: "192.0.2.1"}
	peers := []Peer{
		{Node: "b", PublicKey: id.PublicKey(), Endpoint: "192.0.2.3"},
		{Node: "a", PublicKey: id.PublicKey(), Endpoint: "192.0.2.2"},
		{Node: "duplicate", PublicKey: id.PublicKey(), Endpoint: "192.0.2.2"},
		{Node: "mapped", PublicKey: id.PublicKey(), Endpoint: "::ffff:192.0.2.2"},
		{Node: "self", PublicKey: id.PublicKey(), Endpoint: "192.0.2.1"},
		{Node: "bad-key", PublicKey: "invalid", Endpoint: "192.0.2.4"},
		{Node: "injection", PublicKey: id.PublicKey(), Endpoint: "192.0.2.5 }; flush ruleset; #"},
		{Node: "ipv6", PublicKey: id.PublicKey(), Endpoint: "2001:db8::1"},
		{PublicKey: id.PublicKey(), Endpoint: "192.0.2.6"},
	}
	want := "flush set inet blip nodes\nadd element inet blip nodes { 192.0.2.1, 192.0.2.2, 192.0.2.3 }\n"
	if got := f.peerRules(peers); got != want {
		t.Fatalf("peer rules = %q, want %q", got, want)
	}
	if got := f.peerRules(nil); got != "flush set inet blip nodes\nadd element inet blip nodes { 192.0.2.1 }\n" {
		t.Fatalf("local-only rules = %q", got)
	}
}

func privileged(t *testing.T) {
	t.Helper()
	if os.Getenv("BLIP_PRIVILEGED_TESTS") != "1" {
		t.Skip("set BLIP_PRIVILEGED_TESTS=1 (inside a disposable privileged container)")
	}
}

func output(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

// TestPrivilegedFirewall never installs rules in the calling namespace, even
// when explicitly enabled outside the container harness.
func TestPrivilegedFirewall(t *testing.T) {
	privileged(t)
	cmd := firewallNamespaceCommand(t, "router")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("isolated firewall test: %v\n%s", err, out)
	} else {
		t.Logf("%s", out)
	}
}

func firewallNamespaceCommand(t *testing.T, mode string) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestFirewallNamespace$", "-test.timeout=45s")
	if mode == "router" {
		cmd.Args = append(cmd.Args, "-test.v")
	}
	cmd.Env = append(os.Environ(), "BLIP_FIREWALL_CHILD="+mode)
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}
	return cmd
}

// TestFirewallNamespace is a subprocess entry point. Verify isolation before
// touching links, routes, sysctls, listeners, or nftables.
func TestFirewallNamespace(t *testing.T) {
	mode := os.Getenv("BLIP_FIREWALL_CHILD")
	if mode == "" {
		t.Skip("network namespace subprocess only")
	}
	privileged(t)
	ns, err := os.Readlink("/proc/self/ns/net")
	parent, parentErr := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", os.Getppid()))
	if err != nil || parentErr != nil || ns == parent {
		t.Fatal("firewall test requires a fresh network namespace")
	}
	output(t, "ip", "link", "set", "lo", "up")
	if mode == "endpoint" {
		firewallEndpoint(t)
		return
	}
	if mode != "router" {
		t.Fatalf("unknown namespace mode %q", mode)
	}
	t.Run("input", testFirewallInput)
	t.Run("forward-before-masquerade", testFirewallForward)
}

func testFirewallInput(t *testing.T) {
	for _, port := range []int{ExportPort, NVMePort, 9000} {
		firewallEcho(t, "127.0.0.1", port)
	}
	f, err := NewFirewall("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	id, err := LoadIdentity(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	peer := Peer{Node: "peer", PublicKey: id.PublicKey(), Endpoint: "127.0.0.2"}
	for _, port := range []int{ExportPort, NVMePort} {
		firewallDial(t, "127.0.0.1", "127.0.0.1", port, true)
		firewallDial(t, peer.Endpoint, "127.0.0.1", port, false)
	}
	if err := f.SetPeers([]Peer{peer}); err != nil {
		t.Fatal(err)
	}
	var established []net.Conn
	for _, port := range []int{ExportPort, NVMePort} {
		firewallDial(t, "127.0.0.3", "127.0.0.1", port, false)
		c := firewallDial(t, peer.Endpoint, "127.0.0.1", port, true)
		established = append(established, c)
	}
	firewallDial(t, "127.0.0.3", "127.0.0.1", 9000, true)

	// An agent restart resets discovery, but existing kernel sessions must
	// continue transferring data on both ports.
	f, err = NewFirewall("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	for i, port := range []int{ExportPort, NVMePort} {
		firewallRoundTrip(t, established[i])
		firewallDial(t, peer.Endpoint, "127.0.0.1", port, false)
	}
	if err := f.SetPeers([]Peer{peer}); err != nil {
		t.Fatal(err)
	}
	for _, port := range []int{ExportPort, NVMePort} {
		firewallDial(t, peer.Endpoint, "127.0.0.1", port, true)
	}
	if err := f.SetPeers(nil); err != nil {
		t.Fatal(err)
	}
	for i, port := range []int{ExportPort, NVMePort} {
		firewallRoundTrip(t, established[i])
		firewallDial(t, peer.Endpoint, "127.0.0.1", port, false)
		firewallDial(t, "127.0.0.1", "127.0.0.1", port, true)
	}
}

func firewallEcho(t *testing.T, host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp4", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
}

func firewallDial(t *testing.T, source, target string, port int, allowed bool) net.Conn {
	t.Helper()
	d := net.Dialer{Timeout: 250 * time.Millisecond, LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}
	c, err := d.Dial("tcp4", net.JoinHostPort(target, strconv.Itoa(port)))
	if !allowed {
		if c != nil {
			c.Close()
		}
		if e, ok := err.(net.Error); !ok || !e.Timeout() {
			t.Fatalf("%s -> %s:%d: expected dropped connection, got %v", source, target, port, err)
		}
		return nil
	}
	if err != nil {
		t.Fatalf("%s -> %s:%d: %v", source, target, port, err)
	}
	t.Cleanup(func() { c.Close() })
	firewallRoundTrip(t, c)
	return c
}

func firewallRoundTrip(t *testing.T, c net.Conn) {
	t.Helper()
	if err := c.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	want := "still connected"
	if _, err := io.WriteString(c, want); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, len(want))
	if _, err := io.ReadFull(c, b); err != nil || string(b) != want {
		t.Fatalf("echo = %q, %v", b, err)
	}
}

type firewallCommand struct {
	Address string
	Gateway string
	Listen  bool
	Port    int
}

type firewallReply struct {
	Error   string
	Timeout bool
	Source  string
}

type firewallProcess struct {
	cmd *exec.Cmd
	in  *json.Encoder
	out *json.Decoder
}

func startFirewallEndpoint(t *testing.T) *firewallProcess {
	t.Helper()
	cmd := firewallNamespaceCommand(t, "endpoint")
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.Close(); cmd.Process.Kill(); cmd.Wait() })
	return &firewallProcess{cmd: cmd, in: json.NewEncoder(in), out: json.NewDecoder(out)}
}

func (p *firewallProcess) call(t *testing.T, cmd firewallCommand) firewallReply {
	t.Helper()
	if err := p.in.Encode(cmd); err != nil {
		t.Fatal(err)
	}
	var reply firewallReply
	if err := p.out.Decode(&reply); err != nil {
		t.Fatal(err)
	}
	return reply
}

func testFirewallForward(t *testing.T) {
	if _, err := NewFirewall("10.10.2.1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0); err != nil {
		t.Fatal(err)
	}
	source, target := startFirewallEndpoint(t), startFirewallEndpoint(t)
	for i, p := range []*firewallProcess{source, target} {
		link, peer := fmt.Sprintf("router%d", i), fmt.Sprintf("peer%d", i)
		output(t, "ip", "link", "add", link, "type", "veth", "peer", "name", peer)
		output(t, "ip", "link", "set", peer, "netns", strconv.Itoa(p.cmd.Process.Pid))
		output(t, "ip", "addr", "add", fmt.Sprintf("10.10.%d.1/24", i+1), "dev", link)
		output(t, "ip", "link", "set", link, "up")
		reply := p.call(t, firewallCommand{Address: fmt.Sprintf("10.10.%d.2", i+1), Gateway: fmt.Sprintf("10.10.%d.1", i+1), Listen: i == 1})
		if reply.Error != "" {
			t.Fatal(reply.Error)
		}
	}
	if err := applyFirewall(`table ip firewall_test_nat {
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname "router1" masquerade
	}
}
`); err != nil {
		t.Fatal(err)
	}
	// A control port proves routing and SNAT work. The endpoint must see
	// the router's node address, which would pass an endpoint IP allowlist.
	reply := source.call(t, firewallCommand{Address: "10.10.2.2", Port: 9000})
	if reply.Error != "" || reply.Source != "10.10.2.1" {
		t.Fatalf("masqueraded control connection: %+v", reply)
	}
	for _, port := range []int{ExportPort, NVMePort} {
		reply := source.call(t, firewallCommand{Address: "10.10.2.2", Port: port})
		if !reply.Timeout {
			t.Fatalf("forwarded connection to %d was not dropped: %+v", port, reply)
		}
	}
}

// firewallEndpoint configures only its private namespace. The first command
// sets up the moved veth; later commands test connections from that namespace.
func firewallEndpoint(t *testing.T) {
	dec, enc := json.NewDecoder(os.Stdin), json.NewEncoder(os.Stdout)
	var setup firewallCommand
	if err := dec.Decode(&setup); err != nil {
		t.Fatal(err)
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		if strings.HasPrefix(iface.Name, "peer") {
			output(t, "ip", "addr", "add", setup.Address+"/24", "dev", iface.Name)
			output(t, "ip", "link", "set", iface.Name, "up")
		}
	}
	output(t, "ip", "route", "add", "default", "via", setup.Gateway)
	if setup.Listen {
		for _, port := range []int{ExportPort, NVMePort, 9000} {
			ln, err := net.Listen("tcp4", net.JoinHostPort(setup.Address, strconv.Itoa(port)))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { ln.Close() })
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
					io.WriteString(c, host)
					c.Close()
				}
			}()
		}
	}
	if err := enc.Encode(firewallReply{}); err != nil {
		t.Fatal(err)
	}
	for {
		var cmd firewallCommand
		if err := dec.Decode(&cmd); err == io.EOF {
			return
		} else if err != nil {
			t.Fatal(err)
		}
		var reply firewallReply
		c, err := net.DialTimeout("tcp4", net.JoinHostPort(cmd.Address, strconv.Itoa(cmd.Port)), 250*time.Millisecond)
		if err != nil {
			reply.Error = err.Error()
			if e, ok := err.(net.Error); ok {
				reply.Timeout = e.Timeout()
			}
		} else {
			c.SetDeadline(time.Now().Add(time.Second))
			b, err := io.ReadAll(c)
			c.Close()
			reply.Source = string(b)
			if err != nil {
				reply.Error = err.Error()
			}
		}
		if err := enc.Encode(reply); err != nil {
			t.Fatal(err)
		}
	}
}
