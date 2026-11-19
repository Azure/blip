package runtime

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Azure/blip/internal/bootconfig"
	"github.com/Azure/blip/internal/netpolicy"
)

// TestNetworkNamespace is opt-in and ALL network mutations run in child
// processes created with CLONE_NEWNET. No host interfaces, routes, firewall
// tables, /var/run/netns mounts, or sysctls are touched. Run the compiled test
// binary as root with BLIP_NETWORK_TESTS=1 (or in a privileged disposable
// container); it needs ip, nft, /dev/net/tun and permission to create netns.
func TestNetworkNamespace(t *testing.T) {
	if os.Getenv("BLIP_NETWORK_TESTS") != "1" {
		t.Skip("set BLIP_NETWORK_TESTS=1 to run disposable network-namespace tests")
	}
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	if helper := os.Getenv("BLIP_NETNS_HELPER"); helper != "" {
		parent, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", os.Getppid()))
		if err != nil || self == parent || self == os.Getenv("BLIP_NETNS_PARENT") {
			t.Fatal("refusing network changes: helper is not in a fresh network namespace")
		}
		if helper == "peer" {
			networkPeerLoop()
			os.Exit(0)
		}
		testNetworkNamespace(t)
		return
	}
	cmd := namespaceCommand("main", self)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("isolated network test: %v", err)
	}
}

func namespaceCommand(helper, parent string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=^TestNetworkNamespace$", "-test.timeout=90s")
	cmd.Env = append(os.Environ(), "BLIP_NETNS_HELPER="+helper, "BLIP_NETNS_PARENT="+parent)
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET, Pdeathsig: syscall.SIGKILL}
	return cmd
}

type nsCommand struct {
	Op, Network, Address, LocalIP string
	Args                          []string
}

type nsResult struct{ Data, Error string }

type nsPeer struct {
	cmd *exec.Cmd
	in  *json.Encoder
	out *json.Decoder
}

func startNSPeer(t *testing.T) *nsPeer {
	t.Helper()
	self, _ := os.Readlink("/proc/self/ns/net")
	cmd := namespaceCommand("peer", self)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stdin.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return &nsPeer{cmd: cmd, in: json.NewEncoder(stdin), out: json.NewDecoder(stdout)}
}

func (p *nsPeer) call(t *testing.T, c nsCommand) nsResult {
	t.Helper()
	if err := p.in.Encode(c); err != nil {
		t.Fatal(err)
	}
	var result nsResult
	if err := p.out.Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result
}

func (p *nsPeer) must(t *testing.T, c nsCommand) string {
	t.Helper()
	r := p.call(t, c)
	if r.Error != "" {
		t.Fatalf("peer %+v: %s", c, r.Error)
	}
	return r.Data
}

func testNetworkNamespace(t *testing.T) {
	for _, command := range []string{"ip", "nft"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Fatal(err)
		}
	}
	ip := func(args ...string) {
		t.Helper()
		if _, err := networkCommand("", "ip", args...); err != nil {
			t.Fatal(err)
		}
	}
	peerIP := func(p *nsPeer, args ...string) { t.Helper(); p.must(t, nsCommand{Op: "ip", Args: args}) }
	wan, vm := startNSPeer(t), startNSPeer(t)
	ip("link", "set", "lo", "up")
	ip("link", "add", "eth0", "type", "veth", "peer", "name", "wan")
	ip("link", "set", "wan", "netns", strconv.Itoa(wan.cmd.Process.Pid))
	ip("addr", "add", "192.0.2.2/24", "dev", "eth0")
	ip("link", "set", "eth0", "up")
	ip("route", "add", "default", "via", "192.0.2.1")
	peerIP(wan, "link", "set", "lo", "up")
	peerIP(wan, "link", "set", "wan", "up")
	peerIP(wan, "addr", "add", "192.0.2.1/24", "dev", "wan")
	for _, address := range []string{"198.51.100.10/32", "198.51.100.11/32"} {
		peerIP(wan, "addr", "add", address, "dev", "lo")
	}
	// An unrelated table must survive installation, replacement and teardown.
	if _, err := networkCommand("add table inet unrelated\n", "nft", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	var cfg bootconfig.Config
	p, err := setupNetwork(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer p.teardown()
	if cfg.IP == p.podIP || cfg.MAC == "" {
		t.Fatalf("private config %+v", cfg)
	}
	for _, dev := range []string{"all", "eth0", tapName} {
		for _, key := range []string{"accept_redirects", "send_redirects", "accept_source_route"} {
			value, err := os.ReadFile("/proc/sys/net/ipv4/conf/" + dev + "/" + key)
			if err != nil || strings.TrimSpace(string(value)) != "0" {
				t.Fatalf("%s/%s not disabled: %s %v", dev, key, value, err)
			}
		}
	}
	// Substitute a veth peer for the VMM/TAP endpoint to exercise real kernel
	// forwarding, conntrack and NAT without KVM or a guest image.
	ip("link", "del", tapName)
	ip("link", "add", tapName, "type", "veth", "peer", "name", "vm")
	ip("link", "set", "vm", "netns", strconv.Itoa(vm.cmd.Process.Pid))
	ip("addr", "add", cfg.Gateway+"/30", "dev", tapName)
	ip("link", "set", tapName, "up")
	if err := p.setSysctl("ipv4/conf/"+tapName+"/forwarding", "1", false); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"accept_redirects", "send_redirects", "accept_source_route"} {
		if err := p.setSysctl("ipv4/conf/"+tapName+"/"+key, "0", false); err != nil {
			t.Fatal(err)
		}
	}
	peerIP(vm, "link", "set", "lo", "up")
	peerIP(vm, "link", "set", "vm", "up")
	peerIP(vm, "addr", "add", cfg.IP+"/30", "dev", "vm")
	peerIP(vm, "route", "add", "default", "via", cfg.Gateway)
	peerIP(vm, "addr", "add", "10.77.0.1/32", "dev", "vm")
	for _, address := range []string{"198.51.100.10:8080", "198.51.100.10:8081", "198.51.100.11:8080"} {
		wan.must(t, nsCommand{Op: "listen", Network: "tcp", Address: address})
	}
	wan.must(t, nsCommand{Op: "listen", Network: "udp", Address: "198.51.100.10:5353"})
	request := nsCommand{Op: "exchange", Network: "tcp", Address: "198.51.100.10:8080"}
	denied := func(c nsCommand) {
		t.Helper()
		if r := vm.call(t, c); r.Error == "" {
			t.Fatalf("VM traffic unexpectedly allowed: %+v -> %q", c, r.Data)
		}
	}
	allowed := func(c nsCommand) {
		t.Helper()
		if got := vm.must(t, c); got != p.podIP+"|hello\n" {
			t.Fatalf("VM SNAT source = %q", got)
		}
	}
	denied(request) // boot default deny
	// Pod-origin sidecar traffic retains the pod IP even before policy exists.
	checkSidecar := func(address, source string) {
		t.Helper()
		c, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(time.Second))
		_, _ = io.WriteString(c, "hello\n")
		got, err := bufio.NewReader(c).ReadString('\n')
		if err != nil || got != source+"|hello\n" {
			t.Fatalf("sidecar source = %q: %v", got, err)
		}
	}
	checkSidecar(request.Address, p.podIP)
	policy := &netpolicy.Policy{Revision: "allow", Layers: [][]netpolicy.Rule{
		{{CIDR: "198.51.100.0/24", Except: []string{"198.51.100.11/32", "198.51.100.128/25", "198.51.100.128/26"}}},
		{{CIDR: "0.0.0.0/0", Protocol: "TCP", Port: 8080, EndPort: 8081}, {CIDR: "0.0.0.0/0", Protocol: "UDP", Port: 5353}},
		{{CIDR: "0.0.0.0/0", Protocol: "TCP", Port: 8080}, {CIDR: "0.0.0.0/0", Protocol: "UDP", Port: 5353}},
	}}
	if _, err := p.apply(policy, false); err != nil {
		t.Fatal(err)
	}
	denied(request) // preinstall does not open a warm VM
	if _, err := p.apply(policy, true); err != nil {
		t.Fatal(err)
	}
	allowed(request)
	udp := nsCommand{Op: "exchange", Network: "udp", Address: "198.51.100.10:5353"}
	allowed(udp)
	denied(nsCommand{Op: "exchange", Network: "tcp", Address: "198.51.100.10:8081"}) // AND layers
	denied(nsCommand{Op: "exchange", Network: "tcp", Address: "198.51.100.11:8080"}) // Except
	spoof := request
	spoof.LocalIP = "10.77.0.1"
	denied(spoof)
	// Even allow-all cannot expose the pod's gateway/pod-IP listeners.
	all := &netpolicy.Policy{Revision: "all", Layers: [][]netpolicy.Rule{{{CIDR: "0.0.0.0/0"}}}}
	if _, err := p.apply(all, true); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{cfg.Gateway + ":9090", p.podIP + ":9090"} {
		l, err := net.Listen("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
			}
		}()
		denied(nsCommand{Op: "exchange", Network: "tcp", Address: address})
		l.Close()
	}
	// Enable IPv6 explicitly on the replacement veth: nft must still block it.
	if err := p.setSysctl("ipv6/conf/all/forwarding", "1", false); err != nil {
		t.Fatal(err)
	}
	ip("-6", "addr", "add", "2001:db8:1::2/64", "dev", "eth0", "nodad")
	ip("-6", "addr", "add", "fd00::1/64", "dev", tapName, "nodad")
	peerIP(wan, "-6", "addr", "add", "2001:db8:1::1/64", "dev", "wan", "nodad")
	peerIP(wan, "-6", "route", "add", "fd00::/64", "via", "2001:db8:1::2")
	peerIP(vm, "-6", "addr", "add", "fd00::2/64", "dev", "vm", "nodad")
	peerIP(vm, "-6", "route", "add", "default", "via", "fd00::1")
	wan.must(t, nsCommand{Op: "listen", Network: "tcp", Address: "[2001:db8:1::1]:8080"})
	checkSidecar("[2001:db8:1::1]:8080", "2001:db8:1::2")
	denied(nsCommand{Op: "exchange", Network: "tcp", Address: "[2001:db8:1::1]:8080"})
	if _, err := p.apply(policy, true); err != nil {
		t.Fatal(err)
	}
	// Refresh both flows, then revoke. Unsolicited server pushes on existing
	// flows check the reverse path independently of blocked outbound packets.
	allowed(request)
	allowed(udp)
	if _, err := p.apply(&netpolicy.Policy{Revision: "revoke", Layers: [][]netpolicy.Rule{{}}}, true); err != nil {
		t.Fatal(err)
	}
	for _, c := range []nsCommand{request, udp} {
		push := c
		push.Op = "push"
		wan.must(t, push)
		receive := c
		receive.Op = "receive"
		denied(receive)
		denied(c)
	}
	checkSidecar(request.Address, p.podIP)
	// A denied peer cannot open an inbound connection, so the guest can never
	// be made to reply to it. Only a peer the egress policy allows may
	// establish inbound traffic and receive the return path.
	vm.must(t, nsCommand{Op: "listen", Network: "tcp", Address: cfg.IP + ":8088"})
	inbound := nsCommand{Op: "exchange", Network: "tcp", Address: p.podIP + ":8088"}
	if r := wan.call(t, inbound); r.Error == "" {
		t.Fatalf("denied peer opened an inbound DNAT connection: %q", r.Data)
	}
	inboundPolicy := &netpolicy.Policy{Revision: "inbound", Layers: [][]netpolicy.Rule{
		{{CIDR: "192.0.2.0/24", Protocol: "TCP"}},
	}}
	if _, err := p.apply(inboundPolicy, true); err != nil {
		t.Fatal(err)
	}
	if got := wan.must(t, inbound); !strings.HasSuffix(got, "|hello\n") {
		t.Fatalf("allowed inbound DNAT/return failed: %q", got)
	}
	if _, err := p.apply(&netpolicy.Policy{Revision: "invalid", Layers: [][]netpolicy.Rule{{{CIDR: "not-an-address"}}}}, true); err == nil {
		t.Fatal("invalid policy accepted")
	}
	denied(request)
	p.teardown()
	if _, err := networkCommand("", "nft", "list", "table", "inet", "unrelated"); err != nil {
		t.Fatal("unrelated nft table removed:", err)
	}
	if _, err := net.InterfaceByName("eth0"); err != nil {
		t.Fatal("pod interface removed:", err)
	}
	checkSidecar(request.Address, p.podIP)
}

type nsServer struct {
	mu     sync.Mutex
	packet net.PacketConn
	remote net.Addr
	stream net.Conn
}

// networkPeerLoop runs only after the fresh-netns check above. Its pipes are
// control-only; test data crosses real namespace interfaces and nft hooks.
func networkPeerLoop() {
	servers := map[string]*nsServer{}
	clients := map[string]net.Conn{}
	decoder, encoder := json.NewDecoder(os.Stdin), json.NewEncoder(os.Stdout)
	for {
		var c nsCommand
		if decoder.Decode(&c) != nil {
			return
		}
		key := c.Network + "/" + c.Address
		var data string
		var err error
		switch c.Op {
		case "ip":
			_, err = networkCommand("", "ip", c.Args...)
		case "listen":
			s := &nsServer{}
			servers[key] = s
			if c.Network == "udp" {
				s.packet, err = net.ListenPacket("udp", c.Address)
				if err == nil {
					go func() {
						buf := make([]byte, 4096)
						for {
							n, remote, err := s.packet.ReadFrom(buf)
							if err != nil {
								return
							}
							s.mu.Lock()
							s.remote = remote
							s.mu.Unlock()
							host, _, _ := net.SplitHostPort(remote.String())
							_, _ = s.packet.WriteTo(append([]byte(host+"|"), buf[:n]...), remote)
						}
					}()
				}
			} else {
				var l net.Listener
				l, err = net.Listen("tcp", c.Address)
				if err == nil {
					go func() {
						for {
							conn, err := l.Accept()
							if err != nil {
								return
							}
							go func() {
								defer conn.Close()
								reader := bufio.NewReader(conn)
								for {
									msg, err := reader.ReadString('\n')
									if err != nil {
										return
									}
									s.mu.Lock()
									s.stream = conn
									s.mu.Unlock()
									host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
									_, _ = io.WriteString(conn, host+"|"+msg)
								}
							}()
						}
					}()
				}
			}
		case "push":
			s := servers[key]
			if s == nil {
				err = fmt.Errorf("missing server %s", key)
				break
			}
			s.mu.Lock()
			if s.packet != nil && s.remote != nil {
				_, err = s.packet.WriteTo([]byte("pushed\n"), s.remote)
			} else if s.stream != nil {
				_, err = io.WriteString(s.stream, "pushed\n")
			} else {
				err = fmt.Errorf("no established peer")
			}
			s.mu.Unlock()
		case "exchange", "receive":
			clientKey := key + "/" + c.LocalIP
			conn := clients[clientKey]
			if conn == nil {
				d := net.Dialer{Timeout: 500 * time.Millisecond}
				if c.LocalIP != "" {
					if c.Network == "tcp" {
						d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(c.LocalIP)}
					} else {
						d.LocalAddr = &net.UDPAddr{IP: net.ParseIP(c.LocalIP)}
					}
				}
				conn, err = d.Dial(c.Network, c.Address)
				if err != nil {
					break
				}
				clients[clientKey] = conn
			}
			_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
			if c.Op == "exchange" {
				_, err = io.WriteString(conn, "hello\n")
			}
			if err == nil {
				if c.Network == "tcp" {
					data, err = bufio.NewReader(conn).ReadString('\n')
				} else {
					buf := make([]byte, 4096)
					var n int
					n, err = conn.Read(buf)
					data = string(buf[:n])
				}
			}
		default:
			err = fmt.Errorf("unknown operation %q", c.Op)
		}
		result := nsResult{Data: data}
		if err != nil {
			result.Error = err.Error()
		}
		_ = encoder.Encode(result)
	}
}
