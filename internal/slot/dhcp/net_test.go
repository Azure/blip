package dhcp

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestNetUdhcpc runs busybox udhcpc in a netns against the server on a
// veth whose ingress is mirred-redirected elsewhere, like the slot tap.
// It needs root and BLIP_NET_TEST=1.
func TestNetUdhcpc(t *testing.T) {
	if os.Getenv("BLIP_NET_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("set BLIP_NET_TEST=1 and run as root")
	}
	bb, err := exec.LookPath("busybox")
	if err != nil {
		t.Skip("no busybox")
	}
	id := fmt.Sprint(os.Getpid() % 100000)
	ns, srv, cli, sink := "bdt"+id, "bds"+id, "bdc"+id, "bdk"+id
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	run("ip", "netns", "add", ns)
	t.Cleanup(func() {
		exec.Command("ip", "link", "del", srv).Run()
		exec.Command("ip", "link", "del", sink).Run()
		exec.Command("ip", "netns", "del", ns).Run()
	})
	run("ip", "link", "add", srv, "type", "veth", "peer", "name", cli, "netns", ns)
	run("ip", "-n", ns, "link", "set", cli, "address", clientMAC.String(), "up")
	run("ip", "link", "set", srv, "up")
	run("ip", "link", "add", sink, "type", "dummy")
	run("ip", "link", "set", sink, "up")
	if os.Getenv("BLIP_NET_TEST_NO_REDIRECT") == "" {
		// Everything the client sends goes to sink, as the slot redirects
		// the tap to the pod interface.
		run("tc", "qdisc", "add", "dev", srv, "ingress")
		run("tc", "filter", "add", "dev", srv, "parent", "ffff:", "protocol", "all", "prio", "1",
			"matchall", "action", "mirred", "egress", "redirect", "dev", sink)
	}

	c := testConfig()
	c.Lease = time.Hour
	c.Routes = []Route{{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParseAddr("10.244.1.254")}}
	s := New(c)
	s.Log = discardLog()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, srv) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	time.Sleep(100 * time.Millisecond)

	dir := t.TempDir()
	script := filepath.Join(dir, "script")
	envOut := filepath.Join(dir, "env")
	os.WriteFile(script, []byte("#!/bin/sh\n[ \"$1\" = bound ] && env > "+envOut+"\nexit 0\n"), 0o755)
	udhcpc := func(extra ...string) map[string]string {
		t.Helper()
		os.Remove(envOut)
		args := append([]string{"netns", "exec", ns, bb, "udhcpc", "-i", cli, "-n", "-q", "-f", "-t", "3", "-T", "1",
			"-s", script, "-O", "staticroutes", "-O", "search", "-O", "hostname"}, extra...)
		cctx, ccancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer ccancel()
		start := time.Now()
		out, err := exec.CommandContext(cctx, "ip", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("udhcpc: %v\n%s", err, out)
		}
		t.Logf("udhcpc %v took %v\n%s", extra, time.Since(start), out)
		b, err := os.ReadFile(envOut)
		if err != nil {
			t.Fatal(err)
		}
		env := map[string]string{}
		for _, l := range strings.Split(string(b), "\n") {
			if k, v, ok := strings.Cut(l, "="); ok {
				env[k] = v
			}
		}
		return env
	}
	env := udhcpc()
	want := map[string]string{
		"ip": "10.244.1.5", "subnet": "255.255.255.0", "router": "10.244.1.1", "dns": "10.96.0.10",
		"mtu": "1450", "hostname": "myblip", "lease": "3600", "serverid": "10.244.1.1",
		"domain": "default.svc.cluster.local", "search": "default.svc.cluster.local svc.cluster.local cluster.local",
		"staticroutes": "10.0.0.0/8 10.244.1.254 0.0.0.0/0 10.244.1.1",
	}
	for k, v := range want {
		if got := strings.TrimSpace(env[k]); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	// A stale address from another node: NAK, then a fresh lease.
	env = udhcpc("-r", "10.9.9.9")
	if env["ip"] != "10.244.1.5" {
		t.Errorf("after stale request ip = %q", env["ip"])
	}
	// Another MAC gets nothing.
	run("ip", "-n", ns, "link", "set", cli, "address", "52:54:00:aa:bb:cc")
	out, _ := exec.Command("ip", "netns", "exec", ns, bb, "udhcpc", "-i", cli, "-n", "-q", "-f", "-t", "2", "-T", "1", "-s", script).CombinedOutput()
	if strings.Contains(string(out), "lease of") {
		t.Errorf("other MAC got a lease:\n%s", out)
	}
}
