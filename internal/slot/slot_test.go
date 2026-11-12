package slot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestParseMemory(t *testing.T) {
	for in, want := range map[string]int64{"2Gi": 2048, "1536Mi": 1536, "1073741824": 1024, "2097152Ki": 2048, "1Ti": 1 << 20} {
		got, err := ParseMemory(in)
		if err != nil || got != want {
			t.Errorf("%s: got %d %v want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "x", "-1Gi", "1000", "1.5Gi", "2G"} {
		if _, err := ParseMemory(in); err == nil {
			t.Errorf("%s: expected error", in)
		}
	}
}

func TestPickHypervisor(t *testing.T) {
	d := t.TempDir()
	if _, err := pickHypervisor(d, ""); err == nil {
		t.Fatal("no device: expected error")
	}
	os.WriteFile(filepath.Join(d, "kvm"), nil, 0o644)
	if h, err := pickHypervisor(d, ""); err != nil || h != "kvm" {
		t.Fatalf("got %q %v", h, err)
	}
	if _, err := pickHypervisor(d, "mshv"); err == nil {
		t.Fatal("mshv missing: expected error")
	}
	os.WriteFile(filepath.Join(d, "mshv"), nil, 0o644)
	if _, err := pickHypervisor(d, ""); err == nil {
		t.Fatal("both: expected error")
	}
	if h, err := pickHypervisor(d, "mshv"); err != nil || h != "mshv" {
		t.Fatalf("got %q %v", h, err)
	}
}

func TestFiles(t *testing.T) {
	d := t.TempDir()
	if err := Probe(d); err == nil {
		t.Fatal("probe should fail")
	}
	os.WriteFile(filepath.Join(d, FileReady), nil, 0o644)
	if err := Probe(d); err != nil {
		t.Fatal(err)
	}
	dl := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	if err := WriteAssignment(d, Assignment{AllocationID: "a1", KillTime: dl}); err != nil {
		t.Fatal(err)
	}
	a, err := readAssignment(d)
	if err != nil || a.AllocationID != "a1" || !a.KillTime.Equal(dl) {
		t.Fatalf("got %+v %v", a, err)
	}
	if _, err := ReadExit(d); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ReadExit: %v", err)
	}
	// An assigned slot refuses to boot before touching anything else.
	err = Run(context.Background(), &Config{RunDir: d})
	if err == nil || Probe(d) != nil {
		t.Fatalf("Run on assigned slot: %v", err)
	}
}

func TestParseConfig(t *testing.T) {
	t.Setenv("VM_CPUS", "2")
	t.Setenv("VM_MEMORY", "2Gi")
	t.Setenv("BLIP_RUN_DIR", "/tmp/x")
	c, err := parseConfig([]string{"--tap", "t0"})
	if err != nil || c.CPUs != 2 || c.MemoryMiB != 2048 || c.RunDir != "/tmp/x" || c.Tap != "t0" {
		t.Fatalf("got %+v %v", c, err)
	}
	t.Setenv("VM_CPUS", "0")
	if _, err := parseConfig(nil); err == nil {
		t.Fatal("expected error for VM_CPUS=0")
	}
}

func TestSortRoutes(t *testing.T) {
	rs := []Route{{Gateway: "10.0.0.1"}, {Destination: "10.0.0.1/32"}, {Destination: "10.1.0.0/16", Gateway: "10.0.0.1"}, {Destination: "fd00::/64"}}
	sortRoutes(rs)
	got := []string{}
	for _, r := range rs {
		got = append(got, r.Destination+"|"+r.Gateway)
	}
	want := []string{"10.0.0.1/32|", "fd00::/64|", "|10.0.0.1", "10.1.0.0/16|10.0.0.1"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestToRoute(t *testing.T) {
	_, any4, _ := net.ParseCIDR("0.0.0.0/0")
	r := toRoute(netlink.Route{Dst: any4, Gw: net.ParseIP("10.244.1.1"), Flags: unix.RTNH_F_ONLINK, Family: unix.AF_INET, Priority: 5})
	if r != (Route{Gateway: "10.244.1.1", Onlink: true, Metric: 5}) {
		t.Fatalf("default: %+v", r)
	}
	_, dst, _ := net.ParseCIDR("10.244.1.1/32")
	r = toRoute(netlink.Route{Dst: dst, Src: net.ParseIP("10.244.1.5"), Family: unix.AF_INET})
	if r != (Route{Destination: "10.244.1.1/32", Source: "10.244.1.5"}) {
		t.Fatalf("link route: %+v", r)
	}
	if r := toRoute(netlink.Route{Gw: net.ParseIP("fe80::1"), Family: unix.AF_INET6}); !r.IPv6 || r.Destination != "" {
		t.Fatalf("v6 default: %+v", r)
	}
}

func TestPodNetworkJSON(t *testing.T) {
	d := t.TempDir()
	pn := PodNetwork{Iface: "eth0", MAC: "0a:58:0a:f4:01:05", MTU: 1450, Addresses: []string{"10.244.1.5/24", "fd00::5/64"},
		Routes: []Route{{Gateway: "10.244.1.1", Onlink: true}}}
	b, _ := json.Marshal(pn)
	os.WriteFile(filepath.Join(d, FileNetwork), b, 0o644)
	got, err := ReadNetwork(d)
	if err != nil || got.MTU != 1450 || got.FirstIP() != "10.244.1.5" || !got.Routes[0].Onlink {
		t.Fatalf("%+v %v", got, err)
	}
}
