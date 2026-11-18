package guest

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/blip/internal/wire"
	"golang.org/x/sys/unix"
)

type fakeFreezer struct {
	mu    sync.Mutex
	calls []string
}

func (f *fakeFreezer) freeze(path string, freeze bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	op := "thaw "
	if freeze {
		op = "freeze "
	}
	f.calls = append(f.calls, op+path)
	return nil
}

func (f *fakeFreezer) take() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := strings.Join(f.calls, ",")
	f.calls = nil
	return s
}

func freezeGuest(t *testing.T) (*Guest, *fakeFreezer) {
	f := &fakeFreezer{}
	old := freezeFS
	freezeFS = f.freeze
	t.Cleanup(func() { freezeFS = old })
	root := t.TempDir()
	g := &Guest{
		root:     root,
		cgroup:   t.TempDir(),
		cgroupFD: -1,
		claim:    &wire.Claim{ID: "r"},
		rootDev:  "/dev/null",
		mounts:   map[string]*mount{"m": {id: "m", path: "/data", target: filepath.Join(root, "data")}},
		frozen:   map[string]*frozenFS{},
		sessions: map[string]*session{},
	}
	return g, f
}

func TestFreezeFSRefusesOutsidePID1(t *testing.T) {
	if os.Getpid() == 1 {
		t.Skip("running as PID 1")
	}
	if err := freezeFS(t.TempDir(), true); err != errNotInit {
		t.Fatalf("freezeFS outside PID 1: %v", err)
	}
}

func TestFreezeThaw(t *testing.T) {
	g, f := freezeGuest(t)
	data := filepath.Join(g.root, "data")
	if err := g.doFreeze("r"); err != nil {
		t.Fatal(err)
	}
	if err := g.doFreeze("r"); err != nil {
		t.Fatal(err)
	}
	if err := g.doFreeze("m"); err != nil {
		t.Fatal(err)
	}
	if err := g.doFreeze("nope"); err == nil {
		t.Fatal("froze an unknown disk")
	}
	if got := f.take(); got != "freeze "+g.root+",freeze "+data {
		t.Fatalf("calls %s", got)
	}
	if err := g.doMount(wire.Mount{ID: "x", Serial: "x", Path: "/x"}); err == nil || !strings.Contains(err.Error(), "frozen") {
		t.Fatalf("mount with frozen root: %v", err)
	}
	if err := g.doThaw("r"); err != nil {
		t.Fatal(err)
	}
	if err := g.doThaw("r"); err != nil {
		t.Fatal(err)
	}
	if err := g.doUnmount("m"); err != nil {
		t.Fatal(err)
	}
	if got := f.take(); got != "thaw "+g.root+",thaw "+data {
		t.Fatalf("calls %s", got)
	}
	if len(g.frozen) != 0 || g.mounts["m"] != nil {
		t.Fatalf("frozen %v mounts %v", g.frozen, g.mounts)
	}

	// Shutdown thaws before unmounting.
	if err := g.doFreeze("r"); err != nil {
		t.Fatal(err)
	}
	f.take()
	g.mu.Lock()
	err := g.unmountAllLocked()
	g.mu.Unlock()
	if err != nil || f.take() != "thaw "+g.root || len(g.frozen) != 0 {
		t.Fatalf("unmountAll: %v frozen %v", err, g.frozen)
	}
}

func controlPair(t *testing.T, g *Guest) *wire.Conn {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	host := os.NewFile(uintptr(fds[0]), "host")
	t.Cleanup(func() { host.Close() })
	go g.serveControl(os.NewFile(uintptr(fds[1]), "guest"))
	return wire.NewConn(host)
}

func readFrame(t *testing.T, c *wire.Conn, typ wire.Type, v any) {
	t.Helper()
	got, p, err := c.Read()
	if err != nil || got != typ {
		t.Fatalf("got frame %d %s %v, want %d", got, p, err, typ)
	}
	if err := wire.Decode(p, v); err != nil {
		t.Fatal(err)
	}
}

func TestFreezeAutoThawAndResync(t *testing.T) {
	g, f := freezeGuest(t)
	old := freezeTimeout
	freezeTimeout = 200 * time.Millisecond
	t.Cleanup(func() { freezeTimeout = old })

	c := controlPair(t, g)
	var h wire.Hello
	readFrame(t, c, wire.THello, &h)
	readFrame(t, c, wire.TStatus, &wire.Status{})
	if err := c.WriteJSON(wire.TFreeze, wire.Freeze{ID: "m"}); err != nil {
		t.Fatal(err)
	}
	var res wire.FreezeResult
	readFrame(t, c, wire.TFreezeResult, &res)
	if res.ID != "m" || !res.Frozen || res.Error != "" {
		t.Fatalf("freeze result %+v", res)
	}

	// A reconnecting runtime learns the frozen disks from Hello.
	c = controlPair(t, g)
	readFrame(t, c, wire.THello, &h)
	if len(h.Frozen) != 1 || h.Frozen[0] != "m" {
		t.Fatalf("hello %+v", h)
	}
	readFrame(t, c, wire.TStatus, &wire.Status{})

	res = wire.FreezeResult{}
	readFrame(t, c, wire.TFreezeResult, &res)
	if res.ID != "m" || res.Frozen || res.Error == "" {
		t.Fatalf("auto-thaw result %+v", res)
	}
	if got := f.take(); got != "freeze "+filepath.Join(g.root, "data")+",thaw "+filepath.Join(g.root, "data") {
		t.Fatalf("calls %s", got)
	}

	if err := c.WriteJSON(wire.TThaw, wire.Freeze{ID: "m"}); err != nil {
		t.Fatal(err)
	}
	res = wire.FreezeResult{}
	readFrame(t, c, wire.TFreezeResult, &res)
	if res.Frozen || res.Error != "" {
		t.Fatalf("thaw result %+v", res)
	}
}

// A mount below a frozen auxiliary mount would block in mkdirat while
// holding mu, and the auto-thaw must never need mu.
func TestFreezeAuxRefusesMountAndAutoThawsUnderMu(t *testing.T) {
	g, f := freezeGuest(t)
	old := freezeTimeout
	freezeTimeout = 50 * time.Millisecond
	t.Cleanup(func() { freezeTimeout = old })

	if err := g.doFreeze("m"); err != nil {
		t.Fatal(err)
	}
	if err := g.doMount(wire.Mount{ID: "x", Serial: "x", Path: "/data/x"}); err == nil || !strings.Contains(err.Error(), "frozen") {
		t.Fatalf("mount below frozen mount: %v", err)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for deadline := time.Now().Add(5 * time.Second); g.anyFrozen(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("auto-thaw blocked behind mu")
		}
	}
	data := filepath.Join(g.root, "data")
	if got := f.take(); got != "freeze "+data+",thaw "+data {
		t.Fatalf("calls %s", got)
	}
}
