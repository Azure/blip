package guest

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Azure/blip/internal/wire"
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
	root := t.TempDir()
	g := &Guest{
		root:       root,
		cgroup:     t.TempDir(),
		cgroupFD:   -1,
		claim:      &wire.Claim{ID: "r"},
		rootDev:    "/dev/null",
		mounts:     map[string]*mount{"m": {id: "m", path: "/data", target: filepath.Join(root, "data")}},
		frozen:     map[string]*frozenFS{},
		sessions:   map[string]*session{},
		filesystem: &filesystemEffects{sync: func(string) {}, freeze: f.freeze},
	}
	t.Cleanup(func() { _ = g.thawAll() })
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
	host, guest := net.Pipe()
	t.Cleanup(func() { host.Close() })
	go g.serveControlStream(guest)
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
	synctest.Test(t, func(t *testing.T) {
		g, f := freezeGuest(t)

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

		time.Sleep(freezeTimeout)
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
	})
}

// A mount below a frozen auxiliary mount would block in mkdirat while
// holding mu, and the auto-thaw must never need mu.
func TestFreezeAuxRefusesMountAndAutoThawsUnderMu(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g, f := freezeGuest(t)
		thawed := make(chan struct{}, 1)
		g.filesystem.freeze = func(path string, freeze bool) error {
			err := f.freeze(path, freeze)
			if !freeze {
				thawed <- struct{}{}
			}
			return err
		}

		if err := g.doFreeze("m"); err != nil {
			t.Fatal(err)
		}
		if err := g.doMount(wire.Mount{ID: "x", Serial: "x", Path: "/data/x"}); err == nil || !strings.Contains(err.Error(), "frozen") {
			t.Fatalf("mount below frozen mount: %v", err)
		}
		g.mu.Lock()
		time.Sleep(freezeTimeout)
		<-thawed
		if g.anyFrozen() {
			g.mu.Unlock()
			t.Fatal("auto-thaw blocked behind mu")
		}
		g.mu.Unlock()
		synctest.Wait()
		data := filepath.Join(g.root, "data")
		if got := f.take(); got != "freeze "+data+",thaw "+data {
			t.Fatalf("calls %s", got)
		}
	})
}
