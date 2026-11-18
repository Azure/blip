package guest

import (
	"errors"
	"io"
	"net"
	"reflect"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Azure/blip/internal/wire"
)

func TestFreezeLeaseRenewalRejectsStaleExpiry(t *testing.T) {
	start := time.Unix(100, 0)
	var lease freezeLease
	old := lease.renew(start)
	if lease.expired(old, start.Add(freezeTimeout-time.Nanosecond)) {
		t.Fatal("lease expired before its deadline")
	}
	if !lease.expired(old, start.Add(freezeTimeout)) {
		t.Fatal("lease did not expire at its deadline")
	}
	current := lease.renew(start.Add(freezeTimeout))
	if lease.expired(old, start.Add(10*freezeTimeout)) {
		t.Fatal("late callback from an old lease can thaw a renewed freeze")
	}
	if !lease.expired(current, start.Add(2*freezeTimeout)) {
		t.Fatal("renewed lease did not expire")
	}
}

func TestFreezeStaleTimerAfterRenewalAndRefreeze(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g, f := freezeGuest(t)
		syncs := 0
		g.filesystem.sync = func(string) { syncs++ }
		if err := g.doFreeze("m"); err != nil {
			t.Fatal(err)
		}
		old := g.frozen["m"]
		token := old.lease.token
		time.Sleep(freezeTimeout / 2)
		if err := g.doFreeze("m"); err != nil {
			t.Fatal(err)
		}
		time.Sleep(freezeTimeout / 2)
		g.autoThaw("m", old, token) // callback was already queued before Stop
		if !g.anyFrozen() || syncs != 1 {
			t.Fatalf("renewal lost freeze or synced a frozen filesystem: frozen=%v syncs=%d", g.anyFrozen(), syncs)
		}
		if err := g.doThaw("m"); err != nil {
			t.Fatal(err)
		}
		if err := g.doFreeze("m"); err != nil {
			t.Fatal(err)
		}
		g.autoThaw("m", old, old.lease.token) // old incarnation, same disk ID
		if !g.anyFrozen() {
			t.Fatal("old incarnation thawed a new freeze")
		}
		f.take()
		time.Sleep(freezeTimeout)
		synctest.Wait()
		if g.anyFrozen() || f.take() != "thaw "+g.mounts["m"].target {
			t.Fatal("current lease did not thaw exactly once")
		}
	})
}

// The runtime stops reading after sending Freeze. The actual control handler
// blocks writing its success, but the filesystem must still thaw on schedule.
// The blocked stream must close before expiry, so resuming cannot deliver a
// stale success. A reconnect reports the current (thawed) state in Hello.
func TestFreezeExpiresWhileResultBackpressured(t *testing.T) {
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
		host, guest := net.Pipe()
		defer host.Close()
		go g.serveControl(guest)
		c := wire.NewConn(host)
		readFrame(t, c, wire.THello, &wire.Hello{})
		readFrame(t, c, wire.TStatus, &wire.Status{})
		if err := c.WriteJSON(wire.TFreeze, wire.Freeze{ID: "m"}); err != nil {
			t.Fatal(err)
		}
		synctest.Wait() // success write is now blocked in the real wire codec
		time.Sleep(freezeTimeout)
		<-thawed
		if g.anyFrozen() {
			t.Fatal("control backpressure prevented automatic thaw")
		}
		path := g.mounts["m"].target
		if got := f.take(); got != "freeze "+path+",thaw "+path {
			t.Fatalf("filesystem effects: %s", got)
		}
		if typ, _, err := c.Read(); typ != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("backpressured connection delivered an expired success: type=%d err=%v", typ, err)
		}
		c = controlPair(t, g)
		var hello wire.Hello
		readFrame(t, c, wire.THello, &hello)
		readFrame(t, c, wire.TStatus, &wire.Status{})
		if len(hello.Frozen) != 0 {
			t.Fatalf("reconnect resurrected expired freeze: %+v", hello)
		}
	})
}

func TestFailedThawKeepsWatchdog(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "auto-thaw", true: "explicit-thaw"}[explicit], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g, f := freezeGuest(t)
				fail := true
				g.filesystem.freeze = func(path string, freeze bool) error {
					if !freeze && fail {
						return errors.New("temporary thaw failure")
					}
					return f.freeze(path, freeze)
				}
				if err := g.doFreeze("m"); err != nil {
					t.Fatal(err)
				}
				if explicit {
					if err := g.doThaw("m"); err == nil {
						t.Fatal("expected injected thaw failure")
					}
				} else {
					time.Sleep(freezeTimeout)
					synctest.Wait()
				}
				if !g.anyFrozen() {
					t.Fatal("failed thaw forgot the frozen disk")
				}
				g.fmu.Lock()
				fail = false
				g.fmu.Unlock()
				if explicit {
					time.Sleep(freezeTimeout)
				} else {
					time.Sleep(thawRetryInterval)
				}
				synctest.Wait()
				if g.anyFrozen() {
					t.Fatal("temporary failure permanently disabled automatic thaw")
				}
			})
		})
	}
}

func TestFreezeResultNearExpiryUsesRemainingLease(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g, _ := freezeGuest(t)
		if err := g.doFreeze("m"); err != nil {
			t.Fatal(err)
		}
		time.Sleep(freezeTimeout - time.Second)
		host, guest := net.Pipe()
		defer host.Close()
		c := &controlConn{Conn: wire.NewConn(guest), stream: guest}
		done := make(chan struct{})
		go func() { c.freezeResult(g, "m", nil, true); close(done) }()
		synctest.Wait()
		start := time.Now()
		<-done // Host never reads the pending success.
		if time.Since(start) != time.Second {
			t.Fatal("pending freeze success outlived its lease")
		}
		if _, _, err := wire.NewConn(host).Read(); !errors.Is(err, io.EOF) {
			t.Fatalf("received stale success after expiry: %v", err)
		}
	})
}

func TestFailedAutoThawRetryCannotThawRenewedLease(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g, f := freezeGuest(t)
		g.filesystem.freeze = func(path string, freeze bool) error {
			if !freeze {
				return errors.New("temporary thaw failure")
			}
			return f.freeze(path, freeze)
		}
		if err := g.doFreeze("m"); err != nil {
			t.Fatal(err)
		}
		old := g.frozen["m"]
		token := old.lease.token
		time.Sleep(freezeTimeout)
		synctest.Wait()
		g.filesystem.freeze = f.freeze
		if err := g.doFreeze("m"); err != nil {
			t.Fatal(err)
		}
		time.Sleep(thawRetryInterval)
		g.autoThaw("m", old, token) // a retry queued before renewal
		if !g.anyFrozen() {
			t.Fatal("old retry thawed the renewed lease")
		}
		g.mu.Lock()
		g.stopping = true
		g.mu.Unlock()
		if err := g.doFreeze("m"); err == nil {
			t.Fatal("stopping guest renewed a freeze")
		}
	})
}

func TestFreezeFailuresAndMalformedControlFrames(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g, f := freezeGuest(t)
		failFreeze, failThaw := true, false
		g.filesystem.freeze = func(path string, freeze bool) error {
			if (freeze && failFreeze) || (!freeze && failThaw) {
				return errors.New("injected ioctl failure")
			}
			return f.freeze(path, freeze)
		}
		c := controlPair(t, g)
		readFrame(t, c, wire.THello, &wire.Hello{})
		readFrame(t, c, wire.TStatus, &wire.Status{})
		request := func(typ wire.Type, payload []byte) wire.FreezeResult {
			t.Helper()
			if err := c.Write(typ, payload); err != nil {
				t.Fatal(err)
			}
			var result wire.FreezeResult
			readFrame(t, c, wire.TFreezeResult, &result)
			synctest.Wait()
			return result
		}
		for _, payload := range [][]byte{[]byte(`{"id":`), []byte(`{"id":12}`), []byte(`{"id":"missing"}`), []byte(`{"id":"m"}`)} {
			if result := request(wire.TFreeze, payload); result.Error == "" || result.Frozen {
				t.Fatalf("bad freeze %q: %+v", payload, result)
			}
		}
		if g.anyFrozen() {
			t.Fatal("failed freeze acquired a lease")
		}
		failFreeze = false
		if result := request(wire.TFreeze, []byte(`{"id":"m"}`)); !result.Frozen || result.Error != "" {
			t.Fatalf("freeze: %+v", result)
		}
		failThaw = true
		if result := request(wire.TThaw, []byte(`{"id":"m"}`)); !result.Frozen || result.Error == "" {
			t.Fatalf("failed thaw lost the frozen record: %+v", result)
		}
		if got := g.frozenIDs(); !reflect.DeepEqual(got, []string{"m"}) {
			t.Fatalf("failed thaw state: %v", got)
		}
		failThaw = false
		if result := request(wire.TThaw, []byte(`{"id":"m"}`)); result.Frozen || result.Error != "" {
			t.Fatalf("retry thaw: %+v", result)
		}
	})
}

func TestFreezeConcurrentSyncRechecksLease(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g, f := freezeGuest(t)
		entered := make(chan chan struct{})
		g.filesystem.sync = func(string) {
			resume := make(chan struct{})
			entered <- resume
			<-resume
		}
		results := make(chan error, 2)
		go func() { results <- g.doFreeze("m") }()
		first := <-entered
		go func() { results <- g.doFreeze("m") }()
		second := <-entered
		close(first)
		if err := <-results; err != nil {
			t.Fatal(err)
		}
		close(second)
		if err := <-results; err != nil {
			t.Fatal(err)
		}
		if got := f.take(); got != "freeze "+g.mounts["m"].target {
			t.Fatalf("concurrent requests repeated the freeze ioctl: %s", got)
		}
	})
}

func TestFreezeStoppingDuringSyncAndFailedAutoThaw(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g, f := freezeGuest(t)
		g.filesystem.sync = func(string) { g.stopping = true }
		if err := g.doFreeze("m"); err == nil || g.anyFrozen() || f.take() != "" {
			t.Fatal("shutdown during sync still froze the filesystem")
		}
		g.stopping = false
		g.filesystem.sync = func(string) {}
		g.filesystem.freeze = func(path string, freeze bool) error {
			if !freeze {
				return errors.New("temporary thaw failure")
			}
			return f.freeze(path, freeze)
		}
		if err := g.doFreeze("m"); err != nil {
			t.Fatal(err)
		}
		time.Sleep(freezeTimeout)
		synctest.Wait()
		if !g.anyFrozen() {
			t.Fatal("failed auto-thaw reported the disk as thawed")
		}
		// A failed ioctl preserves the record so an explicit retry (including
		// shutdown's thawAll) can still recover it.
		g.filesystem.freeze = f.freeze
		if err := g.thawAll(); err != nil || g.anyFrozen() {
			t.Fatalf("shutdown retry did not recover failed thaw: %v", err)
		}
	})
}
