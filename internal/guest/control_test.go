package guest

import (
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Azure/blip/internal/wire"
)

func TestControlReconnectReplacesBlockedHello(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := &Guest{}
		host, guest := net.Pipe()
		defer host.Close()
		done := make(chan struct{})
		go func() { g.serveControlStream(guest); close(done) }()
		synctest.Wait() // Hello cannot be delivered to this host.
		start := time.Now()
		c := controlPair(t, g)
		readFrame(t, c, wire.THello, &wire.Hello{})
		readFrame(t, c, wire.TStatus, &wire.Status{})
		<-done
		if time.Since(start) != 0 {
			t.Fatal("reconnect waited for the old Hello write timeout")
		}
	})
}

func TestControlBlockedShutdownReportIsBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := &Guest{}
		c := controlPair(t, g)
		readFrame(t, c, wire.THello, &wire.Hello{})
		readFrame(t, c, wire.TStatus, &wire.Status{})
		start := time.Now()
		g.shutdown() // Host never reads ShutdownDone.
		if elapsed := time.Since(start); elapsed > controlWriteTimeout+2*time.Second {
			t.Fatalf("shutdown report held the guest for %v", elapsed)
		}
		synctest.Wait()
		if g.ctl != nil || !g.stopping {
			t.Fatal("shutdown did not disconnect the stalled control stream")
		}
	})
}
