package gateway

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/Azure/blip/internal/session"
	"github.com/Azure/blip/internal/session/fakeguest"
	"github.com/Azure/blip/internal/wire"
)

// A guest that ignores HUP must still be killed: the gateway has to wait out
// the grace period and send KILL before it closes the transport.
func TestHangupSessionKillsAfterGrace(t *testing.T) {
	oldGrace := hangupGrace
	hangupGrace = 10 * time.Millisecond
	t.Cleanup(func() { hangupGrace = oldGrace })

	events := make(chan string, 8)
	guest := &fakeguest.Guest{}
	guest.Run = func(s *fakeguest.Session) wire.Exit {
		// Deliberately ignore HUP, like a shell that inherited SIG_IGN.
		for ev := range s.Events {
			switch {
			case ev.Signal != "":
				events <- "signal:" + ev.Signal
			case ev.Disconnected:
				events <- "disconnect"
				return wire.Exit{}
			}
		}
		return wire.Exit{}
	}
	client := &session.Client{Connect: guest.Connect}
	sess, err := client.Open(context.Background(), ns, "pod-hangup", wire.Open{Mode: wire.OpenExec})
	if err != nil {
		t.Fatal(err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	start := time.Now()
	hangupSession(log, sess)
	if elapsed := time.Since(start); elapsed < hangupGrace {
		t.Fatalf("hangup returned after %v, before the grace period", elapsed)
	}

	var got []string
	timeout := time.After(5 * time.Second)
	for {
		select {
		case ev := <-events:
			got = append(got, ev)
			if ev != "disconnect" {
				continue
			}
			want := []string{"signal:HUP", "signal:KILL", "disconnect"}
			if len(got) != len(want) {
				t.Fatalf("events = %v, want %v", got, want)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("events = %v, want %v", got, want)
				}
			}
			return
		case <-timeout:
			t.Fatalf("events = %v, want HUP, KILL, then disconnect", got)
		}
	}
}
