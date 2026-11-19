package blipchat

import (
	"testing"
	"time"
)

func TestHubReplayAndGap(t *testing.T) {
	h := NewHub()
	h.Publish(Event{Type: "status"})
	h.Publish(Event{Type: "acp"})
	h.Publish(Event{Type: "acp"})

	replay, ch, cancel := h.Subscribe(1)
	defer cancel()
	if len(replay) != 2 || replay[0].Offset != 2 || replay[1].Offset != 3 {
		t.Fatalf("replay = %+v", replay)
	}
	h.Publish(Event{Type: "status"})
	select {
	case ev := <-ch:
		if ev.Offset != 4 || ev.Type != "status" {
			t.Fatalf("live event = %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("no live event")
	}

	for i := 0; i < hubHistory+10; i++ {
		h.Publish(Event{Type: "acp"})
	}
	tooOld, _, cancel2 := h.Subscribe(1)
	defer cancel2()
	if len(tooOld) == 0 || tooOld[0].Type != "gap" {
		t.Fatalf("expected a leading gap, got %+v", tooOld[:1])
	}
}

func TestHubCancelClosesChannel(t *testing.T) {
	h := NewHub()
	_, ch, cancel := h.Subscribe(0)
	cancel()
	if _, ok := <-ch; ok {
		t.Fatal("channel is still open")
	}
	h.Publish(Event{Type: "status"}) // must not panic
}
