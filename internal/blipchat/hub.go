package blipchat

import (
	"encoding/json"
	"sync"
)

// Event is one server-sent event.
type Event struct {
	// Offset is a per-run sequence number. It is what ?offset= and the SSE
	// Last-Event-ID header refer to.
	Offset  uint64          `json:"offset"`
	Type    string          `json:"type"`
	Message json.RawMessage `json:"message,omitempty"`
	Status  *Status         `json:"status,omitempty"`
}

// Status reports a lifecycle change.
type Status struct {
	Phase   string `json:"phase,omitempty"`
	Running bool   `json:"running"`
	Detail  string `json:"detail,omitempty"`
}

const (
	hubHistory = 512
	hubBuffer  = 256
)

// Hub broadcasts events for one state and keeps a short replay ring.
type Hub struct {
	mu     sync.Mutex
	next   uint64
	events []Event
	subs   map[*hubSub]struct{}
}

type hubSub struct {
	ch      chan Event
	dropped bool
}

func NewHub() *Hub {
	return &Hub{subs: make(map[*hubSub]struct{})}
}

func (h *Hub) Publish(ev Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.next++
	ev.Offset = h.next
	if len(h.events) == hubHistory {
		copy(h.events, h.events[1:])
		h.events[len(h.events)-1] = ev
	} else {
		h.events = append(h.events, ev)
	}
	for sub := range h.subs {
		if sub.dropped {
			select {
			case sub.ch <- Event{Offset: ev.Offset, Type: "gap"}:
				sub.dropped = false
			default:
				continue
			}
		}
		select {
		case sub.ch <- ev:
		default:
			// A slow browser must not block the driver. The next event it
			// receives is a gap marker so it can refetch the transcript.
			sub.dropped = true
		}
	}
}

// Subscribe returns replay events after the requested offset and a live
// channel. If the requested offset is older than the ring, the replay starts
// with a gap marker. The cancel function must be called when the client goes
// away.
func (h *Hub) Subscribe(after uint64) (replay []Event, ch <-chan Event, cancel func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	sub := &hubSub{ch: make(chan Event, hubBuffer)}
	h.subs[sub] = struct{}{}

	if len(h.events) > 0 {
		base := h.events[0].Offset
		if after > 0 && after+1 < base {
			replay = append(replay, Event{Offset: base, Type: "gap"})
		}
		for _, ev := range h.events {
			if ev.Offset > after {
				replay = append(replay, ev)
			}
		}
	}
	return replay, sub.ch, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if _, ok := h.subs[sub]; ok {
			delete(h.subs, sub)
			close(sub.ch)
		}
	}
}

// Seq returns the newest published offset.
func (h *Hub) Seq() uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.next
}
