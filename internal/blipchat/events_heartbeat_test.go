// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"bufio"
	"context"
	"net/http"
	"testing"
	"time"
)

// An idle event stream must deliver a client-visible heartbeat: SSE comments
// never reach EventSource, so the UI cannot use them to tell a live stream
// from a half-open one. The frame must also avoid an id: line, which would
// move Last-Event-ID off the transcript cursor.
func TestServerEventsHeartbeatFrame(t *testing.T) {
	previous := eventHeartbeatInterval
	eventHeartbeatInterval = 25 * time.Millisecond
	t.Cleanup(func() { eventHeartbeatInterval = previous })

	g := newGateway(t, Options{})
	name := g.createChat(t, map[string]any{"profile": DefaultProfileName}, "alice")

	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.ts.URL+"/api/sessions/"+name+"/events?offset=0", nil)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	req.Header.Set("X-Forwarded-User", "alice")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		resp.Body.Close()
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("events: status %d", resp.StatusCode)
	}

	// Deliver whole SSE blocks so a heartbeat can be distinguished from a
	// transcript frame by its lines alone.
	frames := make(chan []string, 8)
	go func() {
		var block []string
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if line != "" {
				block = append(block, line)
				continue
			}
			if len(block) == 0 {
				continue
			}
			select {
			case frames <- block:
			case <-ctx.Done():
				return
			}
			block = nil
		}
	}()

	deadline := time.After(3 * time.Second)
	for {
		select {
		case block := <-frames:
			if len(block) == 1 && block[0] == `data: {"type":"hb"}` {
				return
			}
		case <-deadline:
			t.Fatal("idle event stream did not emit a heartbeat frame")
		}
	}
}
