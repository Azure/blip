// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// browserWire gives every chat its own in-memory ring and answers prompts the
// way a simple agent would: it streams "echo: <prompt>" and ends the turn. A
// prompt containing "slow" streams one chunk and then waits for
// session/cancel, so the UI can exercise a running turn; one containing "wait"
// takes a second and a half before it answers.
type browserWire struct {
	cluster *fakeCluster
	mu      sync.Mutex
	rings   map[string]*fakeWire
	cancels map[string]chan struct{}
}

func (w *browserWire) ring(state string) *fakeWire {
	w.mu.Lock()
	defer w.mu.Unlock()
	r := w.rings[state]
	if r == nil {
		r = newFakeWire()
		w.rings[state] = r
	}
	return r
}

func (w *browserWire) closeAll() {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, r := range w.rings {
		r.closeLog()
	}
}

func (w *browserWire) Send(ctx context.Context, ns, state string, data []byte, eof, note bool, after uint64) (uint64, error) {
	blips, err := w.cluster.ListStateBlips(ctx, ns, state)
	if err != nil {
		return 0, err
	}
	if runningBlip(blips) == nil {
		return 0, ErrNotRunning
	}
	r := w.ring(state)
	off, err := r.Send(ctx, ns, state, data, eof, note, after)
	if err != nil || note {
		return off, err
	}
	if eof {
		// Closing stdin makes the agent exit: the node records the end of the
		// generation, and the controller saves the workspace as a new commit
		// and marks the blip finished.
		r.mu.Lock()
		gen := r.gen
		r.mu.Unlock()
		go func() {
			time.Sleep(20 * time.Millisecond)
			r.end(gen)
			w.cluster.mu.Lock()
			defer w.cluster.mu.Unlock()
			for _, b := range w.cluster.blips {
				if b.Namespace == ns && b.Labels[LabelSession] == state && uint64(generationOf(b)) == gen {
					b.Status.Phase = v1.BlipSucceeded
				}
			}
			if st := w.cluster.states[key(ns, state)]; st != nil {
				st.Status.Writer = nil
				st.Status.Committed = &v1.Commit{ID: fmt.Sprintf("%s-c%d", state, gen), Generation: int64(gen)}
			}
		}()
		return off, nil
	}
	var msg struct {
		Method string          `json:"method"`
		ID     json.RawMessage `json:"id"`
	}
	if json.Unmarshal(data, &msg) != nil {
		return off, nil
	}
	switch msg.Method {
	case "session/prompt":
		r.mu.Lock()
		gen := r.gen
		r.mu.Unlock()
		go w.answer(r, state, gen, msg.ID, promptText(data))
	case "session/cancel":
		w.mu.Lock()
		if ch := w.cancels[state]; ch != nil {
			close(ch)
			delete(w.cancels, state)
		}
		w.mu.Unlock()
	}
	return off, nil
}

func (w *browserWire) answer(r *fakeWire, state string, gen uint64, id json.RawMessage, text string) {
	chunk := func(s string) {
		r.emitACP(gen, map[string]any{
			"jsonrpc": "2.0",
			"method":  "session/update",
			"params": map[string]any{
				"sessionId": "acp-session-1",
				"update": map[string]any{
					"sessionUpdate": "agent_message_chunk",
					"content":       map[string]string{"type": "text", "text": s},
				},
			},
		})
	}
	reason := "end_turn"
	if strings.Contains(text, "slow") {
		ch := make(chan struct{})
		w.mu.Lock()
		w.cancels[state] = ch
		w.mu.Unlock()
		chunk("working on it")
		select {
		case <-ch:
			reason = "cancelled"
		case <-time.After(60 * time.Second):
		}
	} else {
		if strings.Contains(text, "wait") {
			time.Sleep(1500 * time.Millisecond)
		}
		// Stream the reply in two pieces so the UI has to merge chunks.
		time.Sleep(50 * time.Millisecond)
		chunk("echo: ")
		time.Sleep(50 * time.Millisecond)
		chunk(text)
	}
	r.emitACP(gen, map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{"stopReason": reason}})
}

func (w *browserWire) OpenLog(ctx context.Context, _, state string, offset uint64) (io.ReadCloser, error) {
	return &followLogReader{wire: w.ring(state), ctx: ctx, after: offset}, nil
}

func (w *browserWire) ReadLog(ctx context.Context, ns, state string, offset uint64) (io.ReadCloser, error) {
	return (&runningWire{fakeWire: w.ring(state), cluster: w.cluster}).ReadLog(ctx, ns, state, offset)
}

func (w *browserWire) LogEnd(ctx context.Context, ns, state string) (uint64, error) {
	return w.ring(state).LogEnd(ctx, ns, state)
}

// eventDropper lets the browser script cut every open event stream, as a
// proxy restart would, by calling POST /__test/drop-events.
type eventDropper struct {
	mu      sync.Mutex
	cancels map[int]context.CancelFunc
	next    int
}

func (d *eventDropper) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/__test/drop-events" {
			d.mu.Lock()
			n := len(d.cancels)
			for _, cancel := range d.cancels {
				cancel()
			}
			d.mu.Unlock()
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]int{"dropped": n})
			return
		}
		// The deployment's auth proxy sets the identity on every request.
		r.Header.Set("X-Forwarded-User", "alice")
		if !strings.HasSuffix(r.URL.Path, "/events") {
			next.ServeHTTP(rw, r)
			return
		}
		ctx, cancel := context.WithCancel(r.Context())
		d.mu.Lock()
		id := d.next
		d.next++
		d.cancels[id] = cancel
		d.mu.Unlock()
		defer func() {
			d.mu.Lock()
			delete(d.cancels, id)
			d.mu.Unlock()
			cancel()
		}()
		next.ServeHTTP(rw, r.WithContext(ctx))
	})
}

// TestBrowser drives the real UI in Chromium against a real server whose
// Kubernetes and agent backends are in memory. It needs node and Playwright,
// so it only runs with BLIP_BROWSER_TESTS=1 (see make test-ui).
func TestBrowser(t *testing.T) {
	if os.Getenv("BLIP_BROWSER_TESTS") != "1" {
		t.Skip("set BLIP_BROWSER_TESTS=1 to run the browser tests")
	}
	fc := newFakeCluster()
	wire := &browserWire{cluster: fc, rings: map[string]*fakeWire{}, cancels: map[string]chan struct{}{}}
	fc.onCreateBlip = func(b *v1.Blip) {
		wire.ring(b.Spec.State).start(uint64(generationOf(b)))
	}
	s, err := New(Options{
		Namespace:   "team",
		DefaultPool: "default",
		AutoApprove: "always",
		Profiles:    Profiles{DefaultProfileName: {}},
		Cluster:     fc,
		Wire:        wire,
		Log:         testLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.Start(ctx)
	dropper := &eventDropper{cancels: map[int]context.CancelFunc{}}
	ts := httptest.NewServer(dropper.wrap(s.Handler()))
	t.Cleanup(func() {
		ts.Close()
		cancel()
		s.Close()
		wire.closeAll()
	})

	script, err := filepath.Abs("../../hack/e2e/blipchat-ui/run.js")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("node", script, ts.URL)
	cmd.Dir = filepath.Dir(script)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("browser tests failed: %v", err)
	}
}
