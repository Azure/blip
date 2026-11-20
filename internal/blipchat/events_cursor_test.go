// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"context"
	"fmt"
	"io"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	v1 "github.com/Azure/blip/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// cursorTestWire ends the first stream, then cancels on reconnect. Reaching
// the second OpenLog proves the handler consumed the entire first stream,
// without relying on a timeout to establish that no event was emitted.
type cursorTestWire struct {
	Wire
	lines   string
	cancel  context.CancelFunc
	offsets []uint64
}

func (w *cursorTestWire) OpenLog(ctx context.Context, _, _ string, offset uint64) (io.ReadCloser, error) {
	w.offsets = append(w.offsets, offset)
	if len(w.offsets) == 1 {
		return io.NopCloser(strings.NewReader(w.lines)), nil
	}
	w.cancel()
	return nil, ctx.Err()
}

func TestServerEventsCursorNeverMovesBackward(t *testing.T) {
	for _, tt := range []struct {
		name       string
		after      uint64
		lines      string
		wantIDs    []string
		wantCursor uint64
	}{
		{
			name: "one past newest waits", after: 26,
			lines:      "{\"t\":\"gap\",\"o\":25}\n{\"t\":\"start\",\"o\":25}\n",
			wantCursor: 26,
		},
		{
			name: "maximum cursor waits", after: ^uint64(0),
			lines:      "{\"t\":\"gap\",\"o\":25}\n{\"t\":\"start\",\"o\":25}\n",
			wantCursor: ^uint64(0),
		},
		{
			name: "future record resumes strictly after cursor", after: 26,
			lines:   "{\"t\":\"gap\",\"o\":25}\n{\"t\":\"start\",\"o\":26}\n{\"t\":\"end\",\"o\":27}\n",
			wantIDs: []string{"id: 27"}, wantCursor: 27,
		},
		{
			name: "real ring loss still resynchronizes", after: 1,
			lines:   "{\"t\":\"gap\",\"o\":25}\n{\"t\":\"end\",\"o\":27}\n",
			wantIDs: []string{"id: 25", "id: 27"}, wantCursor: 27,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			wire := &cursorTestWire{lines: tt.lines, cancel: cancel}
			cluster := newFakeCluster()
			cluster.states[key("team", "chat-test")] = &v1.BlipState{ObjectMeta: metav1.ObjectMeta{
				Namespace: "team", Name: "chat-test",
				Labels:      map[string]string{LabelSession: "true", v1.LabelOwner: "alice"},
				Annotations: map[string]string{AnnotationProfile: DefaultProfileName},
			}}
			s := &Server{namespace: "team", cluster: cluster, wire: wire, log: testLogger()}
			req := httptest.NewRequest("GET", fmt.Sprintf("/api/sessions/chat-test/events?offset=%d", tt.after), nil).WithContext(ctx)
			req.SetPathValue("name", "chat-test")
			req.Header.Set("X-Forwarded-User", "alice")
			recorder := httptest.NewRecorder()
			s.handleEvents(recorder, req)
			if !reflect.DeepEqual(wire.offsets, []uint64{tt.after, tt.wantCursor}) {
				t.Fatalf("OpenLog cursors = %v, want [%d %d]; response: %s", wire.offsets, tt.after, tt.wantCursor, recorder.Body.String())
			}
			var ids []string
			for _, line := range strings.Split(recorder.Body.String(), "\n") {
				if strings.HasPrefix(line, "id: ") {
					ids = append(ids, line)
				}
			}
			if !reflect.DeepEqual(ids, tt.wantIDs) {
				t.Fatalf("SSE IDs = %v, want %v; response: %s", ids, tt.wantIDs, recorder.Body.String())
			}
			if tt.after == 1 && !strings.Contains(recorder.Body.String(), `"type":"gap"`) {
				t.Fatalf("real ring loss did not emit a gap: %s", recorder.Body.String())
			}
		})
	}
}
