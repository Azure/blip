package blipchat

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/session"
)

// Inspecting a running blip must give the guest command the documented 60
// seconds. Passing the untyped constant 60 as a time.Duration made the
// deadline 60 nanoseconds, so every inspection failed before it dialed.
func TestChatInspectUsesSixtySecondExecTimeout(t *testing.T) {
	thread := testThread()
	owner := Owner(&ThreadKey{Namespace: "ns", Name: "proj"})
	b := &v1.Blip{
		ObjectMeta: metav1.ObjectMeta{
			Name: "blip-a", Namespace: "ns",
			Labels: map[string]string{v1.LabelThread: "proj", v1.LabelOwner: owner},
		},
		Status: v1.BlipStatus{Phase: v1.BlipRunning, Pod: "pod-a"},
	}
	c := testClient(t, thread, b)
	var remaining time.Duration
	s := &Server{Client: c}
	s.execClient = &session.Client{Connect: func(ctx context.Context, _, _ string) (io.ReadWriteCloser, error) {
		if deadline, ok := ctx.Deadline(); ok {
			remaining = time.Until(deadline)
		}
		return nil, errors.New("stop after recording deadline")
	}}
	s.execOnce.Do(func() {})

	chat := &chatStep{s: s, thread: thread}
	if _, err := chat.inspect(context.Background(), "blip-a", []string{"ls"}); err == nil {
		t.Fatal("inspect succeeded, want the connector error")
	}
	if remaining < 50*time.Second || remaining > 61*time.Second {
		t.Errorf("inspect exec deadline remaining = %s, want about 60s", remaining)
	}
}
