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

// timeoutSeconds is checked before the float64-to-Duration conversion. Large
// values used to overflow and wrap to a positive sub-second deadline.
func TestExecTimeoutSecondsRangeChecked(t *testing.T) {
	thread := testThread()
	owner := Owner(&ThreadKey{Namespace: "ns", Name: "proj"})
	b := &v1.Blip{
		ObjectMeta: metav1.ObjectMeta{
			Name: "blip-a", Namespace: "ns",
			Labels: map[string]string{v1.LabelThread: "proj", v1.LabelOwner: owner},
		},
		Status: v1.BlipStatus{Phase: v1.BlipRunning, Pod: "pod-a"},
	}
	for _, tc := range []struct {
		arg  string
		want func(time.Duration) bool
	}{
		{"0", aboutSixtySeconds},
		{"1", aboutOneSecond},
		{"60", aboutSixtySeconds},
		{"61", aboutSixtySeconds},
		{"18446744074", aboutSixtySeconds},
		{"1e300", aboutSixtySeconds},
	} {
		t.Run(tc.arg, func(t *testing.T) {
			c := testClient(t, thread, b)
			var remaining time.Duration
			s := &Server{Client: c}
			s.execClient = &session.Client{Connect: func(ctx context.Context, _, _ string) (io.ReadWriteCloser, error) {
				if deadline, ok := ctx.Deadline(); ok {
					remaining = time.Until(deadline)
				}
				return nil, errors.New("stop after recording the deadline")
			}}
			s.execOnce.Do(func() {})
			st := &step{s: s, thread: thread}
			_, _ = st.call(context.Background(), "exec", `{"blip":"blip-a","argv":["ls"],"timeoutSeconds":`+tc.arg+`}`)
			if !tc.want(remaining) {
				t.Errorf("timeoutSeconds=%s produced a %s deadline", tc.arg, remaining)
			}
		})
	}
}

func aboutSixtySeconds(d time.Duration) bool {
	return d > 50*time.Second && d <= 61*time.Second
}

func aboutOneSecond(d time.Duration) bool {
	return d > 500*time.Millisecond && d <= 2*time.Second
}
