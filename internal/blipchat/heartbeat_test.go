package blipchat

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

func TestNextWakeUsesThreadHeartbeat(t *testing.T) {
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	fiveMinutes := metav1.Duration{Duration: 5 * time.Minute}
	tests := []struct {
		name   string
		thread *metav1.Duration
		config time.Duration
		want   time.Duration
	}{
		{name: "thread heartbeat", thread: &fiveMinutes, config: 30 * time.Minute, want: 5 * time.Minute},
		{name: "falls back to config", thread: nil, config: 7 * time.Minute, want: 7 * time.Minute},
		{name: "falls back to default", thread: nil, config: 0, want: 30 * time.Minute},
		{name: "zero thread heartbeat uses config", thread: &metav1.Duration{Duration: 0}, config: 7 * time.Minute, want: 7 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			thread := testThread()
			thread.Spec.Heartbeat = tt.thread
			st := &step{
				s:      &Server{Config: Config{Heartbeat: tt.config}},
				thread: thread,
				tasks:  []v1.ThreadTask{{ID: "t1", Open: true}},
			}
			got := nextWake(st, now)
			if got == nil {
				t.Fatal("nextWake returned nil")
			}
			if want := now.Add(tt.want); !got.Time.Equal(want) {
				t.Errorf("nextWake = %s, want %s", got.Time, want)
			}
		})
	}

	t.Run("timer earlier than heartbeat wins", func(t *testing.T) {
		thread := testThread()
		thread.Spec.Heartbeat = &fiveMinutes
		at := now.Add(time.Minute)
		st := &step{
			s:      &Server{Config: Config{Heartbeat: 30 * time.Minute}},
			thread: thread,
			tasks:  []v1.ThreadTask{{ID: "t1", Open: true}},
			timers: []v1.ThreadTimer{{ID: "timer", At: metav1.NewTime(at)}},
		}
		got := nextWake(st, now)
		if got == nil || !got.Time.Equal(at) {
			t.Errorf("nextWake = %v, want timer at %s", got, at)
		}
	})
}
