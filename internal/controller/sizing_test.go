package controller

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPoolTarget(t *testing.T) {
	n := func(v int) *int { return &v }
	for _, tc := range []struct {
		name            string
		in              poolSizing
		desired, target int
	}{
		{"idle", poolSizing{MinFree: 2, MaxFree: 10, Headroom: 10}, 2, 2},
		{"demand", poolSizing{MinFree: 2, MaxFree: 10, Demand: 3, Headroom: 10}, 5, 5},
		{"demand capped by maxFree", poolSizing{MinFree: 2, MaxFree: 4, Demand: 9, Headroom: 10}, 4, 4},
		{"demand capped by headroom", poolSizing{MinFree: 2, MaxFree: 10, Demand: 9, Headroom: 1}, 3, 3},
		{"no headroom keeps minFree", poolSizing{MinFree: 2, MaxFree: 10, Demand: 9, Headroom: -3}, 2, 2},
		{"waiting", poolSizing{MinFree: 1, MaxFree: 3, Demand: 1, Waiting: 4, Headroom: 10}, 2, 6},
		{"maxSlots", poolSizing{MinFree: 1, MaxFree: 3, Waiting: 4, Assigned: 3, MaxSlots: n(5), Headroom: 10}, 1, 2},
		{"maxSlots full", poolSizing{MinFree: 1, MaxFree: 3, Assigned: 7, MaxSlots: n(5), Headroom: 10}, 1, 0},
		{"zero", poolSizing{Waiting: 2, MaxSlots: n(0)}, 0, 0},
	} {
		d, tg := poolTarget(tc.in)
		if d != tc.desired || tg != tc.target {
			t.Errorf("%s: got %d/%d want %d/%d", tc.name, d, tg, tc.desired, tc.target)
		}
	}
}

func TestScaleStep(t *testing.T) {
	now := time.Unix(1000, 0)
	d := 10 * time.Second
	for _, tc := range []struct {
		name         string
		have, target int
		since        time.Time
		delta        int
		keepSince    bool
		wait         time.Duration
	}{
		{"up", 1, 4, now.Add(-time.Hour), 3, false, 0},
		{"equal", 2, 2, now.Add(-time.Hour), 0, false, 0},
		{"down starts timer", 5, 2, time.Time{}, 0, true, d},
		{"down waits", 5, 2, now.Add(-4 * time.Second), 0, true, 6 * time.Second},
		{"down due", 5, 2, now.Add(-d), -3, true, 0},
	} {
		delta, since, wait := scaleStep(tc.have, tc.target, tc.since, now, d)
		if delta != tc.delta || wait != tc.wait || since.IsZero() == tc.keepSince {
			t.Errorf("%s: got %d %v %v", tc.name, delta, since, wait)
		}
	}
}

func TestSortForDeletion(t *testing.T) {
	ready := []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	mk := func(name, node string, r bool) *corev1.Pod {
		p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: corev1.PodSpec{NodeName: node}}
		if r {
			p.Status.Conditions = ready
		}
		return p
	}
	pods := []*corev1.Pod{mk("a", "n1", true), mk("b", "n2", true), mk("c", "n1", false), mk("d", "", false), mk("e", "n2", true)}
	sortForDeletion(pods, map[string]int{"n1": 1, "n2": 2})
	got := ""
	for _, p := range pods {
		got += p.Name
	}
	if got != "dcbea" {
		t.Errorf("order %s", got)
	}
}
