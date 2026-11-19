package blipchat

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// task_create's cap equals the default retention cap. At the cap it must
// evict the oldest closed task, exactly like prune with headroom, so a board
// of recently closed tasks doesn't block creation for days.
func TestTaskCreateTrimsOldestClosedAtCap(t *testing.T) {
	now := metav1.NewTime(timeNow())
	tasks := make([]v1.ThreadTask, 0, taskBoardLimit)
	for i := 0; i < 150; i++ {
		updated := metav1.NewTime(now.Add(-time.Duration(i) * time.Minute))
		tasks = append(tasks, v1.ThreadTask{ID: fmt.Sprintf("closed-%03d", i), Title: "done", Open: false, Updated: &updated})
	}
	for i := 0; i < 50; i++ {
		tasks = append(tasks, v1.ThreadTask{ID: fmt.Sprintf("open-%03d", i), Title: "live", Open: true, Updated: &now})
	}
	st := &step{tasks: append([]v1.ThreadTask{}, tasks...)}
	if _, err := st.call(context.Background(), "task_create", `{"id":"new","title":"new work"}`); err != nil {
		t.Fatalf("task_create at cap: %v", err)
	}
	if len(st.tasks) != taskBoardLimit {
		t.Fatalf("tasks = %d, want %d", len(st.tasks), taskBoardLimit)
	}
	found := false
	closed := 0
	for _, task := range st.tasks {
		if task.ID == "new" {
			found = true
		}
		if !task.Open {
			closed++
		}
	}
	if !found {
		t.Error("new task was not created")
	}
	if closed != 149 {
		t.Errorf("closed tasks = %d, want 149 after evicting one", closed)
	}
	for _, task := range st.tasks {
		if task.ID == "closed-149" {
			t.Error("oldest closed task was not evicted")
		}
	}

	// Open work is never evicted to make room.
	allOpen := make([]v1.ThreadTask, 0, taskBoardLimit)
	for i := 0; i < taskBoardLimit; i++ {
		allOpen = append(allOpen, v1.ThreadTask{ID: fmt.Sprintf("live-%03d", i), Open: true})
	}
	st = &step{tasks: allOpen}
	if _, err := st.call(context.Background(), "task_create", `{"id":"new"}`); err == nil || !strings.Contains(err.Error(), "task board is full") {
		t.Fatalf("task_create with an open board = %v, want task board is full", err)
	}
	if len(st.tasks) != taskBoardLimit {
		t.Errorf("open board changed to %d tasks", len(st.tasks))
	}
}
