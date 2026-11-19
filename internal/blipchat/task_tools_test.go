package blipchat

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestTaskCreateTruncatesTitle(t *testing.T) {
	st := &step{}
	args, err := json.Marshal(map[string]any{"id": "t1", "title": strings.Repeat("x", 121)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.call(context.Background(), "task_create", string(args)); err != nil {
		t.Fatal(err)
	}
	if len(st.tasks) != 1 {
		t.Fatalf("tasks = %+v", st.tasks)
	}
	if got := len([]rune(st.tasks[0].Title)); got != 120 {
		t.Errorf("title length = %d, want 120", got)
	}
}

func TestTaskUpdateRespectsAttributeLimits(t *testing.T) {
	st := &step{}
	attrs := map[string]string{}
	for i := 0; i < 15; i++ {
		attrs[fmt.Sprintf("k%d", i)] = "v"
	}
	create, err := json.Marshal(map[string]any{"id": "t1", "title": "task", "attributes": attrs})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.call(context.Background(), "task_create", string(create)); err != nil {
		t.Fatal(err)
	}

	// A change that would exceed the CRD's 16-attribute limit is rejected
	// without mutating the task, so the step's status update stays valid.
	update, err := json.Marshal(map[string]any{
		"id":         "t1",
		"title":      strings.Repeat("y", 121),
		"attributes": map[string]string{"a": "1", "b": "2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.call(context.Background(), "task_update", string(update)); err == nil {
		t.Fatal("update with 17 attributes was accepted")
	}
	if got := len(st.tasks[0].Attributes); got != 15 {
		t.Errorf("attributes after rejected update = %d, want 15", got)
	}
	if got := st.tasks[0].Title; got != "task" {
		t.Errorf("title after rejected update = %q, want unchanged", got)
	}

	// Long attribute keys and values are truncated to the CRD limits.
	longKey := strings.Repeat("k", 64)
	longValue := strings.Repeat("v", 300)
	update, err = json.Marshal(map[string]any{
		"id":         "t1",
		"attributes": map[string]string{longKey: longValue},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.call(context.Background(), "task_update", string(update)); err != nil {
		t.Fatal(err)
	}
	if got := len(st.tasks[0].Attributes); got != 16 {
		t.Errorf("attributes = %d, want 16", got)
	}
	found := false
	for k, v := range st.tasks[0].Attributes {
		if len([]rune(k)) == 63 && v == strings.Repeat("v", 256) {
			found = true
		}
	}
	if !found {
		t.Errorf("long attribute was not truncated: %+v", st.tasks[0].Attributes)
	}
}
