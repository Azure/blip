package v1alpha1

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/util/validation"
)

func TestParentLabelFitsLabelValueLimit(t *testing.T) {
	if got := ParentLabel("box"); got != "box" {
		t.Fatalf("short parent label = %q", got)
	}
	long := "alice." + strings.Repeat("a", 70)
	got := ParentLabel(long)
	if len(got) > 63 {
		t.Fatalf("long parent label %q is %d bytes", got, len(got))
	}
	if problems := validation.IsValidLabelValue(got); len(problems) > 0 {
		t.Fatalf("long parent label %q: %v", got, problems)
	}
	if got != ParentLabel(long) {
		t.Fatal("parent label is not stable")
	}
	if got == ParentLabel(long+"x") {
		t.Fatal("different names share a parent label")
	}
}

func TestThreadLabelFitsLabelValueLimit(t *testing.T) {
	if got := ThreadLabel("proj"); got != "proj" {
		t.Fatalf("short thread label = %q", got)
	}
	long := "alice-" + strings.Repeat("a", 70)
	got := ThreadLabel(long)
	if len(got) > 63 {
		t.Fatalf("long thread label %q is %d bytes", got, len(got))
	}
	if problems := validation.IsValidLabelValue(got); len(problems) > 0 {
		t.Fatalf("long thread label %q: %v", got, problems)
	}
	if got != ThreadLabel(long) {
		t.Fatal("thread label is not stable")
	}
	if got == ThreadLabel(long+"x") {
		t.Fatal("different names share a thread label")
	}
}

// A hashed thread label must not be representable as a thread name. Otherwise
// a legal short thread (or a turn labelled for one) can collide with a long
// thread's label and the API proxy mixes both projects' turns.
func TestThreadLabelHashIsReserved(t *testing.T) {
	for _, name := range []string{
		"alice-" + strings.Repeat("a", 70),
		"project-" + strings.Repeat("z", 240),
	} {
		got := ThreadLabel(name)
		if !strings.HasPrefix(got, "thread_") {
			t.Errorf("hashed thread label %q lacks the reserved prefix", got)
		}
		if problems := validation.IsDNS1123Subdomain(got); len(problems) == 0 {
			t.Errorf("hashed thread label %q is a legal thread name; a short thread could collide", got)
		}
		// A literal short name keeps its own value, so it cannot be mistaken
		// for the hash of another thread.
		if literal := got; ThreadLabel(literal) != literal {
			t.Errorf("literal thread name %q was re-hashed", literal)
		}
	}
}
