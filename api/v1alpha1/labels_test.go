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
