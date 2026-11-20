// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package v1alpha1

import (
	"crypto/sha256"
	"encoding/hex"
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

// A hashed parent label must not be representable as a parent name. Otherwise
// a legal short parent named exactly another parent's hash shares its
// blip.dev/parent label and bare gather can delete the other parent's forks.
func TestParentLabelHashIsReserved(t *testing.T) {
	for _, name := range []string{
		"alice." + strings.Repeat("a", 70),
		"project-" + strings.Repeat("z", 240),
	} {
		got := ParentLabel(name)
		if !strings.HasPrefix(got, "parent_") {
			t.Errorf("hashed parent label %q lacks the reserved prefix", got)
		}
		if problems := validation.IsDNS1123Subdomain(got); len(problems) == 0 {
			t.Errorf("hashed parent label %q is a legal parent name; a short parent could collide", got)
		}
		// A literal short name keeps its own value, so it cannot be mistaken
		// for the hash of another parent.
		if literal := got; ParentLabel(literal) != literal {
			t.Errorf("literal parent name %q was re-hashed", literal)
		}
	}
}

// Regression: a short parent whose name is the old sha256- hash spelling must
// not share a label with the long parent that produces that hash.
func TestParentLabelHashCannotCollideWithShortName(t *testing.T) {
	long := "alice-" + strings.Repeat("a", 70)
	sum := sha256.Sum256([]byte(long))
	oldHash := "sha256-" + hex.EncodeToString(sum[:])[:56]
	if problems := validation.IsDNS1123Subdomain(oldHash); len(problems) > 0 {
		t.Fatalf("old hash spelling %q is not a legal parent name: %v", oldHash, problems)
	}
	if got := ParentLabel(oldHash); got != oldHash {
		t.Fatalf("short parent %q = %q, want unchanged", oldHash, got)
	}
	if got := ParentLabel(long); got == oldHash {
		t.Fatalf("hashed parent label still uses the legal-name spelling %q", got)
	}
	if ParentLabel(long) == ParentLabel(oldHash) {
		t.Fatalf("hashed parent label %q collides with short parent %q", ParentLabel(long), oldHash)
	}
}
