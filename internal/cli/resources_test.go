package cli

import (
	"fmt"
	"strings"
	"testing"
)

// validateName is the single preflight every command uses. It must reject an
// impossible name with the short message, and accept the longest legal one.
func TestValidateNameEdges(t *testing.T) {
	a := &app{}
	for _, tc := range []struct {
		label string
		name  string
		want  string
	}{
		{"empty", "", "must not be empty"},
		{"whitespace", " ", "RFC 1123"},
		{"254", strings.Repeat("a", 254), "253"},
		{"300", strings.Repeat("a", 300), "253"},
		{"253", strings.Repeat("a", 253), ""},
	} {
		t.Run(tc.label, func(t *testing.T) {
			err := a.validateName("state", tc.name)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("validateName(%d chars) = %v, want nil", len(tc.name), err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validateName(%d chars) = %v, want %q", len(tc.name), err, tc.want)
			}
		})
	}
}

// State references are checked like names the CLI creates: a malformed one
// fails with the short message before client-go sees it.
func TestStateReferencesAreValidated(t *testing.T) {
	tooLong := strings.Repeat("a", 254)
	longest := strings.Repeat("a", 253)
	h := newHarness(t, readyState("base"))
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"from slash", []string{"run", "--name", "s1", "--from", "a/b", "--", "true"}, `invalid state name "a/b"`},
		{"state slash", []string{"run", "--name", "s2", "--state", "a/b", "--", "true"}, `invalid state name "a/b"`},
		{"from dotdot", []string{"run", "--name", "s3", "--from", "..", "--", "true"}, `invalid state name ".."`},
		{"from 254", []string{"run", "--name", "s4", "--from", tooLong, "--", "true"}, `invalid state name "` + tooLong + `"`},
		{"mount root slash", []string{"mount", "--root", "a/b"}, `invalid state name "a/b"`},
		{"mount rm slash", []string{"mount", "--rm", "a/b", "--root", "base"}, `invalid state name "a/b"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, errOut := h.run("", tc.args...)
			if code != 1 || !strings.Contains(errOut, tc.want) {
				t.Fatalf("code %d stderr %q, want %q", code, errOut, tc.want)
			}
			if strings.Contains(errOut, "invalid resource name") {
				t.Fatalf("stderr %q leaked client-go validation", errOut)
			}
		})
	}
	// The longest legal name passes validation and fails only at the lookup.
	code, _, errOut := h.run("", "run", "--name", "s5", "--from", longest, "--", "true")
	if code != 1 || !strings.Contains(errOut, `state "`+longest+`" not found`) || strings.Contains(errOut, "invalid state name") {
		t.Fatalf("253-char state: code %d stderr %q", code, errOut)
	}
}

func TestOwnerScopedNamesReportFullCheckedName(t *testing.T) {
	long := strings.Repeat("a", 250)
	full := "alice." + long
	h := newHarness(t, ownedBlip("alice.box", "alice.home"), readyState("alice.base"))
	h.self = "alice.box"
	for _, tc := range []struct {
		name string
		kind string
		args []string
	}{
		{"pull", "state", []string{"pull", long, "registry/dev:v1", "-d"}},
		{"gather", "blip", []string{"gather", long}},
		{"run", "blip", []string{"run", "--name", long, "--from", "base", "--", "true"}},
		{"logs", "blip", []string{"logs", long}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, errOut := h.run("", tc.args...)
			if code != 1 {
				t.Fatalf("code %d: %s", code, errOut)
			}
			if want := fmt.Sprintf("invalid %s name %q", tc.kind, full); !strings.Contains(errOut, want) {
				t.Fatalf("stderr %q does not report the checked name %q", errOut, want)
			}
			if !strings.Contains(errOut, "253") {
				t.Fatalf("stderr %q does not mention the 253 limit", errOut)
			}
			if !strings.Contains(errOut, `"alice." owner prefix`) {
				t.Fatalf("stderr %q does not explain the owner prefix", errOut)
			}
			if strings.Contains(errOut, fmt.Sprintf("invalid %s name %q", tc.kind, long)) {
				t.Fatalf("stderr %q reports the short unchecked name", errOut)
			}
		})
	}
}
