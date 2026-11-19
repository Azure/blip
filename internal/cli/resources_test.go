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

// An owner-scoped caller checks "<owner>.<name>". When the prefix is what
// pushed it over 253, the error must quote the name that was checked and
// explain that the prefix counts, not quote the short name against a limit it
// meets. This covers each command that scopes a name before validating it.
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
		{"exec", "blip", []string{"exec", long, "--", "true"}},
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
