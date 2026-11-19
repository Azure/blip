package cli

import (
	"strings"
	"testing"
)

func TestParseSizeFlag(t *testing.T) {
	for _, value := range []string{"1", "20Gi", "1.5Gi", "1Pi"} {
		size, err := parseSizeFlag(value)
		if err != nil {
			t.Errorf("%s rejected: %v", value, err)
			continue
		}
		if size.Sign() <= 0 {
			t.Errorf("%s parsed as %s", value, size.String())
		}
	}
	for _, tc := range []struct{ value, want string }{
		{"nope", "invalid --size"},
		{"0", "must be positive"},
		{"-1Gi", "must be positive"},
		{"8Ei", "too large"},
		{"10Ei", "too large"},
		{"100Ei", "too large"},
		{"9223372036854775807", "too large"},
		{"9223372036854775808", "too large"},
	} {
		_, err := parseSizeFlag(tc.value)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", tc.value, err, tc.want)
		}
	}
}
