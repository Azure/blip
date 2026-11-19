package mountpath

import "testing"

func TestValidate(t *testing.T) {
	for _, tc := range []struct {
		path string
		ok   bool
	}{
		{"/proc", false},
		{"/proc/x", false},
		{"/sys", false},
		{"/dev/x", false},
		{"/run/blip", false},
		{"/run/blip/x", false},
		{"/lib64", false},
		{"/lib64/x", false},
		{"/bin/x", false},
		{"/var/run/x", false},
		{"/run/data", true},
		{"/procdata", true},
		{"/lib64x", true},
		{"/data", true},
		{"/data/sub", true},
	} {
		err := Validate(tc.path)
		if (err == nil) != tc.ok {
			t.Errorf("Validate(%q) = %v, want ok=%v", tc.path, err, tc.ok)
		}
	}
}

func TestOverlap(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"/data", "/data", true},
		{"/data", "/data/sub", true},
		{"/data/sub", "/data", true},
		{"/data", "/data2", false},
		{"/proc", "/procdata", false},
	} {
		if got := Overlap(tc.a, tc.b); got != tc.want {
			t.Errorf("Overlap(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}
