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
		{"/var/spool/mail", false},
		{"/var/spool/mail/x", false},
		{"/usr/local/man", false},
		{"/usr/local/man/x", false},
		{"/usr/lib/ssl/certs", false},
		{"/usr/lib/ssl/certs/x", false},
		{"/usr/lib/ssl/private/x", false},
		{"/usr/share/perl/5.38/x", false},
		{"/run/data", true},
		{"/procdata", true},
		{"/lib64x", true},
		{"/data", true},
		{"/data/sub", true},
		// Real directories and prefix-sharing paths the guest accepts must
		// stay legal; only exact base-image symlinks are rejected.
		{"/var/mail", true},
		{"/var/spool/maillog", true},
		{"/usr/local/manual", true},
		{"/usr/lib/ssl", true},
		{"/usr/share/perl/5.40", true},
		{"/usr/share/doc/example", true},
		// Ancestors of a symlink are real directories the guest can create
		// or mount over; only the symlink itself and its descendants fail.
		{"/var/spool", true},
		{"/usr/local", true},
		{"/usr/share/perl", true},
		{"/usr/share", true},
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
