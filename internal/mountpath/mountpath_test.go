package mountpath

import (
	"strings"
	"testing"
)

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
		// Package-specific directory symlinks shipped in the dev/base image.
		// They are not usr-merge aliases, but the guest still refuses a mount
		// point below them.
		{"/usr/share/doc/gcc", false},
		{"/usr/share/doc/gcc/x", false},
		{"/usr/share/doc/libatomic1/y", false},
		{"/usr/share/doc/git/contrib/hooks/z", false},
		{"/usr/lib/x86_64-linux-gnu/perl/5.38/x", false},
		{"/usr/lib/aarch64-linux-gnu/perl/5.38/x", false},
		// Permanent guest-managed files: they are bind-mounted over the
		// root before any user mount and are not directories.
		{"/etc/hosts", false},
		{"/etc/hosts/x", false},
		{"/etc/resolv.conf", false},
		{"/etc/resolv.conf/x", false},
		// Regular files shipped by the base image are not directories
		// either; an offline mount below them must be rejected.
		{"/etc/passwd", false},
		{"/etc/passwd/x", false},
		{"/etc/group/x", false},
		{"/etc/mtab", false},
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
		{"/usr/share/doc", true},
		{"/usr/share/doc/git", true},
		{"/usr/share/doc/git/contrib", true},
		{"/usr/lib/x86_64-linux-gnu/perl", true},
		{"/etc", true},
		{"/etc/hostname", false},
		{"/etc/hostname.d", true},
		{"/etc/hosts.d", true},
		{"/etc/resolv.conf.d", true},
		{"/etc/passwd.d", true},
		{"/etc/mtab.d", true},
	} {
		err := Validate(tc.path)
		if (err == nil) != tc.ok {
			t.Errorf("Validate(%q) = %v, want ok=%v", tc.path, err, tc.ok)
		}
	}
}

// TestValidateLinuxPathLimits reproduces mounts the CLI accepted offline but
// no Linux guest can create: a component over NAME_MAX (255 bytes) or a full
// path at PATH_MAX (4096 bytes, including the terminating NUL).
func TestValidateLinuxPathLimits(t *testing.T) {
	longComponent := func(n int) string {
		return "/" + strings.Repeat("a", n)
	}
	safeNested := "/" + strings.Repeat("abcdefghij/", 20) + strings.Repeat("c", 255)
	pathAtMax := "/" + strings.Repeat(strings.Repeat("b", NameMax)+"/", 15) + strings.Repeat("b", 253) + "/c"
	if len(pathAtMax) != PathMax {
		t.Fatalf("test path is %d bytes, want PATH_MAX %d", len(pathAtMax), PathMax)
	}
	for _, tc := range []struct {
		name string
		path string
		ok   bool
	}{
		{"name_max over by one", longComponent(NameMax + 1), false},
		{"300 byte component", longComponent(300), false},
		{"260 byte component", longComponent(260), false},
		{"exact name_max component", longComponent(NameMax), true},
		{"path at limit", pathAtMax, false},
		{"safe long nested path", safeNested, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(tc.path)
			if (err == nil) != tc.ok {
				t.Errorf("Validate(%d-byte path) = %v, want ok=%v", len(tc.path), err, tc.ok)
			}
		})
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
