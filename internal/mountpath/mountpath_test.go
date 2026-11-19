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
		{"/run/blip-collect", false},
		{"/run/blip-collect/x", false},
		// Permanent guest-managed files: they are bind-mounted over the
		// root before any user mount and are not directories.
		{"/etc/hosts", false},
		{"/etc/hosts/x", false},
		{"/etc/resolv.conf", false},
		{"/etc/resolv.conf/x", false},
		// Non-directories shipped by the base image are not mount points
		// either; an offline mount below them must be rejected.
		{"/etc/passwd", false},
		{"/etc/passwd/x", false},
		{"/etc/group/x", false},
		{"/etc/mtab", false},
		{"/etc/mtab/x", false},
		{"/etc/os-release/x", false},
		{"/etc/hostname", false},
		{"/run/data", true},
		{"/run/blip-collector", true},
		{"/procdata", true},
		{"/lib64x", true},
		{"/data", true},
		{"/data/sub", true},
		// Directory symlinks in the base image are legal mount points: the
		// guest resolves them inside the root, as Linux mount does. This
		// includes usr-merge aliases and image-specific package aliases
		// such as the dev image's /usr/share/doc/gcc-13.
		{"/lib64", true},
		{"/lib64/x", true},
		{"/bin/x", true},
		{"/var/run/x", true},
		{"/var/spool/mail", true},
		{"/var/spool/mail/x", true},
		{"/usr/local/man", true},
		{"/usr/local/man/x", true},
		{"/usr/lib/ssl/certs", true},
		{"/usr/lib/ssl/certs/x", true},
		{"/usr/lib/ssl/private/x", true},
		{"/usr/share/perl/5.38/x", true},
		{"/usr/share/doc/gcc", true},
		{"/usr/share/doc/gcc/x", true},
		{"/usr/share/doc/libatomic1/y", true},
		{"/usr/share/doc/git/contrib/hooks/z", true},
		{"/usr/share/doc/gcc-13/probe", true},
		{"/usr/lib/x86_64-linux-gnu/perl/5.38/x", true},
		{"/usr/lib/aarch64-linux-gnu/perl/5.38/x", true},
		// Real directories and prefix-sharing paths stay legal too.
		{"/var/mail", true},
		{"/var/spool/maillog", true},
		{"/usr/local/manual", true},
		{"/usr/lib/ssl", true},
		{"/usr/share/perl/5.40", true},
		{"/usr/share/doc/example", true},
		// Ancestors of an image symlink are real directories the guest can
		// create or mount over; they stay legal.
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

func TestCollectMountPath(t *testing.T) {
	for _, tc := range []struct {
		path string
		want bool
	}{
		{CollectRoot, false},
		{CollectRoot + "/data", true},
		{CollectRoot + "/data/sub", false},
		{CollectRoot + "x/data", false},
		{"/data", false},
	} {
		if got := CollectMountPath(tc.path); got != tc.want {
			t.Errorf("CollectMountPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}
