// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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
		// /etc/timezone, /etc/shells, and /usr/lib/os-release are regular
		// files in the dev image; a mount below one poisons the root until
		// it is removed.
		{"/etc/timezone", false},
		{"/etc/timezone/x", false},
		{"/etc/shells", false},
		{"/etc/shells/x", false},
		{"/usr/lib/os-release", false},
		{"/usr/lib/os-release/x", false},
		// The usr-merge spelling reaches the same regular file.
		{"/lib/os-release/x", false},
		// /etc/ld.so.cache and the stable base-system files are regular
		// files in the dev image, so nothing can be mounted at or below
		// them offline.
		{"/etc/ld.so.cache", false},
		{"/etc/ld.so.cache/x", false},
		{"/etc/ld.so.conf/x", false},
		{"/etc/bash.bashrc/x", false},
		{"/etc/environment/x", false},
		{"/etc/profile/x", false},
		{"/etc/inputrc/x", false},
		{"/etc/login.defs/x", false},
		{"/etc/host.conf/x", false},
		{"/etc/gai.conf/x", false},
		// /var/run is the standard alias of /run, so a path below it that
		// resolves into a reserved tree must be rejected offline. The alias
		// itself resolves to /run, an ancestor of /run/blip, and the legal
		// sibling /var/run/x still resolves to an unreserved directory.
		{"/var/run/blip", false},
		{"/var/run/blip/x", false},
		{"/var/run/blip-collect/x", false},
		{"/var/run", false},
		{"/var/lock", true},
		{"/var/lock/x", true},
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
// path that does not fit PATH_MAX (4096 bytes including the terminating NUL)
// once the guest's root prefix is prepended.
func TestValidateLinuxPathLimits(t *testing.T) {
	longComponent := func(n int) string {
		return "/" + strings.Repeat("a", n)
	}
	safeNested := "/" + strings.Repeat("abcdefghij/", 20) + strings.Repeat("c", 255)
	pathAtMax := "/" + strings.Repeat(strings.Repeat("b", NameMax)+"/", 15) + strings.Repeat("b", 243) + "/c"
	if len(pathAtMax) != MaxPath {
		t.Fatalf("test path is %d bytes, want %d", len(pathAtMax), MaxPath)
	}
	if len(pathAtMax)+len(GuestRoot)+1 != PathMax {
		t.Fatalf("guest path with root prefix is %d bytes, want PATH_MAX %d", len(pathAtMax)+len(GuestRoot)+1, PathMax)
	}
	pathOver := pathAtMax + "c"
	componentsAtMax := "/" + strings.Repeat("c/", MaxComponents-1) + "c"
	componentsOver := "/" + strings.Repeat("c/", MaxComponents) + "c"
	for _, tc := range []struct {
		name string
		path string
		ok   bool
	}{
		{"name_max over by one", longComponent(NameMax + 1), false},
		{"300 byte component", longComponent(300), false},
		{"260 byte component", longComponent(260), false},
		{"exact name_max component", longComponent(NameMax), true},
		{"multibyte name_max over", "/" + strings.Repeat("é", 128), false},
		{"multibyte name_max at", "/" + strings.Repeat("é", 127), true},
		{"components at max", componentsAtMax, true},
		{"components over max", componentsOver, false},
		{"path at guest limit", pathAtMax, true},
		{"path over guest limit", pathOver, false},
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

// A path is a NUL-terminated C string in every filesystem syscall, so a
// control character can never name a mount point.
func TestValidateControlCharacters(t *testing.T) {
	for _, p := range []string{"/a\x00b", "/a\tb", "/a\nb", "/a\x7fb"} {
		if err := Validate(p); err == nil {
			t.Errorf("Validate(%q) accepted a control character", p)
		}
	}
	if err := Validate("/a b"); err != nil {
		t.Errorf("Validate(%q) = %v, want space allowed", "/a b", err)
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

// TestOverlapResolvesImageAliases reproduces the alias mounts the guest used to
// stack at one directory because every offline check compared written paths.
func TestOverlapResolvesImageAliases(t *testing.T) {
	for _, tc := range []struct {
		name, a, b string
		want       bool
	}{
		{"usr-merge bin", "/bin/x", "/usr/bin/x", true},
		{"usr-merge sbin", "/sbin/x", "/usr/sbin/x", true},
		{"usr-merge lib", "/lib/x", "/usr/lib/x", true},
		{"usr-merge lib64", "/lib64/x", "/usr/lib64/x", true},
		{"mail spool", "/var/spool/mail/x", "/var/mail/x", true},
		{"nested through alias", "/bin/x/sub", "/usr/bin/x", true},
		{"same alias family but distinct", "/bin/x", "/usr/bin/y", false},
		{"mail alias sibling", "/var/spool/mail/x", "/var/mail/y", false},
		{"plain distinct", "/bin/x", "/usr/sbin/x", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Overlap(tc.a, tc.b); got != tc.want {
				t.Errorf("Overlap(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestResolveAliases(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"/bin/x", "/usr/bin/x"},
		{"/usr/bin/x", "/usr/bin/x"},
		{"/var/spool/mail/x", "/var/mail/x"},
		{"/var/run/blip/x", "/run/blip/x"},
		{"/binomial", "/binomial"},
	} {
		if got := Resolve(tc.in); got != tc.want {
			t.Errorf("Resolve(%q) = %q, want %q", tc.in, got, tc.want)
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
