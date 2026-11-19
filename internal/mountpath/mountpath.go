// Package mountpath holds mount-point rules shared by the command-line
// preflight and the guest, so a mount the guest cannot create is rejected
// before it becomes durable intent.
package mountpath

import (
	"fmt"
	"strings"
)

// Reserved paths are mounted by the guest itself inside the root. A user mount
// must not be at, below, or above one of them.
var Reserved = []string{"/proc", "/sys", "/dev", "/run/blip"}

const (
	// NameMax is the maximum length in bytes of one Linux path component.
	NameMax = 255
	// PathMax is Linux PATH_MAX (4096 bytes) including the terminating NUL,
	// so the longest usable path string is PathMax-1 bytes.
	PathMax = 4096
)

// ImageSymlinks are directories that are symlinks in the standard usr-merged
// base images (Debian and Ubuntu) and in the development image. The guest
// creates mount points without following symlinks, so a mount at or below one
// of these can never attach. Only these exact paths and their descendants are
// rejected: real directories and prefix-sharing names stay legal.
//
// The list includes the package-specific directory symlinks shipped by the
// dev/base image (ubuntu:24.04 with build-essential, git and python3) in
// addition to the usr-merge aliases. Those aliases change with the packaged
// versions and packages, so an image-specific symlink that is not listed here
// is still rejected by the guest when it creates the mount point; a live mount
// also rolls back its newly written intent instead of leaving the root
// unstartable (see cli.mountState).
var ImageSymlinks = []string{
	"/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32",
	"/var/lock", "/var/run", "/var/spool/mail",
	"/usr/local/man", "/usr/lib/ssl/certs", "/usr/lib/ssl/private",
	"/usr/share/perl/5.38",
	// Versioned perl tree; the triplet differs by architecture.
	"/usr/lib/x86_64-linux-gnu/perl/5.38", "/usr/lib/aarch64-linux-gnu/perl/5.38",
	// Per-package documentation aliases in the base image.
	"/usr/share/doc/gcc", "/usr/share/doc/libatomic1",
	"/usr/share/doc/git/contrib/hooks",
}

// Overlap reports whether either path contains the other.
func Overlap(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

// ValidateLength reports why p is too long for a Linux filesystem. Every
// component must fit NAME_MAX and the whole path must leave room for the
// terminating NUL within PATH_MAX, or no guest can create the mount point.
func ValidateLength(p string) error {
	if len(p) >= PathMax {
		return fmt.Errorf("mount path is %d bytes, exceeding the Linux PATH_MAX limit of %d bytes", len(p), PathMax-1)
	}
	for _, c := range strings.Split(p, "/") {
		if len(c) > NameMax {
			return fmt.Errorf("mount path has a %d-byte component, exceeding the Linux NAME_MAX limit of %d bytes", len(c), NameMax)
		}
	}
	return nil
}

// Validate reports why p cannot be a guest mount point, ignoring the guest's
// dynamic check for symlinks that are specific to a custom image.
func Validate(p string) error {
	if err := ValidateLength(p); err != nil {
		return err
	}
	for _, r := range Reserved {
		if Overlap(p, r) {
			return fmt.Errorf("mount path %s overlaps %s, which the guest reserves", p, r)
		}
	}
	for _, s := range ImageSymlinks {
		if p == s {
			return fmt.Errorf("mount path %s is a symlink in the image; choose a real directory", p)
		}
		if strings.HasPrefix(p, s+"/") {
			return fmt.Errorf("mount path %s is below %s, which is a symlink in the image; choose a real directory", p, s)
		}
	}
	return nil
}
