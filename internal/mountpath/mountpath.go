// Package mountpath holds mount-point rules shared by the command-line
// preflight and the guest, so a mount the guest cannot create is rejected
// before it becomes durable intent.
package mountpath

import (
	"fmt"
	"strings"
)

// CollectRoot is where collect mounts a worker's state inside the calling
// blip. It is reserved so a user mount cannot shadow the paths collect
// generates for itself.
const CollectRoot = "/run/blip-collect"

// Reserved paths are mounted by the guest itself inside the root. A user mount
// must not be at, below, or above one of them.
var Reserved = []string{"/proc", "/sys", "/dev", "/run/blip", CollectRoot}

const (
	// NameMax is the maximum length in bytes of one Linux path component.
	NameMax = 255
	// PathMax is Linux PATH_MAX (4096 bytes) including the terminating NUL,
	// so the longest usable path string is PathMax-1 bytes.
	PathMax = 4096
)

// GuestFiles are the regular files the guest bind-mounts over the durable
// root before a user command runs. A filesystem mount point must be a
// directory, so these exact files and anything below them can never attach.
// The ancestor directory /etc stays legal.
var GuestFiles = []string{"/etc/hosts", "/etc/resolv.conf"}

// ImageFiles are non-directories that every base image ships, including
// symlinks to regular files. Like GuestFiles, they cannot be a filesystem
// mount point or one of its ancestors, so an offline mount below one would
// poison the root on its next execution.
//
// Directory symlinks are deliberately absent: the guest resolves each mount
// path component and allows a symlink whose target is a directory inside the
// root, so image aliases such as /bin -> usr/bin and the per-package
// /usr/share/doc entries need no hardcoded list here.
var ImageFiles = []string{
	"/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow",
	"/etc/hostname", "/etc/hostid", "/etc/machine-id",
	"/etc/os-release", "/etc/debian_version", "/etc/nsswitch.conf",
	"/etc/subuid", "/etc/subgid",
	// /etc/mtab is a symlink to the proc mount table.
	"/etc/mtab",
}

// Overlap reports whether either path contains the other.
func Overlap(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

// CollectMountPath reports whether p is exactly one mount below CollectRoot.
// The command-line collect creates these paths itself, so the guest accepts
// them although the collect root is otherwise reserved.
func CollectMountPath(p string) bool {
	rest, ok := strings.CutPrefix(p, CollectRoot+"/")
	return ok && rest != "" && !strings.Contains(rest, "/")
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

// Validate reports why p cannot be a guest mount point. It is a lexical
// preflight: the guest additionally resolves symlinks inside the root, so an
// image directory alias can still be accepted here without an image-specific
// list of symlinks.
func Validate(p string) error {
	if err := ValidateLength(p); err != nil {
		return err
	}
	for _, r := range Reserved {
		if Overlap(p, r) {
			return fmt.Errorf("mount path %s overlaps %s, which the guest reserves", p, r)
		}
	}
	for _, f := range GuestFiles {
		if p == f {
			return fmt.Errorf("mount path %s is a guest-managed file; choose a directory", p)
		}
		if strings.HasPrefix(p, f+"/") {
			return fmt.Errorf("mount path %s is below %s, which is a guest-managed file; choose a directory", p, f)
		}
	}
	for _, f := range ImageFiles {
		if p == f {
			return fmt.Errorf("mount path %s is a file in the base image; choose a directory", p)
		}
		if strings.HasPrefix(p, f+"/") {
			return fmt.Errorf("mount path %s is below %s, which is a file in the base image; choose a directory", p, f)
		}
	}
	return nil
}
