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

// Aliases are directory symlinks commonly present in the base image. The guest
// resolves them before it checks a mount target, so the preflight must resolve
// them too: /var/run/blip/x reaches the reserved /run/blip/x even though the
// spelling is not lexically reserved. Only well-known system aliases belong
// here; image-specific symlinks cannot be known offline.
var Aliases = []struct{ Path, Target string }{
	{"/var/run", "/run"},
	{"/var/lock", "/run/lock"},
}

// resolveAlias rewrites a path whose first component is a known alias. It does
// not resolve image-specific symlinks, which only the guest can see.
func resolveAlias(p string) string {
	for _, a := range Aliases {
		if p == a.Path {
			return a.Target
		}
		if strings.HasPrefix(p, a.Path+"/") {
			return a.Target + strings.TrimPrefix(p, a.Path)
		}
	}
	return p
}

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

// ValidateLength reports why p is too long or otherwise unusable as a Linux
// filesystem path. Every component must fit NAME_MAX and the whole path must
// leave room for the terminating NUL within PATH_MAX, or no guest can create
// the mount point. ASCII control characters (including NUL) cannot be part of
// a syscall path.
func ValidateLength(p string) error {
	for i := 0; i < len(p); i++ {
		if p[i] < 0x20 || p[i] == 0x7f {
			return fmt.Errorf("mount path contains a control character at byte %d", i)
		}
	}
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
// preflight: image-specific symlinks can only be resolved inside the root, so
// they may still be accepted here. Known system aliases such as /var/run are
// resolved first, and the target is checked against the same rules, because
// the guest follows those symlinks before it validates the mount target.
func Validate(p string) error {
	if err := ValidateLength(p); err != nil {
		return err
	}
	if err := validatePath(p); err != nil {
		return err
	}
	if target := resolveAlias(p); target != p {
		if err := validatePath(target); err != nil {
			return fmt.Errorf("mount path %s resolves to %s: %w", p, target, err)
		}
	}
	return nil
}

// validatePath applies the reserved and non-directory file rules to one path.
func validatePath(p string) error {
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
