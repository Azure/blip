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

// ImageSymlinks are directories that are symlinks in the standard usr-merged
// base images (Debian and Ubuntu). The guest creates mount points without
// following symlinks, so a mount at or below one of these can never attach.
// Custom images may contain other symlinks; the guest still rejects those when
// it creates the mount point.
var ImageSymlinks = []string{"/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/var/lock", "/var/run"}

// Overlap reports whether either path contains the other.
func Overlap(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

// Validate reports why p cannot be a guest mount point, ignoring the guest's
// dynamic check for symlinks that are specific to a custom image.
func Validate(p string) error {
	for _, r := range Reserved {
		if Overlap(p, r) {
			return fmt.Errorf("mount path %s overlaps %s, which the guest reserves", p, r)
		}
	}
	for _, s := range ImageSymlinks {
		if p == s {
			return fmt.Errorf("mount path %s is a symlink in the image; choose a real directory", p)
		}
		if Overlap(p, s) {
			return fmt.Errorf("mount path %s is below %s, which is a symlink in the image; choose a real directory", p, s)
		}
	}
	return nil
}
