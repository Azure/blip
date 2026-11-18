package main

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// writableSysfs remounts /sys read-write in this container's mount
// namespace. Some runtimes (kind) mount it read-only even for privileged
// containers, and disconnecting NVMe controllers writes to sysfs.
func writableSysfs() error {
	var st unix.Statfs_t
	if err := unix.Statfs("/sys", &st); err != nil {
		return err
	}
	if st.Flags&unix.ST_RDONLY == 0 {
		return nil
	}
	flags := uintptr(unix.MS_REMOUNT | unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC | unix.MS_RELATIME)
	if err := unix.Mount("", "/sys", "", flags, ""); err != nil {
		return fmt.Errorf("remount /sys read-write: %w", err)
	}
	return nil
}
