// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Package devnode creates device nodes below /dev from sysfs device numbers.
package devnode

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Parse parses a sysfs "major:minor" device number into a device number.
func Parse(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	major, minor, ok := strings.Cut(s, ":")
	if !ok {
		return 0, fmt.Errorf("bad device number %q", s)
	}
	ma, err1 := strconv.ParseUint(major, 10, 32)
	mi, err2 := strconv.ParseUint(minor, 10, 32)
	if err1 != nil || err2 != nil {
		return 0, fmt.Errorf("bad device number %q", s)
	}
	return unix.Mkdev(uint32(ma), uint32(mi)), nil
}

// Ensure makes path a block device node for rdev. It replaces an existing node
// with a different type or device number.
func Ensure(path string, rdev uint64) error { return ensure(path, rdev, unix.S_IFBLK) }

// EnsureChar makes path a character device node for rdev.
func EnsureChar(path string, rdev uint64) error { return ensure(path, rdev, unix.S_IFCHR) }

func ensure(path string, rdev uint64, mode uint32) error {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err == nil {
		if st.Rdev == rdev && st.Mode&unix.S_IFMT == mode {
			return nil
		}
		os.Remove(path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := unix.Mknod(path, mode|0o600, int(rdev)); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("mknod %s: %w", path, err)
	}
	return nil
}
