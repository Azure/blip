// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package storage

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"golang.org/x/sys/unix"
)

func mkfsExt4(ctx context.Context, dev string, fsBytes int64) error {
	blocks := fsBytes / 4096
	if blocks <= 0 {
		return fmt.Errorf("storage: invalid filesystem size %d", fsBytes)
	}
	_, err := runInContext(ctx, "", nil, "mkfs.ext4", "-q", "-F", "-m", "0", "-b", "4096",
		"-E", "nodiscard,lazy_itable_init=1,lazy_journal_init=1", dev, strconv.FormatInt(blocks, 10))
	return err
}

// fixedTimeEnv sets the clock of e2fsprogs tools so the timestamps they
// write are the same on every node (image.MakeFS uses the same clock). It
// must be after 2010, or e2fsck treats the clock as broken.
// E2FSPROGS_FAKE_TIME, unlike SOURCE_DATE_EPOCH, does not clamp file times.
var fixedTimeEnv = []string{"E2FSPROGS_FAKE_TIME=1735689600", "E2FSCK_TIME=1735689600"}

// growExt4 grows the filesystem on dev to fsBytes. With reproducible set, the
// result depends only on the input bytes and the filesystem size.
func growExt4(ctx context.Context, dev string, fsBytes int64, reproducible bool) error {
	blocks := fsBytes / 4096
	if blocks <= 0 {
		return fmt.Errorf("storage: invalid filesystem size %d", fsBytes)
	}
	var env []string
	if reproducible {
		env = fixedTimeEnv
	}
	if _, err := runInContext(ctx, "", env, "e2fsck", "-f", "-y", dev); err != nil {
		var ee *exec.ExitError
		// 1 and 2 mean errors were corrected.
		if !errors.As(err, &ee) || ee.ExitCode() > 2 {
			return err
		}
	}
	_, err := runInContext(ctx, "", env, "resize2fs", dev, strconv.FormatInt(blocks, 10))
	return err
}

// ext4NeedsRecovery reads the superblock with O_DIRECT (bypassing any page
// cache this process may hold) and reports the needs_recovery flag.
func ext4NeedsRecovery(dev string) (bool, error) {
	f, err := os.OpenFile(dev, os.O_RDONLY|unix.O_DIRECT, 0)
	if err != nil {
		return false, err
	}
	defer f.Close()
	buf, err := unix.Mmap(-1, 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		return false, err
	}
	defer unix.Munmap(buf)
	if _, err := f.ReadAt(buf, 0); err != nil {
		return false, err
	}
	sb := buf[1024:]
	if binary.LittleEndian.Uint16(sb[0x38:]) != 0xEF53 {
		return false, fmt.Errorf("%s: no ext4 superblock", dev)
	}
	const incompatRecover = 0x4
	return binary.LittleEndian.Uint32(sb[0x60:])&incompatRecover != 0, nil
}

func flushDevice(dev string) error {
	f, err := os.OpenFile(dev, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
