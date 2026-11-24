// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package storage

import (
	"errors"
	"fmt"
	"os"

	"github.com/Azure/blip/internal/stream"
	"golang.org/x/sys/unix"
)

// resetStream clears a state's trajectory ring on a writable plaintext device.
// It discards the whole ring, not just the header: a rewritten header would
// leave the source's records in the data area, where writer recovery could
// mistake them for records written by the copy.
func resetStream(dev string, size int64) (err error) {
	if size < stream.MinSize || size > stream.MaxSize || size%stream.SlotSize != 0 {
		return fmt.Errorf("storage: invalid stream size %d", size)
	}
	f, err := os.OpenFile(dev, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	err = blkDiscard(f, stream.Offset, size)
	if err != nil {
		// Discard is not supported on every backing device. Fall back to
		// writing zeroes there; other errors should fail the copy rather than
		// allocate a full ring of exceptions.
		if !errors.Is(err, unix.EOPNOTSUPP) && !errors.Is(err, unix.ENOTTY) && !errors.Is(err, unix.EINVAL) {
			return err
		}
		if err := zeroRing(f, size); err != nil {
			return err
		}
	} else {
		// dm-thin can complete a discard without clearing when the pool is
		// out of metadata space. Verify the header instead of publishing a
		// copied ring.
		header := make([]byte, stream.HeaderSize)
		if _, err := f.ReadAt(header, stream.Offset); err != nil {
			return err
		}
		for _, b := range header {
			if b != 0 {
				if err := zeroRing(f, size); err != nil {
					return err
				}
				break
			}
		}
	}
	return f.Sync()
}

func zeroRing(f *os.File, size int64) error {
	zero := make([]byte, 1<<20)
	for off := int64(0); off < size; off += int64(len(zero)) {
		n := min(int64(len(zero)), size-off)
		written, err := f.WriteAt(zero[:n], stream.Offset+off)
		if err != nil {
			return err
		}
		if int64(written) != n {
			return fmt.Errorf("storage: short write resetting stream on %s", f.Name())
		}
	}
	return nil
}
