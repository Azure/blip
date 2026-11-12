// Package extent copies byte ranges between block devices with direct I/O
// and hashes devices per block for scrub.
package extent

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"

	"golang.org/x/sys/unix"
)

// Align is the required alignment of offsets and lengths.
const Align = 4096

const bufSize = 1 << 20

// Range is a byte range.
type Range struct {
	Off, Len int64
}

// Total returns the number of bytes in rs.
func Total(rs []Range) int64 {
	var n int64
	for _, r := range rs {
		n += r.Len
	}
	return n
}

// Normalize sorts and merges overlapping or adjacent ranges and drops
// empty ones.
func Normalize(rs []Range) []Range {
	c := make([]Range, 0, len(rs))
	for _, r := range rs {
		if r.Len > 0 {
			c = append(c, r)
		}
	}
	sort.Slice(c, func(i, j int) bool { return c[i].Off < c[j].Off })
	var out []Range
	for _, r := range c {
		if n := len(out); n > 0 && out[n-1].Off+out[n-1].Len >= r.Off {
			if end := r.Off + r.Len; end > out[n-1].Off+out[n-1].Len {
				out[n-1].Len = end - out[n-1].Off
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

func check(rs []Range) error {
	for _, r := range rs {
		if r.Off < 0 || r.Len < 0 || r.Off%Align != 0 || r.Len%Align != 0 {
			return fmt.Errorf("range %d+%d is not %d-byte aligned", r.Off, r.Len, Align)
		}
	}
	return nil
}

func alignedBuf() ([]byte, func(), error) {
	b, err := unix.Mmap(-1, 0, bufSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		return nil, nil, err
	}
	return b, func() { _ = unix.Munmap(b) }, nil
}

func openDirect(path string, flag int) (*os.File, int64, error) {
	f, err := os.OpenFile(path, flag|unix.O_DIRECT, 0)
	if err != nil {
		return nil, 0, err
	}
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	return f, size, nil
}

// clamp cuts ranges at size.
func clamp(rs []Range, size int64) []Range {
	var out []Range
	for _, r := range rs {
		if r.Off >= size {
			continue
		}
		if r.Off+r.Len > size {
			r.Len = size - r.Off
		}
		out = append(out, r)
	}
	return out
}

// Copy copies ranges from src to dst at the same offsets, then flushes
// dst. Ranges past the end of either device are cut.
func Copy(ctx context.Context, src, dst string, rs []Range) error {
	if err := check(rs); err != nil {
		return err
	}
	in, inSize, err := openDirect(src, os.O_RDONLY)
	if err != nil {
		return err
	}
	defer in.Close()
	out, outSize, err := openDirect(dst, os.O_WRONLY)
	if err != nil {
		return err
	}
	defer out.Close()
	buf, free, err := alignedBuf()
	if err != nil {
		return err
	}
	defer free()
	for _, r := range clamp(clamp(Normalize(rs), inSize), outSize) {
		for off := r.Off; off < r.Off+r.Len; {
			if err := ctx.Err(); err != nil {
				return err
			}
			n := min(int64(bufSize), r.Off+r.Len-off)
			if _, err := in.ReadAt(buf[:n], off); err != nil {
				return fmt.Errorf("read %s at %d: %w", src, off, err)
			}
			if _, err := out.WriteAt(buf[:n], off); err != nil {
				return fmt.Errorf("write %s at %d: %w", dst, off, err)
			}
			off += n
		}
	}
	if err := out.Sync(); err != nil {
		return fmt.Errorf("flush %s: %w", dst, err)
	}
	return out.Close()
}

// Zero writes zeros over ranges of dst, then flushes it.
func Zero(ctx context.Context, dst string, rs []Range) error {
	if err := check(rs); err != nil {
		return err
	}
	out, size, err := openDirect(dst, os.O_WRONLY)
	if err != nil {
		return err
	}
	defer out.Close()
	buf, free, err := alignedBuf()
	if err != nil {
		return err
	}
	defer free()
	for _, r := range clamp(Normalize(rs), size) {
		for off := r.Off; off < r.Off+r.Len; {
			if err := ctx.Err(); err != nil {
				return err
			}
			n := min(int64(bufSize), r.Off+r.Len-off)
			if _, err := out.WriteAt(buf[:n], off); err != nil {
				return fmt.Errorf("write %s at %d: %w", dst, off, err)
			}
			off += n
		}
	}
	if err := out.Sync(); err != nil {
		return fmt.Errorf("flush %s: %w", dst, err)
	}
	return out.Close()
}

// Hashes holds one SHA-256 per block of a device.
type Hashes struct {
	BlockSize int64
	Size      int64
	Sums      [][32]byte
}

// Hash reads the whole device with direct I/O and hashes each block.
func Hash(ctx context.Context, dev string, blockSize int64) (Hashes, error) {
	if blockSize <= 0 || blockSize%Align != 0 || bufSize%blockSize != 0 {
		return Hashes{}, fmt.Errorf("bad block size %d", blockSize)
	}
	f, size, err := openDirect(dev, os.O_RDONLY)
	if err != nil {
		return Hashes{}, err
	}
	defer f.Close()
	buf, free, err := alignedBuf()
	if err != nil {
		return Hashes{}, err
	}
	defer free()
	h := Hashes{BlockSize: blockSize, Size: size}
	for off := int64(0); off < size; {
		if err := ctx.Err(); err != nil {
			return Hashes{}, err
		}
		n := min(int64(bufSize), size-off)
		// Direct I/O needs aligned lengths; device sizes are 512-byte
		// multiples, so round the read up and use only n bytes.
		rd := (n + Align - 1) / Align * Align
		got, err := f.ReadAt(buf[:rd], off)
		if err != nil && !(errors.Is(err, io.EOF) && int64(got) >= n) {
			return Hashes{}, fmt.Errorf("read %s at %d: %w", dev, off, err)
		}
		for b := int64(0); b < n; b += blockSize {
			e := min(b+blockSize, n)
			h.Sums = append(h.Sums, sha256.Sum256(buf[b:e]))
		}
		off += n
	}
	return h, nil
}

// Diff returns the indexes of blocks that differ between a and b. Blocks
// present in only one of them count as different.
func Diff(a, b Hashes) []int64 {
	var out []int64
	n := max(len(a.Sums), len(b.Sums))
	for i := 0; i < n; i++ {
		if i >= len(a.Sums) || i >= len(b.Sums) || a.Sums[i] != b.Sums[i] {
			out = append(out, int64(i))
		}
	}
	return out
}

// Sum returns one SHA-256 over all block sums, for quick comparison.
func (h Hashes) Sum() [32]byte {
	d := sha256.New()
	for _, s := range h.Sums {
		d.Write(s[:])
	}
	var out [32]byte
	copy(out[:], d.Sum(nil))
	return out
}
