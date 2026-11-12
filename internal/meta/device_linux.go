//go:build linux

package meta

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Device is the guest side of the metadata disk. It bypasses the page cache
// (O_DIRECT) so host updates are visible, falling back to buffered I/O when
// O_DIRECT is unsupported (e.g. tmpfs in tests).
type Device struct {
	f      *os.File
	direct bool
}

// Open opens the metadata block device (or image file) and checks the header.
func Open(path string) (*Device, error) {
	d := &Device{direct: true}
	f, err := os.OpenFile(path, os.O_RDWR|unix.O_DIRECT|unix.O_DSYNC, 0)
	if err != nil {
		d.direct = false
		if f, err = os.OpenFile(path, os.O_RDWR|unix.O_DSYNC, 0); err != nil {
			return nil, err
		}
	}
	d.f = f
	if err := checkHeader(d.read); err != nil {
		f.Close()
		return nil, err
	}
	return d, nil
}

func (d *Device) Close() error { return d.f.Close() }

// alignedBuf returns a zeroed n-byte slice aligned to blockSize.
func alignedBuf(n int) []byte {
	b := make([]byte, n+blockSize)
	off := int(uintptr(unsafe.Pointer(&b[0])) & (blockSize - 1))
	if off != 0 {
		off = blockSize - off
	}
	return b[off : off+n : off+n]
}

// reopenBuffered switches to buffered I/O after an O_DIRECT EINVAL.
func (d *Device) reopenBuffered() error {
	f, err := os.OpenFile(d.f.Name(), os.O_RDWR|unix.O_DSYNC, 0)
	if err != nil {
		return err
	}
	d.f.Close()
	d.f, d.direct = f, false
	return nil
}

func (d *Device) read(off int64, n int) ([]byte, error) {
	b := alignedBuf(n)
	_, err := d.f.ReadAt(b, off)
	if d.direct && errors.Is(err, unix.EINVAL) {
		if err = d.reopenBuffered(); err == nil {
			_, err = d.f.ReadAt(b, off)
		}
	}
	return b, err
}

func (d *Device) write(b []byte, off int64) error {
	a := alignedBuf(len(b))
	copy(a, b)
	_, err := d.f.WriteAt(a, off)
	if d.direct && errors.Is(err, unix.EINVAL) {
		if err = d.reopenBuffered(); err == nil {
			_, err = d.f.WriteAt(a, off)
		}
	}
	if err == nil && !d.direct {
		err = d.f.Sync()
	}
	return err
}

// ReadHost returns the newest valid host slot and its seq.
func (d *Device) ReadHost() (*HostData, uint64, error) { return readHost(d.read) }

// ReadGuest returns the current guest data.
func (d *Device) ReadGuest() (*GuestData, error) { return readGuest(d.read) }

// WriteGuest writes g with seq = previous+1 (g.Seq is updated). Time is set
// to now when zero.
func (d *Device) WriteGuest(g *GuestData) error {
	var prev uint64
	if old, err := d.ReadGuest(); err == nil {
		prev = old.Seq
	}
	g.Seq = prev + 1
	if g.Time.IsZero() {
		g.Time = time.Now().UTC()
	}
	p, err := json.Marshal(g)
	if err != nil {
		return err
	}
	rec, err := encodeRecord(g.Seq, p, MaxGuestPayload)
	if err != nil {
		return err
	}
	return d.write(rec, GuestOffset)
}

// UpdateGuest reads the guest data (empty if none), applies fn and writes it.
func (d *Device) UpdateGuest(fn func(*GuestData)) error {
	g, err := d.ReadGuest()
	if err != nil {
		g = &GuestData{}
	}
	fn(g)
	g.Time = time.Time{}
	return d.WriteGuest(g)
}

// FindBySerial returns /dev/<name> for the first block device in sysBlock
// (normally /sys/block) whose serial equals serial, or "" if none.
func FindBySerial(sysBlock, serial string) string {
	ents, _ := os.ReadDir(sysBlock)
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(sysBlock, e.Name(), "serial"))
		if err == nil && strings.TrimSpace(string(b)) == serial {
			return "/dev/" + e.Name()
		}
	}
	return ""
}

// FindDevice locates the metadata disk via /dev/disk/by-id or /sys/block.
func FindDevice() string {
	p := "/dev/disk/by-id/virtio-" + Serial
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return FindBySerial("/sys/block", Serial)
}
