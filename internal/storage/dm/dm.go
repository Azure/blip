// Package dm drives device-mapper through dmsetup, without udev.
//
// Tables refer to devices by "major:minor", so no device nodes are needed
// to build them. Callers that need a node for I/O use package devnode.
package dm

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/example/blip/internal/storage/devnode"
	"github.com/example/blip/internal/storage/run"
)

// Info describes one device-mapper device.
type Info struct {
	Name      string
	UUID      string
	Dev       devnode.Dev
	Open      int
	Suspended bool
	ReadOnly  bool
}

func dmsetup(ctx context.Context, args ...string) ([]byte, error) {
	return run.Cmd(ctx, nil, "dmsetup", args...)
}

// ErrNotFound is returned for a missing device.
var ErrNotFound = errors.New("device-mapper device not found")

func isMissing(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "No such device or address") || strings.Contains(s, "does not exist")
}

const infoFields = "name,uuid,major,minor,open,attr"

// Get returns the device, or ErrNotFound.
func Get(ctx context.Context, name string) (Info, error) {
	out, err := dmsetup(ctx, "info", "-c", "--noheadings", "--separator", "|", "-o", infoFields, name)
	if isMissing(err) {
		return Info{}, ErrNotFound
	}
	if err != nil {
		return Info{}, err
	}
	infos, err := parseInfo(string(out))
	if err != nil {
		return Info{}, err
	}
	if len(infos) != 1 {
		return Info{}, ErrNotFound
	}
	return infos[0], nil
}

// List returns all devices whose name starts with prefix. dmsetup lists
// the names first and then queries each device, so it fails when any
// device of the host is removed meanwhile (other nodes share the kernel);
// List retries then.
func List(ctx context.Context, prefix string) ([]Info, error) {
	var out []byte
	var err error
	for i := 0; ; i++ {
		out, err = dmsetup(ctx, "info", "-c", "--noheadings", "--separator", "|", "-o", infoFields)
		if err == nil || !isMissing(err) || i == 20 {
			break
		}
		select {
		case <-ctx.Done():
			return nil, err
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err != nil {
		if strings.Contains(err.Error(), "No devices found") {
			return nil, nil
		}
		return nil, err
	}
	all, err := parseInfo(string(out))
	if err != nil {
		return nil, err
	}
	var res []Info
	for _, i := range all {
		if strings.HasPrefix(i.Name, prefix) {
			res = append(res, i)
		}
	}
	return res, nil
}

func parseInfo(out string) ([]Info, error) {
	var res []Info
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || l == "No devices found" {
			continue
		}
		f := strings.Split(l, "|")
		if len(f) != 6 {
			return nil, fmt.Errorf("dmsetup info: bad line %q", l)
		}
		ma, err1 := strconv.ParseUint(f[2], 10, 32)
		mi, err2 := strconv.ParseUint(f[3], 10, 32)
		open, err3 := strconv.Atoi(f[4])
		if err1 != nil || err2 != nil || err3 != nil {
			return nil, fmt.Errorf("dmsetup info: bad line %q", l)
		}
		// attr is like "L--w": L live, s suspended, r read-only, w writable.
		attr := f[5]
		res = append(res, Info{
			Name: f[0], UUID: f[1], Dev: devnode.Dev{Major: uint32(ma), Minor: uint32(mi)},
			Open: open, Suspended: strings.Contains(attr, "s"), ReadOnly: strings.Contains(attr, "r"),
		})
	}
	return res, nil
}

// Create creates a device unless one with this name exists. An existing
// device with another uuid is an error. The table of an existing device is
// not changed.
func Create(ctx context.Context, name, uuid, table string, readOnly bool) (Info, error) {
	if i, err := Get(ctx, name); err == nil {
		if i.UUID != uuid {
			return Info{}, fmt.Errorf("device %s exists with uuid %q, want %q", name, i.UUID, uuid)
		}
		return i, nil
	} else if !errors.Is(err, ErrNotFound) {
		return Info{}, err
	}
	args := []string{"create", name, "--uuid", uuid, "--table", table}
	if readOnly {
		args = append(args, "--readonly")
	}
	if _, err := dmsetup(ctx, args...); err != nil {
		return Info{}, err
	}
	return Get(ctx, name)
}

// Table returns the live table.
func Table(ctx context.Context, name string) (string, error) {
	out, err := dmsetup(ctx, "table", name)
	if isMissing(err) {
		return "", ErrNotFound
	}
	return strings.TrimSpace(string(out)), err
}

// InactiveTable returns the loaded, not yet live table, or "".
func InactiveTable(ctx context.Context, name string) (string, error) {
	out, err := dmsetup(ctx, "table", "--inactive", name)
	if isMissing(err) {
		return "", ErrNotFound
	}
	return strings.TrimSpace(string(out)), err
}

// Clear drops the inactive table. Load followed by a crash leaves one,
// and it keeps the devices it maps open.
func Clear(ctx context.Context, name string) error {
	_, err := dmsetup(ctx, "clear", name)
	return err
}

// Status returns the status line(s).
func Status(ctx context.Context, name string) (string, error) {
	out, err := dmsetup(ctx, "status", name)
	if isMissing(err) {
		return "", ErrNotFound
	}
	return strings.TrimSpace(string(out)), err
}

// Suspend suspends a device. With noFlush, queued I/O is not flushed.
func Suspend(ctx context.Context, name string, noFlush bool) error {
	args := []string{"suspend", name}
	if noFlush {
		args = append(args, "--noflush")
	}
	_, err := dmsetup(ctx, args...)
	return err
}

// Resume resumes a device and makes a loaded table live.
func Resume(ctx context.Context, name string) error {
	_, err := dmsetup(ctx, "resume", name)
	return err
}

// Load loads an inactive table.
func Load(ctx context.Context, name, table string) error {
	_, err := dmsetup(ctx, "load", name, "--table", table)
	return err
}

// Reload replaces the live table: load, suspend (with flush), resume. If
// the live table already equals table, nothing happens.
func Reload(ctx context.Context, name, table string) error {
	if cur, err := Table(ctx, name); err == nil && cur == table {
		return nil
	}
	if err := Load(ctx, name, table); err != nil {
		return err
	}
	if err := Suspend(ctx, name, false); err != nil {
		// The device may be suspended anyway (for example a timed out
		// dmsetup): drop the new table and resume with the old one.
		_ = Clear(ctx, name)
		_ = Resume(ctx, name)
		return err
	}
	// A device left suspended blocks every opener (udev included) and
	// cannot be removed: try a few times.
	var err error
	for try := 0; try < 3; try++ {
		if err = Resume(ctx, name); err == nil {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return err
}

// Message sends a target message to sector 0.
func Message(ctx context.Context, name, msg string) error {
	_, err := dmsetup(ctx, append([]string{"message", name, "0"}, strings.Fields(msg)...)...)
	return err
}

// Remove removes a device. A missing device is not an error. Busy devices
// are retried for up to 10 seconds: udev probes new devices, and a probe
// of a thin device whose external origin has a failing path can take
// seconds.
func Remove(ctx context.Context, name string) error {
	var err error
	for i := 0; i < 100; i++ {
		_, err = dmsetup(ctx, "remove", name)
		if err == nil || isMissing(err) {
			return nil
		}
		if !strings.Contains(err.Error(), "busy") {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(100 * time.Millisecond):
		}
	}
	return err
}

// Tables. Sizes are in 512-byte sectors.

// LinearTable maps the device onto dev starting at offset.
func LinearTable(sectors int64, dev devnode.Dev, offset int64) string {
	return fmt.Sprintf("0 %d linear %s %d", sectors, dev, offset)
}

// ErrorTable fails every I/O.
func ErrorTable(sectors int64) string {
	return fmt.Sprintf("0 %d error", sectors)
}

// MultipathTable builds one priority group over paths with round-robin.
// NVMe namespace heads are bio-based, so the table needs
// "queue_mode bio". queue_if_no_path is not set, so I/O fails when every
// path has failed.
func MultipathTable(sectors int64, paths []devnode.Dev) string {
	var b strings.Builder
	fmt.Fprintf(&b, "0 %d multipath 2 queue_mode bio 0 1 1 round-robin 0 %d 1", sectors, len(paths))
	for _, p := range paths {
		fmt.Fprintf(&b, " %s 1000", p)
	}
	return b.String()
}

// ThinPoolTable builds a thin-pool with ignore_discard and
// error_if_no_space. blockSectors is the thin block size (128 = 64KiB).
func ThinPoolTable(dataSectors int64, meta, data devnode.Dev, blockSectors int) string {
	return fmt.Sprintf("0 %d thin-pool %s %s %d 0 2 ignore_discard error_if_no_space", dataSectors, meta, data, blockSectors)
}

// ThinTable maps thin device id of pool. origin, if not nil, is the
// external origin that serves reads of unmapped blocks.
func ThinTable(sectors int64, pool devnode.Dev, id uint32, origin *devnode.Dev) string {
	t := fmt.Sprintf("0 %d thin %s %d", sectors, pool, id)
	if origin != nil {
		t += " " + origin.String()
	}
	return t
}

// MultipathPath is the state of one path in a multipath status line.
type MultipathPath struct {
	Dev    devnode.Dev
	Active bool
}

// ParseMultipathStatus reads path states from a multipath status line
// such as "0 524288 multipath 2 0 0 0 1 1 A 0 3 0 259:15 A 0 259:17 F 1".
func ParseMultipathStatus(s string) ([]MultipathPath, error) {
	var out []MultipathPath
	fs := strings.Fields(s)
	for i := 0; i+1 < len(fs); i++ {
		if !strings.Contains(fs[i], ":") {
			continue
		}
		d, err := devnode.Parse(fs[i])
		if err != nil {
			continue
		}
		st := fs[i+1]
		if st != "A" && st != "F" {
			continue
		}
		out = append(out, MultipathPath{Dev: d, Active: st == "A"})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no paths in multipath status %q", s)
	}
	return out, nil
}

// ReinstatePath marks a failed path active again. Without multipathd,
// failed paths stay failed until reinstated.
func ReinstatePath(ctx context.Context, name string, dev devnode.Dev) error {
	return Message(ctx, name, "reinstate_path "+dev.String())
}
