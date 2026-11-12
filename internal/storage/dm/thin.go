package dm

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"

	"github.com/example/blip/internal/storage/run"
)

// BlockRange is a run of thin blocks.
type BlockRange struct {
	Begin, Length uint64
}

// ErrExists is returned when a thin ID already exists in a pool.
var ErrExists = errors.New("thin device id already exists")

// CreateThinID creates thin device id in pool.
func CreateThinID(ctx context.Context, pool string, id uint32) error {
	err := Message(ctx, pool, fmt.Sprintf("create_thin %d", id))
	if err != nil && strings.Contains(err.Error(), "File exists") {
		return ErrExists
	}
	return err
}

// CreateSnapID creates thin device id in pool as a snapshot of origin. If
// origin is active, it must be suspended.
func CreateSnapID(ctx context.Context, pool string, id, origin uint32) error {
	err := Message(ctx, pool, fmt.Sprintf("create_snap %d %d", id, origin))
	if err != nil && strings.Contains(err.Error(), "File exists") {
		return ErrExists
	}
	return err
}

// MaxThinID is the largest thin device ID (thin IDs are 24-bit).
const MaxThinID = 1<<24 - 1

// DeleteThinID deletes thin device id. A missing id is not an error.
func DeleteThinID(ctx context.Context, pool string, id uint32) error {
	err := Message(ctx, pool, fmt.Sprintf("delete %d", id))
	if err != nil && (strings.Contains(err.Error(), "No data available") || strings.Contains(err.Error(), "No such")) {
		return nil
	}
	return err
}

// PoolStatus is the parsed status of a thin-pool.
type PoolStatus struct {
	TransactionID       uint64
	UsedMeta, TotalMeta uint64 // metadata blocks (4KiB)
	UsedData, TotalData uint64 // data blocks
	Mode                string // rw, ro, out_of_data_space, Fail
	MetaSnapHeld        bool   // a metadata snapshot is reserved
}

// ParsePoolStatus parses "0 N thin-pool <tid> <um>/<tm> <ud>/<td> ...".
func ParsePoolStatus(s string) (PoolStatus, error) {
	f := strings.Fields(s)
	if len(f) == 4 && f[3] == "Fail" {
		return PoolStatus{Mode: "Fail"}, nil
	}
	if len(f) < 8 || f[2] != "thin-pool" {
		return PoolStatus{}, fmt.Errorf("bad thin-pool status %q", s)
	}
	var p PoolStatus
	var err error
	if p.TransactionID, err = strconv.ParseUint(f[3], 10, 64); err != nil {
		return p, fmt.Errorf("bad thin-pool status %q", s)
	}
	if _, err := fmt.Sscanf(f[4], "%d/%d", &p.UsedMeta, &p.TotalMeta); err != nil {
		return p, fmt.Errorf("bad thin-pool status %q", s)
	}
	if _, err := fmt.Sscanf(f[5], "%d/%d", &p.UsedData, &p.TotalData); err != nil {
		return p, fmt.Errorf("bad thin-pool status %q", s)
	}
	p.MetaSnapHeld = f[6] != "-"
	p.Mode = f[7]
	return p, nil
}

// GetPoolStatus returns the status of a thin-pool device.
func GetPoolStatus(ctx context.Context, pool string) (PoolStatus, error) {
	s, err := Status(ctx, pool)
	if err != nil {
		return PoolStatus{}, err
	}
	return ParsePoolStatus(s)
}

// Only one metadata snapshot can exist per pool.
var metaSnapMu sync.Map // pool name -> *sync.Mutex

func withMetaSnap(ctx context.Context, pool string, fn func() error) error {
	m, _ := metaSnapMu.LoadOrStore(pool, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()
	// A snapshot left by a crashed process blocks a new one; drop it.
	// Release only when one is held: the kernel logs a warning on every
	// release without a snapshot.
	if st, err := GetPoolStatus(ctx, pool); err != nil || st.MetaSnapHeld {
		_ = Message(ctx, pool, "release_metadata_snap")
	}
	if err := Message(ctx, pool, "reserve_metadata_snap"); err != nil {
		return fmt.Errorf("reserve metadata snapshot of %s: %w", pool, err)
	}
	defer func() { _ = Message(context.WithoutCancel(ctx), pool, "release_metadata_snap") }()
	return fn()
}

// MappedBlocks returns the mapped blocks of thin device id, read with
// thin_dump from a metadata snapshot. pool is the thin-pool device name
// and metaPath a device node of its metadata device. The pool must be
// flushed (for example by suspending the thin device) for recent writes to
// show.
func MappedBlocks(ctx context.Context, pool, metaPath string, id uint32) (blockSectors uint64, ranges []BlockRange, err error) {
	err = withMetaSnap(ctx, pool, func() error {
		out, err := run.Cmd(ctx, nil, "thin_dump", "-m", "--dev-id", strconv.FormatUint(uint64(id), 10), metaPath)
		if err != nil {
			return err
		}
		blockSectors, ranges, err = ParseThinDump(strings.NewReader(string(out)), id)
		return err
	})
	return blockSectors, ranges, err
}

// ThinIDs returns the IDs of every thin device in the pool metadata, read
// with thin_dump --skip-mappings from a metadata snapshot.
func ThinIDs(ctx context.Context, pool, metaPath string) ([]uint32, error) {
	var ids []uint32
	err := withMetaSnap(ctx, pool, func() error {
		out, err := run.Cmd(ctx, nil, "thin_dump", "-m", "--skip-mappings", metaPath)
		if err != nil {
			return err
		}
		ids, err = ParseThinIDs(strings.NewReader(string(out)))
		return err
	})
	return ids, err
}

// ParseThinIDs returns the dev_id of every device in thin_dump XML.
func ParseThinIDs(r io.Reader) ([]uint32, error) {
	d := xml.NewDecoder(r)
	var ids []uint32
	super := false
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("thin_dump output: %w", err)
		}
		if t, ok := tok.(xml.StartElement); ok {
			switch t.Name.Local {
			case "superblock":
				super = true
			case "device":
				n, err := strconv.ParseUint(attrs(t)["dev_id"], 10, 32)
				if err != nil {
					return nil, errors.New("thin_dump: bad dev_id")
				}
				ids = append(ids, uint32(n))
			}
		}
	}
	if !super {
		return nil, errors.New("thin_dump: no superblock")
	}
	return ids, nil
}

// ParseThinDump parses thin_dump XML and returns the data block size (in
// sectors) and the mapped virtual blocks of device id, merged and sorted.
func ParseThinDump(r io.Reader, id uint32) (uint64, []BlockRange, error) {
	d := xml.NewDecoder(r)
	var blockSectors uint64
	var ranges []BlockRange
	found, in := false, false
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, nil, fmt.Errorf("thin_dump output: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			a := attrs(t)
			switch t.Name.Local {
			case "superblock":
				if blockSectors, err = strconv.ParseUint(a["data_block_size"], 10, 64); err != nil {
					return 0, nil, fmt.Errorf("thin_dump: bad data_block_size")
				}
			case "device":
				dev, _ := strconv.ParseUint(a["dev_id"], 10, 32)
				in = uint32(dev) == id
				found = found || in
			case "single_mapping":
				if in {
					b, err := strconv.ParseUint(a["origin_block"], 10, 64)
					if err != nil {
						return 0, nil, fmt.Errorf("thin_dump: bad origin_block")
					}
					ranges = appendRange(ranges, BlockRange{b, 1})
				}
			case "range_mapping":
				if in {
					b, err1 := strconv.ParseUint(a["origin_begin"], 10, 64)
					n, err2 := strconv.ParseUint(a["length"], 10, 64)
					if err1 != nil || err2 != nil {
						return 0, nil, fmt.Errorf("thin_dump: bad range_mapping")
					}
					ranges = appendRange(ranges, BlockRange{b, n})
				}
			}
		case xml.EndElement:
			if t.Name.Local == "device" {
				in = false
			}
		}
	}
	if blockSectors == 0 {
		return 0, nil, errors.New("thin_dump: no superblock")
	}
	if !found {
		return 0, nil, fmt.Errorf("thin_dump: device %d not found", id)
	}
	return blockSectors, ranges, nil
}

// Delta is the difference between two thin devices.
type Delta struct {
	BlockSectors uint64
	// Copy holds blocks that differ or are mapped only in the second
	// device: copy them from the second device.
	Copy []BlockRange
	// Zero holds blocks mapped only in the first device: they read as
	// zeros in the second device.
	Zero []BlockRange
}

// ThinDelta compares thin devices id1 (base) and id2 of one pool with
// thin_delta on a metadata snapshot.
func ThinDelta(ctx context.Context, pool, metaPath string, id1, id2 uint32) (Delta, error) {
	var d Delta
	err := withMetaSnap(ctx, pool, func() error {
		out, err := run.Cmd(ctx, nil, "thin_delta", "-m",
			"--snap1", strconv.FormatUint(uint64(id1), 10),
			"--snap2", strconv.FormatUint(uint64(id2), 10), metaPath)
		if err != nil {
			return err
		}
		d, err = ParseThinDelta(strings.NewReader(string(out)))
		return err
	})
	return d, err
}

// ParseThinDelta parses thin_delta XML.
func ParseThinDelta(r io.Reader) (Delta, error) {
	dec := xml.NewDecoder(r)
	var d Delta
	sawDiff := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return Delta{}, fmt.Errorf("thin_delta output: %w", err)
		}
		t, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		a := attrs(t)
		switch t.Name.Local {
		case "superblock":
			if d.BlockSectors, err = strconv.ParseUint(a["data_block_size"], 10, 64); err != nil {
				return Delta{}, errors.New("thin_delta: bad data_block_size")
			}
		case "diff":
			sawDiff = true
		case "same", "different", "left_only", "right_only":
			b, err1 := strconv.ParseUint(a["begin"], 10, 64)
			n, err2 := strconv.ParseUint(a["length"], 10, 64)
			if err1 != nil || err2 != nil {
				return Delta{}, fmt.Errorf("thin_delta: bad %s entry", t.Name.Local)
			}
			switch t.Name.Local {
			case "different", "right_only":
				d.Copy = appendRange(d.Copy, BlockRange{b, n})
			case "left_only":
				d.Zero = appendRange(d.Zero, BlockRange{b, n})
			}
		}
	}
	if d.BlockSectors == 0 || !sawDiff {
		return Delta{}, errors.New("thin_delta: incomplete output")
	}
	return d, nil
}

func attrs(t xml.StartElement) map[string]string {
	m := make(map[string]string, len(t.Attr))
	for _, a := range t.Attr {
		m[a.Name.Local] = a.Value
	}
	return m
}

// appendRange appends r, merging it with the last range when adjacent.
// Input from thin tools is sorted.
func appendRange(rs []BlockRange, r BlockRange) []BlockRange {
	if n := len(rs); n > 0 && rs[n-1].Begin+rs[n-1].Length == r.Begin {
		rs[n-1].Length += r.Length
		return rs
	}
	return append(rs, r)
}
