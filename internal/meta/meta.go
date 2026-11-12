package meta

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// readRegion reads n bytes at off. Implementations may use aligned buffers.
type regionReader func(off int64, n int) ([]byte, error)

func checkHeader(read regionReader) error {
	b, err := read(0, headerSize)
	if err != nil {
		return err
	}
	_, err = decodeHeader(b)
	return err
}

// hostSlots returns (seq, payload, err) for slot A and B.
func readHostSlots(read regionReader) (seqs [2]uint64, payloads [2][]byte, errs [2]error) {
	for i, off := range []int64{HostAOffset, HostBOffset} {
		b, err := read(off, HostSlotSize)
		if err != nil {
			errs[i] = err
			continue
		}
		seqs[i], payloads[i], errs[i] = decodeRecord(b, MaxHostPayload)
	}
	return
}

func readHost(read regionReader) (*HostData, uint64, error) {
	if err := checkHeader(read); err != nil {
		return nil, 0, err
	}
	seqs, payloads, errs := readHostSlots(read)
	best := -1
	for i := range 2 {
		if errs[i] == nil && (best < 0 || seqs[i] > seqs[best]) {
			best = i
		}
	}
	if best < 0 {
		return nil, 0, ErrNoHostData
	}
	var d HostData
	if err := json.Unmarshal(payloads[best], &d); err != nil {
		return nil, 0, fmt.Errorf("meta: host data: %w", err)
	}
	return &d, seqs[best], nil
}

func readGuest(read regionReader) (*GuestData, error) {
	if err := checkHeader(read); err != nil {
		return nil, err
	}
	b, err := read(GuestOffset, GuestAreaSize)
	if err != nil {
		return nil, err
	}
	seq, p, err := decodeRecord(b, MaxGuestPayload)
	if err != nil {
		return nil, err
	}
	var g GuestData
	if err := json.Unmarshal(p, &g); err != nil {
		return nil, fmt.Errorf("meta: guest data: %w", err)
	}
	g.Seq = seq
	if len(g.Reason) > 256 {
		g.Reason = g.Reason[:256]
	}
	if len(g.Message) > 4096 {
		g.Message = g.Message[:4096]
	}
	return &g, nil
}

// Create creates (or truncates) a sparse metadata disk image with a header.
func Create(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if err := f.Truncate(Size); err == nil {
		_, err = f.WriteAt(encodeHeader(), 0)
		if err == nil {
			err = f.Sync()
		}
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// Writer is the host side of a metadata disk image.
type Writer struct {
	f *os.File
}

// OpenWriter opens an existing image created by Create.
func OpenWriter(path string) (*Writer, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	w := &Writer{f: f}
	if err := checkHeader(w.read); err != nil {
		f.Close()
		return nil, err
	}
	return w, nil
}

func (w *Writer) read(off int64, n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := w.f.ReadAt(b, off)
	return b, err
}

func (w *Writer) Close() error { return w.f.Close() }

// WriteHost writes d into the older (or invalid) host slot with seq = max+1
// and fsyncs. It returns the new seq.
func (w *Writer) WriteHost(d *HostData) (uint64, error) {
	if d.Version == 0 {
		d.Version = Version
	}
	p, err := json.Marshal(d)
	if err != nil {
		return 0, err
	}
	seqs, _, errs := readHostSlots(w.read)
	var max uint64
	target := 0
	for i := range 2 {
		if errs[i] != nil {
			seqs[i] = 0
		}
		max = maxu(max, seqs[i])
	}
	// Overwrite the invalid one, else the lower seq.
	if errs[0] == nil && (errs[1] != nil || seqs[1] < seqs[0]) {
		target = 1
	}
	rec, err := encodeRecord(max+1, p, MaxHostPayload)
	if err != nil {
		return 0, err
	}
	off := int64(HostAOffset)
	if target == 1 {
		off = HostBOffset
	}
	if _, err := w.f.WriteAt(rec, off); err != nil {
		return 0, err
	}
	return max + 1, w.f.Sync()
}

// ReadHost returns the newest valid host data and its seq.
func (w *Writer) ReadHost() (*HostData, uint64, error) { return readHost(w.read) }

// ReadGuest returns the guest data. ErrEmpty means the guest never wrote.
func (w *Writer) ReadGuest() (*GuestData, error) { return readGuest(w.read) }

// ResetGuest clears the guest area.
func (w *Writer) ResetGuest() error {
	if _, err := w.f.WriteAt(make([]byte, GuestAreaSize), GuestOffset); err != nil {
		return err
	}
	return w.f.Sync()
}

// ResetHost clears both host slots.
func (w *Writer) ResetHost() error {
	z := make([]byte, HostSlotSize)
	for _, off := range []int64{HostAOffset, HostBOffset} {
		if _, err := w.f.WriteAt(z, off); err != nil {
			return err
		}
	}
	return w.f.Sync()
}

func maxu(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

// IsEmpty reports whether err means "nothing written yet".
func IsEmpty(err error) bool { return errors.Is(err, ErrEmpty) || errors.Is(err, ErrNoHostData) }
