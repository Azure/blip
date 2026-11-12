//go:build linux

package meta

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"
)

func newImage(t *testing.T) (string, *Writer) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "meta.img")
	if err := Create(p); err != nil {
		t.Fatal(err)
	}
	w, err := OpenWriter(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })
	return p, w
}

func TestCreateEmpty(t *testing.T) {
	p, w := newImage(t)
	st, _ := os.Stat(p)
	if st.Size() != Size {
		t.Fatalf("size %d", st.Size())
	}
	if _, _, err := w.ReadHost(); !errors.Is(err, ErrNoHostData) {
		t.Fatalf("ReadHost: %v", err)
	}
	if _, err := w.ReadGuest(); !errors.Is(err, ErrEmpty) || !IsEmpty(err) {
		t.Fatalf("ReadGuest: %v", err)
	}
}

func TestHostRoundTripAndAlternation(t *testing.T) {
	p, w := newImage(t)
	d, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	for i := 1; i <= 5; i++ {
		seq, err := w.WriteHost(&HostData{AllocationID: string(rune('a' + i)), Boot: Boot{RootSerial: "root", Init: []string{"/sbin/init"}}})
		if err != nil || seq != uint64(i) {
			t.Fatalf("write %d: seq %d err %v", i, seq, err)
		}
		h, s, err := d.ReadHost()
		if err != nil || s != uint64(i) || h.AllocationID != string(rune('a'+i)) || h.Version != Version {
			t.Fatalf("read %d: %+v %d %v", i, h, s, err)
		}
	}
	// Slots alternate: A has odd seqs, B even.
	sa, _, _ := decodeRecord(mustRead(t, w, HostAOffset, HostSlotSize), MaxHostPayload)
	sb, _, _ := decodeRecord(mustRead(t, w, HostBOffset, HostSlotSize), MaxHostPayload)
	if sa != 5 || sb != 4 {
		t.Fatalf("slots A=%d B=%d", sa, sb)
	}
}

func mustRead(t *testing.T, w *Writer, off int64, n int) []byte {
	b, err := w.read(off, n)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTornWriteFallsBack(t *testing.T) {
	_, w := newImage(t)
	w.WriteHost(&HostData{AllocationID: "one"}) // A seq1
	w.WriteHost(&HostData{AllocationID: "two"}) // B seq2
	// Simulate a torn write of B: corrupt a payload byte.
	w.f.WriteAt([]byte{'X'}, HostBOffset+recordHeader+3)
	h, seq, err := w.ReadHost()
	if err != nil || h.AllocationID != "one" || seq != 1 {
		t.Fatalf("got %+v %d %v", h, seq, err)
	}
	// Next write must go to the invalid slot B, not overwrite good A.
	seq, _ = w.WriteHost(&HostData{AllocationID: "three"})
	if seq != 2 {
		t.Fatalf("seq %d", seq)
	}
	if s, _, err := decodeRecord(mustRead(t, w, HostAOffset, HostSlotSize), MaxHostPayload); err != nil || s != 1 {
		t.Fatalf("A clobbered: %d %v", s, err)
	}
	h, _, _ = w.ReadHost()
	if h.AllocationID != "three" {
		t.Fatal(h.AllocationID)
	}
}

func TestBadCRCAndLength(t *testing.T) {
	_, w := newImage(t)
	w.WriteHost(&HostData{AllocationID: "x"})
	// Bad crc field.
	w.f.WriteAt([]byte{1, 2, 3, 4}, HostAOffset+12)
	if _, _, err := w.ReadHost(); !errors.Is(err, ErrNoHostData) {
		t.Fatal(err)
	}
	// Huge length in guest area.
	b := make([]byte, recordHeader)
	binary.LittleEndian.PutUint64(b, 1)
	binary.LittleEndian.PutUint32(b[8:], 1<<30)
	w.f.WriteAt(b, GuestOffset)
	if _, err := w.ReadGuest(); !errors.Is(err, ErrCorrupt) {
		t.Fatal(err)
	}
}

func TestOversized(t *testing.T) {
	p, w := newImage(t)
	big := strings.Repeat("a", MaxHostPayload)
	if _, err := w.WriteHost(&HostData{Hostname: big}); !errors.Is(err, ErrTooLarge) {
		t.Fatal(err)
	}
	d, _ := Open(p)
	defer d.Close()
	if err := d.WriteGuest(&GuestData{Message: strings.Repeat("m", MaxGuestPayload)}); !errors.Is(err, ErrTooLarge) {
		t.Fatal(err)
	}
}

func TestVersionAndMagic(t *testing.T) {
	p, w := newImage(t)
	h := encodeHeader()
	binary.LittleEndian.PutUint32(h[8:], 2)
	w.f.WriteAt(h, 0)
	if _, err := OpenWriter(p); !errors.Is(err, ErrCorrupt) { // crc covers version
		t.Fatal(err)
	}
	// Valid crc but unknown version.
	h = encodeHeader()
	binary.LittleEndian.PutUint32(h[8:], 2)
	copy(h[36:], crcLE(h[:36]))
	w.f.WriteAt(h, 0)
	if _, err := OpenWriter(p); !errors.Is(err, ErrVersion) {
		t.Fatal(err)
	}
	if _, err := Open(p); !errors.Is(err, ErrVersion) {
		t.Fatal(err)
	}
	w.f.WriteAt([]byte("NOTMETA!"), 0)
	if _, err := OpenWriter(p); !errors.Is(err, ErrBadMagic) {
		t.Fatal(err)
	}
}

func crcLE(b []byte) []byte {
	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out, crc32.Checksum(b, castagnoli))
	return out
}

func TestGuestSeqAndUpdate(t *testing.T) {
	p, w := newImage(t)
	d, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := d.WriteGuest(&GuestData{State: StateWaiting, BootCount: 1}); err != nil {
		t.Fatal(err)
	}
	if err := d.UpdateGuest(func(g *GuestData) { g.State = StateExec }); err != nil {
		t.Fatal(err)
	}
	code := 7
	d.UpdateGuest(func(g *GuestData) { g.ExitCode = &code })
	g, err := w.ReadGuest()
	if err != nil || g.Seq != 3 || g.State != StateExec || g.BootCount != 1 || g.ExitCode == nil || *g.ExitCode != 7 || g.Time.IsZero() {
		t.Fatalf("%+v %v", g, err)
	}
	// Truncate untrusted fields.
	d.WriteGuest(&GuestData{Message: strings.Repeat("m", 10000)})
	g, _ = w.ReadGuest()
	if len(g.Message) != 4096 || g.Seq != 4 {
		t.Fatal(len(g.Message), g.Seq)
	}
	if err := w.ResetGuest(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ReadGuest(); !IsEmpty(err) {
		t.Fatal(err)
	}
}

func TestFindBySerial(t *testing.T) {
	dir := t.TempDir()
	for name, serial := range map[string]string{"vda": "blip-meta\n", "vdb": "root"} {
		os.MkdirAll(filepath.Join(dir, name), 0o755)
		os.WriteFile(filepath.Join(dir, name, "serial"), []byte(serial), 0o644)
	}
	os.MkdirAll(filepath.Join(dir, "loop0"), 0o755)
	if got := FindBySerial(dir, Serial); got != "/dev/vda" {
		t.Fatal(got)
	}
	if got := FindBySerial(dir, "root"); got != "/dev/vdb" {
		t.Fatal(got)
	}
	if got := FindBySerial(dir, "nope"); got != "" {
		t.Fatal(got)
	}
}

func TestAlignedBuf(t *testing.T) {
	for _, n := range []int{4096, 65536} {
		b := alignedBuf(n)
		if len(b) != n || uintptr(unsafe.Pointer(&b[0]))%blockSize != 0 {
			t.Fatal(n)
		}
	}
}
