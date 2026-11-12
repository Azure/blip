// Package meta implements the blip metadata disk: a small raw disk shared by
// the host (node/slot) and the guest (blip-boot, blip-meta).
//
// Layout (little endian):
//
//	0       header: magic "BLIPMETA", version u32, then u32 offsets/sizes
//	4 KiB   host slot A
//	64 KiB  host slot B
//	128 KiB guest area (to 256 KiB)
//
// Each slot/area holds a record: seq u64, len u32, crc32c u32, JSON payload.
// The CRC covers seq, len and the payload, so torn writes are detected.
// The package depends on the standard library and golang.org/x/sys only,
// because it is compiled into the initramfs stub.
package meta

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
)

const (
	Magic   = "BLIPMETA"
	Version = 1

	// Size is the size of the metadata disk.
	Size = 256 << 10

	HostAOffset = 4 << 10
	HostBOffset = 64 << 10
	GuestOffset = 128 << 10

	// HostSlotSize is the size of each host slot (A ends where B starts).
	HostSlotSize = 60 << 10
	// GuestAreaSize is the size of the guest area.
	GuestAreaSize = Size - GuestOffset

	recordHeader = 16
	// MaxHostPayload and MaxGuestPayload bound the JSON payloads.
	MaxHostPayload  = HostSlotSize - recordHeader
	MaxGuestPayload = GuestAreaSize - recordHeader

	headerSize = 4096
	blockSize  = 4096
)

// Serial is the virtio serial of the metadata disk.
const Serial = "blip-meta"

var (
	ErrBadMagic   = errors.New("meta: bad magic")
	ErrVersion    = errors.New("meta: unsupported version")
	ErrEmpty      = errors.New("meta: empty record")
	ErrCorrupt    = errors.New("meta: corrupt record")
	ErrTooLarge   = errors.New("meta: payload too large")
	ErrNoHostData = errors.New("meta: no valid host data")
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

type header struct {
	version                  uint32
	hostA, hostB, guest      uint32
	hostSize, guestSize, end uint32
}

func encodeHeader() []byte {
	b := make([]byte, headerSize)
	copy(b, Magic)
	le := binary.LittleEndian
	le.PutUint32(b[8:], Version)
	le.PutUint32(b[12:], HostAOffset)
	le.PutUint32(b[16:], HostBOffset)
	le.PutUint32(b[20:], GuestOffset)
	le.PutUint32(b[24:], HostSlotSize)
	le.PutUint32(b[28:], GuestAreaSize)
	le.PutUint32(b[32:], Size)
	le.PutUint32(b[36:], crc32.Checksum(b[:36], castagnoli))
	return b
}

func decodeHeader(b []byte) (header, error) {
	var h header
	if len(b) < 40 || string(b[:8]) != Magic {
		return h, ErrBadMagic
	}
	le := binary.LittleEndian
	if crc32.Checksum(b[:36], castagnoli) != le.Uint32(b[36:]) {
		return h, fmt.Errorf("meta: header %w", ErrCorrupt)
	}
	h.version = le.Uint32(b[8:])
	if h.version != Version {
		return h, fmt.Errorf("%w %d", ErrVersion, h.version)
	}
	h.hostA, h.hostB, h.guest = le.Uint32(b[12:]), le.Uint32(b[16:]), le.Uint32(b[20:])
	h.hostSize, h.guestSize, h.end = le.Uint32(b[24:]), le.Uint32(b[28:]), le.Uint32(b[32:])
	if h.hostA != HostAOffset || h.hostB != HostBOffset || h.guest != GuestOffset ||
		h.hostSize != HostSlotSize || h.guestSize != GuestAreaSize || h.end != Size {
		return h, fmt.Errorf("meta: unexpected layout: %w", ErrCorrupt)
	}
	return h, nil
}

// encodeRecord returns the record bytes, padded to a block multiple.
func encodeRecord(seq uint64, payload []byte, max int) ([]byte, error) {
	if len(payload) > max {
		return nil, fmt.Errorf("%w: %d > %d", ErrTooLarge, len(payload), max)
	}
	n := (recordHeader + len(payload) + blockSize - 1) / blockSize * blockSize
	b := make([]byte, n)
	le := binary.LittleEndian
	le.PutUint64(b[0:], seq)
	le.PutUint32(b[8:], uint32(len(payload)))
	copy(b[recordHeader:], payload)
	c := crc32.Update(crc32.Checksum(b[:12], castagnoli), castagnoli, payload)
	le.PutUint32(b[12:], c)
	return b, nil
}

// decodeRecord validates a record. An all-zero header is ErrEmpty.
func decodeRecord(b []byte, max int) (uint64, []byte, error) {
	if len(b) < recordHeader {
		return 0, nil, ErrCorrupt
	}
	le := binary.LittleEndian
	seq, n, c := le.Uint64(b), le.Uint32(b[8:]), le.Uint32(b[12:])
	if seq == 0 && n == 0 && c == 0 {
		return 0, nil, ErrEmpty
	}
	if int(n) > max || recordHeader+int(n) > len(b) {
		return 0, nil, fmt.Errorf("%w: length %d", ErrCorrupt, n)
	}
	p := b[recordHeader : recordHeader+int(n)]
	if crc32.Update(crc32.Checksum(b[:12], castagnoli), castagnoli, p) != c {
		return 0, nil, fmt.Errorf("%w: crc mismatch", ErrCorrupt)
	}
	return seq, p, nil
}
