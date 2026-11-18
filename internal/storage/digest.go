package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// digestPrefix names the content digest format. Change it whenever the
// hashed representation changes, so digests of different formats never
// compare equal.
const digestPrefix = "v2:sha256:"

// digestChunk is the read size when hashing a volume.
const digestChunk = 4 << 20

// Digest returns the content digest of immutable volume id, computing and
// persisting it on first use. It hashes the size and the index and data of
// every non-zero 64 KiB block of ciphertext, so it depends only on the bytes
// the volume reads, not on how its blocks are mapped: two volumes with equal
// digests (under one disk key) are interchangeable as delta bases.
func (s *Store) Digest(ctx context.Context, id string) (string, error) {
	defer s.locks.lock("digest/" + id)()
	r, err := s.source(id, "")
	if err != nil {
		return "", err
	}
	defer s.unhold(id)
	s.mu.Lock()
	d, hydrating, failed := r.Digest, r.Clone != nil, r.Failed
	s.mu.Unlock()
	switch {
	case d != "":
		return d, nil
	case failed != "":
		return "", fmt.Errorf("storage: %s failed: %s", id, failed)
	case hydrating:
		return "", fmt.Errorf("storage: %s is still hydrating", id)
	}
	dev, err := s.Activate(id)
	if err != nil {
		return "", err
	}
	var regions []Region
	err = s.withMetaSnap(func() error {
		regions, err = s.mapped(r)
		return err
	})
	if err != nil {
		return "", err
	}
	d, err = hashContent(ctx, dev, r.Size, regions)
	if err != nil {
		return "", fmt.Errorf("digest %s: %w", id, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r.Digest = d
	if err := s.putLocked(r); err != nil {
		return "", err
	}
	return d, nil
}

// sameContent reports whether volume id has the given content digest.
func (s *Store) sameContent(ctx context.Context, id, digest string) bool {
	if !strings.HasPrefix(digest, digestPrefix) {
		return false
	}
	d, err := s.Digest(ctx, id)
	if err != nil {
		logf("digest %s: %v", id, err)
		return false
	}
	return d == digest
}

// hashContent hashes size bytes of dev, reading only regions (everything
// else must read as zeros). Reads bypass the page cache.
func hashContent(ctx context.Context, dev string, size int64, regions []Region) (string, error) {
	f, err := os.OpenFile(dev, os.O_RDONLY|unix.O_DIRECT, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	buf, err := unix.Mmap(-1, 0, digestChunk, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		return "", err
	}
	defer unix.Munmap(buf)

	h := sha256.New()
	var hdr [8]byte
	h.Write([]byte("blip-volume-content-v2\x00"))
	binary.LittleEndian.PutUint64(hdr[:], uint64(size))
	h.Write(hdr[:])
	zero := make([]byte, blockSize)
	for _, g := range regions {
		end := min(g.Offset+g.Length, size)
		for off := g.Offset; off < end; {
			if err := ctx.Err(); err != nil {
				return "", err
			}
			n := min(int64(len(buf)), end-off)
			if _, err := f.ReadAt(buf[:n], off); err != nil {
				return "", err
			}
			for i := int64(0); i < n; i += blockSize {
				b := buf[i:min(i+blockSize, n)]
				if bytes.Equal(b, zero[:len(b)]) {
					continue
				}
				binary.LittleEndian.PutUint64(hdr[:], uint64((off+i)/blockSize))
				h.Write(hdr[:])
				h.Write(b)
			}
			off += n
		}
	}
	return digestPrefix + hex.EncodeToString(h.Sum(nil)), nil
}
