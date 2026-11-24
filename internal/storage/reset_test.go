// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package storage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Azure/blip/internal/stream"
)

func TestResetStreamClearsRing(t *testing.T) {
	const size = stream.MinSize
	path := filepath.Join(t.TempDir(), "ring")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(stream.Offset + size); err != nil {
		f.Close()
		t.Fatal(err)
	}
	w, err := stream.NewWriter(f, stream.Offset, size, 1)
	if err != nil {
		f.Close()
		t.Fatal(err)
	}
	if _, err := w.Append(stream.TypeStart, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(stream.TypeOut, []byte("parent output")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if err := resetStream(path, size); err != nil {
		t.Fatal(err)
	}

	// Format the empty ring, then reopen it. Recovery must not walk into the
	// source's old records beyond the header.
	f, err = os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	w, err = stream.NewWriter(f, stream.Offset, size, 2)
	if err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	f, err = os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	r, err := stream.NewReader(f, stream.Offset, size)
	if err != nil {
		f.Close()
		t.Fatal(err)
	}
	head, tail := r.Head()
	if head != 0 || tail != 0 {
		f.Close()
		t.Fatalf("reset ring head/tail = %d/%d, want 0/0", head, tail)
	}
	recs, _, err := r.Read(0, 10)
	if err != nil {
		f.Close()
		t.Fatal(err)
	}
	if len(recs) != 0 {
		f.Close()
		t.Fatalf("reset ring still holds %d records", len(recs))
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	f, err = os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	w, err = stream.NewWriter(f, stream.Offset, size, 3)
	if err != nil {
		f.Close()
		t.Fatal(err)
	}
	off, err := w.Append(stream.TypeStart, nil)
	if err != nil {
		f.Close()
		t.Fatal(err)
	}
	if off != 0 {
		f.Close()
		t.Fatalf("first record after reset offset = %d, want 0", off)
	}
	if err := w.Close(); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}
