// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package storage

import (
	"context"
	"errors"
	"testing"

	"github.com/Azure/blip/internal/stream"
)

func TestVolumeBytes(t *testing.T) {
	const mib = 1 << 20
	for _, tt := range []struct {
		fs, streamSize, want int64
	}{
		{32 * mib, 0, 32 * mib},
		{32 * mib, 64 * mib, stream.Offset + 64*mib},
		{stream.Offset + 32*mib, 64 * mib, stream.Offset + 32*mib + 64*mib},
		{1, 0, blockSize},
	} {
		if got := VolumeBytes(tt.fs, tt.streamSize); got != tt.want {
			t.Fatalf("VolumeBytes(%d, %d) = %d, want %d", tt.fs, tt.streamSize, got, tt.want)
		}
	}
}

func TestCreateStreamVolumeGeometry(t *testing.T) {
	x := newStorageSimulation(t)
	ctx := context.Background()
	const streamSize = 64 << 20
	if err := x.s.CreateCommit(ctx, CreateCommit{CommitID: "state", SizeBytes: 8 * blockSize, StreamSize: streamSize}); err != nil {
		t.Fatal(err)
	}
	r := x.s.vols["state"]
	if r.StreamSize != streamSize || r.FSBytes != 8*blockSize || r.Size != VolumeBytes(8*blockSize, streamSize) {
		t.Fatalf("stream commit geometry: %+v", r)
	}

	_, err := x.s.CreateWorking(ctx, CreateWorking{
		AttachmentID: "working", FromCommit: "state", SizeBytes: 16 * blockSize, StreamSize: streamSize,
	})
	if err != nil {
		t.Fatal(err)
	}
	w := x.s.vols["working"]
	if w.StreamSize != streamSize || w.FSBytes != 16*blockSize || w.Size != VolumeBytes(16*blockSize, streamSize) {
		t.Fatalf("stream working geometry: %+v", w)
	}
	if got := x.read(x.s.plainName(w), 0); got != "ext4" {
		t.Fatalf("working filesystem block = %q", got)
	}

	if _, err := x.s.Seal(ctx, "working", "sealed"); err != nil {
		t.Fatal(err)
	}
	c := x.s.vols["sealed"]
	if c.Size != w.Size || c.FSBytes != w.FSBytes || c.StreamSize != w.StreamSize {
		t.Fatalf("seal changed geometry: %+v != %+v", c, w)
	}
}

func TestGrowUsesFilesystemBytes(t *testing.T) {
	x := newStorageSimulation(t)
	ctx := context.Background()
	x.image()
	if _, err := x.s.CreateWorking(ctx, CreateWorking{
		AttachmentID: "working", FromImage: "image", SizeBytes: 16 * blockSize, StreamSize: 64 << 20,
	}); err != nil {
		t.Fatal(err)
	}
	w := x.s.vols["working"]
	if w.Size != VolumeBytes(16*blockSize, 64<<20) {
		t.Fatalf("working size = %d", w.Size)
	}
	if w.FSBytes != 16*blockSize {
		t.Fatalf("filesystem bytes = %d", w.FSBytes)
	}
	// Growing to the filesystem size leaves the origin's block 7 untouched.
	if x.thin[x.s.vols["image"].Thin][7] != "" {
		t.Fatal("grow spilled into the snapshot origin")
	}
}

func TestRemoteStreamGeometry(t *testing.T) {
	x := newStorageSimulation(t)
	ctx := context.Background()
	x.image()
	const streamSize = 64 << 20
	_, err := x.s.CreateWorking(ctx, CreateWorking{
		AttachmentID: "remote", StateUID: "u", StreamSize: streamSize, SizeBytes: 16 * blockSize,
		Remote: &Remote{
			ID: "remote/lease", Device: "/remote/source", SizeBytes: 8 * blockSize, Base: "image",
			Regions: []Region{{0, 8 * blockSize}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := x.s.vols["remote"]
	if r.StreamSize != streamSize || r.FSBytes != 16*blockSize || r.Size != VolumeBytes(16*blockSize, streamSize) {
		t.Fatalf("remote geometry: %+v", r)
	}
}

func TestViewLifecycle(t *testing.T) {
	x := newStorageSimulation(t)
	ctx := context.Background()
	x.image()
	if err := x.s.CreateCommit(ctx, CreateCommit{StateUID: "u", CommitID: "commit", FromImage: "image"}); err != nil {
		t.Fatal(err)
	}
	dev, err := x.s.OpenView(ctx, "u", "commit", "view")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := x.s.Device("view"); err != nil || got != dev {
		t.Fatalf("Device(view) = %q, %v", got, err)
	}
	again, err := x.s.OpenView(ctx, "u", "commit", "view")
	if err != nil || again != dev {
		t.Fatalf("reopen view = %q, %v", again, err)
	}
	if r := x.s.vols["view"]; r == nil || !r.ReadOnly || r.Kind != KindWorking {
		t.Fatalf("view record: %+v", r)
	}
	if err := x.s.CloseView("view"); err != nil {
		t.Fatal(err)
	}
	if _, err := x.s.Device("view"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Device after CloseView = %v", err)
	}
	if err := x.s.CloseView("view"); err != nil {
		t.Fatalf("second CloseView = %v", err)
	}
}
