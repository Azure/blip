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

func TestCopiedCommitRingHeader(t *testing.T) {
	x := newStorageSimulation(t)
	ctx := context.Background()
	const (
		streamSize = 64 << 20
		fsSize     = 8 * blockSize
	)
	header := int(stream.Offset / blockSize)
	activate := func(id string) *record {
		t.Helper()
		if _, err := x.s.Activate(id); err != nil {
			t.Fatal(err)
		}
		return x.s.vols[id]
	}

	if err := x.s.CreateCommit(ctx, CreateCommit{CommitID: "base", StateUID: "src",
		SizeBytes: fsSize, StreamSize: streamSize}); err != nil {
		t.Fatal(err)
	}
	if _, err := x.s.CreateWorking(ctx, CreateWorking{AttachmentID: "working", FromCommit: "base",
		StateUID: "src", SizeBytes: fsSize, StreamSize: streamSize}); err != nil {
		t.Fatal(err)
	}
	x.write(x.s.plainName(x.s.vols["working"]), header, "marker")
	if _, err := x.s.Seal(ctx, "working", "sealed"); err != nil {
		t.Fatal(err)
	}
	sealed := activate("sealed")
	if got := x.read(x.s.thinName(sealed), header); got != "marker" {
		t.Fatalf("seal dropped ring header: %q", got)
	}

	// A working volume for the same state keeps the ring so a restart can
	// continue its trajectory.
	if _, err := x.s.CreateWorking(ctx, CreateWorking{AttachmentID: "restart", FromCommit: "sealed",
		StateUID: "src", SizeBytes: fsSize, StreamSize: streamSize}); err != nil {
		t.Fatal(err)
	}
	if got := x.read(x.s.plainName(x.s.vols["restart"]), header); got != "marker" {
		t.Fatalf("same-state working header = %q", got)
	}

	// A copy within the same state keeps the source's ring.
	if err := x.s.CreateCommit(ctx, CreateCommit{CommitID: "same", FromCommit: "sealed",
		StateUID: "src", StreamSize: streamSize}); err != nil {
		t.Fatal(err)
	}
	if got := x.read(x.s.thinName(activate("same")), header); got != "marker" {
		t.Fatalf("same-state copy header = %q", got)
	}

	// A copy into another state starts with an empty ring, keeps the
	// filesystem, and leaves the source's ring intact.
	if err := x.s.CreateCommit(ctx, CreateCommit{CommitID: "copy", FromCommit: "sealed",
		StateUID: "dst", StreamSize: streamSize}); err != nil {
		t.Fatal(err)
	}
	copied := activate("copy")
	for _, block := range []int{header, header + 1} {
		if got := x.read(x.s.thinName(copied), block); got != "" {
			t.Fatalf("cross-state copy header block %d = %q", block, got)
		}
	}
	if got := x.read(x.s.thinName(copied), 0); got != "ext4" {
		t.Fatalf("cross-state copy filesystem block = %q", got)
	}
	if got := x.read(x.s.thinName(sealed), header); got != "marker" {
		t.Fatalf("cross-state copy changed source header to %q", got)
	}

	// A cross-state copy without an explicit ring still must not inherit the
	// source's ring; its volume carries the source's size.
	if err := x.s.CreateCommit(ctx, CreateCommit{CommitID: "copy-no-spec", FromCommit: "sealed",
		StateUID: "dst3"}); err != nil {
		t.Fatal(err)
	}
	noSpec := activate("copy-no-spec")
	if got := x.read(x.s.thinName(noSpec), header); got != "" {
		t.Fatalf("cross-state copy without stream size header = %q", got)
	}
	if got := x.read(x.s.thinName(sealed), header); got != "marker" {
		t.Fatalf("copy without stream size changed source header to %q", got)
	}

	// A grown cross-state copy resets the ring after growing the filesystem.
	if err := x.s.CreateCommit(ctx, CreateCommit{CommitID: "grown", FromCommit: "sealed",
		StateUID: "dst2", SizeBytes: 16 * blockSize, StreamSize: streamSize}); err != nil {
		t.Fatal(err)
	}
	grown := activate("grown")
	if got := x.read(x.s.thinName(grown), header); got != "" {
		t.Fatalf("grown cross-state copy header = %q", got)
	}
	if got := x.read(x.s.thinName(grown), 7); got != "grown" {
		t.Fatalf("grown cross-state copy filesystem block = %q", got)
	}
}

// TestFetchedCommitRingHeader covers a source replica whose StreamSize was not
// persisted by FetchCommit. The destination ring is what decides whether a
// cross-state copy needs resetting.
func TestFetchedCommitRingHeader(t *testing.T) {
	x := newStorageSimulation(t)
	ctx := context.Background()
	const (
		streamSize = 64 << 20
		fsSize     = 8 * blockSize
	)
	header := int(stream.Offset / blockSize)

	if err := x.s.CreateCommit(ctx, CreateCommit{CommitID: "base", StateUID: "src",
		SizeBytes: fsSize, StreamSize: streamSize}); err != nil {
		t.Fatal(err)
	}
	if _, err := x.s.CreateWorking(ctx, CreateWorking{AttachmentID: "working", FromCommit: "base",
		StateUID: "src", SizeBytes: fsSize, StreamSize: streamSize}); err != nil {
		t.Fatal(err)
	}
	x.write(x.s.plainName(x.s.vols["working"]), header, "marker")
	if _, err := x.s.Seal(ctx, "working", "sealed"); err != nil {
		t.Fatal(err)
	}

	// FetchCommit does not persist a replica's StreamSize.
	sealed := x.s.vols["sealed"]
	x.s.mu.Lock()
	sealed.StreamSize = 0
	x.s.mu.Unlock()

	if err := x.s.CreateCommit(ctx, CreateCommit{CommitID: "copy", FromCommit: "sealed",
		StateUID: "dst", StreamSize: streamSize}); err != nil {
		t.Fatal(err)
	}
	if _, err := x.s.Activate("sealed"); err != nil {
		t.Fatal(err)
	}
	if _, err := x.s.Activate("copy"); err != nil {
		t.Fatal(err)
	}
	if got := x.read(x.s.thinName(x.s.vols["copy"]), header); got != "" {
		t.Fatalf("fetched-replica copy header = %q", got)
	}
	if got := x.read(x.s.thinName(sealed), header); got != "marker" {
		t.Fatalf("fetched-replica source header = %q", got)
	}
}

func TestLiveCopyRingHeader(t *testing.T) {
	x := newStorageSimulation(t)
	ctx := context.Background()
	const (
		streamSize = 64 << 20
		fsSize     = 8 * blockSize
	)
	header := int(stream.Offset / blockSize)

	x.image()
	if _, err := x.s.CreateWorking(ctx, CreateWorking{AttachmentID: "working", FromImage: "image",
		StateUID: "src", SizeBytes: fsSize, StreamSize: streamSize}); err != nil {
		t.Fatal(err)
	}
	x.write(x.s.plainName(x.s.vols["working"]), header, "marker")

	if _, err := x.s.LiveCopy(ctx, "working", "same", "src"); err != nil {
		t.Fatal(err)
	}
	if _, err := x.s.Activate("same"); err != nil {
		t.Fatal(err)
	}
	if got := x.read(x.s.thinName(x.s.vols["same"]), header); got != "marker" {
		t.Fatalf("same-state live copy header = %q", got)
	}

	if _, err := x.s.LiveCopy(ctx, "working", "copy", "dst"); err != nil {
		t.Fatal(err)
	}
	if _, err := x.s.Activate("copy"); err != nil {
		t.Fatal(err)
	}
	if got := x.read(x.s.thinName(x.s.vols["copy"]), header); got != "" {
		t.Fatalf("cross-state live copy header = %q", got)
	}
	if got := x.read(x.s.thinName(x.s.vols["working"]), header); got != "marker" {
		t.Fatalf("live copy changed source header to %q", got)
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
