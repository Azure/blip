package storage

import (
	"math"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMergeRegions(t *testing.T) {
	got := MergeRegions([]Region{{128, 64}, {0, 64}, {64, 64}, {300, 0}, {400, 10}, {405, 10}})
	want := []Region{{0, 192}, {400, 15}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

// TestRoundUpOverflow: a size near int64 max must not wrap to a negative
// device-mapper length. It saturates at the largest representable aligned
// value; the CLI and controller reject such sizes before they reach here.
func TestRoundUpOverflow(t *testing.T) {
	saturated := int64(math.MaxInt64/blockSize) * blockSize
	for _, n := range []int64{math.MaxInt64, math.MaxInt64 - 1, saturated + 1, saturated} {
		got := roundUp(n, blockSize)
		if got < 0 {
			t.Fatalf("roundUp(%d) wrapped negative: %d", n, got)
		}
		if got%blockSize != 0 {
			t.Fatalf("roundUp(%d) = %d is not block aligned", n, got)
		}
		if n > saturated && got != saturated {
			t.Fatalf("roundUp(%d) = %d, want saturation %d", n, got, saturated)
		}
	}
	for _, tc := range []struct{ n, want int64 }{
		{0, 0},
		{1, blockSize},
		{blockSize, blockSize},
		{blockSize + 1, 2 * blockSize},
	} {
		if got := roundUp(tc.n, blockSize); got != tc.want {
			t.Errorf("roundUp(%d) = %d, want %d", tc.n, got, tc.want)
		}
	}
}

func TestCloneProgress(t *testing.T) {
	st := "0 2097152 clone 8 72/2048 128 4096/16384 3 2 no_hydration no_discard_passdown 4 hydration_threshold 256 hydration_batch_size 32 rw\n" +
		"2097152 1024 linear"
	h, total, mode, err := cloneProgress(st)
	if err != nil || h != 4096 || total != 16384 || mode != "rw" {
		t.Fatalf("%d %d %q %v", h, total, mode, err)
	}
	if _, _, _, err := cloneProgress("0 10 linear"); err == nil {
		t.Fatal("expected error without clone target")
	}
}

func TestDMPrefix(t *testing.T) {
	if p := DMPrefix("blip-dev-worker"); len(p) != len("blip-")+8 || p == DMPrefix("blip-dev-worker2") {
		t.Fatalf("prefix %q", p)
	}
}

func TestThinFree(t *testing.T) {
	free, ok := thinFree("0 100 thin-pool 1 10/100 64/200 0 0")
	if !ok || free != (200-64)*blockSize {
		t.Fatalf("thinFree = %d, %v", free, ok)
	}
	if free, ok := thinFree("0 100 thin-pool 1 10/100 300/200 0 0"); !ok || free != 0 {
		t.Fatalf("underflow = %d, %v", free, ok)
	}
	if _, ok := thinFree("0 100 linear"); ok {
		t.Fatal("parsed a non-thin status")
	}
}

// TestFreeBytesUsesFilesystem: without a thin pool the store still reports
// the backing filesystem's available space instead of zero.
func TestFreeBytesUsesFilesystem(t *testing.T) {
	dir := t.TempDir()
	s := &Store{cfg: Config{DataDir: dir, NodeName: "free-test"}, prefix: DMPrefix("free-test")}
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		t.Fatal(err)
	}
	total := int64(st.Blocks) * int64(st.Bsize)
	if free := s.FreeBytes(); free <= 0 || free > total {
		t.Fatalf("FreeBytes = %d, want 1..%d", free, total)
	}
}
