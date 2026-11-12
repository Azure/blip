package extent

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestNormalize(t *testing.T) {
	got := Normalize([]Range{{8192, 4096}, {0, 4096}, {4096, 4096}, {100, 0}, {20000, 10}, {20000, 5}})
	want := []Range{{0, 12288}, {20000, 10}}
	if !reflect.DeepEqual(got, want) {
		t.Fatal(got)
	}
	if Total(want) != 12298 {
		t.Fatal(Total(want))
	}
}

func TestClamp(t *testing.T) {
	got := clamp([]Range{{0, 4096}, {8192, 8192}, {20000, 4096}}, 12288)
	if !reflect.DeepEqual(got, []Range{{0, 4096}, {8192, 4096}}) {
		t.Fatal(got)
	}
}

func TestDiff(t *testing.T) {
	a := Hashes{Sums: [][32]byte{{1}, {2}, {3}}}
	b := Hashes{Sums: [][32]byte{{1}, {9}}}
	if got := Diff(a, b); !reflect.DeepEqual(got, []int64{1, 2}) {
		t.Fatal(got)
	}
}

// Copy and Hash on regular files (tmpfs may not support O_DIRECT, so the
// test skips there).
func TestCopyAndHash(t *testing.T) {
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "src"), filepath.Join(dir, "dst")
	data := make([]byte, 3<<20)
	rand.Read(data)
	if err := os.WriteFile(src, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, make([]byte, len(data)), 0o600); err != nil {
		t.Fatal(err)
	}
	if f, err := os.OpenFile(src, os.O_RDONLY|0o40000, 0); err != nil {
		t.Skip("no O_DIRECT here:", err)
	} else {
		f.Close()
	}
	ctx := context.Background()
	rs := []Range{{0, 65536}, {1 << 20, 2 << 20}}
	if err := Copy(ctx, src, dst, rs); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dst)
	want := make([]byte, len(data))
	copy(want[:65536], data[:65536])
	copy(want[1<<20:], data[1<<20:])
	if !bytes.Equal(got, want) {
		t.Fatal("copy mismatch")
	}
	if err := Zero(ctx, dst, []Range{{0, 4096}}); err != nil {
		t.Fatal(err)
	}
	ha, err := Hash(ctx, src, 65536)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := Hash(ctx, dst, 65536)
	if err != nil {
		t.Fatal(err)
	}
	// Block 0 was zeroed in part; blocks 1-15 (64KiB to 1MiB) were not copied.
	want16 := make([]int64, 16)
	for i := range want16 {
		want16[i] = int64(i)
	}
	if len(ha.Sums) != 48 || !reflect.DeepEqual(Diff(ha, hb), want16) {
		t.Fatal(Diff(ha, hb))
	}
	if Copy(ctx, src, dst, []Range{{1, 4096}}) == nil {
		t.Fatal("unaligned range must fail")
	}
}
