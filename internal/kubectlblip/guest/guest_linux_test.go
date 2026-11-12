//go:build linux

package guest

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFindDeviceSysBlock(t *testing.T) {
	old := SysBlock
	t.Cleanup(func() { SysBlock = old })
	SysBlock = t.TempDir()
	_ = os.MkdirAll(filepath.Join(SysBlock, "vdc"), 0o755)
	_ = os.WriteFile(filepath.Join(SysBlock, "vdc", "serial"), []byte("blip-test-data\n"), 0o644)
	if d := FindDevice("blip-test-data"); d != "/dev/vdc" {
		t.Fatal(d)
	}
	if d := FindDevice("blip-test-none"); d != "" {
		t.Fatal(d)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := WaitDevice(ctx, "blip-test-none"); err == nil {
		t.Fatal("found")
	}
}

func TestMajorMinor(t *testing.T) {
	// makedev(259, 70000) per glibc encoding.
	maj, mnr := uint64(259), uint64(70000)
	d := (maj&0xfff)<<8 | (maj&^0xfff)<<32 | mnr&0xff | (mnr&^0xff)<<12
	if major(d) != maj || minor(d) != mnr {
		t.Fatal(major(d), minor(d))
	}
	if major(0x810) != 8 || minor(0x810) != 16 {
		t.Fatal(major(0x810), minor(0x810))
	}
}
