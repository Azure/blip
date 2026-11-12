package storage

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/example/blip/internal/storage/dm"
	"github.com/example/blip/internal/storage/extent"
)

func TestBlocksToRanges(t *testing.T) {
	got := blocksToRanges([]dm.BlockRange{{Begin: 0, Length: 3}, {Begin: 10, Length: 1}}, 128)
	want := []extent.Range{{Off: 0, Len: 3 * 65536}, {Off: 10 * 65536, Len: 65536}}
	if !reflect.DeepEqual(got, want) {
		t.Fatal(got)
	}
}

func TestPoolHeader(t *testing.T) {
	p := filepath.Join(t.TempDir(), "disk")
	if err := os.WriteFile(p, header(), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &ComputeNode{cfg: ComputeConfig{Device: p}}
	if got := c.PoolBootID(); got == "" || got != bootID() {
		t.Fatalf("boot id %q", got)
	}
	os.WriteFile(p, make([]byte, 4096), 0o600)
	if got := c.PoolBootID(); got != "" {
		t.Fatalf("boot id %q on blank disk", got)
	}
}

func TestJournal(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "journal.json")
	j, err := loadJournal(p, "n1")
	if err != nil || len(j.Thins) != 0 {
		t.Fatal(j, err)
	}
	j.Thins[7] = &thinEntry{State: thinLive, Kind: kindLocalSnap, AllocID: "a", AttID: "b", Seq: 3}
	j.Attachments[attKey("a", "b")] = &attEntry{AllocID: "a", AttID: "b", Generation: 4, SlotDisk: -1}
	if err := j.save(); err != nil {
		t.Fatal(err)
	}
	j2, err := loadJournal(p, "n1")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(j2.Thins, j.Thins) || !reflect.DeepEqual(j2.Attachments, j.Attachments) || j2.maxID() != 7 {
		t.Fatalf("%+v", j2)
	}
	// Another node's journal is ignored.
	if j3, _ := loadJournal(p, "n2"); len(j3.Thins) != 0 {
		t.Fatal("journal of another node used")
	}
	// A journal of another boot is ignored.
	j.BootID = "other"
	if err := j.save(); err != nil {
		t.Fatal(err)
	}
	if j4, _ := loadJournal(p, "n1"); len(j4.Thins) != 0 {
		t.Fatal("journal of another boot used")
	}
}
