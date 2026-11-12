package dm

import (
	"reflect"
	"strings"
	"testing"

	"github.com/example/blip/internal/storage/devnode"
)

// Output captured from thin_dump 0.9.0 in the spike.
const dumpXML = `<superblock uuid="" time="0" transaction="0" flags="0" version="2" data_block_size="128" nr_data_blocks="0">
  <device dev_id="1" mapped_blocks="12" transaction="0" creation_time="0" snap_time="0">
    <range_mapping origin_begin="0" data_begin="0" length="3" time="0"/>
    <single_mapping origin_block="3" data_block="9" time="0"/>
    <single_mapping origin_block="15" data_block="3" time="0"/>
    <single_mapping origin_block="80" data_block="4" time="0"/>
    <range_mapping origin_begin="1525" data_begin="5" length="6" time="0"/>
    <single_mapping origin_block="4095" data_block="11" time="0"/>
  </device>
  <device dev_id="2" mapped_blocks="1" transaction="0" creation_time="0" snap_time="0">
    <single_mapping origin_block="7" data_block="12" time="0"/>
  </device>
</superblock>
`

func TestParseThinDump(t *testing.T) {
	bs, rs, err := ParseThinDump(strings.NewReader(dumpXML), 1)
	if err != nil {
		t.Fatal(err)
	}
	want := []BlockRange{{0, 4}, {15, 1}, {80, 1}, {1525, 6}, {4095, 1}}
	if bs != 128 || !reflect.DeepEqual(rs, want) {
		t.Fatalf("got %d %v", bs, rs)
	}
	_, rs, err = ParseThinDump(strings.NewReader(dumpXML), 2)
	if err != nil || !reflect.DeepEqual(rs, []BlockRange{{7, 1}}) {
		t.Fatal(rs, err)
	}
	if _, _, err := ParseThinDump(strings.NewReader(dumpXML), 3); err == nil {
		t.Fatal("missing device must fail")
	}
	empty := `<superblock data_block_size="128"><device dev_id="5" mapped_blocks="0"></device></superblock>`
	_, rs, err = ParseThinDump(strings.NewReader(empty), 5)
	if err != nil || len(rs) != 0 {
		t.Fatal(rs, err)
	}
}

// Output captured from thin_delta 0.9.0 in the spike, plus left/right only.
const deltaXML = `<superblock uuid="" time="2" transaction="4" data_block_size="128" nr_data_blocks="0">
  <diff left="2" right="3">
    <same begin="0" length="7"/>
    <different begin="7" length="2"/>
    <right_only begin="9" length="1"/>
    <same begin="10" length="91"/>
    <different begin="101" length="1"/>
    <left_only begin="200" length="4"/>
    <same begin="250" length="1"/>
  </diff>
</superblock>
`

func TestParseThinDelta(t *testing.T) {
	d, err := ParseThinDelta(strings.NewReader(deltaXML))
	if err != nil {
		t.Fatal(err)
	}
	if d.BlockSectors != 128 ||
		!reflect.DeepEqual(d.Copy, []BlockRange{{7, 3}, {101, 1}}) ||
		!reflect.DeepEqual(d.Zero, []BlockRange{{200, 4}}) {
		t.Fatalf("%+v", d)
	}
	if _, err := ParseThinDelta(strings.NewReader("<superblock data_block_size=\"128\"></superblock>")); err == nil {
		t.Fatal("missing diff must fail")
	}
}

func TestParsePoolStatus(t *testing.T) {
	p, err := ParsePoolStatus("0 2097152 thin-pool 4 280/16384 12/16384 - rw no_discard_passdown error_if_no_space - 1024")
	if err != nil {
		t.Fatal(err)
	}
	if p.TransactionID != 4 || p.UsedMeta != 280 || p.TotalMeta != 16384 || p.UsedData != 12 || p.Mode != "rw" || p.MetaSnapHeld {
		t.Fatalf("%+v", p)
	}
	if p, err := ParsePoolStatus("0 2097152 thin-pool 4 280/16384 12/16384 77 rw no_discard_passdown error_if_no_space - 1024"); err != nil || !p.MetaSnapHeld {
		t.Fatal(p, err)
	}
	if p, err := ParsePoolStatus("0 10 thin-pool Fail"); err != nil || p.Mode != "Fail" {
		t.Fatal(p, err)
	}
}

func TestParseMultipathStatus(t *testing.T) {
	ps, err := ParseMultipathStatus("0 524288 multipath 2 0 0 0 1 1 A 0 3 0 259:15 F 1 259:17 F 1 259:19 A 0 ")
	if err != nil {
		t.Fatal(err)
	}
	want := []MultipathPath{{devnode.Dev{Major: 259, Minor: 15}, false}, {devnode.Dev{Major: 259, Minor: 17}, false}, {devnode.Dev{Major: 259, Minor: 19}, true}}
	if !reflect.DeepEqual(ps, want) {
		t.Fatal(ps)
	}
}

func TestTables(t *testing.T) {
	a, b := devnode.Dev{Major: 259, Minor: 1}, devnode.Dev{Major: 259, Minor: 2}
	if got := MultipathTable(100, []devnode.Dev{a, b}); got != "0 100 multipath 2 queue_mode bio 0 1 1 round-robin 0 2 1 259:1 1000 259:2 1000" {
		t.Error(got)
	}
	if got := ThinTable(100, devnode.Dev{Major: 252, Minor: 0}, 7, &a); got != "0 100 thin 252:0 7 259:1" {
		t.Error(got)
	}
	if got := ThinTable(100, devnode.Dev{Major: 252, Minor: 0}, 7, nil); got != "0 100 thin 252:0 7" {
		t.Error(got)
	}
	if got := ThinPoolTable(2048, a, b, 128); got != "0 2048 thin-pool 259:1 259:2 128 0 2 ignore_discard error_if_no_space" {
		t.Error(got)
	}
}

func TestParseInfo(t *testing.T) {
	in := "blip_c1_pool|BLIP-blip_c1_pool|252|0|1|L--w\nblip_c1_mp_a|BLIP-blip_c1_mp_a|252|3|0|L-sr\n"
	is, err := parseInfo(in)
	if err != nil || len(is) != 2 {
		t.Fatal(is, err)
	}
	if is[1].Dev != (devnode.Dev{Major: 252, Minor: 3}) || !is[1].Suspended || !is[1].ReadOnly || is[0].Open != 1 {
		t.Fatalf("%+v", is)
	}
}

func TestParseThinIDs(t *testing.T) {
	ids, err := ParseThinIDs(strings.NewReader(dumpXML))
	if err != nil || !reflect.DeepEqual(ids, []uint32{1, 2}) {
		t.Fatal(ids, err)
	}
	ids, err = ParseThinIDs(strings.NewReader(`<superblock data_block_size="128"></superblock>`))
	if err != nil || len(ids) != 0 {
		t.Fatal(ids, err)
	}
	if _, err := ParseThinIDs(strings.NewReader(``)); err == nil {
		t.Fatal("empty output accepted")
	}
}
