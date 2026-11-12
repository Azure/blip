package lvm

import (
	"strings"
	"testing"

	"github.com/example/blip/internal/storage/devnode"
)

// Output shape of lvm 2.03.16 lvs -a --reportformat json --units b --nosuffix.
const lvsOut = `{
  "report": [
    {
      "lv": [
        {"lv_name":"c-root", "lv_tags":"blip.kind=content,blip.owner=x", "thin_id":"1", "pool_lv":"pool", "origin":"", "lv_size":"268435456", "lv_time":"2026-11-05 21:33:52 +0000", "lv_active":"active", "lv_kernel_major":"252", "lv_kernel_minor":"6", "data_percent":"3.12", "metadata_percent":""},
        {"lv_name":"c-seed", "lv_tags":"blip.kind=seed,blip.sealed", "thin_id":"2", "pool_lv":"pool", "origin":"c-root", "lv_size":"268435456", "lv_time":"2026-11-05 21:33:52 +0000", "lv_active":"", "lv_kernel_major":"-1", "lv_kernel_minor":"-1", "data_percent":"3.15", "metadata_percent":""},
        {"lv_name":"[lvol0_pmspare]", "lv_tags":"", "thin_id":"", "pool_lv":"", "origin":"", "lv_size":"67108864", "lv_time":"2026-11-05 21:33:48 +0000", "lv_active":"", "lv_kernel_major":"-1", "lv_kernel_minor":"-1", "data_percent":"", "metadata_percent":""},
        {"lv_name":"pool", "lv_tags":"", "thin_id":"", "pool_lv":"", "origin":"", "lv_size":"1073741824", "lv_time":"2026-11-05 21:33:48 +0000", "lv_active":"active", "lv_kernel_major":"252", "lv_kernel_minor":"5", "data_percent":"0.81", "metadata_percent":"10.10"},
        {"lv_name":"[pool_tdata]", "lv_tags":"", "thin_id":"", "pool_lv":"", "origin":"", "lv_size":"1073741824", "lv_time":"2026-11-05 21:33:48 +0000", "lv_active":"active", "lv_kernel_major":"252", "lv_kernel_minor":"3", "data_percent":"", "metadata_percent":""},
        {"lv_name":"[pool_tmeta]", "lv_tags":"", "thin_id":"", "pool_lv":"", "origin":"", "lv_size":"67108864", "lv_time":"2026-11-05 21:33:48 +0000", "lv_active":"active", "lv_kernel_major":"252", "lv_kernel_minor":"2", "data_percent":"", "metadata_percent":""}
      ]
    }
  ]
}`

func TestParseReport(t *testing.T) {
	r, err := parseReport([]byte(lvsOut), "blip-s1", "pool")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.LVs) != 2 || r.DataPercent != 0.81 || r.MetaPercent != 10.10 || r.PoolSize != 1<<30 {
		t.Fatalf("%+v", r)
	}
	if r.PoolDM != "blip--s1-pool-tpool" || r.MetaDev != (devnode.Dev{Major: 252, Minor: 2}) {
		t.Fatalf("%+v", r)
	}
	root := r.LVs["c-root"]
	if !root.Active || root.Dev != (devnode.Dev{Major: 252, Minor: 6}) || root.ThinID != 1 || root.TagValue("blip.kind") != "content" || root.Created.IsZero() {
		t.Fatalf("%+v", root)
	}
	seed := r.LVs["c-seed"]
	if seed.Active || seed.Origin != "c-root" || !seed.HasTag("blip.sealed") || seed.Size != 268435456 {
		t.Fatalf("%+v", seed)
	}
}

func TestConfigString(t *testing.T) {
	l, _ := New(Config{VG: "v", Devices: []string{"/dev/loop20"}})
	s := l.configString()
	if !strings.Contains(s, `global_filter=["a|^/dev/loop20$|","r|.*|"]`) || !strings.Contains(s, "udev_rules=0") {
		t.Fatal(s)
	}
}

func TestDMName(t *testing.T) {
	if got := DMName("blip-s1", "c-a-b"); got != "blip--s1-c--a--b" {
		t.Fatal(got)
	}
}
