package api

import (
	"strings"
	"testing"
)

func TestNames(t *testing.T) {
	if got := LVName("abc"); got != "c-abc" {
		t.Fatal(got)
	}
	if got := ContentIDFromLV("c-abc"); got != "abc" {
		t.Fatal(got)
	}
	if got := ContentIDFromLV("pool"); got != "" {
		t.Fatal(got)
	}
	if got := SubsystemNQN("s1", "c-abc"); got != "nqn.2026-01.com.example.blip:s1:c-abc" {
		t.Fatal(got)
	}
	if got := HostNQN("s1"); got != "nqn.2026-01.com.example.blip:host:s1" {
		t.Fatal(got)
	}
	// 57 char name + "-" + 5 random chars fits 63.
	if MaxBlipNameLength+1+5 != 63 {
		t.Fatal("name length budget")
	}
}

func TestNodeConfig(t *testing.T) {
	c, err := ParseNodeConfig([]byte(`
hypervisor: kvm
slots: 8
address: 10.0.0.5
storage: {vg: blip-w1}
compute: {device: /dev/loop20}
`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Storage.MaxLVs != 5000 || c.ChunkSizeBytes != 65536 || c.CtrlLossTmoSeconds != 60 {
		t.Fatalf("defaults: %+v", c)
	}
	c, err = ParseNodeConfig([]byte("hypervisor: kvm\nstorage: {}\n"))
	if err != nil || c.Storage.VG != "blip" {
		t.Fatal(c, err)
	}
	for _, bad := range []string{
		"hypervisor: xen",
		"hypervisor: kvm\nslots: 2",
		"hypervisor: kvm\naddress: nope",
		"hypervisor: kvm\nunknown: 1",
		"hypervisor: kvm\ncompute: {device: sda}",
		"hypervisor: kvm\nstorage: {devices: [sdb]}",
	} {
		if _, err := ParseNodeConfig([]byte(bad)); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestStorageConfig(t *testing.T) {
	c, err := ParseStorageConfigMap(map[string]string{"config.yaml": "groups: [{name: sg-1, nodes: [s1, s2, s3]}]"})
	if err != nil {
		t.Fatal(err)
	}
	if c.GroupOf("s2").Name != "sg-1" || c.GroupOf("x") != nil || c.Group("sg-1") == nil {
		t.Fatal("lookup")
	}
	_, err = ParseStorageConfig([]byte("groups: [{name: a, nodes: [s1, s2]}, {name: a, nodes: [s1, s3, s4]}]"))
	if err == nil || !strings.Contains(err.Error(), "exactly 3") || !strings.Contains(err.Error(), "duplicate") || !strings.Contains(err.Error(), "s1") {
		t.Fatal(err)
	}
	if _, err := ParseStorageConfigMap(map[string]string{}); err == nil {
		t.Fatal("missing key")
	}
}

func TestVolumeNames(t *testing.T) {
	uid := "3f9c0a12-aaaa-bbbb-cccc-dddddddddddd"
	id := SnapshotContentID(uid, 41)
	if id != uid+"-41" {
		t.Fatal(id)
	}
	if u, n, ok := ParseSnapshotContentID(id); !ok || u != uid || n != 41 {
		t.Fatal(u, n, ok)
	}
	for _, bad := range []string{"", "41", "-41", uid, uid + "-0", uid + "-x", uid + "-041"} {
		if _, _, ok := ParseSnapshotContentID(bad); ok {
			t.Errorf("parsed %q", bad)
		}
	}
	if got := GuestVolumePath("data"); got != "/dev/disk/by-id/virtio-data" {
		t.Fatal(got)
	}
	if got := SlotDiskPath(3); got != "/dev/blip/disks/3" {
		t.Fatal(got)
	}
}
