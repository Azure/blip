package names

import (
	"strings"
	"testing"
)

func TestSubsystemNQN(t *testing.T) {
	for _, rw := range []bool{false, true} {
		n := SubsystemNQN("s1", "abc-1", rw)
		node, id, gotRW, ok := ParseSubsystemNQN(n)
		if !ok || node != "s1" || id != "abc-1" || gotRW != rw {
			t.Fatalf("%s: got %q %q %v %v", n, node, id, gotRW, ok)
		}
	}
	if _, _, _, ok := ParseSubsystemNQN(HostNQN("s1")); ok {
		t.Fatal("host NQN parsed as subsystem")
	}
	if got := SubsystemNQN("s1", "x", true); got != "nqn.2026-01.com.example.blip:s1:c-x:rw" {
		t.Fatal(got)
	}
}

func TestHostID(t *testing.T) {
	a, b := HostID(HostNQN("a")), HostID(HostNQN("b"))
	if a == b || len(a) != 36 || a != HostID(HostNQN("a")) {
		t.Fatalf("%s %s", a, b)
	}
}

func TestParseDM(t *testing.T) {
	cases := map[string]DMName{
		Pool("n1"):                          {Kind: KindPool},
		PoolMeta("n1"):                      {Kind: KindPoolMeta},
		PoolData("n1"):                      {Kind: KindPoolData},
		Origin("n1", "a-1", "b2"):           {Kind: KindOrigin, AllocID: "a-1", AttID: "b2"},
		Overlay("n1", 42, "a-1", "b2"):      {Kind: KindOverlay, ThinID: 42, AllocID: "a-1", AttID: "b2"},
		LocalSnap("n1", 43, "a-1", "b2", 7): {Kind: KindLocalSnap, ThinID: 43, AllocID: "a-1", AttID: "b2", Seq: 7},
		SlotDisk("n1", "3", 5):              {Kind: KindSlotDisk, SlotID: "3", Disk: 5},
	}
	for name, want := range cases {
		got, ok := ParseDM("n1", name)
		if !ok || got != want {
			t.Errorf("%s: got %+v %v", name, got, ok)
		}
		if _, ok := ParseDM("n2", name); ok {
			t.Errorf("%s parsed for other node", name)
		}
	}
	// Node names may contain "-" and must not be confused.
	if _, ok := ParseDM("n", Pool("n-mp")); ok {
		t.Error("prefix node matched")
	}
	for _, bad := range []string{"blip_n1_ov_x_a_b", "blip_n1_ls_1_a_b", "blip_n1_slot_3_x", "blip_n1_mp_a", "blip_n1_mp_a__"} {
		if _, ok := ParseDM("n1", bad); ok {
			t.Errorf("%s parsed", bad)
		}
	}
	if CheckDM(LocalSnap(strings.Repeat("n", 63), 1<<24-1, "0123456789abcdef", "0123456789abcdef", 1<<40)) == nil {
		t.Error("long name accepted")
	}
}

func TestCheck(t *testing.T) {
	for _, s := range []string{"a", "kind-worker2", "0f3c.x"} {
		if Check("x", s) != nil {
			t.Error(s)
		}
	}
	for _, s := range []string{"", "A", "a:b", "a/b", "-a", "a_b"} {
		if Check("x", s) == nil {
			t.Error(s)
		}
	}
}
