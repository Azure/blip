package tlskeys

import (
	"bufio"
	"encoding/hex"
	"strings"
	"testing"
)

func TestDerivePSK(t *testing.T) {
	// Same value as: printf %s "$HN" | openssl dgst -sha256 -hmac "$KEY"
	got := hex.EncodeToString(DerivePSK([]byte("clusterkey-test-32-bytes-xxxxxxx"), "nqn.2026-01.com.example.blip:host:c1"))
	want := "4b301f17e2c27612e9ac2674e9026bf625b2707f5f195884e7ffcb0c32aa3b76"
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestIdentity(t *testing.T) {
	id := Identity("nqn.h", "nqn.s")
	if id != "NVMe0R01 nqn.h nqn.s" {
		t.Fatal(id)
	}
	if Description(id, Target) != id+" target" || Description(id, Host) != id {
		t.Fatal("description")
	}
}

func TestFindKeyring(t *testing.T) {
	in := `059af268 I--Q---     7 perm 3f030000  1000  1000 keyring   _ses: 1
1dc06b61 I------     1 perm 1f1f0000     0     0 keyring   .nvme: empty
09baf7ee I--Q---     1 perm 3b010000     0     0 psk       NVMe0R01 a b: 32
`
	id, err := findKeyring(bufio.NewScanner(strings.NewReader(in)))
	if err != nil || id != 0x1dc06b61 {
		t.Fatal(id, err)
	}
	if _, err := findKeyring(bufio.NewScanner(strings.NewReader(""))); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseDescribe(t *testing.T) {
	typ, desc, ok := parseDescribe("psk;0;0;3b010000;NVMe0R01 a;b c")
	if !ok || typ != "psk" || desc != "NVMe0R01 a;b c" {
		t.Fatal(typ, desc, ok)
	}
}
