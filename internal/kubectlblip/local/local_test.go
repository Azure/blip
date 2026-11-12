package local

import (
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestKeyRoundtrip(t *testing.T) {
	d := Dir{Path: t.TempDir() + "/blip"}
	line, err := d.EnsureKey()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(line, "ssh-ed25519 ") || !strings.Contains(line, " blip@") {
		t.Fatalf("pub line %q", line)
	}
	for name, want := range map[string]os.FileMode{"": 0o700, KeyFile: 0o600, PubKeyFile: 0o644} {
		st, err := os.Stat(d.File(name))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != want {
			t.Errorf("%q mode %v, want %v", name, st.Mode().Perm(), want)
		}
	}
	b, _ := os.ReadFile(d.File(KeyFile))
	signer, err := ssh.ParsePrivateKey(b)
	if err != nil {
		t.Fatal(err)
	}
	if KeyFields(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) != KeyFields(line) {
		t.Fatal("private and public key differ")
	}
	again, err := d.EnsureKey()
	if err != nil || again != line {
		t.Fatalf("reload %q %v", again, err)
	}
	os.Remove(d.File(PubKeyFile))
	again, err = d.EnsureKey()
	if err != nil || KeyFields(again) != KeyFields(line) {
		t.Fatalf("regenerated pub %q %v", again, err)
	}
	if !ContainsKey("# c\nssh-rsa AAAAB3 x\n"+KeyFields(line)+" other", line) {
		t.Fatal("ContainsKey false")
	}
	if ContainsKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtherKey x", line) {
		t.Fatal("ContainsKey true")
	}
}

const hk1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ root@guest"

func TestKnownHosts(t *testing.T) {
	d := Dir{Path: t.TempDir()}
	other := Dir{Path: t.TempDir()}
	_, _ = other.EnsureKey()
	pb, _ := os.ReadFile(other.File(PubKeyFile))
	hk2 := strings.TrimSpace(string(pb))
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(d.UpsertKnownHost("blip/c/ns/a", hk1))
	must(d.UpsertKnownHost("blip/c/ns/b", hk1))
	must(d.UpsertKnownHost("blip/c/ns/a", hk2))
	b, _ := os.ReadFile(d.File(KnownHostsFile))
	want := "blip/c/ns/b " + KeyFields(hk1) + "\nblip/c/ns/a " + KeyFields(hk2) + "\n"
	if string(b) != want {
		t.Fatalf("got\n%s\nwant\n%s", b, want)
	}
	if err := d.UpsertKnownHost("x", "garbage"); err == nil {
		t.Fatal("accepted invalid key")
	}
}

func TestConfigPrecedence(t *testing.T) {
	d := Dir{Path: t.TempDir()}
	c, err := d.LoadConfig()
	if err != nil || c != (Config{}) {
		t.Fatal(c, err)
	}
	os.WriteFile(d.File(ConfigFile), []byte("volume: v\nsku: big\nttl: 8h\n"), 0o600)
	c, err = d.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	o, err := Resolve(Options{}, c)
	if err != nil || o != (Options{Volume: "v", SKU: "big", TTL: 8 * time.Hour}) {
		t.Fatal(o, err)
	}
	o, err = Resolve(Options{Image: "r/i:1", SKU: "s", TTL: time.Minute}, c)
	if err != nil || o != (Options{Image: "r/i:1", SKU: "s", TTL: time.Minute}) {
		t.Fatal(o, err)
	}
	o, err = Resolve(Options{Volume: "x"}, Config{})
	if err != nil || o != (Options{Volume: "x", SKU: DefaultSKU, TTL: DefaultTTL}) {
		t.Fatal(o, err)
	}
	if _, err := Resolve(Options{}, Config{}); err == nil {
		t.Fatal("no volume accepted")
	}
	if _, err := Resolve(Options{Volume: "a", Image: "b"}, Config{}); err == nil {
		t.Fatal("both accepted")
	}
	os.WriteFile(d.File(ConfigFile), []byte("bogus: 1\n"), 0o600)
	if _, err := d.LoadConfig(); err == nil {
		t.Fatal("unknown field accepted")
	}
}
