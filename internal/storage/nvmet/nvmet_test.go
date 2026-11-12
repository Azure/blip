package nvmet

import (
	"os"
	"path/filepath"
	"testing"
)

// A port left half configured by an interrupted EnsurePort is completed;
// one with subsystems and other attributes is refused. A plain directory
// stands in for configfs.
func TestEnsurePortInterrupted(t *testing.T) {
	root := t.TempDir()
	tg := &Target{Root: root}
	p := Port{ID: 1234, Addr: "10.0.0.1", Svc: 4420}
	dir := tg.portDir(p.ID)
	if err := os.MkdirAll(filepath.Join(dir, "subsystems"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "addr_trtype"), []byte("tcp\n"), 0o644)
	if err := tg.EnsurePort(p); err != nil {
		t.Fatal(err)
	}
	if got := readAttr(dir, "addr_traddr"); got != "10.0.0.1" {
		t.Fatalf("addr_traddr = %q", got)
	}
	if err := tg.EnsurePort(p); err != nil {
		t.Fatal(err)
	}
	p.Addr = "10.0.0.2"
	os.Mkdir(filepath.Join(dir, "subsystems", "nqn.x"), 0o755)
	if err := tg.EnsurePort(p); err == nil {
		t.Fatal("port in use with another address accepted")
	}
}
