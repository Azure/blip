package slot

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/example/blip/internal/api"
	"github.com/example/blip/internal/meta"
)

func TestConsoleTruncation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "serial.log")
	var out bytes.Buffer
	c := &console{path: p, w: &out}
	if c.poll() {
		t.Fatal("missing file is not a truncation")
	}
	os.WriteFile(p, []byte("boot 1\nKernel panic - not syncing: old\n"), 0o644)
	c.poll()
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("more\n")
	f.Close()
	c.poll()
	if out.String() != "boot 1\nKernel panic - not syncing: old\nmore\n" {
		t.Fatalf("%q", out.String())
	}
	// Reboot: truncated in place.
	os.WriteFile(p, []byte("b2\n"), 0o644)
	if !c.poll() {
		t.Fatal("truncation not seen")
	}
	if c.text() != "b2\n" {
		t.Fatalf("tail %q", c.text())
	}
	// Replaced by a new file.
	os.Remove(p)
	os.WriteFile(p, []byte("boot 3 is longer than before\n"), 0o644)
	if !c.poll() || c.text() != "boot 3 is longer than before\n" {
		t.Fatalf("replace: %q", c.text())
	}
	c.close()
}

func TestEventReader(t *testing.T) {
	p := filepath.Join(t.TempDir(), "events.json")
	r := &eventReader{path: p}
	if len(r.read()) != 0 {
		t.Fatal("events from nothing")
	}
	ev := func(src, e string) string {
		return "{\n  \"timestamp\": {\n    \"secs\": 0,\n    \"nanos\": 1\n  },\n  \"source\": \"" + src + "\",\n  \"event\": \"" + e + "\",\n  \"properties\": null\n}\n\n"
	}
	full := ev("vm", "booted") + ev("vm", "rebooting")
	partial := ev("guest", "panic")
	os.WriteFile(p, []byte(full+partial[:20]), 0o644)
	got := r.read()
	if len(got) != 2 || got[1].String() != "vm rebooting" {
		t.Fatalf("%+v", got)
	}
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(partial[20:])
	f.Close()
	got = r.read()
	if len(got) != 1 || got[0].String() != "guest panic" {
		t.Fatalf("%+v", got)
	}
}

func TestParsePanic(t *testing.T) {
	text := "[    1.0] Run /init\n[    1.2] Kernel panic - not syncing: Attempted to kill init! exitcode=0x00000300\n[    1.2] CPU: 0\n"
	line, code, ok := parsePanic(text)
	if !ok || code == nil || *code != 3 || !strings.HasPrefix(line, "Kernel panic") {
		t.Fatal(line, code, ok)
	}
	line, code, ok = parsePanic("Kernel panic - not syncing: sysrq triggered crash\n")
	if !ok || code != nil || line != "Kernel panic - not syncing: sysrq triggered crash" {
		t.Fatal(line, code, ok)
	}
	if _, _, ok := parsePanic("all fine\n"); ok {
		t.Fatal("panic in a quiet log")
	}
}

func TestClassify(t *testing.T) {
	five, three, zero := 5, 3, 0
	cases := []struct {
		name    string
		rec     ExitRecord
		g       *meta.GuestData
		reboots int
		line    string
		init    *int
		reason  string
		msg     string
		code    *int
		boots   int
	}{
		{name: "poweroff", rec: ExitRecord{Cause: "exited"}, g: &meta.GuestData{State: meta.StateExec, BootCount: 1}, reason: api.ReasonSucceeded, msg: "the guest powered off", boots: 1},
		{name: "poweroff with 0", rec: ExitRecord{Cause: "exited"}, g: &meta.GuestData{State: meta.StateExec, BootCount: 1, ExitCode: &zero}, reason: api.ReasonSucceeded, msg: "the guest powered off", code: &zero, boots: 1},
		{name: "poweroff with code", rec: ExitRecord{Cause: "exited"}, g: &meta.GuestData{State: meta.StateExec, BootCount: 2, ExitCode: &five}, reason: api.ReasonError, msg: "the guest powered off with exit code 5", code: &five, boots: 2},
		{name: "crash", rec: ExitRecord{Cause: "exited", ExitCode: 1}, reason: api.ReasonHypervisorExited, msg: "the VM exited (crashed, status 1)"},
		{name: "signal", rec: ExitRecord{Cause: "exited", ExitCode: -1, Signal: "killed"}, reason: api.ReasonHypervisorExited, msg: "the VM exited (crashed, killed)"},
		{name: "killed", rec: ExitRecord{Cause: "killed", ExitCode: -1}, reason: api.ReasonHypervisorExited, msg: "the VM was killed (killed)", reboots: 2, boots: 3},
		{name: "stopped", rec: ExitRecord{Cause: "stopped"}, reason: api.ReasonHypervisorExited, msg: "the VM was killed (stopped)"},
		{name: "deadline", rec: ExitRecord{Cause: "deadline"}, reason: api.ReasonTTLExceeded, msg: "the deadline passed"},
		{name: "backend", rec: ExitRecord{Cause: "backend"}, reason: api.ReasonHypervisorExited, msg: "the VM exited (backend, status 0)"},
		{name: "panic", rec: ExitRecord{Cause: "panic"}, line: "Kernel panic - not syncing: x", reason: api.ReasonGuestPanic, msg: "the guest kernel panicked: Kernel panic - not syncing: x"},
		{name: "init exited", rec: ExitRecord{Cause: "panic"}, init: &three, reason: api.ReasonInitExited, msg: "init exited with code 3", code: &three},
		{name: "guest code wins", rec: ExitRecord{Cause: "panic"}, init: &three, g: &meta.GuestData{State: meta.StateExec, ExitCode: &five}, reason: api.ReasonInitExited, msg: "init exited with code 5", code: &five},
		{name: "boot failed", rec: ExitRecord{Cause: "exited"}, g: &meta.GuestData{State: meta.StateFail, Reason: "RootMountFailed", Message: "bad", BootCount: 1}, reason: api.ReasonBootFailed, msg: "boot failed (RootMountFailed): bad", boots: 1},
		{name: "fail then killed", rec: ExitRecord{Cause: "killed"}, g: &meta.GuestData{State: meta.StateFail, Reason: "RootNotFound"}, reason: api.ReasonHypervisorExited, msg: "the VM was killed (killed)"},
	}
	for _, c := range cases {
		rec := c.rec
		Classify(&rec, c.g, c.reboots, c.line, c.init)
		if rec.Reason != c.reason || rec.Message != c.msg || rec.BootCount != c.boots || (c.code == nil) != (rec.GuestExitCode == nil) || (c.code != nil && *c.code != *rec.GuestExitCode) {
			t.Errorf("%s: %+v", c.name, rec)
		}
	}
}

func TestReadyOnWaiting(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, FileMeta)
	if err := meta.Create(p); err != nil {
		t.Fatal(err)
	}
	s := &supervisor{c: &Config{RunDir: dir}, metaPath: p}
	s.checkMeta()
	if exists(filepath.Join(dir, FileReady)) {
		t.Fatal("ready before the guest waits")
	}
	d, err := meta.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := d.WriteGuest(&meta.GuestData{State: meta.StateWaiting, BootCount: 1}); err != nil {
		t.Fatal(err)
	}
	s.checkMeta()
	if !exists(filepath.Join(dir, FileReady)) {
		t.Fatal("not ready")
	}
	// After the assignment a WAITING (reboot) does not mark it ready again.
	os.Remove(filepath.Join(dir, FileReady))
	os.WriteFile(filepath.Join(dir, FileAssigned), nil, 0o644)
	s.ready = false
	s.checkMeta()
	if exists(filepath.Join(dir, FileReady)) {
		t.Fatal("ready after assignment")
	}
}
