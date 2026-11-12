package boot

import (
	"slices"
	"testing"
	"time"
)

func TestParseMountOptions(t *testing.T) {
	f, d := ParseMountOptions("ro,noatime, discard,commit=60,defaults")
	if f != 0x1|0x400 || d != "discard,commit=60" {
		t.Fatalf("%#x %q", f, d)
	}
	if f, d := ParseMountOptions("ro,rw"); f != 0 || d != "" {
		t.Fatalf("%#x %q", f, d)
	}
	if f, d := ParseMountOptions(""); f != 0 || d != "" {
		t.Fatal(f, d)
	}
}

func TestInitArgv(t *testing.T) {
	if a, _ := InitArgv(nil); !slices.Equal(a, []string{"/sbin/init"}) {
		t.Fatal(a)
	}
	if _, err := InitArgv([]string{"init"}); err == nil {
		t.Fatal("relative accepted")
	}
	if a, _ := InitArgv([]string{"/bin/sh", "-c", "x"}); len(a) != 3 {
		t.Fatal(a)
	}
}

func TestInitEnv(t *testing.T) {
	e := InitEnv([]string{"HOME=/", "TERM=vt100"})
	if !slices.Contains(e, "TERM=vt100") || slices.Contains(e, "TERM=linux") || len(e) != 3 {
		t.Fatal(e)
	}
}

func TestWaitFor(t *testing.T) {
	ev := make(chan struct{}, 1)
	n := 0
	go func() { ev <- struct{}{} }()
	if !WaitFor(func() bool { n++; return n >= 2 }, ev, time.Hour, time.Second) {
		t.Fatal("event did not trigger check")
	}
	n = 0
	if !WaitFor(func() bool { n++; return n >= 3 }, nil, 10*time.Millisecond, time.Second) {
		t.Fatal("rescan did not trigger check")
	}
	start := time.Now()
	if WaitFor(func() bool { return false }, nil, 10*time.Millisecond, 50*time.Millisecond) || time.Since(start) > time.Second {
		t.Fatal("timeout")
	}
}
