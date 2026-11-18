package guest

import (
	"strings"
	"testing"
)

func TestWorkdirInRoot(t *testing.T) {
	for _, tc := range []struct {
		dir  string
		want string
	}{
		{"", "/"},
		{"/", "/"},
		{"/tmp", "/tmp"},
		{"/tmp/", "/tmp"},
		{"/tmp/../etc", "/etc"},
		{"tmp", "/tmp"},
		{"tmp/", "/tmp"},
		{"./tmp", "/tmp"},
		{"a/../tmp", "/tmp"},
		{"../etc", "/etc"},
		{"../../../etc", "/etc"},
		{"..", "/"},
	} {
		if got := workdirInRoot(tc.dir); got != tc.want {
			t.Errorf("workdirInRoot(%q) = %q, want %q", tc.dir, got, tc.want)
		}
	}
}

// A relative workdir must be resolved inside the workload root before it is
// validated or passed to os.StartProcess; the guest init's cwd after chroot is
// outside the root, so "tmp" used to mean the initramfs /tmp.
func TestStartProcNormalizesRelativeWorkdir(t *testing.T) {
	g := testGuest(t)
	_, _, err := g.startProc(procSpec{argv: []string{"/bin/sh"}, dir: "relative/dir"}, nil)
	if err == nil {
		t.Fatal("startProc accepted a missing relative workdir")
	}
	if want := "chdir /relative/dir: no such file or directory"; !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want it to contain %q", err, want)
	}

	// ".." is clamped at the root instead of escaping to the guest initramfs.
	// The temp root has /etc, so validation of "../../etc" must pass and the
	// failure must come from starting the (missing) executable.
	_, _, err = g.startProc(procSpec{argv: []string{"/does/not/exist"}, dir: "../../etc"}, nil)
	if err == nil {
		t.Fatal("starting a missing executable unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), "chdir") {
		t.Fatalf("dot-dot workdir was not normalized inside the root: %v", err)
	}
}
