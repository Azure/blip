// Package boot implements blip-boot, the initramfs /init stub: it waits for an
// allocation on the metadata disk, mounts the root disk and execs the guest
// init (switch_root semantics).
package boot

import (
	"errors"
	"strings"
	"time"
)

// DefaultInit is used when the host data has no init argv.
var DefaultInit = []string{"/sbin/init"}

// Mount flag names understood in RootMountOptions; the rest is fs data.
var mountFlags = map[string]struct {
	set   bool
	value uintptr
}{
	// Values match MS_* from <sys/mount.h>.
	"ro":         {true, 0x1},
	"rw":         {false, 0x1},
	"nosuid":     {true, 0x2},
	"suid":       {false, 0x2},
	"nodev":      {true, 0x4},
	"dev":        {false, 0x4},
	"noexec":     {true, 0x8},
	"exec":       {false, 0x8},
	"sync":       {true, 0x10},
	"async":      {false, 0x10},
	"dirsync":    {true, 0x80},
	"noatime":    {true, 0x400},
	"atime":      {false, 0x400},
	"nodiratime": {true, 0x800},
	"diratime":   {false, 0x800},
	"relatime":   {true, 0x200000},
	"norelatime": {false, 0x200000},
	"lazytime":   {true, 1 << 25},
	"defaults":   {false, 0},
}

// ParseMountOptions splits a comma-separated option string into mount(2)
// flags and filesystem data.
func ParseMountOptions(s string) (flags uintptr, data string) {
	var rest []string
	for _, o := range strings.Split(s, ",") {
		o = strings.TrimSpace(o)
		if o == "" {
			continue
		}
		f, ok := mountFlags[o]
		switch {
		case !ok:
			rest = append(rest, o)
		case f.set:
			flags |= f.value
		default:
			flags &^= f.value
		}
	}
	return flags, strings.Join(rest, ",")
}

// InitArgv returns argv or the default, validating that it is absolute.
func InitArgv(argv []string) ([]string, error) {
	if len(argv) == 0 {
		return DefaultInit, nil
	}
	if !strings.HasPrefix(argv[0], "/") {
		return nil, errors.New("init path must be absolute: " + argv[0])
	}
	return argv, nil
}

// InitEnv returns the environment for init: env with PATH and TERM defaulted.
func InitEnv(env []string) []string {
	out := make([]string, 0, len(env)+2)
	hasPath, hasTerm := false, false
	for _, e := range env {
		hasPath = hasPath || strings.HasPrefix(e, "PATH=")
		hasTerm = hasTerm || strings.HasPrefix(e, "TERM=")
		out = append(out, e)
	}
	if !hasPath {
		out = append(out, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	}
	if !hasTerm {
		out = append(out, "TERM=linux")
	}
	return out
}

// WaitFor calls check until it returns true, rechecking whenever events
// fires and at least every rescan. It returns false on timeout (0 = never).
func WaitFor(check func() bool, events <-chan struct{}, rescan, timeout time.Duration) bool {
	var deadline <-chan time.Time
	if timeout > 0 {
		t := time.NewTimer(timeout)
		defer t.Stop()
		deadline = t.C
	}
	tick := time.NewTicker(rescan)
	defer tick.Stop()
	for {
		if check() {
			return true
		}
		select {
		case <-events:
		case <-tick.C:
		case <-deadline:
			return check()
		}
	}
}
