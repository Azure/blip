// Package run executes external tools (dmsetup, lvm, thin_dump, mkfs.ext4)
// with a timeout and an environment that keeps them away from udev.
package run

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// DefaultTimeout bounds every command that has no deadline in its context.
const DefaultTimeout = 2 * time.Minute

// NoUdevEnv is added to every command. Containers have no udev, so
// device-mapper and LVM must not wait for udev or rely on its rules.
var NoUdevEnv = []string{
	"DM_DISABLE_UDEV=1",
	"LVM_SUPPRESS_FD_WARNINGS=1",
	"LC_ALL=C",
}

// Error is returned when a command fails. It includes stderr.
type Error struct {
	Cmd    string
	Err    error
	Stderr string
}

func (e *Error) Error() string {
	s := strings.TrimSpace(e.Stderr)
	if s == "" {
		return fmt.Sprintf("%s: %v", e.Cmd, e.Err)
	}
	return fmt.Sprintf("%s: %v: %s", e.Cmd, e.Err, s)
}

func (e *Error) Unwrap() error { return e.Err }

// Hook, if set, is called before (after=false) and after (after=true,
// err is the outcome) every external command and every kernel change
// made through Step. A non-nil return value replaces the outcome: before
// the step, the step does not run. It is for fault and crash injection in
// tests only and must be nil in production.
var Hook func(name string, args []string, after bool, err error) error

// Step runs fn, a kernel change that does not go through Cmd (configfs,
// /dev/nvme-fabrics, keyctl), under Hook.
func Step(name string, args []string, fn func() error) error {
	if Hook == nil {
		return fn()
	}
	if err := Hook(name, args, false, nil); err != nil {
		return err
	}
	err := fn()
	if herr := Hook(name, args, true, err); herr != nil {
		return herr
	}
	return err
}

// Cmd runs name with args and returns stdout. stdin may be nil.
func Cmd(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	if Hook != nil {
		var out []byte
		err := Step(name, args, func() (err error) {
			out, err = cmd(ctx, stdin, name, args...)
			return err
		})
		return out, err
	}
	return cmd(ctx, stdin, name, args...)
}

func cmd(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultTimeout)
		defer cancel()
	}
	c := exec.CommandContext(ctx, name, args...)
	c.Env = append(os.Environ(), NoUdevEnv...)
	c.WaitDelay = 5 * time.Second
	if stdin != nil {
		c.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	c.Stdout = &out
	c.Stderr = &errb
	if err := c.Run(); err != nil {
		return out.Bytes(), &Error{Cmd: name + " " + strings.Join(args, " "), Err: err, Stderr: filterNoise(errb.String())}
	}
	return out.Bytes(), nil
}

// filterNoise drops the warning dmsetup prints when udev runs on the host
// but DM_DISABLE_UDEV is set.
func filterNoise(s string) string {
	var keep []string
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, "DM_DISABLE_UDEV environment variable is set") {
			continue
		}
		keep = append(keep, l)
	}
	return strings.Join(keep, "\n")
}
