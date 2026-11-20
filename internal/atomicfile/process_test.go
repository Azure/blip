// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package atomicfile

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// checkpointEffects executes the actual filesystem adapter, then stops before
// the operation receives its result. The parent can SIGKILL at that boundary.
type checkpointEffects struct{ osEffects }

func (e *checkpointEffects) Execute(effect Effect) Result {
	r := e.osEffects.Execute(effect)
	if r.Err == nil {
		fmt.Fprintln(os.Stdout, effect.Kind)
		var ack [1]byte
		if _, err := io.ReadFull(os.Stdin, ack[:]); err != nil {
			os.Exit(2)
		}
	}
	return r
}

func TestReplacementCrashHelper(t *testing.T) {
	path := os.Getenv("BLIP_ATOMICFILE_CRASH_CHILD")
	if path == "" {
		return
	}
	if err := Run(New(path, []byte("replacement"), 0o600), &checkpointEffects{}); err != nil {
		t.Fatal(err)
	}
}

// This qualifies process-death behavior of the real adapter, including crashes
// after an applied syscall but before acknowledgement. It deliberately does not
// stand in for host power loss: the kernel's page cache survives a child death.
func TestReplacementProcessCrash(t *testing.T) {
	for _, phase := range []Kind{Create, Write, Chmod, Sync, Close, Rename, SyncDir} {
		t.Run(string(phase), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state")
			if err := Replace(path, []byte("original"), 0o640); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestReplacementCrashHelper$")
			cmd.Env = append(os.Environ(), "BLIP_ATOMICFILE_CRASH_CHILD="+path)
			output, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			input, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			cmd.Stderr = os.Stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			defer func() {
				if !waited {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
				}
			}()
			scanner := bufio.NewScanner(output)
			reached := false
			for scanner.Scan() {
				if scanner.Text() == string(phase) {
					reached = true
					break
				}
				if _, err := input.Write([]byte{1}); err != nil {
					t.Fatal(err)
				}
			}
			if !reached {
				t.Fatalf("child did not reach %s: scan=%v context=%v", phase, scanner.Err(), ctx.Err())
			}
			if err := cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			err = cmd.Wait()
			waited = true
			if err == nil || ctx.Err() != nil {
				t.Fatalf("expected injected process death, got exit=%v context=%v", err, ctx.Err())
			}
			want := "original"
			if phase == Rename || phase == SyncDir {
				want = "replacement"
			}
			if data, err := os.ReadFile(path); err != nil || string(data) != want {
				t.Fatalf("after %s crash: data=%q err=%v, want %q", phase, data, err, want)
			}
			if err := Replace(path, []byte("recovered"), 0o600); err != nil {
				t.Fatalf("recovery with orphan temporary files: %v", err)
			}
			if data, err := os.ReadFile(path); err != nil || string(data) != "recovered" {
				t.Fatalf("recovery: data=%q err=%v", data, err)
			}
		})
	}
}
