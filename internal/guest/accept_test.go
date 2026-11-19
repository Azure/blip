// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package guest

import (
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A transient descriptor-exhaustion error must not kill the listener: once
// descriptors are available again, the next connection is accepted.
func TestAcceptRetriesTemporaryErrors(t *testing.T) {
	oldAccept, oldDelay, oldMax := acceptConn, acceptRetryDelay, acceptMaxDelay
	acceptRetryDelay, acceptMaxDelay = time.Millisecond, 2*time.Millisecond
	t.Cleanup(func() { acceptConn, acceptRetryDelay, acceptMaxDelay = oldAccept, oldDelay, oldMax })

	var mu sync.Mutex
	calls := 0
	acceptConn = func(int) (*os.File, error) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		switch n {
		case 1, 2:
			return nil, &os.SyscallError{Syscall: "accept4", Err: unix.EMFILE}
		case 3:
			r, w, err := os.Pipe()
			if err != nil {
				return nil, err
			}
			w.Close()
			return r, nil
		default:
			// A permanent error ends the loop; the listener was closed.
			return nil, &os.SyscallError{Syscall: "accept4", Err: unix.EBADF}
		}
	}

	g := newGuest(t.TempDir(), t.TempDir())
	accepted := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		g.accept(0, func(f io.ReadWriteCloser) {
			f.Close()
			accepted <- struct{}{}
		})
		close(done)
	}()

	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("accept did not recover after EMFILE")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("accept did not stop on a permanent error")
	}
	mu.Lock()
	got := calls
	mu.Unlock()
	if got != 4 {
		t.Fatalf("accept called %d times, want 4", got)
	}
}
