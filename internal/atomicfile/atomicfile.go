// Package atomicfile replaces files atomically and durably using a temporary
// file in the destination directory. Success means both the file contents and
// mode, and the directory entry naming that file, have been synced.
//
// The parent directory must already exist durably. The filesystem must honor
// file/directory fsync and crash-atomic same-directory rename. Before success,
// a crash can leave the old or new destination and orphan temporary files.
// An error after rename does not imply rollback: the new file is visible and
// may already be durable. Callers must serialize replacements of the same path
// if they need to associate a successful return with a particular version.
package atomicfile

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
)

// Kind is one filesystem effect. Cleanup removes only this operation's temp.
type Kind string

const (
	Create  Kind = "create"
	Write   Kind = "write"
	Chmod   Kind = "chmod"
	Sync    Kind = "sync"
	Close   Kind = "close"
	Rename  Kind = "rename"
	SyncDir Kind = "dirsync"
	Cleanup Kind = "cleanup"
)

// Effect describes the next operation without performing it. Data is immutable
// so machines can be cloned cheaply. Target is used only by Rename.
type Effect struct {
	Kind   Kind
	Path   string
	Target string
	Data   string
	Mode   fs.FileMode
}

// Result is the outcome of one effect. Create returns the unique temporary
// path in Name; Write returns its byte count in N, including on error.
type Result struct {
	Name string
	N    int
	Err  error
}

// Effects owns one operation's resources. A failed Create owns no resource;
// Close releases the descriptor even when it reports an error. Rename errors
// must mean the destination was not replaced (as for local filesystem rename).
type Effects interface {
	Execute(Effect) Result
}

// Error reports the failing effect. Renamed means the replacement is already
// visible, but its durability is uncertain. Unwrap preserves the underlying
// filesystem error for errors.Is/As.
type Error struct {
	Kind    Kind
	Path    string
	Renamed bool
	Err     error
}

func (e *Error) Error() string {
	if e.Renamed {
		return fmt.Sprintf("replace %s: %s: replacement visible, durability uncertain: %v", e.Path, e.Kind, e.Err)
	}
	return fmt.Sprintf("replace %s: %s: %v", e.Path, e.Kind, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

// Operation is a deterministic, resumable decision machine. Next and Complete
// never perform I/O. Execute the returned effect exactly once, then supply its
// result before requesting another effect. A process crash discards the machine
// without running cleanup; recovery can safely read the destination or start a
// fresh replacement. Resuming here means between effects, not across crashes.
type Operation struct {
	path    string
	data    string
	mode    fs.FileMode
	temp    string
	offset  int
	next    Kind
	renamed bool
	err     error
}

func New(path string, data []byte, mode fs.FileMode) *Operation {
	return &Operation{path: path, data: string(data), mode: mode, next: Create}
}

// Clone isolates the machine state. Its input bytes and accumulated errors are
// immutable; effects and their resources must be cloned separately by a model.
func (o *Operation) Clone() *Operation {
	copy := *o
	return &copy
}

func (o *Operation) Done() bool { return o.next == "" }

// Err is the final result once Done is true.
func (o *Operation) Err() error { return o.err }

func (o *Operation) Next() (Effect, bool) {
	if o.Done() {
		return Effect{}, false
	}
	e := Effect{Kind: o.next, Path: o.temp}
	switch o.next {
	case Create:
		e.Path = o.path
	case Write:
		e.Data = o.data[o.offset:]
	case Chmod:
		e.Mode = o.mode
	case Rename:
		e.Target = o.path
	case SyncDir:
		e.Path = filepath.Dir(o.path)
	}
	return e, true
}

// Complete consumes one effect result. Cleanup and close failures are retained
// alongside the original error. A zero-progress write is an error, rather than
// an infinite retry; positive short writes continue at the correct offset.
func (o *Operation) Complete(r Result) {
	if o.Done() {
		panic("atomicfile: completion after operation finished")
	}
	if o.next == Write {
		if r.N < 0 || r.N > len(o.data)-o.offset || (r.N == 0 && r.Err == nil) {
			r.Err = errors.Join(r.Err, io.ErrShortWrite)
		} else {
			o.offset += r.N
		}
	}
	if r.Err != nil {
		err := &Error{Kind: o.next, Path: o.path, Renamed: o.renamed, Err: r.Err}
		if o.err == nil {
			o.err = err
		} else {
			o.err = errors.Join(o.err, err)
		}
		switch o.next {
		case Write, Chmod, Sync:
			o.next = Close
		case Close, Rename:
			o.next = Cleanup
		default:
			o.next = ""
		}
		return
	}
	switch o.next {
	case Create:
		o.temp = r.Name
		o.next = Write
		if len(o.data) == 0 {
			o.next = Chmod
		}
	case Write:
		if o.offset == len(o.data) {
			o.next = Chmod
		}
	case Chmod:
		o.next = Sync
	case Sync:
		o.next = Close
	case Close:
		o.next = Rename
		if o.err != nil {
			o.next = Cleanup
		}
	case Rename:
		o.renamed = true
		o.next = SyncDir
	case SyncDir, Cleanup:
		o.next = ""
	}
}

// Run drives the same machine used by simulations with per-operation effects.
func Run(o *Operation, effects Effects) error {
	for {
		e, ok := o.Next()
		if !ok {
			return o.Err()
		}
		o.Complete(effects.Execute(e))
	}
}
