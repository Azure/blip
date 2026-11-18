package atomicfile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// Replace atomically and durably replaces path with data and mode. See the
// package contract, especially the ambiguity of an error after rename.
func Replace(path string, data []byte, mode fs.FileMode) error {
	return Run(New(path, data, mode), &osEffects{})
}

// osEffects holds a descriptor for just one replacement. There are no package
// globals or deferred cleanup decisions hidden from the operation machine.
type osEffects struct {
	file *os.File
}

func (s *osEffects) Execute(e Effect) Result {
	switch e.Kind {
	case Create:
		f, err := os.CreateTemp(filepath.Dir(e.Path), "."+filepath.Base(e.Path)+".*")
		if err != nil {
			return Result{Err: err}
		}
		s.file = f
		return Result{Name: f.Name()}
	case Write:
		n, err := s.file.WriteString(e.Data)
		return Result{N: n, Err: err}
	case Chmod:
		return Result{Err: s.file.Chmod(e.Mode)}
	case Sync:
		return Result{Err: s.file.Sync()}
	case Close:
		err := s.file.Close()
		s.file = nil
		return Result{Err: err}
	case Rename:
		return Result{Err: os.Rename(e.Path, e.Target)}
	case SyncDir:
		dir, err := os.Open(e.Path)
		if err != nil {
			return Result{Err: err}
		}
		// Close still runs on a sync error, and neither error is lost.
		err = dir.Sync()
		return Result{Err: errors.Join(err, dir.Close())}
	case Cleanup:
		err := os.Remove(e.Path)
		if errors.Is(err, fs.ErrNotExist) {
			err = nil
		}
		return Result{Err: err}
	default:
		panic("atomicfile: unknown effect " + e.Kind)
	}
}
