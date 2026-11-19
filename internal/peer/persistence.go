// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package peer

import (
	"errors"
	"os"

	"github.com/Azure/blip/internal/atomicfile"
)

// LeasePersistence stores the encoded lease snapshot. Save must durably replace
// the whole snapshot before returning nil. An error after replacement must be
// an AmbiguousSaveError: callers must retain cleanup ownership and pins.
// Load returns os.ErrNotExist for an uninitialized journal.
type LeasePersistence interface {
	Load() ([]byte, error)
	Save([]byte) error
}

// AmbiguousSaveError means the new snapshot may be visible after restart, even
// though its durability could not be confirmed.
type AmbiguousSaveError struct{ Err error }

func (e *AmbiguousSaveError) Error() string { return "peer: ambiguous lease save: " + e.Err.Error() }
func (e *AmbiguousSaveError) Unwrap() error { return e.Err }

func ambiguousSave(err error) bool {
	var ambiguous *AmbiguousSaveError
	return errors.As(err, &ambiguous)
}

type leaseFile struct{ path string }

func (f leaseFile) Load() ([]byte, error) { return os.ReadFile(f.path) }

func (f leaseFile) Save(data []byte) error {
	err := atomicfile.Replace(f.path, data, 0o600)
	var replacement *atomicfile.Error
	if errors.As(err, &replacement) && replacement.Renamed {
		// Preserve the journal contract: a visible replacement must retain
		// cleanup ownership even if syncing its directory failed.
		return &AmbiguousSaveError{Err: err}
	}
	return err
}
