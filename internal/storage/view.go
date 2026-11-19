package storage

import (
	"context"
	"errors"
)

// Device returns the plaintext device of a ready working volume.
func (s *Store) Device(id string) (string, error) {
	defer s.locks.lock(id)()
	r, err := s.lookup(id)
	if err != nil {
		return "", ErrNotFound
	}
	if r.Kind != KindWorking {
		return "", ErrNotFound
	}
	return mapperPath(s.plainName(r)), nil
}

// OpenView creates or reuses a read-only working volume at viewID backed by
// commitID and returns its plaintext device.
func (s *Store) OpenView(ctx context.Context, stateUID, commitID, viewID string) (string, error) {
	return s.CreateWorking(ctx, CreateWorking{
		AttachmentID: viewID,
		StateUID:     stateUID,
		FromCommit:   commitID,
		ReadOnly:     true,
	})
}

// CloseView removes a view created by OpenView. A missing view is not an
// error.
func (s *Store) CloseView(viewID string) error {
	err := s.Delete(context.Background(), viewID)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}
