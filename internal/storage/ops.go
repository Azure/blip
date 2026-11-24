// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package storage

import (
	"context"
	"errors"
	"fmt"
)

// CreateImage creates an image volume of sizeBytes and calls fill with the
// path of its writable device to populate it.
func (s *Store) CreateImage(ctx context.Context, id string, sizeBytes int64, fill func(dev string) error) error {
	if id == "" || sizeBytes <= 0 {
		return errors.New("storage: image id and size are required")
	}
	defer s.locks.lock(id)()
	if _, err := s.lookup(id); err == nil {
		return nil
	}
	size := roundUp(sizeBytes, blockSize)
	rec := &record{ID: id, Kind: KindImage, Size: size, FSBytes: size}
	if _, err := s.begin(rec, 1); err != nil {
		return err
	}
	if err := s.buildImage(ctx, rec, fill); err != nil {
		if rerr := s.rollback(rec); rerr != nil {
			logf("rollback image %s: %v", id, rerr)
		}
		return err
	}
	return s.setPhase(rec, phaseReady)
}

func (s *Store) buildImage(ctx context.Context, rec *record, fill func(dev string) error) error {
	return s.runOperationContext(ctx, createPlan(s.layout(rec), rec, nil, true), imageFill(ctx, fill))
}

// CreateCommit builds a commit from an image, another commit, or nothing.
func (s *Store) CreateCommit(ctx context.Context, req CreateCommit) error {
	if req.CommitID == "" || (req.FromImage != "" && req.FromCommit != "") {
		return errors.New("storage: invalid CreateCommit")
	}
	defer s.locks.lock(req.CommitID)()
	if r, err := s.lookup(req.CommitID); err == nil {
		if r.Kind != KindCommit {
			return fmt.Errorf("%w: %s is a %s", ErrInUse, r.ID, r.Kind)
		}
		return nil
	}
	rec := &record{ID: req.CommitID, Kind: KindCommit, StateUID: req.StateUID, StreamSize: req.StreamSize}
	fsSize := roundUp(req.SizeBytes, blockSize)
	var src *record
	var srcSize int64
	if id := req.FromImage + req.FromCommit; id != "" {
		kind := KindImage
		if req.FromCommit != "" {
			kind = KindCommit
		}
		var err error
		src, err = s.source(id, kind)
		if err != nil {
			return err
		}
		defer s.unhold(id)
		rec.Base = id
		srcSize = src.Size
		srcFS := src.fsBytes()
		if req.FromImage != "" && fsSize > 0 && srcFS > fsSize {
			return fmt.Errorf("storage: image %s needs %d bytes, more than the requested %d", id, srcFS, req.SizeBytes)
		}
		fsSize = max(fsSize, srcFS)
	}
	if fsSize == 0 {
		return errors.New("storage: empty commit needs a size")
	}
	rec.FSBytes = fsSize
	if req.StreamSize > 0 {
		rec.Size = VolumeBytes(fsSize, req.StreamSize)
	} else {
		rec.Size = max(fsSize, srcSize)
	}
	if _, err := s.begin(rec, 1); err != nil {
		return err
	}
	if err := s.buildCommit(ctx, rec, src); err != nil {
		if rerr := s.rollback(rec); rerr != nil {
			logf("rollback commit %s: %v", rec.ID, rerr)
		}
		return err
	}
	return s.setPhase(rec, phaseReady)
}

func (s *Store) buildCommit(ctx context.Context, rec, src *record) error {
	return s.runOperationContext(ctx, createPlan(s.layout(rec), rec, src, false), nil)
}

// source holds a ready volume of the given kind for the duration of an
// operation; release it with unhold.
func (s *Store) source(id string, kind Kind) (*record, error) {
	s.mu.Lock()
	r, ok := s.vols[id]
	if !ok || r.Phase != phaseReady {
		s.mu.Unlock()
		return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if kind != "" && r.Kind != kind {
		s.mu.Unlock()
		return nil, fmt.Errorf("storage: %s is a %s, not a %s", id, r.Kind, kind)
	}
	if r.Kind == KindWorking || r.Kind == kindExport {
		s.mu.Unlock()
		return nil, fmt.Errorf("storage: %s is not immutable", id)
	}
	s.tmpPins[id]++
	s.mu.Unlock()
	// Mark the source recently used so cache eviction prefers colder commits.
	// A failed metadata write only costs eviction order, never the operation.
	if err := s.Touch(id); err != nil {
		logf("touch source %s: %v", id, err)
	}
	return r, nil
}

func (s *Store) unhold(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tmpPins[id]--
	if s.tmpPins[id] <= 0 {
		delete(s.tmpPins, id)
	}
}

// CreateWorking creates a working volume and returns its device path.
func (s *Store) CreateWorking(ctx context.Context, req CreateWorking) (string, error) {
	n := 0
	for _, set := range []bool{req.FromImage != "", req.FromCommit != "", req.Remote != nil} {
		if set {
			n++
		}
	}
	if n != 1 || req.AttachmentID == "" {
		releaseOnce(req.Remote)
		return "", errors.New("storage: invalid CreateWorking")
	}
	defer s.locks.lock(req.AttachmentID)()
	if r, err := s.lookup(req.AttachmentID); err == nil {
		releaseOnce(req.Remote)
		if r.Kind != KindWorking {
			return "", fmt.Errorf("%w: %s is a %s", ErrInUse, r.ID, r.Kind)
		}
		return mapperPath(s.plainName(r)), nil
	}
	if req.Remote != nil {
		return s.createRemoteWorking(ctx, req)
	}
	id, kind := req.FromImage, KindImage
	if req.FromCommit != "" {
		id, kind = req.FromCommit, KindCommit
	}
	src, err := s.source(id, kind)
	if err != nil {
		return "", err
	}
	defer s.unhold(id)
	fsSize := max(roundUp(req.SizeBytes, blockSize), src.fsBytes())
	rec := &record{
		ID: req.AttachmentID, Kind: KindWorking, StateUID: req.StateUID, Base: id,
		StreamSize: req.StreamSize, FSBytes: fsSize, ReadOnly: req.ReadOnly,
	}
	if req.StreamSize > 0 {
		rec.Size = VolumeBytes(fsSize, req.StreamSize)
	} else {
		rec.Size = max(fsSize, src.Size)
	}
	if _, err := s.begin(rec, 1); err != nil {
		return "", err
	}
	if err := s.buildWorking(ctx, rec, src); err != nil {
		if rerr := s.rollback(rec); rerr != nil {
			logf("rollback working %s: %v", rec.ID, rerr)
		}
		return "", err
	}
	if err := s.setPhase(rec, phaseReady); err != nil {
		return "", err
	}
	return mapperPath(s.plainName(rec)), nil
}

func (s *Store) buildWorking(ctx context.Context, rec, src *record) error {
	return s.runOperationContext(ctx, createPlan(s.layout(rec), rec, src, false), nil)
}

func releaseOnce(r *Remote) {
	if r != nil && r.Release != nil {
		r.Release()
	}
}

// prepareSnapshot validates a snapshot request. It returns the working source,
// or, when commitID already exists, its size and existing=true. The returned
// unlock releases both volume key locks and must be called by the caller.
func (s *Store) prepareSnapshot(ctx context.Context, attachmentID, commitID string) (w *record, size int64, existing bool, unlock func(), err error) {
	if attachmentID == "" || commitID == "" || attachmentID == commitID {
		return nil, 0, false, nil, errors.New("storage: invalid snapshot IDs")
	}
	if err := s.waitHydrated(ctx, attachmentID); err != nil {
		return nil, 0, false, nil, err
	}
	unlock = s.locks.lockPair(attachmentID, commitID)
	if c, err := s.lookup(commitID); err == nil {
		if c.Kind != KindCommit {
			unlock()
			return nil, 0, false, nil, fmt.Errorf("%w: %s is a %s", ErrInUse, c.ID, c.Kind)
		}
		return nil, c.Size, true, unlock, nil
	}
	// Retry a snapshot whose own cleanup failed after begin. Recovery does
	// the same at startup, but without it a running node would refuse this
	// deterministic commit ID forever and never retry the seal.
	if err := s.retryUnfinished(commitID); err != nil {
		unlock()
		return nil, 0, false, nil, err
	}
	w, err = s.lookup(attachmentID)
	if err != nil {
		unlock()
		return nil, 0, false, nil, err
	}
	switch {
	case w.Kind != KindWorking:
		err = fmt.Errorf("storage: %s is not a working volume", w.ID)
	case w.Failed != "":
		err = fmt.Errorf("storage: %s failed: %s", w.ID, w.Failed)
	case w.Clone != nil:
		err = fmt.Errorf("storage: %s is still hydrating", w.ID)
	}
	if err != nil {
		unlock()
		return nil, 0, false, nil, err
	}
	return w, 0, false, unlock, nil
}

// Seal snapshots a fenced working volume into a new commit owned by the
// volume's state. It returns the commit size.
func (s *Store) Seal(ctx context.Context, attachmentID, commitID string) (int64, error) {
	w, size, existing, unlock, err := s.prepareSnapshot(ctx, attachmentID, commitID)
	if err != nil {
		return 0, err
	}
	defer unlock()
	if existing {
		return size, nil
	}
	// The host-side fence: nothing (in particular the VMM) may still have
	// the disk open, or writes could land after the snapshot.
	name := s.plainName(w)
	if err := s.runOperation([]deviceEffect{{Kind: eCheckClosed, Name: name}, {Kind: eCheckClean, Name: name}, {Kind: eFlush, Name: name}}, nil); err != nil {
		return 0, err
	}
	rec := &record{ID: commitID, Kind: KindCommit, StateUID: w.StateUID, Base: w.Base,
		Size: w.Size, StreamSize: w.StreamSize, FSBytes: w.fsBytes()}
	if _, err := s.begin(rec, 1); err != nil {
		return 0, err
	}
	if err := s.snapshotActive(w, rec); err != nil {
		if rerr := s.rollback(rec); rerr != nil {
			logf("rollback seal %s: %v", rec.ID, rerr)
		}
		return 0, err
	}
	if err := s.setPhase(rec, phaseReady); err != nil {
		// The snapshot is complete but not published. Roll it back so a
		// retry starts clean instead of finding a creating record; if the
		// rollback fails, the next Seal retries it before beginning.
		if rerr := s.rollback(rec); rerr != nil {
			logf("rollback seal %s after phase write: %v", rec.ID, rerr)
		}
		return 0, err
	}
	return rec.Size, nil
}

// Adopt keeps the fully hydrated data of a ready, read-only working volume
// whose owner is gone as commit commitID, a local cache of a whole version.
//
// Base is intentionally empty, not the working volume's base: a read-only
// attachment is often created from a local commit, so its base would equal
// commitID and the commit could never serve as a delta base. No ext4-clean
// check is needed either: the volume was mounted read-only, so its filesystem
// cannot have been dirtied.
func (s *Store) Adopt(ctx context.Context, attachmentID, commitID string) (int64, error) {
	if attachmentID == "" || commitID == "" || attachmentID == commitID {
		return 0, errors.New("storage: invalid adopt IDs")
	}
	unlock := s.locks.lockPair(attachmentID, commitID)
	defer unlock()
	if c, err := s.lookup(commitID); err == nil {
		if c.Kind != KindCommit {
			return 0, fmt.Errorf("%w: %s is a %s", ErrInUse, c.ID, c.Kind)
		}
		return c.Size, nil
	}
	// Retry a snapshot whose own cleanup failed after begin, as Seal does.
	if err := s.retryUnfinished(commitID); err != nil {
		return 0, err
	}
	w, err := s.lookup(attachmentID)
	if err != nil {
		return 0, err
	}
	switch {
	case w.Kind != KindWorking:
		err = fmt.Errorf("storage: %s is not a working volume", w.ID)
	case w.Failed != "":
		err = fmt.Errorf("storage: %s failed: %s", w.ID, w.Failed)
	case w.Clone != nil:
		err = fmt.Errorf("storage: %s is still hydrating", w.ID)
	case !w.ReadOnly:
		err = fmt.Errorf("storage: %s is not read-only", w.ID)
	}
	if err != nil {
		return 0, err
	}
	if err := s.runOperation([]deviceEffect{{Kind: eCheckClosed, Name: s.plainName(w)}}, nil); err != nil {
		return 0, err
	}
	rec := &record{ID: commitID, Kind: KindCommit, StateUID: w.StateUID,
		Size: w.Size, StreamSize: w.StreamSize, FSBytes: w.fsBytes()}
	if _, err := s.begin(rec, 1); err != nil {
		return 0, err
	}
	if err := s.snapshotActive(w, rec); err != nil {
		if rerr := s.rollback(rec); rerr != nil {
			logf("rollback adopt %s: %v", rec.ID, rerr)
		}
		return 0, err
	}
	if err := s.setPhase(rec, phaseReady); err != nil {
		if rerr := s.rollback(rec); rerr != nil {
			logf("rollback adopt %s after phase write: %v", rec.ID, rerr)
		}
		return 0, err
	}
	return rec.Size, nil
}

// LiveCopy snapshots a working volume that is still in use, with its
// filesystem frozen by the guest, into a new commit owned by stateUID. The
// snapshot is kept only if its ext4 superblock is clean. It returns the
// commit size.
func (s *Store) LiveCopy(ctx context.Context, attachmentID, commitID, stateUID string) (int64, error) {
	w, size, existing, unlock, err := s.prepareSnapshot(ctx, attachmentID, commitID)
	if err != nil {
		return 0, err
	}
	defer unlock()
	if existing {
		return size, nil
	}
	if err := s.runOperation([]deviceEffect{{Kind: eFlush, Name: s.plainName(w)}}, nil); err != nil {
		return 0, err
	}
	rec := &record{ID: commitID, Kind: KindCommit, StateUID: stateUID, Base: w.Base,
		Size: w.Size, StreamSize: w.StreamSize, FSBytes: w.fsBytes()}
	if _, err := s.begin(rec, 1); err != nil {
		return 0, err
	}
	err = s.snapshotActive(w, rec)
	if err == nil {
		// A live copy into a different state must not inherit this state's
		// trajectory. Same-state live copies keep the ring.
		reset := stateUID != w.StateUID && w.StreamSize > 0
		err = s.checkClean(rec, reset)
	}
	if err != nil {
		if rerr := s.rollback(rec); rerr != nil {
			logf("rollback live copy %s: %v", rec.ID, rerr)
		}
		return 0, err
	}
	if err := s.setPhase(rec, phaseReady); err != nil {
		if rerr := s.rollback(rec); rerr != nil {
			logf("rollback live copy %s after phase write: %v", rec.ID, rerr)
		}
		return 0, err
	}
	return rec.Size, nil
}

// checkClean reports ErrUnclean unless the ext4 filesystem of an inactive
// commit has needs_recovery clear. With reset it also empties the commit's
// trajectory ring, which requires writable mappings.
func (s *Store) checkClean(rec *record, reset bool) error {
	name := s.thinName(rec)
	if err := s.deviceCreate(name, thinTable(s.poolName(), rec.Thin, rec.Size), !reset); err != nil {
		return err
	}
	err := s.withPlain(rec, !reset, func(string) error {
		steps := []deviceEffect{{Kind: eCheckClean, Name: s.plainName(rec)}}
		if reset {
			steps = append(steps, deviceEffect{Kind: eResetStream, Name: s.plainName(rec), Size: rec.StreamSize})
		}
		return s.runOperation(steps, nil)
	})
	if rerr := s.deviceRemove(name); err == nil {
		err = rerr
	}
	return err
}

// snapshotActive snapshots an active thin device, suspending it as dm-thin
// requires.
func (s *Store) snapshotActive(origin, dest *record) error {
	name := s.thinName(origin)
	active := s.deviceExists(name)
	if active {
		err := s.change(dest, func(next *record) { next.ResumeDevice = name })
		if err != nil {
			return err
		}
	}
	if err := s.runOperation(snapshotPlan(s.poolName(), name, dest.Thin, origin.Thin, active), nil); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.changeLocked(dest, func(next *record) { next.ResumeDevice = "" })
}
