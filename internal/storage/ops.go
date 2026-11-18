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
	rec := &record{ID: id, Kind: KindImage, Size: roundUp(sizeBytes, blockSize)}
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
	if err := s.createThin(rec.Thin); err != nil {
		return err
	}
	name := s.thinName(rec)
	if err := dmCreate(name, thinTable(s.poolName(), rec.Thin, rec.Size), false); err != nil {
		return err
	}
	err := ctx.Err()
	if err == nil {
		err = s.withPlain(rec, false, fill)
	}
	if rerr := dmRemove(name); err == nil {
		err = rerr
	}
	return err
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
	rec := &record{ID: req.CommitID, Kind: KindCommit, StateUID: req.StateUID, Size: roundUp(req.SizeBytes, blockSize)}
	var src *record
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
		if req.FromImage != "" && rec.Size > 0 && src.Size > rec.Size {
			return fmt.Errorf("storage: image %s needs %d bytes, more than the requested %d", id, src.Size, req.SizeBytes)
		}
		rec.Size = max(rec.Size, src.Size)
	} else if rec.Size == 0 {
		return errors.New("storage: empty commit needs a size")
	}
	if _, err := s.begin(rec, 1); err != nil {
		return err
	}
	if err := s.buildCommit(rec, src); err != nil {
		if rerr := s.rollback(rec); rerr != nil {
			logf("rollback commit %s: %v", rec.ID, rerr)
		}
		return err
	}
	return s.setPhase(rec, phaseReady)
}

func (s *Store) buildCommit(rec, src *record) error {
	if src != nil {
		if err := s.createSnap(rec.Thin, src.Thin); err != nil {
			return err
		}
		if rec.Size <= src.Size {
			return nil
		}
	} else if err := s.createThin(rec.Thin); err != nil {
		return err
	}
	name := s.thinName(rec)
	if err := dmCreate(name, thinTable(s.poolName(), rec.Thin, rec.Size), false); err != nil {
		return err
	}
	err := s.withPlain(rec, false, func(dev string) error {
		if src == nil {
			return mkfsExt4(dev)
		}
		// Every node builds commits from images itself; growing them
		// reproducibly lets nodes use each other's copies as delta bases.
		return growExt4(dev, src.Kind == KindImage)
	})
	if rerr := dmRemove(name); err == nil {
		err = rerr
	}
	return err
}

// source holds a ready volume of the given kind for the duration of an
// operation; release it with unhold.
func (s *Store) source(id string, kind Kind) (*record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.vols[id]
	if !ok || r.Phase != phaseReady {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if kind != "" && r.Kind != kind {
		return nil, fmt.Errorf("storage: %s is a %s, not a %s", id, r.Kind, kind)
	}
	if r.Kind == KindWorking || r.Kind == kindExport {
		return nil, fmt.Errorf("storage: %s is not immutable", id)
	}
	s.tmpPins[id]++
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
	rec := &record{
		ID: req.AttachmentID, Kind: KindWorking, StateUID: req.StateUID, Base: id,
		Size: max(roundUp(req.SizeBytes, blockSize), src.Size), ReadOnly: req.ReadOnly,
	}
	if _, err := s.begin(rec, 1); err != nil {
		return "", err
	}
	if err := s.buildWorking(rec, src); err != nil {
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

func (s *Store) buildWorking(rec, src *record) error {
	if err := s.createSnap(rec.Thin, src.Thin); err != nil {
		return err
	}
	name := s.thinName(rec)
	table := thinTable(s.poolName(), rec.Thin, rec.Size)
	if rec.Size <= src.Size {
		if err := dmCreate(name, table, rec.ReadOnly); err != nil {
			return err
		}
		return s.openPlain(rec)
	}
	if err := dmCreate(name, table, false); err != nil {
		return err
	}
	if err := s.withPlain(rec, false, func(dev string) error { return growExt4(dev, false) }); err != nil {
		return err
	}
	if rec.ReadOnly {
		if err := dmReload(name, table, true); err != nil {
			return err
		}
	}
	return s.openPlain(rec)
}

func releaseOnce(r *Remote) {
	if r != nil && r.Release != nil {
		r.Release()
	}
}

// Seal snapshots a fenced working volume into a new commit owned by the
// volume's state. It returns the commit size.
func (s *Store) Seal(ctx context.Context, attachmentID, commitID string) (int64, error) {
	if err := s.waitHydrated(ctx, attachmentID); err != nil {
		return 0, err
	}
	defer s.locks.lock(attachmentID)()
	defer s.locks.lock(commitID)()
	if c, err := s.lookup(commitID); err == nil {
		if c.Kind != KindCommit {
			return 0, fmt.Errorf("%w: %s is a %s", ErrInUse, c.ID, c.Kind)
		}
		return c.Size, nil
	}
	w, err := s.lookup(attachmentID)
	if err != nil {
		return 0, err
	}
	switch {
	case w.Kind != KindWorking:
		return 0, fmt.Errorf("storage: %s is not a working volume", w.ID)
	case w.Failed != "":
		return 0, fmt.Errorf("storage: %s failed: %s", w.ID, w.Failed)
	case w.Clone != nil:
		return 0, fmt.Errorf("storage: %s is still hydrating", w.ID)
	}
	// The host-side fence: nothing (in particular the VMM) may still have
	// the disk open, or writes could land after the snapshot.
	if n, err := dmOpenCount(s.plainName(w)); err != nil {
		return 0, err
	} else if n > 0 {
		return 0, fmt.Errorf("%w: %s is still open", ErrInUse, w.ID)
	}
	plain := mapperPath(s.plainName(w))
	dirty, err := ext4NeedsRecovery(plain)
	if err != nil {
		return 0, err
	}
	if dirty {
		return 0, ErrUnclean
	}
	if err := flushDevice(plain); err != nil {
		return 0, err
	}
	rec := &record{ID: commitID, Kind: KindCommit, StateUID: w.StateUID, Base: w.Base, Size: w.Size}
	if _, err := s.begin(rec, 1); err != nil {
		return 0, err
	}
	if err := s.snapshotActive(w, rec.Thin); err != nil {
		if rerr := s.rollback(rec); rerr != nil {
			logf("rollback seal %s: %v", rec.ID, rerr)
		}
		return 0, err
	}
	if err := s.setPhase(rec, phaseReady); err != nil {
		return 0, err
	}
	return rec.Size, nil
}

// LiveCopy snapshots a working volume that is still in use, with its
// filesystem frozen by the guest, into a new commit owned by stateUID. The
// snapshot is kept only if its ext4 superblock is clean. It returns the
// commit size.
func (s *Store) LiveCopy(ctx context.Context, attachmentID, commitID, stateUID string) (int64, error) {
	if err := s.waitHydrated(ctx, attachmentID); err != nil {
		return 0, err
	}
	defer s.locks.lock(attachmentID)()
	defer s.locks.lock(commitID)()
	if c, err := s.lookup(commitID); err == nil {
		if c.Kind != KindCommit {
			return 0, fmt.Errorf("%w: %s is a %s", ErrInUse, c.ID, c.Kind)
		}
		return c.Size, nil
	}
	w, err := s.lookup(attachmentID)
	if err != nil {
		return 0, err
	}
	switch {
	case w.Kind != KindWorking:
		return 0, fmt.Errorf("storage: %s is not a working volume", w.ID)
	case w.Failed != "":
		return 0, fmt.Errorf("storage: %s failed: %s", w.ID, w.Failed)
	case w.Clone != nil:
		return 0, fmt.Errorf("storage: %s is still hydrating", w.ID)
	}
	if err := flushDevice(mapperPath(s.plainName(w))); err != nil {
		return 0, err
	}
	rec := &record{ID: commitID, Kind: KindCommit, StateUID: stateUID, Base: w.Base, Size: w.Size}
	if _, err := s.begin(rec, 1); err != nil {
		return 0, err
	}
	err = s.snapshotActive(w, rec.Thin)
	if err == nil {
		err = s.checkClean(rec)
	}
	if err != nil {
		if rerr := s.rollback(rec); rerr != nil {
			logf("rollback live copy %s: %v", rec.ID, rerr)
		}
		return 0, err
	}
	if err := s.setPhase(rec, phaseReady); err != nil {
		return 0, err
	}
	return rec.Size, nil
}

// checkClean reports ErrUnclean unless the ext4 filesystem of an inactive
// commit has needs_recovery clear.
func (s *Store) checkClean(rec *record) error {
	name := s.thinName(rec)
	if err := dmCreate(name, thinTable(s.poolName(), rec.Thin, rec.Size), true); err != nil {
		return err
	}
	var dirty bool
	err := s.withPlain(rec, true, func(dev string) (err error) {
		dirty, err = ext4NeedsRecovery(dev)
		return err
	})
	if rerr := dmRemove(name); err == nil {
		err = rerr
	}
	if err == nil && dirty {
		err = ErrUnclean
	}
	return err
}

// snapshotActive snapshots an active thin device, suspending it as dm-thin
// requires.
func (s *Store) snapshotActive(origin *record, thin uint32) error {
	name := s.thinName(origin)
	if !dmExists(name) {
		return s.createSnap(thin, origin.Thin)
	}
	if _, err := dmsetup("--noudevsync", "suspend", name); err != nil {
		return err
	}
	err := s.createSnap(thin, origin.Thin)
	if _, rerr := dmsetup("--noudevsync", "resume", name); err == nil {
		err = rerr
	}
	return err
}
