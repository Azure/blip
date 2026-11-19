package storage

import "fmt"

// OpenExport returns a device serving the contents of immutable volume id for
// lease leaseID. nvmet needs a writable block device, so this is a throwaway
// thin snapshot; writes to it never reach id.
func (s *Store) OpenExport(id, leaseID string) (string, error) {
	xid := "x-" + leaseID
	defer s.locks.lock(xid)()
	if r, err := s.lookup(xid); err == nil {
		if r.Base != id {
			return "", fmt.Errorf("%w: lease %s exports %s", ErrInUse, leaseID, r.Base)
		}
		return mapperPath(s.thinName(r)), s.reactivate(r)
	}
	src, err := s.source(id, "")
	if err != nil {
		return "", err
	}
	defer s.unhold(id)
	rec := &record{ID: xid, Kind: kindExport, Base: id, StateUID: src.StateUID,
		Size: src.Size, StreamSize: src.StreamSize, FSBytes: src.fsBytes()}
	if _, err := s.begin(rec, 1); err != nil {
		return "", err
	}
	err = s.createSnap(rec.Thin, src.Thin)
	if err == nil {
		err = s.deviceCreate(s.thinName(rec), thinTable(s.poolName(), rec.Thin, rec.Size), false)
	}
	if err == nil {
		err = s.setPhase(rec, phaseReady)
	}
	if err != nil {
		if rerr := s.rollback(rec); rerr != nil {
			logf("rollback export %s: %v", leaseID, rerr)
		}
		return "", err
	}
	return mapperPath(s.thinName(rec)), nil
}

// CloseExport removes the export device of a lease.
func (s *Store) CloseExport(leaseID string) error {
	xid := "x-" + leaseID
	defer s.locks.lock(xid)()
	s.mu.Lock()
	r, ok := s.vols[xid]
	s.mu.Unlock()
	if !ok {
		return nil
	}
	phase := phaseDeleting
	if r.Phase == phaseReady || r.Phase == phaseDetaching {
		phase = phaseDetaching
	}
	if err := s.setPhase(r, phase); err != nil {
		return err
	}
	return s.detachAndDelete(r)
}

// Exports returns leaseID -> volume ID of every export device.
func (s *Store) Exports() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	for _, r := range s.vols {
		if r.Kind == kindExport && r.Phase == phaseReady {
			out[r.ID[2:]] = r.Base
		}
	}
	return out
}
