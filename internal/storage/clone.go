package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// hydration tracks a background clone watcher.
type hydration struct {
	release  func()
	released bool
	cancel   context.CancelFunc
	stopped  chan struct{}
}

func cloneMetaSize(size int64) int64 { return roundUp(8<<20+size/512, blockSize) }

// createRemoteWorking builds a writable volume whose data streams from
// req.Remote: a dm-clone device that is swapped to a linear mapping of the
// destination once hydrated.
func (s *Store) createRemoteWorking(ctx context.Context, req CreateWorking) (string, error) {
	src := req.Remote
	base, err := s.cloneBase(src)
	if err != nil {
		releaseOnce(src)
		return "", err
	}
	if base != nil {
		defer s.unhold(base.ID)
	}
	rec := &record{
		ID: req.AttachmentID, Kind: KindWorking, StateUID: req.StateUID, Base: src.Base,
		Size: max(roundUp(req.SizeBytes, blockSize), src.SizeBytes), ReadOnly: req.ReadOnly, Layered: true,
		Clone: &cloneInfo{MetaSize: cloneMetaSize(src.SizeBytes), Source: src.Device, SourceSize: src.SizeBytes, RemoteID: src.ID},
	}
	if _, err := s.begin(rec, 2); err != nil {
		releaseOnce(src)
		return "", err
	}
	s.mu.Lock()
	s.hydrates[rec.ID] = &hydration{release: src.Release}
	s.mu.Unlock()
	top := s.topName(rec)
	err = s.setupClone(rec, base, top, src.Regions)
	if err == nil && rec.Size > src.SizeBytes {
		err = s.withPlain(rec, false, func(string) error {
			return s.runOperation([]deviceEffect{{Kind: eGrow, Name: s.plainName(rec)}}, nil)
		})
	}
	if err == nil {
		err = s.runOperation([]deviceEffect{{Kind: eMessage, Name: top, Table: "enable_hydration"}}, nil)
	}
	if err == nil {
		err = s.openPlain(rec)
	}
	if err == nil {
		err = s.setPhase(rec, phaseReady)
	}
	if err != nil {
		if rerr := s.rollback(rec); rerr != nil {
			logf("rollback remote working %s: %v", rec.ID, rerr)
		}
		return "", err
	}
	s.startWatch(rec, src.Release)
	return mapperPath(s.plainName(rec)), nil
}

// FetchCommit copies a remote commit into a local commit and returns when all
// data is local.
func (s *Store) FetchCommit(ctx context.Context, stateUID, commitID string, src Remote, progress func(done, total int64)) error {
	if commitID == "" || src.Device == "" || src.SizeBytes <= 0 {
		releaseOnce(&src)
		return errors.New("storage: invalid FetchCommit")
	}
	defer s.locks.lock(commitID)()
	if _, err := s.lookup(commitID); err == nil {
		releaseOnce(&src)
		return nil
	}
	base, err := s.cloneBase(&src)
	if err != nil {
		releaseOnce(&src)
		return err
	}
	if base != nil {
		defer s.unhold(base.ID)
	}
	rec := &record{
		ID: commitID, Kind: KindCommit, StateUID: stateUID, Base: src.Base, Size: src.SizeBytes,
		Clone: &cloneInfo{MetaSize: cloneMetaSize(src.SizeBytes), Source: src.Device, SourceSize: src.SizeBytes, RemoteID: src.ID},
	}
	if _, err := s.begin(rec, 2); err != nil {
		releaseOnce(&src)
		return err
	}
	s.mu.Lock()
	s.hydrates[rec.ID] = &hydration{release: src.Release}
	s.mu.Unlock()
	if err := s.fetch(ctx, rec, base, src.Regions, progress); err != nil {
		if rerr := s.rollback(rec); rerr != nil {
			logf("rollback fetch %s: %v", rec.ID, rerr)
		}
		return err
	}
	return s.completeClone(rec, phaseReady)
}

func (s *Store) fetch(ctx context.Context, rec, base *record, regions []Region, progress func(done, total int64)) error {
	name := s.fetchName(rec)
	if err := s.setupClone(rec, base, name, regions); err != nil {
		return err
	}
	if err := s.runOperation([]deviceEffect{{Kind: eMessage, Name: name, Table: "enable_hydration"}}, nil); err != nil {
		return err
	}
	if err := s.waitClone(ctx, name, rec.Clone.Source, progress); err != nil {
		return err
	}
	if err := s.runOperation([]deviceEffect{{Kind: eFlush, Name: name}}, nil); err != nil {
		return err
	}
	for _, n := range []string{name, s.metaName(rec), s.thinName(rec)} {
		if err := s.deviceRemove(n); err != nil {
			return err
		}
	}
	return s.deleteThin(rec.Clone.MetaThin)
}

func (s *Store) cloneBase(src *Remote) (*record, error) {
	if src.Device == "" || src.SizeBytes <= 0 || src.SizeBytes%512 != 0 {
		return nil, errors.New("storage: invalid remote")
	}
	if src.Base == "" {
		return nil, nil
	}
	return s.source(src.Base, "")
}

// setupClone creates the destination (snapshot of base or new thin), the
// clone metadata volume, and a dm-clone device named name with hydration
// disabled, then marks every region outside regions as hydrated.
func (s *Store) setupClone(rec, base *record, name string, regions []Region) error {
	return s.runOperation(cloneSetupPlan(s.layout(rec), rec, base, name, regions), nil)
}

// discardOutside discards (on dm-clone: marks hydrated without copying)
// every byte range of [0,size) not covered by regions.
func discardOutside(dev string, regions []Region, size int64) error {
	f, err := os.OpenFile(dev, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	var pos int64
	for _, r := range MergeRegions(regions) {
		if r.Offset > pos {
			if err := blkDiscard(f, pos, min(r.Offset, size)-pos); err != nil {
				return err
			}
		}
		pos = max(pos, r.Offset+r.Length)
		if pos >= size {
			return nil
		}
	}
	if pos < size {
		return blkDiscard(f, pos, size-pos)
	}
	return nil
}

func blkDiscard(f *os.File, off, length int64) error {
	if length <= 0 {
		return nil
	}
	r := [2]uint64{uint64(off), uint64(length)}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.BLKDISCARD, uintptr(unsafe.Pointer(&r[0])))
	if errno != 0 {
		return fmt.Errorf("BLKDISCARD %s [%d,+%d): %w", f.Name(), off, length, errno)
	}
	return nil
}

// MergeRegions sorts regions and merges overlapping or adjacent ones.
func MergeRegions(in []Region) []Region {
	rs := make([]Region, 0, len(in))
	for _, r := range in {
		if r.Length > 0 {
			rs = append(rs, r)
		}
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].Offset < rs[j].Offset })
	var out []Region
	for _, r := range rs {
		if n := len(out); n > 0 && r.Offset <= out[n-1].Offset+out[n-1].Length {
			out[n-1].Length = max(out[n-1].Length, r.Offset+r.Length-out[n-1].Offset)
			continue
		}
		out = append(out, r)
	}
	return out
}

// cloneProgress parses the clone line of `dmsetup status`.
func cloneProgress(status string) (hydrated, total int64, mode string, err error) {
	for _, line := range strings.Split(status, "\n") {
		f := strings.Fields(line)
		if len(f) < 8 || f[2] != "clone" {
			continue
		}
		if _, err := fmt.Sscanf(f[6], "%d/%d", &hydrated, &total); err != nil {
			return 0, 0, "", fmt.Errorf("clone status %q: %w", line, err)
		}
		return hydrated, total, f[len(f)-1], nil
	}
	return 0, 0, "", fmt.Errorf("no clone target in status %q", status)
}

// waitClone polls a clone device until every region is hydrated.
func waitClone(ctx context.Context, name, source string, progress func(done, total int64)) error {
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		st, err := dmStatus(name)
		if err != nil {
			return err
		}
		done, h, t, err := hydrationDecision(name, st)
		if err != nil {
			return err
		}
		if progress != nil {
			progress(h*blockSize, t*blockSize)
		}
		if done {
			return nil
		}
		if _, err := os.Stat(source); err != nil {
			return fmt.Errorf("clone source %s is gone", source)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

func (s *Store) waitClone(ctx context.Context, name, source string, progress func(int64, int64)) error {
	if s.cloneWait != nil {
		return s.cloneWait(ctx, name, source, progress)
	}
	return waitClone(ctx, name, source, progress)
}

// startWatch runs a background goroutine that waits for a remote working
// volume to hydrate and then swaps it to a linear mapping.
func (s *Store) startWatch(r *record, release func()) {
	ctx, cancel := context.WithCancel(s.ctx)
	source := r.Clone.Source
	h := &hydration{release: release, cancel: cancel, stopped: make(chan struct{})}
	s.mu.Lock()
	s.hydrates[r.ID] = h
	s.mu.Unlock()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer close(h.stopped)
		err := s.waitClone(ctx, s.topName(r), source, nil)
		if ctx.Err() != nil {
			return
		}
		defer s.locks.lock(r.ID)()
		s.mu.Lock()
		current := s.vols[r.ID] == r && r.Clone != nil
		s.mu.Unlock()
		if !current || ctx.Err() != nil {
			return
		}
		if err != nil {
			logf("hydrate %s: %v", r.ID, err)
			s.markFailed(r, err.Error())
			return
		}
		if err := s.finishClone(r); err != nil {
			logf("finish hydration of %s: %v", r.ID, err)
			s.markFailed(r, err.Error())
		}
	}()
}

// finishClone swaps a hydrated working volume to a linear mapping of its
// destination (same dm name, so open handles stay valid), drops the clone
// metadata, and releases the remote.
func (s *Store) finishClone(r *record) error {
	if r.Clone == nil {
		return s.releaseRemote(r)
	}
	top := s.topName(r)
	table, err := s.deviceTable(top)
	if err != nil {
		return err
	}
	cloning := strings.Contains(table, " clone ")
	if !cloning {
		for _, line := range strings.Split(strings.TrimSpace(table), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 3 || fields[2] != "linear" {
				return fmt.Errorf("storage: unexpected completed clone table %q", table)
			}
		}
	}
	if !r.CloneFinishing {
		// A full hydration counter is only an in-memory observation. Flush
		// destination data and clone metadata before claiming that a host
		// reboot can reconstruct this volume without its remote source.
		if err := s.runOperation([]deviceEffect{{Kind: eResume, Name: top}, {Kind: eFlush, Name: top}}, nil); err != nil {
			return err
		}
		if err := s.change(r, func(next *record) { next.CloneFinishing = true }); err != nil {
			return err
		}
	}
	if err := s.runOperation(finishClonePlan(s.layout(r), r, cloning), nil); err != nil {
		return err
	}
	return s.completeClone(r, r.Phase)
}

// completeClone makes local ownership and pending release durable together.
// A failed write leaves Clone intact so retry/recovery still owns its metadata
// thin ID and remote lease. The device cleanup that precedes this is replayable.
func (s *Store) completeClone(r *record, phase string) error {
	err := s.change(r, func(next *record) {
		if next.Clone != nil && next.Clone.RemoteID != "" {
			next.PendingRemote = next.Clone.RemoteID
		}
		next.Clone = nil
		next.CloneFinishing = false
		next.Phase = phase
		next.Failed = ""
	})
	if err != nil {
		return err
	}
	return s.releaseRemote(r)
}

// waitHydrated blocks until the background hydration of id (if any) stops.
func (s *Store) waitHydrated(ctx context.Context, id string) error {
	s.mu.Lock()
	h := s.hydrates[id]
	s.mu.Unlock()
	if h == nil || h.stopped == nil {
		return nil
	}
	select {
	case <-h.stopped:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
