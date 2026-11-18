package guest

import (
	"errors"
	"fmt"
	"log"
	"sort"
	"time"

	"golang.org/x/sys/unix"
)

const (
	ioctlFIFREEZE = 0xC0045877 // _IOWR('X', 119, int)
	ioctlFITHAW   = 0xC0045878 // _IOWR('X', 120, int)
)

// freezeTimeout bounds how long a filesystem stays frozen without a thaw.
// It must exceed the node's freeze wait (internal/node freezeTimeout): the
// node has to observe the freeze and finish the snapshot before this fires.
const freezeTimeout = 90 * time.Second

const thawRetryInterval = time.Second

// freezeFS freezes or thaws the filesystem mounted at path. It is a no-op
// error unless this process is PID 1.
func freezeFS(path string, freeze bool) error {
	if !isInit() {
		return errNotInit
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	req := uint(ioctlFITHAW)
	if freeze {
		req = ioctlFIFREEZE
	}
	if err := unix.IoctlSetInt(fd, req, 0); err != nil {
		if !freeze && err == unix.EINVAL {
			return nil // not frozen
		}
		return err
	}
	return nil
}

// syncFS writes back the filesystem mounted at path. Like freezeFS it does
// nothing unless this process is PID 1.
func syncFS(path string) {
	if !isInit() {
		return
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return
	}
	defer unix.Close(fd)
	_ = unix.Syncfs(fd)
}

// frozenFS is a frozen filesystem at path; timer thaws it after
// freezeTimeout.
type frozenFS struct {
	path  string
	timer *time.Timer
	lease freezeLease
}

// freezeLease is the time-only part of the freeze lifecycle. Each renewal
// invalidates callbacks already queued by an older timer, even if Stop lost
// the race. Filesystem and timer effects remain in the Guest adapter below.
type freezeLease struct {
	token uint64
	until time.Time
}

func (l *freezeLease) renew(now time.Time) uint64 {
	l.token++
	l.until = now.Add(freezeTimeout)
	return l.token
}

func (l freezeLease) expired(token uint64, now time.Time) bool {
	return token == l.token && !now.Before(l.until)
}

// filesystemEffects belongs to one guest; nil selects the real OS adapter.
type filesystemEffects struct {
	sync   func(string)
	freeze func(string, bool) error
}

func (g *Guest) syncFilesystem(path string) {
	if g.filesystem != nil {
		g.filesystem.sync(path)
		return
	}
	syncFS(path)
}

func (g *Guest) freezeFilesystem(path string, freeze bool) error {
	if g.filesystem != nil {
		return g.filesystem.freeze(path, freeze)
	}
	return freezeFS(path, freeze)
}

// diskPathLocked returns the guest path of the filesystem on disk id.
func (g *Guest) diskPathLocked(id string) (string, error) {
	if g.claim != nil && g.claim.ID == id && g.rootDev != "" {
		return g.root, nil
	}
	if m := g.mounts[id]; m != nil {
		return m.target, nil
	}
	return "", fmt.Errorf("disk %s is not mounted", id)
}

func (g *Guest) anyFrozen() bool {
	g.fmu.Lock()
	defer g.fmu.Unlock()
	return len(g.frozen) > 0
}

// doFreeze freezes disk id until doThaw or freezeTimeout.
func (g *Guest) doFreeze(id string) error {
	// A repeated freeze must not sync a filesystem that is already frozen:
	// syncfs waits for the thaw, stalling this control request.
	g.mu.Lock()
	if g.stopping {
		g.mu.Unlock()
		return errors.New("guest is stopping")
	}
	g.fmu.Lock()
	if f := g.frozen[id]; f != nil {
		g.renewFrozenLocked(id, f)
		g.fmu.Unlock()
		g.mu.Unlock()
		return nil
	}
	g.fmu.Unlock()

	// Write back dirty data first, so writers block for as short a time as
	// possible once the filesystem is frozen.
	p, err := g.diskPathLocked(id)
	g.mu.Unlock()
	if err == nil {
		g.syncFilesystem(p)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.stopping {
		return errors.New("guest is stopping")
	}
	g.fmu.Lock()
	defer g.fmu.Unlock()
	if f := g.frozen[id]; f != nil {
		g.renewFrozenLocked(id, f)
		return nil
	}
	p, err = g.diskPathLocked(id)
	if err != nil {
		return err
	}
	if err := g.freezeFilesystem(p, true); err != nil {
		return fmt.Errorf("freeze %s: %w", id, err)
	}
	g.startFrozenLocked(id, p)
	log.Printf("froze %s", id)
	return nil
}

// startFrozenLocked records id as frozen at path. Needs fmu.
func (g *Guest) startFrozenLocked(id, path string) {
	f := &frozenFS{path: path}
	g.frozen[id] = f
	g.renewFrozenLocked(id, f)
}

func (g *Guest) renewFrozenLocked(id string, f *frozenFS) {
	if f.timer != nil {
		f.timer.Stop()
	}
	token := f.lease.renew(time.Now())
	f.timer = time.AfterFunc(freezeTimeout, func() { g.autoThaw(id, f, token) })
}

func (g *Guest) doThaw(id string) error {
	g.fmu.Lock()
	defer g.fmu.Unlock()
	return g.thawFLocked(id)
}

// thawFLocked thaws disk id. Needs fmu.
func (g *Guest) thawFLocked(id string) error {
	f := g.frozen[id]
	if f == nil {
		return nil
	}
	if err := g.freezeFilesystem(f.path, false); err != nil {
		return fmt.Errorf("thaw %s: %w", id, err)
	}
	f.timer.Stop()
	delete(g.frozen, id)
	log.Printf("thawed %s", id)
	return nil
}

func (g *Guest) thawAll() error {
	g.fmu.Lock()
	defer g.fmu.Unlock()
	var errs []error
	for id := range g.frozen {
		errs = append(errs, g.thawFLocked(id))
	}
	return errors.Join(errs...)
}

// autoThaw takes only fmu so that it cannot wait behind an operation
// holding mu that is blocked on the frozen filesystem.
func (g *Guest) autoThaw(id string, f *frozenFS, token uint64) {
	g.fmu.Lock()
	if g.frozen[id] != f || !f.lease.expired(token, time.Now()) {
		g.fmu.Unlock()
		return
	}
	log.Printf("%s frozen for %v without thaw; thawing", id, freezeTimeout)
	err := g.thawFLocked(id)
	if err != nil {
		// Keep the expired lease's token: a renewal invalidates this retry,
		// while a temporary ioctl error cannot leave the disk frozen forever.
		f.timer = time.AfterFunc(thawRetryInterval, func() { g.autoThaw(id, f, token) })
	}
	g.fmu.Unlock()
	if err != nil {
		log.Print(err)
		return
	}
	g.mu.Lock()
	c := g.ctl
	g.mu.Unlock()
	if c != nil {
		c.freezeResult(g, id, errors.New("thawed after timeout"), false)
	}
}

func (g *Guest) frozenIDs() []string {
	g.fmu.Lock()
	defer g.fmu.Unlock()
	var ids []string
	for id := range g.frozen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
