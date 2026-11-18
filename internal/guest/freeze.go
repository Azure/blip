package guest

import (
	"errors"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/Azure/blip/internal/wire"
	"golang.org/x/sys/unix"
)

const (
	ioctlFIFREEZE = 0xC0045877 // _IOWR('X', 119, int)
	ioctlFITHAW   = 0xC0045878 // _IOWR('X', 120, int)
)

// freezeTimeout bounds how long a filesystem stays frozen without a thaw.
// It must exceed the node's freeze wait (internal/node freezeTimeout): the
// node has to observe the freeze and finish the snapshot before this fires.
var freezeTimeout = 90 * time.Second

// freezeFS freezes or thaws the filesystem mounted at path. It is a no-op
// error unless this process is PID 1; tests replace it.
var freezeFS = func(path string, freeze bool) error {
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
var syncFS = func(path string) {
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
	g.fmu.Lock()
	if f := g.frozen[id]; f != nil {
		if f.timer.Stop() {
			f.timer.Reset(freezeTimeout)
			g.fmu.Unlock()
			return nil
		}
		// The auto-thaw already fired and is waiting for fmu; replacing
		// the entry makes it a no-op so the filesystem stays frozen.
		g.startFrozenLocked(id, f.path)
		g.fmu.Unlock()
		return nil
	}
	g.fmu.Unlock()

	// Write back dirty data first, so writers block for as short a time as
	// possible once the filesystem is frozen.
	g.mu.Lock()
	p, err := g.diskPathLocked(id)
	g.mu.Unlock()
	if err == nil {
		syncFS(p)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.stopping {
		return errors.New("guest is stopping")
	}
	g.fmu.Lock()
	defer g.fmu.Unlock()
	if f := g.frozen[id]; f != nil {
		if f.timer.Stop() {
			f.timer.Reset(freezeTimeout)
			return nil
		}
		// The auto-thaw already fired and is waiting for fmu; replacing
		// the entry makes it a no-op so the filesystem stays frozen.
		g.startFrozenLocked(id, f.path)
		return nil
	}
	p, err = g.diskPathLocked(id)
	if err != nil {
		return err
	}
	if err := freezeFS(p, true); err != nil {
		return fmt.Errorf("freeze %s: %w", id, err)
	}
	g.startFrozenLocked(id, p)
	log.Printf("froze %s", id)
	return nil
}

// startFrozenLocked records id as frozen at path. Needs fmu.
func (g *Guest) startFrozenLocked(id, path string) {
	f := &frozenFS{path: path}
	f.timer = time.AfterFunc(freezeTimeout, func() { g.autoThaw(id, f) })
	g.frozen[id] = f
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
	f.timer.Stop()
	if err := freezeFS(f.path, false); err != nil {
		return fmt.Errorf("thaw %s: %w", id, err)
	}
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
func (g *Guest) autoThaw(id string, f *frozenFS) {
	g.fmu.Lock()
	if g.frozen[id] != f {
		g.fmu.Unlock()
		return
	}
	log.Printf("%s frozen for %v without thaw; thawing", id, freezeTimeout)
	err := g.thawFLocked(id)
	g.fmu.Unlock()
	if err != nil {
		log.Print(err)
		return
	}
	g.send(wire.TFreezeResult, wire.FreezeResult{ID: id, Error: "thawed after timeout"})
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
