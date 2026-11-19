// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package storage

import (
	"context"
	"errors"
	"fmt"
	"strconv"
)

// deviceEffect is one externally observable storage action. Plans contain no
// callbacks, clocks, or kernel access: the same decisions run against Linux and
// the fault-injecting device model. Creation is rolled back after a restart;
// teardown is replayed (remove/delete/resume must be idempotent).
type effectKind string

const (
	eCreateThin  effectKind = "create-thin"
	eSnapshot    effectKind = "snapshot"
	eDeleteThin  effectKind = "delete-thin"
	eCreate      effectKind = "create-device"
	eRemove      effectKind = "remove-device"
	eSuspend     effectKind = "suspend"
	eLoad        effectKind = "load-table"
	eResume      effectKind = "resume"
	eNodes       effectKind = "make-nodes"
	eFormat      effectKind = "format"
	eGrow        effectKind = "grow"
	eFill        effectKind = "fill"
	eDiscard     effectKind = "discard-outside"
	eMessage     effectKind = "message"
	eFlush       effectKind = "flush"
	eCheckClosed effectKind = "check-closed"
	eCheckClean  effectKind = "check-clean"
)

type deviceEffect struct {
	Kind         effectKind
	Name, Table  string
	Thin, Origin uint32
	ReadOnly     bool
	Reproducible bool
	Regions      []Region
	Size         int64
	Always       bool // compensation that runs even after an ambiguous failure
	Teardown     bool
}

// operation is a deterministic, resumable cursor over a small operation's
// effects. A failed ordinary step skips to compensations, retaining both the
// original error and any compensation errors. A crash discards the cursor:
// record.Phase and ResumeDevice specify the recovery operation instead.
type operation struct {
	steps []deviceEffect
	next  int
	err   error
}

func (m *operation) effect() (deviceEffect, bool) {
	for m.next < len(m.steps) {
		e := m.steps[m.next]
		if m.err == nil || e.Always {
			return e, true
		}
		m.next++
	}
	return deviceEffect{}, false
}

func (m *operation) complete(err error) {
	m.next++
	if err != nil {
		m.err = errors.Join(m.err, err)
	}
}

// storageDevices is instance-local. No production global functions are
// replaced by tests. Observations are separate from effects so recovery plans
// can be rebuilt from the actual surviving device graph.
type storageDevices interface {
	Apply(deviceEffect) error
	Names() map[string]bool
	Table(string) (string, error)
}

func (s *Store) runOperation(steps []deviceEffect, fill func(string) error) error {
	return s.runOperationContext(context.Background(), steps, fill)
}

// runOperationContext runs an operation and stops before the next ordinary
// step once ctx is done. Compensations (Always) and teardown steps still run
// so a cancelled build removes the devices and thin volume it created.
func (s *Store) runOperationContext(ctx context.Context, steps []deviceEffect, fill func(string) error) error {
	s.mu.Lock()
	err := s.metadataErr
	s.mu.Unlock()
	if err != nil {
		return err
	}
	m := operation{steps: steps}
	for {
		e, ok := m.effect()
		if !ok {
			return m.err
		}
		var err error
		if e.Teardown {
			err = s.beforeTeardown()
		}
		if err == nil {
			switch {
			case ctx.Err() != nil && !e.Always && !e.Teardown:
				err = ctx.Err()
			case e.Kind == eFill:
				err = fill(mapperPath(e.Name))
			case s.devices != nil:
				err = s.devices.Apply(e)
			default:
				err = applyDeviceEffect(ctx, e)
			}
		}
		m.complete(err)
	}
}

func applyDeviceEffect(ctx context.Context, e deviceEffect) error {
	id := strconv.FormatUint(uint64(e.Thin), 10)
	switch e.Kind {
	case eCreateThin:
		return dmMessage(e.Name, "create_thin", id)
	case eSnapshot:
		return dmMessage(e.Name, "create_snap", id, strconv.FormatUint(uint64(e.Origin), 10))
	case eDeleteThin:
		return deleteThin(e.Name, e.Thin)
	case eCreate:
		return dmCreate(e.Name, e.Table, e.ReadOnly)
	case eRemove:
		return dmRemove(e.Name)
	case eResume:
		return dmResume(e.Name)
	case eSuspend:
		_, err := dmsetup("--noudevsync", "suspend", e.Name)
		return err
	case eLoad:
		args := []string{"load", e.Name}
		if e.ReadOnly {
			args = append(args, "--readonly")
		}
		_, err := runIn(e.Table+"\n", nil, "dmsetup", args...)
		return err
	case eNodes:
		_, err := dmsetup("mknodes", e.Name)
		return err
	case eFormat:
		return mkfsExt4(ctx, mapperPath(e.Name), e.Size)
	case eGrow:
		return growExt4(ctx, mapperPath(e.Name), e.Size, e.Reproducible)
	case eDiscard:
		return discardOutside(mapperPath(e.Name), e.Regions, e.Size)
	case eMessage:
		return dmMessage(e.Name, e.Table)
	case eFlush:
		return flushDevice(mapperPath(e.Name))
	case eCheckClosed:
		n, err := dmOpenCount(e.Name)
		if err == nil && n > 0 {
			err = fmt.Errorf("%w: %s is still open", ErrInUse, e.Name)
		}
		return err
	case eCheckClean:
		dirty, err := ext4NeedsRecovery(mapperPath(e.Name))
		if err == nil && dirty {
			err = ErrUnclean
		}
		return err
	default:
		return fmt.Errorf("storage: unknown device effect %q", e.Kind)
	}
}

func (s *Store) deviceNames() map[string]bool {
	if s.devices != nil {
		return s.devices.Names()
	}
	return dmNames()
}

func (s *Store) deviceExists(name string) bool { return s.deviceNames()[name] }

func (s *Store) deviceTable(name string) (string, error) {
	if s.devices != nil {
		return s.devices.Table(name)
	}
	return dmTable(name)
}

func (s *Store) deviceCreate(name, table string, ro bool) error {
	return s.runOperation([]deviceEffect{{Kind: eCreate, Name: name, Table: table, ReadOnly: ro}}, nil)
}

func (s *Store) deviceRemove(name string) error {
	return s.runOperation([]deviceEffect{{Kind: eRemove, Name: name}}, nil)
}

func reloadPlan(name, table string, ro bool) []deviceEffect {
	return []deviceEffect{
		{Kind: eSuspend, Name: name},
		{Kind: eLoad, Name: name, Table: table, ReadOnly: ro},
		{Kind: eResume, Name: name, Always: true},
		{Kind: eNodes, Name: name},
	}
}

// layout is the immutable input to the pure volume planners.
type layout struct {
	pool, thin, top, plain, meta, fetch, crypt string
}

func (s *Store) layout(r *record) layout {
	return layout{s.poolName(), s.thinName(r), s.topName(r), s.plainName(r), s.metaName(r), s.fetchName(r),
		cryptTable(mapperPath(s.topName(r)), r.Size, s.cfg.Key)}
}

func createPlan(l layout, r, src *record, image bool) []deviceEffect {
	e := deviceEffect{Kind: eCreateThin, Name: l.pool, Thin: r.Thin}
	if src != nil {
		e.Kind, e.Origin = eSnapshot, src.Thin
	}
	steps := []deviceEffect{e}
	working := r.Kind == KindWorking
	grow := src != nil && r.fsBytes() > src.fsBytes()
	if !image && !working && src != nil && !grow {
		return steps
	}
	table := thinTable(l.pool, r.Thin, r.Size)
	steps = append(steps, deviceEffect{Kind: eCreate, Name: l.thin, Table: table, ReadOnly: working && !grow && r.ReadOnly})
	if working && !grow {
		return append(steps, deviceEffect{Kind: eCreate, Name: l.plain, Table: l.crypt, ReadOnly: r.ReadOnly})
	}
	steps = append(steps, deviceEffect{Kind: eCreate, Name: l.plain, Table: l.crypt})
	body := deviceEffect{Kind: eFormat, Name: l.plain, Size: r.fsBytes()}
	if image {
		body.Kind = eFill
	} else if grow {
		body.Kind, body.Reproducible = eGrow, !working && src.Kind == KindImage
	}
	steps = append(steps, body, deviceEffect{Kind: eRemove, Name: l.plain, Always: true})
	if !working {
		return append(steps, deviceEffect{Kind: eRemove, Name: l.thin, Always: true})
	}
	if r.ReadOnly {
		steps = append(steps, reloadPlan(l.thin, table, true)...)
	}
	return append(steps, deviceEffect{Kind: eCreate, Name: l.plain, Table: l.crypt, ReadOnly: r.ReadOnly})
}

func teardownPlan(l layout, r *record) []deviceEffect {
	var steps []deviceEffect
	if r.ResumeDevice != "" {
		steps = append(steps, deviceEffect{Kind: eResume, Name: r.ResumeDevice})
	}
	for _, name := range []string{l.fetch, l.plain, l.top, l.thin, l.meta} {
		steps = append(steps, deviceEffect{Kind: eRemove, Name: name, Teardown: true})
	}
	steps = append(steps, deviceEffect{Kind: eDeleteThin, Name: l.pool, Thin: r.Thin, Teardown: true})
	meta := r.TeardownMetaThin
	if r.Clone != nil {
		meta = r.Clone.MetaThin
	}
	if meta != 0 {
		steps = append(steps, deviceEffect{Kind: eDeleteThin, Name: l.pool, Thin: meta, Teardown: true})
	}
	return steps
}

func cloneSetupPlan(l layout, r, base *record, name string, regions []Region) []deviceEffect {
	c := r.Clone
	e := deviceEffect{Kind: eCreateThin, Name: l.pool, Thin: r.Thin}
	if base != nil {
		e.Kind, e.Origin = eSnapshot, base.Thin
	}
	table := fmt.Sprintf("0 %d clone %s %s %s %d 2 no_hydration no_discard_passdown 4 hydration_threshold 256 hydration_batch_size 32",
		c.SourceSize/512, mapperPath(l.meta), mapperPath(l.thin), c.Source, blockSectors)
	if r.Size > c.SourceSize {
		table += fmt.Sprintf("\n%d %d linear %s %d", c.SourceSize/512, (r.Size-c.SourceSize)/512, mapperPath(l.thin), c.SourceSize/512)
	}
	return []deviceEffect{
		e,
		{Kind: eCreateThin, Name: l.pool, Thin: c.MetaThin},
		{Kind: eCreate, Name: l.thin, Table: thinTable(l.pool, r.Thin, r.Size)},
		{Kind: eCreate, Name: l.meta, Table: thinTable(l.pool, c.MetaThin, c.MetaSize)},
		{Kind: eCreate, Name: name, Table: table},
		{Kind: eDiscard, Name: name, Regions: append([]Region(nil), regions...), Size: c.SourceSize},
	}
}

func finishClonePlan(l layout, r *record, cloning bool) []deviceEffect {
	var steps []deviceEffect
	if cloning {
		steps = append(steps, reloadPlan(l.top, linearTable(mapperPath(l.thin), r.Size), r.ReadOnly)...)
	} else {
		// A resume may have completed but its acknowledgement was lost, or the
		// process may have died after loading a new table while suspended.
		steps = append(steps, deviceEffect{Kind: eResume, Name: l.top})
	}
	return append(steps,
		deviceEffect{Kind: eRemove, Name: l.meta},
		deviceEffect{Kind: eDeleteThin, Name: l.pool, Thin: r.Clone.MetaThin})
}

func snapshotPlan(pool, name string, thin, origin uint32, active bool) []deviceEffect {
	snap := deviceEffect{Kind: eSnapshot, Name: pool, Thin: thin, Origin: origin}
	if !active {
		return []deviceEffect{snap}
	}
	return []deviceEffect{{Kind: eSuspend, Name: name}, snap, {Kind: eResume, Name: name, Always: true}}
}

// hydrationDecision consumes one observation, independent of polling time.
// Failure modes take precedence over counters: a failed target reporting a
// full counter must never be published as healthy local data.
func hydrationDecision(name, status string) (done bool, hydrated, total int64, err error) {
	hydrated, total, mode, err := cloneProgress(status)
	if err != nil {
		return false, 0, 0, err
	}
	if hydrated < 0 || total <= 0 || hydrated > total {
		return false, hydrated, total, fmt.Errorf("clone %s invalid progress %d/%d", name, hydrated, total)
	}
	if mode != "rw" {
		return false, hydrated, total, fmt.Errorf("clone %s metadata is %s", name, mode)
	}
	return hydrated == total, hydrated, total, nil
}

func imageFill(ctx context.Context, fill func(string) error) func(string) error {
	return func(dev string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return fill(dev)
	}
}
