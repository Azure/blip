package atomicfile

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"strings"
	"testing"

	"github.com/Azure/blip/internal/sim"
)

const (
	destination = "/pod/state.json"
	oldData     = "old"
	newData     = "new"
	oldMode     = fs.FileMode(0o644)
	newMode     = fs.FileMode(0o640)
)

var errDisk = errors.New("injected disk failure")

// diskFS is below the effect boundary: directory entries name inodes, and
// inode bytes/mode persist independently of directory entries. Rename changes
// only live names; Sync changes only the inode; SyncDir changes only names.
// Crash discards descriptors and volatile state, without invoking any cleanup.
// Unsynced directory changes may either survive or disappear. This finite
// model assumes crash-atomic rename and working fsync, as the package requires.
type diskInode struct {
	Data, DurableData string
	Mode, DurableMode fs.FileMode
}

type diskFS struct {
	Names        map[string]int
	DurableNames map[string]int
	Inodes       map[int]diskInode
	Open         int
	Sequence     int
}

func newDiskFS(existing bool) diskFS {
	d := diskFS{
		Names: map[string]int{}, DurableNames: map[string]int{},
		Inodes: map[int]diskInode{}, Sequence: 1,
	}
	if existing {
		d.Names[destination] = 1
		d.DurableNames[destination] = 1
		d.Inodes[1] = diskInode{oldData, oldData, oldMode, oldMode}
	}
	return d
}

func (d diskFS) clone() diskFS {
	d.Names = maps.Clone(d.Names)
	d.DurableNames = maps.Clone(d.DurableNames)
	d.Inodes = maps.Clone(d.Inodes)
	return d
}

func (d *diskFS) Execute(e Effect) Result {
	switch e.Kind {
	case Create:
		d.Sequence++
		name := fmt.Sprintf("/pod/.state.json.%d", d.Sequence)
		d.Open = d.Sequence
		d.Names[name] = d.Open
		d.Inodes[d.Open] = diskInode{Mode: 0o600, DurableMode: 0o600}
		return Result{Name: name}
	case Write:
		inode := d.Inodes[d.Open]
		inode.Data += e.Data
		d.Inodes[d.Open] = inode
		return Result{N: len(e.Data)}
	case Chmod:
		inode := d.Inodes[d.Open]
		inode.Mode = e.Mode
		d.Inodes[d.Open] = inode
	case Sync:
		inode := d.Inodes[d.Open]
		inode.DurableData, inode.DurableMode = inode.Data, inode.Mode
		d.Inodes[d.Open] = inode
	case Close:
		d.Open = 0
	case Rename:
		d.Names[e.Target] = d.Names[e.Path]
		delete(d.Names, e.Path)
	case SyncDir:
		d.DurableNames = maps.Clone(d.Names)
	case Cleanup:
		delete(d.Names, e.Path)
	default:
		panic("unknown effect")
	}
	return Result{}
}

func (d *diskFS) crash(keepDirectory bool) {
	if keepDirectory {
		d.DurableNames = maps.Clone(d.Names)
	}
	d.Names = maps.Clone(d.DurableNames)
	for id, inode := range d.Inodes {
		inode.Data, inode.Mode = inode.DurableData, inode.DurableMode
		d.Inodes[id] = inode
	}
	d.Open = 0
}

type replaceModel struct {
	op           *Operation
	disk         diskFS
	pending      *Result
	existing     bool
	crashed      bool
	acknowledged bool
	renamed      bool // actual rename, even if the process has not seen its result
}

func newReplaceModel(existing bool) *replaceModel {
	return &replaceModel{
		op:   New(destination, []byte(newData), newMode),
		disk: newDiskFS(existing), existing: existing,
	}
}

func (m *replaceModel) Clone() sim.Model {
	c := *m
	if m.op != nil {
		c.op = m.op.Clone()
	}
	c.disk = m.disk.clone()
	if m.pending != nil {
		r := *m.pending
		c.pending = &r
	}
	return &c
}

func (m *replaceModel) Key() string {
	// Include the machine, filesystem, in-flight response, and monitors. Error
	// text is canonical here: injected errors are immutable fixed sentinels.
	op, pending := "", ""
	if o := m.op; o != nil {
		op = fmt.Sprintf("%q/%q/%o/%q/%d/%s/%t/%v", o.path, o.data, o.mode, o.temp, o.offset, o.next, o.renamed, o.err)
	}
	if r := m.pending; r != nil {
		pending = fmt.Sprintf("%q/%d/%v", r.Name, r.N, r.Err)
	}
	data, err := json.Marshal(struct {
		Operation, Pending string
		Disk               diskFS
		Existing, Crashed  bool
		Acked, Renamed     bool
	}{op, pending, m.disk, m.existing, m.crashed, m.acknowledged, m.renamed})
	if err != nil {
		panic(err)
	}
	return string(data)
}

func (m *replaceModel) Enabled() []string {
	if m.op == nil {
		return []string{"recover"}
	}
	var actions []string
	if !m.crashed {
		actions = append(actions, "crash/drop-directory", "crash/keep-directory")
	}
	if m.pending != nil {
		return append(actions, "complete")
	}
	e, ok := m.op.Next()
	if !ok {
		return actions
	}
	prefix := string(e.Kind) + "/"
	actions = append(actions, prefix+"ok")
	if m.crashed {
		return actions // recovery has a fair, fault-free suffix
	}
	actions = append(actions, prefix+"fail")
	if e.Kind == Write {
		actions = append(actions, prefix+"zero", prefix+"partial-error")
		if len(e.Data) > 1 {
			actions = append(actions, prefix+"short")
		}
	}
	if e.Kind == Sync || e.Kind == SyncDir || e.Kind == Chmod {
		actions = append(actions, prefix+"fail-after")
	}
	return actions
}

func (m *replaceModel) Step(action string) error {
	switch action {
	case "crash/drop-directory", "crash/keep-directory":
		m.disk.crash(action == "crash/keep-directory")
		m.op, m.pending, m.crashed = nil, nil, true
		return nil
	case "recover":
		// Orphan temps are ignored. A fresh exclusive temp name makes retry
		// independent of whether the previous cleanup reached the disk.
		m.op = New(destination, []byte(newData), newMode)
		return nil
	case "complete":
		m.op.Complete(*m.pending)
		m.pending = nil
		if m.op.Done() && m.op.Err() == nil {
			m.acknowledged = true
		}
		return nil
	}
	e, ok := m.op.Next()
	if !ok {
		return fmt.Errorf("effect after completion")
	}
	if !strings.HasPrefix(action, string(e.Kind)+"/") {
		return fmt.Errorf("effect %q does not match %s", action, e.Kind)
	}
	var r Result
	switch strings.TrimPrefix(action, string(e.Kind)+"/") {
	case "ok":
		r = m.disk.Execute(e)
	case "fail":
		if e.Kind == Close {
			m.disk.Execute(e) // close consumes its descriptor even on error
		}
		r.Err = errDisk
	case "fail-after":
		r = m.disk.Execute(e)
		r.Err = errDisk
	case "zero":
	case "short", "partial-error":
		e.Data = e.Data[:1]
		r = m.disk.Execute(e)
		if strings.HasSuffix(action, "partial-error") {
			r.Err = errDisk
		}
	default:
		return fmt.Errorf("unknown action %q", action)
	}
	if e.Kind == Rename && r.Err == nil {
		m.renamed = true
	}
	m.pending = &r
	return nil
}

func (m *replaceModel) Check() error {
	check := func(names map[string]int, durable bool) error {
		id, exists := names[destination]
		if !exists {
			if m.existing || m.acknowledged {
				return fmt.Errorf("destination disappeared")
			}
			return nil
		}
		inode, exists := m.disk.Inodes[id]
		if !exists {
			return fmt.Errorf("destination names a missing inode")
		}
		data, mode := inode.Data, inode.Mode
		if durable {
			data, mode = inode.DurableData, inode.DurableMode
		}
		switch {
		case data == newData && mode == newMode:
			if !m.renamed {
				return fmt.Errorf("new destination before rename")
			}
		case data == oldData && mode == oldMode && m.existing:
			if m.acknowledged {
				return fmt.Errorf("acknowledged replacement lost after crash")
			}
		default:
			return fmt.Errorf("partial data or wrong mode: data=%q mode=%#o", data, mode)
		}
		return nil
	}
	// Readers see only complete versions. Both possible crash directory images
	// must also refer to a complete, durable inode, even before acknowledgement.
	if err := check(m.disk.Names, false); err != nil {
		return fmt.Errorf("visible: %w", err)
	}
	if err := check(m.disk.DurableNames, true); err != nil {
		return fmt.Errorf("crash discards directory changes: %w", err)
	}
	if err := check(m.disk.Names, true); err != nil {
		return fmt.Errorf("crash retains directory changes: %w", err)
	}
	if m.op != nil && m.op.Done() {
		if m.disk.Open != 0 {
			return fmt.Errorf("completed operation leaked descriptor")
		}
		if m.crashed && m.op.Err() != nil {
			return fmt.Errorf("fault-free recovery did not converge: %w", m.op.Err())
		}
	}
	return nil
}

func TestReplacementCrashExploration(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprintf("existing=%t", existing), func(t *testing.T) {
			initial := newReplaceModel(existing)
			report, err := sim.Explore(initial, sim.Limits{States: 30000, Depth: 64})
			if err != nil {
				t.Fatalf("%v\ntrace: %+v", err, report.Trace)
			}
			if !report.Complete {
				t.Fatalf("incomplete exploration: %+v", report)
			}
			t.Logf("%d states, %d transitions", report.States, report.Transitions)
			for seed := uint64(0); seed < 20; seed++ {
				trace, err := sim.Run(initial, seed, 64)
				if err != nil {
					t.Fatalf("seed %d: %v", seed, err)
				}
				final, err := sim.Replay(initial, trace)
				if err != nil {
					t.Fatalf("replay seed %d: %v", seed, err)
				}
				if len(final.Enabled()) != 0 {
					t.Fatalf("seed %d did not finish recovery", seed)
				}
			}
		})
	}
}

func TestCrashModelDetectsMissingSyncs(t *testing.T) {
	for _, omitted := range []Kind{Sync, SyncDir} {
		t.Run(string(omitted), func(t *testing.T) {
			m := newReplaceModel(true)
			for {
				e, ok := m.op.Next()
				if !ok {
					break
				}
				if e.Kind == omitted {
					// Negative control: emulate a production regression that
					// claims success without issuing the durability effect.
					m.pending = &Result{}
				} else if err := m.Step(string(e.Kind) + "/ok"); err != nil {
					t.Fatal(err)
				}
				if err := m.Step("complete"); err != nil {
					t.Fatal(err)
				}
			}
			if err := m.Check(); err == nil {
				t.Fatal("model accepted a replacement that omitted a required sync")
			}
		})
	}
}
