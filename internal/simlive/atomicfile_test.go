// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package simlive_test

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"testing"

	"github.com/Azure/blip/internal/atomicfile"
	"github.com/Azure/blip/internal/sim"
	"github.com/Azure/blip/internal/simlive"
)

const (
	replacePath = "/state/value"
	tempPath    = "/state/.value.tmp"
	replaceData = "new"
	replaceMode = fs.FileMode(0o640)
)

// fileWorld is below the production effect boundary. It separates volatile
// bytes/mode, synced bytes/mode, visible rename and synced directory entry.
// This finite scenario has one replacement, working fsync, no crashes or I/O
// errors, and arbitrary scheduler/delivery delays (including infinite delays).
type fileWorld struct {
	Temp, Open             bool
	Data, DurableData      string
	Mode, DurableMode      fs.FileMode
	VisibleNew, DurableNew bool
}

func (w *fileWorld) execute(e atomicfile.Effect) (atomicfile.Result, error) {
	var r atomicfile.Result
	switch e.Kind {
	case atomicfile.Create:
		if e.Path != replacePath || w.Temp || w.Open {
			return r, fmt.Errorf("invalid create")
		}
		w.Temp, w.Open, w.Mode = true, true, 0o600
		r.Name = tempPath
	case atomicfile.Write, atomicfile.Chmod, atomicfile.Sync:
		if !w.Open || !w.Temp || e.Path != tempPath {
			return r, fmt.Errorf("effect on missing descriptor")
		}
		switch e.Kind {
		case atomicfile.Write:
			w.Data += e.Data
			r.N = len(e.Data)
		case atomicfile.Chmod:
			w.Mode = e.Mode
		case atomicfile.Sync:
			w.DurableData, w.DurableMode = w.Data, w.Mode
		}
	case atomicfile.Close:
		if !w.Open || e.Path != tempPath {
			return r, fmt.Errorf("close on missing descriptor")
		}
		w.Open = false
	case atomicfile.Rename:
		if !w.Temp || e.Path != tempPath || e.Target != replacePath {
			return r, fmt.Errorf("rename of missing temporary file")
		}
		w.Temp, w.VisibleNew = false, true
	case atomicfile.SyncDir:
		if e.Path != "/state" {
			return r, fmt.Errorf("sync of wrong directory")
		}
		w.DurableNew = w.VisibleNew
	default:
		return r, fmt.Errorf("unexpected effect %s", e.Kind)
	}
	return r, nil
}

type fileModel struct {
	op      *atomicfile.Operation
	world   fileWorld
	pending *atomicfile.Result
}

func newFileModel() *fileModel {
	return &fileModel{op: atomicfile.New(replacePath, []byte(replaceData), replaceMode)}
}

func (m *fileModel) Clone() sim.Model {
	c := *m
	c.op = m.op.Clone()
	if m.pending != nil {
		p := *m.pending
		c.pending = &p
	}
	return &c
}

func (m *fileModel) Key() string {
	// For this fixed-input, fixed-temp, error-free scenario, Next includes the
	// phase and remaining write suffix, which determine all machine behavior.
	// The independently cloned world and in-flight response must also be keyed.
	e, more := m.op.Next()
	data, err := json.Marshal(struct {
		Next    atomicfile.Effect
		More    bool
		Error   string
		World   fileWorld
		Pending *atomicfile.Result
	}{e, more, fmt.Sprint(m.op.Err()), m.world, m.pending})
	if err != nil {
		panic(err)
	}
	return string(data)
}

func (m *fileModel) Enabled() []string {
	if m.op.Done() {
		return nil
	}
	if m.pending != nil {
		return []string{"wait", "complete"}
	}
	actions := []string{"wait", "apply"}
	e, _ := m.op.Next()
	if e.Kind == atomicfile.Write && len(e.Data) > 1 {
		actions = append(actions, "apply-short")
	}
	return actions
}

func (m *fileModel) Step(action string) error {
	switch action {
	case "wait":
		return nil
	case "complete":
		if m.pending == nil {
			return fmt.Errorf("delivery without a response")
		}
		m.op.Complete(*m.pending)
		m.pending = nil
		return nil
	case "apply", "apply-short":
		if m.pending != nil {
			return fmt.Errorf("effect repeated before delivery")
		}
		e, more := m.op.Next()
		if !more {
			return fmt.Errorf("effect after termination")
		}
		if action == "apply-short" {
			e.Data = e.Data[:1]
		}
		r, err := m.world.execute(e)
		if err != nil {
			return err
		}
		m.pending = &r
		return nil
	default:
		return fmt.Errorf("unknown action %q", action)
	}
}

func (m *fileModel) Check() error {
	if m.world.VisibleNew || m.world.DurableNew {
		if m.world.Data != replaceData || m.world.Mode != replaceMode ||
			m.world.DurableData != replaceData || m.world.DurableMode != replaceMode {
			return fmt.Errorf("replacement exposed before durable bytes and mode")
		}
	}
	if m.op.Done() && (m.op.Err() != nil || m.world.Open || !m.world.DurableNew) {
		return fmt.Errorf("successful termination without a durable replacement and closed descriptor")
	}
	return nil
}

func TestAtomicfileEventualDurableReplacementUnderWeakFairness(t *testing.T) {
	m := newFileModel()
	opts := simlive.Options{
		Limits: sim.Limits{States: 200, Depth: 30},
		Goal: func(m sim.Model) bool {
			f := m.(*fileModel)
			return f.op.Done() && f.op.Err() == nil && f.world.DurableNew
		},
		WeakFairness: []simlive.Group{
			{Name: "filesystem", Actions: []string{"apply", "apply-short"}},
			{Name: "completion delivery", Actions: []string{"complete"}},
		},
	}
	r := check(t, m, opts)
	if !r.Complete || r.Witness != nil {
		t.Fatalf("production replacement did not converge: %+v", r)
	}
	t.Logf("%d states, %d transitions", r.States, r.Transitions)
	for _, keep := range [][]simlive.Group{nil, opts.WeakFairness[:1], opts.WeakFairness[1:]} {
		opts.WeakFairness = keep
		r := check(t, m, opts)
		if !r.Complete || r.Witness == nil || len(r.Witness.Cycle) == 0 {
			t.Fatalf("unfair effect/delivery starvation escaped: %+v", r)
		}
	}
}
