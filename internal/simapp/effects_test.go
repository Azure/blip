// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package simapp

import (
	"fmt"
	"time"

	"github.com/Azure/blip/internal/node"
	"github.com/Azure/blip/internal/peer"
	bruntime "github.com/Azure/blip/internal/runtime"
	"github.com/Azure/blip/internal/storage"
	"github.com/Azure/blip/internal/wire"
)

func (w *world) apply(e bruntime.Event) {
	w.Effects = append(w.Effects, w.runtime.Apply(w.now(), e)...)
	w.observeRuntime()
}
func (w *world) reconcileRuntime() {
	// Retry time is external input, not a sleep. Each turn advances one second;
	// only runtime turns consume time, so informer scheduling cannot time out a
	// healthy node or accidentally consume the startup budget.
	w.Now += time.Second
	w.Effects = append(w.Effects, w.runtime.Reconcile(w.now())...)
	w.observeRuntime()
}
func (w *world) hello(gen int) {
	h := wire.Hello{ClaimID: w.GuestClaim}
	for _, id := range sortedKeys(w.GuestMounts) {
		if id != w.GuestClaim {
			h.Mounts = append(h.Mounts, id)
		}
	}
	w.Replies = append(w.Replies, control(gen, wire.THello, h))
}
func control(gen int, typ wire.Type, payload any) bruntime.Event {
	return bruntime.Event{Kind: bruntime.EventControl, Generation: gen, Type: typ, Payload: []byte(encode(payload))}
}

// Guest and CH here are environment effects, not reimplementations of their
// private business cores. Mounted filesystems, open VMM devices, and replies
// are distinct realities. In particular remove acceptance cannot seal a disk.
func (w *world) effect() error {
	e := w.Effects[0]
	w.Effects = w.Effects[1:]
	switch e.Kind {
	case bruntime.EffectAddDisk:
		v, ok := w.Working[e.Disk.ID]
		if !ok || v.Sealed {
			return fmt.Errorf("runtime attached missing/sealed volume %s", e.Disk.ID)
		}
		w.Devices[e.Disk.ID] = true
		w.Replies = append(w.Replies, bruntime.Event{Kind: bruntime.EventResult, Token: e.Token})
	case bruntime.EffectRemoveDisk:
		if w.GuestMounts[e.Disk.ID] {
			return fmt.Errorf("remove of mounted filesystem %s", e.Disk.ID)
		}
		if w.Removal != nil {
			return fmt.Errorf("overlapping CH removals")
		}
		w.Removal = &e // the device remains open until another scheduled action
	case bruntime.EffectConnect:
		w.apply(bruntime.Event{Kind: bruntime.EventConnected, Generation: e.Generation})
		w.hello(e.Generation)
		w.Coverage["reconnect"]++
	case bruntime.EffectClose:
	case bruntime.EffectKill:
		w.Devices = map[string]bool{}
		w.GuestMounts = map[string]bool{}
		w.VMExited = true
		w.apply(bruntime.Event{Kind: bruntime.EventVMExited})
	case bruntime.EffectSend:
		if e.Generation != w.runtime.Generation() {
			return nil
		}
		switch e.Type {
		case wire.TClaim:
			var claim wire.Claim
			if err := wire.Decode(e.Payload, &claim); err != nil {
				return err
			}
			if !w.Devices[claim.ID] {
				return fmt.Errorf("claim before root device")
			}
			if w.GuestClaim != "" && w.GuestClaim != claim.ID {
				return fmt.Errorf("guest claimed twice")
			}
			w.GuestClaim = claim.ID
			w.GuestMounts[claim.ID] = true
			for _, m := range claim.Mounts {
				if !w.Devices[m.ID] {
					return fmt.Errorf("claim before mount device")
				}
				w.GuestMounts[m.ID] = true
				w.Replies = append(w.Replies, control(e.Generation, wire.TMountResult, wire.Result{ID: m.ID}))
			}
			w.Replies = append(w.Replies, control(e.Generation, wire.TClaimResult, wire.Result{ID: claim.ID}))
		case wire.TUnmount:
			var u wire.Unmount
			if err := wire.Decode(e.Payload, &u); err != nil {
				return err
			}
			delete(w.GuestMounts, u.ID)
			w.Replies = append(w.Replies, control(e.Generation, wire.TUnmountResult, wire.Result{ID: u.ID}))
		case wire.TShutdown:
			w.GuestStopped = true
			w.GuestMounts = map[string]bool{}
			w.Replies = append(w.Replies, control(e.Generation, wire.TShutdownDone, wire.ShutdownDone{Clean: true}))
		default:
			return fmt.Errorf("unsupported workload control effect %v", e.Type)
		}
	default:
		return fmt.Errorf("unsupported runtime effect %s", e.Kind)
	}
	return nil
}

func (w *world) schedule(ops []node.Operation) []node.Attempt {
	return w.scheduler.Schedule(w.now(), ops)
}
func (w *world) complete(a node.Attempt, outcome node.Outcome) {
	if !w.scheduler.Complete(w.now(), a, outcome) {
		panic("completion lost its scheduler reservation")
	}
}

func (w *world) finishIO(ambiguous bool) error {
	i := w.IO
	switch i.Kind {
	case "prepare":
		if i.Prepare.Source != nil || i.Prepare.FromImage != "" {
			return fmt.Errorf("workload has no remote/image preparation effect")
		}
		bytes, ok := w.Durable[i.Node][i.Commit]
		if !ok {
			return fmt.Errorf("prepare from missing durable commit %s on %s", i.Commit, i.Node)
		}
		if old, ok := w.Working[i.ID]; ok && (old.Base != i.Commit || old.Node != i.Node) {
			return fmt.Errorf("attachment identity reused")
		}
		if _, exists := w.Working[i.ID]; !exists {
			w.Working[i.ID] = volume{State: i.State, Node: i.Node, Base: i.Commit, Bytes: bytes}
			w.Inventory[i.Node][i.ID] = storage.Volume{ID: i.ID, Kind: storage.KindWorking,
				StateUID: i.Prepare.StateUID, Base: i.Commit, SizeBytes: i.Prepare.SizeBytes, ReadOnly: i.Prepare.ReadOnly}
		}
		w.Directories[i.Node][i.Prepare.Pod].Devices[i.ID] = deviceNumber(i.ID)
	case "seal":
		if w.Devices[i.ID] || w.GuestMounts[i.ID] {
			return fmt.Errorf("seal before physical fence of %s", i.ID)
		}
		v, ok := w.Working[i.ID]
		if !ok {
			return fmt.Errorf("seal missing working volume")
		}
		if old, ok := w.Durable[i.Node][i.Commit]; ok && old != v.Bytes {
			return fmt.Errorf("commit identity changed contents")
		}
		w.Durable[i.Node][i.Commit] = v.Bytes
		working := w.Inventory[i.Node][i.ID]
		w.Inventory[i.Node][i.Commit] = storage.Volume{ID: i.Commit, Kind: storage.KindCommit,
			StateUID: working.StateUID, Base: working.Base, SizeBytes: working.SizeBytes}
		v.Sealed = true
		w.Working[i.ID] = v
		w.Saved[i.State] = i.Commit
	default:
		return fmt.Errorf("unexpected I/O %s", i.Kind)
	}
	outcome := node.Succeeded
	if ambiguous {
		outcome = node.Failed
	}
	w.complete(i.Attempt, outcome)
	w.IO = nil
	return nil
}

func (w *world) replicate() error {
	name := w.saveState()
	if w.Transfer == nil {
		p := w.nodePlan("n2")
		for _, f := range p.Fetches {
			if f.Owner == string(w.state(name).UID) {
				w.startPlannedIO(p, "state/"+f.Owner, ioAttempt{Kind: "fetch", State: name, Commit: f.Source.CommitID, Node: "n2", Source: &f.Source})
				break
			}
		}
		if w.IO == nil {
			return nil
		}
		id := w.IO.Commit
		bytes, ok := w.Durable[w.IO.Source.Node][id]
		if !ok {
			return fmt.Errorf("lease source absent")
		}
		w.Transfer = &transfer{State: name, Commit: id, Bytes: bytes, Operation: peer.PrepareLease}
		return nil
	}
	x := w.Transfer
	e := peer.NextLeaseEffect(x.Operation, x.Completed)
	if e == peer.LeaseDone {
		switch x.Operation {
		case peer.PrepareLease:
			x.Operation = peer.ActivateLease
			x.Completed = peer.LeaseDone
		case peer.ActivateLease:
			if !x.Published || !x.Pinned || !x.Open {
				return fmt.Errorf("replication without live lease")
			}
			if x.Copied < len(x.Bytes) {
				x.Copied = min(len(x.Bytes), x.Copied+(len(x.Bytes)+1)/2)
				w.Coverage["transfer-chunk"]++
				return nil
			}
			// A partial destination is not a commit. Publish only complete,
			// content-checked bytes, while its source lease remains pinned.
			if w.Durable[w.IO.Source.Node][x.Commit] != x.Bytes {
				return fmt.Errorf("source changed under lease")
			}
			w.Durable[w.IO.Node][x.Commit] = x.Bytes
			w.Inventory[w.IO.Node][x.Commit] = copyValue(w.Inventory[w.IO.Source.Node][x.Commit])
			x.Hydrated = true
			x.Operation = peer.ReleaseLease
			x.Completed = peer.LeaseDone
		case peer.ReleaseLease:
			w.complete(w.IO.Attempt, node.Succeeded)
			w.IO = nil
			w.Transfer = nil
			w.Stage++
		}
		return nil
	}
	switch e {
	case peer.LeasePin:
		x.Pinned = true
	case peer.LeasePersist:
		x.Persisted = true
	case peer.LeaseOpenDevice:
		x.Open = true
	case peer.LeasePublish:
		x.Published = true
	case peer.LeasePersistRevocation:
		x.Revoked = true
	case peer.LeaseUnpublish:
		x.Published = false
	case peer.LeaseCloseDevice:
		x.Open = false
	case peer.LeaseUnpin:
		x.Pinned = false
	case peer.LeaseForget:
		x.Persisted = false
	default:
		return fmt.Errorf("unknown lease effect %d", e)
	}
	x.Completed = e
	return nil
}
