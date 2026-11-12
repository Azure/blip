package session

import (
	"context"
	"fmt"
	"slices"
	"sort"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/example/blip/internal/api/v1alpha1"
)

// Pin is a reason a snapshot of a BlipVol is kept beyond its snapshot
// limit, or the BlipVol cannot be deleted yet.
type Pin struct {
	Snapshot int64  // 0 when not about one snapshot
	Why      string // e.g. "origin of blipvol x", "claim of blip dev"
}

// VolumeInfo is a BlipVol with the pins on its snapshots.
type VolumeInfo struct {
	Vol  v1alpha1.BlipVol
	Pins []Pin
}

// ListVolumes returns the BlipVols of ns (all namespaces when ns is "")
// sorted by namespace and name, each with its pins. With name set, only
// that BlipVol is returned.
func (c *Client) ListVolumes(ctx context.Context, ns, name string) ([]VolumeInfo, error) {
	var l v1alpha1.BlipVolList
	if err := c.C.List(ctx, &l, client.InNamespace(ns)); err != nil {
		return nil, err
	}
	sort.Slice(l.Items, func(i, j int) bool {
		a, b := l.Items[i], l.Items[j]
		return a.Namespace < b.Namespace || (a.Namespace == b.Namespace && a.Name < b.Name)
	})
	var out []VolumeInfo
	for _, v := range l.Items {
		if name != "" && v.Name != name {
			continue
		}
		out = append(out, VolumeInfo{Vol: v, Pins: Pins(&v, l.Items)})
	}
	if name != "" && len(out) == 0 {
		return nil, fmt.Errorf("blipvol %s not found in namespace %s", name, ns)
	}
	return out, nil
}

// Pins returns what keeps snapshots of v: derived BlipVols among all whose
// status.origin names v, holds, and the claim's starting snapshot and
// baseline.
func Pins(v *v1alpha1.BlipVol, all []v1alpha1.BlipVol) []Pin {
	var out []Pin
	for _, d := range all {
		if o := d.Status.Origin; o != nil && o.UID == string(v.UID) && d.UID != v.UID {
			name := d.Name
			if d.Namespace != v.Namespace {
				name = d.Namespace + "/" + d.Name
			}
			out = append(out, Pin{Snapshot: o.Snapshot, Why: "origin of blipvol " + name})
		}
	}
	for _, h := range v.Status.Holds {
		out = append(out, Pin{Snapshot: h.Snapshot, Why: holdString(h)})
	}
	if cl := v.Status.Claim; cl != nil {
		if cl.Snapshot != 0 {
			out = append(out, Pin{Snapshot: cl.Snapshot, Why: "start of the attachment to blip " + cl.BlipName})
		}
		if cl.Baseline != 0 {
			out = append(out, Pin{Snapshot: cl.Baseline, Why: "baseline of the attachment to blip " + cl.BlipName})
		}
	}
	slices.SortStableFunc(out, func(a, b Pin) int { return int(a.Snapshot - b.Snapshot) })
	return out
}
