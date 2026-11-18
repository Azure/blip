package node

import (
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/image"
	"github.com/Azure/blip/internal/network"
	"github.com/Azure/blip/internal/podapi"
	"github.com/Azure/blip/internal/storage"
)

// Snapshot supplies observations to the production node planner without clients,
// devices or workers. Maps keyed by pod use namespace/name; Busy uses Scheduler's
// reservation keys. Missing objects are not proof of deletion: Gone maps contain
// only absences confirmed by authoritative reads. Callers keep inputs unchanged
// during Compute; the returned Plan owns its values independently of this input.
type Snapshot struct {
	Now               time.Time
	Node, Incarnation string
	Nodes             []v1alpha1.BlipNode
	KubeNodes         []corev1.Node // nil means unknown
	Pools             []v1alpha1.BlipPool
	States            []v1alpha1.BlipState
	Blips             []v1alpha1.Blip
	Pods              []corev1.Pod // all pods; Compute selects this node's VM pods
	Directories       map[string]PodSnapshot
	Volumes           []storage.Volume
	Devices           map[string]uint64
	Configs           map[string]*image.Config
	Busy, Pinned      map[string]bool
	Freezes           map[string][]string
	SealErrors        map[string]string
	StateErrors       map[string]string
	Progress          map[string]*v1alpha1.Transfer
	PodsGone          map[string]bool
	StatesGone        map[string]bool
	BlipsGone         map[string]bool
	Destinations      network.Destinations
}

// PodSnapshot is the on-disk node/runtime contract and device-node inventory.
// Device numbers are distinct from the VMM's open device handles.
type PodSnapshot struct {
	Desired  *podapi.Desired
	Observed *podapi.Observed
	Devices  map[string]uint64
}

// Plan projects the lifecycle portion of the existing planner. Image imports,
// initial builds, live copies and garbage collection still belong to Agent's
// executor; this bridge neither performs those effects nor replaces compute.
type Plan struct {
	Desired    map[string]podapi.Desired
	Pods       []PodUpdate
	PodErrors  map[string]string // changed prepare-error annotations; empty clears
	Prepares   []PrepareRequest
	Seals      []SealRequest
	Fetches    []FetchRequest
	Entries    []StateEntry
	Operations []Operation // production reservations, including other planned jobs
}

type PodUpdate struct {
	Namespace, Name string
	Warm            bool
	Observed        string // empty leaves the annotation unchanged
}

// PrepareRequest contains only values, before a remote source is opened.
type PrepareRequest struct {
	Pod, AttachmentID, StateUID, FromImage, FromCommit string
	SizeBytes                                          int64
	ReadOnly, Exists                                   bool
	Source                                             *CommitSource
}

type SealRequest struct {
	StateUID, AttachmentID, CommitID string
}

type CommitSource struct {
	Node, Purpose, StateUID, CommitID string
	Bases, ImageBases                 []string
}

type FetchRequest struct {
	Owner  string // state UID
	Source CommitSource
}

type StateEntry struct {
	Namespace, Name string
	Observation     *v1alpha1.NodeObservation // nil removes this node's entry
}

// Compute runs exactly the planner used by Agent.sync. No input or live agent
// state is retained, and no I/O is performed.
func Compute(s Snapshot) Plan {
	v := &view{
		now: s.Now, node: s.Node, incarnation: s.Incarnation,
		blipNodes: map[string]*v1alpha1.BlipNode{}, pools: map[string]*v1alpha1.BlipPool{},
		states: ptrs(s.States), blips: ptrs(s.Blips), pods: map[string]*corev1.Pod{},
		dirs: map[string]*podDir{}, volumes: map[string]storage.Volume{},
		devices: s.Devices, configs: s.Configs, busy: s.Busy, pinned: s.Pinned,
		freezes: s.Freezes, sealErrs: s.SealErrors, stateErrs: s.StateErrors, progress: s.Progress,
		podsGone: s.PodsGone, statesGone: s.StatesGone, blipsGone: s.BlipsGone, destinations: s.Destinations,
	}
	for i := range s.Nodes {
		v.blipNodes[s.Nodes[i].Name] = &s.Nodes[i]
	}
	if s.KubeNodes != nil {
		v.kubeNodes = map[string]*corev1.Node{}
		for i := range s.KubeNodes {
			v.kubeNodes[s.KubeNodes[i].Name] = &s.KubeNodes[i]
		}
	}
	for i := range s.Pools {
		p := &s.Pools[i]
		v.pools[p.Namespace+"/"+p.Name] = p
	}
	for i := range s.Pods {
		p := &s.Pods[i]
		if p.Spec.NodeName == s.Node && p.Labels[v1alpha1.LabelPool] != "" {
			v.pods[podKey(p.Namespace, p.Name)] = p
		}
	}
	for key, d := range s.Directories {
		v.dirs[key] = &podDir{desired: d.Desired, observed: d.Observed, devs: d.Devices}
	}
	for _, vol := range s.Volumes {
		v.volumes[vol.ID] = vol
	}
	p := compute(v)
	out := Plan{Desired: map[string]podapi.Desired{}, PodErrors: map[string]string{}, Operations: p.operations()}
	for key, d := range p.desired {
		out.Desired[key] = copyDesired(d)
	}
	for _, m := range p.podMeta {
		out.Pods = append(out.Pods, PodUpdate{Namespace: m.namespace, Name: m.name, Warm: m.warm, Observed: m.observed})
	}
	for _, e := range p.podErrs {
		out.PodErrors[e.pod] = e.err
	}
	for _, pr := range p.prepares {
		r := pr.req
		out.Prepares = append(out.Prepares, PrepareRequest{Pod: pr.pod, AttachmentID: r.AttachmentID,
			StateUID: r.StateUID, FromImage: r.FromImage, FromCommit: r.FromCommit,
			SizeBytes: r.SizeBytes, ReadOnly: r.ReadOnly, Exists: pr.exists, Source: copySource(pr.src)})
	}
	for _, r := range p.seals {
		out.Seals = append(out.Seals, SealRequest{StateUID: r.stateUID, AttachmentID: r.attachmentID, CommitID: r.commitID})
	}
	for _, f := range p.fetches {
		out.Fetches = append(out.Fetches, FetchRequest{Owner: f.owner, Source: *copySource(&f.src)})
	}
	for _, e := range p.entries {
		out.Entries = append(out.Entries, StateEntry{Namespace: e.namespace, Name: e.name, Observation: e.obs.DeepCopy()})
	}
	return out
}

func copySource(s *source) *CommitSource {
	if s == nil {
		return nil
	}
	return &CommitSource{Node: s.node, Purpose: s.purpose, StateUID: s.stateUID,
		CommitID: s.commitID, Bases: slices.Clone(s.bases), ImageBases: slices.Clone(s.imageBases)}
}

func copyDesired(d podapi.Desired) podapi.Desired {
	if d.Claim != nil {
		c := *d.Claim
		c.Command, c.Env = slices.Clone(c.Command), slices.Clone(c.Env)
		d.Claim = &c
	}
	d.Mounts, d.Freeze = slices.Clone(d.Mounts), slices.Clone(d.Freeze)
	if d.Network != nil {
		n := *d.Network
		n.Layers = slices.Clone(n.Layers)
		for i, layer := range n.Layers {
			n.Layers[i] = slices.Clone(layer)
			for j := range n.Layers[i] {
				n.Layers[i][j].Except = slices.Clone(layer[j].Except)
			}
		}
		d.Network = &n
	}
	return d
}
