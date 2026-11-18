package node

import (
	"cmp"
	"slices"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/image"
	"github.com/Azure/blip/internal/podapi"
	"github.com/Azure/blip/internal/registryauth"
	"github.com/Azure/blip/internal/storage"
)

// plan is the set of actions one pass decided on.
type plan struct {
	desired    map[string]podapi.Desired // podKey -> changed desired.json
	podMeta    []podMeta
	podErrs    []podErr
	prepares   []prepare
	seals      []seal
	deletes    []string // volume IDs
	rmDevs     []devRef
	rmDirs     []string // podKeys
	imports    []imageImport
	builds     []build
	digests    []string // commit IDs whose content digest to compute
	liveCopies []liveCopy
	fetches    []fetch
	entries    []entry
	needed     map[string]bool   // attachment IDs that pods on this node want
	errs       map[string]string // state UID -> why a needed fetch has no source
}

// podErr sets ("") or clears the prepare-error annotation of a pod.
type podErr struct {
	pod string // podKey
	err string
}

// podMeta sets the warm label and observed annotation of a VM pod.
type podMeta struct {
	namespace, name string
	warm            bool
	observed        string // "" leaves the annotation unchanged
}

// prepare creates a working volume (unless exists) and its device node.
type prepare struct {
	pod    string
	req    storage.CreateWorking
	src    *source // remote holder when the commit is not local
	exists bool
}

type seal struct {
	stateUID, attachmentID, commitID string
}

type devRef struct {
	pod, id string
}

// imageImport imports a pinned image reference with its pull credentials.
type imageImport struct {
	ref     string
	secrets []registryauth.PullSecret
}

// build is a commit this node builds.
type build struct {
	req storage.CreateCommit
}

// liveCopy snapshots a mounted working volume of pod, frozen by its guest,
// into a commit of stateUID.
type liveCopy struct {
	pod, stateUID, attachmentID, commitID string
}

// fetch copies a commit to this node. owner is the state the fetch is for
// (the copying state when fetching a copy source).
type fetch struct {
	owner string
	src   source
}

// entry is this node's status.nodes entry for a state; obs nil removes it.
type entry struct {
	namespace, name string
	obs             *v1alpha1.NodeObservation
}

func compute(v *view) *plan {
	// Index and canonicalize a local copy; a snapshot can be replayed or used
	// concurrently without compute changing it.
	local := *v
	v = &local
	v.states = slices.Clone(v.states)
	slices.SortFunc(v.states, func(a, b *v1alpha1.BlipState) int {
		return cmp.Or(cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Name, b.Name), cmp.Compare(a.UID, b.UID))
	})
	v.blips = slices.Clone(v.blips)
	slices.SortFunc(v.blips, func(a, b *v1alpha1.Blip) int {
		return cmp.Or(cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Name, b.Name), cmp.Compare(a.UID, b.UID))
	})
	v.index()
	p := &plan{desired: map[string]podapi.Desired{}, needed: map[string]bool{}, errs: map[string]string{}}
	planPods(v, p)
	sealed := planSeals(v, p)
	planStates(v, p)
	planGC(v, p, sealed)
	planEntries(v, p, sealed)
	return p
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func podDirectoryKey(pod string) string {
	if pod == "" {
		return ""
	}
	return "pod/" + pod
}

// operations is shared by admission and GC, so a planned source read is
// protected even before the worker starts or while it waits for a class slot.
func (p *plan) operations() []Operation {
	var ops []Operation
	for _, pr := range p.prepares {
		reads := []string{pr.req.FromCommit, pr.req.FromImage, podDirectoryKey(pr.pod)}
		if pr.src != nil {
			reads = append(reads, pr.src.bases...)
			reads = append(reads, pr.src.imageBases...)
		}
		ops = append(ops, Operation{Key: pr.req.AttachmentID, Writes: []string{pr.req.AttachmentID}, Reads: reads})
	}
	for _, s := range p.seals {
		ops = append(ops, Operation{Key: s.attachmentID, Class: "seal", Writes: []string{s.attachmentID, s.commitID}})
	}
	for _, imp := range p.imports {
		id, _ := image.DigestOf(imp.ref)
		ops = append(ops, Operation{Key: id, Class: "image", Writes: []string{id}})
	}
	for _, b := range p.builds {
		ops = append(ops, Operation{Key: stateKey(b.req.StateUID), Class: "image", Writes: []string{b.req.CommitID}, Reads: []string{b.req.FromImage, b.req.FromCommit}})
	}
	for _, id := range p.digests {
		ops = append(ops, Operation{Key: digestKey(id), Class: "image", Reads: []string{id}})
	}
	for _, lc := range p.liveCopies {
		ops = append(ops, Operation{Key: stateKey(lc.stateUID), Writes: []string{lc.attachmentID, lc.commitID}, Reads: []string{podDirectoryKey(lc.pod)}})
	}
	for _, f := range p.fetches {
		ops = append(ops, Operation{Key: stateKey(f.owner), Writes: []string{f.src.commitID}, Reads: append(slices.Clone(f.src.bases), f.src.imageBases...)})
	}
	return ops
}
