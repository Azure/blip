package node

import (
	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/podapi"
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
	secrets []pullSecret
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
	v.index()
	p := &plan{desired: map[string]podapi.Desired{}, needed: map[string]bool{}, errs: map[string]string{}}
	planPods(v, p)
	sealed := planSeals(v, p)
	planStates(v, p)
	planGC(v, p, sealed)
	planEntries(v, p, sealed)
	return p
}
