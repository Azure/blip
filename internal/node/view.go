// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Package node is the blip-node agent: it owns the node's storage, peer trust and
// export service, prepares disks for VM pods, and reports this node's view of
// every BlipState. See the README's implementation outline.
//
// Each pass reads a snapshot (view) of cached cluster objects, the store, and
// the pod directories, computes a plan with pure functions, and executes it.
// Long operations run in the background and trigger another pass when done.
package node

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/image"
	"github.com/Azure/blip/internal/network"
	"github.com/Azure/blip/internal/peer"
	"github.com/Azure/blip/internal/podapi"
	"github.com/Azure/blip/internal/storage"
)

// nodeHeartbeatTTL is how long a node's last heartbeat keeps it eligible as
// a source of commits.
const nodeHeartbeatTTL = 60 * time.Second

// podKey is the namespace-qualified key of a VM pod. It is also the key of
// its pod directory, so identically named pods in different namespaces never
// collide.
func podKey(namespace, name string) string { return namespace + "/" + name }

// podDirFor returns the host directory of a pod key below dataDir. The
// default data directory uses podapi.PodDir, shared with the runtime's mount.
func podDirFor(dataDir, key string) string {
	namespace, name, _ := strings.Cut(key, "/")
	if dataDir == "" || dataDir == podapi.DataDir {
		return podapi.PodDir(namespace, name)
	}
	return filepath.Join(dataDir, "pods", namespace, name)
}

// podDirFor returns the host directory of a pod key on this node.
func (a *Agent) podDirFor(key string) string { return podDirFor(a.cfg.DataDir, key) }

// Store is the part of *storage.Store the agent uses.
type Store interface {
	Incarnation() string
	FreeBytes() int64
	List() []storage.Volume
	PendingDeletes() []string
	CreateImage(ctx context.Context, id string, sizeBytes int64, fill func(dev string) error) error
	CreateCommit(ctx context.Context, req storage.CreateCommit) error
	FetchCommit(ctx context.Context, stateUID, commitID string, src storage.Remote, progress func(done, total int64)) error
	CreateWorking(ctx context.Context, req storage.CreateWorking) (string, error)
	Activate(id string) (string, error)
	Seal(ctx context.Context, attachmentID, commitID string) (int64, error)
	LiveCopy(ctx context.Context, attachmentID, commitID, stateUID string) (int64, error)
	Delete(ctx context.Context, id string) error
	Digest(ctx context.Context, id string) (string, error)
	// Device returns the plaintext device path of a working volume.
	Device(id string) (string, error)
	// OpenView publishes a read-only view of a commit; CloseView releases it.
	OpenView(ctx context.Context, stateUID, commitID, viewID string) (string, error)
	CloseView(viewID string) error
}

// SealCommitID is the commit ID a seal of attachmentID produces. Deriving it
// makes sealing idempotent across agent restarts.
func SealCommitID(attachmentID string) string {
	sum := sha256.Sum256([]byte("blip-seal:" + attachmentID))
	return hex.EncodeToString(sum[:8])
}

// view is one consistent-enough snapshot of everything a pass decides from.
type view struct {
	now         time.Time
	node        string
	incarnation string
	blipNodes   map[string]*v1alpha1.BlipNode
	kubeNodes   map[string]*corev1.Node       // Kubernetes Nodes by name; nil = unknown
	pools       map[string]*v1alpha1.BlipPool // namespace/name
	states      []*v1alpha1.BlipState
	blips       []*v1alpha1.Blip
	pods        map[string]*corev1.Pod // VM pods on this node by podKey
	dirs        map[string]*podDir     // pod directories by podKey
	volumes     map[string]storage.Volume
	pending     []string                 // volume IDs whose teardown failed and must be retried
	devices     map[string]uint64        // volume ID -> rdev of its active device
	configs     map[string]*image.Config // image ID -> artifact config
	pinned      map[string]bool          // export pins captured before planning
	busy        map[string]bool          // volume IDs and stateKey(uid) with running operations
	freezes     map[string][]string      // podKey -> disk IDs a live copy wants frozen
	sealErrs    map[string]string
	stateErrs   map[string]string
	progress    map[string]*v1alpha1.Transfer // state UID -> running fetch
	podsGone    map[string]bool               // podKeys confirmed absent by a live read
	statesGone  map[string]bool               // state UIDs confirmed absent by a live read
	blipsGone   map[string]bool               // blip UIDs confirmed absent by a live read
	idleImages  map[string]bool               // cached image IDs unused for imageRetention

	destinations network.Destinations // cluster-wide network destinations, not managed pods

	stateByUID  map[string]*v1alpha1.BlipState
	stateByName map[string]*v1alpha1.BlipState // namespace/name
	blipByUID   map[string]*v1alpha1.Blip
	trusted     *peer.Registry // immutable trust snapshot for this planning pass
}

type podDir struct {
	observed *podapi.Observed
	desired  *podapi.Desired
	devs     map[string]uint64 // attachment ID -> rdev of dev/<id> (0 if not a block device)
}

func (v *view) index() {
	v.trusted = peer.NewRegistry()
	v.trusted.SetPeers(v.registeredPeers())
	v.stateByUID = map[string]*v1alpha1.BlipState{}
	v.stateByName = map[string]*v1alpha1.BlipState{}
	v.blipByUID = map[string]*v1alpha1.Blip{}
	for _, s := range v.states {
		v.stateByUID[string(s.UID)] = s
		v.stateByName[s.Namespace+"/"+s.Name] = s
	}
	for _, b := range v.blips {
		v.blipByUID[string(b.UID)] = b
	}
}

func stateKey(uid string) string { return "state/" + uid }

// imageKey keys the error of the last failed import of an image in stateErrs.
func imageKey(id string) string { return "image/" + id }

// digestKey keys a running digest computation of a commit in busy.
func digestKey(id string) string { return "digest/" + id }

func (v *view) holds(commitID string) bool {
	vol, ok := v.volumes[commitID]
	return ok && vol.Kind == storage.KindCommit
}

func (v *view) hasImage(id string) bool {
	vol, ok := v.volumes[id]
	return ok && vol.Kind == storage.KindImage
}

// held returns the sorted commit IDs this node holds for a state.
func (v *view) held(stateUID string) []string {
	var ids []string
	for _, vol := range v.volumes {
		if vol.Kind == storage.KindCommit && vol.StateUID == stateUID {
			ids = append(ids, vol.ID)
		}
	}
	slices.Sort(ids)
	return ids
}

// bases returns the held commits of a state that can serve as delta bases by
// ID. Commits built from an image are excluded: each node converts images
// itself, so the same commit ID may differ between nodes (see imageBases).
func (v *view) bases(stateUID string) []string {
	return slices.DeleteFunc(v.held(stateUID), func(id string) bool { return v.builtFromImage(stateUID, id) })
}

// imageBases returns the held commits of a state built from an image. They
// can serve as delta bases only by content digest: image conversion is
// reproducible, so they usually match the exporter's copy.
func (v *view) imageBases(stateUID string) []string {
	return slices.DeleteFunc(v.held(stateUID), func(id string) bool {
		vol := v.volumes[id]
		return !v.builtFromImage(stateUID, id) || vol.Hydrating || vol.Failed != ""
	})
}

// builtFromImage reports whether commit id of a state was built from an
// image (once the image is deleted only its digest is left as the base).
func (v *view) builtFromImage(stateUID, id string) bool {
	b := v.volumes[id].Base
	if b == "" {
		return false
	}
	if s := v.stateByUID[stateUID]; s != nil {
		if img, _ := image.DigestOf(s.Status.ImageDigest); b == img {
			return true
		}
	}
	return v.hasImage(b) || strings.Contains(b, ":")
}

// source is a remote node to read a commit from.
type source struct {
	node     string
	purpose  string
	stateUID string
	commitID string
	bases    []string
	// imageBases are offered to the exporter by content digest.
	imageBases []string
}

func nodePeer(n *v1alpha1.BlipNode) peer.Peer {
	if n == nil {
		return peer.Peer{}
	}
	return peer.Peer{Node: n.Name, PublicKey: n.Status.TLSPublicKey, Endpoint: n.Status.Endpoint}
}

// registeredPeers includes the local node so duplicate identities are rejected
// consistently by both source selection and the live trust registry.
func (v *view) registeredPeers() []peer.Peer {
	peers := make([]peer.Peer, 0, len(v.blipNodes))
	for _, key := range sortedKeys(v.blipNodes) {
		n := v.blipNodes[key]
		peers = append(peers, nodePeer(n))
	}
	return peers
}

// healthyNode returns the BlipNode of name if it can serve commits now: it
// has a trusted TLS identity and endpoint, is not draining, its Kubernetes Node
// still exists, and its heartbeat is recent. incarnation is checked when non-empty.
func (v *view) healthyNode(name, incarnation string) *v1alpha1.BlipNode {
	return v.presentNode(name, incarnation, false)
}

// servingNode is healthyNode without the drain check. Draining forbids new
// placements; it does not stop a node from serving a commit it already sealed.
// A save whose source began draining must still be replicable, or the state
// would wait for that commit forever.
func (v *view) servingNode(name, incarnation string) *v1alpha1.BlipNode {
	return v.presentNode(name, incarnation, true)
}

func (v *view) presentNode(name, incarnation string, allowDrain bool) *v1alpha1.BlipNode {
	bn := v.blipNodes[name]
	if bn == nil || (!allowDrain && bn.Spec.Drain) {
		return nil
	}
	if p, ok := v.trusted.Lookup(name); !ok || p != nodePeer(bn) {
		return nil
	}
	if incarnation != "" && bn.Status.Incarnation != incarnation {
		return nil
	}
	if v.kubeNodes != nil && v.kubeNodes[name] == nil {
		return nil
	}
	hb := bn.Status.Heartbeat
	if hb == nil || v.now.Sub(hb.Time) > nodeHeartbeatTTL {
		return nil
	}
	return bn
}

// holder picks a healthy node that reports holding commitID of s, preferring
// prefer (only if it is itself a healthy holder), then placements. Entries
// from a stale incarnation or an unhealthy node are ignored. It returns nil
// rather than a dead preferred node.
func (v *view) holder(s *v1alpha1.BlipState, commitID, prefer string) *source {
	return v.holderFrom(s, commitID, prefer, func(name, incarnation string) bool {
		return v.healthyNode(name, incarnation) != nil
	})
}

// servingHolder picks a holder for a commit this node needs to fetch. It
// prefers a node healthy for new placements, then accepts a healthy draining
// holder: draining forbids new placements, not serving a commit it already
// sealed. Without the fallback repair could never move the last copy off a
// draining node.
func (v *view) servingHolder(s *v1alpha1.BlipState, commitID string) *source {
	if src := v.holder(s, commitID, ""); src != nil {
		return src
	}
	return v.holderFrom(s, commitID, "", func(name, incarnation string) bool {
		return v.servingNode(name, incarnation) != nil
	})
}

// servingSource picks a holder for a pending commit whose source is prefer.
// It first looks for a node that is healthy for new placements; when there is
// none, it accepts prefer itself if it is healthy and merely draining. Draining
// blocks new placements, not reading a commit the node already sealed. Without
// this fallback a drain that starts while a save is replicating leaves every
// replica reporting "no healthy holder of commit ...", and the save never
// resolves.
func (v *view) servingSource(s *v1alpha1.BlipState, commitID, prefer string) *source {
	if src := v.holder(s, commitID, prefer); src != nil {
		return src
	}
	if prefer == "" {
		return nil
	}
	return v.holderFrom(s, commitID, prefer, func(name, incarnation string) bool {
		return name == prefer && v.servingNode(name, incarnation) != nil
	})
}

func (v *view) holderFrom(s *v1alpha1.BlipState, commitID, prefer string, eligible func(name, incarnation string) bool) *source {
	if s == nil {
		return nil
	}
	var candidates []string
	for _, e := range s.Status.Nodes {
		if e.Node == v.node || !slices.Contains(e.Commits, commitID) {
			continue
		}
		if !eligible(e.Node, e.Incarnation) {
			continue
		}
		candidates = append(candidates, e.Node)
	}
	rank := func(n string) int {
		if n == prefer {
			return 0
		}
		if slices.Contains(s.Status.Placements, n) {
			return 1
		}
		return 2
	}
	slices.SortFunc(candidates, func(a, b string) int { return cmp.Or(rank(a)-rank(b), cmp.Compare(a, b)) })
	if len(candidates) == 0 {
		return nil
	}
	return &source{
		node:       candidates[0],
		stateUID:   string(s.UID),
		commitID:   commitID,
		bases:      v.bases(string(s.UID)),
		imageBases: v.imageBases(string(s.UID)),
	}
}

// fenced reports whether the VM of pod podKey can no longer write the
// attachment: the VMM exited, the disk was detached, or the pod is gone or
// terminated. podUID "" matches any pod with that key.
func (v *view) fenced(podKey, podUID, attachmentID string) bool {
	if dir := v.dirs[podKey]; dir != nil && dir.observed != nil {
		if dir.observed.Phase == podapi.PhaseExited {
			return true
		}
		for _, m := range dir.observed.Mounts {
			if m.ID == attachmentID && m.Phase == podapi.DiskDetached {
				return true
			}
		}
	}
	pod := v.pods[podKey]
	if pod != nil && (podUID == "" || string(pod.UID) == podUID) {
		return pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed
	}
	return pod != nil || v.podsGone[podKey]
}

// stateConfig returns the image config the controller recorded on the state.
func (v *view) stateConfig(s *v1alpha1.BlipState) *image.Config {
	if s == nil {
		return nil
	}
	return apiImageConfig(s.Status.ImageConfig)
}

func apiImageConfig(c *v1alpha1.ImageConfig) *image.Config {
	if c == nil {
		return nil
	}
	return &image.Config{
		Env:        slices.Clone(c.Env),
		Entrypoint: slices.Clone(c.Entrypoint),
		Cmd:        slices.Clone(c.Cmd),
		WorkingDir: c.WorkingDir,
		User:       c.User,
	}
}
