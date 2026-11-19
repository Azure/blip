package v1alpha1

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Labels, annotations, and the finalizer shared by every component. Everything
// the controller, node agent, and CLI agree on lives here so a rename
// cannot drift between packages.
const (
	LabelPool             = "blip.dev/pool"
	LabelBlipUID          = "blip.dev/blip-uid"
	LabelWarm             = "blip.dev/warm"
	LabelEnrolled         = "blip.dev/enrolled"
	LabelHypervisorPrefix = "blip.dev/hypervisor-"
	LabelOwner            = "blip.dev/owner"
	// LabelParent scopes "blip gather" with no arguments to the forks of the
	// blip it runs in. Label values are limited to 63 characters, so a long
	// short name is hashed under a prefix that cannot be a legal Blip name;
	// AnnotationParent keeps the full name.
	LabelParent = "blip.dev/parent"
	// LabelThread marks blips and other objects owned by a BlipThread. Its
	// value is ThreadLabel(name), because Kubernetes labels are at most 63
	// characters but BlipThread names may be longer.
	LabelThread = "blip.dev/thread"
	// LabelThreadUID pins a turn to the BlipThread incarnation that produced
	// it. A deleted and recreated thread keeps its name and thread label but
	// gets a new UID, so the proxy can select only the current incarnation's
	// turns instead of returning stale history from the previous one.
	LabelThreadUID = "blip.dev/thread-uid"
	// AnnotationThread carries the full BlipThread name when LabelThread is
	// hashed for a long name.
	AnnotationThread = "blip.dev/thread-name"
	// AnnotationThreadUID pins a Blip and its BlipState to the incarnation of
	// the BlipThread that created them. Labels are name-derived and survive a
	// delete/recreate of the thread, so the UID is what tells two incarnations
	// of the same name apart.
	AnnotationThreadUID = "blip.dev/thread-uid"
	// LabelTask marks a blip as work for one ThreadTask.
	LabelTask = "blip.dev/task"

	// AnnotationParent is the full short name of the blip a fork was started
	// from, including names too long for LabelParent's hash.
	AnnotationParent          = "blip.dev/parent-name"
	AnnotationBlip            = "blip.dev/blip"
	AnnotationObserved        = "blip.dev/observed"
	AnnotationPrepareError    = "blip.dev/prepare-error"
	AnnotationForceRecover    = "blip.dev/force-recover-writer"
	AnnotationCollectMounts   = "blip.dev/collect-mounts"
	AnnotationTemplateHash    = "blip.dev/template-hash"
	AnnotationEnrollmentDrain = "blip.dev/enrollment-drain"
	AnnotationPinnedNode      = "blip.dev/pinned-node"
	// AnnotationRelocated marks a warm pod the pool created by moving a spare
	// to a hot node. Relocation cannot see free capacity, so a rejection of
	// such a pod backs the node off for longer than a rejected demand pod.
	AnnotationRelocated = "blip.dev/relocated"
	// AnnotationStopReason records why the controller set spec.stop, for the
	// client to report when it gathers the blip.
	AnnotationStopReason = "blip.dev/stop-reason"
	// AnnotationPrunedReportSeq records the highest report sequence whose
	// deterministic watcher turn retention has deleted. The watcher
	// deduplicates by turn name, so without this tombstone it would recreate
	// the pruned turn from the Blip's unchanged status and deliver stale
	// input to the coordinator again.
	AnnotationPrunedReportSeq = "blip.dev/pruned-report-seq"
	// AnnotationPrunedFinished marks a deleted finished-phase turn. It stops
	// the watcher from recreating that deterministic turn after retention.
	AnnotationPrunedFinished = "blip.dev/pruned-finished"

	Finalizer = "blip.dev/finalizer"
)

// parentLabelHash is the reserved prefix of a hashed ParentLabel. An
// underscore is legal in a Kubernetes label value but not in a DNS-1123 Blip
// name, so a hashed label can never equal a literal parent name. Without that
// separation, a short parent named exactly another parent's 63-character hash
// shared its blip.dev/parent label and a bare gather could delete the other
// parent's forks.
const parentLabelHash = "parent_"

// ParentLabel is the LabelParent value for a fork's short parent name.
// Kubernetes label values are at most 63 characters: names that fit are used
// as-is so existing selectors keep working, and longer names become a stable
// 63-character hash under the reserved parent_ prefix. AnnotationParent always
// carries the full name.
func ParentLabel(name string) string {
	if len(name) <= 63 {
		return name
	}
	sum := sha256.Sum256([]byte(name))
	return parentLabelHash + hex.EncodeToString(sum[:])[:56]
}

// threadLabelHash is the reserved prefix of a hashed ThreadLabel. An
// underscore is legal in a Kubernetes label value but not in a DNS-1123
// BlipThread name, so a hashed label can never equal a literal thread name.
// Without that separation, a short thread named exactly another thread's
// 63-character hash shared its blip.dev/thread label and the API proxy mixed
// both projects' turns.
const threadLabelHash = "thread_"

// ThreadLabel is the LabelThread value for a BlipThread name. Kubernetes label
// values are at most 63 characters: names that fit are used as-is so existing
// selectors keep working, and longer names become a stable 63-character hash
// under the reserved thread_ prefix. AnnotationThread always carries the full
// name.
func ThreadLabel(name string) string {
	if len(name) <= 63 {
		return name
	}
	sum := sha256.Sum256([]byte(name))
	return threadLabelHash + hex.EncodeToString(sum[:])[:56]
}

// ThreadOwner is the blip.dev/owner label of the blips and states a
// BlipThread creates. It is derived from the thread's namespace and name, so
// it is stable and cannot collide with the u- owners derived from user
// identities.
func ThreadOwner(namespace, name string) string {
	sum := sha256.Sum256([]byte(namespace + "/" + name))
	return "p-" + hex.EncodeToString(sum[:8])
}

// OwnerPrefix is the prefix of every object name scoped to owner.
func OwnerPrefix(owner string) string { return owner + "." }

// OwnedBy reports whether name is scoped to owner.
func OwnedBy(name, owner string) bool { return strings.HasPrefix(name, OwnerPrefix(owner)) }

// Finished reports whether a blip has stopped and will not run again.
func Finished(b *Blip) bool {
	return b.Status.Phase == BlipSucceeded || b.Status.Phase == BlipFailed
}

// DesiredMounts returns the root state mounts this blip should have: unclaimed
// mounts and mounts already claimed by this blip.
func DesiredMounts(root *BlipState, b *Blip) []Mount {
	var mounts []Mount
	for _, m := range root.Spec.Mounts {
		if m.BlipUID == "" || m.BlipUID == string(b.UID) {
			mounts = append(mounts, m)
		}
	}
	return mounts
}

// CollectMountUse is one entry in AnnotationCollectMounts: the blip that holds
// a collected mount and the path it was collected into.
type CollectMountUse struct {
	BlipUID string `json:"blipUID"`
	Path    string `json:"path"`
}
