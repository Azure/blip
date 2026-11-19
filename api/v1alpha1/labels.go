package v1alpha1

import "strings"

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
	// LabelParent is the short name of the blip a fork was started from. It
	// scopes "blip gather" with no arguments to that blip's forks.
	LabelParent = "blip.dev/parent"
	// LabelThread marks blips and other objects owned by a BlipThread.
	LabelThread = "blip.dev/thread"
	// LabelTask marks a blip as work for one ThreadTask.
	LabelTask = "blip.dev/task"

	AnnotationBlip            = "blip.dev/blip"
	AnnotationObserved        = "blip.dev/observed"
	AnnotationPrepareError    = "blip.dev/prepare-error"
	AnnotationForceRecover    = "blip.dev/force-recover-writer"
	AnnotationCollectMounts   = "blip.dev/collect-mounts"
	AnnotationTemplateHash    = "blip.dev/template-hash"
	AnnotationEnrollmentDrain = "blip.dev/enrollment-drain"
	AnnotationPinnedNode      = "blip.dev/pinned-node"
	// AnnotationStopReason records why the controller set spec.stop, for the
	// client to report when it gathers the blip.
	AnnotationStopReason = "blip.dev/stop-reason"

	// AnnotationWaitForClient on a Blip asks the guest to hold the primary
	// command's output until a client attaches. A Blip created directly
	// through the API may omit it, and then the command starts itself.
	// `blip gather -f` attaches to a command that is already running, so the
	// CLI does not set it.
	AnnotationWaitForClient = "blip.dev/wait-for-client"

	Finalizer = "blip.dev/finalizer"
)

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
