package v1alpha1

import "strings"

// Labels, annotations, and the finalizer shared by every component. Everything
// the controller, node agent, CLI, and gateway agree on lives here so a rename
// cannot drift between packages.
const (
	LabelPool             = "blip.dev/pool"
	LabelBlipUID          = "blip.dev/blip-uid"
	LabelWarm             = "blip.dev/warm"
	LabelEnrolled         = "blip.dev/enrolled"
	LabelHypervisorPrefix = "blip.dev/hypervisor-"
	LabelOwner            = "blip.dev/owner"

	AnnotationBlip            = "blip.dev/blip"
	AnnotationObserved        = "blip.dev/observed"
	AnnotationPrepareError    = "blip.dev/prepare-error"
	AnnotationForceRecover    = "blip.dev/force-recover-writer"
	AnnotationCollectMounts   = "blip.dev/collect-mounts"
	AnnotationTemplateHash    = "blip.dev/template-hash"
	AnnotationEnrollmentDrain = "blip.dev/enrollment-drain"
	AnnotationPinnedNode      = "blip.dev/pinned-node"

	// AnnotationWaitForClient on a Blip asks the guest to hold the primary
	// command's output until a client attaches. `kubectl blip run` sets it
	// because it always attaches; a Blip created directly through the API may
	// omit it, and then the command starts itself.
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
