// Package api holds names, labels, conditions and config schemas shared by
// the controller and the node daemon.
package api

import (
	"fmt"
	"strconv"
	"strings"
)

// Domain is the placeholder domain used for all names.
const (
	Group   = "blip.example.com"
	Version = "v1alpha1"
)

// Annotations read and written by guests (by convention; Blip itself does not
// interpret them). The images/blip-ubuntu bootstrap reads the authorized keys
// and publishes the guest's SSH host key.
const (
	AnnotationSSHAuthorizedKeys = "blip.example.com/ssh-authorized-keys"
	AnnotationSSHHostKey        = "blip.example.com/ssh-host-key"
)

// kubectl-blip sessions: Blips created by the kubectl plugin carry the
// session label ("true") and the creating user's name.
const (
	LabelSession           = "blip.example.com/session"
	AnnotationSessionOwner = "blip.example.com/session-owner"
)

// GuestServiceAccountDir is where guest images conventionally place the
// service account credentials (blip-meta creds --dir), as in pods.
const GuestServiceAccountDir = "/run/secrets/kubernetes.io/serviceaccount"

// MetaDiskSerial is the virtio serial of the metadata disk; no volume may
// use it as its name.
const MetaDiskSerial = "blip-meta"

// DefaultInit is the default init argv.
var DefaultInit = []string{"/sbin/init"}

// Labels.
const (
	LabelLineage    = "blip.example.com/lineage"
	LabelSKU        = "blip.example.com/sku"
	LabelSlot       = "blip.example.com/slot"
	LabelNamespace  = "blip.example.com/namespace" // on claimed pods
	LabelName       = "blip.example.com/name"      // on claimed pods
	LabelHypervisor = "blip.example.com/hypervisor"
	// On slot pods: the BlipPool that created the pod (kept after a claim)
	// and the hash of the pod shape it was built from.
	LabelPool         = "blip.example.com/pool"
	LabelTemplateHash = "blip.example.com/template-hash"
	// LabelAllocation marks the Secret that service account tokens of an
	// allocation are bound to.
	LabelAllocation = "blip.example.com/allocation"

	SlotFree     = "free"
	SlotAssigned = "assigned"
)

// Annotations.
const (
	// AnnotationQuotaPrefix + SKU on a Namespace holds the running-blip limit.
	AnnotationQuotaPrefix = "quota.blip.example.com/"
	// On claimed pods.
	AnnotationBlipUID      = "blip.example.com/blip-uid"
	AnnotationAllocationID = "blip.example.com/allocation-id"
)

// QuotaAnnotation returns the namespace annotation for a SKU.
func QuotaAnnotation(sku string) string { return AnnotationQuotaPrefix + sku }

// Finalizers.
const (
	FinalizerCleanup = "blip.example.com/cleanup" // Blip
	FinalizerStorage = "blip.example.com/storage" // BlipVol
)

// Extended resource advertised by the device plugin.
const ResourceHypervisor = "blip.example.com/hypervisor"

// Well known objects in the system namespace.
const (
	SystemNamespace    = "blip-system"
	ControllerService  = "blip-controller"
	ControllerPort     = 8443
	StorageConfigMap   = "blip-storage"
	CAConfigMap        = "blip-ca"
	CASecret           = "blip-ca"
	NVMePSKSecret      = "blip-nvme-psk"
	LeaseName          = "blip-controller"
	NodeTokenAudience  = "blip"
	NodeConfigPath     = "/etc/blip/node.yaml"
	DefaultSKU         = "default"
	DefaultVG          = "blip"
	DefaultMaxLVs      = 5000
	DefaultSizeBytes   = 20 << 30
	DefaultChunkBytes  = 64 << 10
	DefaultCtrlLossTmo = 60
	MaxBlipNameLength  = 57
)

// Condition types.
const (
	CondScheduled = "Scheduled"
	CondStarted   = "Started"
	CondFinished  = "Finished"
	CondComplete  = "Complete"
	CondFailed    = "Failed"
	CondReady     = "Ready" // BlipVol

	CondVolumesReady    = "VolumesReady"    // Blip: every initial volume attached
	CondSnapshotsBehind = "SnapshotsBehind" // Blip: an interval capture of a volume was skipped or late
	CondRescheduling    = "Rescheduling"    // Blip: a failed attempt is released or waits for its backoff
	// BlipVol: more Ready snapshots are kept than snapshotPolicy.limit.
	CondRetentionLimitExceeded = "RetentionLimitExceeded"
)

// Condition reasons.
const (
	ReasonQuotaExceeded          = "QuotaExceeded"
	ReasonNoCapacity             = "NoCapacity"
	ReasonUnknownSKU             = "UnknownSKU"
	ReasonServiceAccountNotFound = "ServiceAccountNotFound"
	ReasonWaitingForBlipVol      = "WaitingForBlipVol"
	ReasonStorageFull            = "StorageFull"

	ReasonSucceeded = "Succeeded"

	ReasonError              = "Error"
	ReasonTTLExceeded        = "TTLExceeded"
	ReasonCancelled          = "Cancelled"
	ReasonNodeLost           = "NodeLost"
	ReasonSlotLost           = "SlotLost"
	ReasonHypervisorExited   = "HypervisorExited"
	ReasonInputBlipVolFailed = "InputBlipVolFailed"
	ReasonStartFailed        = "StartFailed" // assign or start call failed
	ReasonGuestPanic         = "GuestPanic"  // the guest kernel panicked
	ReasonInitExited         = "InitExited"  // PID 1 of the guest exited
	ReasonBootFailed         = "BootFailed"  // the boot stub could not start init

	ReasonVolumeInUse       = "VolumeInUse"     // claim held by another Blip
	ReasonNodeUnreachable   = "NodeUnreachable" // unreachable and not fenced
	ReasonDeletionBlocked   = "DeletionBlocked" // BlipVol claim/holds remain
	ReasonTooManyVolumes    = "TooManyVolumes"  // more volumes than disks per slot
	ReasonAttachFailed      = "AttachFailed"
	ReasonCaptureSkipped    = "CaptureSkipped"
	ReasonRescheduleBackoff = "RescheduleBackoff" // Scheduled=False: waiting for status.nextScheduleTime

	// RetentionLimitExceeded reasons: snapshots beyond the limit are kept
	// because a derived BlipVol's origin pins them, or a hold names them.
	ReasonPinned = "Pinned"
	ReasonHeld   = "Held"
	// Derive (BlipVol with spec.parent).
	ReasonParentNotFound           = "ParentNotFound"
	ReasonParentNotReady           = "ParentNotReady"
	ReasonSnapshotNotFound         = "SnapshotNotFound"         // parent.snapshot was deleted or failed (terminal)
	ReasonSnapshotNotYetTaken      = "SnapshotNotYetTaken"      // parent.snapshot is above the parent's lastSequence: waiting
	ReasonWaitingForCapture        = "WaitingForCapture"        // parent attached: waiting for a live capture
	ReasonSourceUnreachable        = "SourceUnreachable"        // parent's node is unreachable
	ReasonResumedFromOlderSnapshot = "ResumedFromOlderSnapshot" // Rescheduling: writes since the snapshot were lost

	// Blip progress.
	ReasonPending     = "Pending"     // initial value of every Blip condition
	ReasonClaimed     = "Claimed"     // Scheduled=True: a slot is claimed
	ReasonAttaching   = "Attaching"   // VolumesReady=False: a volume is being attached
	ReasonStarted     = "Started"     // Started=True
	ReasonRescheduled = "Rescheduled" // conditions reset for a new attempt
	ReasonReleasing   = "Releasing"   // Finished=False: the slot and volumes are being released

	// BlipVol progress and failures.
	ReasonReady           = "Ready"
	ReasonNoReadySnapshot = "NoReadySnapshot" // no snapshot of the volume is Ready
	ReasonImporting       = "Importing"
	ReasonImportFailed    = "ImportFailed"
	ReasonImagePullFailed = "ImagePullFailed"
	ReasonParentDeleted   = "ParentDeleted" // the parent was deleted during the clone
	ReasonCloneFailed     = "CloneFailed"
	ReasonScrubMismatch   = "ScrubMismatch" // replicas differ after a scrub
	ReasonWithinLimit     = "WithinLimit"   // RetentionLimitExceeded=False
)

// Event reasons.
const (
	// EventOverlayDiscarded: a node returned holding the overlay of an
	// abandoned attempt; the overlay was torn down.
	EventOverlayDiscarded = "OverlayDiscarded"

	// BlipPool Ready condition.
	ReasonPoolReady    = "Ready"        // enough current-shape free slots
	ReasonScaling      = "Scaling"      // waiting for slots to boot
	ReasonDuplicateSKU = "DuplicateSKU" // an older pool has the same SKU
	ReasonCreateFailed = "CreateFailed" // slot pod create error
)

// TaintOutOfService on a Node fences it: claims held on it can be released.
const TaintOutOfService = "node.kubernetes.io/out-of-service"

// Volume defaults.
const (
	DefaultDisksPerSlot = 8
	MinSnapshotInterval = 5 * 60 // seconds, enforced by CEL
)

// GuestVolumePath is the guest device path of the attachment named name
// (its virtio serial).
func GuestVolumePath(name string) string { return "/dev/disk/by-id/virtio-" + name }

// SlotDiskPath is the device path of slot disk n inside a slot container.
func SlotDiskPath(n int) string { return fmt.Sprintf("/dev/blip/disks/%d", n) }

// SnapshotContentID is the content ID of snapshot seq of the BlipVol with
// UID volUID.
func SnapshotContentID(volUID string, seq int64) string {
	return volUID + "-" + strconv.FormatInt(seq, 10)
}

// ParseSnapshotContentID splits a content ID made by SnapshotContentID.
func ParseSnapshotContentID(id string) (volUID string, seq int64, ok bool) {
	i := strings.LastIndexByte(id, '-')
	if i <= 0 {
		return "", 0, false
	}
	n, err := strconv.ParseInt(id[i+1:], 10, 64)
	if err != nil || n < 1 || strconv.FormatInt(n, 10) != id[i+1:] {
		return "", 0, false
	}
	return id[:i], n, true
}

// NQN prefix for all Blip subsystems and hosts.
const NQNPrefix = "nqn.2026-01.com.example.blip"

// LVName returns the thin LV name for a content ID.
func LVName(contentID string) string { return "c-" + contentID }

// ContentIDFromLV returns the content ID of an LV name, or "" if it is not a content LV.
func ContentIDFromLV(lv string) string {
	if id, ok := strings.CutPrefix(lv, "c-"); ok {
		return id
	}
	return ""
}

// SubsystemNQN is the NQN of an export of lvName on node.
func SubsystemNQN(node, lvName string) string {
	return fmt.Sprintf("%s:%s:%s", NQNPrefix, node, lvName)
}

// HostNQN is the NVMe host NQN of a node.
func HostNQN(node string) string { return fmt.Sprintf("%s:host:%s", NQNPrefix, node) }

// SecretTypeTokenBinding is the type of the per-allocation Secrets that Blip
// service account tokens are bound to.
const SecretTypeTokenBinding = "blip.example.com/token-binding"
