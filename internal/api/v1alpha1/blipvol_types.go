package v1alpha1

import (
	"time"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// BlipVolPhase is a display summary of the BlipVol state.
type BlipVolPhase string

const (
	BlipVolPending   BlipVolPhase = "Pending"
	BlipVolImporting BlipVolPhase = "Importing"
	BlipVolReady     BlipVolPhase = "Ready"
	BlipVolFailed    BlipVolPhase = "Failed"
)

// LocalObjectRef names an object in the same namespace.
type LocalObjectRef struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
}

// ImageSource is an OCI image to import.
type ImageSource struct {
	// +kubebuilder:validation:MinLength=1
	Reference string `json:"reference"`
	// PullSecretRef names a docker config Secret in the same namespace.
	// +optional
	PullSecretRef *LocalObjectRef `json:"pullSecretRef,omitempty"`
}

// ParentRef names the BlipVol to derive from and, optionally, which of its
// snapshots.
type ParentRef struct {
	// Namespace defaults to the namespace of the new BlipVol.
	// +optional
	Namespace string `json:"namespace,omitempty"`
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// Snapshot is the sequence of the parent snapshot to clone. Unset means
	// the parent's newest Ready snapshot, or, while the parent is attached
	// to a running Blip, the first snapshot captured after this BlipVol was
	// created (a live capture is triggered).
	// +kubebuilder:validation:Minimum=1
	// +optional
	Snapshot *int64 `json:"snapshot,omitempty"`
}

// SnapshotPolicy says when snapshots of the volume are taken while it is
// attached to a Blip, and how many are kept.
type SnapshotPolicy struct {
	// SkipShutdown disables the snapshot taken when the volume is released
	// (VM stop, live detach, end of the run). Writes after the newest
	// snapshot are then discarded. Snapshots for a reschedule are taken
	// regardless.
	// +optional
	SkipShutdown bool `json:"skipShutdown,omitempty"`
	// Interval takes a snapshot every interval while the volume is attached,
	// e.g. "30m" or "1h". At least 5m. Unset means no interval snapshots.
	// +kubebuilder:validation:Type=string
	// +kubebuilder:validation:MaxLength=32
	// +kubebuilder:validation:XValidation:rule="duration(self) >= duration('5m')",message="interval must be at least 5m"
	// +optional
	Interval *metav1.Duration `json:"interval,omitempty"`
	// Limit is the number of Ready snapshots kept. Older ones are deleted
	// unless pinned or held.
	// +kubebuilder:default=24
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100
	// +optional
	Limit int32 `json:"limit,omitempty"`
}

// DefaultSnapshotLimit is the snapshot limit when snapshotPolicy.limit is
// unset.
const DefaultSnapshotLimit int32 = 24

// SnapshotReason says why a snapshot was taken.
// +kubebuilder:validation:Enum=Initial;Shutdown;Interval;Derive;Reschedule
type SnapshotReason string

const (
	// SnapshotInitial: sequence 1, the content from image, size or parent.
	SnapshotInitial SnapshotReason = "Initial"
	// SnapshotShutdown: taken when the attachment was released.
	SnapshotShutdown SnapshotReason = "Shutdown"
	// SnapshotInterval: taken by snapshotPolicy.interval.
	SnapshotInterval SnapshotReason = "Interval"
	// SnapshotDerive: taken because another BlipVol derives from this one
	// while it is attached.
	SnapshotDerive SnapshotReason = "Derive"
	// SnapshotReschedule: taken when an attempt of the Blip failed and is
	// rescheduled; the next attempt continues from it.
	SnapshotReschedule SnapshotReason = "Reschedule"
)

// SnapshotState is the state of a snapshot.
// +kubebuilder:validation:Enum=Pending;Ready;Failed
type SnapshotState string

const (
	SnapshotPending SnapshotState = "Pending"
	SnapshotReady   SnapshotState = "Ready"
	SnapshotFailed  SnapshotState = "Failed"
)

// Writer is the attachment that produced a snapshot.
type Writer struct {
	BlipName     string `json:"blipName"`
	BlipUID      string `json:"blipUID"`
	AttachmentID string `json:"attachmentID"`
	// Generation is the claim generation the attachment held when it
	// wrote the snapshot.
	// +optional
	Generation int64 `json:"generation,omitempty"`
}

// VolSnapshot is one entry of the snapshot history of a BlipVol.
type VolSnapshot struct {
	// Sequence numbers snapshots of this BlipVol, starting at 1. Never
	// reused.
	// +kubebuilder:validation:Minimum=1
	Sequence int64 `json:"sequence"`
	// ContentID identifies the data on the storage nodes:
	// <BlipVol UID>-<sequence>.
	ContentID string         `json:"contentID"`
	Reason    SnapshotReason `json:"reason"`
	State     SnapshotState  `json:"state"`
	// +optional
	CaptureTime *metav1.Time `json:"captureTime,omitempty"`
	// +optional
	StorageGroup string `json:"storageGroup,omitempty"`
	// Base is the content ID this snapshot was sent incrementally against;
	// empty for a full copy.
	// +optional
	Base string `json:"base,omitempty"`
	// +listType=map
	// +listMapKey=node
	// +optional
	Replicas []Replica `json:"replicas,omitempty"`
	// Writer is the attachment that wrote the data; unset for Initial.
	// +optional
	Writer *Writer `json:"writer,omitempty"`
	// Result is the result of the run, for snapshots taken at its end.
	// +optional
	Result *RunResult `json:"result,omitempty"`
	// +optional
	Message string `json:"message,omitempty"`
}

// OriginStatus records the parent snapshot a derived BlipVol was cloned
// from. It pins that snapshot against compaction.
type OriginStatus struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
	// Snapshot is the parent sequence; 0 while waiting for a live capture.
	// +optional
	Snapshot int64 `json:"snapshot,omitempty"`
	// +optional
	ContentID string `json:"contentID,omitempty"`
}

// RunResult is the result of the run that produced an output.
type RunResult struct {
	ExitCode     int32 `json:"exitCode"`
	RestartCount int32 `json:"restartCount"`
}

// ReplicaState is the state of one replica.
type ReplicaState string

const (
	ReplicaSealed   ReplicaState = "Sealed"
	ReplicaMissing  ReplicaState = "Missing"
	ReplicaRepair   ReplicaState = "Repairing"
	ReplicaMismatch ReplicaState = "Mismatch"
)

// Replica is one copy of the content.
type Replica struct {
	Node  string       `json:"node"`
	State ReplicaState `json:"state"`
}

// BlipVolSpec describes the initial content and the snapshot policy. A
// BlipVol with an image is an ext4 filesystem built from the image. A BlipVol
// with a parent is a clone of a parent snapshot. A BlipVol with neither is a
// zero-filled raw block device of spec.size (default 20Gi) with no
// filesystem. image, parent and size are immutable; snapshotPolicy is
// mutable.
// +kubebuilder:validation:XValidation:rule="!(has(self.image) && has(self.parent))",message="set at most one of image and parent"
// +kubebuilder:validation:XValidation:rule="!(has(self.parent) && has(self.size))",message="size is not allowed with parent"
// +kubebuilder:validation:XValidation:rule="has(self.image) == has(oldSelf.image) && (!has(self.image) || self.image == oldSelf.image)",message="image is immutable"
// +kubebuilder:validation:XValidation:rule="has(self.parent) == has(oldSelf.parent) && (!has(self.parent) || self.parent == oldSelf.parent)",message="parent is immutable"
// +kubebuilder:validation:XValidation:rule="has(self.size) == has(oldSelf.size) && (!has(self.size) || self.size == oldSelf.size)",message="size is immutable"
type BlipVolSpec struct {
	// +optional
	Image *ImageSource `json:"image,omitempty"`
	// +optional
	Parent *ParentRef `json:"parent,omitempty"`
	// Size of a new empty volume. Defaults to 20Gi in the controller when
	// neither image nor parent is set.
	// +optional
	Size *resource.Quantity `json:"size,omitempty"`
	// +optional
	SnapshotPolicy *SnapshotPolicy `json:"snapshotPolicy,omitempty"`
}

// Claim is the exclusive attachment of a BlipVol to one Blip.
type Claim struct {
	BlipName     string `json:"blipName"`
	BlipUID      string `json:"blipUID"`
	AttachmentID string `json:"attachmentID"`
	// +optional
	AllocationID string `json:"allocationID,omitempty"`
	// +optional
	Node string `json:"node,omitempty"`
	// Generation is the claim generation; equals status.claimGeneration
	// at the time the claim was taken.
	Generation int64 `json:"generation"`
	// +optional
	Since *metav1.Time `json:"since,omitempty"`
	// Snapshot is the sequence the attachment started from.
	// +optional
	Snapshot int64 `json:"snapshot,omitempty"`
	// Baseline is the newest Ready snapshot taken by this attachment: the
	// base of its next incremental save. 0 until the first one.
	// +optional
	Baseline int64 `json:"baseline,omitempty"`
}

// HoldKind says why data must be kept.
// +kubebuilder:validation:Enum=Attachment;Clone
type HoldKind string

const (
	// HoldAttachment: the volume is attached.
	HoldAttachment HoldKind = "Attachment"
	// HoldClone: a snapshot is being cloned into a derived BlipVol.
	HoldClone HoldKind = "Clone"
)

// HolderRef names the object holding a BlipVol.
type HolderRef struct {
	Kind string `json:"kind"`
	// +optional
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	// +optional
	UID string `json:"uid,omitempty"`
}

// Hold blocks deletion of a BlipVol and, with snapshot set, compaction of
// that snapshot.
type Hold struct {
	Kind   HoldKind  `json:"kind"`
	Holder HolderRef `json:"holder"`
	// +optional
	Since *metav1.Time `json:"since,omitempty"`
	// +optional
	Message string `json:"message,omitempty"`
	// Snapshot is the sequence held (the clone source of a Clone hold).
	// +optional
	Snapshot int64 `json:"snapshot,omitempty"`
}

// BlipVolStatus is written only by the controller.
type BlipVolStatus struct {
	// Phase is Ready once sequence 1 is Ready.
	// +optional
	Phase BlipVolPhase `json:"phase,omitempty"`
	// +optional
	Size *resource.Quantity `json:"size,omitempty"`
	// +optional
	ImageDigest string `json:"imageDigest,omitempty"`
	// RootContentID is the content ID at the root of the lineage (shared by
	// derived BlipVols).
	// +optional
	RootContentID string `json:"rootContentID,omitempty"`
	// Current is the sequence of the newest Ready snapshot, which every
	// attach starts from. 0 means none yet.
	// +optional
	Current int64 `json:"current,omitempty"`
	// LastSequence is the highest sequence ever allocated.
	// +optional
	LastSequence int64 `json:"lastSequence,omitempty"`
	// Origin is the parent snapshot this BlipVol was derived from.
	// +optional
	Origin *OriginStatus `json:"origin,omitempty"`
	// Snapshots is the snapshot history, oldest first.
	// +listType=map
	// +listMapKey=sequence
	// +optional
	Snapshots []VolSnapshot `json:"snapshots,omitempty"`
	// Claim is the exclusive attachment, if any.
	// +optional
	Claim *Claim `json:"claim,omitempty"`
	// ClaimGeneration is the last claim generation handed out. It never
	// decreases and survives claim release.
	// +optional
	ClaimGeneration int64 `json:"claimGeneration,omitempty"`
	// Holds block deletion; the data is deleted only when claim and holds
	// are empty.
	// +listType=atomic
	// +optional
	Holds []Hold `json:"holds,omitempty"`
	// Conditions: Ready, Failed, RetentionLimitExceeded.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// BlipVol is a volume with a bounded history of snapshots. Attaching it to
// a Blip starts from the newest Ready snapshot.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Current",type=integer,JSONPath=`.status.current`
// +kubebuilder:printcolumn:name="Size",type=string,JSONPath=`.status.size`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type BlipVol struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +optional
	Spec BlipVolSpec `json:"spec,omitempty"`
	// +optional
	Status BlipVolStatus `json:"status,omitempty"`
}

// BlipVolList is a list of BlipVols.
// +kubebuilder:object:root=true
type BlipVolList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BlipVol `json:"items"`
}

// Snapshot returns the snapshot with sequence seq, or nil.
func (v *BlipVol) Snapshot(seq int64) *VolSnapshot {
	for i := range v.Status.Snapshots {
		if v.Status.Snapshots[i].Sequence == seq {
			return &v.Status.Snapshots[i]
		}
	}
	return nil
}

// NewestReady returns the Ready snapshot with the highest sequence, or nil.
func (v *BlipVol) NewestReady() *VolSnapshot {
	var n *VolSnapshot
	for i := range v.Status.Snapshots {
		s := &v.Status.Snapshots[i]
		if s.State == SnapshotReady && (n == nil || s.Sequence > n.Sequence) {
			n = s
		}
	}
	return n
}

// SnapshotLimit returns snapshotPolicy.limit or DefaultSnapshotLimit.
func (v *BlipVol) SnapshotLimit() int32 {
	if p := v.Spec.SnapshotPolicy; p != nil && p.Limit > 0 {
		return p.Limit
	}
	return DefaultSnapshotLimit
}

// SkipShutdown reports whether snapshotPolicy.skipShutdown is set.
func (v *BlipVol) SkipShutdown() bool {
	return v.Spec.SnapshotPolicy != nil && v.Spec.SnapshotPolicy.SkipShutdown
}

// SnapshotInterval returns snapshotPolicy.interval, or 0 if unset.
func (v *BlipVol) SnapshotInterval() time.Duration {
	if p := v.Spec.SnapshotPolicy; p != nil && p.Interval != nil {
		return p.Interval.Duration
	}
	return 0
}
