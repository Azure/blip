package v1alpha1

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// BlipPhase is a display-only summary of the Blip state.
type BlipPhase string

const (
	BlipPending   BlipPhase = "Pending"
	BlipRunning   BlipPhase = "Running"
	BlipSaving    BlipPhase = "Saving"
	BlipSucceeded BlipPhase = "Succeeded"
	BlipFailed    BlipPhase = "Failed"
)

// BlipSpec is the desired run. All fields except volumes (non-root entries
// can be added and removed) and ttlSecondsAfterFinished are immutable.
// +kubebuilder:validation:XValidation:rule="self.sku == oldSelf.sku && self.rootVolume == oldSelf.rootVolume && self.maxTTLSeconds == oldSelf.maxTTLSeconds && has(self.reschedule) == has(oldSelf.reschedule) && (!has(self.reschedule) || self.reschedule == oldSelf.reschedule) && self.serviceAccountName == oldSelf.serviceAccountName && has(self.init) == has(oldSelf.init) && (!has(self.init) || self.init == oldSelf.init) && has(self.rootMountOptions) == has(oldSelf.rootMountOptions) && (!has(self.rootMountOptions) || self.rootMountOptions == oldSelf.rootMountOptions) && has(self.ports) == has(oldSelf.ports) && (!has(self.ports) || self.ports == oldSelf.ports)",message="spec fields are immutable except volumes and ttlSecondsAfterFinished"
// +kubebuilder:validation:XValidation:rule="self.volumes.exists(v, v.name == self.rootVolume)",message="rootVolume must name an entry in volumes"
// +kubebuilder:validation:XValidation:rule="oldSelf.volumes.filter(o, o.name == oldSelf.rootVolume).all(o, self.volumes.exists(v, v.name == o.name))",message="the root volume entry cannot be removed"
type BlipSpec struct {
	// SKU selects the kind of slot: the Blip runs in a free slot pod of
	// this SKU in its own namespace.
	// +kubebuilder:default=default
	// +optional
	SKU string `json:"sku,omitempty"`

	// RootVolume names the entry of volumes that the boot stub mounts
	// (ext4) as / before it execs init. Immutable.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=20
	RootVolume string `json:"rootVolume"`

	// Volumes are the BlipVols attached to the VM as raw block devices. Each
	// attachment starts from the BlipVol's newest Ready snapshot and writes
	// to a private overlay that is saved back as new snapshots of the
	// BlipVol according to its snapshotPolicy. Entries are immutable; entries
	// other than the root volume can be added and removed while the Blip runs
	// (live attach/detach).
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	Volumes []BlipVolume `json:"volumes"`

	// Init is the argv the boot stub execs as PID 1 after it mounts the
	// root volume (ext4) as /. The first element must be an absolute path.
	// +kubebuilder:default={"/sbin/init"}
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	// +kubebuilder:validation:items:MaxLength=1024
	// +kubebuilder:validation:XValidation:rule="self[0].startsWith('/')",message="init[0] must be an absolute path"
	// +optional
	Init []string `json:"init,omitempty"`

	// RootMountOptions are the ext4 mount options of the root volume
	// (comma separated, as for mount -o).
	// +kubebuilder:validation:MaxLength=256
	// +optional
	RootMountOptions string `json:"rootMountOptions,omitempty"`

	// MaxTTLSeconds limits the run, counted from slot claim.
	// +kubebuilder:default=3600
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=604800
	// +optional
	MaxTTLSeconds int64 `json:"maxTTLSeconds,omitempty"`

	// TTLSecondsAfterFinished is how long the finished Blip is kept. Mutable.
	// +kubebuilder:default=300
	// +kubebuilder:validation:Minimum=0
	// +optional
	TTLSecondsAfterFinished *int64 `json:"ttlSecondsAfterFinished,omitempty"`

	// Reschedule, when set, gives the workload another attempt in a new VM
	// (possibly on another node) after a retryable failure, with
	// exponential backoff, until it succeeds, the limit is reached or the
	// deadline (maxTTLSeconds from the first slot claim) passes. Each
	// volume is snapshotted when an attempt fails, and the next attempt
	// starts from each volume's newest Ready snapshot.
	// Immutable.
	// +optional
	Reschedule *ReschedulePolicy `json:"reschedule,omitempty"`

	// ServiceAccountName is the ServiceAccount in the Blip's namespace whose
	// token the guest gets at /run/secrets/kubernetes.io/serviceaccount
	// (token, ca.crt, namespace). The token is bound to a Secret of the allocation and
	// rotated before it expires. The Blip waits with ServiceAccountNotFound
	// until the ServiceAccount exists.
	// +kubebuilder:default=default
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +optional
	ServiceAccountName string `json:"serviceAccountName,omitempty"`

	// Ports are guest ports reachable on the slot pod's loopback, so
	// `kubectl port-forward pod/<status.allocation.podName> <port>` connects
	// to the guest's AF_VSOCK listener on port <port>.
	// +listType=map
	// +listMapKey=port
	// +kubebuilder:validation:MaxItems=16
	// +optional
	Ports []BlipPort `json:"ports,omitempty"`
}

// ReschedulePolicy says how often and how fast a failed Blip is given a new
// attempt.
// +kubebuilder:validation:XValidation:rule="self.maxBackoffSeconds >= self.initialBackoffSeconds",message="maxBackoffSeconds must be at least initialBackoffSeconds"
type ReschedulePolicy struct {
	// Limit is the maximum number of reschedules. Unset means no limit
	// other than the deadline.
	// +kubebuilder:validation:Minimum=0
	// +optional
	Limit *int32 `json:"limit,omitempty"`
	// InitialBackoffSeconds is the wait before the first reschedule. It
	// doubles with each further reschedule.
	// +kubebuilder:default=10
	// +kubebuilder:validation:Minimum=1
	// +optional
	InitialBackoffSeconds int32 `json:"initialBackoffSeconds,omitempty"`
	// MaxBackoffSeconds caps the wait.
	// +kubebuilder:default=300
	// +kubebuilder:validation:Minimum=1
	// +optional
	MaxBackoffSeconds int32 `json:"maxBackoffSeconds,omitempty"`
	// SalvageTimeout is how long, from the end of a failed attempt, to wait
	// for an unreachable node to return so the volumes can be snapshotted
	// before the next attempt.
	// +kubebuilder:default="5m"
	// +kubebuilder:validation:Type=string
	// +kubebuilder:validation:MaxLength=32
	// +optional
	SalvageTimeout *metav1.Duration `json:"salvageTimeout,omitempty"`
	// NodeLoss says what happens when the salvage timeout expires. Fence
	// waits until the node returns or is fenced (out-of-service taint or
	// deleted). Abandon reschedules from each volume's newest Ready
	// snapshot without waiting; writes since then are lost.
	// +kubebuilder:default=Fence
	// +optional
	NodeLoss NodeLossPolicy `json:"nodeLoss,omitempty"`
}

// NodeLossPolicy says how a reschedule treats a node that does not return.
// +kubebuilder:validation:Enum=Fence;Abandon
type NodeLossPolicy string

const (
	NodeLossFence   NodeLossPolicy = "Fence"
	NodeLossAbandon NodeLossPolicy = "Abandon"
)

// DefaultSalvageTimeout is the default spec.reschedule.salvageTimeout.
const DefaultSalvageTimeout = 5 * time.Minute

// SalvageTimeoutOrDefault returns salvageTimeout or DefaultSalvageTimeout.
func (p *ReschedulePolicy) SalvageTimeoutOrDefault() time.Duration {
	if p != nil && p.SalvageTimeout != nil {
		return p.SalvageTimeout.Duration
	}
	return DefaultSalvageTimeout
}

// AttemptFailure records why an attempt of a Blip ended.
type AttemptFailure struct {
	// Reason is a Failed condition reason, e.g. NodeLost or Error.
	Reason string `json:"reason"`
	// +optional
	Message string      `json:"message,omitempty"`
	Time    metav1.Time `json:"time"`
}

// BlipPort exposes one guest TCP port for port forwarding.
type BlipPort struct {
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
	// +kubebuilder:validation:MaxLength=15
	// +optional
	Name string `json:"name,omitempty"`
}

// BlipVolume attaches one BlipVol to the Blip. The guest sees it as the raw
// virtio block device with serial <name>, /dev/disk/by-id/virtio-<name>.
// Immutable: remove and re-add the entry to change it.
// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="a volume entry is immutable; remove and re-add it to change it"
type BlipVolume struct {
	// Name is a DNS label, unique within the Blip, and the virtio serial of
	// the disk (at most 20 bytes). blip-meta is reserved.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=20
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	// +kubebuilder:validation:XValidation:rule="self != 'blip-meta'",message="the volume name blip-meta is reserved"
	Name string `json:"name"`
	// BlipVolRef names a BlipVol in the same namespace.
	BlipVolRef LocalObjectRef `json:"blipVolRef"`
}

// ObjectRef names an object and its UID.
type ObjectRef struct {
	Name string `json:"name"`
	// +optional
	UID string `json:"uid,omitempty"`
}

// Allocation is the slot claimed for a run.
type Allocation struct {
	ID string `json:"id"`
	// +optional
	Node string `json:"node,omitempty"`
	// +optional
	PodName string `json:"podName,omitempty"`
	// +optional
	PodUID string `json:"podUID,omitempty"`
}

// VolumeState is the state of one attachment.
type VolumeState string

const (
	VolumeReserving  VolumeState = "Reserving"
	VolumeAttaching  VolumeState = "Attaching"
	VolumeAttached   VolumeState = "Attached"
	VolumeDetaching  VolumeState = "Detaching"
	VolumeCapturing  VolumeState = "Capturing"
	VolumePublishing VolumeState = "Publishing"
	VolumeReleased   VolumeState = "Released"
	VolumeFailed     VolumeState = "Failed"
)

// ReleaseReason says why an attachment was released.
type ReleaseReason string

const (
	ReleaseDetach           ReleaseReason = "Detach"
	ReleaseCompleted        ReleaseReason = "Completed"
	ReleaseFailed           ReleaseReason = "Failed"
	ReleaseDeadlineExceeded ReleaseReason = "DeadlineExceeded"
	ReleaseDeleted          ReleaseReason = "Deleted"
	// ReleaseReschedule: the attempt failed and the Blip is rescheduled;
	// the next attempt continues from the snapshot.
	ReleaseReschedule ReleaseReason = "Reschedule"
)

// ShutdownSnapshotState is the state of the snapshot taken when an
// attachment is released.
// +kubebuilder:validation:Enum=Pending;Ready;Skipped;Unavailable;Failed
type ShutdownSnapshotState string

const (
	ShutdownSnapshotPending ShutdownSnapshotState = "Pending"
	ShutdownSnapshotReady   ShutdownSnapshotState = "Ready"
	// ShutdownSnapshotSkipped: snapshotPolicy.skipShutdown is set.
	ShutdownSnapshotSkipped ShutdownSnapshotState = "Skipped"
	// ShutdownSnapshotUnavailable: the node or its overlay was lost; the
	// BlipVol's newest Ready snapshot is the recovery point.
	ShutdownSnapshotUnavailable ShutdownSnapshotState = "Unavailable"
	ShutdownSnapshotFailed      ShutdownSnapshotState = "Failed"
)

// ShutdownSnapshot is the snapshot taken when an attachment is released.
type ShutdownSnapshot struct {
	// Sequence is the BlipVol snapshot sequence, once allocated.
	// +optional
	Sequence int64 `json:"sequence,omitempty"`
	// +optional
	Reason ReleaseReason `json:"reason,omitempty"`
	// +optional
	State ShutdownSnapshotState `json:"state,omitempty"`
	// +optional
	Message string `json:"message,omitempty"`
}

// ResumedFrom records that an attempt started from a snapshot older than
// where the previous attempt stopped.
type ResumedFrom struct {
	Sequence int64 `json:"sequence"`
	// +optional
	CaptureTime *metav1.Time `json:"captureTime,omitempty"`
}

// BlipVolumeStatus is the observed state of one attachment.
type BlipVolumeStatus struct {
	// Name of the spec.volumes entry.
	Name string `json:"name"`
	// BlipVolRef is the resolved input BlipVol.
	// +optional
	BlipVolRef *ObjectRef `json:"blipVolRef,omitempty"`
	// AttachmentID is 16 hex characters, new for every attach.
	// +optional
	AttachmentID string `json:"attachmentID,omitempty"`
	// Generation is the BlipVol claim generation of this attachment.
	// +optional
	Generation int64 `json:"generation,omitempty"`
	// SlotDisk is the index N of /dev/blip/disks/N in the slot used by
	// this attachment.
	// +optional
	SlotDisk *int32 `json:"slotDisk,omitempty"`
	// DevicePath is /dev/disk/by-id/virtio-<name> in the guest.
	// +optional
	DevicePath string `json:"devicePath,omitempty"`
	// +optional
	State VolumeState `json:"state,omitempty"`
	// +optional
	Message string `json:"message,omitempty"`
	// Snapshot is the BlipVol snapshot sequence this attachment started
	// from.
	// +optional
	Snapshot int64 `json:"snapshot,omitempty"`
	// ResumedFrom is set when this attempt started from an older snapshot
	// than where the previous attempt stopped.
	// +optional
	ResumedFrom *ResumedFrom `json:"resumedFrom,omitempty"`
	// ShutdownSnapshot is the snapshot taken when the attachment is
	// released (also for a reschedule).
	// +optional
	ShutdownSnapshot *ShutdownSnapshot `json:"shutdownSnapshot,omitempty"`
}

// BlipStatus is written only by the controller.
type BlipStatus struct {
	// Phase summarizes the workload: Pending, Running, Saving, Succeeded,
	// Failed.
	// +optional
	Phase BlipPhase `json:"phase,omitempty"`
	// +optional
	Allocation *Allocation `json:"allocation,omitempty"`
	// Volumes is the observed state of each attachment, including entries
	// that were removed from spec and are still being released.
	// +listType=map
	// +listMapKey=name
	// +optional
	Volumes []BlipVolumeStatus `json:"volumes,omitempty"`
	// +optional
	StartTime *metav1.Time `json:"startTime,omitempty"`
	// +optional
	Deadline *metav1.Time `json:"deadline,omitempty"`
	// +optional
	CompletionTime *metav1.Time `json:"completionTime,omitempty"`
	// StopRequestedTime is when the controller first asked the node to
	// stop the VM gracefully (Kill). The graceful timeout counts from
	// here, also after a controller restart.
	// +optional
	StopRequestedTime *metav1.Time `json:"stopRequestedTime,omitempty"`
	// RestartCount is the number of guest reboots in the current attempt.
	// +optional
	RestartCount int32 `json:"restartCount,omitempty"`
	// RescheduleCount is the number of times the Blip was given a new
	// attempt (spec.reschedule).
	// +optional
	RescheduleCount int32 `json:"rescheduleCount,omitempty"`
	// NextScheduleTime is the end of the reschedule backoff: the next
	// attempt claims a slot no earlier.
	// +optional
	NextScheduleTime *metav1.Time `json:"nextScheduleTime,omitempty"`
	// LastFailure is why the last rescheduled attempt ended.
	// +optional
	LastFailure *AttemptFailure `json:"lastFailure,omitempty"`
	// +optional
	LastExitCode *int32 `json:"lastExitCode,omitempty"`
	// PodIP is the IP address of the guest. The guest takes over the
	// network identity of its slot pod, so this is the slot pod's IP.
	// +optional
	PodIP string `json:"podIP,omitempty"`
	// Message says why the run failed.
	// +optional
	Message string `json:"message,omitempty"`
	// Conditions: Scheduled, Started, VolumesReady, SnapshotsBehind,
	// Rescheduling, Finished, Complete, Failed. Complete/Failed describe the workload
	// only; Finished is set once every shutdown snapshot is settled and
	// every claim is released.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// Blip boots a guest OS from its root volume in a microVM.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced
// +kubebuilder:printcolumn:name="SKU",type=string,JSONPath=`.spec.sku`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Restarts",type=integer,JSONPath=`.status.restartCount`
// +kubebuilder:printcolumn:name="Reschedules",type=integer,JSONPath=`.status.rescheduleCount`
// +kubebuilder:printcolumn:name="Root",type=string,JSONPath=`.spec.rootVolume`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:validation:XValidation:rule="size(self.metadata.name) <= 57",message="Blip names must be at most 57 characters"
type Blip struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec BlipSpec `json:"spec"`
	// +optional
	Status BlipStatus `json:"status,omitempty"`
}

// BlipList is a list of Blips.
// +kubebuilder:object:root=true
type BlipList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Blip `json:"items"`
}
