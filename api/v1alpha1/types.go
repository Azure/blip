// Package v1alpha1 contains the blip.dev/v1alpha1 API.
//
// Ownership rules (see the README's implementation outline):
//   - Users write spec.
//   - The controller is the only writer of Blip.status, BlipPool.status,
//     BlipNode.spec, and every BlipState.status field except status.nodes.
//   - Each node agent writes only its own entry in BlipState.status.nodes
//     (server-side apply, field manager "blip-node/<node>") and its own
//     BlipNode.status.
//
// +kubebuilder:object:generate=true
// +groupName=blip.dev
package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	GroupVersion  = schema.GroupVersion{Group: "blip.dev", Version: "v1alpha1"}
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}
	AddToScheme   = SchemeBuilder.AddToScheme
)

func init() {
	SchemeBuilder.Register(&Blip{}, &BlipList{}, &BlipState{}, &BlipStateList{},
		&BlipPool{}, &BlipPoolList{}, &BlipNode{}, &BlipNodeList{},
		&BlipThread{}, &BlipThreadList{}, &BlipTurn{}, &BlipTurnList{})
}

// ---------------------------------------------------------------------------
// BlipPool

// BlipPoolSpec describes a VM shape and how many warm VMs to keep. Pools are
// image independent: a warm VM has no root disk until it is claimed.
type BlipPoolSpec struct {
	// +kubebuilder:validation:Enum=kvm
	// +kubebuilder:default=kvm
	Hypervisor string `json:"hypervisor,omitempty"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default=2
	CPUs int32 `json:"cpus,omitempty"`
	// +kubebuilder:default="2Gi"
	Memory resource.Quantity `json:"memory,omitempty"`
	// WarmCount is the number of vacant, booted VMs to keep ready.
	// +kubebuilder:validation:Minimum=0
	WarmCount int32 `json:"warmCount,omitempty"`
	// MaxCount caps vacant plus claimed VM pods. 0 means no cap.
	// +kubebuilder:validation:Minimum=0
	MaxCount int32 `json:"maxCount,omitempty"`
	// ServiceAccountName is the identity of VMs in this pool.
	ServiceAccountName string `json:"serviceAccountName,omitempty"`
	// NodeSelector selects the nodes that run this pool's VMs. It must be
	// non-empty: matching nodes are enrolled automatically and run the node
	// agent.
	// +kubebuilder:validation:MinProperties=1
	NodeSelector map[string]string   `json:"nodeSelector"`
	Tolerations  []corev1.Toleration `json:"tolerations,omitempty"`
	// ImagePullSecrets authenticate pulls of the pool's infrastructure pod
	// images. Image states use their own imagePullSecrets.
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`
	// Network is the maximum egress allowed for this pool. Omitted applies the
	// default policy: public internet egress on any port, LAN and other
	// non-public ranges denied, and cluster DNS (kube-dns) allowed. An
	// explicitly empty policy denies all egress. Changes apply to running blips.
	Network *NetworkPolicy `json:"network,omitempty"`
}

type BlipPoolStatus struct {
	// Ready counts vacant VMs that finished booting.
	Ready   int32 `json:"ready,omitempty"`
	Vacant  int32 `json:"vacant,omitempty"`
	Claimed int32 `json:"claimed,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Warm",type=integer,JSONPath=`.spec.warmCount`
// +kubebuilder:printcolumn:name="Ready",type=integer,JSONPath=`.status.ready`
// +kubebuilder:printcolumn:name="Claimed",type=integer,JSONPath=`.status.claimed`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type BlipPool struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              BlipPoolSpec   `json:"spec,omitempty"`
	Status            BlipPoolStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type BlipPoolList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BlipPool `json:"items"`
}

// ---------------------------------------------------------------------------
// BlipState

// BlipStateSpec is one durable ext4 filesystem. A state can be a blip's root
// filesystem or an auxiliary mount. Provisioning fields are immutable;
// mounts and runtime defaults can be updated for subsequent or running blips.
//
// +kubebuilder:validation:XValidation:rule="!(has(self.image) && has(self.copyFrom))",message="set at most one of image and copyFrom"
// +kubebuilder:validation:XValidation:rule="!(has(self.image) && has(self.replicas))",message="replicas cannot be set for image states; they are held by every eligible node"
// +kubebuilder:validation:XValidation:rule="has(self.image) == has(oldSelf.image) && (!has(self.image) || self.image == oldSelf.image)",message="image is immutable"
// +kubebuilder:validation:XValidation:rule="has(self.copyFrom) == has(oldSelf.copyFrom) && (!has(self.copyFrom) || self.copyFrom == oldSelf.copyFrom)",message="copyFrom is immutable"
// +kubebuilder:validation:XValidation:rule="has(self.size) == has(oldSelf.size) && (!has(self.size) || self.size == oldSelf.size)",message="size is immutable"
// +kubebuilder:validation:XValidation:rule="has(self.replicas) == has(oldSelf.replicas) && (!has(self.replicas) || self.replicas == oldSelf.replicas)",message="replicas is immutable"
// +kubebuilder:validation:XValidation:rule="has(self.nodeSelector) == has(oldSelf.nodeSelector) && (!has(self.nodeSelector) || self.nodeSelector == oldSelf.nodeSelector)",message="nodeSelector is immutable"
// +kubebuilder:validation:XValidation:rule="has(self.imagePullSecrets) == has(oldSelf.imagePullSecrets) && (!has(self.imagePullSecrets) || self.imagePullSecrets == oldSelf.imagePullSecrets)",message="imagePullSecrets is immutable"
type BlipStateSpec struct {
	// Image initializes the filesystem from a container image, which each
	// node converts to ext4 itself. Every eligible node (matching
	// nodeSelector) holds an image state. Without image or copyFrom the
	// state starts as an empty ext4 filesystem. Image states may only be
	// attached read-only; copy one to create a writable root.
	Image string `json:"image,omitempty"`
	// CopyFrom names a state in the same namespace. The copy pins the
	// source when created: its committed version, or a live snapshot of an
	// active writer's disk. Later source changes or
	// deletion do not affect it.
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-.a-z0-9]*[a-z0-9])?$`
	CopyFrom string `json:"copyFrom,omitempty"`
	// Size is the filesystem size. Defaults to the source state's size for
	// copies and to 10Gi otherwise. An image state fails if the converted
	// image does not fit.
	//
	// Size is an int-or-string in the schema, so the rule checks the string
	// form as a quantity and the integer form numerically.
	// +kubebuilder:validation:XValidation:rule="type(self) == string ? quantity(self).isGreaterThan(quantity('0')) : self > 0",message="size must be greater than 0"
	Size *resource.Quantity `json:"size,omitempty"`
	// Replicas is the number of nodes that hold every committed version.
	// Default 3. Must not be set for image states.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=3
	Replicas int32 `json:"replicas,omitempty"`
	// NodeSelector limits which nodes may hold the state.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// ImagePullSecrets authenticate the image pull when Image is set.
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`
	// Mounts attaches states when this state is used as a blip's root.
	// Changes apply to the running blip.
	// +kubebuilder:validation:XValidation:rule="self.all(m, self.exists_one(o, o.path == m.path))",message="mount paths must be unique"
	// +listType=map
	// +listMapKey=state
	// +kubebuilder:validation:MaxItems=16
	Mounts []Mount `json:"mounts,omitempty"`
	// Runtime supplies execution defaults over the imported image metadata.
	// Blip execution overrides take precedence.
	Runtime *RuntimeDefaults `json:"runtime,omitempty"`
}

const (
	StatePending = "Pending" // initial version not committed yet
	StateReady   = "Ready"   // committed, no writer
	StateInUse   = "InUse"   // a writer holds the state
	StateSaving  = "Saving"  // a new version is replicating
	StateFailed  = "Failed"  // initialization failed permanently
)

// Commit identifies one immutable, committed version of a state.
type Commit struct {
	// ID is unique across all states and versions.
	ID         string      `json:"id"`
	Generation int64       `json:"generation"`
	SizeBytes  int64       `json:"sizeBytes"`
	Time       metav1.Time `json:"time"`
	// AttachmentID is the writer that produced this version; empty for
	// the initial version.
	AttachmentID string `json:"attachmentID,omitempty"`
}

// Writer is the single writable attachment of a state.
type Writer struct {
	// AttachmentID is unique per acquisition.
	AttachmentID string `json:"attachmentID"`
	BlipName     string `json:"blipName"`
	BlipUID      string `json:"blipUID"`
	// PodName/PodUID/Node are the claimed VM pod.
	PodName string `json:"podName"`
	PodUID  string `json:"podUID"`
	Node    string `json:"node"`
	// BaseCommit is the committed version the writer started from.
	BaseCommit string `json:"baseCommit"`
}

// PendingCommit is a new version that is being replicated. It becomes
// status.committed once every node in Replicas reports holding it.
type PendingCommit struct {
	CommitID   string `json:"commitID"`
	Generation int64  `json:"generation"`
	// SourceNode builds or already holds the version.
	SourceNode string `json:"sourceNode"`
	// AttachmentID is the writer that produced it; empty for the initial
	// version.
	AttachmentID string `json:"attachmentID,omitempty"`
	// Replicas are the nodes that must hold the version before commit.
	Replicas []string `json:"replicas"`
}

// CopySource is the exact version a copy was created from.
type CopySource struct {
	StateUID string `json:"stateUID"`
	// CommitID is the source's committed version, or empty for a live copy.
	CommitID string `json:"commitID,omitempty"`
	// AttachmentID is set for a live copy: a snapshot of the source's
	// running writer attachment, taken on Nodes[0] while the guest keeps
	// the filesystem frozen.
	AttachmentID string `json:"attachmentID,omitempty"`
	// Nodes held the source version when the copy was resolved.
	Nodes []string `json:"nodes"`
}

// NodeObservation is written only by the node agent named by Node.
type NodeObservation struct {
	Node string `json:"node"`
	// Incarnation must equal BlipNode.status.incarnation, otherwise the
	// entry is ignored (the node lost its storage).
	Incarnation string `json:"incarnation"`
	// Commits are the commit IDs this node durably holds for this state.
	Commits []string `json:"commits,omitempty"`
	// Sealed reports the outcome of ending a writable attachment on this
	// node. CommitID is empty when the data could not be saved.
	Sealed []SealResult `json:"sealed,omitempty"`
	// Fetching is the commit being copied to this node, with progress.
	Fetching *Transfer `json:"fetching,omitempty"`
	Error    string    `json:"error,omitempty"`
}

type SealResult struct {
	AttachmentID string `json:"attachmentID"`
	CommitID     string `json:"commitID,omitempty"`
	SizeBytes    int64  `json:"sizeBytes,omitempty"`
	Error        string `json:"error,omitempty"`
}

// ImageConfig is the image metadata that affects how a container image root
// is presented to the guest. It is copied into a state's status so copies and
// image states do not need their original source or image after creation.
type ImageConfig struct {
	Env        []string `json:"env,omitempty"` // KEY=VALUE
	Entrypoint []string `json:"entrypoint,omitempty"`
	Cmd        []string `json:"cmd,omitempty"`
	WorkingDir string   `json:"workingDir,omitempty"`
	User       string   `json:"user,omitempty"`
}

type Transfer struct {
	CommitID   string `json:"commitID"`
	DoneBytes  int64  `json:"doneBytes"`
	TotalBytes int64  `json:"totalBytes"`
}

type BlipStateStatus struct {
	Phase   string `json:"phase,omitempty"`
	Message string `json:"message,omitempty"`
	// ImageDigest is the resolved container image (digest reference
	// repo@sha256:...) for image-initialized states.
	ImageDigest string `json:"imageDigest,omitempty"`
	// ImageConfig is the container image metadata resolved when the state
	// was created. It is copied into copies and remains valid after the
	// original image or source state is gone.
	ImageConfig *ImageConfig   `json:"imageConfig,omitempty"`
	CopiedFrom  *CopySource    `json:"copiedFrom,omitempty"`
	SizeBytes   int64          `json:"sizeBytes,omitempty"`
	Committed   *Commit        `json:"committed,omitempty"`
	Writer      *Writer        `json:"writer,omitempty"`
	Pending     *PendingCommit `json:"pending,omitempty"`
	// Seals records the outcome of ended writer attachments, keyed by
	// attachment ID. The controller keeps entries long enough for the Blip
	// that wrote them to observe the result, so a later save cannot hide an
	// earlier failure.
	// +listType=map
	// +listMapKey=attachmentID
	// +kubebuilder:validation:MaxItems=32
	Seals []SealResult `json:"seals,omitempty"`
	// LastError is the latest node-side preparation error for this state.
	LastError string `json:"lastError,omitempty"`
	// Placements are the nodes that hold (or are being given) the
	// committed version.
	Placements []string `json:"placements,omitempty"`
	// +listType=map
	// +listMapKey=node
	Nodes []NodeObservation `json:"nodes,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=bst
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Gen",type=integer,JSONPath=`.status.committed.generation`
// +kubebuilder:printcolumn:name="Writer",type=string,JSONPath=`.status.writer.blipName`
// +kubebuilder:printcolumn:name="Replicas",type=integer,JSONPath=`.spec.replicas`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type BlipState struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              BlipStateSpec   `json:"spec"`
	Status            BlipStateStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type BlipStateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BlipState `json:"items"`
}

// ---------------------------------------------------------------------------
// Blip

// NetworkPolicy allows IPv4 egress. Rules are ORed; an empty policy denies all.
type NetworkPolicy struct {
	// +kubebuilder:validation:MaxItems=64
	Egress []NetworkEgressRule `json:"egress,omitempty"`
}

// NetworkEgressRule allows the intersection of its destinations and ports.
type NetworkEgressRule struct {
	// To selects destinations. Omitted or empty means all IPv4 destinations.
	// +kubebuilder:validation:MaxItems=64
	To []NetworkPeer `json:"to,omitempty"`
	// Ports allows numeric TCP/UDP destination ports. Omitted or empty means
	// all IP protocols and ports. Service ports are not translated here.
	// +kubebuilder:validation:MaxItems=64
	Ports []NetworkPort `json:"ports,omitempty"`
}

// NetworkPeer selects an IP block, pods, or services. Pod and namespace
// selectors are ANDed; service and namespace selectors are ANDed. Without a
// namespace selector, selectors are scoped to the Blip's namespace.
//
// +kubebuilder:validation:XValidation:rule="has(self.ipBlock) || has(self.podSelector) || has(self.namespaceSelector) || has(self.serviceSelector)",message="a peer must select an IP block, pods, namespaces, or services"
// +kubebuilder:validation:XValidation:rule="!has(self.ipBlock) || !(has(self.podSelector) || has(self.namespaceSelector) || has(self.serviceSelector))",message="ipBlock cannot be combined with selectors"
// +kubebuilder:validation:XValidation:rule="!(has(self.podSelector) && has(self.serviceSelector))",message="podSelector and serviceSelector cannot be combined"
type NetworkPeer struct {
	// IPBlock allows an IPv4 CIDR minus its strictly smaller exception CIDRs.
	IPBlock *NetworkIPBlock `json:"ipBlock,omitempty"`
	// PodSelector selects direct PodIPs, excluding host-networked, terminal,
	// and deleting pods whose old addresses may have been reassigned.
	PodSelector *metav1.LabelSelector `json:"podSelector,omitempty"`
	// NamespaceSelector selects namespaces by label; alone it selects pods.
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
	// ServiceSelector selects ClusterIPs, or EndpointSlice IPv4 addresses for
	// headless services. ExternalName services have no selectable address.
	ServiceSelector *metav1.LabelSelector `json:"serviceSelector,omitempty"`
}

// NetworkIPBlock is an IPv4 CIDR with optional, strictly smaller exceptions.
//
// +kubebuilder:validation:XValidation:rule="isCIDR(self.cidr) && cidr(self.cidr).ip().family() == 4",message="cidr must be a valid IPv4 CIDR"
// Check containment with containsIP rather than containsCIDR: Kubernetes 1.31's
// containsCIDR compares an unmasked PrefixFrom(exceptionAddr, parentBits), so it
// rejects valid exceptions whose address is not the parent's network address.
// +kubebuilder:validation:XValidation:rule="!has(self.except) || self.except.all(c, isCIDR(c) && cidr(c).ip().family() == 4 && cidr(self.cidr).containsIP(cidr(c).ip()) && cidr(c).prefixLength() > cidr(self.cidr).prefixLength())",message="exceptions must be IPv4 CIDRs strictly inside cidr"
type NetworkIPBlock struct {
	// CIDR is an IPv4 destination range, for example 192.0.2.0/24.
	// +kubebuilder:validation:MaxLength=18
	CIDR string `json:"cidr"`
	// Except removes IPv4 subranges from CIDR.
	// +kubebuilder:validation:MaxItems=32
	// +kubebuilder:validation:items:MaxLength=18
	// +listType=atomic
	Except []string `json:"except,omitempty"`
}

// NetworkPort is a numeric destination port or inclusive port range.
//
// +kubebuilder:validation:XValidation:rule="!has(self.endPort) || self.endPort >= self.port",message="endPort must be at least port"
type NetworkPort struct {
	// +kubebuilder:validation:Enum=TCP;UDP
	// +kubebuilder:default=TCP
	Protocol corev1.Protocol `json:"protocol,omitempty"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	EndPort *int32 `json:"endPort,omitempty"`
}

// Mount attaches a state's filesystem inside a running blip.
type Mount struct {
	// State names a BlipState in the blip's namespace.
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-.a-z0-9]*[a-z0-9])?$`
	State string `json:"state"`
	// Path is an absolute path inside the guest root. It must be clean: no
	// trailing slash, repeated slash, or . and .. segments.
	// +kubebuilder:validation:Pattern=`^/[^/]+(/[^/]+)*$`
	// +kubebuilder:validation:MaxLength=4096
	// +kubebuilder:validation:XValidation:rule="!self.split('/').exists(s, s == '.' || s == '..')",message="path must not contain . or .. segments"
	Path string `json:"path"`
	// Writable mounts take the state's single writer slot and save a new
	// version when unmounted. Read-only mounts pin the committed version.
	Writable bool `json:"writable,omitempty"`
	// BlipUID scopes a temporary mount to one execution. Empty keeps the
	// mount across executions of the root state.
	BlipUID string `json:"blipUID,omitempty"`
}

type EnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
}

// RuntimeDefaults supplies defaults for executions of a root state. Startup
// values are resolved once at claim; Network changes apply to running blips
// that do not override it.
type RuntimeDefaults struct {
	Env        []EnvVar `json:"env,omitempty"`
	WorkingDir string   `json:"workingDir,omitempty"`
	User       string   `json:"user,omitempty"`
	// Network narrows the pool's egress policy. Omitted inherits the pool;
	// explicitly empty denies all.
	Network *NetworkPolicy `json:"network,omitempty"`
}

// BlipSpec is one VM lifetime: one command that runs as the primary session.
// The blip ends when the command exits.
//
// +kubebuilder:validation:XValidation:rule="self.command == oldSelf.command",message="command is immutable"
// +kubebuilder:validation:XValidation:rule="(has(self.env) == has(oldSelf.env)) && (!has(self.env) || self.env == oldSelf.env)",message="env is immutable"
// +kubebuilder:validation:XValidation:rule="(has(self.workingDir) == has(oldSelf.workingDir)) && (!has(self.workingDir) || self.workingDir == oldSelf.workingDir)",message="workingDir is immutable"
// +kubebuilder:validation:XValidation:rule="(has(self.user) == has(oldSelf.user)) && (!has(self.user) || self.user == oldSelf.user)",message="user is immutable"
// +kubebuilder:validation:XValidation:rule="(has(self.tty) && self.tty) == (has(oldSelf.tty) && oldSelf.tty)",message="tty is immutable"
type BlipSpec struct {
	// Pool names a BlipPool in the blip's namespace.
	// +kubebuilder:default=default
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="pool is immutable"
	Pool string `json:"pool,omitempty"`
	// State gives the blip a durable root filesystem. A new version is
	// saved when the blip stops. Mounts and runtime defaults come from this
	// state in the blip's namespace.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-.a-z0-9]*[a-z0-9])?$`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="state is immutable"
	State string `json:"state"`
	// Command runs as the primary session. The blip ends when it exits.
	// +kubebuilder:validation:MinItems=1
	Command []string `json:"command"`
	Env     []EnvVar `json:"env,omitempty"`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="workingDir is immutable"
	WorkingDir string `json:"workingDir,omitempty"`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="user is immutable"
	User string `json:"user,omitempty"`
	// TTY gives the primary command a terminal.
	TTY bool `json:"tty,omitempty"`
	// Stop asks the blip to shut down gracefully and save.
	Stop bool `json:"stop,omitempty"`
	// ActiveDeadlineSeconds stops the blip's command when it has run this
	// long. The VM is stopped as if spec.stop were set. `blip run --timeout`
	// sets it.
	// +kubebuilder:validation:Minimum=1
	// +optional
	ActiveDeadlineSeconds *int64 `json:"activeDeadlineSeconds,omitempty"`
	// TTLSecondsAfterFinished deletes the blip this long after it finished,
	// whether or not anyone gathered its results. `blip run --ttl` sets it.
	// +kubebuilder:validation:Minimum=0
	// +optional
	TTLSecondsAfterFinished *int32 `json:"ttlSecondsAfterFinished,omitempty"`
	// Network narrows the pool's egress policy. Omitted inherits the root
	// state's runtime network policy, or the pool if neither is set.
	// Explicitly empty denies all. Changes apply to running blips.
	Network *NetworkPolicy `json:"network,omitempty"`
}

const (
	BlipPending   = "Pending"   // waiting for a VM or for states
	BlipRunning   = "Running"   // the VM is claimed and running
	BlipSaving    = "Saving"    // the VM stopped; writable states are saving
	BlipSucceeded = "Succeeded" // command exited 0 and all saves committed
	BlipFailed    = "Failed"
)

const (
	MountPending    = "Pending"
	MountMounted    = "Mounted"
	MountUnmounting = "Unmounting"
	MountSaving     = "Saving"
	MountFailed     = "Failed"
)

type MountStatus struct {
	State    string `json:"state"`
	Path     string `json:"path"`
	Writable bool   `json:"writable,omitempty"`
	// StateUID and CommitID pin the version: the mounted version for
	// read-only mounts, the base version for writable mounts.
	StateUID string `json:"stateUID,omitempty"`
	CommitID string `json:"commitID,omitempty"`
	// AttachmentID is unique per mount operation.
	AttachmentID string `json:"attachmentID,omitempty"`
	Phase        string `json:"phase"`
	Message      string `json:"message,omitempty"`
	// Switching is set while the mount is being changed between read-only
	// and writable. It remains set if the switch fails so the previous
	// mode stays visible.
	Switching bool `json:"switching,omitempty"`
}

type BlipStatus struct {
	Phase   string `json:"phase,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
	Pod     string `json:"pod,omitempty"`
	PodUID  string `json:"podUID,omitempty"`
	Node    string `json:"node,omitempty"`
	// StateGeneration is the observed desired generation of the root state.
	StateGeneration int64 `json:"stateGeneration,omitempty"`
	// RootAttachmentID is the writer attachment of a durable root.
	RootAttachmentID string       `json:"rootAttachmentID,omitempty"`
	StartTime        *metav1.Time `json:"startTime,omitempty"`
	FinishTime       *metav1.Time `json:"finishTime,omitempty"`
	ExitCode         *int32       `json:"exitCode,omitempty"`
	Sessions         int32        `json:"sessions,omitempty"`
	// +listType=map
	// +listMapKey=state
	Mounts []MountStatus `json:"mounts,omitempty"`
	// Locality is where a pending Blip's durable data lives. The pool
	// boots a VM pinned to that node so the Blip does not start on a
	// remote clone.
	Locality *Locality `json:"locality,omitempty"`
	// Report is the last report the workload submitted through
	// BLIP_REPORT_URL. It is retained after the pod is gone.
	Report *BlipReport `json:"report,omitempty"`
}

// BlipReport is one bounded progress or result string published by a
// workload. Seq increases for every accepted report and never decreases.
type BlipReport struct {
	// +kubebuilder:validation:Minimum=1
	Seq int64 `json:"seq"`
	// +kubebuilder:validation:MaxLength=1024
	Text string       `json:"text"`
	Time *metav1.Time `json:"time,omitempty"`
}

// Locality records the node a pending Blip prefers and whether it still
// waits for a VM there.
type Locality struct {
	// Node holds the root state (or the most writable mount states).
	Node string `json:"node"`
	// Since is when the Blip, with all its states usable, started waiting
	// for a VM on Node.
	Since *metav1.Time `json:"since,omitempty"`
	// Fallback means the Blip stopped waiting and claims any warm VM.
	Fallback bool `json:"fallback,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Root",type=string,JSONPath=`.spec.state`
// +kubebuilder:printcolumn:name="Exit",type=integer,JSONPath=`.status.exitCode`
// +kubebuilder:printcolumn:name="Node",type=string,JSONPath=`.status.node`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.reason`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type Blip struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              BlipSpec   `json:"spec"`
	Status            BlipStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type BlipList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Blip `json:"items"`
}

// ---------------------------------------------------------------------------
// BlipNode (internal)

type BlipNodeSpec struct {
	// Drain stops writers on this node gracefully (durable states save and
	// replicas are moved to other nodes) and prevents new claims. The node
	// is safe to remove once it holds no needed replicas or writers. Admins
	// set it to remove a node; the controller also sets it when no BlipPool
	// selects the node.
	Drain bool `json:"drain,omitempty"`
}

type BlipNodeStatus struct {
	// Incarnation changes whenever the node's storage is recreated.
	Incarnation string `json:"incarnation,omitempty"`
	// TLSPublicKey is the base64-encoded Ed25519 public key used to authenticate
	// peer TLS connections.
	TLSPublicKey string `json:"tlsPublicKey,omitempty"`
	// Endpoint is the node's host IPv4 address for HTTPS control and NVMe/TCP.
	Endpoint string `json:"endpoint,omitempty"`
	// Hypervisors are the hypervisors this node supports, for example
	// ["kvm"]. The controller requires at least one before scheduling VMs or
	// state replicas on the node.
	Hypervisors []string     `json:"hypervisors,omitempty"`
	FreeBytes   int64        `json:"freeBytes,omitempty"`
	Heartbeat   *metav1.Time `json:"heartbeat,omitempty"`
	// SafeToRemove is set by the controller once a draining node holds
	// no needed replicas and runs no writers.
	SafeToRemove bool `json:"safeToRemove,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Endpoint",type=string,JSONPath=`.status.endpoint`
// +kubebuilder:printcolumn:name="Drain",type=boolean,JSONPath=`.spec.drain`
// +kubebuilder:printcolumn:name="SafeToRemove",type=boolean,JSONPath=`.status.safeToRemove`
// +kubebuilder:printcolumn:name="Heartbeat",type=date,JSONPath=`.status.heartbeat`
type BlipNode struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              BlipNodeSpec   `json:"spec,omitempty"`
	Status            BlipNodeStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type BlipNodeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BlipNode `json:"items"`
}
