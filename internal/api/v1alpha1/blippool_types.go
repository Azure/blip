package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Hypervisor selects the kind of hypervisor node slot pods run on.
// +kubebuilder:validation:Enum=kvm;mshv
type Hypervisor string

const (
	HypervisorKVM  Hypervisor = "kvm"
	HypervisorMSHV Hypervisor = "mshv"
)

// BlipPoolSpec is the VM shape, placement and scaling of a pool of slot
// pods for one SKU in a namespace. The controller builds the pods; there is
// no pod template.
// +kubebuilder:validation:XValidation:rule="self.minFree <= self.maxFree",message="minFree must not exceed maxFree"
// +kubebuilder:validation:XValidation:rule="!has(self.maxSlots) || self.maxSlots >= self.maxFree",message="maxSlots must be at least maxFree"
// +kubebuilder:validation:XValidation:rule="quantity(string(self.memory)).compareTo(quantity('256Mi')) >= 0",message="memory must be at least 256Mi"
// +kubebuilder:validation:XValidation:rule="quantity(string(self.memory)).isInteger() && quantity(string(self.memory)).asInteger() % 1048576 == 0",message="memory must be a whole number of MiB"
type BlipPoolSpec struct {
	// SKU is the slot kind Blips select with spec.sku. One pool per
	// namespace and SKU; the oldest pool wins a duplicate. Immutable.
	// +kubebuilder:default=default
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="sku is immutable"
	// +optional
	SKU string `json:"sku,omitempty"`

	// CPUs is the number of guest vCPUs.
	// +kubebuilder:validation:Minimum=1
	CPUs int32 `json:"cpus"`

	// Memory is the guest memory, at least 256Mi and a whole number of MiB.
	Memory resource.Quantity `json:"memory"`

	// Hypervisor restricts slot pods to nodes of this hypervisor kind
	// (node label blip.example.com/hypervisor). Unset means any.
	// +optional
	Hypervisor Hypervisor `json:"hypervisor,omitempty"`

	// NodeSelector is merged with the built-in selector.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations of the slot pods.
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	// MinFree is the number of free (booted, unclaimed) slots kept at all times.
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=0
	// +optional
	MinFree int32 `json:"minFree"`

	// MaxFree caps the demand-driven free buffer.
	// +kubebuilder:validation:Minimum=0
	MaxFree int32 `json:"maxFree"`

	// MaxSlots caps free + booting + assigned slot pods of the pool.
	// +kubebuilder:validation:Minimum=0
	// +optional
	MaxSlots *int32 `json:"maxSlots,omitempty"`

	// DemandWindow is how far back scheduled Blips count as demand.
	// +kubebuilder:default="5m"
	// +optional
	DemandWindow *metav1.Duration `json:"demandWindow,omitempty"`

	// ScaleDownDelay is how long the target must stay lower before free
	// slots are deleted.
	// +kubebuilder:default="10m"
	// +optional
	ScaleDownDelay *metav1.Duration `json:"scaleDownDelay,omitempty"`
}

// BlipPoolStatus is the observed state of a pool.
type BlipPoolStatus struct {
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// TemplateHash is the hash of the pod the controller currently builds.
	// +optional
	TemplateHash string `json:"templateHash,omitempty"`
	// Free counts Ready, unclaimed slot pods owned by the pool.
	// +optional
	Free int32 `json:"free"`
	// Booting counts unclaimed slot pods that are not Ready yet.
	// +optional
	Booting int32 `json:"booting"`
	// Assigned counts claimed slot pods that came from the pool.
	// +optional
	Assigned int32 `json:"assigned"`
	// DesiredFree is the current free buffer target.
	// +optional
	DesiredFree int32 `json:"desiredFree"`
	// LastScaleTime is when the pool last created or deleted slot pods.
	// +optional
	LastScaleTime *metav1.Time `json:"lastScaleTime,omitempty"`
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// BlipPool keeps a buffer of free slot pods for one SKU in its namespace.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=bpool
// +kubebuilder:printcolumn:name="SKU",type=string,JSONPath=`.spec.sku`
// +kubebuilder:printcolumn:name="CPUs",type=integer,JSONPath=`.spec.cpus`
// +kubebuilder:printcolumn:name="Memory",type=string,JSONPath=`.spec.memory`
// +kubebuilder:printcolumn:name="Free",type=integer,JSONPath=`.status.free`
// +kubebuilder:printcolumn:name="Assigned",type=integer,JSONPath=`.status.assigned`
// +kubebuilder:printcolumn:name="Desired",type=integer,JSONPath=`.status.desiredFree`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type BlipPool struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   BlipPoolSpec   `json:"spec,omitempty"`
	Status BlipPoolStatus `json:"status,omitempty"`
}

// BlipPoolList is a list of BlipPools.
// +kubebuilder:object:root=true
type BlipPoolList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BlipPool `json:"items"`
}
