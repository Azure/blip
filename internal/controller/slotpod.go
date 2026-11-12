package controller

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/example/blip/internal/api"
	v1 "github.com/example/blip/internal/api/v1alpha1"
)

const mib = 1 << 20

// slotResources computes the slot container resources of a VM shape:
// CPU request cpus/cpuOvercommit, limit cpus; memory request
// ceil(memory/memOvercommit) MiB + overhead, limit memory + overhead; plus
// one hypervisor device.
func slotResources(cpus int32, memory resource.Quantity, opts *Options) corev1.ResourceRequirements {
	memMiB := memory.Value() / mib
	overMiB := (opts.SlotVMMOverhead.Value() + mib - 1) / mib
	cpuReq := int64(math.Ceil(float64(cpus) * 1000 / opts.SlotCPUOvercommit))
	memReq := int64(math.Ceil(float64(memMiB)/opts.SlotMemoryOvercommit)) + overMiB
	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    *resource.NewMilliQuantity(cpuReq, resource.DecimalSI),
			corev1.ResourceMemory: *resource.NewQuantity(memReq*mib, resource.BinarySI),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:                          *resource.NewQuantity(int64(cpus), resource.DecimalSI),
			corev1.ResourceMemory:                       *resource.NewQuantity((memMiB+overMiB)*mib, resource.BinarySI),
			corev1.ResourceName(api.ResourceHypervisor): *resource.NewQuantity(1, resource.DecimalSI),
		},
	}
}

// slotPodSpec builds the pod spec of a pool's slot pods. It depends only on
// the pool spec and the controller options.
func slotPodSpec(pool *v1.BlipPool, opts *Options) corev1.PodSpec {
	s := &pool.Spec
	var sel map[string]string
	if s.Hypervisor != "" || len(s.NodeSelector) > 0 {
		sel = map[string]string{}
		for k, v := range s.NodeSelector {
			sel[k] = v
		}
		if s.Hypervisor != "" {
			// The built-in selector wins over the pool's.
			sel[api.LabelHypervisor] = string(s.Hypervisor)
		}
	}
	var tol []corev1.Toleration
	if len(s.Tolerations) > 0 {
		tol = append(tol, s.Tolerations...)
	}
	grace := int64(30)
	return corev1.PodSpec{
		AutomountServiceAccountToken:  ptr(false),
		EnableServiceLinks:            ptr(false),
		TerminationGracePeriodSeconds: &grace,
		NodeSelector:                  sel,
		Tolerations:                   tol,
		Containers: []corev1.Container{{
			Name:  "slot",
			Image: opts.SlotImage,
			Args:  []string{"slot"},
			Env: []corev1.EnvVar{
				{Name: "VM_CPUS", Value: fmt.Sprint(s.CPUs)},
				{Name: "VM_MEMORY", Value: fmt.Sprintf("%dMi", s.Memory.Value()/mib)},
			},
			Resources: slotResources(s.CPUs, s.Memory, opts),
			SecurityContext: &corev1.SecurityContext{
				Capabilities:   &corev1.Capabilities{Add: []corev1.Capability{"NET_ADMIN"}},
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			ReadinessProbe: &corev1.Probe{
				ProbeHandler:  corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: []string{"blipd", "slot", "probe"}}},
				PeriodSeconds: 2,
			},
		}},
	}
}

// templateHash is a stable hash of a slot pod spec.
func templateHash(spec *corev1.PodSpec) string {
	b, err := json.Marshal(spec)
	if err != nil {
		panic(err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])[:10]
}

// slotPod builds a free slot pod of the pool and returns it with its
// template hash.
func slotPod(pool *v1.BlipPool, opts *Options) (*corev1.Pod, string) {
	spec := slotPodSpec(pool, opts)
	hash := templateHash(&spec)
	sku := pool.Spec.SKU
	if sku == "" {
		sku = api.DefaultSKU
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: pool.Name + "-",
			Namespace:    pool.Namespace,
			Labels: map[string]string{
				api.LabelSKU: sku, api.LabelSlot: api.SlotFree,
				api.LabelPool: pool.Name, api.LabelTemplateHash: hash,
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: v1.GroupVersion.String(), Kind: "BlipPool", Name: pool.Name, UID: pool.UID,
				Controller: ptr(true), BlockOwnerDeletion: ptr(true),
			}},
		},
		Spec: spec,
	}, hash
}

// poolOwned reports whether the pool controls the pod.
func poolOwned(p *corev1.Pod, pool *v1.BlipPool) bool {
	r := metav1.GetControllerOf(p)
	return r != nil && r.Kind == "BlipPool" && r.UID == pool.UID
}
