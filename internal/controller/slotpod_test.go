package controller

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/example/blip/internal/api"
	v1 "github.com/example/blip/internal/api/v1alpha1"
)

func testPool(cpus int32, mem string) *v1.BlipPool {
	return &v1.BlipPool{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "p", UID: "uid-1"},
		Spec:       v1.BlipPoolSpec{SKU: "s", CPUs: cpus, Memory: resource.MustParse(mem), MaxFree: 2},
	}
}

func testOpts() *Options {
	o := DefaultOptions()
	o.SlotImage = "img:1"
	return &o
}

func TestSlotResources(t *testing.T) {
	for _, tc := range []struct {
		cpus                        int32
		mem, cpuReq, memReq, memLim string
		cpuLim                      string
	}{
		{2, "2Gi", "500m", "1622Mi", "2304Mi", "2"},
		{1, "512Mi", "250m", "598Mi", "768Mi", "1"},
	} {
		p, _ := slotPod(testPool(tc.cpus, tc.mem), testOpts())
		r := p.Spec.Containers[0].Resources
		chk := func(what string, got resource.Quantity, want string) {
			if got.Cmp(resource.MustParse(want)) != 0 {
				t.Errorf("%d/%s %s: got %s want %s", tc.cpus, tc.mem, what, got.String(), want)
			}
		}
		chk("cpu request", r.Requests[corev1.ResourceCPU], tc.cpuReq)
		chk("memory request", r.Requests[corev1.ResourceMemory], tc.memReq)
		chk("cpu limit", r.Limits[corev1.ResourceCPU], tc.cpuLim)
		chk("memory limit", r.Limits[corev1.ResourceMemory], tc.memLim)
		chk("hypervisor", r.Limits[api.ResourceHypervisor], "1")
	}
}

func TestSlotPod(t *testing.T) {
	pl := testPool(2, "2Gi")
	p, h := slotPod(pl, testOpts())
	if p.GenerateName != "p-" || p.Namespace != "ns" || p.Labels[api.LabelPool] != "p" || p.Labels[api.LabelSKU] != "s" ||
		p.Labels[api.LabelSlot] != api.SlotFree || p.Labels[api.LabelTemplateHash] != h || !poolOwned(p, pl) ||
		*p.OwnerReferences[0].BlockOwnerDeletion != true {
		t.Fatalf("metadata: %+v", p.ObjectMeta)
	}
	c := p.Spec.Containers[0]
	if *p.Spec.AutomountServiceAccountToken || *p.Spec.EnableServiceLinks || c.Image != "img:1" || c.Env[0].Value != "2" || c.Env[1].Value != "2048Mi" ||
		len(p.Spec.Volumes) != 0 || c.SecurityContext.Privileged != nil {
		t.Fatalf("spec: %+v", p.Spec)
	}
	// Stable, and independent of name/UID.
	pl2 := pl.DeepCopy()
	pl2.Name, pl2.UID = "q", "uid-2"
	if _, h2 := slotPod(pl2, testOpts()); h2 != h {
		t.Fatal("hash depends on identity")
	}
	for name, mut := range map[string]func(*v1.BlipPool, *Options){
		"cpus":       func(p *v1.BlipPool, _ *Options) { p.Spec.CPUs = 3 },
		"memory":     func(p *v1.BlipPool, _ *Options) { p.Spec.Memory = resource.MustParse("1Gi") },
		"selector":   func(p *v1.BlipPool, _ *Options) { p.Spec.NodeSelector = map[string]string{"a": "b"} },
		"image":      func(_ *v1.BlipPool, o *Options) { o.SlotImage = "img:2" },
		"overcommit": func(_ *v1.BlipPool, o *Options) { o.SlotCPUOvercommit = 2 },
	} {
		pp, o := pl.DeepCopy(), testOpts()
		mut(pp, o)
		if _, h2 := slotPod(pp, o); h2 == h {
			t.Errorf("%s: hash unchanged", name)
		}
	}
	// minFree/maxFree do not change the shape.
	pp := pl.DeepCopy()
	pp.Spec.MinFree, pp.Spec.MaxFree = 3, 9
	if _, h2 := slotPod(pp, testOpts()); h2 != h {
		t.Error("scaling knobs change the hash")
	}
}

func TestSlotPodPlacement(t *testing.T) {
	pl := testPool(1, "512Mi")
	pl.Spec.Hypervisor = v1.HypervisorKVM
	pl.Spec.NodeSelector = map[string]string{"zone": "a", api.LabelHypervisor: "mshv"}
	pl.Spec.Tolerations = []corev1.Toleration{{Key: "k", Operator: corev1.TolerationOpExists}}
	p, _ := slotPod(pl, testOpts())
	if len(p.Spec.NodeSelector) != 2 || p.Spec.NodeSelector["zone"] != "a" || p.Spec.NodeSelector[api.LabelHypervisor] != "kvm" {
		t.Errorf("nodeSelector %v", p.Spec.NodeSelector)
	}
	if len(p.Spec.Tolerations) != 1 || p.Spec.Tolerations[0].Key != "k" {
		t.Errorf("tolerations %v", p.Spec.Tolerations)
	}
	if pl.Spec.NodeSelector[api.LabelHypervisor] != "mshv" {
		t.Error("pool spec mutated")
	}
	p, _ = slotPod(testPool(1, "512Mi"), testOpts())
	if p.Spec.NodeSelector != nil || p.Spec.Tolerations != nil {
		t.Error("unexpected placement")
	}
}
