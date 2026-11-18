package controller

import (
	"fmt"
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/podapi"
)

type podSetup struct {
	claimed bool
	ready   bool
	phase   corev1.PodPhase
}

func TestPoolScaling(t *testing.T) {
	warmPod := podSetup{ready: true, phase: corev1.PodRunning}
	booting := podSetup{phase: corev1.PodPending}
	claimed := podSetup{claimed: true, phase: corev1.PodRunning}
	failed := podSetup{phase: corev1.PodFailed}
	tests := []struct {
		name       string
		warm, max  int32
		pods       []podSetup
		demand     int
		wantVacant int // live vacant pods after one reconcile
		wantTotal  int
		wantStatus v1.BlipPoolStatus
	}{
		{name: "fills warm count", warm: 2, wantVacant: 2, wantTotal: 2, wantStatus: v1.BlipPoolStatus{Vacant: 2}},
		{name: "steady", warm: 2, pods: []podSetup{warmPod, booting}, wantVacant: 2, wantTotal: 2, wantStatus: v1.BlipPoolStatus{Ready: 1, Vacant: 2}},
		{name: "pending demand adds pods", warm: 1, demand: 2, pods: []podSetup{warmPod}, wantVacant: 3, wantTotal: 3, wantStatus: v1.BlipPoolStatus{Ready: 1, Vacant: 3}},
		{name: "warm pods cover demand", warm: 2, demand: 1, pods: []podSetup{warmPod, warmPod}, wantVacant: 2, wantTotal: 2, wantStatus: v1.BlipPoolStatus{Ready: 2, Vacant: 2}},
		{name: "claimed pods do not count as warm", warm: 1, pods: []podSetup{claimed, claimed}, wantVacant: 1, wantTotal: 3, wantStatus: v1.BlipPoolStatus{Vacant: 1, Claimed: 2}},
		{name: "max count caps all pool pods", warm: 2, max: 2, pods: []podSetup{claimed}, demand: 3, wantVacant: 1, wantTotal: 2, wantStatus: v1.BlipPoolStatus{Vacant: 1, Claimed: 1}},
		{name: "at max count", warm: 1, max: 2, pods: []podSetup{claimed, claimed}, wantVacant: 0, wantTotal: 2, wantStatus: v1.BlipPoolStatus{Claimed: 2}},
		{name: "failed vacant pod is replaced", warm: 1, pods: []podSetup{failed}, wantVacant: 1, wantTotal: 1, wantStatus: v1.BlipPoolStatus{Vacant: 1}},
		{name: "excess deletes booting first", warm: 1, pods: []podSetup{booting, warmPod, booting}, wantVacant: 1, wantTotal: 1, wantStatus: v1.BlipPoolStatus{Ready: 1, Vacant: 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			e.newPool("default", tt.warm, tt.max)
			pool := &v1.BlipPool{}
			e.must(e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: "default"}, pool))
			for i, ps := range tt.pods {
				p := e.pool.podFor(pool, fmt.Sprintf("default-p%d", i))
				p.Status.Phase = ps.phase
				if ps.ready {
					p.Labels[LabelWarm] = "true"
				}
				if ps.claimed {
					p.Labels[LabelBlipUID] = fmt.Sprintf("uid-%d", i)
				}
				e.create(p)
			}
			for i := range tt.demand {
				e.pendingBlip(fmt.Sprintf("b%d", i), withImage("reg/img:v1"))
			}
			e.run(e.pool, ns, "default")

			vacant := 0
			pods := e.pods()
			for _, p := range pods {
				if isVacant(&p) && !podTerminated(&p) {
					vacant++
				}
				if isVacant(&p) && podTerminated(&p) {
					t.Errorf("terminated vacant pod %s not deleted", p.Name)
				}
			}
			if vacant != tt.wantVacant || len(pods) != tt.wantTotal {
				t.Errorf("vacant %d total %d, want %d %d", vacant, len(pods), tt.wantVacant, tt.wantTotal)
			}
			if tt.name == "excess deletes booting first" {
				for _, p := range pods {
					if !ready(&p) {
						t.Errorf("kept booting pod %s over the ready one", p.Name)
					}
				}
			}
			e.must(e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: "default"}, pool))
			if pool.Status != tt.wantStatus {
				t.Errorf("status %+v, want %+v", pool.Status, tt.wantStatus)
			}
		})
	}
}

func TestPoolAvoidsDrainingNodes(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 2, 0)
	pool := &v1.BlipPool{}
	e.must(e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: "default"}, pool))
	for i, node := range []string{"n1", "n2"} {
		p := e.pool.podFor(pool, fmt.Sprintf("default-p%d", i))
		p.Spec.NodeName = node
		p.Status.Phase = corev1.PodRunning
		p.Labels[LabelWarm] = "true"
		e.create(p)
	}
	e.setDrain("n2")
	e.run(e.pool, ns, "default")

	var replacement *corev1.Pod
	for _, p := range e.pods() {
		if p.Spec.NodeName == "n2" {
			t.Errorf("vacant pod %s on draining node kept", p.Name)
		}
		if p.Spec.NodeName == "" {
			replacement = &p
		}
	}
	if replacement == nil {
		t.Fatal("no replacement pod")
	}
	aff := replacement.Spec.Affinity
	if aff == nil || aff.NodeAffinity == nil {
		t.Fatalf("replacement has no node affinity")
	}
	req := aff.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms[0].MatchFields[0]
	if req.Operator != corev1.NodeSelectorOpNotIn || len(req.Values) != 1 || req.Values[0] != "n2" {
		t.Errorf("affinity %+v", req)
	}
}

func TestPoolPodSpec(t *testing.T) {
	e := newEnv(t)
	e.create(&v1.BlipPool{
		ObjectMeta: metadata("big"),
		Spec: v1.BlipPoolSpec{
			Hypervisor: "kvm", CPUs: 4, Memory: resource.MustParse("8Gi"), WarmCount: 1,
			ServiceAccountName: "agent", NodeSelector: map[string]string{"zone": "a"},
			Tolerations: []corev1.Toleration{{Key: "blip", Operator: corev1.TolerationOpExists}},
		},
	})
	e.run(e.pool, ns, "big")
	pods := e.pods()
	if len(pods) != 1 {
		t.Fatalf("%d pods", len(pods))
	}
	p := pods[0]
	if len(p.Name) != len("big-")+5 || p.Labels[LabelPool] != "big" || p.Labels[LabelBlipUID] != "" {
		t.Errorf("name/labels: %s %v", p.Name, p.Labels)
	}
	if ref := p.OwnerReferences; len(ref) != 1 || ref[0].Kind != "BlipPool" || ref[0].Controller == nil || !*ref[0].Controller {
		t.Errorf("owner %+v", ref)
	}
	pool := e.getPool("big")
	if got := p.Annotations[annotationTemplateHash]; got == "" || got != templateHash(pool) {
		t.Errorf("template hash %q, want %q", got, templateHash(pool))
	}
	s := p.Spec
	if s.RestartPolicy != corev1.RestartPolicyNever || s.ServiceAccountName != "agent" || len(s.Tolerations) != 1 {
		t.Errorf("spec %+v", s)
	}
	if s.AutomountServiceAccountToken == nil || *s.AutomountServiceAccountToken {
		t.Errorf("service account token automounted: %v", s.AutomountServiceAccountToken)
	}
	if s.NodeSelector["zone"] != "a" || s.NodeSelector[LabelEnrolled] != "true" ||
		s.NodeSelector[LabelHypervisorPrefix+"kvm"] != "true" {
		t.Errorf("node selector %v", s.NodeSelector)
	}
	if len(s.Containers) != 1 {
		t.Fatalf("containers %+v", s.Containers)
	}
	c := s.Containers[0]
	if c.Name != "vm" || c.Image != "reg/blip-runtime:dev" || c.Command[0] != "blip-runtime" || !*c.SecurityContext.Privileged {
		t.Errorf("container %+v", c)
	}
	env := map[string]string{}
	for _, v := range c.Env {
		env[v.Name] = v.Value
		if v.ValueFrom != nil {
			env[v.Name] = v.ValueFrom.FieldRef.FieldPath
		}
	}
	want := map[string]string{"BLIP_CPUS": "4", "BLIP_MEMORY_MB": "8192", "BLIP_HYPERVISOR": "kvm", "POD_NAME": "metadata.name", "POD_NAMESPACE": "metadata.namespace", "BLIP_KUBE_NAMESPACE": "metadata.namespace"}
	for k, v := range want {
		if env[k] != v {
			t.Errorf("env %s=%q, want %q", k, env[k], v)
		}
	}
	if cpu := c.Resources.Requests[corev1.ResourceCPU]; cpu.Value() != 4 {
		t.Errorf("cpu %v", cpu)
	}
	if mem := c.Resources.Requests[corev1.ResourceMemory]; mem.Value() != 8<<30+512<<20 {
		t.Errorf("memory request %v", mem.String())
	}
	if mem := c.Resources.Limits[corev1.ResourceMemory]; mem.Value() != 9<<30 {
		t.Errorf("memory limit %v", mem.String())
	}
	if _, ok := c.Resources.Limits[corev1.ResourceCPU]; ok {
		t.Errorf("cpu limit set: %v", c.Resources.Limits[corev1.ResourceCPU])
	}
	if hp := s.Volumes[0].HostPath; hp.Path != podapi.PodDir(ns, p.Name) || *hp.Type != corev1.HostPathDirectoryOrCreate || c.VolumeMounts[0].MountPath != "/run/blip" {
		t.Errorf("volume %+v %+v", hp, c.VolumeMounts)
	}
}

func TestPoolPodCredentials(t *testing.T) {
	for _, account := range []string{"", "agent", "default"} {
		t.Run("account="+account, func(t *testing.T) {
			e := newEnv(t)
			pool := &v1.BlipPool{ObjectMeta: metadata("p"), Spec: v1.BlipPoolSpec{ServiceAccountName: account}}
			p := e.pool.podFor(pool, "p-vm")
			if p.Spec.AutomountServiceAccountToken == nil || *p.Spec.AutomountServiceAccountToken {
				t.Fatal("VM pod must disable token automount")
			}
			if len(p.Spec.Containers) != 1 || p.Spec.RestartPolicy != corev1.RestartPolicyNever {
				t.Fatalf("VM must be the only regular container, with no pod restart: %+v", p.Spec)
			}
			vm := p.Spec.Containers[0]
			volumes := map[string]corev1.Volume{}
			for _, v := range p.Spec.Volumes {
				volumes[v.Name] = v
			}
			shared := ""
			for _, m := range vm.VolumeMounts {
				v := volumes[m.Name]
				if v.Projected != nil || v.Secret != nil || m.MountPath == serviceAccountPath {
					t.Errorf("runtime has a credential mount: %+v", m)
				}
				if m.MountPath == "/run/blip/vsock" && !m.ReadOnly && v.EmptyDir != nil {
					shared = m.Name
				}
			}
			if shared == "" {
				t.Fatal("runtime has no shared vsock emptyDir")
			}
			namespaceEnv := false
			for _, env := range vm.Env {
				if env.Name == "BLIP_KUBE_NAMESPACE" {
					namespaceEnv = true
					if env.Value != "" || env.ValueFrom == nil || env.ValueFrom.FieldRef == nil || env.ValueFrom.FieldRef.FieldPath != "metadata.namespace" {
						t.Errorf("namespace must come from DownwardAPI: %+v", env)
					}
				}
			}
			if namespaceEnv != (account != "") {
				t.Errorf("namespace env present = %t for account %q", namespaceEnv, account)
			}
			if account == "" {
				if len(p.Spec.InitContainers) != 0 || len(p.Spec.Volumes) != 2 {
					t.Errorf("tokenless pool has a proxy or credential volume: %+v", p.Spec)
				}
				return
			}
			if len(p.Spec.InitContainers) != 1 {
				t.Fatalf("want one native sidecar, got %+v", p.Spec.InitContainers)
			}
			proxy := p.Spec.InitContainers[0]
			if proxy.Name != "api-proxy" || proxy.Image != vm.Image || !slices.Equal(proxy.Command, []string{"blip-runtime", "api-proxy"}) {
				t.Errorf("API proxy invocation: %+v", proxy)
			}
			if proxy.RestartPolicy == nil || *proxy.RestartPolicy != corev1.ContainerRestartPolicyAlways || vm.RestartPolicy != nil {
				t.Error("API proxy must restart independently and terminate with the VM")
			}
			sc := proxy.SecurityContext
			if sc == nil || sc.RunAsUser == nil || *sc.RunAsUser != 65532 || sc.RunAsGroup == nil || *sc.RunAsGroup != 65532 || sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot {
				t.Fatalf("API proxy must run as non-root uid/gid 65532: %+v", sc)
			}
			if sc.Privileged == nil || *sc.Privileged || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation || sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem || sc.Capabilities == nil || len(sc.Capabilities.Add) != 0 || !slices.Equal(sc.Capabilities.Drop, []corev1.Capability{"ALL"}) {
				t.Errorf("API proxy is not confined: %+v", sc)
			}
			if sc := p.Spec.SecurityContext; sc == nil || sc.FSGroup == nil || *sc.FSGroup != 65532 || sc.RunAsUser != nil {
				t.Errorf("pod must grant socket access without changing runtime uid: %+v", sc)
			}
			if cpu := proxy.Resources.Requests.Cpu(); cpu.Sign() <= 0 || cpu.MilliValue() > 100 {
				t.Errorf("proxy CPU request = %s", cpu.String())
			}
			if memory := proxy.Resources.Limits.Memory(); memory.Sign() <= 0 || memory.Value() > 128<<20 {
				t.Errorf("proxy memory limit = %s", memory.String())
			}
			if len(proxy.Env) != 0 {
				t.Errorf("proxy should use Kubernetes service autoenv: %+v", proxy.Env)
			}
			if len(proxy.VolumeMounts) != 2 {
				t.Fatalf("proxy should mount only sockets and credentials: %+v", proxy.VolumeMounts)
			}
			var token *corev1.ProjectedVolumeSource
			for _, m := range proxy.VolumeMounts {
				v := volumes[m.Name]
				switch m.MountPath {
				case "/run/blip/vsock":
					if m.Name != shared || m.ReadOnly || v.EmptyDir == nil {
						t.Errorf("proxy socket mount is not shared: %+v", m)
					}
				case serviceAccountPath:
					if !m.ReadOnly || m.SubPath != "" || m.SubPathExpr != "" {
						t.Errorf("credential mount must support read-only rotation: %+v", m)
					}
					token = v.Projected
				default:
					t.Errorf("unexpected proxy mount: %+v", m)
				}
				if v.HostPath != nil {
					t.Errorf("proxy can access the host pod directory: %+v", m)
				}
			}
			if token == nil || len(token.Sources) != 3 {
				t.Fatalf("missing projected API credentials: %+v", token)
			}
			if s := token.Sources[0].ServiceAccountToken; s == nil || s.Path != "token" || s.Audience != "" || s.ExpirationSeconds == nil || *s.ExpirationSeconds != 3600 {
				t.Errorf("want rotating pod-bound API token: %+v", s)
			}
			if s := token.Sources[1].ConfigMap; s == nil || s.Name != "kube-root-ca.crt" || len(s.Items) != 1 || s.Items[0].Key != "ca.crt" || s.Items[0].Path != "ca.crt" {
				t.Errorf("missing API CA projection: %+v", s)
			}
			if s := token.Sources[2].DownwardAPI; s == nil || len(s.Items) != 1 || s.Items[0].Path != "namespace" || s.Items[0].FieldRef == nil || s.Items[0].FieldRef.FieldPath != "metadata.namespace" {
				t.Errorf("missing namespace projection: %+v", s)
			}
		})
	}
}

// TestPoolPodResources checks the memory arithmetic: the request covers the
// guest plus the VMM's baseline overhead, the limit allows for growth.
func TestPoolPodResources(t *testing.T) {
	tests := []struct {
		name, memory, request, limit string
	}{
		{name: "default", request: "2560Mi", limit: "3Gi"},
		{name: "explicit", memory: "8Gi", request: "8704Mi", limit: "9Gi"},
		{name: "fractional", memory: "1500Mi", request: "2012Mi", limit: "2524Mi"},
	}
	e := newEnv(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := &v1.BlipPool{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: ns}, Spec: v1.BlipPoolSpec{CPUs: 1}}
			if tt.memory != "" {
				pool.Spec.Memory = resource.MustParse(tt.memory)
			}
			c := e.pool.podFor(pool, "p-x").Spec.Containers[0]
			request := c.Resources.Requests[corev1.ResourceMemory]
			limit := c.Resources.Limits[corev1.ResourceMemory]
			if got, want := request, resource.MustParse(tt.request); got.Cmp(want) != 0 {
				t.Errorf("memory request %v, want %v", got.String(), want.String())
			}
			if got, want := limit, resource.MustParse(tt.limit); got.Cmp(want) != 0 {
				t.Errorf("memory limit %v, want %v", got.String(), want.String())
			}
		})
	}
}

// TestPoolPodTerminationGrace keeps the pod alive past the runtime's 60s
// guest shutdown budget so shutdown is never cut short by SIGKILL.
func TestPoolPodTerminationGrace(t *testing.T) {
	const shutdownBudget = int64(60)
	e := newEnv(t)
	pool := &v1.BlipPool{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: ns}, Spec: v1.BlipPoolSpec{CPUs: 1}}
	grace := e.pool.podFor(pool, "p-x").Spec.TerminationGracePeriodSeconds
	if grace == nil {
		t.Fatal("no termination grace period")
	}
	if *grace <= shutdownBudget {
		t.Errorf("termination grace %ds, want more than %ds", *grace, shutdownBudget)
	}
	if *grace != terminationGracePeriod {
		t.Errorf("termination grace %d, want %d", *grace, terminationGracePeriod)
	}
}

func TestTemplateHashTracksPoolShape(t *testing.T) {
	base := func() *v1.BlipPool {
		return &v1.BlipPool{Spec: v1.BlipPoolSpec{
			Hypervisor: "kvm", CPUs: 2, Memory: resource.MustParse("2Gi"),
			ServiceAccountName: "vm", NodeSelector: map[string]string{"zone": "a", "rack": "r1"},
		}}
	}
	ref := templateHash(base())
	if got := templateHash(base()); got != ref {
		t.Fatalf("hash is not stable: %q != %q", got, ref)
	}
	mutations := []struct {
		name   string
		mutate func(*v1.BlipPool)
	}{
		{"cpus", func(p *v1.BlipPool) { p.Spec.CPUs = 4 }},
		{"memory", func(p *v1.BlipPool) { p.Spec.Memory = resource.MustParse("4Gi") }},
		{"hypervisor", func(p *v1.BlipPool) { p.Spec.Hypervisor = "other" }},
		{"service account", func(p *v1.BlipPool) { p.Spec.ServiceAccountName = "other" }},
		{"node selector", func(p *v1.BlipPool) { p.Spec.NodeSelector["zone"] = "b" }},
		{"tolerations", func(p *v1.BlipPool) {
			p.Spec.Tolerations = []corev1.Toleration{{Key: "blip", Operator: corev1.TolerationOpExists}}
		}},
		{"image pull secrets", func(p *v1.BlipPool) {
			p.Spec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: "reg"}}
		}},
	}
	for _, m := range mutations {
		p := base()
		m.mutate(p)
		if templateHash(p) == ref {
			t.Errorf("%s does not change the template hash", m.name)
		}
	}
}

func TestTemplateHashIgnoresMutableNetwork(t *testing.T) {
	pool := &v1.BlipPool{}
	before := templateHash(pool)
	pool.Spec.Network = &v1.NetworkPolicy{Egress: []v1.NetworkEgressRule{{}}}
	if templateHash(pool) != before {
		t.Error("network changes must be reconciled in place, not replace warm VMs")
	}
}

func TestPoolReplacesLegacyTopology(t *testing.T) {
	e := newEnv(t)
	e.newPool("default", 1, 0)
	pool := e.getPool("default")
	// Hash generated by the pre-sidecar template for this unchanged pool.
	const legacyHash = "35baaef82aa3b469"
	if templateHash(pool) == legacyHash {
		t.Fatal("template hash does not version the new pod topology")
	}
	old := e.pool.podFor(pool, "default-old")
	old.Annotations[annotationTemplateHash] = legacyHash
	old.Status.Phase = corev1.PodRunning
	old.Labels[LabelWarm] = "true"
	claimed := old.DeepCopy()
	claimed.Name = "default-claimed"
	claimed.Labels[LabelBlipUID] = "uid-claimed"
	e.create(old, claimed)
	e.run(e.pool, ns, "default")
	pods := e.pods()
	if len(pods) != 2 {
		t.Fatalf("want one claimed and one replacement warm VM, got %d", len(pods))
	}
	for _, p := range pods {
		switch p.Name {
		case old.Name:
			t.Error("legacy warm pod was retained")
		case claimed.Name:
			if p.Annotations[annotationTemplateHash] != legacyHash {
				t.Error("claimed legacy pod was changed")
			}
		default:
			if p.Annotations[annotationTemplateHash] != templateHash(pool) || !hasAPIProxyToken(&p) {
				t.Errorf("replacement is missing the new topology: %+v", p)
			}
		}
	}
}

// TestPoolReplacesStaleVacantPods checks that a pool spec change retires
// vacant pods but never touches a pod a Blip already claimed.
func TestPoolReplacesStaleVacantPods(t *testing.T) {
	e := newEnv(t)
	e.newPool("default", 2, 0)
	pool := e.getPool("default")

	old := e.pool.podFor(pool, "default-old")
	old.Annotations[annotationTemplateHash] = "stale"
	old.Status.Phase = corev1.PodRunning
	old.Labels[LabelWarm] = "true"
	claimed := e.pool.podFor(pool, "default-claimed")
	claimed.Annotations[annotationTemplateHash] = "stale"
	claimed.Labels[LabelBlipUID] = "uid-claimed"
	e.create(old, claimed)

	pool = e.getPool("default")
	pool.Spec.CPUs = 4
	e.must(e.c.Update(e.ctx, pool))

	e.run(e.pool, ns, "default")

	pods := e.pods()
	wantHash := templateHash(e.getPool("default"))
	vacant := 0
	for _, p := range pods {
		if p.Name == "default-old" {
			t.Errorf("stale vacant pod kept")
		}
		if p.Name == "default-claimed" {
			if p.Annotations[annotationTemplateHash] != "stale" || p.Labels[LabelBlipUID] != "uid-claimed" {
				t.Errorf("claimed pod changed: %v %v", p.Labels, p.Annotations)
			}
			continue
		}
		vacant++
		if got := p.Annotations[annotationTemplateHash]; got != wantHash {
			t.Errorf("pod %s hash %q, want %q", p.Name, got, wantHash)
		}
		if cpu := p.Spec.Containers[0].Resources.Requests[corev1.ResourceCPU]; cpu.Value() != 4 {
			t.Errorf("pod %s cpu %v", p.Name, cpu)
		}
	}
	if vacant != 2 {
		t.Errorf("%d vacant pods, want 2", vacant)
	}
}

// TestPoolMaxCountDemand caps the pool at maxCount even when several Blips
// ask for a VM and the pool cannot boot them all at once.
func TestPoolMaxCountDemand(t *testing.T) {
	e := newEnv(t)
	e.newPool("default", 0, 1)
	for i := range 3 {
		e.pendingBlip(fmt.Sprintf("b%d", i), withImage("reg/img:v1"))
	}

	e.run(e.pool, ns, "default")
	pods := e.pods()
	if len(pods) != 1 {
		t.Fatalf("%d pods, want 1", len(pods))
	}

	pods[0].Labels[LabelBlipUID] = "uid-b0"
	e.must(e.c.Update(e.ctx, &pods[0]))
	e.run(e.pool, ns, "default")
	if n := len(e.pods()); n != 1 {
		t.Errorf("%d pods after a claim, want 1", n)
	}
}

// TestPoolClaimDoesNotCreateDuplicate covers the claim race: a Blip's pod
// carries its UID before the Blip reconciler writes status.pod. The Blip must
// not count as demand again, or a burst of forks boots one extra VM each.
func TestPoolClaimDoesNotCreateDuplicate(t *testing.T) {
	e := newEnv(t)
	e.newPool("default", 1, 0)
	e.pendingBlip("b0", withImage("reg/img:v1"))

	e.run(e.pool, ns, "default")
	pods := e.pods()
	if len(pods) != 2 {
		t.Fatalf("%d pods, want 2 (one warm, one for b0)", len(pods))
	}
	uid := e.getBlip("b0").UID
	for i := range pods {
		if isVacant(&pods[i]) {
			pods[i].Labels[LabelBlipUID] = string(uid)
			e.must(e.c.Update(e.ctx, &pods[i]))
			break
		}
	}

	e.run(e.pool, ns, "default")
	if n := len(e.pods()); n != 2 {
		t.Errorf("%d pods after the claim, want 2", n)
	}
}

// TestPoolWarmSparesFollowRunningVMs checks that replacement warm pods land
// on nodes that already run a VM, where a fork can claim them at once instead
// of booting a VM on the critical path.
func TestPoolWarmSparesFollowRunningVMs(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 3, 0)
	pool := e.getPool("default")

	claimed := e.pool.podFor(pool, "default-claimed")
	claimed.Spec.NodeName = "n1"
	claimed.Status.Phase = corev1.PodRunning
	claimed.Labels[LabelBlipUID] = "uid-claimed"
	warm := e.pool.podFor(pool, "default-warm")
	warm.Spec.NodeName = "n2"
	warm.Status.Phase = corev1.PodRunning
	warm.Labels[LabelWarm] = "true"
	e.create(claimed, warm)

	e.run(e.pool, ns, "default")

	var onN1, onN2 int
	for _, p := range e.pods() {
		if !isVacant(&p) || p.DeletionTimestamp != nil || p.Name == "default-warm" || p.Name == "default-claimed" {
			continue
		}
		switch p.Annotations[AnnotationPinnedNode] {
		case "n1":
			onN1++
		case "n2":
			onN2++
		case "":
			t.Errorf("warm spare %s not placed on a running node", p.Name)
		}
	}
	// warmCount 3 with one spare already on n2: all spares move to the
	// active node n1, including the pre-existing one.
	if onN1 != 3 || onN2 != 0 {
		t.Errorf("spares on n1=%d n2=%d, want 3 and 0", onN1, onN2)
	}
}

// TestPoolPinsOnlyCopiedStates checks that a Blip whose data is an image
// state (held by every node) is not pinned to locality.node, while a copied
// state (held by one source node) is.
func TestPoolPinsOnlyCopiedStates(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 0, 0)
	e.newState("img", func(s *v1.BlipState) { s.Spec.Image = "reg/img:v1"; s.Spec.Replicas = 0 })
	e.newState("copy", func(s *v1.BlipState) { s.Spec.CopyFrom = "img"; s.Spec.Replicas = 1 })

	for name, state := range map[string]string{"b0": "img", "b1": "copy"} {
		e.newBlip(name, func(b *v1.Blip) { b.Spec.State = state; b.Spec.Image = "" })
		e.setBlipStatus(name, func(b *v1.Blip) {
			b.Status.Phase = v1.BlipPending
			b.Status.Locality = &v1.Locality{Node: "n1"}
		})
	}

	e.run(e.pool, ns, "default")
	pods := e.pods()
	if len(pods) != 2 {
		t.Fatalf("%d pods, want 2", len(pods))
	}
	pinned := 0
	for _, p := range pods {
		if p.Annotations[AnnotationPinnedNode] != "" {
			pinned++
		}
	}
	if pinned != 1 {
		t.Errorf("%d pods pinned, want only the copied state's VM", pinned)
	}
}

// TestPoolMaxCountCapsWarmCount checks that a pool edited below its warm
// count does not keep more vacant VMs than maxCount allows.
func TestPoolMaxCountCapsWarmCount(t *testing.T) {
	e := newEnv(t)
	e.newPool("default", 4, 2)
	e.run(e.pool, ns, "default")
	if n := len(e.pods()); n != 2 {
		t.Errorf("%d pods, want maxCount 2", n)
	}
}

// TestPoolDemand checks that only Blips that can use this pool create
// demand: finished, running, deleting, and foreign Blips must not.
func TestPoolDemand(t *testing.T) {
	e := newEnv(t)
	e.newPool("default", 0, 0)

	e.pendingBlip("waiting", withImage("reg/img:v1"))

	// A new Blip has no phase until the Blip reconciler observes it; it is
	// pending and still needs a VM.
	e.newBlip("fresh", withImage("reg/img:v1"))

	e.newBlip("running", withImage("reg/img:v1"))
	e.setBlipStatus("running", func(b *v1.Blip) {
		b.Status.Phase = v1.BlipRunning
		b.Status.Pod = "default-pod"
	})

	e.newBlip("succeeded", withImage("reg/img:v1"))
	e.setBlipStatus("succeeded", func(b *v1.Blip) { b.Status.Phase = v1.BlipSucceeded })

	e.newBlip("failed", withImage("reg/img:v1"))
	e.setBlipStatus("failed", func(b *v1.Blip) { b.Status.Phase = v1.BlipFailed })

	e.newBlip("foreign", withImage("reg/img:v1"), func(b *v1.Blip) { b.Spec.Pool = "gpu" })

	e.newBlip("deleting", withImage("reg/img:v1"))
	b := e.getBlip("deleting")
	b.Finalizers = []string{Finalizer}
	e.must(e.c.Update(e.ctx, b))
	e.setBlipStatus("deleting", func(b *v1.Blip) { b.Status.Phase = v1.BlipPending })
	e.must(e.c.Delete(e.ctx, b))

	e.run(e.pool, ns, "default")
	if n := len(e.pods()); n != 2 {
		t.Errorf("%d pods, want 2 for the waiting and new Blips", n)
	}
}

func (e *env) getPool(name string) *v1.BlipPool {
	e.t.Helper()
	pool := &v1.BlipPool{}
	e.must(e.c.Get(e.ctx, types.NamespacedName{Namespace: ns, Name: name}, pool))
	return pool
}

// pendingBlip creates a Blip that waits for a VM; the pool only counts
// pending Blips as demand.
func (e *env) pendingBlip(name string, mutate ...func(*v1.Blip)) {
	e.t.Helper()
	e.newBlip(name, mutate...)
	e.setBlipStatus(name, func(b *v1.Blip) { b.Status.Phase = v1.BlipPending })
}

func (e *env) setBlipStatus(name string, mutate func(b *v1.Blip)) {
	e.t.Helper()
	b := e.getBlip(name)
	mutate(b)
	e.must(e.c.Status().Update(e.ctx, b))
}
