package controller

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"

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
					p.Labels[v1.LabelWarm] = "true"
				}
				if ps.claimed {
					p.Labels[v1.LabelBlipUID] = fmt.Sprintf("uid-%d", i)
				}
				e.create(p)
			}
			for i := range tt.demand {
				e.pendingBlip(fmt.Sprintf("b%d", i), e.withImage("reg/img:v1"))
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

// TestPoolReapsTerminatedClaimedPods covers a finished claimed VM whose Blip
// is stuck: the pod must stop consuming maxCount so the pool can boot the next
// VM, and it must be deleted once its exit status is recorded.
func TestPoolReapsTerminatedClaimedPods(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 1)

	e.newBlip("stuck")
	e.setBlipStatus("stuck", func(b *v1.Blip) { b.Status.Phase = v1.BlipSaving })
	stuck := e.getBlip("stuck")
	stuck.Finalizers = []string{v1.Finalizer}
	e.must(e.c.Update(e.ctx, stuck))
	e.must(e.c.Delete(e.ctx, stuck))
	stuck = e.getBlip("stuck")
	e.pendingBlip("next", e.withImage("reg/img:v1"))

	pool := e.getPool("default")
	done := e.pool.podFor(pool, "default-done")
	done.Spec.NodeName = "n1"
	done.Labels[v1.LabelBlipUID] = string(stuck.UID)
	done.Status.Phase = corev1.PodSucceeded
	e.create(done)

	e.run(e.pool, ns, "default")
	if !e.podGone(done.Name) {
		t.Errorf("captured terminated claimed pod %s not reaped", done.Name)
	}
	if n := len(e.pods()); n != 1 {
		t.Errorf("%d pods, want the replacement VM for the waiting Blip", n)
	}
	if got := e.getPool("default").Status.Claimed; got != 0 {
		t.Errorf("terminated pod counted as claimed: %d", got)
	}
}

// TestPoolDoesNotReapBeforeStatusCapture keeps a terminated claimed pod whose
// Blip is still Running, so its exit status and output can be copied, but no
// longer counts it against maxCount.
func TestPoolDoesNotReapBeforeStatusCapture(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 1)

	e.newBlip("live")
	e.setBlipStatus("live", func(b *v1.Blip) {
		b.Status.Phase = v1.BlipRunning
		b.Status.Pod = "default-live"
	})
	live := e.getBlip("live")
	e.pendingBlip("next", e.withImage("reg/img:v1"))

	pool := e.getPool("default")
	done := e.pool.podFor(pool, "default-live")
	done.Spec.NodeName = "n1"
	done.Labels[v1.LabelBlipUID] = string(live.UID)
	done.Status.Phase = corev1.PodSucceeded
	done.Status.ContainerStatuses = []corev1.ContainerStatus{{
		Name: podapi.VMContainer,
		State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
			FinishedAt: metav1.NewTime(e.now),
		}},
	}}
	e.create(done)

	e.run(e.pool, ns, "default")
	if e.podGone(done.Name) {
		t.Fatal("pod reaped before its Blip captured the exit status")
	}
	if n := len(e.pods()); n != 2 {
		t.Fatalf("%d pods, want the terminated pod kept and a replacement booted", n)
	}

	e.setBlipStatus("live", func(b *v1.Blip) { b.Status.Phase = v1.BlipSaving })
	e.run(e.pool, ns, "default")
	if e.podGone(done.Name) {
		t.Fatal("pod reaped before podReapGrace after its Blip captured the exit status")
	}

	e.now = e.now.Add(podReapGrace + time.Second)
	e.heartbeat()
	e.run(e.pool, ns, "default")
	if !e.podGone(done.Name) {
		t.Fatal("pod not reaped after podReapGrace")
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
		p.Labels[v1.LabelWarm] = "true"
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

// TestPoolRetiresCapacityOnStaleNodes reproduces the stale-node capacity bug:
// a warm pod on a node whose agent stopped heartbeating is not claimable by
// any Blip, but the pool counted it, booted no replacement, and reported it as
// Ready/Vacant. The replacement must avoid the dead node and serve demand.
func TestPoolRetiresCapacityOnStaleNodes(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 2, 0)
	e.run(e.pool, ns, "default")
	e.warmOn("n1", "n2")

	// n2's agent dies: its heartbeat goes stale while its warm pod remains.
	e.now = e.now.Add(5 * time.Minute)
	e.heartbeat("n2")

	e.pendingBlip("b1", e.withImage("reg/img:v1"))
	e.pendingBlip("b2", e.withImage("reg/img:v1"))
	e.run(e.pool, ns, "default")

	status := e.getPool("default").Status
	if status.Ready != 1 || status.Claimed != 0 {
		t.Fatalf("pool status counts the stale node's capacity: %+v", status)
	}
	if live := int32(len(e.pods())); status.Vacant != live {
		t.Errorf("pool status vacant %d, want %d live pods", status.Vacant, live)
	}
	replacements := 0
	for _, p := range e.pods() {
		if p.Spec.NodeName == "n2" || p.Annotations[v1.AnnotationPinnedNode] == "n2" {
			t.Fatalf("pod %s still targets stale node n2", p.Name)
		}
		if p.Spec.NodeName != "" {
			continue
		}
		replacements++
		aff := p.Spec.Affinity
		if aff == nil || aff.NodeAffinity == nil || aff.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution == nil {
			t.Fatalf("replacement %s has no node affinity: %+v", p.Name, aff)
		}
		req := aff.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms[0].MatchFields[0]
		if req.Operator != corev1.NodeSelectorOpNotIn || !slices.Contains(req.Values, "n2") {
			t.Errorf("replacement %s may be scheduled on stale n2: %+v", p.Name, req)
		}
	}
	if replacements == 0 {
		t.Fatal("no replacement for the warm pod on the stale node")
	}

	// b1 claims the healthy warm VM; b2 needs one of the replacements.
	e.run(e.blip, ns, "b1")
	if b := e.getBlip("b1"); b.Status.Phase != v1.BlipRunning || b.Status.Node != "n1" {
		t.Fatalf("b1: phase=%s node=%q msg=%s", b.Status.Phase, b.Status.Node, b.Status.Message)
	}
	// Play the scheduler: the only healthy node schedules the replacements.
	e.warmOn("n1", "n1", "n1")
	e.run(e.blip, ns, "b2")
	b2 := e.getBlip("b2")
	if b2.Status.Phase != v1.BlipRunning || b2.Status.Node != "n1" {
		t.Fatalf("b2: phase=%s node=%q msg=%s", b2.Status.Phase, b2.Status.Node, b2.Status.Message)
	}
}

// TestAuditPoolChurnAtWarmZero reproduces the shrink+relocate interaction: a
// warmCount=0 pool deletes its spares, then relocation acted on the same
// stale vacancy entries and booted fresh spares on the hot node. Pods deleted
// in this pass must not be relocated, and relocation must respect maxCount.
func TestAuditPoolChurnAtWarmZero(t *testing.T) {
	for _, maxCount := range []int32{0, 2} {
		t.Run(fmt.Sprintf("maxCount=%d", maxCount), func(t *testing.T) {
			e := newEnv(t)
			e.addNodes("n1", "n2")
			e.newPool("default", 0, maxCount)
			pool := e.getPool("default")

			claimed := e.pool.podFor(pool, "default-claimed")
			claimed.Spec.NodeName = "n1"
			claimed.Status.Phase = corev1.PodRunning
			claimed.Labels[v1.LabelBlipUID] = "uid-claimed"
			spare := e.pool.podFor(pool, "default-spare1")
			spare.Spec.NodeName = "n2"
			spare.Status.Phase = corev1.PodRunning
			spare.Labels[v1.LabelWarm] = "true"
			spare2 := spare.DeepCopy()
			spare2.Name = "default-spare2"
			e.create(claimed, spare, spare2)

			for pass := range 3 {
				e.run(e.pool, ns, "default")
				live := 0
				for _, p := range e.pods() {
					if p.DeletionTimestamp != nil {
						continue
					}
					live++
					if isVacant(&p) {
						t.Fatalf("pass %d: shrink+relocate re-created spare %s", pass, p.Name)
					}
				}
				if maxCount > 0 && live > int(maxCount) {
					t.Fatalf("pass %d: %d live pods exceed maxCount %d", pass, live, maxCount)
				}
			}
		})
	}
}

func TestPoolPodSpec(t *testing.T) {
	e := newEnv(t)
	e.create(&v1.BlipPool{
		ObjectMeta: metadata("big"),
		Spec: v1.BlipPoolSpec{
			Hypervisor: "kvm", CPUs: 4, Memory: resource.MustParse("8Gi"), WarmCount: 1,
			ServiceAccountName: "agent", NodeSelector: map[string]string{"zone": "a"},
			Tolerations:      []corev1.Toleration{{Key: "blip", Operator: corev1.TolerationOpExists}},
			ImagePullSecrets: []corev1.LocalObjectReference{{Name: "regcred"}},
		},
	})
	e.run(e.pool, ns, "big")
	pods := e.pods()
	if len(pods) != 1 {
		t.Fatalf("%d pods", len(pods))
	}
	p := pods[0]
	if len(p.Name) != len("big-")+5 || p.Labels[v1.LabelPool] != "big" || p.Labels[v1.LabelBlipUID] != "" {
		t.Errorf("name/labels: %s %v", p.Name, p.Labels)
	}
	if ref := p.OwnerReferences; len(ref) != 1 || ref[0].Kind != "BlipPool" || ref[0].Controller == nil || !*ref[0].Controller {
		t.Errorf("owner %+v", ref)
	}
	pool := e.getPool("big")
	if got := p.Annotations[v1.AnnotationTemplateHash]; got == "" || got != templateHash(pool, e.pool.RuntimeImage) {
		t.Errorf("template hash %q, want %q", got, templateHash(pool, e.pool.RuntimeImage))
	}
	s := p.Spec
	if s.RestartPolicy != corev1.RestartPolicyNever || s.ServiceAccountName != "agent" || len(s.Tolerations) != 1 {
		t.Errorf("spec %+v", s)
	}
	if s.AutomountServiceAccountToken == nil || *s.AutomountServiceAccountToken {
		t.Errorf("service account token automounted: %v", s.AutomountServiceAccountToken)
	}
	if len(s.ImagePullSecrets) != 1 || s.ImagePullSecrets[0].Name != "regcred" {
		t.Errorf("image pull secrets %+v", s.ImagePullSecrets)
	}
	if s.NodeSelector["zone"] != "a" || s.NodeSelector[v1.LabelEnrolled] != "true" ||
		s.NodeSelector[v1.LabelHypervisorPrefix+"kvm"] != "true" {
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
			if len(proxy.Env) != 3 {
				t.Fatalf("proxy should carry its trusted identity and API mode: %+v", proxy.Env)
			}
			wantProxyEnv := map[string]string{"POD_NAME": "metadata.name", "POD_NAMESPACE": "metadata.namespace"}
			kubeAPI := ""
			for _, env := range proxy.Env {
				if env.Name == kubeAPIEnv {
					kubeAPI = env.Value
					continue
				}
				if env.Value != "" || env.ValueFrom == nil || env.ValueFrom.FieldRef == nil ||
					env.ValueFrom.FieldRef.FieldPath != wantProxyEnv[env.Name] {
					t.Errorf("proxy identity must come from the DownwardAPI: %+v", env)
				}
				delete(wantProxyEnv, env.Name)
			}
			if len(wantProxyEnv) != 0 {
				t.Errorf("missing proxy identity env: %v", wantProxyEnv)
			}
			if kubeAPI != "1" {
				t.Errorf("proxy API mode = %q, want 1", kubeAPI)
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

func envValue(c corev1.Container, name string) string {
	for _, env := range c.Env {
		if env.Name == name {
			return env.Value
		}
	}
	return ""
}

// TestPoolPodEndpoints checks the sidecar an endpoint-only pool gets: no API
// credentials, a projection per endpoint that needs one, and only hostnames in
// the guest.
func TestPoolPodEndpoints(t *testing.T) {
	e := newEnv(t)
	pool := &v1.BlipPool{ObjectMeta: metadata("p"), Spec: v1.BlipPoolSpec{Endpoints: []v1.PoolEndpoint{
		{Name: "whoami", URL: "https://whoami.example.com", Audience: "blip-gateway", CAConfigMap: "whoami-ca"},
		{Name: "metrics", URL: "https://metrics.example.com:8443"},
		{Name: "ca-only", URL: "https://ca.example.com", CAConfigMap: "ca-only-ca"},
	}}}
	p := e.pool.podFor(pool, "p-vm")
	vm := p.Spec.Containers[0]
	if len(p.Spec.InitContainers) != 1 {
		t.Fatalf("want one native sidecar, got %+v", p.Spec.InitContainers)
	}
	proxy := p.Spec.InitContainers[0]
	if proxy.Name != apiProxyName || !slices.Equal(proxy.Command, []string{"blip-runtime", "api-proxy"}) {
		t.Errorf("API proxy invocation: %+v", proxy)
	}
	if got := envValue(vm, endpointNamesEnv); got != "whoami,metrics,ca-only" {
		t.Errorf("%s = %q, want whoami,metrics,ca-only", endpointNamesEnv, got)
	}
	if got := envValue(vm, endpointsEnv); got != "" {
		t.Errorf("guest received sidecar endpoint config: %q", got)
	}
	if got := envValue(proxy, kubeAPIEnv); got != "" {
		t.Errorf("endpoint-only pool enabled the Kubernetes API: %q", got)
	}
	for _, m := range vm.VolumeMounts {
		if strings.HasPrefix(m.Name, "endpoint-") {
			t.Errorf("guest mounts endpoint credentials: %+v", m)
		}
	}

	var got []proxyEndpoint
	if err := json.Unmarshal([]byte(envValue(proxy, endpointsEnv)), &got); err != nil {
		t.Fatalf("%s is not JSON: %v", endpointsEnv, err)
	}
	want := []proxyEndpoint{
		{Name: "whoami", URL: "https://whoami.example.com", TokenFile: endpointMountRoot + "/0/token", CAFile: endpointMountRoot + "/0/ca.crt"},
		{Name: "metrics", URL: "https://metrics.example.com:8443"},
		{Name: "ca-only", URL: "https://ca.example.com", CAFile: endpointMountRoot + "/2/ca.crt"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("%s = %+v, want %+v", endpointsEnv, got, want)
	}

	volumes := map[string]corev1.Volume{}
	for _, v := range p.Spec.Volumes {
		volumes[v.Name] = v
	}
	if _, ok := volumes[apiTokenVolume]; ok {
		t.Error("endpoint-only pool has an API token volume")
	}
	if _, ok := volumes["endpoint-1"]; ok {
		t.Error("metrics endpoint without credentials has a volume")
	}
	tokenAndCA := volumes["endpoint-0"].Projected
	if tokenAndCA == nil || len(tokenAndCA.Sources) != 2 {
		t.Fatalf("whoami projection: %+v", tokenAndCA)
	}
	if s := tokenAndCA.Sources[0].ServiceAccountToken; s == nil || s.Path != "token" ||
		s.Audience != "blip-gateway" || s.ExpirationSeconds == nil || *s.ExpirationSeconds != 3600 {
		t.Errorf("whoami token projection: %+v", s)
	}
	if s := tokenAndCA.Sources[1].ConfigMap; s == nil || s.Name != "whoami-ca" ||
		len(s.Items) != 1 || s.Items[0].Key != "ca.crt" || s.Items[0].Path != "ca.crt" {
		t.Errorf("whoami CA projection: %+v", s)
	}
	if ca := volumes["endpoint-2"].Projected; ca == nil || len(ca.Sources) != 1 ||
		ca.Sources[0].ConfigMap == nil || ca.Sources[0].ConfigMap.Name != "ca-only-ca" {
		t.Errorf("ca-only projection: %+v", ca)
	}
	if !mounted(proxy, "endpoint-0", endpointMountRoot+"/0", true) {
		t.Errorf("sidecar does not mount endpoint 0: %+v", proxy.VolumeMounts)
	}
	if !mounted(proxy, "endpoint-2", endpointMountRoot+"/2", true) {
		t.Errorf("sidecar does not mount endpoint 2: %+v", proxy.VolumeMounts)
	}
	if mounted(proxy, "endpoint-1", endpointMountRoot+"/1") {
		t.Errorf("sidecar mounts credential-free endpoint 1: %+v", proxy.VolumeMounts)
	}
}

// TestPoolPodEndpointsWithServiceAccount keeps the API credential alongside
// endpoint credentials.
func TestPoolPodEndpointsWithServiceAccount(t *testing.T) {
	e := newEnv(t)
	pool := &v1.BlipPool{ObjectMeta: metadata("p"), Spec: v1.BlipPoolSpec{
		ServiceAccountName: "agent",
		Endpoints:          []v1.PoolEndpoint{{Name: "whoami", URL: "https://whoami.example.com"}},
	}}
	p := e.pool.podFor(pool, "p-vm")
	vm, proxy := p.Spec.Containers[0], p.Spec.InitContainers[0]
	if got := envValue(proxy, kubeAPIEnv); got != "1" {
		t.Errorf("%s = %q, want 1", kubeAPIEnv, got)
	}
	if !mounted(proxy, apiTokenVolume, serviceAccountPath, true) {
		t.Errorf("sidecar does not mount the API token: %+v", proxy.VolumeMounts)
	}
	if !slices.ContainsFunc(vm.Env, func(env corev1.EnvVar) bool {
		return env.Name == "BLIP_KUBE_NAMESPACE" && env.ValueFrom != nil &&
			env.ValueFrom.FieldRef != nil && env.ValueFrom.FieldRef.FieldPath == "metadata.namespace"
	}) {
		t.Errorf("runtime has no namespace env: %+v", vm.Env)
	}
	if got := envValue(proxy, endpointsEnv); got == "" {
		t.Error("sidecar has no endpoint config")
	}
}

// TestPoolRejectsInvalidEndpoints checks that a bad endpoint fails reconcile
// before any warm pod exists and surfaces the reason in pool status. Admission
// normally rejects these, but a controller-side validation error must not leave
// empty status while Blips wait for a VM that can never exist.
func TestPoolRejectsInvalidEndpoints(t *testing.T) {
	for _, tt := range []struct {
		name     string
		endpoint v1.PoolEndpoint
		want     string
	}{
		{"bad url", v1.PoolEndpoint{Name: "whoami", URL: "http://whoami.example.com"}, "must use https"},
		{"reserved name", v1.PoolEndpoint{Name: "blip", URL: "https://whoami.example.com"}, "name is reserved"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			e.newPool("default", 1, 0)
			e.updatePool("default", func(p *v1.BlipPool) {
				p.Spec.Endpoints = []v1.PoolEndpoint{tt.endpoint}
			})
			_, err := e.pool.Reconcile(e.ctx, req(ns, "default"))
			if err == nil || !strings.Contains(err.Error(), "invalid endpoints for pool ns/default") {
				t.Fatalf("reconcile error %v", err)
			}
			if n := len(e.pods()); n != 0 {
				t.Errorf("%d pods created for an invalid pool", n)
			}
			pool := e.getPool("default")
			if pool.Status.Reason != poolInvalidConfiguration {
				t.Errorf("status reason %q, want %s", pool.Status.Reason, poolInvalidConfiguration)
			}
			if !strings.Contains(pool.Status.Message, tt.want) {
				t.Errorf("status message %q does not contain %q", pool.Status.Message, tt.want)
			}
		})
	}
}

func TestTemplateHashTracksEndpoints(t *testing.T) {
	pool := func(endpoints ...v1.PoolEndpoint) *v1.BlipPool {
		return &v1.BlipPool{Spec: v1.BlipPoolSpec{Endpoints: endpoints}}
	}
	whoami := v1.PoolEndpoint{Name: "whoami", URL: "https://whoami.example.com"}
	ref := templateHash(pool(whoami), runtimeImage)
	if got := templateHash(pool(whoami), runtimeImage); got != ref {
		t.Fatalf("hash is not stable: %q != %q", got, ref)
	}
	mutations := []struct {
		name string
		pool *v1.BlipPool
	}{
		{"name", pool(v1.PoolEndpoint{Name: "other", URL: whoami.URL})},
		{"url", pool(v1.PoolEndpoint{Name: whoami.Name, URL: "https://other.example.com"})},
		{"audience", pool(v1.PoolEndpoint{Name: whoami.Name, URL: whoami.URL, Audience: "blip-gateway"})},
		{"ca configmap", pool(v1.PoolEndpoint{Name: whoami.Name, URL: whoami.URL, CAConfigMap: "whoami-ca"})},
		{"added endpoint", pool(whoami, v1.PoolEndpoint{Name: "metrics", URL: "https://metrics.example.com"})},
	}
	for _, m := range mutations {
		if templateHash(m.pool, runtimeImage) == ref {
			t.Errorf("%s does not change the template hash", m.name)
		}
	}
}

// mounted reports whether c mounts name at path. With readOnly set, the mount
// mode must match too.
func mounted(c corev1.Container, name, path string, readOnly ...bool) bool {
	return slices.ContainsFunc(c.VolumeMounts, func(m corev1.VolumeMount) bool {
		return m.Name == name && m.MountPath == path && (len(readOnly) == 0 || m.ReadOnly == readOnly[0])
	})
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
	ref := templateHash(base(), runtimeImage)
	if got := templateHash(base(), runtimeImage); got != ref {
		t.Fatalf("hash is not stable: %q != %q", got, ref)
	}
	// The runtime image comes from the controller, not the pool spec, but it
	// decides which guest binaries boot in a warm VM.
	if got := templateHash(base(), "reg/blip-runtime:other"); got == ref {
		t.Error("runtime image does not change the template hash")
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
		if templateHash(p, runtimeImage) == ref {
			t.Errorf("%s does not change the template hash", m.name)
		}
	}
}

func TestTemplateHashIgnoresMutableNetwork(t *testing.T) {
	pool := &v1.BlipPool{}
	before := templateHash(pool, runtimeImage)
	pool.Spec.Network = &v1.NetworkPolicy{Egress: []v1.NetworkEgressRule{{}}}
	if templateHash(pool, runtimeImage) != before {
		t.Error("network changes must be reconciled in place, not replace warm VMs")
	}
}

func TestPoolReplacesLegacyTopology(t *testing.T) {
	e := newEnv(t)
	e.newPool("default", 1, 0)
	pool := e.getPool("default")
	// Hash generated by the pre-sidecar template for this unchanged pool.
	const legacyHash = "35baaef82aa3b469"
	if templateHash(pool, e.pool.RuntimeImage) == legacyHash {
		t.Fatal("template hash does not version the new pod topology")
	}
	old := e.pool.podFor(pool, "default-old")
	old.Annotations[v1.AnnotationTemplateHash] = legacyHash
	old.Status.Phase = corev1.PodRunning
	old.Labels[v1.LabelWarm] = "true"
	claimed := old.DeepCopy()
	claimed.Name = "default-claimed"
	claimed.Labels[v1.LabelBlipUID] = "uid-claimed"
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
			if p.Annotations[v1.AnnotationTemplateHash] != legacyHash {
				t.Error("claimed legacy pod was changed")
			}
		default:
			if p.Annotations[v1.AnnotationTemplateHash] != templateHash(pool, e.pool.RuntimeImage) || !hasAPIProxyToken(&p) {
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
	old.Annotations[v1.AnnotationTemplateHash] = "stale"
	old.Status.Phase = corev1.PodRunning
	old.Labels[v1.LabelWarm] = "true"
	claimed := e.pool.podFor(pool, "default-claimed")
	claimed.Annotations[v1.AnnotationTemplateHash] = "stale"
	claimed.Labels[v1.LabelBlipUID] = "uid-claimed"
	e.create(old, claimed)

	pool = e.getPool("default")
	pool.Spec.CPUs = 4
	e.must(e.c.Update(e.ctx, pool))

	e.run(e.pool, ns, "default")

	pods := e.pods()
	wantHash := templateHash(e.getPool("default"), e.pool.RuntimeImage)
	vacant := 0
	for _, p := range pods {
		if p.Name == "default-old" {
			t.Errorf("stale vacant pod kept")
		}
		if p.Name == "default-claimed" {
			if p.Annotations[v1.AnnotationTemplateHash] != "stale" || p.Labels[v1.LabelBlipUID] != "uid-claimed" {
				t.Errorf("claimed pod changed: %v %v", p.Labels, p.Annotations)
			}
			continue
		}
		vacant++
		if got := p.Annotations[v1.AnnotationTemplateHash]; got != wantHash {
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

// TestPoolReplacesStaleRuntimeImage reproduces the controller rollout bug:
// warm pods built by the previous controller kept the same template hash when
// the runtime image changed, so a claim could run the old guest binaries.
// Changing only the image must retire vacant pods and leave claimed ones.
func TestPoolReplacesStaleRuntimeImage(t *testing.T) {
	e := newEnv(t)
	e.newPool("default", 2, 0)
	pool := e.getPool("default")

	previous := &PoolReconciler{Client: e.c, Config: e.pool.Config}
	previous.RuntimeImage = "ghcr.io/azure/blip-runtime:b7e8d83edae9"
	stale := previous.podFor(pool, "default-stale")
	stale.Status.Phase = corev1.PodRunning
	stale.Labels[v1.LabelWarm] = "true"
	claimed := previous.podFor(pool, "default-claimed")
	claimed.Labels[v1.LabelBlipUID] = "uid-claimed"
	e.create(stale, claimed)

	wantHash := templateHash(pool, e.pool.RuntimeImage)
	if got := stale.Annotations[v1.AnnotationTemplateHash]; got == wantHash {
		t.Fatalf("old and new runtime images share hash %q", got)
	}

	e.run(e.pool, ns, "default")

	vacant := 0
	for _, p := range e.pods() {
		switch p.Name {
		case stale.Name:
			t.Error("vacant warm VM from the previous runtime image was kept")
		case claimed.Name:
			if p.Annotations[v1.AnnotationTemplateHash] == wantHash {
				t.Error("claimed pod was recreated by the runtime image change")
			}
		default:
			vacant++
			if p.Spec.Containers[0].Image != e.pool.RuntimeImage {
				t.Errorf("replacement %s runs image %q, want %q", p.Name, p.Spec.Containers[0].Image, e.pool.RuntimeImage)
			}
			if got := p.Annotations[v1.AnnotationTemplateHash]; got != wantHash {
				t.Errorf("replacement %s hash %q, want %q", p.Name, got, wantHash)
			}
		}
	}
	if vacant != 2 {
		t.Errorf("%d vacant replacement pods, want 2", vacant)
	}
}

// TestPoolMaxCountDemand caps the pool at maxCount even when several Blips
// ask for a VM and the pool cannot boot them all at once.
func TestPoolMaxCountDemand(t *testing.T) {
	e := newEnv(t)
	e.newPool("default", 0, 1)
	for i := range 3 {
		e.pendingBlip(fmt.Sprintf("b%d", i), e.withImage("reg/img:v1"))
	}

	e.run(e.pool, ns, "default")
	pods := e.pods()
	if len(pods) != 1 {
		t.Fatalf("%d pods, want 1", len(pods))
	}

	pods[0].Labels[v1.LabelBlipUID] = "uid-b0"
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
	e.pendingBlip("b0", e.withImage("reg/img:v1"))

	e.run(e.pool, ns, "default")
	pods := e.pods()
	if len(pods) != 2 {
		t.Fatalf("%d pods, want 2 (one warm, one for b0)", len(pods))
	}
	uid := e.getBlip("b0").UID
	for i := range pods {
		if isVacant(&pods[i]) {
			pods[i].Labels[v1.LabelBlipUID] = string(uid)
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
	claimed.Labels[v1.LabelBlipUID] = "uid-claimed"
	warm := e.pool.podFor(pool, "default-warm")
	warm.Spec.NodeName = "n2"
	warm.Status.Phase = corev1.PodRunning
	warm.Labels[v1.LabelWarm] = "true"
	e.create(claimed, warm)

	e.run(e.pool, ns, "default")

	var onN1, onN2 int
	for _, p := range e.pods() {
		if !isVacant(&p) || p.DeletionTimestamp != nil || p.Name == "default-warm" || p.Name == "default-claimed" {
			continue
		}
		switch p.Annotations[v1.AnnotationPinnedNode] {
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

// Copies of a shared image template each retain their own data locality.
func TestPoolPinsDurableCopiesOfSharedBase(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 0, 0)
	e.newState("img", func(s *v1.BlipState) { s.Spec.Image = "reg/img:v1"; s.Spec.Replicas = 0 })
	e.newState("copy0", func(s *v1.BlipState) { s.Spec.CopyFrom = "img"; s.Spec.Replicas = 1 })
	e.newState("copy1", func(s *v1.BlipState) { s.Spec.CopyFrom = "img"; s.Spec.Replicas = 1 })

	for name, state := range map[string]string{"b0": "copy0", "b1": "copy1"} {
		e.newBlip(name, withRoot(state))
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
		if p.Annotations[v1.AnnotationPinnedNode] != "" {
			pinned++
		}
	}
	if pinned != 2 {
		t.Errorf("%d pods pinned, want a local VM for each durable copy", pinned)
	}
}

// TestPoolMaxCountCapsWarmCount checks that a pool edited below its warm
// count does not keep more vacant VMs than maxCount allows.
func TestPoolMaxCountCapsWarmCount(t *testing.T) {
	t.Run("warm count over cap", func(t *testing.T) {
		e := newEnv(t)
		e.newPool("default", 4, 2)
		e.run(e.pool, ns, "default")
		if n := len(e.pods()); n != 2 {
			t.Errorf("%d pods, want maxCount 2", n)
		}
	})

	// Claimed VMs share the cap with vacant spares. Lowering maxCount below
	// claimed+warm must delete the surplus spares instead of keeping
	// maxCount of them in addition to every claimed VM.
	t.Run("claimed pod over cap", func(t *testing.T) {
		e := newEnv(t)
		e.addNodes("n1")
		e.newPool("default", 2, 2)
		pool := e.getPool("default")

		claimed := e.pool.podFor(pool, "default-claimed")
		claimed.Spec.NodeName = "n1"
		claimed.Status.Phase = corev1.PodRunning
		claimed.Labels[v1.LabelBlipUID] = "uid-claimed"
		e.create(claimed)
		for i := range 2 {
			p := e.pool.podFor(pool, fmt.Sprintf("default-spare-%d", i))
			p.Spec.NodeName = "n1"
			p.Status.Phase = corev1.PodRunning
			p.Labels[v1.LabelWarm] = "true"
			e.create(p)
		}

		e.run(e.pool, ns, "default")
		if n := len(e.pods()); n != 2 {
			t.Fatalf("%d pods, want 2 (one claimed plus one spare) within maxCount", n)
		}
		if e.podGone(claimed.Name) {
			t.Error("claimed VM deleted; the cap only removes vacant spares")
		}
		want := v1.BlipPoolStatus{Ready: 1, Vacant: 1, Claimed: 1}
		if got := e.getPool("default").Status; got != want {
			t.Errorf("status %+v, want %+v", got, want)
		}
	})
}

// TestPoolDemand checks that only Blips that can use this pool create
// demand: finished, running, deleting, and foreign Blips must not.
func TestPoolDemand(t *testing.T) {
	e := newEnv(t)
	e.newPool("default", 0, 0)

	e.pendingBlip("waiting", e.withImage("reg/img:v1"))

	// A new Blip has no phase until the Blip reconciler observes it; it is
	// pending and still needs a VM.
	e.newBlip("fresh", e.withImage("reg/img:v1"))

	e.newBlip("running", e.withImage("reg/img:v1"))
	e.setBlipStatus("running", func(b *v1.Blip) {
		b.Status.Phase = v1.BlipRunning
		b.Status.Pod = "default-pod"
	})

	e.newBlip("succeeded", e.withImage("reg/img:v1"))
	e.setBlipStatus("succeeded", func(b *v1.Blip) { b.Status.Phase = v1.BlipSucceeded })

	e.newBlip("failed", e.withImage("reg/img:v1"))
	e.setBlipStatus("failed", func(b *v1.Blip) { b.Status.Phase = v1.BlipFailed })

	e.newBlip("foreign", e.withImage("reg/img:v1"), func(b *v1.Blip) { b.Spec.Pool = "gpu" })

	e.newBlip("deleting", e.withImage("reg/img:v1"))
	b := e.getBlip("deleting")
	b.Finalizers = []string{v1.Finalizer}
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

func TestReadyRequiresPodReadyCondition(t *testing.T) {
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{v1.LabelWarm: "true"}}}
	p.Status.Phase = corev1.PodRunning
	if !ready(p) {
		t.Fatal("a warm running pod without a condition is not ready")
	}
	p.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionFalse, Reason: "ContainersNotReady"}}
	if ready(p) {
		t.Fatal("a warm pod with a failing sidecar is ready")
	}
	p.Status.Conditions[0].Status = corev1.ConditionTrue
	if !ready(p) {
		t.Fatal("a ready warm pod is not ready")
	}
	p.Status.Phase = corev1.PodPending
	if ready(p) {
		t.Fatal("a pending pod is ready")
	}
}

func TestBrokenSidecarIsNotReadyOrClaimable(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 1, 0)
	e.run(e.pool, ns, "default")
	e.warmOn("n1")
	pods := e.pods()
	if len(pods) != 1 {
		t.Fatalf("pods = %d, want 1", len(pods))
	}
	broken := pods[0]
	p := pods[0]
	p.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionFalse, Reason: "ContainersNotReady"}}
	e.must(e.c.Status().Update(e.ctx, &p))

	e.run(e.pool, ns, "default")
	if pool := e.getPool("default"); pool.Status.Ready != 0 || pool.Status.Vacant != 1 {
		t.Fatalf("pool status = %+v, want ready 0 vacant 1", pool.Status)
	}

	e.newBlip("b", e.withImage("reg/img:v1"))
	e.run(e.blip, ns, "b")
	b := e.getBlip("b")
	if b.Status.Pod != "" || b.Status.Phase != v1.BlipPending {
		t.Fatalf("blip claimed a pod with a broken sidecar: phase %s pod %q", b.Status.Phase, b.Status.Pod)
	}

	// The unready spare cannot satisfy the waiting Blip, so it must not
	// suppress the replacement the uncapped pool can boot.
	e.run(e.pool, ns, "default")
	pods = e.pods()
	if len(pods) != 2 {
		t.Fatalf("%d pods, want the broken spare and a replacement: %+v", len(pods), pods)
	}
	if pool := e.getPool("default"); pool.Status.Ready != 0 || pool.Status.Vacant != 2 {
		t.Fatalf("pool status = %+v, want ready 0 vacant 2", pool.Status)
	}

	e.warmOn("n1")
	for _, p := range e.pods() {
		if p.Name != broken.Name && isVacant(&p) {
			e.observe(p.Name, podapi.Observed{Phase: podapi.PhaseWarm})
		}
	}
	e.run(e.blip, ns, "b")
	b = e.getBlip("b")
	if b.Status.Pod == "" || b.Status.Pod == broken.Name {
		t.Fatalf("blip did not claim the replacement: pod %q", b.Status.Pod)
	}
	expectPhase(t, b, v1.BlipPending, ReasonStarting)
}

// TestPoolRetiresPermanentlyNotReadySpare covers a spare that never becomes
// ready in a capped pool: it consumed the only maxCount slot, so a waiting
// Blip starved until pendingTimeout. After the warming budget the pool must
// retire it and boot a replacement.
func TestPoolRetiresPermanentlyNotReadySpare(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1", "n2")
	e.newPool("default", 1, 1)
	e.run(e.pool, ns, "default")
	e.warmOn("n1")
	pods := e.pods()
	if len(pods) != 1 {
		t.Fatalf("%d pods, want one spare", len(pods))
	}
	stale := pods[0]
	p := pods[0]
	p.Status.Conditions = []corev1.PodCondition{{
		Type: corev1.PodReady, Status: corev1.ConditionFalse, Reason: "ContainersNotReady",
		LastTransitionTime: metav1.NewTime(e.now.Add(-warmTimeout - time.Minute)),
	}}
	e.must(e.c.Status().Update(e.ctx, &p))

	e.run(e.pool, ns, "default")
	pods = e.pods()
	if len(pods) != 1 {
		t.Fatalf("%d pods, want one replacement within maxCount=1: %+v", len(pods), pods)
	}
	if pods[0].Name == stale.Name || !isVacant(&pods[0]) {
		t.Fatalf("stale not-ready spare still holds the slot: %+v", pods[0])
	}
	e.run(e.pool, ns, "default")
	if n := len(e.pods()); n != 1 {
		t.Fatalf("%d pods after the replacement, want no churn", n)
	}
}

// TestPoolNegativeMemoryIsInvalid guards that a pool with negative guest memory
// reports InvalidConfiguration and an Event instead of retrying a Pod create
// forever with empty status. Admission rejects the value; the controller check
// covers objects stored before that rule existed.
func TestPoolNegativeMemoryIsInvalid(t *testing.T) {
	e := newEnv(t)
	e.newPool("default", 1, 0)
	e.updatePool("default", func(p *v1.BlipPool) { p.Spec.Memory = resource.MustParse("-1Gi") })
	recorder := record.NewFakeRecorder(10)
	e.pool.Recorder = recorder

	_, err := e.pool.Reconcile(e.ctx, req(ns, "default"))
	if err == nil || !strings.Contains(err.Error(), "spec.memory must be greater than 0") {
		t.Fatalf("reconcile error %v, want a memory validation error", err)
	}
	event := waitForEvent(t, recorder)
	if !strings.Contains(event, corev1.EventTypeWarning+" InvalidConfiguration") {
		t.Errorf("event = %q, want a Warning InvalidConfiguration event", event)
	}
	pool := e.getPool("default")
	if pool.Status.Reason != poolInvalidConfiguration {
		t.Errorf("status reason %q, want %s", pool.Status.Reason, poolInvalidConfiguration)
	}
	if !strings.Contains(pool.Status.Message, "spec.memory must be greater than 0") {
		t.Errorf("status message %q does not report the memory problem", pool.Status.Message)
	}
	if n := len(e.pods()); n != 0 {
		t.Errorf("%d pods created for an invalid pool", n)
	}
}
