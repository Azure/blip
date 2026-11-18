package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"slices"
	"sort"
	"strconv"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	utilrand "k8s.io/apimachinery/pkg/util/rand"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/podapi"
)

// expectTimeout bounds how long a created or deleted pod that the cache does
// not reflect yet is accounted for.
const expectTimeout = time.Minute

const (
	// annotationTemplateHash records the VM shape a warm pod was created
	// from. A pool spec change leaves vacant pods with a stale hash, which
	// reconcile deletes so they are replaced with the new shape.
	annotationTemplateHash = "blip.dev/template-hash"
	// Bump when pod topology changes without a pool spec change, so warm
	// pods cannot retain the old credential or socket layout.
	podTopologyVersion = "api-proxy-v1"

	apiProxyName             = "api-proxy"
	apiTokenVolume           = "api-token"
	serviceAccountPath       = "/var/run/secrets/kubernetes.io/serviceaccount"
	vsockMountPath           = podapi.MountPath + "/vsock"
	apiProxyUID        int64 = 65532

	// terminationGracePeriod covers the runtime's 60s guest shutdown
	// budget, so the kubelet does not SIGKILL the VMM mid-shutdown.
	terminationGracePeriod = int64(90)

	defaultVMCPUs = int32(2)
)

var (
	defaultVMMemory = resource.MustParse("2Gi")
	// vmRequestOverhead is VMM memory above guest RAM. Features such as
	// swap, dirty page tracking, and the device model grow with RAM, which
	// is why the limit leaves more headroom than the request.
	vmRequestOverhead = resource.MustParse("512Mi")
	vmLimitOverhead   = resource.MustParse("1Gi")
)

// PoolReconciler keeps warm VM pods for each BlipPool.
type PoolReconciler struct {
	client.Client
	Config

	mu sync.Mutex
	// created and deleted hold pod names (per pool) whose change the
	// cache may not show yet.
	created map[types.NamespacedName]map[string]expectation
	deleted map[types.NamespacedName]map[string]expectation
}

type expectation struct {
	at time.Time
	// node is the node a created pod is pinned to.
	node string
}

func (r *PoolReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1.BlipPool{}).
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(func(_ context.Context, o client.Object) []reconcile.Request {
			if p := o.GetLabels()[LabelPool]; p != "" {
				return []reconcile.Request{req(o.GetNamespace(), p)}
			}
			return nil
		})).
		Watches(&v1.Blip{}, handler.EnqueueRequestsFromMapFunc(func(_ context.Context, o client.Object) []reconcile.Request {
			return []reconcile.Request{req(o.GetNamespace(), poolName(o.(*v1.Blip)))}
		})).
		Watches(&v1.BlipNode{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, _ client.Object) []reconcile.Request {
			var pools v1.BlipPoolList
			if err := r.List(ctx, &pools); err != nil {
				return nil
			}
			var out []reconcile.Request
			for _, p := range pools.Items {
				out = append(out, req(p.Namespace, p.Name))
			}
			return out
		}), builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&corev1.ConfigMap{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
			if o.GetName() != VMOwnersConfigMap {
				return nil
			}
			var pools v1.BlipPoolList
			if err := r.List(ctx, &pools, client.InNamespace(o.GetNamespace())); err != nil || len(pools.Items) == 0 {
				return nil
			}
			return []reconcile.Request{req(o.GetNamespace(), pools.Items[0].Name)}
		})).
		Named("blippool").
		WithOptions(controller.Options{MaxConcurrentReconciles: 2}).
		Complete(r)
}

func (r *PoolReconciler) Reconcile(ctx context.Context, rq reconcile.Request) (reconcile.Result, error) {
	if err := syncVMOwners(ctx, r.Client, rq.Namespace); err != nil {
		return reconcile.Result{}, err
	}
	pool := &v1.BlipPool{}
	if err := r.Get(ctx, rq.NamespacedName, pool); err != nil {
		if apierrors.IsNotFound(err) {
			r.mu.Lock()
			delete(r.created, rq.NamespacedName)
			delete(r.deleted, rq.NamespacedName)
			r.mu.Unlock()
		}
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	if pool.DeletionTimestamp != nil {
		return reconcile.Result{}, nil
	}
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(pool.Namespace), client.MatchingLabels{LabelPool: pool.Name}); err != nil {
		return reconcile.Result{}, err
	}
	var blips v1.BlipList
	if err := r.List(ctx, &blips, client.InNamespace(pool.Namespace), client.MatchingFields{indexPool: pool.Name}); err != nil {
		return reconcile.Result{}, err
	}
	// Image states are held by every eligible node, so a Blip whose data is
	// all image states can run anywhere. Pinning it to locality.node would
	// reserve a VM on one arbitrary node and waste warm slots on the node
	// where its sessions actually run.
	var states v1.BlipStateList
	if err := r.List(ctx, &states, client.InNamespace(pool.Namespace)); err != nil {
		return reconcile.Result{}, err
	}
	replicated := map[string]bool{}
	for i := range states.Items {
		if states.Items[i].Spec.Image != "" {
			replicated[states.Items[i].Name] = true
		}
	}
	draining, err := drainingNodes(ctx, r)
	if err != nil {
		return reconcile.Result{}, err
	}

	// claimed holds the Blips whose VM pod already exists, even if the Blip
	// reconciler has not written status.pod yet. Counting such a Blip as
	// demand while its claimed pod is no longer vacant creates a duplicate:
	// under a burst of forks the pool booted one extra VM per claim.
	claimed := map[types.UID]bool{}
	for i := range pods.Items {
		if uid := pods.Items[i].Labels[LabelBlipUID]; uid != "" {
			claimed[types.UID(uid)] = true
		}
	}
	demand := 0
	// deferred counts waiting Blips whose data node is not known yet. A
	// stateful Blip is usually created just before its state (a fork), so
	// booting a generic VM now and a pinned one a moment later would double
	// the pool. Wait for the locality the Blip reconciler writes with its
	// state.
	deferred := 0
	// pinned counts, per node, the waiting Blips whose data lives there.
	pinned := map[string]int{}
	for i := range blips.Items {
		b := &blips.Items[i]
		if !countsAsDemand(b, pool.Name) || claimed[b.UID] {
			continue
		}
		if hasDurableData(b) && b.Status.Locality == nil {
			deferred++
			continue
		}
		demand++
		if loc := b.Status.Locality; loc != nil && !loc.Fallback && loc.Node != "" && !draining[loc.Node] && !replicatedData(b, replicated) {
			pinned[loc.Node]++
		}
	}

	hash := templateHash(pool)
	created, createdOn, deleted := r.expectations(rq.NamespacedName, pods.Items)
	total := len(pods.Items) + created
	var vacant []*corev1.Pod
	var status v1.BlipPoolStatus
	// hot counts the nodes that run a claimed VM of this pool. Warm spares
	// are placed there first: a fork's data lives on the node its parent
	// runs on, so a warm VM there starts the fork without booting a VM on
	// the critical path.
	hot := map[string]int{}
	for i := range pods.Items {
		p := &pods.Items[i]
		switch {
		case !isVacant(p):
			if !podTerminated(p) {
				status.Claimed++
				if p.DeletionTimestamp == nil && p.Spec.NodeName != "" && !draining[p.Spec.NodeName] {
					hot[p.Spec.NodeName]++
				}
			}
		case p.DeletionTimestamp != nil || deleted[p.Name]:
		case podTerminated(p) || draining[podNode(p)] || p.Annotations[annotationTemplateHash] != hash:
			if err := r.deletePod(ctx, rq.NamespacedName, p); err != nil {
				return reconcile.Result{}, err
			}
		default:
			vacant = append(vacant, p)
			if ready(p) {
				status.Ready++
			}
		}
	}

	// Reserve vacant pods on each node for the Blips waiting there, ready
	// ones first, and note how many more that node needs.
	sort.SliceStable(vacant, func(i, j int) bool {
		if ready(vacant[i]) != ready(vacant[j]) {
			return ready(vacant[i])
		}
		return vacant[i].CreationTimestamp.Before(&vacant[j].CreationTimestamp)
	})
	reserved := map[string]bool{}
	short := map[string]int{}
	for _, node := range slices.Sorted(maps.Keys(pinned)) {
		need := pinned[node] - createdOn[node]
		for _, p := range vacant {
			if need > 0 && podNode(p) == node {
				reserved[p.Name] = true
				need--
			}
		}
		if need > 0 {
			short[node] = need
		}
	}
	// A pinned pod that cannot be scheduled and no longer serves a waiting
	// Blip only holds a slot.
	kept := vacant[:0]
	for _, p := range vacant {
		if !reserved[p.Name] && p.Annotations[AnnotationPinnedNode] != "" && unschedulable(p) {
			if err := r.deletePod(ctx, rq.NamespacedName, p); err != nil {
				return reconcile.Result{}, err
			}
			continue
		}
		kept = append(kept, p)
	}
	vacant = kept

	target := int(pool.Spec.WarmCount) + demand
	maxCount := int(pool.Spec.MaxCount)
	if maxCount > 0 {
		target = min(target, maxCount)
	}
	have := len(vacant) + created
	log.FromContext(ctx).V(1).Info("pool sizing", "demand", demand, "deferred", deferred, "claimed", len(claimed), "pinned", pinned, "vacant", len(vacant), "created", created, "target", target, "have", have, "total", total)
	room := func() bool { return maxCount <= 0 || total < maxCount }
	for _, node := range slices.Sorted(maps.Keys(short)) {
		for range short[node] {
			if !room() {
				break
			}
			if err := r.createPod(ctx, pool, draining, node); err != nil {
				return reconcile.Result{}, err
			}
			total++
			have++
		}
	}
	warm := map[string]int{}
	for _, p := range vacant {
		if !reserved[p.Name] {
			warm[podNode(p)]++
		}
	}
	for n, c := range createdOn {
		warm[n] += c
	}
	blocked := map[string]bool{}
	for i := range pods.Items {
		p := &pods.Items[i]
		if unschedulable(p) && p.Annotations[AnnotationPinnedNode] != "" {
			blocked[podNode(p)] = true
		}
	}
	if want := target - have; want > 0 {
		// If every waiting Blip can claim an existing warm VM, do not boot
		// replacements yet. The claim tells us which node is hot, and a
		// spare booted now would land on an arbitrary node and be moved
		// again. The claim wakes the pool, which then boots the replacement.
		if demand > 0 && len(vacant) >= demand {
			want = 0
		}
		for ; want > 0; want-- {
			if !room() {
				break
			}
			node := pickWarmNode(hot, warm, blocked)
			if err := r.createPod(ctx, pool, draining, node); err != nil {
				return reconcile.Result{}, err
			}
			total++
			have++
			if node != "" {
				warm[node]++
			}
		}
	} else {
		spare := slices.DeleteFunc(slices.Clone(vacant), func(p *corev1.Pod) bool { return reserved[p.Name] })
		// Delete booting pods before ready ones, newest first.
		sort.SliceStable(spare, func(i, j int) bool {
			if ready(spare[i]) != ready(spare[j]) {
				return !ready(spare[i])
			}
			return spare[j].CreationTimestamp.Before(&spare[i].CreationTimestamp)
		})
		for _, p := range spare[:max(0, min(have-target, len(spare)))] {
			if err := r.deletePod(ctx, rq.NamespacedName, p); err != nil {
				return reconcile.Result{}, err
			}
			have--
			warm[podNode(p)]--
		}
	}
	// A warm VM is only useful on a node that runs a VM: a fork's data
	// lives on the node its parent runs on. Move spares off idle nodes so
	// the next session claims a local VM instead of booting one.
	if len(hot) > 0 {
		spare := []*corev1.Pod{}
		for _, p := range vacant {
			if !reserved[p.Name] && p.DeletionTimestamp == nil && !deleted[p.Name] && hot[podNode(p)] == 0 {
				spare = append(spare, p)
			}
		}
		// Move booting pods before ready ones: a ready spare is more useful
		// even if it is remote, and booting ones are already cold.
		sort.SliceStable(spare, func(i, j int) bool {
			if ready(spare[i]) != ready(spare[j]) {
				return !ready(spare[i])
			}
			return spare[j].CreationTimestamp.Before(&spare[i].CreationTimestamp)
		})
		for _, p := range spare {
			node := pickWarmNode(hot, warm, blocked)
			if node == "" {
				break
			}
			if err := r.deletePod(ctx, rq.NamespacedName, p); err != nil {
				return reconcile.Result{}, err
			}
			warm[podNode(p)]--
			if err := r.createPod(ctx, pool, draining, node); err != nil {
				return reconcile.Result{}, err
			}
			warm[node]++
		}
	}
	status.Vacant = int32(have)

	if status != pool.Status {
		base := pool.DeepCopy()
		pool.Status = status
		if err := r.Status().Patch(ctx, pool, client.MergeFrom(base)); err != nil {
			return reconcile.Result{}, client.IgnoreNotFound(err)
		}
	}
	if deferred > 0 {
		// The Blip watch usually delivers the locality update first; this
		// is a safety net while a state is created or copied.
		return reconcile.Result{RequeueAfter: time.Second}, nil
	}
	return reconcile.Result{}, nil
}

func ready(p *corev1.Pod) bool {
	return p.Labels[LabelWarm] == "true" && p.Status.Phase == corev1.PodRunning && p.DeletionTimestamp == nil
}

// pickWarmNode picks the node where a warm spare is most useful: a node
// that already runs a VM of the pool and has the fewest warm pods there.
// Ties prefer the busiest node, then the name, so spares spread across
// active nodes but concentrate on one when it is the only active node.
func pickWarmNode(hot, warm map[string]int, blocked map[string]bool) string {
	best := ""
	for _, n := range slices.Sorted(maps.Keys(hot)) {
		if blocked[n] {
			continue
		}
		if best == "" || warm[n] < warm[best] || (warm[n] == warm[best] && hot[n] > hot[best]) {
			best = n
		}
	}
	return best
}

// countsAsDemand reports whether b is waiting for a VM from this pool. Blips
// that already have a pod, are going away, or have finished do not create
// demand: counting them would grow an uncapped pool without ever booting
// them. An empty phase means the Blip reconciler has not run yet; it is a new,
// pending Blip.
func countsAsDemand(b *v1.Blip, pool string) bool {
	phase := b.Status.Phase
	return poolName(b) == pool && (phase == "" || phase == v1.BlipPending) &&
		b.Status.Pod == "" && b.DeletionTimestamp == nil && !finished(b)
}

// expectations drops entries the cache now reflects and returns how many
// created pods are still missing from pods, how many of those are pinned to
// each node, and the names being deleted.
func (r *PoolReconciler) expectations(pool types.NamespacedName, pods []corev1.Pod) (int, map[string]int, map[string]bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	present := map[string]*corev1.Pod{}
	for i := range pods {
		present[pods[i].Name] = &pods[i]
	}
	now := time.Now()
	createdOn := map[string]int{}
	for name, x := range r.created[pool] {
		if present[name] != nil || now.Sub(x.at) > expectTimeout {
			delete(r.created[pool], name)
		} else if x.node != "" {
			createdOn[x.node]++
		}
	}
	deleted := map[string]bool{}
	for name, x := range r.deleted[pool] {
		if p := present[name]; p == nil || p.DeletionTimestamp != nil || now.Sub(x.at) > expectTimeout {
			delete(r.deleted[pool], name)
		} else {
			deleted[name] = true
		}
	}
	return len(r.created[pool]), createdOn, deleted
}

func (r *PoolReconciler) expect(m *map[types.NamespacedName]map[string]expectation, pool types.NamespacedName, name, node string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if *m == nil {
		*m = map[types.NamespacedName]map[string]expectation{}
	}
	if (*m)[pool] == nil {
		(*m)[pool] = map[string]expectation{}
	}
	(*m)[pool][name] = expectation{at: time.Now(), node: node}
}

// createPod creates a VM pod. A pod for a node is pinned to it; others avoid
// draining nodes.
func (r *PoolReconciler) createPod(ctx context.Context, pool *v1.BlipPool, draining map[string]bool, node string) error {
	pod := r.podFor(pool, pool.Name+"-"+utilrand.String(5))
	var match *corev1.NodeSelectorRequirement
	switch {
	case node != "":
		pod.Annotations[AnnotationPinnedNode] = node
		match = &corev1.NodeSelectorRequirement{Key: "metadata.name", Operator: corev1.NodeSelectorOpIn, Values: []string{node}}
	case len(draining) > 0:
		match = &corev1.NodeSelectorRequirement{Key: "metadata.name", Operator: corev1.NodeSelectorOpNotIn, Values: slices.Sorted(maps.Keys(draining))}
	}
	if match != nil {
		pod.Spec.Affinity = &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{{MatchFields: []corev1.NodeSelectorRequirement{*match}}},
			},
		}}
	}
	if err := r.Create(ctx, pod); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil
		}
		return err
	}
	log.FromContext(ctx).Info("created VM pod", "pod", pod.Name, "pinnedNode", node)
	r.expect(&r.created, client.ObjectKeyFromObject(pool), pod.Name, node)
	return nil
}

func (r *PoolReconciler) deletePod(ctx context.Context, pool types.NamespacedName, p *corev1.Pod) error {
	// The resourceVersion precondition loses against a concurrent claim.
	err := r.Delete(ctx, p, client.Preconditions{UID: &p.UID, ResourceVersion: &p.ResourceVersion})
	if err != nil && !apierrors.IsNotFound(err) && !apierrors.IsConflict(err) {
		return err
	}
	r.expect(&r.deleted, pool, p.Name, "")
	return nil
}

// podFor builds a VM pod (docs/ARCHITECTURE.md "VM pod").
func (r *PoolReconciler) podFor(pool *v1.BlipPool, name string) *corev1.Pod {
	cpus, memory, hypervisor := poolShape(pool)
	request := memory.DeepCopy()
	request.Add(vmRequestOverhead)
	limit := memory.DeepCopy()
	limit.Add(vmLimitOverhead)
	selector := poolSelector(pool)
	privileged := true
	// Only the API proxy gets a token, through an explicit projection. The
	// privileged runtime and guest never receive service account credentials.
	automount := false
	grace := terminationGracePeriod
	hostPathType := corev1.HostPathDirectoryOrCreate
	fieldEnv := func(name, path string) corev1.EnvVar {
		return corev1.EnvVar{Name: name, ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: path}}}
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       pool.Namespace,
			Labels:          map[string]string{LabelPool: pool.Name},
			Annotations:     map[string]string{annotationTemplateHash: templateHash(pool)},
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(pool, v1.GroupVersion.WithKind("BlipPool"))},
		},
		Spec: corev1.PodSpec{
			RestartPolicy:                 corev1.RestartPolicyNever,
			ServiceAccountName:            pool.Spec.ServiceAccountName,
			AutomountServiceAccountToken:  &automount,
			TerminationGracePeriodSeconds: &grace,
			NodeSelector:                  selector,
			Tolerations:                   pool.Spec.Tolerations,
			Containers: []corev1.Container{{
				Name:    "vm",
				Image:   r.RuntimeImage,
				Command: []string{"blip-runtime"},
				Env: []corev1.EnvVar{
					{Name: "BLIP_CPUS", Value: strconv.Itoa(int(cpus))},
					{Name: "BLIP_MEMORY_MB", Value: strconv.FormatInt(memory.Value()>>20, 10)},
					{Name: "BLIP_HYPERVISOR", Value: hypervisor},
					fieldEnv("POD_NAME", "metadata.name"),
					fieldEnv("POD_NAMESPACE", "metadata.namespace"),
				},
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:    *resource.NewQuantity(int64(cpus), resource.DecimalSI),
						corev1.ResourceMemory: request,
					},
					Limits: corev1.ResourceList{
						corev1.ResourceMemory: limit,
					},
				},
				SecurityContext: &corev1.SecurityContext{Privileged: &privileged},
				VolumeMounts: []corev1.VolumeMount{
					{Name: "pod-dir", MountPath: podapi.MountPath},
					{Name: "vsock", MountPath: vsockMountPath},
				},
			}},
			Volumes: []corev1.Volume{{
				Name: "pod-dir",
				VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{
					Path: podapi.PodDir(pool.Namespace, name),
					Type: &hostPathType,
				}},
			}, {
				Name:         "vsock",
				VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
			}},
		},
	}
	if pool.Spec.ServiceAccountName != "" {
		pod.Spec.Containers[0].Env = append(pod.Spec.Containers[0].Env, fieldEnv("BLIP_KUBE_NAMESPACE", "metadata.namespace"))
		addAPIProxy(pod, r.RuntimeImage)
	}
	return pod
}

func addAPIProxy(pod *corev1.Pod, image string) {
	uid := apiProxyUID
	enabled, disabled := true, false
	restart := corev1.ContainerRestartPolicyAlways
	expiration := int64(3600)
	mode := int32(0644)
	// Kubelet makes the emptyDir writable by the non-root proxy. The proxy
	// shares only sockets with the runtime, never the hostPath pod directory.
	pod.Spec.SecurityContext = &corev1.PodSecurityContext{FSGroup: &uid}
	// A native sidecar starts before the VM and stops after it exits, without
	// keeping the pod alive. Guest API connections retry until it is listening.
	pod.Spec.InitContainers = []corev1.Container{{
		Name:          apiProxyName,
		Image:         image,
		Command:       []string{"blip-runtime", "api-proxy"},
		RestartPolicy: &restart,
		SecurityContext: &corev1.SecurityContext{
			RunAsUser:                &uid,
			RunAsGroup:               &uid,
			RunAsNonRoot:             &enabled,
			Privileged:               &disabled,
			AllowPrivilegeEscalation: &disabled,
			ReadOnlyRootFilesystem:   &enabled,
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		},
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("10m"),
				corev1.ResourceMemory: resource.MustParse("16Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceMemory: resource.MustParse("64Mi"),
			},
		},
		VolumeMounts: []corev1.VolumeMount{
			{Name: "vsock", MountPath: vsockMountPath},
			{Name: apiTokenVolume, MountPath: serviceAccountPath, ReadOnly: true},
		},
	}}
	// With no audience override, kubelet requests an API-server token bound
	// to this pod and refreshes it before expiry. Mount the whole projection
	// (not a subPath) so the proxy can read the rotated token on each request.
	pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
		Name: apiTokenVolume,
		VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
			DefaultMode: &mode,
			Sources: []corev1.VolumeProjection{
				{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "token", ExpirationSeconds: &expiration}},
				{ConfigMap: &corev1.ConfigMapProjection{
					LocalObjectReference: corev1.LocalObjectReference{Name: "kube-root-ca.crt"},
					Items:                []corev1.KeyToPath{{Key: "ca.crt", Path: "ca.crt"}},
				}},
				{DownwardAPI: &corev1.DownwardAPIProjection{Items: []corev1.DownwardAPIVolumeFile{{
					Path:     "namespace",
					FieldRef: &corev1.ObjectFieldSelector{APIVersion: "v1", FieldPath: "metadata.namespace"},
				}}}},
			},
		}},
	})
}

// poolShape returns the effective VM shape of pool.
func poolShape(pool *v1.BlipPool) (cpus int32, memory resource.Quantity, hypervisor string) {
	cpus = pool.Spec.CPUs
	if cpus <= 0 {
		cpus = defaultVMCPUs
	}
	memory = pool.Spec.Memory
	if memory.IsZero() {
		memory = defaultVMMemory.DeepCopy()
	}
	hypervisor = pool.Spec.Hypervisor
	if hypervisor == "" {
		hypervisor = "kvm"
	}
	return cpus, memory, hypervisor
}

// templateHash identifies the VM shape a pool creates. Warm pods keep the
// shape they were built with, so a change to any of these fields must retire
// them: reconcile deletes vacant pods whose hash no longer matches.
func templateHash(pool *v1.BlipPool) string {
	cpus, memory, hypervisor := poolShape(pool)
	shape := struct {
		TopologyVersion    string
		CPUs               int32
		Memory             resource.Quantity
		Hypervisor         string
		ServiceAccountName string
		NodeSelector       map[string]string
		Tolerations        []corev1.Toleration
		ImagePullSecrets   []corev1.LocalObjectReference
	}{
		TopologyVersion:    podTopologyVersion,
		CPUs:               cpus,
		Memory:             memory,
		Hypervisor:         hypervisor,
		ServiceAccountName: pool.Spec.ServiceAccountName,
		NodeSelector:       pool.Spec.NodeSelector,
		Tolerations:        pool.Spec.Tolerations,
		ImagePullSecrets:   pool.Spec.ImagePullSecrets,
	}
	// encoding/json sorts map keys, so the same shape always hashes the same.
	data, _ := json.Marshal(shape)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:8])
}
