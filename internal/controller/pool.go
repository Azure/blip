package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
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

// recordWarning publishes a pool problem as a Warning Event when a recorder
// is configured.
func (r *PoolReconciler) recordWarning(obj client.Object, reason string, err error) {
	if r.Recorder != nil {
		r.Recorder.Event(obj, corev1.EventTypeWarning, reason, err.Error())
	}
}

// invalidPool records an endpoint validation failure in pool status and, when
// a recorder is configured, as a Warning Event. Status is written only when it
// changes, so the error-driven requeue does not patch forever.
func (r *PoolReconciler) invalidPool(ctx context.Context, pool *v1.BlipPool, reason string, err error) error {
	err = fmt.Errorf("invalid endpoints for pool %s/%s: %w", pool.Namespace, pool.Name, err)
	if pool.Status.Reason != poolInvalidConfiguration || pool.Status.Message != err.Error() {
		base := pool.DeepCopy()
		pool.Status.Reason = poolInvalidConfiguration
		pool.Status.Message = err.Error()
		if patchErr := r.Status().Patch(ctx, pool, client.MergeFrom(base)); patchErr != nil {
			return fmt.Errorf("%w (status update: %v)", err, patchErr)
		}
	}
	r.recordWarning(pool, reason, err)
	return err
}

// expectTimeout bounds how long a created or deleted pod that the cache does
// not reflect yet is accounted for.
const expectTimeout = time.Minute

// blockedGrace bounds how long a node whose pinned pod the scheduler rejected
// is avoided. The pool retries it after the grace, so a node that regained
// room is used again, but deleting one rejected pod cannot immediately
// recreate another unschedulable one there.
const blockedGrace = time.Minute

// warmTimeout bounds how long a spare may stay unready before the pool retires
// it. A pod that never becomes ready (image pull failure, VM boot failure, or
// a crash-looping sidecar) cannot accept a claim, so keeping it would consume
// warmCount/maxCount and suppress the replacement that waiting demand needs.
const warmTimeout = 5 * time.Minute

const (
	// Bump when pod topology changes without a pool spec change, so warm
	// pods cannot retain the old credential or socket layout.
	podTopologyVersion = "api-proxy-v3"

	apiProxyName             = "api-proxy"
	apiTokenVolume           = "api-token"
	serviceAccountPath       = "/var/run/secrets/kubernetes.io/serviceaccount"
	vsockMountPath           = podapi.MountPath + "/vsock"
	apiProxyUID        int64 = 65532

	endpointMountRoot       = "/var/run/blip/endpoints"
	endpointsEnv            = "BLIP_ENDPOINTS"
	endpointNamesEnv        = "BLIP_ENDPOINT_NAMES"
	kubeAPIEnv              = "BLIP_KUBE_API"
	endpointTokenFile       = "token"
	endpointCAFile          = "ca.crt"
	endpointTokenExpiration = int64(3600)

	// terminationGracePeriod covers the runtime's 60s guest shutdown
	// budget, so the kubelet does not SIGKILL the VMM mid-shutdown.
	terminationGracePeriod = int64(90)

	defaultVMCPUs = int32(2)

	// poolInvalidConfiguration is the BlipPool.status.reason for a spec that
	// admission accepted but the controller cannot turn into VMs.
	poolInvalidConfiguration = "InvalidConfiguration"
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
	// Recorder publishes validation failures as Kubernetes Events.
	// SetupWithManager sets it; callers that reconcile directly may leave it
	// nil.
	Recorder record.EventRecorder

	// APIAudiences are the cluster's accepted service-account audiences, as
	// discovered at startup. validateEndpoints rejects an endpoint token
	// projected for any of them.
	APIAudiences []string
	// APIReader reads objects uncached. The manager cache only watches the
	// blip-vm-owners ConfigMap, so CA ConfigMaps must bypass it or every CA
	// reference looks missing. SetupWithManager sets it; direct callers that
	// leave it nil fall back to Client.
	APIReader client.Reader

	mu sync.Mutex
	// created and deleted hold pod names (per pool) whose change the
	// cache may not show yet.
	created map[types.NamespacedName]map[string]expectation
	deleted map[types.NamespacedName]map[string]expectation
	// blocked holds, per pool, when a node whose pinned pod the scheduler
	// rejected may be tried again. A rejected pod is deleted, so the nodes
	// cannot be re-derived from the pod list on the next pass.
	blocked map[types.NamespacedName]map[string]time.Time
}

type expectation struct {
	at time.Time
	// node is the node a created pod is pinned to.
	node string
}

func (r *PoolReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Recorder = mgr.GetEventRecorderFor("blippool")
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1.BlipPool{}).
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(func(_ context.Context, o client.Object) []reconcile.Request {
			if p := o.GetLabels()[v1.LabelPool]; p != "" {
				return []reconcile.Request{req(o.GetNamespace(), p)}
			}
			return nil
		})).
		Watches(&v1.Blip{}, handler.EnqueueRequestsFromMapFunc(func(_ context.Context, o client.Object) []reconcile.Request {
			return []reconcile.Request{req(o.GetNamespace(), poolName(o.(*v1.Blip)))}
		})).
		Watches(&v1.BlipState{}, handler.EnqueueRequestsFromMapFunc(r.namespacePools)).
		// Thread creation and deletion changes the turn-owner table. Status
		// updates from blipchat do not, so ignore them.
		Watches(&v1.BlipThread{}, handler.EnqueueRequestsFromMapFunc(r.namespacePools),
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		// A stale heartbeat is a status-only change, and an agent that dies
		// sends no event at all; reconcile also requeues itself while a node
		// it uses is still healthy (see nextCrossing).
		Watches(&v1.BlipNode{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, _ client.Object) []reconcile.Request {
			return r.poolRequests(ctx, "")
		})).
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

// caReader returns the reader used for CA ConfigMaps. The default direct
// client backs tests and callers that reconcile without a manager.
func (r *PoolReconciler) caReader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}

// State imports and deletions, and thread changes, refresh the authorization
// table even when no Blip currently waits for a VM.
func (r *PoolReconciler) namespacePools(ctx context.Context, o client.Object) []reconcile.Request {
	return r.poolRequests(ctx, o.GetNamespace())
}

// poolRequests enqueues every pool, or only the ones in namespace when it is
// not empty.
func (r *PoolReconciler) poolRequests(ctx context.Context, namespace string) []reconcile.Request {
	var opts []client.ListOption
	if namespace != "" {
		opts = append(opts, client.InNamespace(namespace))
	}
	var pools v1.BlipPoolList
	if err := r.List(ctx, &pools, opts...); err != nil {
		return nil
	}
	var out []reconcile.Request
	for _, p := range pools.Items {
		out = append(out, req(p.Namespace, p.Name))
	}
	return out
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
			delete(r.blocked, rq.NamespacedName)
			r.mu.Unlock()
		}
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	if pool.DeletionTimestamp != nil {
		return reconcile.Result{}, nil
	}
	// Refuse to create pods whose api-proxy sidecar would exit at startup.
	// The failure is recorded in pool status and as an Event on the pool, so
	// an operator can see why no VM becomes ready instead of only finding it
	// in the controller log.
	if err := validateEndpoints(pool, r.APIAudiences...); err != nil {
		return reconcile.Result{}, r.invalidPool(ctx, pool, "InvalidEndpoints", err)
	}
	// The API checks the ConfigMap reference's shape; its contents must also
	// be a usable CA bundle or the sidecar crash-loops before the pod is ready.
	// Read through the API reader: the manager cache only watches
	// blip-vm-owners, so a cached Get would report every other ConfigMap as
	// missing. A transient read failure is retried, not pinned in status.
	if err := validateEndpointCAs(ctx, r.caReader(), pool); err != nil {
		var invalid invalidEndpointCAError
		if !errors.As(err, &invalid) {
			return reconcile.Result{}, err
		}
		return reconcile.Result{}, r.invalidPool(ctx, pool, "InvalidEndpointCA", err)
	}
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(pool.Namespace), client.MatchingLabels{v1.LabelPool: pool.Name}); err != nil {
		return reconcile.Result{}, err
	}
	// API list order is not a placement or deletion preference. This also
	// breaks equal creation-time ties in the stable sorts below.
	sort.Slice(pods.Items, func(i, j int) bool { return pods.Items[i].Name < pods.Items[j].Name })
	var blips v1.BlipList
	if err := r.List(ctx, &blips, client.InNamespace(pool.Namespace), client.MatchingFields{indexPool: pool.Name}); err != nil {
		return reconcile.Result{}, err
	}
	// The pool places and counts VMs with the same node view as the Blip
	// side. A vacant pod on a node that is draining, stale, gone, or no
	// longer enrolled is not capacity: no Blip may claim it, so keeping it
	// in have/total would block the replacement that demand needs.
	cl, err := loadCluster(ctx, r.Client, r.now())
	if err != nil {
		return reconcile.Result{}, err
	}
	// Match the Blip side, which filters candidates with a nil selector:
	// a node is usable for health/placement purposes when it is an
	// enrolled, incarnated, healthy BlipNode that is not draining.
	usable := func(node string) bool { return node == "" || cl.usable(node, nil) }
	// avoid holds every enrolled node a new VM must not use. A generic
	// replacement is otherwise free to land on the dead node it replaces.
	avoid := cl.avoidNodes()

	// claimed holds the Blips whose VM pod already exists, even if the Blip
	// reconciler has not written status.pod yet. Counting such a Blip as
	// demand while its claimed pod is no longer vacant creates a duplicate:
	// under a burst of forks the pool booted one extra VM per claim.
	claimed := map[types.UID]bool{}
	blipByUID := map[types.UID]*v1.Blip{}
	for i := range blips.Items {
		b := &blips.Items[i]
		blipByUID[b.UID] = b
	}
	for i := range pods.Items {
		if uid := pods.Items[i].Labels[v1.LabelBlipUID]; uid != "" {
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
	// blocked holds the nodes whose pinned VM the scheduler rejected. A
	// rejected pod is not capacity: another pinned pod on the same node
	// would be rejected too, so demand for that node moves to another home
	// node (or an unpinned VM) instead. The nodes are remembered for
	// blockedGrace because the rejected pod itself is deleted.
	observed := map[string]bool{}
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.DeletionTimestamp == nil && unschedulable(p) && p.Annotations[v1.AnnotationPinnedNode] != "" {
			observed[podNode(p)] = true
		}
	}
	blocked := r.poolBlocked(rq.NamespacedName, observed, r.now())
	// An alternate home node is only needed once a node is blocked. Load the
	// states lazily so the common path keeps its single Blip list.
	var states map[string]*v1.BlipState
	if len(blocked) > 0 {
		var list v1.BlipStateList
		if err := r.List(ctx, &list, client.InNamespace(pool.Namespace)); err != nil {
			return reconcile.Result{}, err
		}
		states = make(map[string]*v1.BlipState, len(list.Items))
		for i := range list.Items {
			states[list.Items[i].Name] = &list.Items[i]
		}
	}
	// pinned counts, per node, the waiting Blips whose data lives there.
	// localWaiters counts the Blips still waiting on their data node and not
	// fallen back: their pinned pod is worth keeping while the scheduler may
	// still place it once the node has room.
	pinned := map[string]int{}
	localWaiters := map[string]int{}
	for i := range blips.Items {
		b := &blips.Items[i]
		if !countsAsDemand(b, pool.Name) || claimed[b.UID] {
			continue
		}
		if b.Spec.State != "" && b.Status.Locality == nil {
			deferred++
			continue
		}
		demand++
		// A fallback Blip has not claimed a VM yet. Its data node is still
		// the right place to boot one once capacity allows: falling back
		// under transient maxCount pressure is not a reason to start the
		// replacement away from the data.
		loc := b.Status.Locality
		if loc == nil || loc.Node == "" || !usable(loc.Node) {
			continue
		}
		if !loc.Fallback {
			localWaiters[loc.Node]++
		}
		node := loc.Node
		if blocked[node] {
			// The first home node rejected the VM. Prefer another node that
			// holds the same data before falling back to a remote/unpinned
			// start.
			node = ""
			for _, n := range homeNodes(placementScores(b, states), cl, poolSelector(pool)) {
				if !blocked[n] {
					node = n
					break
				}
			}
		}
		if node != "" {
			pinned[node]++
		}
	}

	hash := templateHash(pool, r.RuntimeImage)
	created, createdOn, deleted := r.expectations(rq.NamespacedName, pods.Items)
	// del records pods deleted in this pass. The cached list still shows
	// them (and the deletion expectation hides them only on the next
	// reconcile), so later phases must not act on them again.
	del := func(p *corev1.Pod) error {
		if err := r.deletePod(ctx, rq.NamespacedName, p); err != nil {
			return err
		}
		deleted[p.Name] = true
		return nil
	}
	total := len(pods.Items) + created
	// used holds the nodes that host a pod of this pool; it bounds the
	// self-requeue that notices an agent dying without an event.
	used := map[string]bool{}
	var vacant []*corev1.Pod
	var status v1.BlipPoolStatus
	// hot counts the nodes that run a claimed VM of this pool. Warm spares
	// are placed there first: a fork's data lives on the node its parent
	// runs on, so a warm VM there starts the fork without booting a VM on
	// the critical path.
	hot := map[string]int{}
	// reapPending is set while a terminated claimed pod is waiting for its
	// Blip to capture the exit status. The pool keeps it out of capacity but
	// requeues so a controller outage cannot leak the slot forever.
	reapPending := false
	for i := range pods.Items {
		p := &pods.Items[i]
		node := podNode(p)
		if node != "" {
			used[node] = true
		}
		unusable := node != "" && !usable(node)
		switch {
		case !isVacant(p):
			if podTerminated(p) {
				// A finished VM is no longer capacity, whether or not the
				// pod object is still around. Once its Blip captured the
				// exit status, remove it so the slot can be reused even if
				// that Blip cannot finish and clean up itself.
				total--
				if p.DeletionTimestamp == nil {
					if terminalCaptured(p, blipByUID[types.UID(p.Labels[v1.LabelBlipUID])], r.now()) {
						if err := del(p); err != nil {
							return reconcile.Result{}, err
						}
					} else {
						reapPending = true
					}
				}
			} else {
				status.Claimed++
				if p.DeletionTimestamp == nil && p.Spec.NodeName != "" && usable(p.Spec.NodeName) {
					hot[p.Spec.NodeName]++
				}
			}
		case p.DeletionTimestamp != nil || deleted[p.Name]:
			// Its replacement is already accounted for; do not let a pod
			// leaving an unusable node, a node the scheduler rejected, or
			// one that never became ready hold maxCount capacity either.
			if unusable || !ready(p) {
				total--
			}
		case podTerminated(p) || unusable || p.Annotations[v1.AnnotationTemplateHash] != hash:
			if err := del(p); err != nil {
				return reconcile.Result{}, err
			}
			if unusable {
				total--
			}
		case unschedulable(p):
			// The scheduler rejected this pod, so it cannot satisfy demand
			// and must not hold a maxCount slot: booting the replacement
			// elsewhere is the whole point. Keep a pinned pod while a Blip
			// still waits locally (the scheduler may place it once the node
			// has room); once the Blip fell back, replace it. A generic spare
			// has no node to wait for, and its stale avoid affinity may
			// exclude nodes that are usable again, so delete it and let
			// createPod recompute the placement.
			total--
			if p.Annotations[v1.AnnotationPinnedNode] == "" || localWaiters[node] == 0 {
				if err := del(p); err != nil {
					return reconcile.Result{}, err
				}
			}
		case warmingOverdue(p, r.now()):
			// A spare that never became ready cannot accept a claim. Retire
			// it so a replacement boots instead of it holding a slot and
			// covering waiting demand until pendingTimeout.
			total--
			if err := del(p); err != nil {
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
	target := int(pool.Spec.WarmCount) + demand
	maxCount := int(pool.Spec.MaxCount)
	if maxCount > 0 {
		// maxCount caps claimed VMs as well as vacant spares. Budget the
		// spares only what the claims leave: lowering the cap while a Blip
		// runs must delete surplus spares, not keep maxCount of them on top
		// of every claim. A cap below the claims leaves no spare budget.
		target = min(target, max(maxCount-int(status.Claimed), 0))
	}
	// Only ready vacant pods can satisfy a waiting Blip. A booting or broken
	// spare must not stand in for demand and suppress the replacement that the
	// waiting Blip needs.
	claimable := int(status.Ready)
	have := len(vacant) + created
	log.FromContext(ctx).V(1).Info("pool sizing", "demand", demand, "deferred", deferred, "claimed", len(claimed), "pinned", pinned, "vacant", len(vacant), "created", created, "target", target, "have", have, "total", total, "blocked", blocked)
	room := func() bool { return maxCount <= 0 || total < maxCount }
	for _, node := range slices.Sorted(maps.Keys(short)) {
		// Pinned demand was already moved off a blocked node above; never
		// create another pod the scheduler is known to reject.
		if blocked[node] {
			continue
		}
		for range short[node] {
			if !room() {
				break
			}
			if err := r.createPod(ctx, pool, avoid, node); err != nil {
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
	if want := target - have; want > 0 {
		// If every waiting Blip can claim an existing ready warm VM, do not
		// boot replacements yet. The claim tells us which node is hot, and a
		// spare booted now would land on an arbitrary node and be moved
		// again. The claim wakes the pool, which then boots the replacement.
		if demand > 0 && claimable >= demand {
			want = 0
		}
		for ; want > 0; want-- {
			if !room() {
				break
			}
			node := pickWarmNode(hot, warm, blocked)
			if err := r.createPod(ctx, pool, avoid, node); err != nil {
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
		sortForRemoval(spare)
		for _, p := range spare[:max(0, min(have-target, len(spare)))] {
			if err := del(p); err != nil {
				return reconcile.Result{}, err
			}
			if ready(p) {
				status.Ready--
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
		sortForRemoval(spare)
		for _, p := range spare {
			node := pickWarmNode(hot, warm, blocked)
			// Moving a spare deletes and recreates a pod, so it does not grow
			// the pool: maxCount is no reason to keep a spare on an idle
			// node. Without this a warmCount==maxCount pool can never follow
			// the node that runs VMs.
			if node == "" {
				break
			}
			if err := del(p); err != nil {
				return reconcile.Result{}, err
			}
			warm[podNode(p)]--
			if err := r.createPod(ctx, pool, avoid, node); err != nil {
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
	// A node whose agent dies stops heartbeating and therefore stops
	// producing events. Wake up when one of the nodes this pool uses is due
	// to cross heartbeatTimeout so its capacity is retired.
	next := cl.nextCrossing(slices.Sorted(maps.Keys(used)), heartbeatTimeout, true)
	if reapPending && (next == 0 || next > podReapGrace) {
		// Retry a terminated pod whose exit its Blip has not captured yet.
		next = podReapGrace
	}
	return reconcile.Result{RequeueAfter: next}, nil
}

// sortForRemoval orders pods to delete or move: booting before ready, newest
// first.
func sortForRemoval(pods []*corev1.Pod) {
	sort.SliceStable(pods, func(i, j int) bool {
		if ready(pods[i]) != ready(pods[j]) {
			return !ready(pods[i])
		}
		return pods[j].CreationTimestamp.Before(&pods[i].CreationTimestamp)
	})
}

// ready reports whether a warm pod can accept a claim. A warm pod is only
// usable when every container is ready: the api-proxy native sidecar can
// crash-loop (for example on an invalid endpoint CA) while the privileged vm
// container keeps the pod phase Running, and claiming such a pod gives the
// guest a dead API/endpoint path. The kubelet's Ready condition covers the
// native sidecar as well as the VM container.
func ready(p *corev1.Pod) bool {
	if p.Labels[v1.LabelWarm] != "true" || p.Status.Phase != corev1.PodRunning || p.DeletionTimestamp != nil {
		return false
	}
	for _, condition := range p.Status.Conditions {
		if condition.Type == corev1.PodReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	// A pod that the kubelet has not yet described keeps the previous
	// behavior; phase and warm already say it booted.
	return true
}

// warmingOverdue reports whether a spare has been unready for longer than
// warmTimeout. A Ready=False transition time bounds the wait from when the pod
// stopped being usable; a pod that never reported Readiness is measured from
// its creation. Pods without a usable timestamp are never retired, so a fake
// or unscheduled pod is not deleted immediately.
func warmingOverdue(p *corev1.Pod, now time.Time) bool {
	if ready(p) || podTerminated(p) || p.DeletionTimestamp != nil {
		return false
	}
	since := p.CreationTimestamp.Time
	for _, condition := range p.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status != corev1.ConditionTrue &&
			!condition.LastTransitionTime.IsZero() {
			since = condition.LastTransitionTime.Time
			break
		}
	}
	return !since.IsZero() && now.Sub(since) > warmTimeout
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

// poolBlocked merges the nodes the scheduler rejected in this pass with the
// nodes still inside their retry grace, and drops expired entries. Keeping the
// memory across passes matters because the rejected pod is deleted: without it
// the next pass would immediately pin a new pod to the same node.
func (r *PoolReconciler) poolBlocked(pool types.NamespacedName, observed map[string]bool, now time.Time) map[string]bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	nodes := r.blocked[pool]
	if nodes == nil {
		nodes = map[string]time.Time{}
		if r.blocked == nil {
			r.blocked = map[types.NamespacedName]map[string]time.Time{}
		}
		r.blocked[pool] = nodes
	}
	for node := range observed {
		nodes[node] = now.Add(blockedGrace)
	}
	out := map[string]bool{}
	for node, until := range nodes {
		if now.Before(until) {
			out[node] = true
		} else {
			delete(nodes, node)
		}
	}
	if len(nodes) == 0 {
		delete(r.blocked, pool)
	}
	return out
}

// countsAsDemand reports whether b is waiting for a VM from this pool. Blips
// that already have a pod, are going away, or have finished do not create
// demand: counting them would grow an uncapped pool without ever booting
// them. An empty phase means the Blip reconciler has not run yet; it is a new,
// pending Blip.
func countsAsDemand(b *v1.Blip, pool string) bool {
	phase := b.Status.Phase
	return poolName(b) == pool && (phase == "" || phase == v1.BlipPending) &&
		b.Status.Pod == "" && b.DeletionTimestamp == nil && !v1.Finished(b)
}

// podReapGrace lets a terminated claimed pod outlive a controller outage
// before the pool deletes it even though no Blip recorded the exit.
const podReapGrace = time.Minute

// terminalCaptured reports whether a terminated claimed pod's result is safely
// recorded, so the pool may delete it. A finished or deleted Blip no longer
// needs the pod. Otherwise the pool waits podReapGrace after the pod finished:
// that gives the Blip reconcile time to copy the exit status and output, while
// still bounding a controller outage that would otherwise leak the slot.
func terminalCaptured(p *corev1.Pod, b *v1.Blip, now time.Time) bool {
	if b == nil || v1.Finished(b) || b.DeletionTimestamp != nil {
		return true
	}
	finished := finishedAt(p)
	return !finished.IsZero() && now.Sub(finished) > podReapGrace
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
	now := r.now()
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
	(*m)[pool][name] = expectation{at: r.now(), node: node}
}

// createPod creates a VM pod. A pod for a node is pinned to it; others avoid
// nodes that cannot run one, including draining and unhealthy ones.
func (r *PoolReconciler) createPod(ctx context.Context, pool *v1.BlipPool, avoid map[string]bool, node string) error {
	pod := r.podFor(pool, r.newPodName(pool.Name))
	var match *corev1.NodeSelectorRequirement
	switch {
	case node != "":
		pod.Annotations[v1.AnnotationPinnedNode] = node
		match = &corev1.NodeSelectorRequirement{Key: "metadata.name", Operator: corev1.NodeSelectorOpIn, Values: []string{node}}
	case len(avoid) > 0:
		match = &corev1.NodeSelectorRequirement{Key: "metadata.name", Operator: corev1.NodeSelectorOpNotIn, Values: slices.Sorted(maps.Keys(avoid))}
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

// podFor builds a VM pod (see the README's implementation outline).
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
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       pool.Namespace,
			Labels:          map[string]string{v1.LabelPool: pool.Name},
			Annotations:     map[string]string{v1.AnnotationTemplateHash: templateHash(pool, r.RuntimeImage)},
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(pool, v1.GroupVersion.WithKind("BlipPool"))},
		},
		Spec: corev1.PodSpec{
			RestartPolicy:                 corev1.RestartPolicyNever,
			ServiceAccountName:            pool.Spec.ServiceAccountName,
			AutomountServiceAccountToken:  &automount,
			TerminationGracePeriodSeconds: &grace,
			NodeSelector:                  selector,
			Tolerations:                   pool.Spec.Tolerations,
			ImagePullSecrets:              pool.Spec.ImagePullSecrets,
			Containers: []corev1.Container{{
				Name:    podapi.VMContainer,
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
	if len(pool.Spec.Endpoints) > 0 {
		names := make([]string, len(pool.Spec.Endpoints))
		for i, e := range pool.Spec.Endpoints {
			names[i] = e.Name
		}
		// The guest only needs the hostnames. Credentials and CA bundles stay
		// in the sidecar.
		pod.Spec.Containers[0].Env = append(pod.Spec.Containers[0].Env,
			corev1.EnvVar{Name: endpointNamesEnv, Value: strings.Join(names, ",")})
	}
	if pool.Spec.ServiceAccountName != "" || len(pool.Spec.Endpoints) > 0 {
		if pool.Spec.ServiceAccountName != "" {
			pod.Spec.Containers[0].Env = append(pod.Spec.Containers[0].Env, fieldEnv("BLIP_KUBE_NAMESPACE", "metadata.namespace"))
		}
		addAPIProxy(pod, pool, r.RuntimeImage)
	}
	return pod
}

func fieldEnv(name, path string) corev1.EnvVar {
	return corev1.EnvVar{Name: name, ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: path}}}
}

// proxyEndpoint is the sidecar's view of one configured endpoint. A file path
// is present only when the matching credential was projected.
type proxyEndpoint struct {
	Name      string `json:"name"`
	URL       string `json:"url"`
	TokenFile string `json:"tokenFile,omitempty"`
	CAFile    string `json:"caFile,omitempty"`
}

func addAPIProxy(pod *corev1.Pod, pool *v1.BlipPool, image string) {
	uid := apiProxyUID
	enabled, disabled := true, false
	restart := corev1.ContainerRestartPolicyAlways
	mode := int32(0644)
	// Kubelet makes the emptyDir writable by the non-root proxy. The proxy
	// shares only sockets with the runtime, never the hostPath pod directory.
	pod.Spec.SecurityContext = &corev1.PodSecurityContext{FSGroup: &uid}
	// A native sidecar starts before the VM and stops after it exits, without
	// keeping the pod alive. Guest API connections retry until it is listening.
	proxy := corev1.Container{
		Name:          apiProxyName,
		Image:         image,
		Command:       []string{"blip-runtime", "api-proxy"},
		RestartPolicy: &restart,
		Env: []corev1.EnvVar{
			// Trusted identity for owner-scoped reads. The guest cannot set
			// these; they come from the pod's own metadata.
			fieldEnv("POD_NAME", "metadata.name"),
			fieldEnv("POD_NAMESPACE", "metadata.namespace"),
		},
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
		},
	}
	if pool.Spec.ServiceAccountName != "" {
		expiration := endpointTokenExpiration
		proxy.Env = append(proxy.Env, corev1.EnvVar{Name: kubeAPIEnv, Value: "1"})
		proxy.VolumeMounts = append(proxy.VolumeMounts,
			corev1.VolumeMount{Name: apiTokenVolume, MountPath: serviceAccountPath, ReadOnly: true})
		// With no audience override, kubelet requests an API-server token
		// bound to this pod and refreshes it before expiry. Mount the whole
		// projection (not a subPath) so the proxy can read the rotated token
		// on each request.
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
	if len(pool.Spec.Endpoints) > 0 {
		endpoints := make([]proxyEndpoint, 0, len(pool.Spec.Endpoints))
		for i := range pool.Spec.Endpoints {
			e := &pool.Spec.Endpoints[i]
			dir := fmt.Sprintf("%s/%d", endpointMountRoot, i)
			pe := proxyEndpoint{Name: e.Name, URL: e.URL}
			var sources []corev1.VolumeProjection
			if e.Audience != "" {
				expiration := endpointTokenExpiration
				sources = append(sources, corev1.VolumeProjection{
					ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
						Path:              endpointTokenFile,
						Audience:          e.Audience,
						ExpirationSeconds: &expiration,
					},
				})
				pe.TokenFile = dir + "/" + endpointTokenFile
			}
			if e.CAConfigMap != "" {
				sources = append(sources, corev1.VolumeProjection{
					ConfigMap: &corev1.ConfigMapProjection{
						LocalObjectReference: corev1.LocalObjectReference{Name: e.CAConfigMap},
						Items:                []corev1.KeyToPath{{Key: "ca.crt", Path: endpointCAFile}},
					},
				})
				pe.CAFile = dir + "/" + endpointCAFile
			}
			endpoints = append(endpoints, pe)
			if len(sources) == 0 {
				continue
			}
			name := fmt.Sprintf("endpoint-%d", i)
			pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
				Name: name,
				VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
					DefaultMode: &mode,
					Sources:     sources,
				}},
			})
			proxy.VolumeMounts = append(proxy.VolumeMounts,
				corev1.VolumeMount{Name: name, MountPath: dir, ReadOnly: true})
		}
		data, _ := json.Marshal(endpoints)
		proxy.Env = append(proxy.Env, corev1.EnvVar{Name: endpointsEnv, Value: string(data)})
	}
	pod.Spec.InitContainers = []corev1.Container{proxy}
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

// templateHash identifies the VM shape a controller builds for a pool. Warm
// pods keep the shape they were built with, so a change to any of these
// fields must retire them: reconcile deletes vacant pods whose hash no longer
// matches. The runtime image is controller configuration rather than pool
// spec, but it determines the guest version, so a controller rollout with a
// new image must not leave warm VMs booted by the old one.
func templateHash(pool *v1.BlipPool, runtimeImage string) string {
	cpus, memory, hypervisor := poolShape(pool)
	shape := struct {
		TopologyVersion    string
		RuntimeImage       string
		CPUs               int32
		Memory             resource.Quantity
		Hypervisor         string
		ServiceAccountName string
		Endpoints          []v1.PoolEndpoint `json:",omitempty"`
		NodeSelector       map[string]string
		Tolerations        []corev1.Toleration
		ImagePullSecrets   []corev1.LocalObjectReference `json:",omitempty"`
	}{
		TopologyVersion:    podTopologyVersion,
		RuntimeImage:       runtimeImage,
		CPUs:               cpus,
		Memory:             memory,
		Hypervisor:         hypervisor,
		ServiceAccountName: pool.Spec.ServiceAccountName,
		Endpoints:          pool.Spec.Endpoints,
		NodeSelector:       pool.Spec.NodeSelector,
		Tolerations:        pool.Spec.Tolerations,
		ImagePullSecrets:   pool.Spec.ImagePullSecrets,
	}
	// encoding/json sorts map keys, so the same shape always hashes the same.
	data, _ := json.Marshal(shape)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:8])
}
