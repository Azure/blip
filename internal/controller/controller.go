package controller

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/example/blip/internal/api"
	v1 "github.com/example/blip/internal/api/v1alpha1"
	"github.com/example/blip/internal/proto/nodepb"
)

// Main runs blipd controller.
func Main(ctx context.Context, args []string) error {
	opts, err := ParseFlags(args)
	if err != nil {
		return err
	}
	ctrl.SetLogger(zap.New())
	cfg, err := ctrl.GetConfig()
	if err != nil {
		return err
	}
	return Run(ctx, cfg, opts, nil)
}

// Controller makes all Blip decisions.
type Controller struct {
	client.Client
	live  client.Client // uncached
	log   logr.Logger
	opts  Options
	nodes *NodeManager

	blipEvents chan event.GenericEvent
	volEvents  chan event.GenericEvent
	recorder   record.EventRecorder

	schedMu sync.Mutex
	assumed map[string]assumedClaim // by slot pod namespace/name

	// In-memory state below only paces work; everything that protects
	// data (claims, holds, attachment and snapshot state) is in the CRs.
	mu       sync.Mutex
	allocKey map[string]types.NamespacedName
	scrubbed map[string]time.Time
	retry    map[string]*retryEntry          // operations retried with new IDs
	dropped  map[string]map[int64]bool       // local snapshots dropped, by attachment ID
	written  map[types.NamespacedName]string // Blip status resourceVersions this controller wrote
	saves    map[string]*saveState           // snapshot saves by content ID
	creds    map[string]*credState           // service account tokens by allocation ID
	pools    map[types.NamespacedName]*poolState

	minter TokenMinter
	caCrt  []byte // API server CA given to guests
}

type assumedClaim struct {
	blip      types.NamespacedName
	uid       types.UID // a new Blip with the same name has another UID
	namespace string
	sku       string
	allocID   string
	at        time.Time
}

// Index names.
const (
	idxAllocation = "status.allocation.id"
	idxNode       = "status.allocation.node"
	idxBlipVol    = "volumes.blipVolRef"
	// BlipVol: the UID of the BlipVol in status.origin (derived from it,
	// pinning one of its snapshots or waiting for a live capture), and
	// spec.parent as namespace/name.
	idxOriginUID = "status.origin.uid"
	idxParent    = "spec.parent"
)

// Hooks let tests replace parts of the controller.
type Hooks struct {
	// Auth replaces the TokenReview node authenticator.
	Auth NodeAuthenticator
	// WrapLive wraps the uncached client (used for claims, holds and
	// snapshot status writes).
	WrapLive func(client.Client) client.Client
	// Created is called with the controller before the manager starts.
	Created func(*Controller)
	// Mint wraps the service account token minter.
	Mint func(TokenMinter) TokenMinter
}

// Run starts the controller and blocks until ctx is done.
func Run(ctx context.Context, cfg *rest.Config, opts Options, hooks *Hooks) error {
	if hooks == nil {
		hooks = &Hooks{}
	}
	log := ctrl.Log.WithName("controller")
	if err := opts.validateSlots(); err != nil {
		return err
	}
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return err
	}
	if err := v1.AddToScheme(scheme); err != nil {
		return err
	}
	live, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return err
	}
	cert, _, err := ensureCerts(ctx, live, opts.Namespace, servingNames(opts.ServiceName, opts.Namespace, opts.DNSNames))
	if err != nil {
		return fmt.Errorf("certificates: %w", err)
	}
	clusterKey, err := ensureClusterKey(ctx, live, opts.Namespace)
	if err != nil {
		return fmt.Errorf("nvme cluster key: %w", err)
	}
	auth := hooks.Auth
	if auth == nil {
		auth = &TokenAuthenticator{Client: live, Namespace: opts.Namespace}
	}
	wrapped := live
	if hooks.WrapLive != nil {
		wrapped = hooks.WrapLive(live)
	}
	sys := map[string]cache.Config{opts.Namespace: {}}
	// Slot pods live in tenant namespaces: watch pods cluster-wide, but
	// only those with the slot label.
	slotSel, err := labels.Parse(api.LabelSlot)
	if err != nil {
		return err
	}
	caCrt, err := clusterCA(cfg)
	if err != nil {
		return fmt.Errorf("API server CA: %w", err)
	}
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                        scheme,
		LeaderElection:                opts.LeaderElection,
		LeaderElectionID:              api.LeaseName,
		LeaderElectionNamespace:       opts.Namespace,
		LeaderElectionReleaseOnCancel: true,
		Metrics:                       metricsserver.Options{BindAddress: opts.MetricsAddr},
		HealthProbeBindAddress:        opts.ProbeAddr,
		Cache: cache.Options{ByObject: map[client.Object]cache.ByObject{
			&corev1.Pod{}:       {Label: slotSel},
			&corev1.ConfigMap{}: {Namespaces: sys},
		}},
		Client:     client.Options{Cache: &client.CacheOptions{DisableFor: []client.Object{&corev1.Secret{}}}},
		Controller: config.Controller{SkipNameValidation: ptr(true)},
	})
	if err != nil {
		return err
	}
	c := &Controller{
		Client: mgr.GetClient(), live: wrapped, log: log, opts: opts,
		blipEvents: make(chan event.GenericEvent, 1024), volEvents: make(chan event.GenericEvent, 1024),
		recorder: mgr.GetEventRecorderFor("blip-controller"),
		assumed:  map[string]assumedClaim{}, allocKey: map[string]types.NamespacedName{},
		scrubbed: map[string]time.Time{}, retry: map[string]*retryEntry{}, dropped: map[string]map[int64]bool{}, written: map[types.NamespacedName]string{}, saves: map[string]*saveState{},
		creds: map[string]*credState{}, pools: map[types.NamespacedName]*poolState{}, minter: tokenRequestMinter{c: live, ttl: opts.TokenTTL}, caCrt: caCrt,
	}
	if hooks.Mint != nil {
		c.minter = hooks.Mint(c.minter)
	}
	c.nodes = NewNodeManager(log.WithName("nodes"), auth, clusterKey, &c.opts, NodeHooks{
		Finished:     c.finishedAllocations,
		Connected:    c.nodeConnected,
		AllocChanged: c.allocChanged,
		OpDone:       c.opDone,
	})
	if err := c.setup(mgr); err != nil {
		return err
	}
	if hooks.Created != nil {
		hooks.Created(c)
	}
	_ = mgr.AddHealthzCheck("ping", healthz.Ping)
	_ = mgr.AddReadyzCheck("ping", healthz.Ping)

	if err := mgr.Add(&server{addr: opts.ListenAddr, cert: cert, nodes: c.nodes, log: log}); err != nil {
		return err
	}
	return mgr.Start(ctx)
}

func ptr[T any](v T) *T { return &v }

func (c *Controller) setup(mgr ctrl.Manager) error {
	ix := mgr.GetFieldIndexer()
	ctx := context.Background()
	if err := ix.IndexField(ctx, &v1.Blip{}, idxAllocation, func(o client.Object) []string {
		if a := o.(*v1.Blip).Status.Allocation; a != nil {
			return []string{a.ID}
		}
		return nil
	}); err != nil {
		return err
	}
	if err := ix.IndexField(ctx, &v1.Blip{}, idxNode, func(o client.Object) []string {
		if a := o.(*v1.Blip).Status.Allocation; a != nil && a.Node != "" {
			return []string{a.Node}
		}
		return nil
	}); err != nil {
		return err
	}
	if err := ix.IndexField(ctx, &v1.Blip{}, idxBlipVol, func(o client.Object) []string {
		b := o.(*v1.Blip)
		var names []string
		for _, v := range b.Spec.Volumes {
			names = append(names, v.BlipVolRef.Name)
		}
		for _, v := range b.Status.Volumes {
			if v.BlipVolRef != nil {
				names = append(names, v.BlipVolRef.Name)
			}
		}
		return names
	}); err != nil {
		return err
	}
	if err := ix.IndexField(ctx, &v1.BlipVol{}, idxOriginUID, func(o client.Object) []string {
		if og := o.(*v1.BlipVol).Status.Origin; og != nil && og.UID != "" {
			return []string{og.UID}
		}
		return nil
	}); err != nil {
		return err
	}
	if err := ix.IndexField(ctx, &v1.BlipVol{}, idxParent, func(o client.Object) []string {
		if k := parentKey(o.(*v1.BlipVol)); k.Name != "" {
			return []string{k.String()}
		}
		return nil
	}); err != nil {
		return err
	}
	// A slot pod wakes the Blip it runs. A free slot pod that is Ready
	// (Kubernetes readiness is the only slot readiness signal) wakes the
	// Blips waiting for a slot of its SKU.
	podToBlip := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		l := o.GetLabels()
		if p, ok := o.(*corev1.Pod); ok && freeSlot(p, l[api.LabelSKU]) {
			return c.pendingBlips(ctx, p.Namespace, l[api.LabelSKU])
		}
		if l[api.LabelNamespace] == "" || l[api.LabelName] == "" {
			return nil
		}
		return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: l[api.LabelNamespace], Name: l[api.LabelName]}}}
	})
	volToBlips := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		var l v1.BlipList
		if err := c.List(ctx, &l, client.InNamespace(o.GetNamespace()), client.MatchingFields{idxBlipVol: o.GetName()}); err != nil {
			return nil
		}
		var r []reconcile.Request
		for _, b := range l.Items {
			if !isFinished(&b) {
				r = append(r, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: b.Namespace, Name: b.Name}})
			}
		}
		// A BlipVol deriving from a claimed one may wait for a live
		// capture: wake the Blip holding the parent's claim.
		if d := o.(*v1.BlipVol); d.Spec.Parent != nil && d.Status.Phase != v1.BlipVolReady && d.Status.Phase != v1.BlipVolFailed {
			var p v1.BlipVol
			if err := c.Get(ctx, parentKey(d), &p); err == nil && p.Status.Claim != nil {
				r = append(r, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: p.Namespace, Name: p.Status.Claim.BlipName}})
			}
		}
		return r
	})
	// A fencing taint on a Node releases the claims of Blips on it.
	nodeToBlips := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		var l v1.BlipList
		if err := c.List(ctx, &l, client.MatchingFields{idxNode: o.GetName()}); err != nil {
			return nil
		}
		var r []reconcile.Request
		for _, b := range l.Items {
			if !isFinished(&b) {
				r = append(r, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: b.Namespace, Name: b.Name}})
			}
		}
		return r
	})
	err := ctrl.NewControllerManagedBy(mgr).Named("blip").
		For(&v1.Blip{}).
		Watches(&corev1.Pod{}, podToBlip).
		Watches(&v1.BlipVol{}, volToBlips).
		Watches(&corev1.Node{}, nodeToBlips).
		Watches(&v1.BlipPool{}, handler.EnqueueRequestsFromMapFunc(c.pendingBlipsForPool)).
		WatchesRawSource(source.Channel(c.blipEvents, &handler.EnqueueRequestForObject{})).
		WithOptions(controller.Options{MaxConcurrentReconciles: 32}).
		Complete(reconcile.Func(c.reconcileBlip))
	if err != nil {
		return err
	}
	// BlipVols related by derivation: a change of a parent wakes the
	// BlipVols deriving from it (waiting for a snapshot), and a change or
	// deletion of a derived BlipVol wakes its origin (pins for compaction).
	related := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		v := o.(*v1.BlipVol)
		var r []reconcile.Request
		if og := v.Status.Origin; og != nil {
			r = append(r, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: og.Namespace, Name: og.Name}})
		} else if v.Spec.Parent != nil {
			r = append(r, reconcile.Request{NamespacedName: parentKey(v)})
		}
		seen := map[types.NamespacedName]bool{}
		for _, f := range []client.MatchingFields{{idxOriginUID: string(v.UID)}, {idxParent: types.NamespacedName{Namespace: v.Namespace, Name: v.Name}.String()}} {
			var l v1.BlipVolList
			if err := c.List(ctx, &l, f); err != nil {
				continue
			}
			for _, d := range l.Items {
				k := types.NamespacedName{Namespace: d.Namespace, Name: d.Name}
				if !seen[k] && d.Status.Phase != v1.BlipVolReady && d.Status.Phase != v1.BlipVolFailed {
					seen[k] = true
					r = append(r, reconcile.Request{NamespacedName: k})
				}
			}
		}
		return r
	})
	err = ctrl.NewControllerManagedBy(mgr).Named("blipvol").
		For(&v1.BlipVol{}, builder.WithPredicates()).
		Watches(&v1.BlipVol{}, related).
		WatchesRawSource(source.Channel(c.volEvents, &handler.EnqueueRequestForObject{})).
		WithOptions(controller.Options{MaxConcurrentReconciles: 16}).
		Complete(reconcile.Func(c.reconcileBlipVol))
	if err != nil {
		return err
	}
	// Slot pods carry their pool's name; the pod cache only holds slot pods.
	podToPool := handler.EnqueueRequestsFromMapFunc(func(_ context.Context, o client.Object) []reconcile.Request {
		n := o.GetLabels()[api.LabelPool]
		if n == "" {
			return nil
		}
		return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: o.GetNamespace(), Name: n}}}
	})
	err = ctrl.NewControllerManagedBy(mgr).Named("blippool").
		For(&v1.BlipPool{}).
		Watches(&v1.BlipPool{}, handler.EnqueueRequestsFromMapFunc(c.poolsForPool)).
		Watches(&corev1.Pod{}, podToPool).
		Watches(&v1.Blip{}, handler.EnqueueRequestsFromMapFunc(c.poolsForBlip)).
		WithOptions(controller.Options{MaxConcurrentReconciles: 8}).
		Complete(reconcile.Func(c.reconcilePool))
	if err != nil {
		return err
	}
	return mgr.Add(manager.RunnableFunc(c.background))
}

// background runs the orphan/repair/scrub loops and housekeeping.
func (c *Controller) background(ctx context.Context) error {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	repair := time.NewTicker(c.opts.RepairInterval)
	defer repair.Stop()
	var repairing sync.Map
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			c.nodes.GC(time.Hour)
			c.updateSlotMetrics(ctx)
			c.updateVolMetrics(ctx)
		case <-repair.C:
			for _, n := range c.nodes.Nodes() {
				if _, busy := repairing.LoadOrStore(n, true); busy {
					continue
				}
				go func(n string) {
					defer repairing.Delete(n)
					c.repairNode(ctx, n)
				}(n)
			}
		}
	}
}

func (c *Controller) enqueueBlip(key types.NamespacedName) {
	b := &v1.Blip{}
	b.Namespace, b.Name = key.Namespace, key.Name
	select {
	case c.blipEvents <- event.GenericEvent{Object: b}:
	default:
		go func() { c.blipEvents <- event.GenericEvent{Object: b} }()
	}
}

func (c *Controller) enqueueVol(key types.NamespacedName) {
	v := &v1.BlipVol{}
	v.Namespace, v.Name = key.Namespace, key.Name
	select {
	case c.volEvents <- event.GenericEvent{Object: v}:
	default:
		go func() { c.volEvents <- event.GenericEvent{Object: v} }()
	}
}

func (c *Controller) opDone(o Owner) {
	key := types.NamespacedName{Namespace: o.Namespace, Name: o.Name}
	switch o.Kind {
	case "Blip":
		c.enqueueBlip(key)
	case "BlipVol":
		c.enqueueVol(key)
	}
}

func (c *Controller) allocChanged(id string) {
	c.mu.Lock()
	key, ok := c.allocKey[id]
	c.mu.Unlock()
	if ok {
		c.enqueueBlip(key)
		return
	}
	var l v1.BlipList
	if err := c.List(context.Background(), &l, client.MatchingFields{idxAllocation: id}); err == nil {
		for _, b := range l.Items {
			c.enqueueBlip(types.NamespacedName{Namespace: b.Namespace, Name: b.Name})
		}
	}
}

// finishedAllocations lists finished allocations on a compute node for Welcome.
func (c *Controller) finishedAllocations(node string) []string {
	var l v1.BlipList
	if err := c.List(context.Background(), &l); err != nil {
		return nil
	}
	var ids []string
	for _, b := range l.Items {
		if a := b.Status.Allocation; a != nil && a.Node == node && isFinished(&b) {
			ids = append(ids, a.ID)
		}
	}
	return ids
}

// nodeConnected releases allocations the node has but no unfinished Blip owns.
func (c *Controller) nodeConnected(node string, st *nodepb.NodeState) {
	if st == nil {
		return
	}
	time.Sleep(2 * time.Second) // let the cache catch up with fresh claims
	ctx := context.Background()
	for _, a := range st.Allocations {
		var l v1.BlipList
		if err := c.List(ctx, &l, client.MatchingFields{idxAllocation: a.AllocationId}); err != nil {
			continue
		}
		owned := false
		for _, b := range l.Items {
			if !isFinished(&b) {
				owned = true
				c.enqueueBlip(types.NamespacedName{Namespace: b.Namespace, Name: b.Name})
			}
		}
		if !owned && len(l.Items) == 0 {
			c.log.Info("releasing unknown allocation", "node", node, "allocation", a.AllocationId)
			c.nodes.Send(node, &nodepb.Command{Op: &nodepb.Command_Release{Release: &nodepb.Release{AllocationId: a.AllocationId}}})
			c.overlayDiscarded(node, a)
		} else if !owned {
			// Finished (abandoned) Blip: Welcome told the node to release it.
			c.overlayDiscarded(node, a)
		}
	}
}

// server serves node gRPC over TLS.
type server struct {
	addr  string
	cert  tls.Certificate
	nodes *NodeManager
	log   logr.Logger
}

// NeedLeaderElection makes only the leader serve nodes.
func (s *server) NeedLeaderElection() bool { return true }

func (s *server) Start(ctx context.Context) error {
	g := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{s.cert},
		MinVersion:   tls.VersionTLS12,
	})))
	nodepb.RegisterControllerServer(g, s.nodes)
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		// Close all connections now: node sessions must move to the next leader.
		g.Stop()
	}()
	s.nodes.MarkServing()
	s.log.Info("serving node gRPC", "addr", ln.Addr().String())
	if err := g.Serve(ln); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return err
	}
	return nil
}

func (c *Controller) updateSlotMetrics(ctx context.Context) {
	var pods corev1.PodList
	if err := c.List(ctx, &pods, client.HasLabels{api.LabelSKU, api.LabelSlot}); err != nil {
		return
	}
	metricSlots.Reset()
	for _, p := range pods.Items {
		metricSlots.WithLabelValues(p.Labels[api.LabelSKU], p.Labels[api.LabelSlot]).Inc()
	}
	var blips v1.BlipList
	if err := c.List(ctx, &blips); err != nil {
		return
	}
	metricPending.Reset()
	for _, b := range blips.Items {
		if b.Status.Allocation == nil && !isFinished(&b) {
			metricPending.WithLabelValues(condReason(b.Status.Conditions, api.CondScheduled)).Inc()
		}
	}
}

func (c *Controller) updateVolMetrics(ctx context.Context) {
	var vols v1.BlipVolList
	if err := c.List(ctx, &vols); err != nil {
		return
	}
	claims := 0
	holds := map[v1.HoldKind]int{}
	for _, v := range vols.Items {
		if v.Status.Claim != nil {
			claims++
		}
		for _, h := range v.Status.Holds {
			holds[h.Kind]++
		}
	}
	metricAttachments.Set(float64(claims))
	metricHolds.Reset()
	for k, n := range holds {
		metricHolds.WithLabelValues(string(k)).Set(float64(n))
	}
}

// overlayDiscarded reports, on the Blip, that a node returned holding an
// allocation of an abandoned attempt: the node released it (stopping the
// stale VM, if any) and its overlays were discarded, not saved.
func (c *Controller) overlayDiscarded(node string, a *nodepb.AllocationInfo) {
	ref := a.GetBlip()
	if ref.GetName() == "" || len(a.Attachments) == 0 {
		return
	}
	b := &v1.Blip{ObjectMeta: metav1.ObjectMeta{Namespace: ref.Namespace, Name: ref.Name, UID: types.UID(ref.Uid)}}
	b.APIVersion, b.Kind = v1.GroupVersion.String(), "Blip"
	var names []string
	for _, at := range a.Attachments {
		names = append(names, at.AttachmentId)
	}
	sort.Strings(names)
	c.recorder.Eventf(b, corev1.EventTypeWarning, api.EventOverlayDiscarded,
		"node %s returned holding allocation %s of an abandoned attempt; its overlays (attachments %v) were discarded", node, a.AllocationId, names)
}

// parentKey is the namespace and name of spec.parent (empty without one).
func parentKey(v *v1.BlipVol) types.NamespacedName {
	p := v.Spec.Parent
	if p == nil {
		return types.NamespacedName{}
	}
	ns := p.Namespace
	if ns == "" {
		ns = v.Namespace
	}
	return types.NamespacedName{Namespace: ns, Name: p.Name}
}
