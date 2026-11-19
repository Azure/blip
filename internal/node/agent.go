package node

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/image"
	"github.com/Azure/blip/internal/peer"
	"github.com/Azure/blip/internal/podapi"
	"github.com/Azure/blip/internal/registryauth"
	"github.com/Azure/blip/internal/storage"
)

// Config configures the agent.
type Config struct {
	NodeName string
	HostIP   string
	DataDir  string
	Insecure []string
	DiskKey  []byte // cluster disk key (see internal/diskkey)
	// Peer dependencies are prepared before storage opens so recovery can
	// resume and release remote exports through the same client.
	Identity   *peer.Identity
	Peers      *peer.Registry
	PeerClient *peer.Client
	// Stream configures the aggregated stream API server. Listen empty
	// disables it.
	Stream StreamConfig
}

// StreamConfig configures the node's stream API listener.
type StreamConfig struct {
	Listen    string
	Namespace string
	// ClientCA optionally verifies the API server's front-proxy client
	// certificate.
	ClientCA string
}

const (
	heartbeatInterval = 20 * time.Second
	resyncInterval    = 10 * time.Second
	progressInterval  = 2 * time.Second
	liveReadInterval  = 5 * time.Second
	// imageConcurrency bounds concurrent image imports and builds on a node.
	imageConcurrency = 2
	// sealConcurrency bounds concurrent state saves. Each one syncs a whole
	// filesystem and snapshots a device; unbounded saves starve each other
	// and every reconnecting command session waits for the backlog.
	sealConcurrency = 4
)

// Agent is the node agent.
type Agent struct {
	cfg     Config
	client  client.Client // reads come from the informer cache
	live    client.Reader // uncached reads
	store   Store
	open    func(ctx context.Context, node string, req peer.ExportRequest) (storage.Remote, error)
	pull    func(ctx context.Context, ref string, secrets []registryauth.PullSecret, dir string) (image.Config, string, error)
	mknod   func(path, device string) error
	pinned  func(commitID string) bool
	peers   func([]peer.Peer) error // update the firewall after publishing trust
	wake    chan struct{}
	streams *streamManager

	mu           sync.Mutex
	workers      sync.WaitGroup
	operations   Scheduler
	opCancels    map[string]context.CancelFunc // running operation key -> cancel
	freezes      map[string][]string           // podKey -> disk IDs to keep frozen
	freezeRefs   map[string]map[string]int     // podKey -> disk ID -> live copies holding it
	sealErrs     map[string]string
	stateErrs    map[string]string
	progress     map[string]*v1alpha1.Transfer
	configs      map[string]*image.Config
	podsGone     map[string]bool
	statesGone   map[string]bool
	blipsGone    map[string]bool
	lastBlipRead map[string]time.Time
	imageUsed    map[string]time.Time // image ID -> last time anything referenced it
	lastPodRead  time.Time
	lastStateRd  time.Time
	lastPeers    string
}

func newAgent(cfg Config, c client.Client, live client.Reader, st Store) *Agent {
	a := &Agent{
		cfg:        cfg,
		client:     c,
		live:       live,
		store:      st,
		mknod:      mknodDevice,
		pinned:     func(string) bool { return false },
		peers:      func([]peer.Peer) error { return nil },
		wake:       make(chan struct{}, 1),
		operations: *NewScheduler(map[string]int{"image": imageConcurrency, "seal": sealConcurrency}),
		opCancels:  map[string]context.CancelFunc{},
		freezes:    map[string][]string{},
		freezeRefs: map[string]map[string]int{},
		sealErrs:   map[string]string{},
		stateErrs:  map[string]string{},
		progress:   map[string]*v1alpha1.Transfer{},
		configs:    map[string]*image.Config{},
		podsGone:   map[string]bool{},
		statesGone: map[string]bool{},
		blipsGone:  map[string]bool{},

		lastBlipRead: map[string]time.Time{},
		imageUsed:    map[string]time.Time{},
	}
	a.pull = a.pullImage
	a.open = cfg.PeerClient.Open
	a.streams = newStreamManager(st, cfg.PeerClient, cfg.NodeName,
		func(key string) string { return podDirFor(cfg.DataDir, key) }, live)
	return a
}

// pullImage pulls ref using credentials from the given image pull secrets.
func (a *Agent) pullImage(ctx context.Context, ref string, secrets []registryauth.PullSecret, dir string) (image.Config, string, error) {
	kc, err := registryauth.Keychain(ctx, a.live, secrets)
	if err != nil {
		return image.Config{}, "", err
	}
	return image.Pull(ctx, ref, image.Options{Insecure: a.cfg.Insecure, Keychain: kc}, dir)
}

// Scheme returns the scheme the agent's clients use.
func Scheme() (*runtime.Scheme, error) {
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		return nil, err
	}
	if err := v1alpha1.AddToScheme(s); err != nil {
		return nil, err
	}
	return s, nil
}

// Run runs the agent until ctx is done.
func Run(ctx context.Context, cfg Config, restCfg *rest.Config, st *storage.Store) error {
	if cfg.Identity == nil || cfg.Peers == nil || cfg.PeerClient == nil {
		return fmt.Errorf("peer identity, registry and client must be prepared before opening storage")
	}
	if !(peer.Peer{Node: cfg.NodeName, PublicKey: cfg.Identity.PublicKey(), Endpoint: cfg.HostIP}).Valid() {
		return fmt.Errorf("invalid local peer identity or endpoint")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	scheme, err := Scheme()
	if err != nil {
		return err
	}
	// Network selectors need destinations on every node, including non-VM
	// pods. snapshot still restricts pod management to this node's VM pods.
	informers, err := cache.New(restCfg, cache.Options{Scheme: scheme})
	if err != nil {
		return err
	}
	c, err := client.New(restCfg, client.Options{Scheme: scheme, Cache: &client.CacheOptions{Reader: informers}})
	if err != nil {
		return err
	}
	live, err := client.New(restCfg, client.Options{Scheme: scheme})
	if err != nil {
		return err
	}
	a := newAgent(cfg, c, live, st)
	defer func() {
		cancel()
		a.workers.Wait()
	}()
	if cfg.Stream.Listen != "" {
		cs, err := kubernetes.NewForConfig(restCfg)
		if err != nil {
			return fmt.Errorf("stream api client: %w", err)
		}
		go a.serveStreamAPI(ctx, live, cs, cfg)
	}
	if err := a.registerNode(ctx); err != nil {
		return err
	}
	go a.heartbeat(ctx)
	handler := toolscache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { a.kick() },
		UpdateFunc: func(any, any) { a.kick() },
		DeleteFunc: func(any) { a.kick() },
	}
	for _, obj := range []client.Object{
		&v1alpha1.BlipState{}, &v1alpha1.Blip{}, &v1alpha1.BlipNode{}, &v1alpha1.BlipPool{},
		&corev1.Pod{}, &corev1.Namespace{}, &corev1.Service{}, &discoveryv1.EndpointSlice{},
	} {
		inf, err := informers.GetInformer(ctx, obj)
		if err != nil {
			return err
		}
		if _, err := inf.AddEventHandler(handler); err != nil {
			return err
		}
	}
	go func() {
		if err := informers.Start(ctx); err != nil {
			slog.Error("informers stopped", "err", err)
		}
	}()
	if !informers.WaitForCacheSync(ctx) {
		return fmt.Errorf("informer caches did not sync")
	}

	fw, err := peer.NewFirewall(cfg.HostIP)
	if err != nil {
		return fmt.Errorf("peer firewall: %w", err)
	}
	a.peers = fw.SetPeers
	var nodes v1alpha1.BlipNodeList
	if err := c.List(ctx, &nodes); err != nil {
		return fmt.Errorf("initial peers: %w", err)
	}
	v := &view{blipNodes: map[string]*v1alpha1.BlipNode{}}
	for i := range nodes.Items {
		v.blipNodes[nodes.Items[i].Name] = &nodes.Items[i]
	}
	if err := a.syncPeers(v); err != nil {
		return err
	}
	srv, err := peer.NewServer(peer.ServerConfig{
		Store:     st,
		NodeName:  cfg.NodeName,
		HostIP:    cfg.HostIP,
		DiskKey:   cfg.DiskKey,
		Identity:  cfg.Identity,
		Peers:     cfg.Peers,
		Authorize: a.authorize,
		DataDir:   cfg.DataDir,
		Stream:    a,
	})
	if err != nil {
		return fmt.Errorf("export server: %w", err)
	}
	a.pinned = srv.Pinned
	errc := make(chan error, 1)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		errc <- srv.Run(ctx)
	}()
	defer func() {
		cancel()
		<-serverDone // Drain export handlers before the caller closes storage.
		if a.streams != nil {
			a.streams.closeAll()
		}
	}()
	go a.watchPodDirs(ctx)
	slog.Info("node agent running", "node", cfg.NodeName, "endpoint", cfg.HostIP, "incarnation", st.Incarnation())

	tick := time.NewTicker(resyncInterval)
	defer tick.Stop()
	for {
		if err := a.sync(ctx); err != nil && ctx.Err() == nil {
			slog.Error("sync", "err", err)
		}
		now := time.Now()
		a.mu.Lock()
		deadline, retry := a.operations.Deadline(now)
		a.mu.Unlock()
		var timer *time.Timer
		var retryC <-chan time.Time
		if retry {
			timer = time.NewTimer(deadline.Sub(now))
			retryC = timer.C
		}
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return nil
		case err := <-errc:
			if timer != nil {
				timer.Stop()
			}
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("export server: %w", err)
		case <-a.wake:
		case <-tick.C:
		case <-retryC:
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

func (a *Agent) kick() {
	select {
	case a.wake <- struct{}{}:
	default:
	}
}

func (a *Agent) fieldOwner() client.FieldOwner {
	return client.FieldOwner("blip-node/" + a.cfg.NodeName)
}

func (a *Agent) podsDir() string { return filepath.Join(a.cfg.DataDir, "pods") }

// registerNode creates this node's BlipNode and publishes its status.
func (a *Agent) registerNode(ctx context.Context) error {
	bn := &v1alpha1.BlipNode{ObjectMeta: metav1.ObjectMeta{Name: a.cfg.NodeName}}
	if err := a.client.Create(ctx, bn); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create BlipNode: %w", err)
	}
	return a.applyNodeStatus(ctx)
}

func (a *Agent) applyNodeStatus(ctx context.Context) error {
	now := metav1.Now()
	status := v1alpha1.BlipNodeStatus{
		Incarnation:  a.store.Incarnation(),
		TLSPublicKey: a.cfg.Identity.PublicKey(),
		Endpoint:     a.cfg.HostIP,
		Hypervisors:  hypervisors(),
		FreeBytes:    a.store.FreeBytes(),
		Heartbeat:    &now,
	}
	m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&status)
	if err != nil {
		return err
	}
	u := &unstructured.Unstructured{Object: map[string]any{"status": m}}
	u.SetGroupVersionKind(v1alpha1.GroupVersion.WithKind("BlipNode"))
	u.SetName(a.cfg.NodeName)
	return a.client.Status().Patch(ctx, u, client.Apply, a.fieldOwner(), client.ForceOwnership)
}

func hypervisors() []string {
	var hv []string
	// Only KVM has a runtime backend. Report nothing on nodes without it so
	// scheduling does not treat them as usable.
	if _, err := os.Stat("/dev/kvm"); err == nil {
		hv = append(hv, "kvm")
	}
	return hv
}

func (a *Agent) heartbeat(ctx context.Context) {
	t := time.NewTicker(heartbeatInterval)
	defer t.Stop()
	for {
		if err := a.applyNodeStatus(ctx); err != nil && ctx.Err() == nil {
			slog.Error("heartbeat", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (a *Agent) authorize(node string, req peer.ExportRequest) error {
	ctx := context.Background()
	var states v1alpha1.BlipStateList
	var blips v1alpha1.BlipList
	if err := a.client.List(ctx, &states); err != nil {
		return err
	}
	if err := a.client.List(ctx, &blips); err != nil {
		return err
	}
	all := ptrs(states.Items)
	// The cached list can lag a just-created state, and authorize treats a
	// missing copy source as deleted so an in-flight copy can finish after
	// its source is gone. Fill copy sources that the cache lacks from an
	// uncached read, or an unlabelled destination could read a labelled
	// source until the cache converges.
	seen := make(map[string]bool, len(all))
	for _, s := range all {
		seen[string(s.UID)] = true
	}
	for _, s := range all {
		cf := s.Status.CopiedFrom
		if cf == nil || cf.StateUID != req.StateUID || seen[cf.StateUID] || s.Spec.CopyFrom == "" {
			continue
		}
		// spec.copyFrom is immutable and names a state in the destination's
		// namespace.
		src := &v1alpha1.BlipState{}
		err := a.live.Get(ctx, client.ObjectKey{Namespace: s.Namespace, Name: s.Spec.CopyFrom}, src)
		switch {
		case apierrors.IsNotFound(err):
			// Genuinely deleted: keep the deleted-source allowance.
			continue
		case err != nil:
			// Forbidden or transient: do not guess that the source is gone.
			return fmt.Errorf("read copy source %s/%s: %w", s.Namespace, s.Spec.CopyFrom, err)
		case string(src.UID) != cf.StateUID:
			// The name was reused; this is not the source the copy recorded.
			// Fall through to the deleted-source allowance, which is no worse
			// than the cache-only behavior.
			continue
		}
		seen[cf.StateUID] = true
		all = append(all, src)
	}
	return authorize(all, ptrs(blips.Items), node, req)
}

func ptrs[T any](items []T) []*T {
	out := make([]*T, len(items))
	for i := range items {
		out[i] = &items[i]
	}
	return out
}

// syncPeers trusts nodes with a valid published identity, including draining
// nodes whose existing leases must remain usable. Trust changes take effect
// even if updating the firewall fails.
func (a *Agent) syncPeers(v *view) error {
	peers := v.registeredPeers()
	sort.Slice(peers, func(i, j int) bool { return peers[i].Node < peers[j].Node })
	a.cfg.Peers.SetPeers(peers)
	// The registry rejects ambiguous identities. Admit only those peers to
	// the firewall too; NewFirewall already includes this node's host IP.
	peers = slices.DeleteFunc(peers, func(p peer.Peer) bool {
		trusted, ok := a.cfg.Peers.Lookup(p.Node)
		return p.Node == a.cfg.NodeName || !ok || trusted != p
	})
	key := fmt.Sprint(peers)
	if key == a.lastPeers {
		return nil
	}
	if err := a.peers(peers); err != nil {
		return fmt.Errorf("set peer firewall: %w", err)
	}
	a.lastPeers = key
	return nil
}

// watchPodDirs triggers a pass whenever an observed.json changes.
func (a *Agent) watchPodDirs(ctx context.Context) {
	t := time.NewTicker(200 * time.Millisecond)
	defer t.Stop()
	last := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		sig := ""
		namespaces, _ := os.ReadDir(a.podsDir())
		for _, nsDir := range namespaces {
			if !nsDir.IsDir() {
				continue
			}
			entries, _ := os.ReadDir(filepath.Join(a.podsDir(), nsDir.Name()))
			for _, e := range entries {
				path := filepath.Join(a.podsDir(), nsDir.Name(), e.Name(), podapi.ObservedFile)
				if fi, err := os.Stat(path); err == nil {
					sig += fmt.Sprintf("%s/%s/%d/%d;", nsDir.Name(), e.Name(), fi.ModTime().UnixNano(), fi.Size())
				}
			}
		}
		if sig != last {
			last = sig
			a.kick()
		}
	}
}

type operationJob struct {
	what string
	run  func(context.Context) error
}

// runOperations is the I/O adapter for Scheduler. Admission happens for the
// whole pass before goroutines start, so completion order cannot change which
// jobs this pass admits or let cleanup overtake a reserved source.
func (a *Agent) runOperations(ctx context.Context, ops []Operation, jobs map[string]operationJob) {
	if ctx.Err() != nil {
		return
	}
	a.mu.Lock()
	attempts := a.operations.Schedule(time.Now(), ops)
	a.mu.Unlock()
	for _, attempt := range attempts {
		job := jobs[attempt.Operation.Key]
		key := attempt.Operation.Key
		jobCtx, cancel := context.WithCancel(ctx)
		a.mu.Lock()
		if a.opCancels == nil {
			a.opCancels = map[string]context.CancelFunc{}
		}
		a.opCancels[key] = cancel
		a.mu.Unlock()
		a.workers.Add(1)
		go func() {
			defer a.workers.Done()
			defer cancel()
			start := time.Now()
			slog.Info(job.what, "key", key)
			err := ctx.Err()
			if err == nil {
				err = job.run(jobCtx)
			}
			outcome := Succeeded
			if err != nil {
				outcome = Failed
				if ctx.Err() != nil || jobCtx.Err() != nil || errors.Is(err, context.Canceled) {
					outcome = Canceled
				}
			}
			a.mu.Lock()
			delete(a.opCancels, key)
			a.operations.Complete(time.Now(), attempt, outcome)
			a.mu.Unlock()
			if err != nil && ctx.Err() == nil {
				slog.Error(job.what, "key", attempt.Operation.Key, "err", err, "elapsed", time.Since(start).Round(time.Millisecond))
			} else if err == nil {
				slog.Info(job.what+" done", "key", attempt.Operation.Key, "elapsed", time.Since(start).Round(time.Millisecond))
			}
			a.kick()
		}()
	}
}

func (a *Agent) failures(key string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.operations.Failures(key)
}

// cancelGoneBuilds aborts operations for states confirmed absent by a live
// read: their storage will never be reported or used, so continuing a mkfs
// would only consume the thin pool. The storage layer kills the running tool
// and rolls back the volume.
func (a *Agent) cancelGoneBuilds(v *view) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for uid := range v.statesGone {
		if cancel := a.opCancels[stateKey(uid)]; cancel != nil {
			cancel()
		}
	}
}

func (a *Agent) setStateErr(uid string, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err == nil {
		delete(a.stateErrs, uid)
	} else if !errors.Is(err, context.Canceled) {
		a.stateErrs[uid] = err.Error()
	}
}

// referencedPodKeys returns the pods whose existence matters for this pass, by
// namespace-qualified key.
func referencedPodKeys(dirs map[string]*podDir, states []*v1alpha1.BlipState, node string) []string {
	var keys []string
	for key := range dirs {
		keys = append(keys, key)
	}
	for _, s := range states {
		if w := s.Status.Writer; w != nil && w.Node == node && w.PodName != "" {
			if key := podKey(s.Namespace, w.PodName); !slices.Contains(keys, key) {
				keys = append(keys, key)
			}
		}
	}
	slices.Sort(keys)
	return keys
}
