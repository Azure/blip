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
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/image"
	"github.com/Azure/blip/internal/peer"
	"github.com/Azure/blip/internal/podapi"
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
	// and every reconnecting SSH command waits for the backlog.
	sealConcurrency = 4
)

// Agent is the node agent.
type Agent struct {
	cfg    Config
	client client.Client // reads come from the informer cache
	live   client.Reader // uncached reads
	store  Store
	open   func(ctx context.Context, node string, req peer.ExportRequest) (storage.Remote, error)
	pull   func(ctx context.Context, ref string, secrets []pullSecret, dir string) (image.Config, string, error)
	mknod  func(path, device string) error
	pinned func(commitID string) bool
	peers  func([]peer.Peer) error // update the firewall after publishing trust
	wake   chan struct{}
	images chan struct{} // bounds concurrent image imports and builds
	seals  chan struct{} // bounds concurrent state saves (disk sync)

	mu           sync.Mutex
	busy         map[string]bool
	freezes      map[string][]string // podKey -> disk IDs to keep frozen
	retry        map[string]*retry
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

type retry struct {
	fails int
	next  time.Time
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
		images:     make(chan struct{}, imageConcurrency),
		seals:      make(chan struct{}, sealConcurrency),
		busy:       map[string]bool{},
		freezes:    map[string][]string{},
		retry:      map[string]*retry{},
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
	return a
}

// pullImage pulls ref using credentials from the given image pull secrets.
func (a *Agent) pullImage(ctx context.Context, ref string, secrets []pullSecret, dir string) (image.Config, string, error) {
	kc, err := imageKeychain(ctx, a.live, secrets)
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
	}()
	go a.watchPodDirs(ctx)
	slog.Info("node agent running", "node", cfg.NodeName, "endpoint", cfg.HostIP, "incarnation", st.Incarnation())

	tick := time.NewTicker(resyncInterval)
	defer tick.Stop()
	for {
		if err := a.sync(ctx); err != nil && ctx.Err() == nil {
			slog.Error("sync", "err", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case err := <-errc:
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("export server: %w", err)
		case <-a.wake:
		case <-tick.C:
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
	return authorize(ptrs(states.Items), ptrs(blips.Items), node, req)
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

// spawn runs fn in the background unless one of keys is busy or the first
// key is backing off after a failure.
func (a *Agent) spawn(ctx context.Context, what string, keys []string, fn func(context.Context) error) {
	a.mu.Lock()
	for _, k := range keys {
		if a.busy[k] {
			a.mu.Unlock()
			return
		}
	}
	if r := a.retry[keys[0]]; r != nil && time.Now().Before(r.next) {
		a.mu.Unlock()
		return
	}
	for _, k := range keys {
		a.busy[k] = true
	}
	a.mu.Unlock()
	go func() {
		start := time.Now()
		slog.Info(what, "key", keys[0])
		err := fn(ctx)
		a.mu.Lock()
		for _, k := range keys {
			delete(a.busy, k)
		}
		if err != nil {
			r := a.retry[keys[0]]
			if r == nil {
				r = &retry{}
				a.retry[keys[0]] = r
			}
			r.fails++
			r.next = time.Now().Add(min(time.Second<<min(r.fails, 7), 2*time.Minute))
		} else {
			delete(a.retry, keys[0])
		}
		a.mu.Unlock()
		if err != nil && ctx.Err() == nil {
			slog.Error(what, "key", keys[0], "err", err, "elapsed", time.Since(start).Round(time.Millisecond))
		} else if err == nil {
			slog.Info(what+" done", "key", keys[0], "elapsed", time.Since(start).Round(time.Millisecond))
		}
		a.kick()
	}()
}

func (a *Agent) failures(key string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	if r := a.retry[key]; r != nil {
		return r.fails
	}
	return 0
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
	return keys
}
