package gateway

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/gateway/menu"
)

const (
	catalogOwnerIndex = "owner"
	catalogStateIndex = "state"
)

// Catalog shares two namespace-wide informers across every menu session. Cached
// objects are only used for display; actions recheck ownership against the API.
type Catalog struct {
	states cache.SharedIndexInformer
	blips  cache.SharedIndexInformer
	once   sync.Once
	done   chan struct{}
	mu     sync.Mutex
	closed bool
	subs   map[string]map[chan struct{}]struct{}
}

// NewCatalog prepares the shared state and Blip informers. Call Start before
// serving menus, with the gateway's lifetime context.
func NewCatalog(kube client.WithWatch, namespace string) *Catalog {
	c := &Catalog{done: make(chan struct{}), subs: make(map[string]map[chan struct{}]struct{})}
	ownerIndex := func(obj any) ([]string, error) {
		return []string{obj.(client.Object).GetLabels()[ownerLabel]}, nil
	}
	c.states = cache.NewSharedIndexInformer(catalogListWatch(kube, namespace, func() client.ObjectList {
		return &v1alpha1.BlipStateList{}
	}), &v1alpha1.BlipState{}, 0, cache.Indexers{catalogOwnerIndex: ownerIndex})
	c.blips = cache.NewSharedIndexInformer(catalogListWatch(kube, namespace, func() client.ObjectList {
		return &v1alpha1.BlipList{}
	}), &v1alpha1.Blip{}, 0, cache.Indexers{
		catalogOwnerIndex: ownerIndex,
		catalogStateIndex: func(obj any) ([]string, error) {
			b := obj.(*v1alpha1.Blip)
			var names []string
			if b.Spec.State != "" {
				names = append(names, b.Spec.State)
			}
			for _, m := range b.Spec.Mounts {
				names = append(names, m.State)
			}
			for _, m := range b.Status.Mounts {
				names = append(names, m.State)
			}
			return names, nil
		},
	})
	handler := cache.ResourceEventHandlerFuncs{
		AddFunc: c.changed,
		UpdateFunc: func(old, next any) {
			// Relabeling can remove an entry from one owner's menu and add it
			// to another. Both subscriptions must be invalidated.
			c.changed(old)
			c.changed(next)
		},
		DeleteFunc: c.changed,
	}
	c.states.AddEventHandler(handler)
	c.blips.AddEventHandler(handler)
	return c
}

func catalogListWatch(kube client.WithWatch, namespace string, newList func() client.ObjectList) *cache.ListWatch {
	return &cache.ListWatch{
		ListWithContextFunc: func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
			list := newList()
			err := kube.List(ctx, list, &client.ListOptions{Namespace: namespace, Raw: &opts})
			return list, err
		},
		WatchFuncWithContext: func(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
			return kube.Watch(ctx, newList(), &client.ListOptions{Namespace: namespace, Raw: &opts})
		},
	}
}

// Start starts the informers once and waits for their initial lists. Their
// watches and subscription channels live until the first Start's context ends.
func (c *Catalog) Start(ctx context.Context) error {
	c.once.Do(func() {
		var wg sync.WaitGroup
		for _, informer := range []cache.SharedIndexInformer{c.states, c.blips} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				informer.RunWithContext(ctx)
			}()
		}
		go func() {
			wg.Wait()
			c.mu.Lock()
			defer c.mu.Unlock()
			c.closed = true
			for _, subs := range c.subs {
				for ch := range subs {
					close(ch)
				}
			}
			clear(c.subs)
			close(c.done)
		}()
	})
	if !cache.WaitForCacheSync(ctx.Done(), c.states.HasSynced, c.blips.HasSynced) {
		return fmt.Errorf("sync sandbox catalog: %w", ctx.Err())
	}
	return nil
}

func (c *Catalog) changed(obj any) {
	if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = tombstone.Obj
	}
	if tombstone, ok := obj.(*cache.DeletedFinalStateUnknown); ok && tombstone != nil {
		obj = tombstone.Obj
	}
	o, ok := obj.(client.Object)
	if !ok {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for ch := range c.subs[o.GetLabels()[ownerLabel]] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// Subscribe coalesces changes into one pending notification per subscription.
// Cancel is idempotent and safe to call concurrently with informer callbacks.
func (c *Catalog) Subscribe(owner string) (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	c.mu.Lock()
	if c.closed {
		close(ch)
	} else {
		if c.subs[owner] == nil {
			c.subs[owner] = make(map[chan struct{}]struct{})
		}
		c.subs[owner][ch] = struct{}{}
	}
	c.mu.Unlock()
	return ch, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if _, ok := c.subs[owner][ch]; ok {
			delete(c.subs[owner], ch)
			close(ch)
			if len(c.subs[owner]) == 0 {
				delete(c.subs, owner)
			}
		}
	}
}

func ownedResource(obj client.Object, owner string) bool {
	// Existing CLI workers and states can predate owner-prefixed naming. The
	// live owner label is authoritative; only creation imposes the prefix.
	return owner != "" && obj.GetLabels()[ownerLabel] == owner
}

func stateEntry(st *v1alpha1.BlipState, owner string) menu.Entry {
	return menu.Entry{ID: st.Name, UID: string(st.UID), Name: strings.TrimPrefix(st.Name, owner+".")}
}

// List returns only this owner's states, including CLI-created copies. Missing
// or inaccessible parents leave their children at the top level.
func (c *Catalog) List(owner string) ([]menu.Entry, error) {
	if !c.states.HasSynced() || !c.blips.HasSynced() {
		return nil, fmt.Errorf("sandbox catalog is not ready")
	}
	select {
	case <-c.done:
		return nil, fmt.Errorf("sandbox catalog is stopped")
	default:
	}
	objects, err := c.states.GetIndexer().ByIndex(catalogOwnerIndex, owner)
	if err != nil {
		return nil, err
	}
	states := make(map[string]*v1alpha1.BlipState, len(objects))
	for _, obj := range objects {
		st := obj.(*v1alpha1.BlipState)
		if ownedResource(st, owner) && st.DeletionTimestamp == nil {
			states[st.Name] = st
		}
	}
	entries := make([]menu.Entry, 0, len(states))
	for _, st := range states {
		e := stateEntry(st, owner)
		if parent := states[st.Spec.CopyFrom]; parent != nil && parent.Name != st.Name {
			e.Parent = parent.Name
		}
		blips, err := c.blips.GetIndexer().ByIndex(catalogStateIndex, st.Name)
		if err != nil {
			return nil, err
		}
		for _, obj := range blips {
			b := obj.(*v1alpha1.Blip)
			if ownedResource(b, owner) && runningBlip(b) && stateAttached(b, st) {
				e.Running = true
				break
			}
		}
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	return entries, nil
}

func runningBlip(b *v1alpha1.Blip) bool {
	return b.DeletionTimestamp == nil && !b.Spec.Stop && b.Status.Phase == v1alpha1.BlipRunning
}

// writesState describes desired use, including mounts that have not attached
// yet. Such a worker must be waited for rather than replaced by a new sandbox.
func writesState(b *v1alpha1.Blip, st *v1alpha1.BlipState) bool {
	if b.Spec.State == st.Name {
		return true
	}
	for _, m := range b.Spec.Mounts {
		if m.State == st.Name && m.Writable {
			return true
		}
	}
	return false
}

// stateAttached confirms that the selected filesystem is available in this
// worker. A Running Blip can still be acquiring or unmounting a dynamic mount.
func stateAttached(b *v1alpha1.Blip, st *v1alpha1.BlipState) bool {
	if !writesState(b, st) {
		return false
	}
	w := st.Status.Writer
	if w != nil && (w.BlipName != b.Name || w.BlipUID != string(b.UID)) {
		return false
	}
	if b.Spec.State == st.Name {
		return b.Status.RootAttachmentID == "" || w != nil && w.AttachmentID == b.Status.RootAttachmentID
	}
	m := selectedMountStatus(b, st)
	return m != nil && m.StateUID != "" && m.StateUID == string(st.UID) && m.Phase == v1alpha1.MountMounted
}

// selectedMountStatus ignores an old path, access mode, or state incarnation.
// A failed acquisition can have no UID yet, so callers deciding readiness must
// additionally require the selected UID, while errors can still be surfaced.
func selectedMountStatus(b *v1alpha1.Blip, st *v1alpha1.BlipState) *v1alpha1.MountStatus {
	if b.Spec.State == st.Name {
		return nil
	}
	for _, desired := range b.Spec.Mounts {
		if desired.State != st.Name || !desired.Writable {
			continue
		}
		for i := range b.Status.Mounts {
			m := &b.Status.Mounts[i]
			if m.State == st.Name && m.Path == desired.Path && m.Writable == desired.Writable &&
				(m.StateUID == "" || m.StateUID == string(st.UID)) {
				return m
			}
		}
	}
	return nil
}
