package node

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/image"
	"github.com/Azure/blip/internal/network"
	"github.com/Azure/blip/internal/podapi"
	"github.com/Azure/blip/internal/storage"
)

// sync runs one pass.
func (a *Agent) sync(ctx context.Context) error {
	v, err := a.snapshot(ctx)
	if err != nil {
		return err
	}
	peerErr := a.syncPeers(v)
	p := compute(v)
	a.execute(ctx, v, p)
	return peerErr
}

func (a *Agent) snapshot(ctx context.Context) (*view, error) {
	var states v1alpha1.BlipStateList
	var blips v1alpha1.BlipList
	var nodes v1alpha1.BlipNodeList
	var pools v1alpha1.BlipPoolList
	var pods corev1.PodList
	var kubeNodes corev1.NodeList
	var namespaces corev1.NamespaceList
	var services corev1.ServiceList
	var endpoints discoveryv1.EndpointSliceList
	for _, l := range []client.ObjectList{&states, &blips, &nodes, &pools, &pods, &kubeNodes, &namespaces, &services, &endpoints} {
		if err := a.client.List(ctx, l); err != nil {
			return nil, err
		}
	}
	v := &view{
		node:        a.cfg.NodeName,
		incarnation: a.store.Incarnation(),
		blipNodes:   map[string]*v1alpha1.BlipNode{},
		kubeNodes:   map[string]*corev1.Node{},
		pools:       map[string]*v1alpha1.BlipPool{},
		states:      ptrs(states.Items),
		blips:       ptrs(blips.Items),
		pods:        map[string]*corev1.Pod{},
		dirs:        readPodDirs(a.podsDir()),
		volumes:     map[string]storage.Volume{},
		devices:     map[string]uint64{},
		configs:     map[string]*image.Config{},
		pinned:      a.pinned,
		destinations: network.Destinations{
			Pods: pods.Items, Namespaces: namespaces.Items,
			Services: services.Items, EndpointSlices: endpoints.Items,
		},
	}
	for i := range nodes.Items {
		v.blipNodes[nodes.Items[i].Name] = &nodes.Items[i]
	}
	for i := range kubeNodes.Items {
		v.kubeNodes[kubeNodes.Items[i].Name] = &kubeNodes.Items[i]
	}
	for i := range pools.Items {
		p := &pools.Items[i]
		v.pools[p.Namespace+"/"+p.Name] = p
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Spec.NodeName == a.cfg.NodeName && pod.Labels[LabelPool] != "" {
			v.pods[podKey(pod.Namespace, pod.Name)] = pod
		}
	}
	for _, vol := range a.store.List() {
		v.volumes[vol.ID] = vol
		if vol.Device != "" {
			var st unix.Stat_t
			if unix.Stat(vol.Device, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFBLK {
				v.devices[vol.ID] = uint64(st.Rdev)
			}
		}
	}
	for _, s := range v.states {
		a.loadConfig(v, s.Status.ImageDigest)
	}
	for _, b := range v.blips {
		a.loadConfig(v, b.Status.ImageDigest)
	}
	a.confirmGone(ctx, v)
	a.confirmBlipsGone(ctx, v)

	a.mu.Lock()
	defer a.mu.Unlock()
	v.busy = clone(a.busy)
	v.freezes = clone(a.freezes)
	v.sealErrs = clone(a.sealErrs)
	v.stateErrs = clone(a.stateErrs)
	v.progress = clone(a.progress)
	v.podsGone = clone(a.podsGone)
	v.statesGone = clone(a.statesGone)
	v.blipsGone = clone(a.blipsGone)
	v.idleImages = a.idleImages(v, time.Now())
	return v, nil
}

// imageRetention is how long an unreferenced image stays cached, so repeated
// runs of the same image do not import it again.
const imageRetention = time.Hour

// idleImages returns the cached images nothing has referenced for
// imageRetention. Callers hold a.mu.
func (a *Agent) idleImages(v *view, now time.Time) map[string]bool {
	for _, ref := range v.imageRefs() {
		if id, err := image.DigestOf(ref.Ref); err == nil {
			a.imageUsed[id] = now
		}
	}
	idle := map[string]bool{}
	for id, vol := range v.volumes {
		if vol.Kind != storage.KindImage {
			continue
		}
		used, ok := a.imageUsed[id]
		if !ok {
			a.imageUsed[id] = now // first seen since the agent started
		} else if now.Sub(used) > imageRetention {
			idle[id] = true
		}
	}
	return idle
}

func clone[K comparable, V any](m map[K]V) map[K]V {
	out := make(map[K]V, len(m))
	for k, x := range m {
		out[k] = x
	}
	return out
}

func (a *Agent) configPath(id string) string {
	return filepath.Join(a.cfg.DataDir, "images", id+".json")
}

func (a *Agent) loadConfig(v *view, ref string) {
	id, err := image.DigestOf(ref)
	if err != nil {
		return
	}
	a.mu.Lock()
	cfg := a.configs[id]
	a.mu.Unlock()
	if cfg == nil {
		var c image.Config
		if podapi.ReadJSON(a.configPath(id), &c) != nil {
			return
		}
		cfg = &c
		a.mu.Lock()
		a.configs[id] = cfg
		a.mu.Unlock()
	}
	v.configs[id] = cfg
}

// confirmGone checks with live reads whether pods and states that the caches
// do not show really are gone. Destructive decisions (removing a pod
// directory, sealing because a pod vanished, deleting a state's commits) rely
// on these confirmations, never on the cache alone.
func (a *Agent) confirmGone(ctx context.Context, v *view) {
	var missingPods []string
	referenced := map[string]bool{}
	for _, key := range referencedPodKeys(v.dirs, v.states, v.node) {
		referenced[key] = true
		if v.pods[key] == nil {
			missingPods = append(missingPods, key)
		}
	}
	stateUIDs := map[string]bool{}
	for _, s := range v.states {
		stateUIDs[string(s.UID)] = true
	}
	var missingStates []string
	for _, vol := range v.volumes {
		if vol.StateUID != "" && !stateUIDs[vol.StateUID] {
			missingStates = append(missingStates, vol.StateUID)
		}
	}

	a.mu.Lock()
	needPods := false
	for _, n := range missingPods {
		needPods = needPods || !a.podsGone[n]
	}
	for n := range a.podsGone {
		if !referenced[n] {
			delete(a.podsGone, n)
		}
	}
	needStates := false
	for _, uid := range missingStates {
		needStates = needStates || !a.statesGone[uid]
	}
	now := time.Now()
	readPods := needPods && now.Sub(a.lastPodRead) > liveReadInterval
	readStates := needStates && now.Sub(a.lastStateRd) > liveReadInterval
	if readPods {
		a.lastPodRead = now
	}
	if readStates {
		a.lastStateRd = now
	}
	a.mu.Unlock()

	if readPods {
		var live corev1.PodList
		if err := a.live.List(ctx, &live, client.MatchingFields{"spec.nodeName": v.node}); err == nil {
			present := map[string]bool{}
			for _, p := range live.Items {
				present[podKey(p.Namespace, p.Name)] = true
			}
			a.mu.Lock()
			for _, key := range missingPods {
				if !present[key] {
					a.podsGone[key] = true
				}
			}
			a.mu.Unlock()
		}
	}
	if readStates {
		var live v1alpha1.BlipStateList
		if err := a.live.List(ctx, &live); err == nil {
			present := map[string]bool{}
			for _, s := range live.Items {
				present[string(s.UID)] = true
			}
			a.mu.Lock()
			for _, uid := range missingStates {
				if !present[uid] {
					a.statesGone[uid] = true
				}
			}
			a.mu.Unlock()
		}
	}
}

// confirmBlipsGone checks with a live read whether the Blip that claimed a
// pod is gone, so a lagging Blip cache never stops a freshly claimed VM.
func (a *Agent) confirmBlipsGone(ctx context.Context, v *view) {
	known := map[string]bool{}
	for _, b := range v.blips {
		known[string(b.UID)] = true
	}
	for _, pod := range v.pods {
		uid := pod.Labels[LabelBlipUID]
		if uid == "" || known[uid] {
			continue
		}
		a.mu.Lock()
		skip := a.blipsGone[uid] || time.Since(a.lastBlipRead[uid]) < liveReadInterval
		if !skip {
			a.lastBlipRead[uid] = time.Now()
		}
		a.mu.Unlock()
		if skip {
			continue
		}
		var b v1alpha1.Blip
		err := a.live.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: pod.Annotations[AnnotationBlip]}, &b)
		if apierrors.IsNotFound(err) || (err == nil && string(b.UID) != uid) {
			a.mu.Lock()
			a.blipsGone[uid] = true
			delete(a.lastBlipRead, uid)
			a.mu.Unlock()
		}
	}
}

func readPodDirs(root string) map[string]*podDir {
	dirs := map[string]*podDir{}
	namespaces, _ := os.ReadDir(root)
	for _, nsDir := range namespaces {
		if !nsDir.IsDir() {
			continue
		}
		nsRoot := filepath.Join(root, nsDir.Name())
		pods, _ := os.ReadDir(nsRoot)
		for _, e := range pods {
			if !e.IsDir() {
				continue
			}
			path := filepath.Join(nsRoot, e.Name())
			d := &podDir{devs: map[string]uint64{}}
			var obs podapi.Observed
			if podapi.ReadJSON(filepath.Join(path, podapi.ObservedFile), &obs) == nil {
				d.observed = &obs
			}
			var des podapi.Desired
			if podapi.ReadJSON(filepath.Join(path, podapi.DesiredFile), &des) == nil {
				d.desired = &des
			}
			devs, _ := os.ReadDir(filepath.Join(path, podapi.DevDir))
			for _, dev := range devs {
				var st unix.Stat_t
				if unix.Lstat(filepath.Join(path, podapi.DevDir, dev.Name()), &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFBLK {
					d.devs[dev.Name()] = uint64(st.Rdev)
				} else {
					d.devs[dev.Name()] = 0
				}
			}
			dirs[podKey(nsDir.Name(), e.Name())] = d
		}
	}
	return dirs
}

// mknodDevice creates (or replaces) path as a block device node with the
// same device number as device.
func mknodDevice(path, device string) error {
	var st unix.Stat_t
	if err := unix.Stat(device, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFBLK {
		return &os.PathError{Op: "mknod", Path: device, Err: unix.ENOTBLK}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	var cur unix.Stat_t
	if unix.Lstat(path, &cur) == nil {
		if cur.Mode&unix.S_IFMT == unix.S_IFBLK && cur.Rdev == st.Rdev {
			return nil
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	if err := unix.Mknod(path, unix.S_IFBLK|0o660, int(st.Rdev)); err != nil {
		return &os.PathError{Op: "mknod", Path: path, Err: err}
	}
	return os.Chmod(path, 0o660)
}
