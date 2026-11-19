package node

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/devnode"
	"github.com/Azure/blip/internal/image"
	"github.com/Azure/blip/internal/peer"
	"github.com/Azure/blip/internal/podapi"
	"github.com/Azure/blip/internal/registryauth"
	"github.com/Azure/blip/internal/storage"
)

// maxSealAttempts bounds retries of a seal that fails for a reason other than
// an unclean filesystem before the failure is reported.
const maxSealAttempts = 5

// freezeTimeout bounds the wait for the guest to freeze a live copy's
// filesystem, which includes writing back its dirty data.
const freezeTimeout = 60 * time.Second

// errPodGone means the VM pod disappeared while a live copy waited for it.
// The copy cannot capture the source, but the controller can still fall back
// to the source's last committed version, so this is not a state failure.
// errPodStopping means the source's guest is shutting down and may never
// acknowledge a freeze again; the same fallback applies.
var (
	errPodGone     = errors.New("VM pod is gone")
	errPodStopping = errors.New("VM pod is stopping")
)

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
	return devnode.Ensure(path, st.Rdev)
}

func (a *Agent) execute(ctx context.Context, v *view, p *plan) {
	for _, key := range sortedKeys(p.desired) {
		d := p.desired[key]
		path := filepath.Join(a.podDirFor(key), podapi.DesiredFile)
		if err := podapi.EnsurePodDir(filepath.Dir(path)); err != nil {
			slog.Error("write desired", "pod", key, "err", err)
			continue
		}
		if err := podapi.WriteJSON(path, d); err != nil {
			slog.Error("write desired", "pod", key, "err", err)
		}
	}
	for _, m := range p.podMeta {
		if err := a.patchPod(ctx, m); err != nil {
			slog.Error("update pod", "pod", m.name, "err", err)
		}
	}
	for _, e := range p.podErrs {
		if err := a.patchPrepareError(ctx, e.pod, e.err); err != nil {
			slog.Error("update prepare error", "pod", e.pod, "err", err)
		}
	}
	jobs := map[string]operationJob{}
	add := func(key, what string, run func(context.Context) error) {
		if _, exists := jobs[key]; !exists {
			jobs[key] = operationJob{what: what, run: run}
		}
	}
	for _, pr := range p.prepares {
		add(pr.req.AttachmentID, "prepare disk", func(ctx context.Context) error {
			err := a.prepare(ctx, v, pr)
			a.reportPrepare(ctx, pr, err)
			return err
		})
	}
	for _, s := range p.seals {
		add(s.attachmentID, "seal", func(ctx context.Context) error {
			return a.seal(ctx, s)
		})
	}
	for _, imp := range p.imports {
		id, _ := image.DigestOf(imp.ref)
		add(id, "import image", func(ctx context.Context) error {
			err := a.importImage(ctx, imp.ref, id, imp.secrets)
			a.setStateErr(imageKey(id), err)
			return err
		})
	}
	for _, b := range p.builds {
		add(stateKey(b.req.StateUID), "build commit", func(ctx context.Context) error {
			err := a.store.CreateCommit(ctx, b.req)
			a.setStateErr(b.req.StateUID, err)
			return err
		})
	}
	for _, id := range p.digests {
		add(digestKey(id), "digest commit", func(ctx context.Context) error {
			_, err := a.store.Digest(ctx, id)
			return err
		})
	}
	for _, lc := range p.liveCopies {
		add(stateKey(lc.stateUID), "live copy", func(ctx context.Context) error {
			err := a.liveCopy(ctx, lc)
			a.setStateErr(lc.stateUID, err)
			return err
		})
	}
	for _, f := range p.fetches {
		add(stateKey(f.owner), "fetch commit", func(ctx context.Context) error {
			return a.fetch(ctx, f)
		})
	}
	a.runOperations(ctx, p.operations(), jobs)
	deleted := false
	for _, id := range p.deletes {
		err := a.store.Delete(ctx, id)
		switch {
		case err == nil:
			slog.Info("deleted volume", "id", id)
			deleted = true
		case errors.Is(err, storage.ErrPinned), errors.Is(err, storage.ErrInUse), errors.Is(err, storage.ErrNotFound):
		default:
			slog.Error("delete volume", "id", id, "err", err)
		}
	}
	for _, d := range p.rmDevs {
		if err := os.Remove(filepath.Join(a.podDirFor(d.pod), podapi.DevDir, d.id)); err != nil && !os.IsNotExist(err) {
			slog.Error("remove device node", "pod", d.pod, "id", d.id, "err", err)
		}
	}
	for _, key := range p.rmDirs {
		slog.Info("removing pod directory", "pod", key)
		if err := os.RemoveAll(a.podDirFor(key)); err != nil {
			slog.Error("remove pod directory", "pod", key, "err", err)
		}
	}
	for _, e := range p.entries {
		if err := a.applyEntry(ctx, e); err != nil && !apierrors.IsNotFound(err) {
			slog.Error("report state", "state", e.namespace+"/"+e.name, "err", err)
		}
	}
	a.pruneErrors(v, p)
	if deleted || len(p.rmDevs) > 0 {
		a.kick()
	}
}

// reportPrepare records the outcome of preparing a pod's disk: a failure is
// shown on the pod and on the state, a success clears the pod annotation.
func (a *Agent) reportPrepare(ctx context.Context, pr prepare, err error) {
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		if e := a.patchPrepareError(ctx, pr.pod, prepareErrText(err)); e != nil {
			slog.Error("update prepare error", "pod", pr.pod, "err", e)
		}
		if pr.req.StateUID != "" {
			a.setStateErr(pr.req.StateUID, err)
		}
		return
	}
	if e := a.patchPrepareError(ctx, pr.pod, ""); e != nil {
		slog.Error("clear prepare error", "pod", pr.pod, "err", e)
	}
}

// maxPrepareErr bounds the size of an error annotation.
const maxPrepareErr = 512

func prepareErrText(err error) string {
	msg := err.Error()
	if len(msg) > maxPrepareErr {
		msg = msg[:maxPrepareErr]
	}
	return msg
}

// patchPrepareError sets (value non-empty) or clears the prepare-error
// annotation of a pod.
func (a *Agent) patchPrepareError(ctx context.Context, key, value string) error {
	namespace, name, ok := strings.Cut(key, "/")
	if !ok {
		return nil
	}
	var pod corev1.Pod
	if err := a.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &pod); err != nil {
		return client.IgnoreNotFound(err)
	}
	if cur := pod.Annotations[v1alpha1.AnnotationPrepareError]; cur == value {
		return nil
	}
	orig := pod.DeepCopy()
	if value == "" {
		delete(pod.Annotations, v1alpha1.AnnotationPrepareError)
	} else {
		if pod.Annotations == nil {
			pod.Annotations = map[string]string{}
		}
		pod.Annotations[v1alpha1.AnnotationPrepareError] = value
	}
	return client.IgnoreNotFound(a.client.Patch(ctx, &pod, client.MergeFrom(orig)))
}

// pruneErrors forgets state errors once the state needs no build or fetch
// from this node, image errors once nothing references the image, and seal
// errors once no writer slot names the attachment.
func (a *Agent) pruneErrors(v *view, p *plan) {
	relevant := map[string]bool{}
	for _, b := range p.builds {
		relevant[b.req.StateUID] = true
	}
	for _, f := range p.fetches {
		relevant[f.owner] = true
	}
	for _, lc := range p.liveCopies {
		relevant[lc.stateUID] = true
	}
	for _, pr := range p.prepares {
		if pr.req.StateUID != "" {
			relevant[pr.req.StateUID] = true
		}
	}
	for _, ref := range v.imageRefs() {
		if id, err := image.DigestOf(ref.Ref); err == nil {
			relevant[imageKey(id)] = true
		}
	}
	writers := map[string]bool{}
	for _, s := range v.states {
		if w := s.Status.Writer; w != nil && w.Node == v.node {
			writers[w.AttachmentID] = true
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	busy := a.operations.Busy()
	for uid := range a.stateErrs {
		if !relevant[uid] && !busy[stateKey(uid)] {
			delete(a.stateErrs, uid)
		}
	}
	for id := range a.sealErrs {
		if !writers[id] && !busy[id] {
			delete(a.sealErrs, id)
		}
	}
}

func (a *Agent) patchPod(ctx context.Context, m podMeta) error {
	var pod corev1.Pod
	if err := a.client.Get(ctx, client.ObjectKey{Namespace: m.namespace, Name: m.name}, &pod); err != nil {
		return client.IgnoreNotFound(err)
	}
	orig := pod.DeepCopy()
	if m.warm {
		if pod.Labels == nil {
			pod.Labels = map[string]string{}
		}
		pod.Labels[v1alpha1.LabelWarm] = "true"
	} else {
		delete(pod.Labels, v1alpha1.LabelWarm)
	}
	if m.observed != "" {
		if pod.Annotations == nil {
			pod.Annotations = map[string]string{}
		}
		pod.Annotations[v1alpha1.AnnotationObserved] = m.observed
	}
	return client.IgnoreNotFound(a.client.Patch(ctx, &pod, client.MergeFrom(orig)))
}

// applyEntry server-side applies this node's status.nodes entry of a state.
// Applying an empty list removes the entry.
func (a *Agent) applyEntry(ctx context.Context, e entry) error {
	nodes := []any{}
	if e.obs != nil {
		m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(e.obs)
		if err != nil {
			return err
		}
		nodes = append(nodes, m)
	}
	u := &unstructured.Unstructured{Object: map[string]any{"status": map[string]any{"nodes": nodes}}}
	u.SetGroupVersionKind(v1alpha1.GroupVersion.WithKind("BlipState"))
	u.SetNamespace(e.namespace)
	u.SetName(e.name)
	return a.client.Status().Patch(ctx, u, client.Apply, a.fieldOwner(), client.ForceOwnership)
}

func (a *Agent) exportRequest(ctx context.Context, src source) peer.ExportRequest {
	req := peer.ExportRequest{
		StateUID: src.stateUID,
		CommitID: src.commitID,
		Purpose:  src.purpose,
		Bases:    src.bases,
		HostNQN:  peer.HostNQN(a.cfg.NodeName),
	}
	for _, id := range src.imageBases {
		// Usually computed already (see planDigests); a missing base only
		// costs a larger transfer.
		d, err := a.store.Digest(ctx, id)
		if err != nil {
			slog.Warn("digest delta base", "commit", id, "err", err)
			continue
		}
		if req.BaseDigests == nil {
			req.BaseDigests = map[string]string{}
		}
		req.BaseDigests[id] = d
	}
	return req
}

// openRemote asks src to export its commit. The returned release is safe to
// call more than once, so it can be called on failure even if the store
// already did.
func (a *Agent) openRemote(ctx context.Context, src source) (storage.Remote, func(), error) {
	remote, err := a.open(ctx, src.node, a.exportRequest(ctx, src))
	if err != nil {
		return storage.Remote{}, nil, fmt.Errorf("export %s from %s: %w", src.commitID, src.node, err)
	}
	release := remote.Release
	if release == nil {
		release = func() {}
	}
	remote.Release = sync.OnceFunc(release)
	return remote, remote.Release, nil
}

func (a *Agent) prepare(ctx context.Context, v *view, pr prepare) error {
	id := pr.req.AttachmentID
	var dev string
	if pr.exists {
		dev = v.volumes[id].Device
		if dev == "" {
			// The volume is ready but the snapshot did not see its device
			// (it may have been sampled while the volume was still being
			// created, or the device may be gone). The store recreates a
			// missing device; Activate is bounded and idempotent.
			var err error
			dev, err = a.store.Activate(id)
			if err != nil {
				return fmt.Errorf("reactivate working volume %s: %w", id, err)
			}
			slog.Info("reactivated working volume", "id", id, "pod", pr.pod)
		}
	} else {
		req := pr.req
		var release func()
		if pr.src != nil {
			remote, rel, err := a.openRemote(ctx, *pr.src)
			if err != nil {
				return err
			}
			req.Remote, release = &remote, rel
		}
		var err error
		dev, err = a.store.CreateWorking(ctx, req)
		if err != nil {
			if release != nil {
				release()
			}
			return err
		}
		slog.Info("created working volume", "id", id, "pod", pr.pod)
	}
	return a.mknod(filepath.Join(a.podDirFor(pr.pod), podapi.DevDir, id), dev)
}

func (a *Agent) seal(ctx context.Context, s seal) error {
	size, err := a.store.Seal(ctx, s.attachmentID, s.commitID)
	if err == nil {
		slog.Info("sealed", "attachment", s.attachmentID, "commit", s.commitID, "size", size)
		return nil
	}
	if ctx.Err() != nil || errors.Is(err, context.Canceled) {
		return err
	}
	// A disk that is still open means the VMM may still write: never
	// give up on it, keep the writer reserved and retry. A record conflict
	// (ErrConflict) is not an open disk, so it falls through to the bounded
	// path and is reported instead of blocking the save forever.
	if !errors.Is(err, storage.ErrInUse) && (errors.Is(err, storage.ErrUnclean) || a.failures(s.attachmentID) >= maxSealAttempts-1) {
		slog.Error("seal failed; not saving", "attachment", s.attachmentID, "err", err)
		a.mu.Lock()
		a.sealErrs[s.attachmentID] = err.Error()
		a.mu.Unlock()
		return nil
	}
	return err
}

// liveCopy has the guest freeze the source filesystem, snapshots the
// attachment into the copy's commit, and thaws it again.
func (a *Agent) liveCopy(ctx context.Context, lc liveCopy) error {
	// A pod that is already gone cannot be frozen. Abandon the copy instead
	// of waiting for the freeze timeout; its attachment is about to seal and
	// the controller will copy the resulting committed version.
	if podGone(a.podDirFor(lc.pod)) {
		slog.Info("live copy abandoned; pod is gone", "pod", lc.pod, "attachment", lc.attachmentID, "state", lc.stateUID)
		return nil
	}
	// observed.json may still report the freeze of a previous copy of
	// this attachment; wait for its thaw so it isn't taken as ours. The
	// freeze is requested only after this wait, so waiting copies never hold
	// a reference that would prevent the guest from thawing.
	if err := a.waitFrozen(ctx, lc.pod, lc.attachmentID, false); err != nil {
		if errors.Is(err, errPodGone) || errors.Is(err, errPodStopping) {
			slog.Info("live copy abandoned; source pod is gone or stopping", "pod", lc.pod, "attachment", lc.attachmentID, "state", lc.stateUID)
			return nil
		}
		return err
	}
	a.setFreeze(lc.pod, lc.attachmentID, true)
	defer a.setFreeze(lc.pod, lc.attachmentID, false)
	if err := a.waitFrozen(ctx, lc.pod, lc.attachmentID, true); err != nil {
		if errors.Is(err, errPodGone) || errors.Is(err, errPodStopping) {
			slog.Info("live copy abandoned; source pod is gone or stopping", "pod", lc.pod, "attachment", lc.attachmentID, "state", lc.stateUID)
			return nil
		}
		return err
	}
	size, err := a.store.LiveCopy(ctx, lc.attachmentID, lc.commitID, lc.stateUID)
	if err != nil {
		return fmt.Errorf("live copy of %s: %w", lc.attachmentID, err)
	}
	slog.Info("live copied", "attachment", lc.attachmentID, "commit", lc.commitID, "state", lc.stateUID, "size", size)
	return nil
}

// setFreeze adds or removes one request to keep a disk of pod's guest frozen
// and wakes a pass to write desired.json. Requests are reference-counted:
// concurrent live copies of the same writer share one desired freeze, which is
// cleared only when the last copy releases it.
func (a *Agent) setFreeze(pod, id string, on bool) {
	a.mu.Lock()
	refs := a.freezeRefs[pod]
	changed := false
	switch {
	case on:
		if refs == nil {
			refs = map[string]int{}
		}
		refs[id]++
		changed = true
	case refs[id] > 0:
		refs[id]--
		if refs[id] == 0 {
			delete(refs, id)
		}
		changed = true
	}
	if changed {
		if len(refs) == 0 {
			delete(a.freezeRefs, pod)
			delete(a.freezes, pod)
		} else {
			a.freezeRefs[pod] = refs
			ids := make([]string, 0, len(refs))
			for x := range refs {
				ids = append(ids, x)
			}
			slices.Sort(ids)
			a.freezes[pod] = ids
		}
	}
	a.mu.Unlock()
	if changed {
		a.kick()
	}
}

// podGone reports whether the pod's host directory has been removed, which
// happens when the node reaps a deleted pod.
func podGone(dir string) bool {
	_, err := os.Stat(dir)
	return errors.Is(err, os.ErrNotExist)
}

// waitFrozen waits until the runtime reports id frozen (or not) in
// observed.json.
func (a *Agent) waitFrozen(ctx context.Context, pod, id string, frozen bool) error {
	ctx, cancel := context.WithTimeout(ctx, freezeTimeout)
	defer cancel()
	path := filepath.Join(a.podDirFor(pod), podapi.ObservedFile)
	desired := filepath.Join(a.podDirFor(pod), podapi.DesiredFile)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		if podGone(a.podDirFor(pod)) {
			return fmt.Errorf("%s: %w", pod, errPodGone)
		}
		var des podapi.Desired
		if podapi.ReadJSON(desired, &des) == nil && des.Stop {
			return fmt.Errorf("%s: %w", pod, errPodStopping)
		}
		var obs podapi.Observed
		err := podapi.ReadJSON(path, &obs)
		if err == nil {
			if slices.Contains(obs.Frozen, id) == frozen {
				return nil
			}
		} else if !errors.Is(err, podapi.ErrMissing) {
			// A malformed or unreadable observation file is not evidence
			// that the guest thawed.
			return fmt.Errorf("read guest state of %s: %w", pod, err)
		} else if !frozen {
			// No observation file means no freeze either.
			return nil
		}
		select {
		case <-ctx.Done():
			if !frozen {
				return fmt.Errorf("guest of %s did not thaw %s: %w", pod, id, ctx.Err())
			}
			return fmt.Errorf("guest of %s did not freeze %s: %w", pod, id, ctx.Err())
		case <-tick.C:
		}
	}
}

func (a *Agent) importImage(ctx context.Context, ref, id string, secrets []registryauth.PullSecret) error {
	// Scratch space for the image's tar lives on the data disk. Imports of
	// one image never run concurrently, so leftovers of a crashed attempt
	// are removed here.
	dir := filepath.Join(a.cfg.DataDir, "tmp", id)
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	cfg, tar, err := a.pull(ctx, ref, secrets, dir)
	if err != nil {
		return err
	}
	fi, err := os.Stat(tar)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(a.configPath(id)), 0o755); err != nil {
		return err
	}
	if err := podapi.WriteJSON(a.configPath(id), cfg); err != nil {
		return err
	}
	held := false
	for _, vol := range a.store.List() {
		held = held || (vol.ID == id && vol.Kind == storage.KindImage)
	}
	if !held {
		err := a.store.CreateImage(ctx, id, image.FSSize(fi.Size()), func(dev string) error {
			return image.MakeFS(ctx, tar, dev, id)
		})
		if err != nil {
			return fmt.Errorf("import %s: %w", ref, err)
		}
		slog.Info("imported image", "ref", ref)
	}
	a.mu.Lock()
	a.configs[id] = &cfg
	a.mu.Unlock()
	return nil
}

func (a *Agent) fetch(ctx context.Context, f fetch) error {
	src := f.src
	a.mu.Lock()
	a.progress[f.owner] = &v1alpha1.Transfer{CommitID: src.commitID}
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		delete(a.progress, f.owner)
		a.mu.Unlock()
	}()
	remote, release, err := a.openRemote(ctx, src)
	if err != nil {
		a.setStateErr(f.owner, err)
		return err
	}
	last := time.Now()
	err = a.store.FetchCommit(ctx, src.stateUID, src.commitID, remote, func(done, total int64) {
		if time.Since(last) < progressInterval {
			return
		}
		last = time.Now()
		a.mu.Lock()
		a.progress[f.owner] = &v1alpha1.Transfer{CommitID: src.commitID, DoneBytes: done, TotalBytes: total}
		a.mu.Unlock()
		a.kick()
	})
	if err != nil {
		release()
		err = fmt.Errorf("fetch %s from %s: %w", src.commitID, src.node, err)
	} else {
		slog.Info("fetched commit", "commit", src.commitID, "from", src.node)
	}
	a.setStateErr(f.owner, err)
	return err
}
