package controller

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/example/blip/internal/api"
	v1 "github.com/example/blip/internal/api/v1alpha1"
	"github.com/example/blip/internal/proto/nodepb"
)

func volOwner(bv *v1.BlipVol) Owner {
	return Owner{Kind: "BlipVol", Namespace: bv.Namespace, Name: bv.Name}
}

func volRef(bv *v1.BlipVol) *nodepb.ObjectRef {
	return &nodepb.ObjectRef{Namespace: bv.Namespace, Name: bv.Name, Uid: string(bv.UID)}
}

func volOpPrefix(bv *v1.BlipVol) string { return "v-" + string(bv.UID) + "." }

func (c *Controller) reconcileBlipVol(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	var bv v1.BlipVol
	if err := c.Get(ctx, req.NamespacedName, &bv); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	if bv.DeletionTimestamp != nil {
		return c.deleteVol(ctx, &bv)
	}
	if !controllerutil.ContainsFinalizer(&bv, api.FinalizerStorage) || bv.Labels[api.LabelLineage] == "" {
		patch := client.MergeFrom(bv.DeepCopy())
		controllerutil.AddFinalizer(&bv, api.FinalizerStorage)
		if bv.Labels[api.LabelLineage] == "" {
			if bv.Labels == nil {
				bv.Labels = map[string]string{}
			}
			// Every BlipVol starts a new lineage.
			bv.Labels[api.LabelLineage] = string(bv.UID)
		}
		return reconcile.Result{}, c.Patch(ctx, &bv, patch)
	}
	if bv.Status.Phase == v1.BlipVolReady || bv.Status.Phase == v1.BlipVolFailed {
		return c.compact(ctx, &bv)
	}
	orig := bv.DeepCopy()
	res, err := c.provision(ctx, &bv)
	if !equality.Semantic.DeepEqual(orig.Status, bv.Status) {
		// Nothing else writes the status of a BlipVol before its first
		// snapshot is Ready, but write conditionally anyway.
		if uerr := c.Status().Update(ctx, &bv); uerr != nil {
			if apierrors.IsConflict(uerr) {
				return reconcile.Result{Requeue: true}, nil
			}
			return reconcile.Result{}, uerr
		}
	}
	return res, err
}

func volWait(bv *v1.BlipVol, reason, msg string, after time.Duration) (reconcile.Result, error) {
	if bv.Status.Phase == "" {
		bv.Status.Phase = v1.BlipVolPending
	}
	setCond(&bv.Status.Conditions, bv.Generation, api.CondReady, false, reason, msg)
	setCond(&bv.Status.Conditions, bv.Generation, api.CondFailed, false, reason, "")
	return reconcile.Result{RequeueAfter: after}, nil
}

func (c *Controller) volFail(ctx context.Context, bv *v1.BlipVol, reason, msg string) (reconcile.Result, error) {
	if err := c.volDone(ctx, bv); err != nil {
		return reconcile.Result{}, err
	}
	if s := bv.Snapshot(1); s != nil && s.State == v1.SnapshotPending {
		s.State, s.Message = v1.SnapshotFailed, msg
		metricSnapshots.WithLabelValues(snapKind(s.Reason), "failed").Inc()
	}
	bv.Status.Phase = v1.BlipVolFailed
	setCond(&bv.Status.Conditions, bv.Generation, api.CondReady, false, reason, msg)
	setCond(&bv.Status.Conditions, bv.Generation, api.CondFailed, true, reason, msg)
	return reconcile.Result{}, nil
}

// volReady makes sequence 1 Ready with its sealed replicas.
func (c *Controller) volReady(ctx context.Context, bv *v1.BlipVol, s *v1.VolSnapshot, sealed []string) (reconcile.Result, error) {
	if err := c.volDone(ctx, bv); err != nil {
		return reconcile.Result{}, err
	}
	now := metav1.NewTime(timeNow().Truncate(time.Second))
	s.State, s.Message, s.CaptureTime = v1.SnapshotReady, "", &now
	s.Replicas = sealedList(sealed)
	metricSnapshots.WithLabelValues(snapKind(s.Reason), "ready").Inc()
	syncCurrent(bv)
	return reconcile.Result{}, nil
}

// volDone drops the Clone hold of a finished (or deleted) derived BlipVol
// on its parent. A finished clone has status.origin.snapshot persisted (and
// read back) before this runs, so compaction of the parent always sees the
// hold or the origin pin (compact.go).
func (c *Controller) volDone(ctx context.Context, bv *v1.BlipVol) error {
	if o := bv.Status.Origin; o != nil && o.UID != "" && bv.Spec.Parent != nil {
		return c.dropHold(ctx, o.Namespace, v1.ObjectRef{Name: o.Name, UID: o.UID}, v1.HoldClone, string(bv.UID))
	}
	return nil
}

// provision makes sequence 1: an image import, an empty volume, or a
// clone of a parent snapshot (derive.go) (design 7.5).
func (c *Controller) provision(ctx context.Context, bv *v1.BlipVol) (reconcile.Result, error) {
	st := &bv.Status
	cfg, err := c.storageConfig(ctx)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("storage config: %w", err)
	}
	if bv.Spec.Parent != nil {
		return c.derive(ctx, bv, cfg)
	}
	s1 := bv.Snapshot(1)
	if s1 == nil {
		g := c.leastFullGroup(cfg, "")
		if g == nil {
			return volWait(bv, api.ReasonStorageFull, "no storage group has room", 30*time.Second)
		}
		size := resource.NewQuantity(api.DefaultSizeBytes, resource.BinarySI)
		if bv.Spec.Size != nil {
			q := bv.Spec.Size.DeepCopy()
			size = &q
		}
		st.Size = size
		id := api.SnapshotContentID(string(bv.UID), 1)
		st.RootContentID = id
		st.Snapshots = append(st.Snapshots, v1.VolSnapshot{Sequence: 1, ContentID: id, Reason: v1.SnapshotInitial, State: v1.SnapshotPending, StorageGroup: g.Name})
		st.LastSequence = 1
		st.Phase = v1.BlipVolImporting
		setCond(&st.Conditions, bv.Generation, api.CondReady, false, api.ReasonImporting, "")
		setCond(&st.Conditions, bv.Generation, api.CondFailed, false, api.ReasonImporting, "")
		return reconcile.Result{Requeue: true}, nil
	}
	g := cfg.Group(s1.StorageGroup)
	if g == nil {
		return volWait(bv, "GroupMissing", fmt.Sprintf("storage group %q is not configured", s1.StorageGroup), 30*time.Second)
	}
	return c.importRoot(ctx, bv, g, s1)
}

func (c *Controller) importRoot(ctx context.Context, bv *v1.BlipVol, g *api.StorageGroup, s1 *v1.VolSnapshot) (reconcile.Result, error) {
	st := &bv.Status
	members := c.connectedMembers(g)
	if len(members) < 2 {
		return volWait(bv, api.ReasonImporting, fmt.Sprintf("%d members of %s connected, need 2", len(members), g.Name), 10*time.Second)
	}
	own, pre, to, id := volOwner(bv), volOpPrefix(bv), c.opts.CommandTimeout, s1.ContentID
	size := sizeBytes(bv)
	primary, others := members[0], members[1:]
	waitRes := reconcile.Result{RequeueAfter: 10 * time.Second}
	var targets []*nodepb.Path
	pending := false
	for _, s := range others {
		res := c.nodes.Do(s, pre+"create."+s, own, to, &nodepb.Command{Op: &nodepb.Command_CreateContent{CreateContent: &nodepb.CreateContent{
			ContentId: id, SizeBytes: size, Kind: nodepb.ContentKind_CONTENT_KIND_ROOT, Blipvol: volRef(bv),
		}}})
		if res == nil {
			pending = true
			continue
		}
		if !ok(res) {
			continue
		}
		res = c.nodes.Do(s, pre+"exp."+s, own, to, c.exportCmd(id, nodepb.ExportMode_EXPORT_MODE_READ_WRITE, primary, "", false))
		if res == nil {
			pending = true
		} else if ok(res) && res.GetExport().GetPath() != nil {
			targets = append(targets, res.GetExport().GetPath())
		}
	}
	if pending {
		return waitRes, nil
	}
	if len(targets) < 1 {
		return c.volFail(ctx, bv, api.ReasonImportFailed, "no replica target could be prepared")
	}
	imp := &nodepb.Import{ContentId: id, Blipvol: volRef(bv), SizeBytes: size, Targets: targets}
	if im := bv.Spec.Image; im != nil {
		imp.ImageReference = im.Reference
		if im.PullSecretRef != nil {
			var s corev1.Secret
			err := c.live.Get(ctx, types.NamespacedName{Namespace: bv.Namespace, Name: im.PullSecretRef.Name}, &s)
			if apierrors.IsNotFound(err) {
				return volWait(bv, "PullSecretNotFound", fmt.Sprintf("secret %q not found", im.PullSecretRef.Name), 30*time.Second)
			}
			if err != nil {
				return reconcile.Result{}, err
			}
			imp.PullSecretDockerconfigjson = s.Data[corev1.DockerConfigJsonKey]
		}
	}
	res := c.nodes.Do(primary, pre+"import."+primary, own, c.opts.ImportTimeout, &nodepb.Command{Op: &nodepb.Command_Import{Import: imp}})
	if res == nil {
		return waitRes, nil
	}
	if !ok(res) {
		reason := api.ReasonImportFailed
		switch res.Code {
		case nodepb.ErrorCode_ERROR_CODE_IMAGE_PULL:
			reason = api.ReasonImagePullFailed
		case nodepb.ErrorCode_ERROR_CODE_NO_SPACE:
			reason = api.ReasonStorageFull
		}
		return c.volFail(ctx, bv, reason, resultErr(res))
	}
	ir := res.GetImport()
	good := []string{primary}
	for _, t := range ir.GetTargets() {
		if t.Ok {
			good = append(good, t.Node)
		}
	}
	for _, s := range others {
		if c.nodes.Do(s, pre+"unexp."+s, own, to, unexportCmd(id, "")) == nil {
			pending = true
		}
	}
	if pending {
		return waitRes, nil
	}
	sealed, pending := c.sealAll(bv, id, good)
	if pending {
		return waitRes, nil
	}
	if len(sealed) < 2 {
		return c.volFail(ctx, bv, api.ReasonImportFailed, fmt.Sprintf("sealed on %d replicas, need 2", len(sealed)))
	}
	st.ImageDigest = ir.GetImageDigest()
	return c.volReady(ctx, bv, s1, sealed)
}

func (c *Controller) sealAll(bv *v1.BlipVol, id string, nodes []string) ([]string, bool) {
	var sealed []string
	pending := false
	for _, s := range nodes {
		res := c.nodes.Do(s, volOpPrefix(bv)+"seal."+s, volOwner(bv), c.opts.CommandTimeout, sealCmd(id, volRef(bv)))
		if res == nil {
			pending = true
		} else if ok(res) {
			sealed = append(sealed, s)
		}
	}
	return sealed, pending
}

// deleteVol removes the content of every snapshot from every reachable
// replica, then the finalizer (design 7.7). It is the deletion barrier:
// nothing is deleted while the BlipVol has a claim or holds, or an
// operation of its own (import, clone) is in flight. BlipVols derived from
// it do not block it: their content is independent.
func (c *Controller) deleteVol(ctx context.Context, bv *v1.BlipVol) (reconcile.Result, error) {
	if !controllerutil.ContainsFinalizer(bv, api.FinalizerStorage) {
		return reconcile.Result{}, nil
	}
	pre := volOpPrefix(bv)
	if c.nodes.Pending(pre) && !c.nodes.Pending(pre+"del.") {
		return reconcile.Result{RequeueAfter: 2 * time.Second}, nil
	}
	key := types.NamespacedName{Namespace: bv.Namespace, Name: bv.Name}
	// Read live and drop holds whose holder is gone, so a lost holder
	// cannot pin data forever.
	cur, err := c.updateVolStatus(ctx, key, string(bv.UID), func(v *v1.BlipVol) (bool, error) {
		changed := false
		for _, h := range append([]v1.Hold(nil), v.Status.Holds...) {
			if c.holderGone(ctx, h.Holder) {
				changed = removeHold(v, h.Kind, h.Holder.UID) || changed
			}
		}
		if cl := v.Status.Claim; cl != nil && c.claimStale(ctx, v.Namespace, cl) {
			c.log.Info("dropping stale claim", "blipvol", v.Name, "blip", cl.BlipName, "attachment", cl.AttachmentID)
			v.Status.Claim = nil
			changed = true
		}
		if v.Status.Claim != nil || len(v.Status.Holds) > 0 {
			var why []string
			if cl := v.Status.Claim; cl != nil {
				why = append(why, "claimed by blip "+cl.BlipName)
			}
			for _, h := range v.Status.Holds {
				why = append(why, fmt.Sprintf("%s hold by %s %s", h.Kind, h.Holder.Kind, h.Holder.Name))
			}
			msg := strings.Join(why, ", ")
			if cnd := findCond(v.Status.Conditions, api.CondReady); cnd == nil || cnd.Reason != api.ReasonDeletionBlocked || cnd.Message != msg {
				setCond(&v.Status.Conditions, v.Generation, api.CondReady, v.Status.Phase == v1.BlipVolReady, api.ReasonDeletionBlocked, msg)
				changed = true
			}
		}
		return changed, nil
	})
	if err == errGone {
		return reconcile.Result{}, nil
	}
	if err != nil {
		return reconcile.Result{}, err
	}
	if cur.Status.Claim != nil || len(cur.Status.Holds) > 0 {
		return reconcile.Result{RequeueAfter: 5 * time.Second}, nil
	}
	if err := c.volDone(ctx, cur); err != nil {
		return reconcile.Result{}, err
	}
	if len(cur.Status.Snapshots) > 0 {
		cfg, err := c.storageConfig(ctx)
		if err != nil {
			return reconcile.Result{}, err
		}
		// Every snapshot's content on every member of its group.
		ids := map[string][]string{}
		for _, s := range cur.Status.Snapshots {
			if g := cfg.Group(s.StorageGroup); g != nil {
				for _, n := range g.Nodes {
					ids[n] = append(ids[n], s.ContentID)
				}
			}
		}
		pending := false
		for _, n := range sortedKeys(ids) {
			if c.nodes.Lost(n) {
				continue // orphan cleanup removes it when the node returns
			}
			if !c.nodes.Connected(n) {
				pending = true
				continue
			}
			res := c.nodes.Do(n, pre+"del."+n, volOwner(cur), c.opts.CommandTimeout, deleteContentCmd(ids[n]...))
			if res == nil {
				pending = true
			} else if !ok(res) {
				c.log.Info("delete content failed, retrying", "blipvol", cur.Name, "node", n, "err", resultErr(res))
				c.nodes.Forget(pre + "del." + n)
				pending = true
			}
		}
		if pending {
			return reconcile.Result{RequeueAfter: 5 * time.Second}, nil
		}
	}
	c.nodes.Forget(pre)
	for _, s := range cur.Status.Snapshots {
		c.saveDone(s.ContentID)
	}
	// Optimistic lock: a claim or hold added meanwhile makes this fail.
	patch := client.MergeFromWithOptions(cur.DeepCopy(), client.MergeFromWithOptimisticLock{})
	controllerutil.RemoveFinalizer(cur, api.FinalizerStorage)
	err = c.live.Patch(ctx, cur, patch)
	if apierrors.IsConflict(err) {
		return reconcile.Result{Requeue: true}, nil
	}
	return reconcile.Result{}, client.IgnoreNotFound(err)
}

// holderGone reports whether the holder of a hold no longer exists.
func (c *Controller) holderGone(ctx context.Context, h v1.HolderRef) bool {
	key := types.NamespacedName{Namespace: h.Namespace, Name: h.Name}
	var obj client.Object
	switch h.Kind {
	case "Blip":
		obj = &v1.Blip{}
	case "BlipVol":
		obj = &v1.BlipVol{}
	default:
		return false
	}
	err := c.live.Get(ctx, key, obj)
	if apierrors.IsNotFound(err) {
		return true
	}
	return err == nil && h.UID != "" && string(obj.GetUID()) != h.UID
}

// claimStale reports whether a claim's Blip is gone and its attachment can
// no longer be in use: no node recorded, the node is fenced, or the node is
// connected and does not have the attachment.
func (c *Controller) claimStale(ctx context.Context, ns string, cl *v1.Claim) bool {
	if !c.holderGone(ctx, v1.HolderRef{Kind: "Blip", Namespace: ns, Name: cl.BlipName, UID: cl.BlipUID}) {
		return false
	}
	if cl.Node == "" || c.fenced(ctx, cl.Node) {
		return true
	}
	return c.nodes.Connected(cl.Node) && !c.nodes.HasAttachment(cl.Node, cl.AttachmentID)
}

func sortedKeys[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
