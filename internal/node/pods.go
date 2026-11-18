package node

import (
	"encoding/json"
	"fmt"
	"path"
	"sort"

	corev1 "k8s.io/api/core/v1"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/image"
	"github.com/Azure/blip/internal/podapi"
	"github.com/Azure/blip/internal/storage"
)

const (
	defaultIdleTimeoutSeconds = 30
	// defaultRootSize is the size of a throwaway image root; the store
	// grows it to the image's size if that is larger.
	defaultRootSize = 10 << 30
)

func planPods(v *view, p *plan) {
	keys := make([]string, 0, len(v.pods))
	for key := range v.pods {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		pod := v.pods[key]
		dir := v.dirs[key]
		if m, ok := podMetaFor(pod, dir); ok {
			p.podMeta = append(p.podMeta, m)
		}
		if dir == nil {
			continue
		}
		d, preps, perr := desiredFor(v, p, pod, dir)
		if !sameDesired(dir.desired, d) {
			p.desired[key] = d
		}
		p.prepares = append(p.prepares, preps...)
		switch cur := pod.Annotations[AnnotationPrepareError]; {
		case perr != "" && perr != cur:
			p.podErrs = append(p.podErrs, podErr{pod: key, err: perr})
		case perr == "" && cur != "":
			p.podErrs = append(p.podErrs, podErr{pod: key})
		}
	}
}

func podMetaFor(pod *corev1.Pod, dir *podDir) (podMeta, bool) {
	m := podMeta{namespace: pod.Namespace, name: pod.Name}
	var obs *podapi.Observed
	if dir != nil {
		obs = dir.observed
	}
	m.warm = obs != nil && obs.Phase == podapi.PhaseWarm && pod.Labels[LabelBlipUID] == ""
	changed := m.warm != (pod.Labels[LabelWarm] == "true")
	if obs != nil {
		data, _ := json.Marshal(obs)
		if string(data) != pod.Annotations[AnnotationObserved] {
			m.observed = string(data)
			changed = true
		}
	}
	return m, changed
}

func sameDesired(cur *podapi.Desired, d podapi.Desired) bool {
	if cur == nil {
		cur = &podapi.Desired{}
	}
	a, _ := json.Marshal(cur)
	b, _ := json.Marshal(d)
	return string(a) == string(b)
}

// desiredFor computes desired.json for a VM pod and the disks still to prepare.
// Once written, a claim and attached mounts are only removed deliberately: the
// claim is kept, and stop is sticky. It also returns the preparation error to
// show on the pod, if any.
func desiredFor(v *view, p *plan, pod *corev1.Pod, dir *podDir) (podapi.Desired, []prepare, string) {
	var prev podapi.Desired
	if dir.desired != nil {
		prev = *dir.desired
	}
	key := podKey(pod.Namespace, pod.Name)
	uid := pod.Labels[LabelBlipUID]
	if uid == "" || podDone(pod, dir) {
		prev.Network = denyNetwork()
		return prev, nil, ""
	}
	b := v.blipByUID[uid]
	if b == nil || b.Namespace != pod.Namespace {
		prev.Stop = prev.Stop || v.blipsGone[uid]
		prev.Network = denyNetwork()
		return prev, nil, "network policy: claiming Blip not found"
	}
	d := podapi.Desired{Stop: prev.Stop || b.Spec.Stop || b.DeletionTimestamp != nil}
	// Publish policy independently of root preparation, including live
	// revocations while a disk import or mount is still in progress.
	var networkErr error
	d.Network, networkErr = v.networkFor(pod, b)
	if prev.Claim != nil && writerLost(v, pod, b, prev) {
		d.Stop = true
	}
	var preps []prepare
	var perr string
	add := func(pr *prepare) {
		if pr != nil {
			preps = append(preps, *pr)
		}
	}

	rootID := b.Status.RootAttachmentID
	if rootID != "" {
		p.needed[rootID] = true
	}
	var claim *podapi.Claim
	if prev.Claim != nil && prev.Claim.BlipUID == uid {
		claim = prev.Claim
	} else if rootID != "" {
		var cfg *image.Config
		var a *attach
		if b.Spec.Image != "" {
			if id, err := image.DigestOf(b.Status.ImageDigest); err == nil && v.configs[id] != nil {
				cfg = v.configs[id]
				a = &attach{id: rootID, image: id}
			} else if err == nil {
				perr = v.stateErrs[imageKey(id)]
			}
		} else if s := v.stateByName[b.Namespace+"/"+b.Spec.State]; s != nil && writes(s, rootID, pod) {
			cfg = v.stateConfig(s)
			a = &attach{id: rootID, state: s, commitID: s.Status.Writer.BaseCommit, purpose: "attach"}
		}
		if a != nil {
			ready, pr := v.ensure(key, dir, *a)
			add(pr)
			if ready {
				claim = claimFor(b, disk(rootID, false), cfg)
			} else if e := v.waitErr(*a); e != "" {
				perr = e
			}
		}
	}

	// A new claim waits until every mount is ready so the command starts
	// with its mounts in place.
	allReady := true
	if claim != nil {
		for _, m := range b.Status.Mounts {
			if m.Phase != v1alpha1.MountPending && m.Phase != v1alpha1.MountMounted {
				continue
			}
			if m.AttachmentID == "" {
				allReady = false
				continue
			}
			p.needed[m.AttachmentID] = true
			var a *attach
			if !m.Writable {
				a = &attach{id: m.AttachmentID, state: v.stateByUID[m.StateUID], stateUID: m.StateUID,
					commitID: m.CommitID, readOnly: true, purpose: "mount"}
			} else if s := v.stateByName[b.Namespace+"/"+m.State]; s != nil && writes(s, m.AttachmentID, pod) {
				a = &attach{id: m.AttachmentID, state: s, commitID: s.Status.Writer.BaseCommit, purpose: "mount"}
			}
			ready := v.devReady(dir, m.AttachmentID)
			if !ready && a != nil {
				var pr *prepare
				ready, pr = v.ensure(key, dir, *a)
				add(pr)
			}
			if ready {
				dk := disk(m.AttachmentID, !m.Writable)
				dk.State, dk.Path = m.State, m.Path
				d.Mounts = append(d.Mounts, dk)
			} else {
				allReady = false
				if a != nil {
					if e := v.waitErr(*a); e != "" {
						perr = e
					}
				}
			}
		}
	}
	if claim != nil && (claim == prev.Claim || allReady) {
		d.Claim = claim
		d.Freeze = v.freezes[key]
	} else {
		d.Mounts = nil
	}
	if networkErr != nil {
		perr = prepareErrText(fmt.Errorf("network policy: %w", networkErr))
	} else if dir.observed != nil && dir.observed.NetworkError != "" {
		perr = prepareErrText(fmt.Errorf("network policy: %s", dir.observed.NetworkError))
	}
	return d, preps, perr
}

// waitErr returns the last error that explains why a is not ready yet.
func (v *view) waitErr(a attach) string {
	if a.image != "" && !v.hasImage(a.image) {
		return v.stateErrs[imageKey(a.image)]
	}
	if a.state != nil {
		return v.stateErrs[string(a.state.UID)]
	}
	return ""
}

// podDone reports whether the VM has exited or the pod is going away; no new
// disks are attached then.
func podDone(pod *corev1.Pod, dir *podDir) bool {
	if dir.observed != nil && dir.observed.Phase == podapi.PhaseExited {
		return true
	}
	return pod.DeletionTimestamp != nil || pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed
}

// writes reports whether s's writer slot names this attachment on this pod.
func writes(s *v1alpha1.BlipState, attachmentID string, pod *corev1.Pod) bool {
	w := s.Status.Writer
	return w != nil && w.AttachmentID == attachmentID && w.PodUID == string(pod.UID)
}

// writerLost reports whether a durable disk already given to the VM lost its
// writer slot.
func writerLost(v *view, pod *corev1.Pod, b *v1alpha1.Blip, prev podapi.Desired) bool {
	lost := func(stateName, id string) bool {
		s := v.stateByName[b.Namespace+"/"+stateName]
		return s == nil || !writes(s, id, pod)
	}
	if b.Spec.State != "" && lost(b.Spec.State, prev.Claim.Root.ID) {
		return true
	}
	for _, m := range prev.Mounts {
		if !m.ReadOnly && lost(m.State, m.ID) {
			return true
		}
	}
	return false
}

func disk(id string, readOnly bool) podapi.Disk {
	return podapi.Disk{ID: id, Device: path.Join(podapi.MountPath, podapi.DevDir, id), Serial: id, ReadOnly: readOnly}
}

func claimFor(b *v1alpha1.Blip, root podapi.Disk, cfg *image.Config) *podapi.Claim {
	c := &podapi.Claim{
		BlipName:      b.Name,
		BlipUID:       string(b.UID),
		Root:          root,
		Command:       b.Spec.Command,
		TTY:           b.Spec.TTY,
		WorkingDir:    b.Spec.WorkingDir,
		User:          b.Spec.User,
		WaitForClient: b.Annotations[v1alpha1.AnnotationWaitForClient] == "true",
	}
	if cfg != nil {
		c.Env = append(c.Env, cfg.Env...)
		if c.WorkingDir == "" {
			c.WorkingDir = cfg.WorkingDir
		}
		if c.User == "" {
			c.User = cfg.User
		}
	}
	for _, e := range b.Spec.Env {
		c.Env = append(c.Env, e.Name+"="+e.Value)
	}
	if len(c.Command) == 0 {
		c.IdleTimeoutSeconds = defaultIdleTimeoutSeconds
		if b.Spec.IdleTimeout != nil {
			c.IdleTimeoutSeconds = int64(b.Spec.IdleTimeout.Seconds())
		}
	}
	return c
}

// attach describes a working volume a pod needs.
type attach struct {
	id       string
	image    string              // image root
	state    *v1alpha1.BlipState // durable or read-only source state (may be nil for read-only)
	stateUID string              // read-only mounts: the pinned state's UID
	commitID string
	readOnly bool
	purpose  string
}

func (v *view) devReady(dir *podDir, id string) bool {
	_, ok := v.volumes[id]
	return ok && dir.devs[id] != 0 && dir.devs[id] == v.devices[id]
}

// ensure reports whether the attachment's device node is ready, or returns
// the preparation it needs (nil while waiting on something else).
func (v *view) ensure(podKey string, dir *podDir, a attach) (bool, *prepare) {
	if v.devReady(dir, a.id) {
		return true, nil
	}
	if v.busy[a.id] {
		return false, nil
	}
	if vol, ok := v.volumes[a.id]; ok {
		if vol.Failed != "" {
			return false, nil
		}
		return false, &prepare{pod: podKey, req: storage.CreateWorking{AttachmentID: a.id}, exists: true}
	}
	pr := &prepare{pod: podKey, req: storage.CreateWorking{AttachmentID: a.id, StateUID: a.stateUID, ReadOnly: a.readOnly}}
	if a.state != nil {
		pr.req.StateUID = string(a.state.UID)
		if !a.readOnly {
			pr.req.SizeBytes = a.state.Status.SizeBytes
		}
	}
	switch {
	case a.image != "":
		if !v.hasImage(a.image) {
			return false, nil
		}
		pr.req.FromImage = a.image
		pr.req.SizeBytes = defaultRootSize
	case a.commitID == "":
		return false, nil
	case v.holds(a.commitID):
		pr.req.FromCommit = a.commitID
	default:
		pr.src = v.holder(a.state, a.commitID, "")
		if pr.src == nil {
			return false, nil
		}
		pr.src.purpose = a.purpose
	}
	return false, pr
}
