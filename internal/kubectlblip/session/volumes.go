package session

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/example/blip/internal/api"
	"github.com/example/blip/internal/api/v1alpha1"
)

// MaxVolumeName is the longest spec.volumes name.
const MaxVolumeName = 20

// ValidateVolumeName checks a spec.volumes name.
func ValidateVolumeName(name string) error {
	if errs := validation.IsDNS1123Label(name); len(errs) > 0 {
		return fmt.Errorf("invalid volume name %q: %s", name, errs[0])
	}
	if len(name) > MaxVolumeName {
		return fmt.Errorf("invalid volume name %q: longer than %d characters", name, MaxVolumeName)
	}
	if name == "blip-meta" {
		return fmt.Errorf("invalid volume name %q: reserved", name)
	}
	return nil
}

func specVolume(b *v1alpha1.Blip, name string) *v1alpha1.BlipVolume {
	for i := range b.Spec.Volumes {
		if b.Spec.Volumes[i].Name == name {
			return &b.Spec.Volumes[i]
		}
	}
	return nil
}

// VolumeStatus returns the status.volumes entry name of b, or nil.
func VolumeStatus(b *v1alpha1.Blip, name string) *v1alpha1.BlipVolumeStatus {
	for i := range b.Status.Volumes {
		if b.Status.Volumes[i].Name == name {
			return &b.Status.Volumes[i]
		}
	}
	return nil
}

func (c *Client) mustGet(ctx context.Context, ns, name string) (*v1alpha1.Blip, error) {
	b, err := c.Get(ctx, ns, name)
	if err == nil && b == nil {
		err = fmt.Errorf("blip %s not found in namespace %s", name, ns)
	}
	return b, err
}

// update gets Blip ns/name, applies f and updates it, retrying on
// conflicts. f returns false to skip the update.
func (c *Client) update(ctx context.Context, ns, name string, f func(*v1alpha1.Blip) (bool, error)) (*v1alpha1.Blip, error) {
	var b *v1alpha1.Blip
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var err error
		if b, err = c.mustGet(ctx, ns, name); err != nil {
			return err
		}
		if Finished(b) || b.DeletionTimestamp != nil {
			return fmt.Errorf("blip %s is %s", name, finishedState(b))
		}
		ok, err := f(b)
		if err != nil || !ok {
			return err
		}
		return c.C.Update(ctx, b)
	})
	return b, err
}

func finishedState(b *v1alpha1.Blip) string {
	if b.DeletionTimestamp != nil {
		return "being deleted"
	}
	return string(orPending(b.Status.Phase))
}

// Attach adds BlipVol blipVol to Blip ns/name as volume vol and waits until
// it is attached. The guest sees it at the returned status's DevicePath.
func (c *Client) Attach(ctx context.Context, ns, name, vol, blipVol string) (*v1alpha1.BlipVolumeStatus, error) {
	if err := ValidateVolumeName(vol); err != nil {
		return nil, err
	}
	bv := &v1alpha1.BlipVol{}
	if err := c.C.Get(ctx, client.ObjectKey{Namespace: ns, Name: blipVol}, bv); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("blipvol %s not found in namespace %s", blipVol, ns)
		}
		return nil, err
	}
	var prev string
	_, err := c.update(ctx, ns, name, func(b *v1alpha1.Blip) (bool, error) {
		if sv := specVolume(b, vol); sv != nil {
			if sv.BlipVolRef.Name != blipVol {
				return false, fmt.Errorf("blip %s already has a volume %s (blipvol %s)", name, vol, sv.BlipVolRef.Name)
			}
			return false, nil // already requested: wait for it
		}
		prev = ""
		if vs := VolumeStatus(b, vol); vs != nil {
			prev = vs.AttachmentID
		}
		b.Spec.Volumes = append(b.Spec.Volumes, v1alpha1.BlipVolume{Name: vol, BlipVolRef: v1alpha1.LocalObjectRef{Name: blipVol}})
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	c.logf("waiting for blipvol %s to attach to blip %s as %s...", blipVol, name, vol)
	var out *v1alpha1.BlipVolumeStatus
	msg := ""
	err = wait.PollUntilContextCancel(ctx, c.poll(), true, func(ctx context.Context) (bool, error) {
		b, err := c.mustGet(ctx, ns, name)
		if err != nil {
			return false, err
		}
		if Finished(b) {
			return false, fmt.Errorf("blip %s is %s", name, b.Status.Phase)
		}
		if specVolume(b, vol) == nil {
			return false, fmt.Errorf("volume %s was removed from blip %s", vol, name)
		}
		vs := VolumeStatus(b, vol)
		if vs == nil || (prev != "" && vs.AttachmentID == prev) {
			return false, nil
		}
		switch vs.State {
		case v1alpha1.VolumeAttached:
			out = vs.DeepCopy()
			return true, nil
		case v1alpha1.VolumeFailed:
			return false, fmt.Errorf("attach volume %s to blip %s failed: %s", vol, name, vs.Message)
		}
		if vs.Message != "" && vs.Message != msg {
			msg = vs.Message
			c.logf("%s: %s", vs.State, msg)
		}
		return false, nil
	})
	return out, wrapCtx(err, "volume "+vol+" not attached to blip "+name)
}

// ErrRootVolume is returned when detaching the root volume.
var ErrRootVolume = errors.New("the root volume cannot be detached")

// Detach removes volume vol from Blip ns/name and waits until it is
// released. It returns the BlipVol that was attached. The guest must stop
// using the device first: detach is forced.
func (c *Client) Detach(ctx context.Context, ns, name, vol string) (string, error) {
	var blipVol string
	_, err := c.update(ctx, ns, name, func(b *v1alpha1.Blip) (bool, error) {
		if len(b.Spec.Volumes) > 0 && b.Spec.Volumes[0].Name == vol {
			return false, ErrRootVolume
		}
		sv := specVolume(b, vol)
		if sv == nil {
			if vs := VolumeStatus(b, vol); vs != nil && vs.BlipVolRef != nil {
				blipVol = vs.BlipVolRef.Name // already removed: wait for it
				return false, nil
			}
			return false, fmt.Errorf("blip %s has no volume %s", name, vol)
		}
		blipVol = sv.BlipVolRef.Name
		b.Spec.Volumes = slices.DeleteFunc(b.Spec.Volumes, func(v v1alpha1.BlipVolume) bool { return v.Name == vol })
		return true, nil
	})
	if err != nil {
		return "", err
	}
	c.logf("waiting for volume %s to detach from blip %s...", vol, name)
	err = wait.PollUntilContextCancel(ctx, c.poll(), true, func(ctx context.Context) (bool, error) {
		b, err := c.Get(ctx, ns, name)
		if err != nil || b == nil || Finished(b) {
			return b == nil || Finished(b), err
		}
		if specVolume(b, vol) != nil {
			return false, fmt.Errorf("volume %s was added to blip %s again", vol, name)
		}
		vs := VolumeStatus(b, vol)
		return vs == nil || vs.State == v1alpha1.VolumeReleased || vs.State == v1alpha1.VolumeFailed, nil
	})
	return blipVol, wrapCtx(err, "volume "+vol+" not detached from blip "+name)
}

// DeleteVolume deletes BlipVol ns/name and waits until it is gone.
//
// The controller deletes the data only once the BlipVol has no claim and no
// holds (attached to a Blip, or a snapshot being cloned into a derived
// BlipVol). DeleteVolume does not wait for those: it returns a non-empty
// pending message instead.
func (c *Client) DeleteVolume(ctx context.Context, ns, name string) (pending string, err error) {
	bv := &v1alpha1.BlipVol{}
	if err := c.C.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, bv); err != nil {
		return "", client.IgnoreNotFound(err)
	}
	if err := c.C.Delete(ctx, bv); client.IgnoreNotFound(err) != nil {
		return "", err
	}
	err = wait.PollUntilContextCancel(ctx, c.poll(), true, func(ctx context.Context) (bool, error) {
		cur := &v1alpha1.BlipVol{}
		err := c.C.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, cur)
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		pending = DeletionBlockers(cur)
		return pending != "", nil
	})
	return pending, wrapCtx(err, "blipvol "+name+" not deleted")
}

// DeletionBlockers describes the claim and holds that keep bv's data, or
// returns "" when there are none.
func DeletionBlockers(bv *v1alpha1.BlipVol) string {
	var why []string
	if cl := bv.Status.Claim; cl != nil {
		why = append(why, "attached to blip "+cl.BlipName)
	}
	for _, h := range bv.Status.Holds {
		why = append(why, holdString(h))
	}
	if len(why) == 0 {
		return ""
	}
	return "blocked by " + strings.Join(why, ", ") + "; it is deleted once released"
}

func holdString(h v1alpha1.Hold) string {
	s := strings.ToLower(string(h.Kind)) + " hold by " + strings.ToLower(h.Holder.Kind) + " "
	if h.Holder.Namespace != "" {
		s += h.Holder.Namespace + "/"
	}
	s += h.Holder.Name
	if h.Snapshot != 0 {
		s += fmt.Sprintf(" on snapshot %d", h.Snapshot)
	}
	return s
}

// DeriveOptions describe a derived BlipVol.
type DeriveOptions struct {
	// Name of the new BlipVol; empty generates "<source>-xxxxx".
	Name string
	// Snapshot is the parent sequence; nil means the newest (or a live
	// capture while the source is attached).
	Snapshot *int64
	Policy   *v1alpha1.SnapshotPolicy
}

// BuildDerived returns a BlipVol in ns that derives from source.
func BuildDerived(ns, source string, o DeriveOptions) *v1alpha1.BlipVol {
	bv := &v1alpha1.BlipVol{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: o.Name},
		Spec: v1alpha1.BlipVolSpec{
			Parent:         &v1alpha1.ParentRef{Name: source, Snapshot: o.Snapshot},
			SnapshotPolicy: o.Policy,
		},
	}
	if o.Name == "" {
		prefix := source
		if len(prefix) > maxGeneratePrefix {
			prefix = prefix[:maxGeneratePrefix]
		}
		bv.GenerateName = strings.TrimSuffix(prefix, "-") + "-"
	}
	return bv
}

// maxGeneratePrefix keeps generated names within a DNS label.
const maxGeneratePrefix = validation.DNS1123LabelMaxLength - 6

// Derive creates a BlipVol cloned from a snapshot of BlipVol ns/source and
// returns it.
func (c *Client) Derive(ctx context.Context, ns, source string, o DeriveOptions) (*v1alpha1.BlipVol, error) {
	src := &v1alpha1.BlipVol{}
	if err := c.C.Get(ctx, client.ObjectKey{Namespace: ns, Name: source}, src); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("blipvol %s not found in namespace %s", source, ns)
		}
		return nil, err
	}
	if o.Snapshot != nil {
		if s := src.Snapshot(*o.Snapshot); s == nil {
			return nil, fmt.Errorf("blipvol %s has no snapshot %d", source, *o.Snapshot)
		} else if s.State == v1alpha1.SnapshotFailed {
			return nil, fmt.Errorf("snapshot %d of blipvol %s failed", *o.Snapshot, source)
		}
	}
	bv := BuildDerived(ns, source, o)
	if err := c.C.Create(ctx, bv); err != nil {
		return nil, err
	}
	return bv, nil
}

// AttachmentVolume returns the BlipVol attached to Blip ns/name as vol.
func (c *Client) AttachmentVolume(ctx context.Context, ns, name, vol string) (string, error) {
	b, err := c.mustGet(ctx, ns, name)
	if err != nil {
		return "", err
	}
	sv := specVolume(b, vol)
	if sv == nil {
		return "", fmt.Errorf("blip %s has no volume %s", name, vol)
	}
	return sv.BlipVolRef.Name, nil
}

// WaitVolume waits until BlipVol ns/name is Ready, logging the reasons it
// waits for (such as WaitingForCapture), and returns it.
func (c *Client) WaitVolume(ctx context.Context, ns, name string) (*v1alpha1.BlipVol, error) {
	c.logf("waiting for blipvol %s...", name)
	var out *v1alpha1.BlipVol
	last := ""
	err := wait.PollUntilContextCancel(ctx, c.poll(), true, func(ctx context.Context) (bool, error) {
		bv := &v1alpha1.BlipVol{}
		if err := c.C.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, bv); err != nil {
			if apierrors.IsNotFound(err) {
				return false, fmt.Errorf("blipvol %s was deleted", name)
			}
			return false, err
		}
		cond := meta.FindStatusCondition(bv.Status.Conditions, api.CondReady)
		switch bv.Status.Phase {
		case v1alpha1.BlipVolReady:
			out = bv
			return true, nil
		case v1alpha1.BlipVolFailed:
			msg := ""
			if f := meta.FindStatusCondition(bv.Status.Conditions, api.CondFailed); f != nil {
				msg = ": " + f.Reason + ": " + f.Message
			} else if cond != nil {
				msg = ": " + cond.Reason + ": " + cond.Message
			}
			return false, fmt.Errorf("blipvol %s failed%s", name, msg)
		}
		if cond != nil && cond.Reason != "" {
			if s := cond.Reason + ": " + cond.Message; s != last {
				last = s
				c.logf("%s", strings.TrimSuffix(s, ": "))
			}
		}
		return false, nil
	})
	return out, wrapCtx(err, "blipvol "+name+" not ready")
}
