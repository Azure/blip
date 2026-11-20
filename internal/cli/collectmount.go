// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package cli

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sync"
	"time"

	"github.com/Azure/blip/api/v1alpha1"
)

// collectMount mounts state read-only in the calling blip, or reuses a mount
// of it there, and returns the mount path. A state that is not mounted yet
// is waited for until no blip is writing it.
func (a *app) collectMount(ctx context.Context, state string) (string, func(), error) {
	if _, err := a.clients(); err != nil {
		return "", nil, err
	}
	if a.self == nil {
		return "", nil, errors.New("collect only works inside a blip")
	}
	b, err := a.getBlip(ctx, a.self.Name)
	if err != nil {
		return "", nil, err
	}
	if b.UID != a.self.UID || b.UID == "" {
		return "", nil, errors.New("the calling blip was replaced")
	}
	root, err := a.getState(ctx, b.Spec.State)
	if err != nil {
		return "", nil, err
	}
	// The caller's root state is this blip's own root filesystem. The caller
	// holds its writer, so waiting for it to become ready would never return,
	// and it is already mounted at /.
	if state == b.Spec.State {
		return collectSelfRoot, func() {}, nil
	}
	// A writable mount means this blip holds the writer; waiting for the
	// state to become ready would never return. Its contents are current.
	if existing := findSpecMount(root.Spec.Mounts, state); existing == nil || !existing.Writable {
		if err := a.waitStateReady(ctx, state); err != nil {
			return "", nil, err
		}
	}
	var mountPath string
	var writable, shared bool
	var token string
	var oldAttachment string
	_, err = a.editMountsWaitingStale(ctx, root.Name, state, func(s *v1alpha1.BlipState) (string, error) {
		if s.UID != root.UID {
			return "", errors.New("the calling blip's root state was replaced")
		}
		writer, err := a.rootWriter(ctx, s)
		if err != nil {
			return "", err
		}
		if writer == nil || writer.UID != b.UID {
			return "", fmt.Errorf("blip %q no longer owns root state %q", b.Name, root.Name)
		}
		users := mountUsers(s)
		shared = false
		oldAttachment = ""
		if m := findSpecMount(s.Spec.Mounts, state); m != nil {
			mountPath, writable = m.Path, m.Writable
			if m.BlipUID != "" && m.BlipUID != string(b.UID) {
				return "", fmt.Errorf("temporary mount of state %q belongs to an earlier execution; wait for cleanup", state)
			}
			u := users[state]
			tracked := m.BlipUID != "" && u.BlipUID == m.BlipUID && u.Path == m.Path && u.Token != "" && u.Users > 0
			if tracked {
				oldAttachment = u.PreviousAttachment
			}
			if !writable && (oldAttachment == "" || mountedAttachment(writer, state) != oldAttachment) {
				if err := a.checkMountCurrent(ctx, writer, state, mountPath); err != nil {
					return "", err
				}
			}
			if !tracked {
				// Durable user mounts, and temporary mounts whose bookkeeping
				// was lost, are left in place until their owner's lifetime ends.
				return "", errUnchanged
			}
		} else {
			// Back-to-back collects of the same state find its old
			// read-only attachment still detaching. Adding the mount now
			// would let the controller revive that attachment instead of
			// attaching a fresh one, so wait for it to leave status.
			oldAttachment = mountedAttachment(writer, state)
			if oldAttachment != "" {
				return oldAttachment, errStaleAttach
			}
			mountPath, writable = path.Join(collectMountRoot, state), false
			for _, m := range s.Spec.Mounts {
				if m.Path == mountPath {
					return "", fmt.Errorf("collect path %s is already used by state %q", mountPath, m.State)
				}
			}
			s.Spec.Mounts = append(s.Spec.Mounts, v1alpha1.Mount{State: state, Path: mountPath, BlipUID: string(b.UID)})
			users[state] = collectMountUse{
				CollectMountUse:    v1alpha1.CollectMountUse{BlipUID: string(b.UID), Path: mountPath},
				Token:              rand.Text(),
				PreviousAttachment: mountedAttachment(writer, state),
			}
		}
		shared = true
		u := users[state]
		u.Users++
		users[state], token = u, u.Token
		oldAttachment = u.PreviousAttachment
		return oldAttachment, setMountUsers(s, users)
	})
	if err != nil && !errors.Is(err, errUnchanged) {
		return "", nil, err
	}
	cleanup := func() {}
	if shared {
		cleanup = sync.OnceFunc(func() { a.releaseMount(context.WithoutCancel(ctx), root, state, token) })
	}
	if err := a.waitMount(ctx, b, state, mountPath, writable, 0, oldAttachment); err != nil {
		cleanup()
		return "", nil, err
	}
	if !writable {
		current, err := a.getBlip(ctx, b.Name)
		if err == nil {
			err = a.checkMountCurrent(ctx, current, state, mountPath)
		}
		if err != nil {
			cleanup()
			return "", nil, err
		}
	}
	return mountPath, cleanup, nil
}

// waitStateReady waits until the state has no writer and no commit in
// flight, so a fresh read-only mount sees the latest version.
func (a *app) waitStateReady(ctx context.Context, name string) error {
	r := &reporter{a: a}
	defer r.stop()
	return a.waitState(ctx, name, func(s *v1alpha1.BlipState) (bool, error) {
		if s == nil {
			return false, fmt.Errorf("state %q not found", name)
		}
		switch s.Status.Phase {
		case v1alpha1.StateReady:
			if s.Status.Writer == nil && s.Status.Pending == nil {
				return true, nil
			}
		case v1alpha1.StateFailed:
			return false, fmt.Errorf("state %q failed: %s", name, s.Status.Message)
		}
		switch {
		case s.Status.Writer != nil:
			r.say("waiting for state %s: blip %s is writing", a.short(name), a.short(s.Status.Writer.BlipName))
		case s.Status.Pending != nil:
			r.say("waiting for state %s: saving generation %d", a.short(name), s.Status.Pending.Generation)
		case s.Status.Message != "":
			r.say("waiting for state %s: %s", a.short(name), s.Status.Message)
		default:
			r.say("waiting for state %s...", a.short(name))
		}
		return false, nil
	})
}

// checkMountCurrent rejects reusing a read-only mount that pins an older
// version than the state's latest commit.
func (a *app) checkMountCurrent(ctx context.Context, b *v1alpha1.Blip, state, mountPath string) error {
	m := findMount(b.Status.Mounts, state)
	if m == nil || m.Path != mountPath || m.Writable || m.Phase != v1alpha1.MountMounted {
		return nil
	}
	s, err := a.getState(ctx, state)
	if err != nil {
		return err
	}
	if s.Status.Committed != nil && m.CommitID != s.Status.Committed.ID {
		return fmt.Errorf("state %q is already mounted read-only on blip %q at %s at an older version; unmount it first", state, b.Name, mountPath)
	}
	return nil
}

// collectMountUse is the refcounted collect use of one state on the caller's
// root. It extends the shared annotation entry with lifetime and provenance.
type collectMountUse struct {
	v1alpha1.CollectMountUse
	Token string `json:"token"`
	Users int    `json:"users"`
	// PreviousAttachment is the attachment visible when the mount was
	// added. Adds wait for it to detach first, so it is normally empty;
	// concurrent reuse still inherits the wait if one slips through.
	PreviousAttachment string `json:"previousAttachment,omitempty"`
}

// mountUsers returns the collect refcounts on the caller's root state. They
// live there so refcounts and mount edits are atomic; lifetime and token
// provenance prevent stale cleanup from removing a durable mount or a new use
// of the same path.
func mountUsers(s *v1alpha1.BlipState) map[string]collectMountUse {
	users := map[string]collectMountUse{}
	if v := s.Annotations[v1alpha1.AnnotationCollectMounts]; v != "" {
		if err := json.Unmarshal([]byte(v), &users); err != nil || users == nil {
			return map[string]collectMountUse{}
		}
	}
	return users
}

func setMountUsers(s *v1alpha1.BlipState, users map[string]collectMountUse) error {
	if len(users) == 0 {
		delete(s.Annotations, v1alpha1.AnnotationCollectMounts)
		return nil
	}
	v, err := json.Marshal(users)
	if err != nil {
		return err
	}
	if s.Annotations == nil {
		s.Annotations = map[string]string{}
	}
	s.Annotations[v1alpha1.AnnotationCollectMounts] = string(v)
	return nil
}

// releaseMount only releases the exact temporary mount this collect acquired.
func (a *app) releaseMount(ctx context.Context, root *v1alpha1.BlipState, state, token string) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_, _ = a.updateState(ctx, root.Name, func(s *v1alpha1.BlipState) error {
		users := mountUsers(s)
		u := users[state]
		m := findSpecMount(s.Spec.Mounts, state)
		if s.UID != root.UID || u.Token != token || u.Users < 1 || m == nil ||
			m.BlipUID == "" || m.BlipUID != u.BlipUID || m.Path != u.Path {
			return errUnchanged
		}
		if u.Users > 1 {
			u.Users--
			users[state] = u
		} else {
			delete(users, state)
			var keep []v1alpha1.Mount
			for _, m := range s.Spec.Mounts {
				if m.State != state {
					keep = append(keep, m)
				}
			}
			s.Spec.Mounts = keep
		}
		return setMountUsers(s, users)
	})
}
