// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"context"
	"crypto/sha256"
	"fmt"
	"path"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// reservedMounts are guest-managed paths a profile mount may not shadow.
var reservedMounts = []string{"/proc", "/sys", "/dev", "/run/blip", "/run/blip-collect"}

// validateMountPath requires an absolute, already-clean path outside the
// guest's reserved directories.
func validateMountPath(mountPath string) error {
	if !path.IsAbs(mountPath) {
		return fmt.Errorf("mount path %q must be absolute", mountPath)
	}
	if clean := path.Clean(mountPath); clean != mountPath {
		return fmt.Errorf("mount path %q is not clean; use %q", mountPath, clean)
	}
	if mountPath == "/" {
		return fmt.Errorf("mount path must not be the guest root")
	}
	for _, reserved := range reservedMounts {
		if mountPath == reserved || strings.HasPrefix(mountPath, reserved+"/") {
			return fmt.Errorf("mount path %q is reserved by the guest", mountPath)
		}
	}
	return nil
}

// mountSource is a profile mount resolved to the state it copies.
type mountSource struct {
	Path   string
	Source string
}

// resolveProfileMounts selects a source state for every mount a profile
// declares. It runs before the chat is created so a missing source leaves no
// half-built chat behind.
func (s *Server) resolveProfileMounts(ctx context.Context, profileName string, profile Profile) ([]mountSource, error) {
	out := make([]mountSource, 0, len(profile.Mounts))
	for _, m := range profile.Mounts {
		selector, err := m.selector()
		if err != nil {
			return nil, fmt.Errorf("profile %q mount %q: %w", profileName, m.Path, err)
		}
		best, err := s.newestState(ctx, selector)
		if err != nil {
			return nil, fmt.Errorf("profile %q mount %q: %w", profileName, m.Path, err)
		}
		if best == nil {
			return nil, noBaseError{fmt.Sprintf("profile %q: no Ready BlipState matches mount %s selector %s in namespace %s",
				profileName, m.Path, selector, s.namespace)}
		}
		out = append(out, mountSource{Path: m.Path, Source: best.Name})
	}
	return out, nil
}

// newestState returns the newest ready state matching selector, or nil when
// none is usable. A state that is still copying, failed, or being deleted is
// ignored so a newer complete state can be chosen instead.
func (s *Server) newestState(ctx context.Context, selector labels.Selector) (*v1.BlipState, error) {
	states, err := s.cluster.ListStates(ctx, s.namespace, selector)
	if err != nil {
		return nil, err
	}
	var best *v1.BlipState
	for i := range states {
		st := &states[i]
		if st.DeletionTimestamp != nil || st.Status.Phase != v1.StateReady || st.Status.Committed == nil {
			continue
		}
		if best == nil || newerState(st, best) {
			best = st
		}
	}
	return best, nil
}

// newerState orders states by commit time, then by name so the choice is
// stable when two commits happened in the same second.
func newerState(a, b *v1.BlipState) bool {
	at, bt := a.Status.Committed.Time.Time, b.Status.Committed.Time.Time
	if !at.Equal(bt) {
		return at.After(bt)
	}
	return a.Name > b.Name
}

// attachProfileMounts copies each resolved source into a state owned by root
// and adds the copy as a writable mount. A path root already mounts, as a fork
// inherits from its parent, wins so a profile never replaces the workspace it
// joined.
func (s *Server) attachProfileMounts(ctx context.Context, root *v1.BlipState, mounts []mountSource) error {
	if len(mounts) == 0 {
		return nil
	}
	current, err := s.cluster.GetSession(ctx, s.namespace, root.Name)
	if err != nil {
		return err
	}
	existing := map[string]bool{}
	for _, m := range current.Spec.Mounts {
		existing[m.Path] = true
	}
	var add []v1.Mount
	for _, m := range mounts {
		if existing[m.Path] {
			continue
		}
		st, err := s.createMountCopy(ctx, root, m)
		if err != nil {
			return err
		}
		add = append(add, v1.Mount{State: st.Name, Path: m.Path, Writable: true})
	}
	if len(add) == 0 {
		return nil
	}
	for _, m := range add {
		if err := s.waitStateReady(ctx, s.namespace, m.State); err != nil {
			return fmt.Errorf("mount %s: %w", m.Path, err)
		}
	}
	_, err = s.cluster.UpdateStateMounts(ctx, s.namespace, root.Name, add...)
	return err
}

// createMountCopy creates the private writable copy a profile mount uses. The
// copy belongs to the chat so deleting the chat removes it.
func (s *Server) createMountCopy(ctx context.Context, root *v1.BlipState, mount mountSource) (*v1.BlipState, error) {
	st := &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{
			Name:      mountStateName(root.Name, mount.Path),
			Namespace: s.namespace,
			Labels: map[string]string{
				LabelSession:  "true",
				v1.LabelOwner: root.Labels[v1.LabelOwner],
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: v1.GroupVersion.String(),
				Kind:       "BlipState",
				Name:       root.Name,
				UID:        root.UID,
			}},
		},
		Spec: v1.BlipStateSpec{CopyFrom: mount.Source},
	}
	if err := s.cluster.CreateSession(ctx, s.namespace, st); err != nil {
		return nil, fmt.Errorf("create mount %s from %s: %w", mount.Path, mount.Source, err)
	}
	return st, nil
}

// mountStateName is a legal DNS label for a mount copy. The path hash keeps
// the name stable across retries and distinct per path; session names may be
// subdomains, so dots become hyphens.
func mountStateName(session, mountPath string) string {
	session = strings.ReplaceAll(session, ".", "-")
	sum := sha256.Sum256([]byte(mountPath))
	suffix := fmt.Sprintf("-m-%x", sum[:4])
	if max := 63 - len(suffix); len(session) > max {
		session = strings.TrimRight(session[:max], "-")
	}
	return session + suffix
}

// mountPaths lists the paths a profile mounts, for list_profiles.
func (p Profile) mountPaths() []string {
	if len(p.Mounts) == 0 {
		return nil
	}
	out := make([]string, 0, len(p.Mounts))
	for _, m := range p.Mounts {
		out = append(out, m.Path)
	}
	return out
}
