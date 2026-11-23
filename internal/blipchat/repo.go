// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// defaultRepoRoot is where claim_repo mounts a repository when the caller does
// not choose a path.
const defaultRepoRoot = "/src"

// repoMountTimeout bounds how long claim_repo waits for the copy to attach to
// the running blip. The copy usually starts before the request returns, but a
// busy node may take longer; the agent can use the reported path either way.
const repoMountTimeout = 60 * time.Second

// reservedMounts are guest-managed paths a claim may not shadow.
var reservedMounts = []string{"/proc", "/sys", "/dev", "/run/blip", "/run/blip-collect"}

// repoClaim is the tool result. All fields are always present so an agent does
// not have to distinguish an omitted field from an empty one.
type repoClaim struct {
	Repo     string `json:"repo"`
	Path     string `json:"path"`
	State    string `json:"state"`
	URL      string `json:"url"`
	Branch   string `json:"branch"`
	CachedAt string `json:"cachedAt"`
	Mounted  bool   `json:"mounted"`
	Next     string `json:"next"`
	Note     string `json:"note,omitempty"`
}

// toolClaimRepo copies a shared git cache into a writable state owned by the
// chat and mounts it into the caller's workspace. The copy is a filesystem
// clone, so it is much faster than fetching the repository, and it stays
// private to the chat.
func (s *Server) toolClaimRepo(ctx context.Context, caller *Caller, repo, mountPath string) (string, error) {
	repo = strings.TrimSpace(repo)
	if repo == "" {
		return "", errors.New("repo is required")
	}
	if !validDNSLabel(repo) {
		return "", fmt.Errorf("repo %q is not a repository name", repo)
	}
	mountPath, err := repoMountPath(mountPath, repo)
	if err != nil {
		return "", err
	}

	cache, err := s.newestRepoCache(ctx, caller.Namespace, repo)
	if err != nil {
		return "", err
	}
	if cache == nil {
		available, err := s.availableRepos(ctx, caller.Namespace)
		if err != nil {
			return "", err
		}
		if len(available) == 0 {
			return "", fmt.Errorf("unknown repo %q; available: none", repo)
		}
		return "", fmt.Errorf("unknown repo %q; available: %s", repo, strings.Join(available, ", "))
	}

	// Reusing an existing claim before creating another avoids a duplicate
	// copy when the agent retries the tool in a later turn, and lets a chat
	// that inherited a repo through a fork (or that claimed an older cache
	// generation) keep using it. A mount at the requested path always decides:
	// it must be a copy of this repo. Otherwise any mount of this repo wins.
	mounts := caller.Session.Spec.Mounts
	var existingMount *v1.Mount
	var existingState *v1.BlipState
	for i := range mounts {
		m := &mounts[i]
		mounted, err := s.cluster.GetSession(ctx, caller.Namespace, m.State)
		if err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return "", err
		}
		if m.Path == mountPath {
			if mounted.Labels[v1.LabelGitRepo] != repo {
				return "", fmt.Errorf("path %q is already mounted from %q", m.Path, m.State)
			}
			existingMount, existingState = m, mounted
			break
		}
		if existingMount == nil && mounted.Labels[v1.LabelGitRepo] == repo {
			existingMount, existingState = m, mounted
		}
	}
	if existingMount != nil {
		reported := s.claimCache(ctx, caller.Namespace, existingState, cache)
		return repoClaimText(repo, existingMount.Path, existingMount.State, reported, true), nil
	}

	owner := caller.Session.Labels[v1.LabelOwner]
	name := repoClaimName(caller.Session.Name, repo)
	claim, err := s.ensureRepoClaim(ctx, caller, cache, name, owner, repo)
	if err != nil {
		return "", err
	}
	if err := s.waitRepoClaimReady(ctx, caller.Namespace, claim.Name); err != nil {
		return "", err
	}

	if _, err := s.cluster.UpdateStateMounts(ctx, caller.Namespace, caller.Session.Name, v1.Mount{
		State: claim.Name, Path: mountPath, Writable: true,
	}); err != nil {
		return "", err
	}

	mounted := s.waitRepoMount(ctx, caller, mountPath, claim.Name)
	return repoClaimText(repo, mountPath, claim.Name, cache, mounted), nil
}

// repoMountPath defaults to /src/<repo> and otherwise requires an absolute,
// already-clean path outside the guest's reserved directories.
func repoMountPath(requested, repo string) (string, error) {
	if strings.TrimSpace(requested) == "" {
		return path.Join(defaultRepoRoot, repo), nil
	}
	requested = strings.TrimSpace(requested)
	if !path.IsAbs(requested) {
		return "", fmt.Errorf("path %q must be absolute", requested)
	}
	if clean := path.Clean(requested); clean != requested {
		return "", fmt.Errorf("path %q is not clean; use %q", requested, clean)
	}
	if requested == "/" {
		return "", errors.New("path must not be the guest root")
	}
	for _, reserved := range reservedMounts {
		if requested == reserved || strings.HasPrefix(requested, reserved+"/") {
			return "", fmt.Errorf("path %q is reserved by the guest", requested)
		}
	}
	return requested, nil
}

// newestRepoCache returns the newest ready cache for repo, or nil when the
// namespace has no usable cache. A cache that is still copying or failed is
// ignored so a newer, complete cache can be chosen instead.
func (s *Server) newestRepoCache(ctx context.Context, ns, repo string) (*v1.BlipState, error) {
	selector := labels.SelectorFromSet(labels.Set{v1.LabelShared: "true", v1.LabelGitRepo: repo})
	states, err := s.cluster.ListStates(ctx, ns, selector)
	if err != nil {
		return nil, err
	}
	var best *v1.BlipState
	for i := range states {
		st := &states[i]
		if st.DeletionTimestamp != nil || st.Status.Phase != v1.StateReady || st.Status.Committed == nil {
			continue
		}
		if best == nil || newerCache(st, best) {
			best = st
		}
	}
	return best, nil
}

// newerCache orders caches by commit time, then by name so the choice is
// stable when two refreshes committed in the same second.
func newerCache(a, b *v1.BlipState) bool {
	at, bt := a.Status.Committed.Time.Time, b.Status.Committed.Time.Time
	if !at.Equal(bt) {
		return at.After(bt)
	}
	return a.Name > b.Name
}

// availableRepos lists the repositories that have any shared cache, including
// ones that are not ready, so an unknown-repo error explains what exists.
func (s *Server) availableRepos(ctx context.Context, ns string) ([]string, error) {
	states, err := s.cluster.ListStates(ctx, ns, labels.SelectorFromSet(labels.Set{v1.LabelShared: "true"}))
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var repos []string
	for i := range states {
		repo := states[i].Labels[v1.LabelGitRepo]
		if repo == "" || seen[repo] {
			continue
		}
		seen[repo] = true
		repos = append(repos, repo)
	}
	sort.Strings(repos)
	return repos, nil
}

// ensureRepoClaim returns the claim state, creating it when it does not exist.
// A state with the claim name is only accepted when it is this cache's claim
// for this chat; anything else means the name is occupied.
func (s *Server) ensureRepoClaim(ctx context.Context, caller *Caller, cache *v1.BlipState, name, owner, repo string) (*v1.BlipState, error) {
	accept := func(st *v1.BlipState) error {
		if st.Labels[v1.LabelGitRepo] != repo || st.Labels[v1.LabelOwner] != owner {
			return fmt.Errorf("claim name %q is already in use", name)
		}
		return nil
	}

	st, err := s.cluster.GetSession(ctx, caller.Namespace, name)
	switch {
	case err == nil:
		if err := accept(st); err != nil {
			return nil, err
		}
		return st, nil
	case !apierrors.IsNotFound(err):
		return nil, err
	}

	st = &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: caller.Namespace,
			Labels: map[string]string{
				v1.LabelChatSession: "true",
				v1.LabelOwner:       owner,
				v1.LabelGitRepo:     repo,
			},
			Annotations: map[string]string{v1.AnnotationGitSource: cache.Name},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: v1.GroupVersion.String(),
				Kind:       "BlipState",
				Name:       caller.Session.Name,
				UID:        caller.Session.UID,
			}},
		},
		Spec: v1.BlipStateSpec{CopyFrom: cache.Name},
	}
	if err := s.cluster.CreateSession(ctx, caller.Namespace, st); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return nil, err
		}
		// Another request created it between the read and the create.
		existing, err := s.cluster.GetSession(ctx, caller.Namespace, name)
		if err != nil {
			return nil, err
		}
		if err := accept(existing); err != nil {
			return nil, err
		}
		return existing, nil
	}
	return st, nil
}

// waitRepoClaimReady waits for the filesystem copy to commit or fail.
func (s *Server) waitRepoClaimReady(ctx context.Context, ns, name string) error {
	deadline := time.Now().Add(startTimeout)
	for {
		st, err := s.cluster.GetSession(ctx, ns, name)
		if err == nil && st.Status.Phase == v1.StateReady {
			return nil
		}
		if err == nil && st.Status.Phase == v1.StateFailed {
			return fmt.Errorf("repo claim %s could not start: %s", name, st.Status.Message)
		}
		if err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("repo claim %s could not start: timed out waiting for the copy", name)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(statusPoll):
		}
	}
}

// waitRepoMount reports whether the running blip has attached the mount. A
// timeout is not an error: the mount is in the root state and will attach on
// the next reconcile, so the caller may already use the path.
func (s *Server) waitRepoMount(ctx context.Context, caller *Caller, mountPath, state string) bool {
	if caller.Blip == nil {
		return false
	}
	deadline := time.Now().Add(repoMountTimeout)
	for {
		blip, err := s.cluster.GetBlip(ctx, caller.Namespace, caller.Blip.Name)
		if err == nil {
			for _, m := range blip.Status.Mounts {
				if m.Path == mountPath && m.State == state && m.Phase == v1.MountMounted {
					return true
				}
			}
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(statusPoll):
		}
	}
}

// claimCache reports the cache version a claim was copied from, so a reused
// claim describes its own snapshot rather than a newer generation.
func (s *Server) claimCache(ctx context.Context, ns string, claim, fallback *v1.BlipState) *v1.BlipState {
	name := claim.Annotations[v1.AnnotationGitSource]
	if name == "" || name == fallback.Name {
		return fallback
	}
	st, err := s.cluster.GetSession(ctx, ns, name)
	if err != nil || st.Status.Committed == nil {
		return fallback
	}
	return st
}

// repoClaimText renders the tool result. next assumes the agent is already in
// a shell; the branch command is only useful when the cache recorded one.
func repoClaimText(repo, mountPath, state string, cache *v1.BlipState, mounted bool) string {
	branch := cache.Annotations[v1.AnnotationGitBranch]
	next := fmt.Sprintf("git -C %s fetch --prune origin", mountPath)
	if branch != "" {
		next += fmt.Sprintf("; git -C %s merge --ff-only origin/%s", mountPath, branch)
	}
	out := repoClaim{
		Repo:    repo,
		Path:    mountPath,
		State:   state,
		URL:     cache.Annotations[v1.AnnotationGitURL],
		Branch:  branch,
		Mounted: mounted,
		Next:    next,
	}
	if cache.Status.Committed != nil {
		out.CachedAt = cache.Status.Committed.Time.Format(time.RFC3339)
	}
	if !mounted {
		out.Note = "the repository copy is ready; it is still attaching to the running blip"
	}
	return jsonText(out)
}

// repoClaimName is a legal DNS label for the claim: <session>-r-<repo>, or a
// hashed form when that would exceed 63 characters. Session names may be
// subdomains, so dots become hyphens; truncating the joined form stays legal
// because both inputs end in an alphanumeric character.
func repoClaimName(session, repo string) string {
	session = strings.ReplaceAll(session, ".", "-")
	name := session + "-r-" + repo
	if len(name) <= 63 {
		return name
	}
	prefix := session + "-r-"
	if len(prefix) > 40 {
		prefix = prefix[:40]
	}
	prefix = strings.TrimRight(prefix, "-")
	sum := sha256.Sum256([]byte(session + "\x00" + repo))
	return fmt.Sprintf("%s-%x", prefix, sum[:4])
}
