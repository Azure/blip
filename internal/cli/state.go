package cli

import (
	"context"
	"fmt"

	"github.com/Azure/blip/api/v1alpha1"
)

// stateFailure returns why a state cannot commit, or "" while it can still
// make progress. A Failed state is terminal even if a stale pending commit is
// still recorded: the controller may keep retrying that commit, but a client
// must not wait forever for a state whose immutable provisioning can never
// succeed (for example an image larger than --size).
func stateFailure(s *v1alpha1.BlipState) string {
	if s.Status.Phase != v1alpha1.StateFailed {
		return ""
	}
	return stateFailureMessage(s)
}

// usableStateFailure returns why an existing state cannot be used as a run
// source or root. A state with a committed version remains usable even if its
// initialization history left a failed phase behind.
func usableStateFailure(s *v1alpha1.BlipState) string {
	if s.Status.Committed != nil {
		return ""
	}
	return stateFailure(s)
}

func stateFailureMessage(s *v1alpha1.BlipState) string {
	if s.Status.LastError != "" {
		return s.Status.LastError
	}
	if s.Status.Message != "" {
		return s.Status.Message
	}
	return "creation failed"
}

// waitStateCommitted waits until the state's first commit is usable, whether
// it is Ready or already attached by a concurrent blip. A fork's snapshot is
// usable once its first commit exists, so run can return.
func (a *app) waitStateCommitted(ctx context.Context, name string) (*v1alpha1.BlipState, error) {
	return a.waitStateCommittedUnless(ctx, name, stateFailure)
}

func (a *app) waitStateCommittedUnless(ctx context.Context, name string, failure func(*v1alpha1.BlipState) string) (*v1alpha1.BlipState, error) {
	r := &reporter{a: a}
	defer r.stop()
	var got *v1alpha1.BlipState
	err := a.waitState(ctx, name, func(s *v1alpha1.BlipState) (bool, error) {
		if s == nil {
			return false, fmt.Errorf("state %q was deleted", a.short(name))
		}
		got = s
		if s.Status.Committed != nil {
			return true, nil
		}
		if msg := failure(s); msg != "" {
			return false, fmt.Errorf("state %q failed: %s", a.short(name), msg)
		}
		if s.Status.Message != "" {
			r.say("waiting for state %s: %s", a.short(name), s.Status.Message)
		}
		return false, nil
	})
	return got, err
}
