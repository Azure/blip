package cli

import (
	"context"
	"fmt"

	"github.com/Azure/blip/api/v1alpha1"
)

// stateFailure returns why a state cannot commit, or "" while it can still
// make progress. A failed first version with a pending commit is retried by
// the controller, so it is not terminal.
func stateFailure(s *v1alpha1.BlipState) string {
	if s.Status.Phase != v1alpha1.StateFailed || s.Status.Pending != nil {
		return ""
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
		if msg := stateFailure(s); msg != "" {
			return false, fmt.Errorf("state %q failed: %s", a.short(name), msg)
		}
		if s.Status.Message != "" {
			r.say("waiting for state %s: %s", a.short(name), s.Status.Message)
		}
		return false, nil
	})
	return got, err
}
