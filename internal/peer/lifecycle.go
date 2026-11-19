// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package peer

import (
	"context"
	"net/http"
	"time"
)

// LeaseOperation identifies a transaction's ordered, idempotent effects. A
// failed effect stops the transaction; cleanup can safely restart at the first
// effect. In particular, revocation must be durable before removing a device.
type LeaseOperation uint8

const (
	PrepareLease LeaseOperation = iota
	ActivateLease
	ReleaseLease
)

type LeaseEffect uint8

const (
	LeaseDone LeaseEffect = iota
	LeasePin
	LeasePersist
	LeaseOpenDevice
	LeasePublish
	LeasePersistRevocation
	LeaseUnpublish
	LeaseCloseDevice
	LeaseUnpin
	LeaseForget
)

// NextLeaseEffect is the production lifecycle's pure sequencing decision.
// completed is LeaseDone before the first effect, otherwise the last successful
// effect. Failed/ambiguous effects must not be reported as completed.
func NextLeaseEffect(op LeaseOperation, completed LeaseEffect) LeaseEffect {
	var steps []LeaseEffect
	switch op {
	case PrepareLease:
		steps = []LeaseEffect{LeasePin, LeasePersist}
	case ActivateLease:
		steps = []LeaseEffect{LeasePin, LeaseOpenDevice, LeasePublish}
	case ReleaseLease:
		steps = []LeaseEffect{LeasePersistRevocation, LeaseUnpublish, LeaseCloseDevice, LeaseUnpin, LeaseForget}
	}
	if completed == LeaseDone && len(steps) > 0 {
		return steps[0]
	}
	for i := 0; i+1 < len(steps); i++ {
		if steps[i] == completed {
			return steps[i+1]
		}
	}
	return LeaseDone
}

func runLeaseEffects(op LeaseOperation, apply func(LeaseEffect) error) error {
	for effect := NextLeaseEffect(op, LeaseDone); effect != LeaseDone; effect = NextLeaseEffect(op, effect) {
		if err := apply(effect); err != nil {
			return err
		}
	}
	return nil
}

// LeaseMustRelease is shared by activation, renewal, recheck, and recovery.
// The deadline is exclusive: a renewal at the expiry instant is too late.
func LeaseMustRelease(now, lastRenewed time.Time, revoked, registered, authorized bool) bool {
	return revoked || !registered || !authorized || !now.Before(lastRenewed.Add(LeaseTTL))
}

type RetryDecision struct {
	Stop  bool
	Delay time.Duration
}

// ReleaseRetry counts completed attempts, not time spent waiting for initial
// discovery. Network errors include ambiguous successes: release is idempotent.
func ReleaseRetry(attempts int, succeeded, canceled bool) RetryDecision {
	if succeeded || canceled || attempts >= releaseMaxAttempts {
		return RetryDecision{Stop: true}
	}
	delay := releaseMinBackoff
	for i := 1; i < attempts && delay < releaseMaxBackoff; i++ {
		delay = min(2*delay, releaseMaxBackoff)
	}
	return RetryDecision{Delay: delay}
}

// RenewalRetry treats 403/404 as terminal. A lost response is transient even
// when the server durably renewed the lease before the connection was lost.
func RenewalRetry(status int, failed, canceled bool) RetryDecision {
	if canceled || status == http.StatusNotFound || status == http.StatusForbidden {
		return RetryDecision{Stop: true}
	}
	if failed {
		return RetryDecision{Delay: releaseMaxBackoff}
	}
	return RetryDecision{Delay: leaseRenewInterval}
}

// Clock controls lifecycle time and waits per instance. Implementations must
// honor cancellation. The zero configuration uses the real clock.
type Clock interface {
	Now() time.Time
	Wait(context.Context, time.Duration) error
	WithTimeout(context.Context, time.Duration) (context.Context, context.CancelFunc)
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }
func (realClock) WithTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, d)
}
func (realClock) Wait(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return ctx.Err()
	}
}
