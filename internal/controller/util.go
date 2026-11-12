package controller

import (
	"crypto/hmac"
	"crypto/sha256"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/example/blip/internal/api"
	v1 "github.com/example/blip/internal/api/v1alpha1"
)

// blipConditions are added on the first reconcile.
var blipConditions = []string{api.CondScheduled, api.CondStarted, api.CondFinished, api.CondComplete, api.CondFailed}

// initConditions adds missing Blip conditions as False. It reports whether it changed anything.
func initConditions(b *v1.Blip) bool {
	changed := false
	for _, t := range blipConditions {
		if meta.FindStatusCondition(b.Status.Conditions, t) == nil {
			reason := api.ReasonPending
			meta.SetStatusCondition(&b.Status.Conditions, metav1.Condition{Type: t, Status: metav1.ConditionFalse, Reason: reason, ObservedGeneration: b.Generation})
			changed = true
		}
	}
	if b.Status.Phase == "" {
		b.Status.Phase = v1.BlipPending
		changed = true
	}
	return changed
}

func setCond(conds *[]metav1.Condition, gen int64, t string, status bool, reason, msg string) {
	s := metav1.ConditionFalse
	if status {
		s = metav1.ConditionTrue
	}
	meta.SetStatusCondition(conds, metav1.Condition{Type: t, Status: s, Reason: reason, Message: msg, ObservedGeneration: gen})
}

func isTrue(conds []metav1.Condition, t string) bool {
	return meta.IsStatusConditionTrue(conds, t)
}

func condReason(conds []metav1.Condition, t string) string {
	if c := meta.FindStatusCondition(conds, t); c != nil {
		return c.Reason
	}
	return ""
}

// isFinished reports whether the Blip is Finished.
func isFinished(b *v1.Blip) bool { return isTrue(b.Status.Conditions, api.CondFinished) }

// isFailed reports whether the Blip has Failed=True.
func isFailed(b *v1.Blip) bool { return isTrue(b.Status.Conditions, api.CondFailed) }

// isRunningForQuota reports whether the Blip counts against the running quota.
func isRunningForQuota(b *v1.Blip) bool { return b.Status.Allocation != nil && !isFinished(b) }

// setFailed marks the run failed. Finished is set later, after cleanup.
func setFailed(b *v1.Blip, reason, msg string) {
	setCond(&b.Status.Conditions, b.Generation, api.CondFailed, true, reason, firstLine(msg))
	setCond(&b.Status.Conditions, b.Generation, api.CondComplete, false, reason, "")
	if isTrue(b.Status.Conditions, api.CondRescheduling) {
		setCond(&b.Status.Conditions, b.Generation, api.CondRescheduling, false, reason, "")
	}
	b.Status.Phase = v1.BlipFailed
	if msg != "" {
		b.Status.Message = msg
	}
}

// setFinished sets Finished with the reason of Complete or Failed.
func setFinished(b *v1.Blip, now time.Time) {
	reason := condReason(b.Status.Conditions, api.CondFailed)
	if isTrue(b.Status.Conditions, api.CondComplete) {
		reason = api.ReasonSucceeded
	}
	setCond(&b.Status.Conditions, b.Generation, api.CondFinished, true, reason, "")
	if b.Status.CompletionTime == nil {
		t := metav1.NewTime(now)
		b.Status.CompletionTime = &t
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// PSK returns HMAC-SHA256(clusterKey, hostNQN) (design 7.3).
func PSK(clusterKey []byte, hostNQN string) []byte {
	m := hmac.New(sha256.New, clusterKey)
	m.Write([]byte(hostNQN))
	return m.Sum(nil)
}

// backoff returns the retry delay for attempt n (0 based): base doubling up to max.
func backoff(n int, base, max time.Duration) time.Duration {
	d := base
	for i := 0; i < n && d < max; i++ {
		d *= 2
	}
	if d > max {
		d = max
	}
	return d
}

// timeNow is replaced in tests.
var timeNow = time.Now

// newID returns a random content or allocation ID (16 hex characters).
func newID() string { return randID() }
