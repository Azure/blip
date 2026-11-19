package blipchat

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/session"
)

const (
	requeueDelay = 2 * time.Second
	stepInterval = 2 * time.Second
	// defaultTurnAge is the retention applied to turns that no thread can
	// prune, and the default for threads without retention.turns.
	defaultTurnAge = 7 * 24 * time.Hour
	// turnField indexes BlipTurns by spec.thread.
	turnField = "spec.thread"
	// budgetPauseReason is the only pause blipchat clears automatically.
	budgetPauseReason = "daily token budget exhausted"
	// promptBudget bounds the turns section of one step's user prompt.
	promptBudget = 48000
	// boardBudget bounds the task board so it cannot crowd the turns out of
	// the prompt. The CRD allows a board far larger than a whole prompt.
	boardBudget = promptBudget / 2
	// stalledPromptBackoff delays a thread whose pending turns cannot be
	// rendered within promptBudget at all. Without it the same unrenderable
	// input would return to shouldStep every tick.
	stalledPromptBackoff = time.Minute
)

var timeNow = time.Now

// errStaleIncarnation means the thread name now belongs to a different
// incarnation than the snapshot a step or prune pass started from. The
// snapshot's turns, board, timers and spend must not be written to it.
var errStaleIncarnation = errors.New("thread incarnation changed")

// currentThread re-reads a thread and rejects it when the name was deleted
// and recreated since snapshot was taken.
func (s *Server) currentThread(ctx context.Context, snapshot *v1.BlipThread) (*v1.BlipThread, error) {
	current := &v1.BlipThread{}
	if err := s.Get(ctx, client.ObjectKeyFromObject(snapshot), current); err != nil {
		return nil, err
	}
	if snapshot.UID != "" && current.UID != snapshot.UID {
		return nil, errStaleIncarnation
	}
	return current, nil
}

// logError logs when a logger was configured. Tests construct Server values
// without one, and a zero logr.Logger panics on use.
func (s *Server) logError(err error, msg string, kv ...any) {
	if s.Log.GetSink() == nil {
		return
	}
	s.Log.Error(err, msg, kv...)
}

func nowTime() *metav1.Time {
	t := metav1.NewTime(timeNow())
	return &t
}

// Server holds the clients and settings shared by sequencing, watching, and
// stepping.
type Server struct {
	client.Client
	Config     Config
	LLM        *LLM
	RestConfig *rest.Config
	Cache      cache.Cache
	Log        logr.Logger

	stepMu     sync.Mutex // one coordinator step at a time
	execOnce   sync.Once
	execClient *session.Client
	execErr    error

	backoffMu  sync.Mutex
	backoff    map[string]time.Time
	pruneCount int
}

// Steps runs coordinator steps. It is a leader-elected runnable: only the
// elected replica advances threads.
func (s *Server) Steps(ctx context.Context) error {
	ticker := time.NewTicker(stepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			threads := &v1.BlipThreadList{}
			if err := s.List(ctx, threads); err != nil {
				s.Log.Error(err, "list threads")
				continue
			}
			s.pruneCount++
			prune := s.pruneCount >= 150
			if prune {
				s.pruneCount = 0
			}
			for i := range threads.Items {
				thread := &threads.Items[i]
				s.maybeUnpause(ctx, thread)
				if prune {
					if err := s.prune(ctx, thread); err != nil {
						s.Log.Error(err, "prune thread", "thread", thread.Namespace+"/"+thread.Name)
					}
				}
				if !s.shouldStep(ctx, thread) {
					continue
				}
				s.stepMu.Lock()
				err := s.step(ctx, thread)
				s.stepMu.Unlock()
				if err != nil {
					s.Log.Error(err, "coordinator step", "thread", thread.Namespace+"/"+thread.Name)
					s.deferThread(thread, errRetry)
				}
			}
			if prune {
				if err := s.pruneOrphanTurns(ctx, threads.Items); err != nil {
					s.Log.Error(err, "prune orphan turns")
				}
			}
		}
	}
}

const errRetry = time.Minute

func (s *Server) deferThread(thread *v1.BlipThread, delay time.Duration) {
	s.backoffMu.Lock()
	if s.backoff == nil {
		s.backoff = map[string]time.Time{}
	}
	s.backoff[thread.Namespace+"/"+thread.Name] = timeNow().Add(delay)
	s.backoffMu.Unlock()
}

func (s *Server) backingOff(thread *v1.BlipThread) bool {
	s.backoffMu.Lock()
	defer s.backoffMu.Unlock()
	until, ok := s.backoff[thread.Namespace+"/"+thread.Name]
	if !ok {
		return false
	}
	if timeNow().After(until) {
		delete(s.backoff, thread.Namespace+"/"+thread.Name)
		return false
	}
	return true
}

func (s *Server) shouldStep(ctx context.Context, thread *v1.BlipThread) bool {
	if thread.Status.Paused != nil || thread.DeletionTimestamp != nil || s.backingOff(thread) {
		return false
	}
	now := timeNow()
	if wake := thread.Status.NextWake; wake != nil && !now.Before(wake.Time) {
		return true
	}
	// A stored timer that is already due is a pending wake even if an older
	// version of status did not record it in NextWake.
	for _, timer := range thread.Status.Timers {
		if !timer.At.After(now) {
			return true
		}
	}
	turns, err := s.pendingTurns(ctx, thread)
	if err != nil {
		s.Log.Error(err, "list pending turns", "thread", thread.Namespace+"/"+thread.Name)
		return false
	}
	// WakeNone turns are context for a later step, never a reason to step.
	var waking []v1.BlipTurn
	for _, t := range turns {
		if t.Spec.Wake == v1.WakeNow {
			return true
		}
		if t.Spec.Wake != v1.WakeNone {
			waking = append(waking, t)
		}
	}
	if len(waking) > 0 {
		oldest := waking[0].Status.AcceptedTime
		if oldest != nil && !now.Before(oldest.Add(s.Config.Debounce)) {
			return true
		}
	}
	if len(waking) == 0 && thread.Status.NextWake == nil && hasOpenTask(thread.Status.Tasks) {
		return true
	}
	return false
}

func hasOpenTask(tasks []v1.ThreadTask) bool {
	for _, t := range tasks {
		if t.Open {
			return true
		}
	}
	return false
}

// pendingTurns returns every turn not yet consumed, in sequence order,
// excluding the coordinator's own output. It deliberately keeps turns older
// than any fixed window: a step must never consume a turn it did not show to
// the coordinator, and an old Wake=Now turn must still be able to wake it.
func (s *Server) pendingTurns(ctx context.Context, thread *v1.BlipThread) ([]v1.BlipTurn, error) {
	var turns v1.BlipTurnList
	if err := s.List(ctx, &turns, client.InNamespace(thread.Namespace), client.MatchingFields{turnField: thread.Name}); err != nil {
		return nil, err
	}
	out := turns.Items[:0]
	for _, t := range turns.Items {
		if !turnBelongsToThread(&t, thread) ||
			t.Status.Seq <= thread.Status.ConsumedSeq || t.Spec.Author.Kind == v1.TurnAuthorCoordinator {
			continue
		}
		out = append(out, t)
	}
	sortTurns(out)
	return out, nil
}

// step is one coordinator advance. It is not safe for concurrent use; the
// server serializes steps.
type step struct {
	s      *Server
	thread *v1.BlipThread
	tasks  []v1.ThreadTask
	timers []v1.ThreadTimer
	// replies become coordinator turns at the end of the step.
	replies []v1.BlipTurnSpec
	// started records the blips and states this step's start_task calls
	// created, so an abandoned step can remove them.
	started []startedTask
	summary string
	// summarySet distinguishes "remember was called" (even with empty text)
	// from a step that did not touch the summary.
	summarySet bool
	paused     string
	// deferred records a step that made no renderable progress. Its next
	// wake is delayed instead of immediately re-running the same input.
	deferred bool
	usage    int64
}

func (s *Server) step(ctx context.Context, thread *v1.BlipThread) error {
	pending, err := s.pendingTurns(ctx, thread)
	if err != nil {
		return err
	}
	now := timeNow()
	st := &step{
		s: s, thread: thread,
		tasks:   append([]v1.ThreadTask{}, thread.Status.Tasks...),
		timers:  append([]v1.ThreadTimer{}, thread.Status.Timers...),
		summary: thread.Status.Summary,
	}
	// Check the budget before draining timers or turns: an exhausted step does
	// not process this input, so it must stay pending.
	started := timeNow()
	tokensToday := thread.Status.TokensToday
	if thread.Status.TokenDay != started.UTC().Format("2006-01-02") {
		tokensToday = 0
	}
	if thread.Spec.DailyTokens > 0 && tokensToday >= thread.Spec.DailyTokens {
		st.paused = budgetPauseReason
		return s.commitStep(ctx, st, thread.Status.ConsumedSeq, pending, started)
	}

	// Consume due timers: their notes are part of this step's input.
	allTimers := append([]v1.ThreadTimer{}, st.timers...)
	var dueTimers []v1.ThreadTimer
	kept := st.timers[:0]
	for _, timer := range st.timers {
		if !timer.At.After(now) {
			dueTimers = append(dueTimers, timer)
			continue
		}
		kept = append(kept, timer)
	}
	st.timers = kept

	model := thread.Spec.Model
	if model == "" {
		model = s.Config.Model
	}
	if model == "" {
		return fmt.Errorf("no model: set spec.model or --model")
	}

	messages := []Message{
		{Role: "system", Content: systemPrompt(thread)},
	}
	prompt, lastRendered := boardPrompt(thread, st.tasks, pending, dueTimers, st.summary)
	// A renderer that cannot show even the oldest pending turn cannot make
	// contiguous progress: a completion would send the same input and repeat
	// its replies every tick. Keep every turn pending and defer the retry
	// instead of paying for an identical step.
	if len(pending) > 0 && lastRendered <= thread.Status.ConsumedSeq {
		st.deferred = true
		// This step consumed no input, so keep the due timers pending too.
		st.timers = allTimers
		if err := s.commitStep(ctx, st, thread.Status.ConsumedSeq, pending, started); err != nil {
			return err
		}
		s.deferThread(thread, stalledPromptBackoff)
		return nil
	}
	target := thread.Status.ConsumedSeq
	if len(pending) > 0 {
		target = pending[len(pending)-1].Status.Seq
	}
	// Never advance ConsumedSeq past a turn the prompt did not render, and
	// never move it backwards: a rewind resurrects consumed turns and makes
	// the same step run again.
	if len(pending) > 0 && lastRendered < target {
		target = lastRendered
	}
	if target < thread.Status.ConsumedSeq {
		target = thread.Status.ConsumedSeq
	}
	messages = append(messages, Message{Role: "user", Content: prompt})
	toollist := st.tools()
	for calls := 0; calls < s.Config.MaxToolCalls; calls++ {
		reply, usage, err := s.LLM.Chat(ctx, model, messages, toollist)
		if err != nil {
			// The completion was paid for even though the step fails, so the
			// spend must still count against the daily budget.
			s.chargeUsage(ctx, thread, st.usage)
			return err
		}
		st.usage += usage.Total()
		messages = append(messages, reply)
		// Crossing the daily budget mid-step must not strand the completion
		// we already paid for: run its tool calls (including reply) and then
		// stop before requesting another completion.
		overBudget := thread.Spec.DailyTokens > 0 && tokensToday+st.usage >= thread.Spec.DailyTokens
		if len(reply.ToolCalls) == 0 {
			if overBudget {
				st.paused = budgetPauseReason
			}
			break
		}
		for _, call := range reply.ToolCalls {
			result, err := st.call(ctx, call.Function.Name, call.Function.Arguments)
			if err != nil {
				result = "error: " + err.Error()
			}
			messages = append(messages, Message{Role: "tool", ToolCallID: call.ID, Content: result})
		}
		if overBudget {
			st.paused = budgetPauseReason
			break
		}
		if st.usage >= s.Config.StepTokenLimit {
			break
		}
	}
	if err := s.commitStep(ctx, st, target, pending, started); err != nil {
		s.chargeUsage(ctx, thread, st.usage)
		return err
	}
	return nil
}

// commitStep commits a finished step. A thread deleted and recreated while
// the completion was in flight is left untouched: the step belongs to the
// previous incarnation, whose turn history and board are already gone. Work
// the abandoned step started is removed so it does not outlive its thread.
func (s *Server) commitStep(ctx context.Context, st *step, target int64, pending []v1.BlipTurn, started time.Time) error {
	err := s.commit(ctx, st, target, pending, started)
	if errors.Is(err, errStaleIncarnation) {
		s.discardStarted(ctx, st)
		return nil
	}
	return err
}

// discardStarted removes the blips and states this step started. Only objects
// created by the step are deleted: everything recorded in st.started carries
// the UID assigned when it was created, so an object replaced in the meantime
// is never touched. States go first because deleting a Blip cascades to its
// owned workspace.
func (s *Server) discardStarted(ctx context.Context, st *step) {
	ctx = context.WithoutCancel(ctx)
	for i := len(st.started) - 1; i >= 0; i-- {
		started := st.started[i]
		for j := len(started.states) - 1; j >= 0; j-- {
			s.deleteCreated(ctx, started.states[j])
		}
		s.deleteCreated(ctx, started.blip)
	}
}

func (s *Server) deleteCreated(ctx context.Context, obj client.Object) {
	opts := &client.DeleteOptions{}
	if uid := obj.GetUID(); uid != "" {
		opts.Preconditions = &metav1.Preconditions{UID: &uid}
	}
	if err := s.Delete(ctx, obj, opts); err != nil && !apierrors.IsNotFound(err) {
		s.logError(err, "remove stale step object", "name", obj.GetName())
	}
}

// commit writes the step's coordinator turns and then one thread status
// update. Turns are named by step start so retries are idempotent.
func (s *Server) commit(ctx context.Context, st *step, target int64, _ []v1.BlipTurn, started time.Time) error {
	// Abandon before creating any coordinator turn when the name already
	// belongs to another incarnation. createTurnIn repeats the UID check so a
	// deletion racing this commit cannot attach replies to the new thread.
	if _, err := s.currentThread(ctx, st.thread); err != nil {
		return err
	}
	key := &ThreadKey{Namespace: st.thread.Namespace, Name: st.thread.Name}
	prefix := fmt.Sprintf("coord-%s-%d", Owner(key), started.Unix())
	for i := range st.replies {
		spec := st.replies[i]
		if err := createTurnIn(ctx, s.Client, st.thread.Namespace, fmt.Sprintf("%s-%d", prefix, i), turnSpec{
			Thread: spec.Thread, ThreadUID: string(st.thread.UID), AuthorKind: spec.Author.Kind, AuthorName: spec.Author.Name,
			Topic: spec.Topic, Text: spec.Text, InReplyTo: spec.InReplyTo, Wake: v1.WakeNone,
		}); err != nil {
			return err
		}
	}
	tokens := st.usage
	today := started.UTC().Format("2006-01-02")
	next := nextWake(st, started)
	if st.deferred {
		// The step did not run, so retry after the bounded backoff rather
		// than schedule an immediate wake for the same input.
		next = &metav1.Time{Time: started.Add(stalledPromptBackoff)}
	}
	for attempt := 0; attempt < 5; attempt++ {
		current, err := s.currentThread(ctx, st.thread)
		if err != nil {
			return err
		}
		// A concurrent commit must never let this step move consumption
		// backwards, even when its prompt rendered only older turns.
		consumed := target
		if consumed < current.Status.ConsumedSeq {
			consumed = current.Status.ConsumedSeq
		}
		current.Status.ConsumedSeq = consumed
		if st.summarySet {
			current.Status.Summary = truncateRunes(st.summary, 16384)
		}
		current.Status.Tasks = st.tasks
		current.Status.Timers = st.timers
		current.Status.NextWake = next
		if current.Status.TokenDay != today {
			current.Status.TokenDay = today
			current.Status.TokensToday = 0
		}
		current.Status.TokensToday += tokens
		// A pause set while the step ran (an operator hold) is not ours to
		// replace: only install the budget pause on an otherwise idle thread.
		if st.paused != "" && current.Status.Paused == nil {
			current.Status.Paused = &v1.ThreadPause{Reason: st.paused}
		}
		if err := s.Status().Update(ctx, current); err != nil {
			if apierrors.IsConflict(err) {
				continue
			}
			return err
		}
		return nil
	}
	return fmt.Errorf("thread status update kept conflicting")
}

// chargeUsage records tokens already spent on a step that will not reach a
// successful commit, so retries still count against the daily budget. It is
// best effort: the step's original error is more important than accounting.
func (s *Server) chargeUsage(ctx context.Context, thread *v1.BlipThread, usage int64) {
	if usage <= 0 {
		return
	}
	today := timeNow().UTC().Format("2006-01-02")
	for attempt := 0; attempt < 5; attempt++ {
		current, err := s.currentThread(ctx, thread)
		if err != nil {
			return
		}
		if current.Status.TokenDay != today {
			current.Status.TokenDay = today
			current.Status.TokensToday = 0
		}
		current.Status.TokensToday += usage
		if err := s.Status().Update(ctx, current); err != nil {
			if apierrors.IsConflict(err) {
				continue
			}
			return
		}
		return
	}
}

// nextWake picks the next step time: the heartbeat while tasks are open, or a
// future timer, whichever is sooner.
func nextWake(st *step, now time.Time) *metav1.Time {
	var next time.Time
	if hasOpenTask(st.tasks) {
		heartbeat := st.s.Config.Heartbeat
		if st.thread != nil && st.thread.Spec.Heartbeat != nil && st.thread.Spec.Heartbeat.Duration > 0 {
			heartbeat = st.thread.Spec.Heartbeat.Duration
		}
		if heartbeat <= 0 {
			heartbeat = 30 * time.Minute
		}
		next = now.Add(heartbeat)
	}
	for _, timer := range st.timers {
		at := timer.At.Time
		if !timer.At.After(now) {
			// A timer set for the past is due now; wake on the next tick so
			// its note is not stranded.
			at = now
		}
		if next.IsZero() || at.Before(next) {
			next = at
		}
	}
	if next.IsZero() {
		return nil
	}
	return &metav1.Time{Time: next}
}

const defaultCoordinatorSystemPrompt = `You are the coordinator for the Blip project "%s/%s".

You own the task board and decide what work happens, in what order, and with what concurrency. Work happens in blips: start_task forks the thread's base workspace and runs one agent command which ends by itself and reports a bounded summary.

Rules:
- Keep the board truthful. Create tasks for new work, update attributes and notes as work progresses, and close tasks when they are done.
- Task attributes are your own conventions. The engine never interprets them.
- Reports and finished blips arrive as turns. Do not poll for them. Use exec only when a report is not enough.
- Every step should end with set_timer or idle.
- Use reply to answer the turns you were given and note to record a decision.
- Keep prompts to agents specific and self-contained.`

func systemPrompt(thread *v1.BlipThread) string {
	prompt := thread.Spec.SystemPrompt
	if prompt == "" {
		prompt = fmt.Sprintf(defaultCoordinatorSystemPrompt, thread.Namespace, thread.Name)
	}
	return prompt + "\n\nCharter:\n" + thread.Spec.Charter
}

// boardPrompt renders one step's input. It returns the prompt and the
// highest turn sequence it actually rendered, so the caller never consumes a
// turn the coordinator did not see. When the turns do not fit the budget, the
// newest turns win: they are the ones most likely to be actionable, and the
// older turns are summarized so the notice is accurate and consuming them
// does not silently lose input.
func boardPrompt(thread *v1.BlipThread, tasks []v1.ThreadTask, turns []v1.BlipTurn, timers []v1.ThreadTimer, summary string) (string, int64) {
	var b strings.Builder
	b.WriteString("Task board:\n")
	if len(tasks) == 0 {
		b.WriteString("(empty)\n")
	}
	for _, t := range tasks {
		fmt.Fprintf(&b, "- %s %s %q", t.ID, openState(t.Open), t.Title)
		if len(t.Blips) > 0 {
			fmt.Fprintf(&b, " blips=%s", strings.Join(t.Blips, ","))
		}
		if t.Note != "" {
			fmt.Fprintf(&b, " note=%q", t.Note)
		}
		keys := make([]string, 0, len(t.Attributes))
		for k := range t.Attributes {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, " %s=%q", k, t.Attributes[k])
		}
		b.WriteString("\n")
	}
	if summary != "" {
		fmt.Fprintf(&b, "\nSummary of earlier history:\n%s\n", summary)
	}
	if len(timers) > 0 {
		b.WriteString("\nTimers that fired:\n")
		for _, timer := range timers {
			fmt.Fprintf(&b, "- %s: %s\n", timer.At.Format(time.RFC3339), timer.Note)
		}
	}
	b.WriteString("\nNew turns (oldest first):\n")
	if len(turns) == 0 {
		b.WriteString("(none; this is a scheduled wake-up)\n")
		return b.String(), 0
	}

	last := boardTurns(&b, turns, promptBudget-b.Len())
	return b.String(), last
}

// summarizeTurn renders a compact one-line form of a turn. It keeps the
// sequence, author, and topic plus a short excerpt so a prompt that cannot fit
// the full text still shows the coordinator that the turn happened.
func summarizeTurn(t *v1.BlipTurn, excerpt int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "#%d %s/%s %s", t.Status.Seq, t.Spec.Author.Kind, t.Spec.Author.Name, t.Spec.Topic)
	if t.Spec.Text != "" && excerpt > 0 {
		fmt.Fprintf(&b, ": %s", truncateRunes(t.Spec.Text, excerpt))
	}
	b.WriteString("\n")
	return b.String()
}

// summarizeTurns fits a compact form of every turn into budget. It reports
// false when even the metadata-only summaries do not fit: the caller must then
// render a prefix and leave the rest pending rather than consuming turns it
// cannot show.
func summarizeTurns(turns []v1.BlipTurn, budget int) (string, bool) {
	if budget <= 0 {
		return "", false
	}
	for _, excerpt := range []int{240, 120, 60, 0} {
		var b strings.Builder
		for i := range turns {
			b.WriteString(summarizeTurn(&turns[i], excerpt))
		}
		if b.Len() <= budget {
			return b.String(), true
		}
	}
	return "", false
}

// boardTurns renders the turn section under budget and returns the highest
// sequence it showed. Newest-wins: the suffix that fits is rendered in full,
// and the older turns are summarized so consuming them loses no input
// silently. When the older turns cannot be represented even compactly, the
// oldest turns are rendered instead and the newer ones stay pending, because
// consumedSeq can only advance over a contiguous prefix that was shown.
func boardTurns(b *strings.Builder, turns []v1.BlipTurn, budget int) int64 {
	if len(turns) == 0 {
		return 0
	}
	lines := make([]string, len(turns))
	for i := range turns {
		line := renderTurn(&turns[i])
		if len(line) > 2048 {
			line = truncateRunes(line, 2048)
		}
		lines[i] = line + "\n"
	}
	if budget < 0 {
		budget = 0
	}
	start, used := suffixTurns(lines, budget)
	// A turn that asked to wake the coordinator must not be dropped in favour
	// of newer context: it is the input this step exists for. When one is
	// outside the newest suffix, render the contiguous prefix through it and
	// consume only that prefix so the skipped context stays pending.
	keepEnd := -1
	for i := 0; i < start; i++ {
		if turns[i].Spec.Wake != v1.WakeNone {
			keepEnd = i
		}
	}
	if keepEnd >= 0 {
		return renderWakePrefix(b, turns, lines, budget, keepEnd)
	}
	if start == 0 {
		for i := range lines {
			b.WriteString(lines[i])
		}
		return turns[len(turns)-1].Status.Seq
	}
	notice := fmt.Sprintf("(%d older turns summarized)\n", start)
	if summaries, ok := summarizeTurns(turns[:start], budget-used-len(notice)); ok {
		b.WriteString(notice)
		b.WriteString(summaries)
		for i := start; i < len(lines); i++ {
			b.WriteString(lines[i])
		}
		return turns[len(turns)-1].Status.Seq
	}
	// The omitted turns cannot be shown in any form. Rendering the newest
	// suffix would consume them without ever presenting them, so render the
	// oldest turns and leave the newer ones for a later step instead. Any
	// wake turn in the pending suffix is still shown compactly, but the
	// returned sequence stops at the rendered prefix so it stays pending.
	omittedStart := start
	start = 0
	used = 0
	for start < len(turns) {
		rest := len(turns) - start - 1
		notice := 0
		if rest > 0 {
			notice = len(fmt.Sprintf("(%d newer turns left for a later step)\n", rest))
		}
		if used+len(lines[start])+notice > budget {
			break
		}
		used += len(lines[start])
		start++
	}
	if start == 0 {
		start = 1
	}
	if rest := len(turns) - start; rest > 0 {
		fmt.Fprintf(b, "(%d newer turns left for a later step)\n", rest)
	}
	for i := 0; i < start; i++ {
		b.WriteString(lines[i])
	}
	for i := omittedStart; i < len(turns); i++ {
		if turns[i].Spec.Wake != v1.WakeNone {
			fmt.Fprintf(b, "(wake turn %d shown, left for a later step)\n", turns[i].Status.Seq)
			b.WriteString(summarizeTurn(&turns[i], 0))
		}
	}
	return turns[start-1].Status.Seq
}

// renderWakePrefix renders a contiguous prefix through the last omitted wake
// turn plus as much of the newest suffix as fits. When the full prefix does
// not fit, it is shown compactly so the step can still consume it; only when
// even the compact form does not fit does the rendered prefix stay empty (the
// caller then defers instead of re-running the same input). It returns the
// highest sequence of the contiguous rendered prefix; gaps stay pending.
func renderWakePrefix(b *strings.Builder, turns []v1.BlipTurn, lines []string, budget, keepEnd int) int64 {
	out := make([]string, len(turns))
	rendered := make([]bool, len(turns))
	prefix := 0
	for i := 0; i <= keepEnd; i++ {
		prefix += len(lines[i])
	}
	if prefix <= budget {
		for i := 0; i <= keepEnd; i++ {
			rendered[i] = true
			out[i] = lines[i]
		}
		if remaining := budget - prefix; remaining > 0 {
			s, _ := suffixTurns(lines[keepEnd+1:], remaining)
			for i := s + keepEnd + 1; i < len(turns); i++ {
				rendered[i] = true
				out[i] = lines[i]
			}
		}
	} else {
		// The context before the wake turn is itself over budget. Show it as
		// compact summaries so the contiguous prefix through the wake turn
		// can be consumed without dropping its input; the wake turn itself
		// stays in full and the newest suffix uses whatever room remains.
		notice, summaries := "", ""
		ok := true
		if keepEnd > 0 {
			notice = fmt.Sprintf("(%d older turns summarized)\n", keepEnd)
			summaries, ok = summarizeTurns(turns[:keepEnd], budget-len(lines[keepEnd])-len(notice))
		}
		if ok {
			if keepEnd > 0 {
				out[0] = notice + summaries
				for i := 0; i < keepEnd; i++ {
					rendered[i] = true
				}
			}
			rendered[keepEnd] = true
			out[keepEnd] = lines[keepEnd]
			remaining := budget - len(notice) - len(summaries) - len(lines[keepEnd])
			if remaining > 0 {
				s, _ := suffixTurns(lines[keepEnd+1:], remaining)
				for i := s + keepEnd + 1; i < len(turns); i++ {
					rendered[i] = true
					out[i] = lines[i]
				}
			}
		} else {
			// Keep every wake turn, but never consume across a gap.
			for i := 0; i <= keepEnd; i++ {
				if turns[i].Spec.Wake != v1.WakeNone {
					rendered[i] = true
					out[i] = lines[i]
				}
			}
		}
	}
	lastRendered := int64(0)
	for i := 0; i < len(turns); i++ {
		if !rendered[i] {
			break
		}
		lastRendered = turns[i].Status.Seq
	}
	gap := 0
	for i := 0; i < len(turns); i++ {
		if !rendered[i] {
			gap++
			continue
		}
		if gap > 0 {
			if i == gap {
				fmt.Fprintf(b, "(%d older turns omitted)\n", gap)
			} else {
				fmt.Fprintf(b, "(%d context turns omitted)\n", gap)
			}
			gap = 0
		}
		b.WriteString(out[i])
	}
	if gap > 0 {
		fmt.Fprintf(b, "(%d newer turns omitted)\n", gap)
	}
	return lastRendered
}

// suffixTurns returns the index where the newest suffix of lines that fits
// budget begins, along with the bytes it uses. It keeps at least the newest
// line so a step always has something it may consume.
func suffixTurns(lines []string, budget int) (int, int) {
	start := len(lines)
	used := 0
	for start > 0 {
		i := start - 1
		notice := 0
		if i > 0 {
			notice = len(fmt.Sprintf("(%d older turns summarized)\n", i))
		}
		if used+len(lines[i])+notice > budget {
			break
		}
		used += len(lines[i])
		start = i
	}
	if start == len(lines) && len(lines) > 0 {
		start = len(lines) - 1
	}
	return start, used
}

func openState(open bool) string {
	if open {
		return "open"
	}
	return "closed"
}

// maybeUnpause lets a thread run again on a new day after its budget paused it.
func (s *Server) maybeUnpause(ctx context.Context, thread *v1.BlipThread) {
	today := timeNow().UTC().Format("2006-01-02")
	if thread.Status.Paused == nil || thread.Status.Paused.Reason != budgetPauseReason || thread.Status.TokenDay == today {
		return
	}
	current := &v1.BlipThread{}
	if err := s.Get(ctx, client.ObjectKeyFromObject(thread), current); err != nil {
		return
	}
	current.Status.Paused = nil
	current.Status.TokensToday = 0
	current.Status.TokenDay = today
	if err := s.Status().Update(ctx, current); err != nil {
		return
	}
	thread.Status = current.Status
}

// prune deletes consumed turns past retention and old closed tasks.
func (s *Server) prune(ctx context.Context, thread *v1.BlipThread) error {
	// The Steps list snapshot can be minutes old when an earlier step in the
	// same tick ran long. If the name was deleted and recreated, this pass
	// belongs to an incarnation that no longer exists: sweeping with the old
	// UID would delete the new thread's turns and restore its old board.
	live, err := s.currentThread(ctx, thread)
	if err != nil {
		if apierrors.IsNotFound(err) || errors.Is(err, errStaleIncarnation) {
			return nil
		}
		return err
	}
	*thread = *live
	now := timeNow()
	// Turns sequenced by a previous incarnation of a recreated thread are
	// not history of this one. Delete them regardless of age or sequence.
	var all v1.BlipTurnList
	if err := s.List(ctx, &all, client.InNamespace(thread.Namespace), client.MatchingFields{turnField: thread.Name}); err != nil {
		return err
	}
	for i := range all.Items {
		t := &all.Items[i]
		if turnBelongsToThread(t, thread) {
			continue
		}
		if err := s.Delete(ctx, t); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	turnAge, keepTurns := thread.Spec.Retention.Turns, int(thread.Spec.Retention.KeepTurns)
	if turnAge == nil {
		turnAge = &metav1.Duration{Duration: defaultTurnAge}
	}
	if keepTurns == 0 {
		keepTurns = 200
	}
	turns, err := s.recentTurns(ctx, thread, 0, 1<<20)
	if err != nil {
		return err
	}
	kept := 0
	for i := len(turns) - 1; i >= 0; i-- {
		t := &turns[i]
		// A sequence above consumedSeq only marks pending *input*.
		// pendingTurns excludes coordinator output, so a timer-driven note
		// or reply above consumedSeq must still age out; otherwise a thread
		// whose steps emit notes keeps every one of them forever.
		pending := t.Status.Seq > thread.Status.ConsumedSeq && t.Spec.Author.Kind != v1.TurnAuthorCoordinator
		if pending || kept < keepTurns {
			kept++
			continue
		}
		if t.Status.AcceptedTime == nil || now.Sub(t.Status.AcceptedTime.Time) < turnAge.Duration {
			continue
		}
		if err := s.Delete(ctx, t); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	taskAge, maxTasks := thread.Spec.Retention.ClosedTasks, int(thread.Spec.Retention.MaxTasks)
	if taskAge == nil {
		taskAge = &metav1.Duration{Duration: 72 * time.Hour}
	}
	if maxTasks == 0 {
		maxTasks = 200
	}
	var keptTasks []v1.ThreadTask
	for _, t := range thread.Status.Tasks {
		if !t.Open && t.Updated != nil && now.Sub(t.Updated.Time) > taskAge.Duration {
			continue
		}
		keptTasks = append(keptTasks, t)
	}
	for len(keptTasks) > maxTasks {
		oldest := -1
		for i, t := range keptTasks {
			if t.Open {
				continue
			}
			if oldest < 0 || closedTaskOlder(t, keptTasks[oldest]) {
				oldest = i
			}
		}
		if oldest < 0 {
			// Only open tasks remain; deleting them would lose live work.
			break
		}
		keptTasks = append(keptTasks[:oldest], keptTasks[oldest+1:]...)
	}
	if len(keptTasks) != len(thread.Status.Tasks) {
		current, err := s.currentThread(ctx, thread)
		if err != nil {
			return err
		}
		current.Status.Tasks = keptTasks
		if err := s.Status().Update(ctx, current); err != nil {
			return err
		}
		// Steps shares this thread value; keep it in sync so a step later in
		// the same tick cannot write the pruned tasks back.
		thread.Status = current.Status
	}
	return nil
}

// closedTaskOlder reports whether a should be pruned before b. A closed task
// without an update time is treated as the oldest.
func closedTaskOlder(a, b v1.ThreadTask) bool {
	if a.Updated == nil {
		return b.Updated != nil
	}
	if b.Updated == nil {
		return false
	}
	return a.Updated.Before(b.Updated)
}

// pruneOrphanTurns deletes turns that reference no existing thread. A turn
// whose thread was deleted, or whose spec.thread is a typo, is never sequenced
// and no thread prune pass will ever see it. It is kept for the default turn
// age so the cause is still visible, then garbage-collected.
func (s *Server) pruneOrphanTurns(ctx context.Context, threads []v1.BlipThread) error {
	live := make(map[string]bool, len(threads))
	for i := range threads {
		live[threads[i].Namespace+"/"+threads[i].Name] = true
	}
	var turns v1.BlipTurnList
	if err := s.List(ctx, &turns); err != nil {
		return err
	}
	now := timeNow()
	for i := range turns.Items {
		t := &turns.Items[i]
		if t.DeletionTimestamp != nil || live[t.Namespace+"/"+t.Spec.Thread] {
			continue
		}
		if now.Sub(t.CreationTimestamp.Time) < defaultTurnAge {
			continue
		}
		if err := s.Delete(ctx, t); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}
