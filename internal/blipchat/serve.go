package blipchat

import (
	"context"
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
	// turnField indexes BlipTurns by spec.thread.
	turnField = "spec.thread"
	// budgetPauseReason is the only pause blipchat clears automatically.
	budgetPauseReason = "daily token budget exhausted"
)

var timeNow = time.Now

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
			for i := range threads.Items {
				thread := &threads.Items[i]
				s.maybeUnpause(ctx, thread)
				if s.pruneCount >= 150 {
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
			if s.pruneCount >= 150 {
				s.pruneCount = 0
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
		if t.Status.Seq <= thread.Status.ConsumedSeq || t.Spec.Author.Kind == v1.TurnAuthorCoordinator {
			continue
		}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Status.Seq < out[j].Status.Seq })
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
	summary string
	idle    bool
	paused  string
	usage   int64
}

func (s *Server) step(ctx context.Context, thread *v1.BlipThread) error {
	pending, err := s.pendingTurns(ctx, thread)
	if err != nil {
		return err
	}
	target := thread.Status.ConsumedSeq
	if len(pending) > 0 {
		target = pending[len(pending)-1].Status.Seq
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
	if thread.Status.TokenDay != started.Format("2006-01-02") {
		tokensToday = 0
	}
	if thread.Spec.DailyTokens > 0 && tokensToday >= thread.Spec.DailyTokens {
		st.paused = budgetPauseReason
		return s.commit(ctx, st, thread.Status.ConsumedSeq, pending, started)
	}

	// Consume due timers: their notes are part of this step's input.
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
		{Role: "user", Content: boardPrompt(thread, st.tasks, pending, dueTimers, st.summary)},
	}
	toollist := st.tools()
	for calls := 0; calls < s.Config.MaxToolCalls; calls++ {
		reply, usage, err := s.LLM.Chat(ctx, model, messages, toollist)
		if err != nil {
			return err
		}
		st.usage += usage.Total()
		messages = append(messages, reply)
		if thread.Spec.DailyTokens > 0 && tokensToday+st.usage >= thread.Spec.DailyTokens {
			st.paused = budgetPauseReason
			break
		}
		if len(reply.ToolCalls) == 0 {
			break
		}
		for _, call := range reply.ToolCalls {
			result, err := st.call(ctx, call.Function.Name, call.Function.Arguments)
			if err != nil {
				result = "error: " + err.Error()
			}
			messages = append(messages, Message{Role: "tool", ToolCallID: call.ID, Content: result})
		}
		if st.usage >= s.Config.StepTokenLimit {
			break
		}
	}
	return s.commit(ctx, st, target, pending, started)
}

// commit writes the step's coordinator turns and then one thread status
// update. Turns are named by step start so retries are idempotent.
func (s *Server) commit(ctx context.Context, st *step, target int64, _ []v1.BlipTurn, started time.Time) error {
	key := &ThreadKey{Namespace: st.thread.Namespace, Name: st.thread.Name}
	prefix := fmt.Sprintf("coord-%s-%d", Owner(key), started.Unix())
	for i := range st.replies {
		spec := st.replies[i]
		if err := createTurnIn(ctx, s.Client, st.thread.Namespace, fmt.Sprintf("%s-%d", prefix, i), turnSpec{
			Thread: spec.Thread, AuthorKind: spec.Author.Kind, AuthorName: spec.Author.Name,
			Topic: spec.Topic, Text: spec.Text, InReplyTo: spec.InReplyTo, Wake: v1.WakeNone,
		}); err != nil {
			return err
		}
	}
	tokens := st.usage
	today := started.Format("2006-01-02")
	next := nextWake(st, started)
	for attempt := 0; attempt < 5; attempt++ {
		current := &v1.BlipThread{}
		if err := s.Get(ctx, client.ObjectKeyFromObject(st.thread), current); err != nil {
			return err
		}
		current.Status.ConsumedSeq = target
		if st.summary != "" {
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
		if st.paused != "" {
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
		if timer.At.After(now) && (next.IsZero() || timer.At.Time.Before(next)) {
			next = timer.At.Time
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

func boardPrompt(thread *v1.BlipThread, tasks []v1.ThreadTask, turns []v1.BlipTurn, timers []v1.ThreadTimer, summary string) string {
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
	}
	for i := range turns {
		line := renderTurn(&turns[i])
		if len(line) > 2048 {
			line = truncateRunes(line, 2048)
		}
		if b.Len()+len(line) > 48000 {
			b.WriteString("(older turns omitted)\n")
			break
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

func openState(open bool) string {
	if open {
		return "open"
	}
	return "closed"
}

// maybeUnpause lets a thread run again on a new day after its budget paused it.
func (s *Server) maybeUnpause(ctx context.Context, thread *v1.BlipThread) {
	if thread.Status.Paused == nil || thread.Status.TokenDay == timeNow().Format("2006-01-02") {
		return
	}
	current := &v1.BlipThread{}
	if err := s.Get(ctx, client.ObjectKeyFromObject(thread), current); err != nil {
		return
	}
	current.Status.Paused = nil
	current.Status.TokensToday = 0
	current.Status.TokenDay = timeNow().Format("2006-01-02")
	if err := s.Status().Update(ctx, current); err != nil {
		return
	}
	thread.Status = current.Status
}

// prune deletes consumed turns past retention and old closed tasks.
func (s *Server) prune(ctx context.Context, thread *v1.BlipThread) error {
	now := timeNow()
	turnAge, keepTurns := thread.Spec.Retention.Turns, int(thread.Spec.Retention.KeepTurns)
	if turnAge == nil {
		turnAge = &metav1.Duration{Duration: 7 * 24 * time.Hour}
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
		if t.Status.Seq > thread.Status.ConsumedSeq || kept < keepTurns {
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
	closed := 0
	for _, t := range thread.Status.Tasks {
		if !t.Open && t.Updated != nil && now.Sub(t.Updated.Time) > taskAge.Duration {
			continue
		}
		keptTasks = append(keptTasks, t)
		if !t.Open {
			closed++
		}
	}
	for closed > maxTasks && len(keptTasks) > 0 {
		for i, t := range keptTasks {
			if !t.Open {
				keptTasks = append(keptTasks[:i], keptTasks[i+1:]...)
				closed--
				break
			}
		}
	}
	if len(keptTasks) != len(thread.Status.Tasks) {
		current := &v1.BlipThread{}
		if err := s.Get(ctx, client.ObjectKeyFromObject(thread), current); err != nil {
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
