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
	summary string
	// summarySet distinguishes "remember was called" (even with empty text)
	// from a step that did not touch the summary.
	summarySet bool
	idle       bool
	paused     string
	usage      int64
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
	if thread.Status.TokenDay != started.UTC().Format("2006-01-02") {
		tokensToday = 0
	}
	if thread.Spec.DailyTokens > 0 && tokensToday >= thread.Spec.DailyTokens {
		st.paused = budgetPauseReason
		return s.commitStep(ctx, st, thread.Status.ConsumedSeq, pending, started)
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
	}
	prompt, lastRendered := boardPrompt(thread, st.tasks, pending, dueTimers, st.summary)
	// Never advance ConsumedSeq past a turn the prompt did not render.
	if len(pending) > 0 && lastRendered < target {
		target = lastRendered
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
// previous incarnation, whose turn history and board are already gone.
func (s *Server) commitStep(ctx context.Context, st *step, target int64, pending []v1.BlipTurn, started time.Time) error {
	err := s.commit(ctx, st, target, pending, started)
	if errors.Is(err, errStaleIncarnation) {
		return nil
	}
	return err
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
	for attempt := 0; attempt < 5; attempt++ {
		current, err := s.currentThread(ctx, st.thread)
		if err != nil {
			return err
		}
		current.Status.ConsumedSeq = target
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
// notice reports exactly how many older turns were left out.
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

	lines := make([]string, len(turns))
	for i := range turns {
		line := renderTurn(&turns[i])
		if len(line) > 2048 {
			line = truncateRunes(line, 2048)
		}
		lines[i] = line + "\n"
	}
	// Walk backwards from the newest turn, reserving room for an accurate
	// notice about the older turns that will not fit. Keep at least the
	// newest turn even when the board alone is already over budget, so a step
	// always has something it may consume.
	budget := 48000 - b.Len()
	start, _ := suffixTurns(lines, budget)
	if start == len(turns) {
		start = len(turns) - 1
	}
	rendered := make([]bool, len(turns))
	for i := start; i < len(turns); i++ {
		rendered[i] = true
	}
	lastRendered := turns[len(turns)-1].Status.Seq
	// A turn that asked to wake the coordinator must not be dropped in favour
	// of newer context: it is the input this step exists for. Keep the prefix
	// through the last omitted wake turn, and consume only the contiguous
	// prefix that was rendered so the dropped context stays pending.
	keepEnd := -1
	for i := 0; i < start; i++ {
		if turns[i].Spec.Wake != v1.WakeNone {
			keepEnd = i
		}
	}
	if keepEnd >= 0 {
		// Only a contiguous prefix may be consumed; the dropped context must
		// stay pending.
		lastRendered = 0
		prefix := 0
		for i := 0; i <= keepEnd; i++ {
			prefix += len(lines[i])
		}
		if prefix <= budget {
			for i := 0; i <= keepEnd; i++ {
				rendered[i] = true
			}
			// Let the newest turns use what the kept prefix leaves.
			if remaining := budget - prefix; remaining > 0 {
				s, _ := suffixTurns(lines[keepEnd+1:], remaining)
				for i := s + keepEnd + 1; i < len(turns); i++ {
					rendered[i] = true
				}
			}
		} else {
			// The context before the wake turn is itself over budget. Keep
			// every wake turn, but never consume across a gap.
			for i := 0; i <= keepEnd; i++ {
				rendered[i] = turns[i].Spec.Wake != v1.WakeNone
			}
		}
		for i := 0; i < len(turns); i++ {
			if !rendered[i] {
				break
			}
			lastRendered = turns[i].Status.Seq
		}
	}
	// Render in sequence order, reporting each gap so omitted input is not
	// invisible to the coordinator.
	gap := 0
	for i := 0; i < len(turns); i++ {
		if !rendered[i] {
			gap++
			continue
		}
		if gap > 0 {
			if i == gap {
				fmt.Fprintf(&b, "(%d older turns omitted)\n", gap)
			} else {
				fmt.Fprintf(&b, "(%d context turns omitted)\n", gap)
			}
			gap = 0
		}
		b.WriteString(lines[i])
	}
	if gap > 0 {
		fmt.Fprintf(&b, "(%d newer turns omitted)\n", gap)
	}
	return b.String(), lastRendered
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
			notice = len(fmt.Sprintf("(%d older turns omitted)\n", i))
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
