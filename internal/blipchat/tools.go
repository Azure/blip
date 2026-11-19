package blipchat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/session"
	"github.com/Azure/blip/internal/wire"
	"github.com/Azure/blip/internal/workspace"
)

var taskIDPattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// maxExecTimeout bounds one exec or inspect command.
const maxExecTimeout = 60 * time.Second

func schema(properties map[string]any, required ...string) map[string]any {
	out := map[string]any{"type": "object", "properties": properties}
	if len(required) > 0 {
		out["required"] = required
	}
	return out
}

func props(entries ...map[string]any) map[string]any {
	out := map[string]any{}
	for _, e := range entries {
		for k, v := range e {
			out[k] = v
		}
	}
	return out
}

func str(description string) map[string]any {
	return map[string]any{"type": "string", "description": description}
}

// tools is the coordinator's tool set. Every tool except exec returns
// immediately; exec waits at most 60 seconds for one command.
func (s *step) tools() []Tool {
	return []Tool{
		FunctionTool("task_create", "Create a task on the project board. Ids are short and DNS-safe.", schema(props(
			map[string]any{"id": str("Task id, lowercase letters, digits and dashes, at most 16 characters")},
			map[string]any{"title": str("Human-readable title")},
			map[string]any{"attributes": map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "Free-form task fields"}},
			map[string]any{"note": str("Short note")},
		), "id")),
		FunctionTool("task_update", "Change a task. Omitted fields are unchanged; an attribute set to an empty string is deleted.", schema(props(
			map[string]any{"id": str("Task id")},
			map[string]any{"title": str("New title")},
			map[string]any{"attributes": map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "Attribute changes to merge"}},
			map[string]any{"note": str("New note")},
			map[string]any{"open": map[string]any{"type": "boolean", "description": "Whether the task is open"}},
		), "id")),
		FunctionTool("start_task", "Start a blip for an open task. Fails when the thread is at maxRunning. The prompt is the agent's command argument.", schema(props(
			map[string]any{"task": str("Open task id")},
			map[string]any{"prompt": str("Work to do; becomes the agent's prompt")},
			map[string]any{"from": str("Optional BlipState to fork the workspace from instead of spec.base")},
		), "task", "prompt")),
		FunctionTool("exec", "Run one command in a running blip and return its whole output. Waits at most 60 seconds.", schema(props(
			map[string]any{"blip": str("Blip name")},
			map[string]any{"argv": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "minItems": 1}},
			map[string]any{"timeoutSeconds": map[string]any{"type": "integer", "minimum": 1, "maximum": 60}},
		), "blip", "argv")),
		FunctionTool("stop", "Ask a running blip to stop and save.", schema(props(
			map[string]any{"blip": str("Blip name")},
		), "blip")),
		FunctionTool("set_timer", "Wake the coordinator at a fixed time.", schema(props(
			map[string]any{"at": str("RFC 3339 time")},
			map[string]any{"note": str("Why to wake")},
		), "at")),
		FunctionTool("reply", "Write a turn answering a user or blip turn.", schema(props(
			map[string]any{"inReplyTo": map[string]any{"type": "integer", "minimum": 0, "description": "Sequence number being answered"}},
			map[string]any{"text": str("Reply text, at most 2048 characters")},
		), "text")),
		FunctionTool("note", "Record a short decision or observation for later steps.", schema(props(
			map[string]any{"text": str("Note text")},
		), "text")),
		FunctionTool("remember", "Replace the rolling summary of consumed history.", schema(props(
			map[string]any{"text": str("New summary, at most 16 KiB")},
		), "text")),
		FunctionTool("idle", "End the step without scheduling another wake. Use when there is nothing to do.", schema(props())),
	}
}

// call executes one tool call and returns the tool result text.
func (s *step) call(ctx context.Context, name, arguments string) (string, error) {
	var args map[string]any
	if strings.TrimSpace(arguments) != "" {
		if err := json.Unmarshal([]byte(arguments), &args); err != nil {
			return "", fmt.Errorf("invalid arguments: %w", err)
		}
	}
	strArg := func(key string) string {
		v, _ := args[key].(string)
		return v
	}
	switch name {
	case "task_create":
		id := strArg("id")
		if !taskIDPattern.MatchString(id) || len(id) > 16 {
			return "", fmt.Errorf("invalid task id %q", id)
		}
		for _, t := range s.tasks {
			if t.ID == id {
				return "", fmt.Errorf("task %q already exists", id)
			}
		}
		if len(s.tasks) >= 200 {
			return "", fmt.Errorf("task board is full")
		}
		attrs := map[string]string{}
		if raw, ok := args["attributes"].(map[string]any); ok {
			for k, v := range raw {
				attrs[k] = fmt.Sprint(v)
			}
		}
		s.tasks = append(s.tasks, v1.ThreadTask{ID: id, Title: truncateRunes(strArg("title"), 120), Open: true, Attributes: cleanAttributes(attrs), Note: truncateRunes(strArg("note"), 256), Updated: nowTime()})
		return "created " + id, nil
	case "task_update":
		t := s.task(strArg("id"))
		if t == nil {
			return "", fmt.Errorf("task %q not found", strArg("id"))
		}
		// Validate the whole change before touching the task so a rejected
		// update cannot leave a partial, CRD-invalid value behind.
		title, note, attrs := t.Title, t.Note, t.Attributes
		if v, ok := args["title"].(string); ok {
			title = truncateRunes(v, 120)
		}
		if v, ok := args["note"].(string); ok {
			note = truncateRunes(v, 256)
		}
		if raw, ok := args["attributes"].(map[string]any); ok {
			merged := make(map[string]string, len(t.Attributes)+len(raw))
			for k, value := range t.Attributes {
				merged[k] = value
			}
			for k, value := range raw {
				if k == "" {
					continue
				}
				key := truncateRunes(k, 63)
				if fmt.Sprint(value) == "" {
					delete(merged, key)
					continue
				}
				merged[key] = truncateRunes(fmt.Sprint(value), 256)
			}
			if len(merged) > 16 {
				return "", fmt.Errorf("task %q would have %d attributes; the maximum is 16", t.ID, len(merged))
			}
			attrs = merged
		}
		t.Title = title
		t.Note = note
		t.Attributes = attrs
		if v, ok := args["open"].(bool); ok {
			t.Open = v
		}
		t.Updated = nowTime()
		return fmt.Sprintf("updated %s open=%v", t.ID, t.Open), nil
	case "start_task":
		return s.startTask(ctx, strArg("task"), strArg("prompt"), strArg("from"))
	case "exec":
		var argv []string
		if raw, ok := args["argv"].([]any); ok {
			for _, a := range raw {
				argv = append(argv, fmt.Sprint(a))
			}
		}
		timeout := maxExecTimeout
		if v, ok := args["timeoutSeconds"].(float64); ok {
			timeout = time.Duration(v) * time.Second
		}
		return s.s.execIn(ctx, s.thread, strArg("blip"), argv, timeout)
	case "stop":
		var b v1.Blip
		if err := s.s.Get(ctx, client.ObjectKey{Namespace: s.thread.Namespace, Name: strArg("blip")}, &b); err != nil {
			return "", err
		}
		if !belongsToThread(&b, s.thread) {
			return "", fmt.Errorf("blip %q does not belong to thread %q", b.Name, s.thread.Name)
		}
		b.Spec.Stop = true
		if err := s.s.Update(ctx, &b); err != nil {
			return "", err
		}
		return "stopping " + b.Name, nil
	case "set_timer":
		at, err := time.Parse(time.RFC3339, strArg("at"))
		if err != nil {
			return "", fmt.Errorf("at must be RFC 3339: %w", err)
		}
		if len(s.timers) >= 32 {
			return "", fmt.Errorf("too many timers")
		}
		id := fmt.Sprintf("t%d", timeNow().UnixNano())
		s.timers = append(s.timers, v1.ThreadTimer{ID: id, At: metav1.NewTime(at), Note: truncateRunes(strArg("note"), 256)})
		return "timer " + id + " at " + at.Format(time.RFC3339), nil
	case "reply":
		seq, _ := args["inReplyTo"].(float64)
		if seq < 0 {
			return "", fmt.Errorf("inReplyTo must be a non-negative sequence number")
		}
		s.replies = append(s.replies, v1.BlipTurnSpec{
			Thread: s.thread.Name, Author: v1.TurnAuthor{Kind: v1.TurnAuthorCoordinator, Name: s.thread.Name},
			Topic: "coordinator.reply", InReplyTo: int64(seq), Text: truncateRunes(strArg("text"), 2048), Wake: v1.WakeNone,
		})
		return "reply recorded", nil
	case "note":
		s.replies = append(s.replies, v1.BlipTurnSpec{
			Thread: s.thread.Name, Author: v1.TurnAuthor{Kind: v1.TurnAuthorCoordinator, Name: s.thread.Name},
			Topic: "coordinator.note", Text: truncateRunes(strArg("text"), 2048), Wake: v1.WakeNone,
		})
		return "note recorded", nil
	case "remember":
		s.summary = truncateRunes(strArg("text"), 16384)
		s.summarySet = true
		return "summary replaced", nil
	case "idle":
		s.idle = true
		return "idle", nil
	default:
		return "", fmt.Errorf("unknown tool %q", name)
	}
}

func (s *step) task(id string) *v1.ThreadTask {
	for i := range s.tasks {
		if s.tasks[i].ID == id {
			return &s.tasks[i]
		}
	}
	return nil
}

// startTask forks a workspace and starts one agent blip for a task.
func (s *step) startTask(ctx context.Context, taskID, prompt, from string) (string, error) {
	t := s.task(taskID)
	if t == nil {
		return "", fmt.Errorf("task %q not found", taskID)
	}
	if !t.Open {
		return "", fmt.Errorf("task %q is closed", taskID)
	}
	var running v1.BlipList
	if err := s.s.List(ctx, &running, client.InNamespace(s.thread.Namespace), client.MatchingLabels{v1.LabelThread: v1.ThreadLabel(s.thread.Name)}); err != nil {
		return "", err
	}
	active := 0
	for i := range running.Items {
		if !v1.Finished(&running.Items[i]) {
			active++
		}
	}
	limit := int(s.thread.Spec.MaxRunning)
	if limit < 1 {
		limit = 1
	}
	if active >= limit {
		return "", fmt.Errorf("thread already runs %d blips (maxRunning %d)", active, limit)
	}
	source := from
	if source == "" {
		source = s.thread.Spec.Base
	}
	if source == "" {
		return "", fmt.Errorf("thread has no spec.base and no from state was given")
	}
	var src v1.BlipState
	if err := s.s.Get(ctx, client.ObjectKey{Namespace: s.thread.Namespace, Name: source}, &src); err != nil {
		return "", fmt.Errorf("read source state %q: %w", source, err)
	}
	owner := Owner(&ThreadKey{Namespace: s.thread.Namespace, Name: s.thread.Name})
	name := fmt.Sprintf("%s.%s-%d", owner, taskID, timeNow().UnixNano())
	command := append(append([]string{}, s.s.Config.AgentCommand...), prompt)
	b := &v1.Blip{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: s.thread.Namespace,
			Labels:    map[string]string{v1.LabelOwner: owner, v1.LabelThread: v1.ThreadLabel(s.thread.Name), v1.LabelTask: taskID},
			Annotations: map[string]string{
				v1.AnnotationThread: s.thread.Name,
			},
		},
		Spec: v1.BlipSpec{Pool: s.thread.Spec.Pool, State: name, Command: command},
	}
	if err := s.s.Create(ctx, b); err != nil {
		return "", err
	}
	ref := metav1.OwnerReference{APIVersion: v1.GroupVersion.String(), Kind: "Blip", Name: b.Name, UID: b.UID}
	state := &v1.BlipState{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: s.thread.Namespace,
			Labels:    map[string]string{v1.LabelOwner: owner, v1.LabelThread: v1.ThreadLabel(s.thread.Name), v1.LabelTask: taskID},
			Annotations: map[string]string{
				v1.AnnotationThread: s.thread.Name,
			},
		},
	}
	if _, err := workspace.Fork(ctx, s.s.Client, &src, state, &workspace.ForkOptions{Owner: &ref}); err != nil {
		_ = s.s.Delete(context.WithoutCancel(ctx), b)
		return "", fmt.Errorf("fork state for %q: %w", name, err)
	}
	t.Blips = append(t.Blips, name)
	if len(t.Blips) > 8 {
		t.Blips = t.Blips[len(t.Blips)-8:]
	}
	t.Updated = nowTime()
	return "started " + name, nil
}

// belongsToThread reports whether b was created by this thread: the thread
// label must name it and the owner label must be the thread's derived owner.
// A coordinator may hold commands or stop only blips of its own project.
func belongsToThread(b *v1.Blip, thread *v1.BlipThread) bool {
	owner := Owner(&ThreadKey{Namespace: thread.Namespace, Name: thread.Name})
	return b.Namespace == thread.Namespace &&
		b.Labels[v1.LabelThread] == v1.ThreadLabel(thread.Name) &&
		b.Labels[v1.LabelOwner] == owner
}

// execIn runs one command in a running blip and returns bounded output.
func (s *Server) execIn(ctx context.Context, thread *v1.BlipThread, name string, argv []string, timeout time.Duration) (string, error) {
	if len(argv) == 0 {
		return "", fmt.Errorf("argv is required")
	}
	if timeout <= 0 || timeout > maxExecTimeout {
		timeout = maxExecTimeout
	}
	var b v1.Blip
	if err := s.Get(ctx, client.ObjectKey{Namespace: thread.Namespace, Name: name}, &b); err != nil {
		return "", err
	}
	if !belongsToThread(&b, thread) {
		return "", fmt.Errorf("blip %q does not belong to thread %q", name, thread.Name)
	}
	if b.Status.Pod == "" || v1.Finished(&b) {
		return "", fmt.Errorf("blip %q is not running", name)
	}
	exec, err := s.ExecClient()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	sess, err := exec.Open(ctx, b.Namespace, b.Status.Pod, wire.Open{Mode: wire.OpenExec, Argv: argv})
	if err != nil {
		return "", err
	}
	defer sess.Close()
	var stdout, stderr bytes.Buffer
	exit, err := sess.Copy(&stdout, &stderr, nil)
	if err != nil {
		return "", err
	}
	code := 0
	reason := ""
	if exit != nil {
		code = exit.Code
		reason = exit.Reason
	}
	out := fmt.Sprintf("exit=%d", code)
	if reason != "" {
		out += " reason=" + reason
	}
	if s := tailWords(&stdout, 8192); s != "" {
		out += "\nstdout:\n" + s
	}
	if s := tailWords(&stderr, 4096); s != "" {
		out += "\nstderr:\n" + s
	}
	return out, nil
}

func tailWords(b *bytes.Buffer, n int) string {
	s := strings.TrimSpace(b.String())
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}

// blipList renders blips of this thread for the chat and coordinator prompts.
func (s *Server) blipList(ctx context.Context, thread *v1.BlipThread) (string, error) {
	var blips v1.BlipList
	if err := s.List(ctx, &blips, client.InNamespace(thread.Namespace), client.MatchingLabels{v1.LabelThread: v1.ThreadLabel(thread.Name)}); err != nil {
		return "", err
	}
	sort.Slice(blips.Items, func(i, j int) bool { return blips.Items[i].Name < blips.Items[j].Name })
	var b strings.Builder
	for i := range blips.Items {
		x := &blips.Items[i]
		fmt.Fprintf(&b, "%s task=%s phase=%s", x.Name, x.Labels[v1.LabelTask], x.Status.Phase)
		if r := x.Status.Report; r != nil {
			_, summary := reportFields(r.Text)
			fmt.Fprintf(&b, " report=%q", truncateRunes(summary, 400))
		}
		b.WriteString("\n")
	}
	return b.String(), nil
}

// ExecClient lazily builds the pod exec client.
func (s *Server) ExecClient() (*session.Client, error) {
	s.execOnce.Do(func() {
		s.execClient, s.execErr = session.NewClient(s.RestConfig)
	})
	return s.execClient, s.execErr
}
