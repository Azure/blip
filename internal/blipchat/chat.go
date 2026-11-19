package blipchat

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"unicode/utf8"

	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

const (
	// maxChatBody is the total request size; the same bound is advertised by
	// the 413-style error from http.MaxBytesReader.
	maxChatBody = 1 << 20
	// maxMessageRunes matches the per-history-entry bound below. It keeps a
	// single prompt from dwarfing the thread's context.
	maxMessageRunes = 8000
	// maxHistoryMessages and maxHistoryRunes bound the transcript the browser
	// may replay. The body limit alone still allows hundreds of 8k messages.
	maxHistoryMessages = 40
	maxHistoryRunes    = 32000
)

// Chat is the engineer-facing conversation about a thread. The server keeps no
// transcript: the browser sends the history with every request. Tools let the
// model propose work, read the board and turns, and inspect running blips.
type Chat struct {
	Server *Server
}

type chatRequest struct {
	Thread  string        `json:"thread"`
	Message string        `json:"message"`
	History []chatMessage `json:"history,omitempty"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResponse struct {
	Reply string `json:"reply"`
}

type chatStep struct {
	s      *Server
	thread *v1.BlipThread
	user   string
}

func (c *Chat) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// X-Forwarded-User is trusted from the front end (see README). A proxy
	// that appends instead of overwriting would let a client pre-seed the
	// first value, so require exactly one.
	users := r.Header.Values("X-Forwarded-User")
	if len(users) == 0 {
		http.Error(w, "missing X-Forwarded-User", http.StatusUnauthorized)
		return
	}
	if len(users) != 1 {
		http.Error(w, "exactly one X-Forwarded-User header is required", http.StatusBadRequest)
		return
	}
	user := strings.TrimSpace(users[0])
	if user == "" {
		http.Error(w, "missing X-Forwarded-User", http.StatusUnauthorized)
		return
	}
	// Header.Values returns one element per header line, so a proxy that
	// joins repeated values with commas still arrives as one element here.
	if strings.Contains(user, ",") {
		http.Error(w, "exactly one X-Forwarded-User identity is required", http.StatusBadRequest)
		return
	}
	var req chatRequest
	if err := decodeChatRequest(w, r, &req); err != nil {
		// Read failures can contain the pod's bound socket address and the
		// peer address; JSON syntax errors echo the payload. Keep them in
		// the server log only.
		status := http.StatusBadRequest
		message := "invalid request"
		var nerr net.Error
		if errors.As(err, &nerr) && nerr.Timeout() {
			status = http.StatusRequestTimeout
			message = "request timeout"
		}
		c.Server.logError(err, "chat request body", "remote", r.RemoteAddr)
		http.Error(w, message, status)
		return
	}
	if req.Thread == "" || req.Message == "" {
		http.Error(w, "thread and message are required", http.StatusBadRequest)
		return
	}
	if n := utf8.RuneCountInString(req.Message); n > maxMessageRunes {
		http.Error(w, fmt.Sprintf("message is too long: %d characters, limit %d", n, maxMessageRunes), http.StatusBadRequest)
		return
	}
	if len(req.History) > maxHistoryMessages {
		http.Error(w, fmt.Sprintf("too many history messages: %d, limit %d", len(req.History), maxHistoryMessages), http.StatusBadRequest)
		return
	}
	historyRunes := 0
	for _, h := range req.History {
		historyRunes += utf8.RuneCountInString(h.Content)
	}
	if historyRunes > maxHistoryRunes {
		http.Error(w, fmt.Sprintf("history is too long: %d characters, limit %d", historyRunes, maxHistoryRunes), http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	namespace := r.URL.Query().Get("namespace")
	if namespace == "" {
		namespace = "default"
	}
	if !validNamespace(namespace) {
		http.Error(w, "invalid namespace", http.StatusBadRequest)
		return
	}
	thread := &v1.BlipThread{}
	if err := c.Server.Get(ctx, client.ObjectKey{Namespace: namespace, Name: req.Thread}, thread); err != nil {
		http.Error(w, "thread: "+err.Error(), http.StatusNotFound)
		return
	}
	st := &chatStep{s: c.Server, thread: thread, user: user}
	reply, err := st.run(ctx, req)
	if err != nil {
		// Details can include the internal LLM URL, resolver output, and
		// upstream response bodies. Keep them in the server log only.
		c.Server.logError(err, "chat request failed",
			"thread", thread.Namespace+"/"+thread.Name, "user", user)
		http.Error(w, "chat backend unavailable", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(chatResponse{Reply: reply})
}

func decodeChatRequest(w http.ResponseWriter, r *http.Request, req *chatRequest) error {
	return json.NewDecoder(http.MaxBytesReader(w, r.Body, maxChatBody)).Decode(req)
}

func (c *chatStep) run(ctx context.Context, req chatRequest) (string, error) {
	model := c.thread.Spec.Model
	if model == "" {
		model = c.s.Config.Model
	}
	messages := []Message{{Role: "system", Content: c.system()}}
	for _, h := range req.History {
		if h.Role != "user" && h.Role != "assistant" {
			continue
		}
		messages = append(messages, Message{Role: h.Role, Content: truncateRunes(h.Content, 8000)})
	}
	messages = append(messages, Message{Role: "user", Content: req.Message})
	tools := []Tool{
		FunctionTool("send", "Send a turn to the project coordinator. Only use this when the user asks for work or wants the coordinator to know something.", schema(props(
			map[string]any{"topic": map[string]any{"type": "string", "enum": []string{"chat.propose", "chat.note", "chat.answer"}}},
			map[string]any{"text": str("Message text")},
		), "topic", "text")),
		FunctionTool("turns", "Read recent turns of the coordinator thread.", schema(props(
			map[string]any{"since": map[string]any{"type": "integer", "description": "Only turns after this sequence number"}},
		))),
		FunctionTool("board", "Read the task board.", schema(props())),
		FunctionTool("task", "Read one task.", schema(props(map[string]any{"id": str("Task id")}), "id")),
		FunctionTool("blips", "List blips of this thread with their latest report.", schema(props())),
		FunctionTool("inspect", "Run a read-only command in a running blip, or read a finished blip's report.", schema(props(
			map[string]any{"blip": str("Blip name")},
			map[string]any{"argv": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}},
		), "blip")),
	}
	for calls := 0; calls < 10; calls++ {
		reply, _, err := c.s.LLM.Chat(ctx, model, messages, tools)
		if err != nil {
			return "", err
		}
		messages = append(messages, reply)
		if len(reply.ToolCalls) == 0 {
			return reply.Content, nil
		}
		for _, call := range reply.ToolCalls {
			result, err := c.call(ctx, call.Function.Name, call.Function.Arguments)
			if err != nil {
				result = "error: " + err.Error()
			}
			messages = append(messages, Message{Role: "tool", ToolCallID: call.ID, Content: result})
		}
	}
	return "I could not finish that in time. Please try again.", nil
}

func (c *chatStep) system() string {
	var b strings.Builder
	fmt.Fprintf(&b, "You are the engineer-facing assistant for the Blip project %q. Users talk to you; you can read the coordinator's board and turns and propose work by sending a turn to the coordinator. You cannot do work yourself.\n\n", c.thread.Namespace+"/"+c.thread.Name)
	b.WriteString("Use send with topic chat.propose when the user asks for work, chat.answer to answer a question aimed at the coordinator, and chat.note for context. Do not claim work is done before a turn reports it.\n\nCharter:\n")
	b.WriteString(c.thread.Spec.Charter)
	b.WriteString("\n\nTask board:\n")
	if len(c.thread.Status.Tasks) == 0 {
		b.WriteString("(empty)\n")
	}
	for _, t := range c.thread.Status.Tasks {
		fmt.Fprintf(&b, "- %s %s %q\n", t.ID, openState(t.Open), t.Title)
	}
	b.WriteString("\nRecent turns:\n")
	ctx := context.Background()
	turns, err := c.s.recentTurns(ctx, c.thread, 0, 30)
	if err == nil {
		for i := range turns {
			b.WriteString(renderTurn(&turns[i]))
			b.WriteString("\n")
		}
	}
	return b.String()
}

func (c *chatStep) call(ctx context.Context, name, arguments string) (string, error) {
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
	case "send":
		topic := strArg("topic")
		switch topic {
		case "chat.propose", "chat.note", "chat.answer":
		default:
			return "", fmt.Errorf("invalid topic %q", topic)
		}
		if err := createTurnIn(ctx, c.s.Client, c.thread.Namespace, fmt.Sprintf("chat-%d-%s", timeNow().UnixNano(), shortUser(c.user)), turnSpec{
			Thread: c.thread.Name, AuthorKind: v1.TurnAuthorUser, AuthorName: c.user,
			Topic: topic, Text: truncateRunes(strArg("text"), 2048), Wake: v1.WakeBatch,
		}); err != nil {
			return "", err
		}
		return "sent to the coordinator", nil
	case "turns":
		since, _ := args["since"].(float64)
		turns, err := c.s.recentTurns(ctx, c.thread, int64(since), 50)
		if err != nil {
			return "", err
		}
		var b strings.Builder
		for i := range turns {
			b.WriteString(renderTurn(&turns[i]))
			b.WriteString("\n")
		}
		if b.Len() == 0 {
			return "(no turns)", nil
		}
		return b.String(), nil
	case "board":
		if len(c.thread.Status.Tasks) == 0 {
			return "(empty)", nil
		}
		var b strings.Builder
		for _, t := range c.thread.Status.Tasks {
			fmt.Fprintf(&b, "- %s %s %q note=%q\n", t.ID, openState(t.Open), t.Title, t.Note)
		}
		return b.String(), nil
	case "task":
		for _, t := range c.thread.Status.Tasks {
			if t.ID == strArg("id") {
				raw, _ := json.Marshal(t)
				return string(raw), nil
			}
		}
		return "", fmt.Errorf("task %q not found", strArg("id"))
	case "blips":
		return c.s.blipList(ctx, c.thread)
	case "inspect":
		var argv []string
		if raw, ok := args["argv"].([]any); ok {
			for _, a := range raw {
				argv = append(argv, fmt.Sprint(a))
			}
		}
		return c.inspect(ctx, strArg("blip"), argv)
	default:
		return "", fmt.Errorf("unknown tool %q", name)
	}
}

// inspect is deliberately read-only: engineers may look, not act.
func (c *chatStep) inspect(ctx context.Context, name string, argv []string) (string, error) {
	var b v1.Blip
	if err := c.s.Get(ctx, client.ObjectKey{Namespace: c.thread.Namespace, Name: name}, &b); err != nil {
		return "", err
	}
	if !belongsToThread(&b, c.thread) {
		return "", fmt.Errorf("blip %q does not belong to thread %q", name, c.thread.Name)
	}
	if v1.Finished(&b) || b.Status.Pod == "" {
		summary := ""
		if r := b.Status.Report; r != nil {
			_, summary = reportFields(r.Text)
		}
		return fmt.Sprintf("blip %s is %s; report: %s", b.Name, b.Status.Phase, summary), nil
	}
	if len(argv) == 0 {
		return "", fmt.Errorf("argv is required for a running blip")
	}
	if err := readOnly(argv); err != nil {
		return "", err
	}
	return c.s.execIn(ctx, c.thread, name, argv, maxExecTimeout)
}

// readOnly reports whether argv is safe to run as an inspection command. It
// checks the whole argument vector: several otherwise read-only tools can
// execute commands or write files through options, so looking only at argv[0]
// is not enough.
func readOnly(argv []string) error {
	if len(argv) == 0 {
		return fmt.Errorf("empty command")
	}
	switch argv[0] {
	case "ls", "cat", "head", "tail", "wc", "grep", "pwd":
		return nil
	case "rg":
		for _, arg := range argv[1:] {
			if isRipgrepEscape(arg) {
				return fmt.Errorf("rg option %q can execute commands", arg)
			}
		}
		return nil
	case "find":
		for _, arg := range argv[1:] {
			if isFindEscape(arg) {
				return fmt.Errorf("find option %q can execute commands or write files", arg)
			}
		}
		return nil
	case "git":
		return readOnlyGit(argv[1:])
	}
	return fmt.Errorf("only read-only commands are allowed here")
}

func isRipgrepEscape(arg string) bool {
	return arg == "--pre" || strings.HasPrefix(arg, "--pre=") ||
		arg == "--pre-glob" || strings.HasPrefix(arg, "--pre-glob=")
}

func isFindEscape(arg string) bool {
	switch arg {
	case "-exec", "-execdir", "-delete", "-ok", "-okdir",
		"-fprint", "-fprint0", "-fprintf", "-fls":
		return true
	}
	return false
}

func readOnlyGit(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("git needs a subcommand")
	}
	switch args[0] {
	case "status", "log", "diff", "show", "rev-parse":
		for _, arg := range args[1:] {
			if isGitEscape(arg) {
				return fmt.Errorf("git option %q can execute commands or write files", arg)
			}
		}
		return nil
	case "branch":
		for _, arg := range args[1:] {
			if isGitEscape(arg) {
				return fmt.Errorf("git option %q can execute commands or write files", arg)
			}
			if !strings.HasPrefix(arg, "-") {
				return fmt.Errorf("git branch may only list branches")
			}
			if !isReadOnlyBranchOption(arg) {
				return fmt.Errorf("git branch option %q is not read-only", arg)
			}
		}
		return nil
	}
	return fmt.Errorf("only read-only git subcommands are allowed here")
}

func isGitEscape(arg string) bool {
	return arg == "--output" || strings.HasPrefix(arg, "--output=") ||
		arg == "-O" || strings.HasPrefix(arg, "-O") ||
		arg == "--ext-diff" || strings.HasPrefix(arg, "--ext-diff=") ||
		arg == "--textconv" || strings.HasPrefix(arg, "--textconv=") ||
		arg == "--open-files-in-pager" || strings.HasPrefix(arg, "--open-files-in-pager=")
}

func isReadOnlyBranchOption(arg string) bool {
	name := arg
	if i := strings.IndexByte(name, '='); i >= 0 {
		name = name[:i]
	}
	switch name {
	case "-a", "--all", "-r", "--remotes", "-v", "-vv", "--verbose",
		"-l", "--list", "--show-current", "-i", "--ignore-case",
		"--merged", "--no-merged", "--contains", "--no-contains",
		"--points-at", "--format", "--sort", "--column", "--no-column",
		"--color", "--no-color", "--abbrev", "--no-abbrev", "--omit-empty":
		return true
	}
	return false
}

// shortUser derives a deterministic DNS-1123-safe fragment from an identity
// for use in a turn name. Identities are arbitrary header values: they may
// contain uppercase, backslashes (DOMAIN\user), spaces, or non-ASCII, and
// Kubernetes would reject those names. The short hash keeps distinct
// identities distinct after sanitizing (for example "Alice" and "alice").
func shortUser(user string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(user) {
		if b.Len() >= 28 {
			break
		}
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			dash = false
			continue
		}
		if b.Len() > 0 && !dash {
			b.WriteByte('-')
			dash = true
		}
	}
	s := strings.Trim(b.String(), "-")
	if s == "" {
		s = "user"
	}
	sum := sha256.Sum256([]byte(user))
	return s + "-" + hex.EncodeToString(sum[:4])
}

// validNamespace reports whether the namespace query parameter is a valid
// Kubernetes namespace (a DNS-1123 label).
func validNamespace(ns string) bool {
	return len(validation.IsDNS1123Label(ns)) == 0
}

// recentTurns returns up to limit turns with a sequence above since.
func (s *Server) recentTurns(ctx context.Context, thread *v1.BlipThread, since int64, limit int) ([]v1.BlipTurn, error) {
	var turns v1.BlipTurnList
	if err := s.List(ctx, &turns, client.InNamespace(thread.Namespace), client.MatchingFields{turnField: thread.Name}); err != nil {
		return nil, err
	}
	out := make([]v1.BlipTurn, 0, len(turns.Items))
	for _, t := range turns.Items {
		if t.Status.Seq <= since || !turnBelongsToThread(&t, thread) {
			continue
		}
		out = append(out, t)
	}
	sortTurns(out)
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out, nil
}
