// Package blipchat is the project coordinator: it sequences turns, turns blip
// reports into turns, runs asynchronous coordinator steps against an
// OpenAI-compatible model, and serves the engineer chat.
package blipchat

import (
	"net/http"
	"time"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// Config holds the process-wide settings. Per-thread settings (model, pool,
// heartbeat, retention) come from BlipThread.
type Config struct {
	// BaseURL is the OpenAI-compatible API root, for example
	// https://llm.example/v1. Authentication is supplied by the network
	// proxy in front of it, or by APIKey.
	BaseURL string
	APIKey  string
	// Model is used when a thread does not set spec.model.
	Model string
	// AgentCommand starts one task. The prompt is appended as the last
	// argument.
	AgentCommand []string
	// Debounce is how long Batch turns wait for more turns before a step.
	Debounce time.Duration
	// Heartbeat advances a thread with open tasks when nothing else does.
	Heartbeat time.Duration
	// StepTokenLimit bounds one step's prompt plus completion tokens.
	StepTokenLimit int64
	// MaxToolCalls bounds tool calls in one step.
	MaxToolCalls int
	// Listen is the chat HTTP listen address.
	Listen string
	// HTTPClient is used for LLM requests. Its Timeout bounds one call; a
	// chat round is further bounded by ChatRoundTimeout and the whole chat
	// request by ChatTimeout.
	HTTPClient *http.Client
	// ChatTimeout bounds one /chat request from thread lookup through the
	// last model round and tool call. It must stay below the HTTP server's
	// write timeout so a slow request is answered instead of having its
	// connection closed.
	ChatTimeout time.Duration
	// ChatRoundTimeout bounds one model call in a chat request.
	ChatRoundTimeout time.Duration
	// ChatMaxRounds bounds model round-trips in one chat request.
	ChatMaxRounds int
}

// Default chat budgets. The overall budget leaves the HTTP server room to
// send an error response before writeTimeout closes the connection, even when
// a tool call already committed a turn.
const (
	defaultChatTimeout      = 4 * time.Minute
	defaultChatRoundTimeout = 2 * time.Minute
	defaultChatMaxRounds    = 8
)

func (c *Config) defaults() {
	if c.Debounce <= 0 {
		c.Debounce = 5 * time.Second
	}
	if c.Heartbeat <= 0 {
		c.Heartbeat = 30 * time.Minute
	}
	if c.StepTokenLimit <= 0 {
		c.StepTokenLimit = 60000
	}
	if c.MaxToolCalls <= 0 {
		c.MaxToolCalls = 20
	}
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 5 * time.Minute}
	}
	if c.ChatTimeout <= 0 {
		c.ChatTimeout = defaultChatTimeout
	}
	if c.ChatRoundTimeout <= 0 {
		c.ChatRoundTimeout = defaultChatRoundTimeout
	}
	if c.ChatMaxRounds <= 0 {
		c.ChatMaxRounds = defaultChatMaxRounds
	}
	if len(c.AgentCommand) == 0 {
		c.AgentCommand = []string{"blip-pi"}
	}
}

func (c Config) chatTimeout() time.Duration {
	if c.ChatTimeout > 0 {
		return c.ChatTimeout
	}
	return defaultChatTimeout
}

func (c Config) chatRoundTimeout() time.Duration {
	if c.ChatRoundTimeout > 0 {
		return c.ChatRoundTimeout
	}
	return defaultChatRoundTimeout
}

func (c Config) chatMaxRounds() int {
	if c.ChatMaxRounds > 0 {
		return c.ChatMaxRounds
	}
	return defaultChatMaxRounds
}

// Owner is the ownership label for objects a thread creates. It is derived
// from the thread's namespace and name, so it is stable and cannot collide
// with the u- owners derived from user identities.
func Owner(thread *ThreadKey) string {
	return v1.ThreadOwner(thread.Namespace, thread.Name)
}

// ThreadKey identifies a thread.
type ThreadKey struct {
	Namespace string
	Name      string
}

func (k ThreadKey) String() string { return k.Namespace + "/" + k.Name }

// ValidThread reports whether a turn's thread reference names this thread.
func ValidThread(turnThread string, thread *ThreadKey) bool { return turnThread == thread.Name }
