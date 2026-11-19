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
	// HTTPClient is used for LLM requests.
	HTTPClient *http.Client
}

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
	if len(c.AgentCommand) == 0 {
		c.AgentCommand = []string{"blip-pi"}
	}
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
