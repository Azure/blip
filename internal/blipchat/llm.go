package blipchat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Message is one OpenAI chat message.
type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
}

// ToolCall is a function call requested by the model.
type ToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// Tool is an OpenAI tool definition.
type Tool struct {
	Type     string `json:"type"`
	Function struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Parameters  json.RawMessage `json:"parameters"`
	} `json:"function"`
}

// FunctionTool builds a tool definition from a JSON schema.
func FunctionTool(name, description string, parameters any) Tool {
	raw, err := json.Marshal(parameters)
	if err != nil {
		panic(err)
	}
	var t Tool
	t.Type = "function"
	t.Function.Name = name
	t.Function.Description = description
	t.Function.Parameters = raw
	return t
}

// Usage is token accounting for one completion.
type Usage struct {
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
}

func (u Usage) Total() int64 { return u.PromptTokens + u.CompletionTokens }

// LLM calls an OpenAI-compatible chat completions endpoint.
type LLM struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client
}

// Chat sends one completion request.
func (l *LLM) Chat(ctx context.Context, model string, messages []Message, tools []Tool) (Message, Usage, error) {
	if model == "" {
		return Message{}, Usage{}, errors.New("no model configured")
	}
	body := map[string]any{"model": model, "messages": messages}
	if len(tools) > 0 {
		body["tools"] = tools
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return Message{}, Usage{}, err
	}
	url := strings.TrimRight(l.BaseURL, "/") + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(encoded))
	if err != nil {
		return Message{}, Usage{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if l.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+l.APIKey)
	}
	resp, err := l.HTTP.Do(req)
	if err != nil {
		return Message{}, Usage{}, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return Message{}, Usage{}, err
	}
	if resp.StatusCode/100 != 2 {
		return Message{}, Usage{}, fmt.Errorf("llm: %s: %s", resp.Status, truncate(string(data), 512))
	}
	var out struct {
		Choices []struct {
			Message Message `json:"message"`
		} `json:"choices"`
		Usage Usage `json:"usage"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return Message{}, Usage{}, fmt.Errorf("llm: decode response: %w", err)
	}
	if len(out.Choices) == 0 {
		return Message{}, out.Usage, errors.New("llm: empty response")
	}
	return out.Choices[0].Message, out.Usage, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
