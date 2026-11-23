// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/template"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// DefaultProfileName is the profile used when a request does not name one.
const DefaultProfileName = "default"

// DefaultIdleSeconds stops an idle agent after an hour. A chat agent exits on
// EOF at the end of a turn, so this is only a backstop for a client that
// disappears in the middle of one.
const DefaultIdleSeconds int64 = 3600

// maxPromptBytes caps a message after MessageTemplate is applied.
const maxPromptBytes = 64 << 10

// DefaultCommand is the documented example agent. It is not installed in the
// blip by this program: a deployment that uses it needs a base state whose
// filesystem already has node/npx, or another profile must be configured.
var DefaultCommand = []string{"npx", "-y", "@zed-industries/claude-code-acp"}

// Workspace modes. A chat copies either the base state its selector finds or
// the workspace of the chat that spawned it.
const (
	WorkspaceBase = "base"
	WorkspaceFork = "fork"
)

// Profile describes the blip a chat session runs and the agent inside it.
type Profile struct {
	Pool               string                `json:"pool,omitempty"`
	Command            []string              `json:"command,omitempty"`
	Env                map[string]string     `json:"-"`
	IdleTimeoutSeconds int64                 `json:"idleTimeoutSeconds,omitempty"`
	Title              string                `json:"title,omitempty"`
	BaseSelector       *metav1.LabelSelector `json:"baseSelector,omitempty"`
	// Description explains the profile to an agent that may spawn it.
	Description string `json:"description,omitempty"`
	// MessageTemplate wraps each message before it is sent to the agent. It
	// is a text/template with the message available as {{.Text}}. An empty
	// template sends the message unchanged.
	MessageTemplate string `json:"messageTemplate,omitempty"`
	// Workspace is "base" (the default) or "fork". A forked chat starts with
	// a copy of its parent's workspace.
	Workspace string `json:"workspace,omitempty"`
	// Mounts attaches states selected when the chat is created. Each mount is
	// a private writable copy, so one chat cannot change what another sees.
	Mounts []ProfileMount `json:"mounts,omitempty"`
}

// ProfileMount selects a state and mounts a copy of it at Path for the life of
// the chat.
type ProfileMount struct {
	Path     string               `json:"path"`
	Selector metav1.LabelSelector `json:"selector"`
}

// selector returns the selector that finds the mount's source. Chat states are
// excluded so a broad selector never mounts another conversation's workspace.
func (m ProfileMount) selector() (labels.Selector, error) {
	sel, err := metav1.LabelSelectorAsSelector(&m.Selector)
	if err != nil {
		return nil, err
	}
	notChat, err := labels.NewRequirement(LabelSession, selection.DoesNotExist, nil)
	if err != nil {
		return nil, err
	}
	return sel.Add(*notChat), nil
}

// validProfileName reports whether name is a usable profile name. Admission
// policy scopes a chat to profiles by this name, so spaces and wildcards are
// rejected rather than interpreted.
func validProfileName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '.' || c == '-' || c == '_'
		if !ok {
			return false
		}
		if i == 0 && (c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// MessageData is the data a Profile.MessageTemplate receives.
type MessageData struct {
	Text        string
	Session     string
	Namespace   string
	Profile     string
	Title       string
	Description string
	Base        string
	Parent      string
	Root        string
	Depth       int
	Created     string
	// Agents is deprecated and always empty. It remains so message templates
	// written for the former profile-level allowlist still parse.
	Agents []string
}

// messageSentinel proves a template kept the user's message. It contains no
// template syntax or characters that a printf verb would escape.
const messageSentinel = "blip-message-7f3c5b19"

// renderMessage applies the profile's message template. An empty template
// returns the message unchanged.
func (p Profile) renderMessage(data MessageData) (string, error) {
	if p.MessageTemplate == "" {
		return data.Text, nil
	}
	tmpl, err := template.New("message").Parse(p.MessageTemplate)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	if err := tmpl.Execute(&b, data); err != nil {
		return "", err
	}
	return b.String(), nil
}

// messageSample returns a representative value for startup validation.
func messageSample(text string) MessageData {
	return MessageData{
		Text:        text,
		Session:     "chat-000000",
		Namespace:   "default",
		Profile:     DefaultProfileName,
		Title:       "ACP agent",
		Description: "sample profile",
		Base:        "base-state",
		Parent:      "chat-parent",
		Root:        "chat-root",
		Depth:       1,
		Created:     "2026-01-01T00:00:00Z",
	}
}

// baseStateSelector returns the selector that finds the state a new chat
// copies. Chat states are excluded so a broad selector never picks an
// existing conversation. A nil selector means the chat starts empty.
func (p Profile) baseStateSelector() (labels.Selector, error) {
	if p.BaseSelector == nil {
		return nil, nil
	}
	sel, err := metav1.LabelSelectorAsSelector(p.BaseSelector)
	if err != nil {
		return nil, err
	}
	notChat, err := labels.NewRequirement(LabelSession, selection.DoesNotExist, nil)
	if err != nil {
		return nil, err
	}
	return sel.Add(*notChat), nil
}

// UnmarshalJSON accepts env as an object (KEY: VALUE) or as a list of
// {name,value} objects, which is how the Kubernetes types spell it.
func (p *Profile) UnmarshalJSON(data []byte) error {
	var raw struct {
		Pool               string                `json:"pool"`
		Command            []string              `json:"command"`
		Env                json.RawMessage       `json:"env"`
		IdleTimeoutSeconds int64                 `json:"idleTimeoutSeconds"`
		Title              string                `json:"title"`
		BaseSelector       *metav1.LabelSelector `json:"baseSelector"`
		Description        string                `json:"description"`
		MessageTemplate    string                `json:"messageTemplate"`
		Workspace          string                `json:"workspace"`
		Mounts             []ProfileMount        `json:"mounts"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	p.Pool = raw.Pool
	p.Command = raw.Command
	p.IdleTimeoutSeconds = raw.IdleTimeoutSeconds
	p.Title = raw.Title
	p.BaseSelector = raw.BaseSelector
	p.Description = raw.Description
	p.MessageTemplate = raw.MessageTemplate
	p.Workspace = raw.Workspace
	p.Mounts = raw.Mounts
	p.Env = nil
	if len(raw.Env) != 0 && string(raw.Env) != "null" {
		env, err := parseEnv(raw.Env)
		if err != nil {
			return err
		}
		p.Env = env
	}
	return nil
}

func parseEnv(data json.RawMessage) (map[string]string, error) {
	var m map[string]string
	if err := json.Unmarshal(data, &m); err == nil {
		return m, nil
	}
	var list []corev1.EnvVar
	if err := json.Unmarshal(data, &list); err == nil {
		m = make(map[string]string, len(list))
		for _, e := range list {
			m[e.Name] = e.Value
		}
		return m, nil
	}
	var pairs []string
	if err := json.Unmarshal(data, &pairs); err == nil {
		m = make(map[string]string, len(pairs))
		for _, pair := range pairs {
			k, v, ok := strings.Cut(pair, "=")
			if !ok {
				return nil, fmt.Errorf("profile env %q is not KEY=VALUE", pair)
			}
			m[k] = v
		}
		return m, nil
	}
	return nil, fmt.Errorf("profile env must be an object or a list")
}

func (p Profile) normalized(defaultPool string) Profile {
	if len(p.Command) == 0 {
		p.Command = append([]string(nil), DefaultCommand...)
	}
	if p.Pool == "" {
		p.Pool = defaultPool
	}
	if p.IdleTimeoutSeconds <= 0 {
		p.IdleTimeoutSeconds = DefaultIdleSeconds
	}
	if p.Title == "" {
		p.Title = "ACP agent"
	}
	if p.Workspace == "" {
		p.Workspace = WorkspaceBase
	}
	return p
}

func (p Profile) validate() error {
	switch p.Workspace {
	case WorkspaceBase, WorkspaceFork:
	default:
		return fmt.Errorf("workspace must be %q or %q, got %q", WorkspaceBase, WorkspaceFork, p.Workspace)
	}
	seen := map[string]bool{}
	for _, m := range p.Mounts {
		if err := validateMountPath(m.Path); err != nil {
			return err
		}
		if seen[m.Path] {
			return fmt.Errorf("mount path %q is used more than once", m.Path)
		}
		seen[m.Path] = true
		if len(m.Selector.MatchLabels)+len(m.Selector.MatchExpressions) == 0 {
			return fmt.Errorf("mount %q needs a selector", m.Path)
		}
		if _, err := m.selector(); err != nil {
			return fmt.Errorf("mount %q: %w", m.Path, err)
		}
	}
	if p.MessageTemplate == "" {
		return nil
	}
	if len(p.MessageTemplate) > maxPromptBytes {
		return errors.New("messageTemplate is too large")
	}
	// Distinct samples catch a template that keeps a hardcoded sentinel
	// instead of the message, and the minimal sample catches a message that
	// only appears when optional fields are populated.
	full := messageSample(messageSentinel + "-full")
	minimal := MessageData{Text: messageSentinel + "-minimal"}
	for _, data := range []MessageData{full, minimal} {
		out, err := p.renderMessage(data)
		if err != nil {
			return fmt.Errorf("messageTemplate: %w", err)
		}
		if !strings.Contains(out, data.Text) {
			return errors.New("messageTemplate must include {{.Text}}")
		}
	}
	// Reject a template that cannot carry the largest message the API accepts
	// instead of failing every such message at runtime.
	out, err := p.renderMessage(messageSample(strings.Repeat("x", 32000)))
	if err != nil {
		return fmt.Errorf("messageTemplate: %w", err)
	}
	if len(out) > maxPromptBytes {
		return errors.New("messageTemplate output is too large for a 32000-byte message")
	}
	return nil
}

func (p Profile) envVars() []v1.EnvVar {
	keys := make([]string, 0, len(p.Env))
	for k := range p.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]v1.EnvVar, 0, len(keys))
	for _, k := range keys {
		out = append(out, v1.EnvVar{Name: k, Value: p.Env[k]})
	}
	return out
}

// Profiles is the set available to new sessions.
type Profiles map[string]Profile

func (ps Profiles) get(name, defaultPool string) Profile {
	if p, ok := ps[name]; ok {
		return p.normalized(defaultPool)
	}
	return ps[DefaultProfileName].normalized(defaultPool)
}

// LoadProfiles reads profiles from a ConfigMap and an optional JSON file.
// The file is merged over the ConfigMap. A missing ConfigMap is not an error:
// the built-in default profile is always available.
func LoadProfiles(ctx context.Context, c client.Reader, namespace, configMap, file, defaultPool string) (Profiles, error) {
	ps := Profiles{}
	if configMap != "" {
		ns, name := namespace, configMap
		if before, after, ok := strings.Cut(configMap, "/"); ok {
			ns, name = before, after
		}
		if ns == "" || name == "" {
			return nil, fmt.Errorf("--profiles-configmap must be NAME or NAMESPACE/NAME")
		}
		var cm corev1.ConfigMap
		err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, &cm)
		if err != nil && !apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("read profiles ConfigMap %s/%s: %w", ns, name, err)
		}
		for key, value := range cm.Data {
			if !validProfileName(key) {
				return nil, fmt.Errorf("profile name %q in %s/%s is invalid", key, ns, name)
			}
			var p Profile
			if err := json.Unmarshal([]byte(value), &p); err != nil {
				return nil, fmt.Errorf("profile %q in %s/%s: %w", key, ns, name, err)
			}
			ps[key] = p
		}
	}
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		var fromFile Profiles
		if err := json.Unmarshal(data, &fromFile); err != nil {
			return nil, fmt.Errorf("profiles file %s: %w", file, err)
		}
		for k, v := range fromFile {
			if !validProfileName(k) {
				return nil, fmt.Errorf("profile name %q in %s is invalid", k, file)
			}
			ps[k] = v
		}
	}
	if _, ok := ps[DefaultProfileName]; !ok {
		ps[DefaultProfileName] = Profile{}
	}
	for name, p := range ps {
		ps[name] = p.normalized(defaultPool)
	}
	return ps, nil
}
