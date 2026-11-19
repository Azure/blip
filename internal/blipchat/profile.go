// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// DefaultProfileName is the profile used when a request does not name one.
const DefaultProfileName = "default"

// DefaultIdleSeconds stops an idle agent after an hour. A chat agent exits on
// EOF at the end of a turn, so this is only a backstop for a client that
// disappears in the middle of one.
const DefaultIdleSeconds int64 = 3600

// DefaultCommand is the documented example agent. It is not installed in the
// blip by this program: a deployment that uses it needs a base state whose
// filesystem already has node/npx, or another profile must be configured.
var DefaultCommand = []string{"npx", "-y", "@zed-industries/claude-code-acp"}

// Profile describes the blip a chat session runs and the agent inside it.
type Profile struct {
	Pool               string            `json:"pool,omitempty"`
	Command            []string          `json:"command,omitempty"`
	Env                map[string]string `json:"-"`
	IdleTimeoutSeconds int64             `json:"idleTimeoutSeconds,omitempty"`
	Title              string            `json:"title,omitempty"`
}

// UnmarshalJSON accepts env as an object (KEY: VALUE) or as a list of
// {name,value} objects, which is how the Kubernetes types spell it.
func (p *Profile) UnmarshalJSON(data []byte) error {
	var raw struct {
		Pool               string          `json:"pool"`
		Command            []string        `json:"command"`
		Env                json.RawMessage `json:"env"`
		IdleTimeoutSeconds int64           `json:"idleTimeoutSeconds"`
		Title              string          `json:"title"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	p.Pool = raw.Pool
	p.Command = raw.Command
	p.IdleTimeoutSeconds = raw.IdleTimeoutSeconds
	p.Title = raw.Title
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
	return p
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
