// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestProfileParsesBaseSelector(t *testing.T) {
	var p Profile
	raw := `{"command":["agent"],"baseSelector":{"matchLabels":{"app":"agent"}}}`
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatal(err)
	}
	if p.BaseSelector == nil || p.BaseSelector.MatchLabels["app"] != "agent" {
		t.Fatalf("baseSelector = %+v", p.BaseSelector)
	}
	sel, err := p.baseStateSelector()
	if err != nil {
		t.Fatal(err)
	}
	if !sel.Matches(labels.Set{"app": "agent"}) {
		t.Fatal("selector does not match the configured labels")
	}
	if sel.Matches(labels.Set{"app": "agent", LabelSession: "true"}) {
		t.Fatal("selector matches a chat state")
	}
}

func TestProfileWithoutBaseSelectorStartsEmpty(t *testing.T) {
	var p Profile
	if err := json.Unmarshal([]byte(`{"command":["agent"]}`), &p); err != nil {
		t.Fatal(err)
	}
	sel, err := p.baseStateSelector()
	if err != nil {
		t.Fatal(err)
	}
	if sel != nil {
		t.Fatalf("selector = %v, want nil", sel)
	}
}

func TestProfileRejectsInvalidBaseSelector(t *testing.T) {
	var p Profile
	raw := `{"baseSelector":{"matchExpressions":[{"key":"app","operator":"Bogus"}]}}`
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatal(err)
	}
	if _, err := p.baseStateSelector(); err == nil {
		t.Fatal("invalid selector accepted")
	}
}

func TestProfileIgnoresLegacyAgents(t *testing.T) {
	var p Profile
	raw := `{"command":["agent"],"description":"reviews","workspace":"fork","agents":{"allow":["worker"],"maxChildren":2,"maxDepth":1}}`
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatal(err)
	}
	if p.Description != "reviews" || p.Workspace != WorkspaceFork {
		t.Fatalf("profile = %+v", p)
	}
}

func TestProfileDefaultsWorkspace(t *testing.T) {
	p := Profile{}.normalized("pool")
	if p.Workspace != WorkspaceBase {
		t.Fatalf("workspace = %q", p.Workspace)
	}
}

func TestProfileValidate(t *testing.T) {
	if err := (Profile{Workspace: WorkspaceFork}).validate(); err != nil {
		t.Fatal(err)
	}
	if err := (Profile{Workspace: "copy"}).validate(); err == nil {
		t.Fatal("invalid workspace accepted")
	}
}

func TestProfileParsesWorkingDir(t *testing.T) {
	var p Profile
	raw := `{"command":["agent"],"workingDir":"/src/blip"}`
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatal(err)
	}
	if p.WorkingDir != "/src/blip" {
		t.Fatalf("workingDir = %q", p.WorkingDir)
	}
	if got := p.sessionCwd(); got != "/src/blip" {
		t.Fatalf("sessionCwd = %q, want /src/blip", got)
	}

	var empty Profile
	if err := json.Unmarshal([]byte(`{"command":["agent"]}`), &empty); err != nil {
		t.Fatal(err)
	}
	if got := empty.sessionCwd(); got != "/" {
		t.Fatalf("empty sessionCwd = %q, want /", got)
	}
}

func TestProfileValidateWorkingDir(t *testing.T) {
	tests := []struct {
		name    string
		dir     string
		wantErr string
	}{
		{name: "empty defaults to root", dir: ""},
		{name: "root", dir: "/"},
		{name: "nested", dir: "/src/blip"},
		{name: "home config", dir: "/home/dev/.config"},
		{name: "relative", dir: "src/blip", wantErr: "must be absolute"},
		{name: "unclean parent", dir: "/src/../etc", wantErr: "is not clean"},
		{name: "trailing slash", dir: "/src/", wantErr: "is not clean"},
		{name: "reserved proc", dir: "/proc", wantErr: "is reserved"},
		{name: "reserved proc child", dir: "/proc/1", wantErr: "is reserved"},
		{name: "reserved run blip child", dir: "/run/blip/x", wantErr: "is reserved"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := (Profile{Workspace: WorkspaceBase, WorkingDir: tc.dir}).validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validate(%q) = %v, want nil", tc.dir, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validate(%q) = nil, want error containing %q", tc.dir, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("validate(%q) = %v, want error containing %q", tc.dir, err, tc.wantErr)
			}
		})
	}
}

func TestProfileMessageTemplateKeepsLegacyAgentsField(t *testing.T) {
	if err := (Profile{Workspace: WorkspaceBase, MessageTemplate: "{{.Agents}} {{.Text}}"}).validate(); err != nil {
		t.Fatalf("legacy .Agents template rejected: %v", err)
	}
}

func TestProfileParsesMessageTemplate(t *testing.T) {
	var p Profile
	raw := `{"command":["agent"],"messageTemplate":"chat {{.Session}}: {{.Text}}"}`
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatal(err)
	}
	if p.MessageTemplate != "chat {{.Session}}: {{.Text}}" {
		t.Fatalf("messageTemplate = %q", p.MessageTemplate)
	}
}

func TestProfileMessageTemplateEmpty(t *testing.T) {
	out, err := (Profile{}).renderMessage(MessageData{Text: "hello"})
	if err != nil {
		t.Fatal(err)
	}
	if out != "hello" {
		t.Fatalf("rendered = %q", out)
	}
}

func TestProfileMessageTemplateRendersFields(t *testing.T) {
	p := Profile{MessageTemplate: "session={{.Session}} ns={{.Namespace}} profile={{.Profile}} title={{.Title}} description={{.Description}} base={{.Base}} parent={{.Parent}} root={{.Root}} depth={{.Depth}} created={{.Created}} text={{.Text}}"}
	out, err := p.renderMessage(MessageData{
		Text:        "hello",
		Session:     "chat-abc",
		Namespace:   "team",
		Profile:     "reviewer",
		Title:       "Reviewer",
		Description: "reviews changes",
		Base:        "base-state",
		Parent:      "chat-parent",
		Root:        "chat-root",
		Depth:       2,
		Created:     "2026-01-02T03:04:05Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"session=chat-abc",
		"ns=team",
		"profile=reviewer",
		"title=Reviewer",
		"description=reviews changes",
		"base=base-state",
		"parent=chat-parent",
		"root=chat-root",
		"depth=2",
		"created=2026-01-02T03:04:05Z",
		"text=hello",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("rendered %q does not contain %q", out, want)
		}
	}
}

func TestProfileMessageTemplateValidation(t *testing.T) {
	if err := (Profile{Workspace: WorkspaceBase, MessageTemplate: "chat {{.Session}}: {{.Text}}"}).validate(); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		tmpl string
		want string
	}{
		{"syntax", "{{.Text", "messageTemplate:"},
		{"unknown field", "{{.Missing}} {{.Text}}", "messageTemplate:"},
		{"missing text", "hello", "must include {{.Text}}"},
		{"conditional text", "{{if .Parent}}{{.Text}}{{end}}", "must include {{.Text}}"},
		{"hardcoded sentinel", messageSentinel + " {{.Title}}", "must include {{.Text}}"},
		{"inflates text", "{{.Text}}{{.Text}}{{.Text}}", "too large"},
		{"too large", strings.Repeat("x", maxPromptBytes+1), "too large"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := (Profile{Workspace: WorkspaceBase, MessageTemplate: tc.tmpl}).validate()
			if err == nil {
				t.Fatal("invalid template accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want %q", err, tc.want)
			}
		})
	}
}

func TestValidProfileName(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"default", true},
		{"worker-1", true},
		{"a.b", true},
		{"UPPER", true},
		{"ops_team", true},
		{"", false},
		{"bad name", false},
		{"bad*name", false},
		{"-lead", false},
		{".lead", false},
		{"a/b", false},
	} {
		if got := validProfileName(tc.name); got != tc.want {
			t.Errorf("validProfileName(%q) = %t, want %t", tc.name, got, tc.want)
		}
	}
}

func TestLoadProfilesRejectsInvalidNames(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "profiles.json")
	if err := os.WriteFile(file, []byte(`{"Bad Name":{"command":["agent"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadProfiles(context.Background(), nil, "", "", file, "default"); err == nil {
		t.Fatal("LoadProfiles accepted an invalid profile name in the file")
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "profiles", Namespace: "team"},
		Data:       map[string]string{"bad*name": `{"command":["agent"]}`},
	}
	c := fake.NewClientBuilder().WithScheme(clientgoscheme.Scheme).WithObjects(cm).Build()
	if _, err := LoadProfiles(context.Background(), c, "team", "profiles", "", "default"); err == nil {
		t.Fatal("LoadProfiles accepted an invalid ConfigMap key")
	}
}

func TestLoadProfilesKeepsValidNames(t *testing.T) {
	file := filepath.Join(t.TempDir(), "profiles.json")
	if err := os.WriteFile(file, []byte(`{"worker.1":{"command":["agent"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ps, err := LoadProfiles(context.Background(), nil, "", "", file, "pool")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ps["worker.1"]; !ok {
		t.Fatalf("profiles = %v", ps)
	}
	if ps["worker.1"].Workspace != WorkspaceBase {
		t.Fatalf("workspace = %q", ps["worker.1"].Workspace)
	}
}
