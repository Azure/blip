// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestSessionFramesCarryCwd(t *testing.T) {
	type params struct {
		Cwd       string `json:"cwd"`
		SessionID string `json:"sessionId"`
	}
	type frame struct {
		Method string `json:"method"`
		Params params `json:"params"`
	}
	tests := []struct {
		name      string
		frame     json.RawMessage
		method    string
		sessionID string
		cwd       string
	}{
		{
			name:   "new",
			frame:  newSessionFrame(7, "/src/blip", nil),
			method: "session/new",
			cwd:    "/src/blip",
		},
		{
			name:      "load",
			frame:     sessionSetupFrame(7, "session/load", "s1", "/src/blip", nil),
			method:    "session/load",
			sessionID: "s1",
			cwd:       "/src/blip",
		},
		{
			name:      "resume",
			frame:     sessionSetupFrame(7, "session/resume", "s1", "/src/blip", nil),
			method:    "session/resume",
			sessionID: "s1",
			cwd:       "/src/blip",
		},
		{
			name:   "new defaults to root",
			frame:  newSessionFrame(7, "/", nil),
			method: "session/new",
			cwd:    "/",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got frame
			if err := json.Unmarshal(tc.frame, &got); err != nil {
				t.Fatal(err)
			}
			if got.Method != tc.method {
				t.Fatalf("method = %q, want %q", got.Method, tc.method)
			}
			if got.Params.Cwd != tc.cwd {
				t.Fatalf("cwd = %q, want %q", got.Params.Cwd, tc.cwd)
			}
			if got.Params.SessionID != tc.sessionID {
				t.Fatalf("sessionId = %q, want %q", got.Params.SessionID, tc.sessionID)
			}
		})
	}
}

func TestSendLine(t *testing.T) {
	frame := []byte(`{"jsonrpc":"2.0","method":"initialize"}`)
	want := append(append([]byte(nil), frame...), '\n')
	got := sendLine(frame)
	if !bytes.Equal(got, want) {
		t.Fatalf("sendLine(%q) = %q, want %q", frame, got, want)
	}
	if !bytes.Equal(frame, want[:len(want)-1]) {
		t.Fatal("sendLine mutated its input")
	}

	withNewline := []byte("{\"jsonrpc\":\"2.0\"}\n")
	if got := sendLine(withNewline); !bytes.Equal(got, withNewline) {
		t.Fatalf("sendLine(%q) = %q, want unchanged", withNewline, got)
	}

	if got := sendLine(nil); len(got) != 0 {
		t.Fatalf("sendLine(nil) = %q, want empty", got)
	}
	if got := sendLine([]byte{}); len(got) != 0 {
		t.Fatalf("sendLine(empty) = %q, want empty", got)
	}
}
