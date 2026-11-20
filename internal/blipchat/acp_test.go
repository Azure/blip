// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"bytes"
	"testing"
)

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
