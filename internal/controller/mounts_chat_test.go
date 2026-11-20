// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package controller

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

func TestChatRootMountIsOwnedByTree(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	st := e.readyState("chat-abc", "n1")
	st.Labels = map[string]string{v1.LabelOwner: "chat-abc", v1.LabelChatSession: "true"}
	e.must(e.c.Update(e.ctx, st))
	e.newBlip("chat-abc-g1", withRoot("chat-abc"), func(b *v1.Blip) {
		b.Labels = map[string]string{v1.LabelOwner: "chat-abc", v1.LabelChatSession: "chat-abc"}
	})
	e.run(e.blip, ns, "chat-abc-g1")
	expectPhase(t, e.getBlip("chat-abc-g1"), v1.BlipPending, ReasonWaitingForVM)
}

func TestReadableByChatState(t *testing.T) {
	state := func(name, owner, session, image string) *v1.BlipState {
		return &v1.BlipState{ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{v1.LabelOwner: owner, v1.LabelChatSession: session},
		}, Spec: v1.BlipStateSpec{Image: image}}
	}
	for _, tt := range []struct {
		name     string
		owner    string
		state    *v1.BlipState
		readable bool
		chat     bool
	}{
		{"root chat name equals owner", "chat-abc", state("chat-abc", "chat-abc", "true", ""), false, true},
		{"child chat has tree owner", "chat-abc", state("chat-def", "chat-abc", "true", ""), false, true},
		{"chat owner mismatch", "chat-abc", state("chat-def", "chat-other", "true", ""), false, false},
		{"ordinary owner prefix", "alice", state("alice.data", "alice", "", ""), true, false},
		{"ordinary state is still prefix-scoped", "alice", state("bob.data", "alice", "", ""), false, false},
		{"shared image state is readable", "alice", state("base", "", "", "reg/img:v1"), true, false},
		{"unrestricted owner reads everything", "", state("bob.data", "bob", "", ""), true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := readableBy(tt.owner, tt.state); got != tt.readable {
				t.Fatalf("readableBy(%q, %+v) = %v, want %v", tt.owner, tt.state, got, tt.readable)
			}
			if got := chatStateOwnedBy(tt.owner, tt.state); got != tt.chat {
				t.Fatalf("chatStateOwnedBy(%q, %+v) = %v, want %v", tt.owner, tt.state, got, tt.chat)
			}
		})
	}
}

func TestChatStateNotMountableByNonChatBlip(t *testing.T) {
	e := newEnv(t)
	e.addNodes("n1")
	e.newPool("default", 0, 0)
	st := e.readyState("chat-abc", "n1")
	st.Labels = map[string]string{v1.LabelOwner: "chat-abc", v1.LabelChatSession: "true"}
	e.must(e.c.Update(e.ctx, st))
	e.newBlip("plain", withRoot("chat-abc"), func(b *v1.Blip) {
		b.Labels = map[string]string{v1.LabelOwner: "chat-abc"}
	})
	e.run(e.blip, ns, "plain")
	b := e.getBlip("plain")
	expectPhase(t, b, v1.BlipFailed, ReasonInvalidSpec)
	if !strings.Contains(b.Status.Message, "is not owned by") {
		t.Fatalf("message = %q", b.Status.Message)
	}
}
