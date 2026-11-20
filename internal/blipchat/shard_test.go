// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import "testing"

func TestSharderOwnership(t *testing.T) {
	members := []string{"pod-a", "pod-b", "pod-c"}
	owners := map[string]int{}
	for _, self := range members {
		s := &sharder{service: "blipchat", self: self, members: members}
		for _, chat := range []string{"chat-1", "chat-2", "chat-3", "chat-4", "chat-5", "chat-6"} {
			if s.owns(chat) {
				owners[chat]++
			}
		}
	}
	for chat, n := range owners {
		if n != 1 {
			t.Fatalf("%s has %d owners, want 1", chat, n)
		}
	}

	// Without membership information a replica drives everything rather than
	// dropping chats on the floor.
	for _, s := range []*sharder{
		nil,
		{service: "", self: "pod-a", members: members},
		{service: "blipchat", self: "", members: members},
		{service: "blipchat", self: "pod-a", members: nil},
	} {
		if !s.owns("chat-1") {
			t.Fatalf("sharder %+v should own every chat", s)
		}
	}
}
