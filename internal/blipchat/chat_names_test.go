package blipchat

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"

	"k8s.io/apimachinery/pkg/util/validation"
)

func TestShortUserProducesValidNames(t *testing.T) {
	users := []string{
		"alice",
		"Alice",
		`CORP\Alice`,
		"alice smith",
		"alice@example.com",
		"Ünïcode",
		strings.Repeat("é", 30),
		strings.Repeat("€", 20),
		strings.Repeat("a", 39) + ".",
		strings.Repeat("A", 80),
		"alice.",
		"-alice-",
		"",
		"   ",
		"用户",
	}
	for _, user := range users {
		t.Run(fmt.Sprintf("%q", user), func(t *testing.T) {
			short := shortUser(user)
			if short != shortUser(user) {
				t.Fatalf("shortUser(%q) is not deterministic: %q vs %q", user, short, shortUser(user))
			}
			name := fmt.Sprintf("chat-%d-%s", int64(1750000000000000000), short)
			if errs := validation.IsDNS1123Subdomain(name); len(errs) != 0 {
				t.Errorf("user %q produced invalid name %q: %v", user, name, errs)
			}
			if !utf8.ValidString(name) {
				t.Errorf("user %q produced invalid UTF-8 name %q", user, name)
			}
			if len(name) > 63 {
				t.Errorf("user %q produced name longer than 63 bytes: %q", user, name)
			}
		})
	}
	if shortUser("Alice") == shortUser("alice") {
		t.Error("identities that differ only by case should not collapse to the same turn name fragment")
	}
}

// Send must work for every identity a front end may forward, not only the
// lowercase email-like ones the old sanitizer handled.
func TestChatSendUsesValidTurnNameForAnyIdentity(t *testing.T) {
	for _, user := range []string{"Alice", `CORP\Alice`, "alice smith", "Ünïcode", strings.Repeat("€", 20), "alice."} {
		t.Run(fmt.Sprintf("%q", user), func(t *testing.T) {
			upstream := llmServer(t,
				Message{Role: "assistant", ToolCalls: []ToolCall{toolCall("send", `{"topic":"chat.propose","text":"please add tests"}`)}},
				Message{Role: "assistant", Content: "I sent that to the coordinator."},
			)
			c := testClient(t, testThread())
			rec := chatRequestFor(t, c, upstream, user, "ns", `{"thread":"proj","message":"add tests"}`)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
			}
			turns := chatTurns(t, c)
			if len(turns) != 1 {
				t.Fatalf("got %d turns, want 1", len(turns))
			}
			turn := turns[0]
			if errs := validation.IsDNS1123Subdomain(turn.Name); len(errs) != 0 {
				t.Errorf("turn name %q is invalid: %v", turn.Name, errs)
			}
			if turn.Spec.Author.Name != user {
				t.Errorf("author = %q, want the raw identity %q", turn.Spec.Author.Name, user)
			}
		})
	}
}
