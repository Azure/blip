package blipchat

import (
	"context"
	"strings"
	"testing"
)

// JSON decodes numbers as float64, which cannot represent every integer above
// 2^53. A sequence the coordinator cannot name exactly must be rejected, not
// silently rounded to a neighbouring turn.
func TestReplyRejectsUnrepresentableSequence(t *testing.T) {
	st := &step{thread: testThread()}
	if _, err := st.call(context.Background(), "reply", `{"inReplyTo":9007199254740991,"text":"ok"}`); err != nil {
		t.Fatalf("reply at 2^53-1: %v", err)
	}
	if got := st.replies[0].InReplyTo; got != maxSafeInteger {
		t.Errorf("inReplyTo = %d, want %d", got, maxSafeInteger)
	}

	for _, arg := range []string{"9007199254740992", "9007199254740993", "9223372036854775807"} {
		st := &step{thread: testThread()}
		_, err := st.call(context.Background(), "reply", `{"inReplyTo":`+arg+`,"text":"hi"}`)
		if err == nil {
			t.Errorf("reply accepted inReplyTo=%s", arg)
			continue
		}
		if !strings.Contains(err.Error(), "inReplyTo") {
			t.Errorf("reply error for %s = %v", arg, err)
		}
		if len(st.replies) != 0 {
			t.Errorf("reply for %s recorded %d turns", arg, len(st.replies))
		}
	}
}
