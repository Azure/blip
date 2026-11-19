package blipchat

import (
	"context"
	"strings"
	"testing"
)

// reply must reject an inReplyTo that cannot be stored as a non-negative
// int64. Converting an out-of-range float64 wraps negative, and createTurnIn
// would then clamp the reply to sequence 0 instead of the requested turn.
func TestReplyRejectsOutOfRangeSequence(t *testing.T) {
	for _, seq := range []string{
		"1e300",
		"9223372036854775807",  // MaxInt64 rounds to 2^63 as float64
		"9223372036854775808",  // MaxInt64+1
		"18446744073709551616", // 1<<64
		"1.5",
		"-1",
	} {
		t.Run(seq, func(t *testing.T) {
			st := &step{thread: testThread()}
			_, err := st.call(context.Background(), "reply", `{"inReplyTo":`+seq+`,"text":"hi"}`)
			if err == nil {
				t.Fatalf("inReplyTo %s was accepted", seq)
			}
			if !strings.Contains(err.Error(), "inReplyTo must be a non-negative sequence number") {
				t.Errorf("error = %v, want the inReplyTo message", err)
			}
			if len(st.replies) != 0 {
				t.Errorf("rejected reply was recorded: %+v", st.replies)
			}
		})
	}
}

func TestReplyAcceptsSequence(t *testing.T) {
	st := &step{thread: testThread()}
	if _, err := st.call(context.Background(), "reply", `{"inReplyTo":3,"text":"hi"}`); err != nil {
		t.Fatal(err)
	}
	if len(st.replies) != 1 || st.replies[0].InReplyTo != 3 {
		t.Errorf("replies = %+v, want inReplyTo 3", st.replies)
	}
}
