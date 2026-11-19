package wire

import (
	"bytes"
	"strings"
	"testing"
)

// HTML metacharacters must not inflate the encoded frame: the frame limit is
// a byte budget for payloads, not a budget that depends on their content.
func TestWriteJSONDoesNotHTMLEscape(t *testing.T) {
	arg := strings.Repeat("<&>", 40_000)
	var buf bytes.Buffer
	if err := NewConn(&buf).WriteJSON(TExited, Exit{Output: arg}); err != nil {
		t.Fatal(err)
	}
	payload := buf.Bytes()[5:]
	if bytes.Contains(payload, []byte(`\u003c`)) || len(payload) > len(arg)+32 {
		t.Fatalf("encoded payload escaped metacharacters: %d bytes", len(payload))
	}
}

func TestStdioDataRoundTrip(t *testing.T) {
	frame := EncodeData(42, []byte("hello"))
	off, data, err := DecodeData(frame)
	if err != nil || off != 42 || string(data) != "hello" {
		t.Fatalf("off=%d data=%q err=%v", off, data, err)
	}
	if _, _, err := DecodeData([]byte("x")); err == nil {
		t.Fatal("short frame accepted")
	}
}

func TestDecodeRejectsNonObjects(t *testing.T) {
	var h StdioHello
	for _, payload := range []string{"", "null", "[]", `"x"`} {
		if err := Decode([]byte(payload), &h); err == nil {
			t.Fatalf("accepted %q", payload)
		}
	}
}
