package wire

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// An old client's Open frame has no openID field. Decoding it must keep the
// mode and arguments and leave OpenID empty so the guest starts the command
// as it always did.
func TestOpenDecodesWithoutOpenID(t *testing.T) {
	var o Open
	if err := Decode([]byte(`{"mode":"exec","argv":["sh","-c","id"]}`), &o); err != nil {
		t.Fatal(err)
	}
	if o.Mode != OpenExec || len(o.Argv) != 3 || o.OpenID != "" {
		t.Fatalf("decoded %+v", o)
	}
}

// HTML metacharacters must not inflate the encoded frame: the frame limit is
// a byte budget for argv/env, not a budget that depends on their content. A
// 120 KB argument of < & > must stay about 120 KB, not grow to 720 KB.
func TestWriteJSONDoesNotHTMLEscape(t *testing.T) {
	arg := strings.Repeat("<&>", 40_000)
	o := Open{Mode: OpenExec, Argv: []string{"true", arg}}
	var buf bytes.Buffer
	if err := NewConn(&buf).WriteJSON(TOpen, o); err != nil {
		t.Fatal(err)
	}
	frame := buf.Bytes()
	if len(frame) < 5 {
		t.Fatalf("short frame: %d bytes", len(frame))
	}
	payload := frame[5:]
	if bytes.Contains(payload, []byte(`\u003c`)) || bytes.Contains(payload, []byte(`\u003e`)) || bytes.Contains(payload, []byte(`\u0026`)) {
		t.Fatalf("encoded payload HTML-escaped metacharacters: %s", payload[:80])
	}
	if len(payload) > len(arg)+64 {
		t.Fatalf("encoded payload = %d bytes for a %d-byte argument", len(payload), len(arg))
	}
	var got Open
	if err := Decode(payload, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Argv) != 2 || got.Argv[1] != arg {
		t.Fatalf("round trip changed argv: %d args", len(got.Argv))
	}
}

// The new field is omitted when empty and carried when set, so old guests
// that ignore unknown fields keep working.
func TestOpenOpenIDJSON(t *testing.T) {
	data, err := json.Marshal(Open{Mode: OpenExec})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if _, ok := fields["openID"]; ok {
		t.Fatalf("empty OpenID was encoded: %s", data)
	}

	data, err = json.Marshal(Open{Mode: OpenExec, OpenID: "open-1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["openID"] != "open-1" {
		t.Fatalf("encoded OpenID = %v in %s", fields["openID"], data)
	}
}

// Follow is omitted when false so an old guest that ignores unknown fields is
// unaffected, and carried when a follower sets it.
func TestOpenFollowJSON(t *testing.T) {
	data, err := json.Marshal(Open{Mode: OpenAttach})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if _, ok := fields["follow"]; ok {
		t.Fatalf("false Follow was encoded: %s", data)
	}

	data, err = json.Marshal(Open{Mode: OpenAttach, Follow: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["follow"] != true {
		t.Fatalf("encoded Follow = %v in %s", fields["follow"], data)
	}

	var o Open
	if err := Decode(data, &o); err != nil {
		t.Fatal(err)
	}
	if !o.Follow || o.Mode != OpenAttach {
		t.Fatalf("decoded %+v", o)
	}
}
