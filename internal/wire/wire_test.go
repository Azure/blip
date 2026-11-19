package wire

import (
	"encoding/json"
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
