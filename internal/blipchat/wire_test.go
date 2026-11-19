package blipchat

import (
	"encoding/json"
	"testing"
)

func TestStreamLogRecordJSON(t *testing.T) {
	var out streamLogRecord
	line := `{"o":12,"g":3,"t":"out","d":"aGVsbG8K"}`
	if err := json.Unmarshal([]byte(line), &out); err != nil {
		t.Fatal(err)
	}
	if out.Offset != 12 || out.Gen != 3 || out.Type != recordOut || string(out.Data) != "hello\n" {
		t.Fatalf("out = %+v (%q)", out, out.Data)
	}

	var gap streamLogRecord
	if err := json.Unmarshal([]byte(`{"t":"gap","o":40}`), &gap); err != nil {
		t.Fatal(err)
	}
	if gap.Type != recordGap || gap.Offset != 40 || len(gap.Data) != 0 {
		t.Fatalf("gap = %+v", gap)
	}

	var arr streamLogRecord
	if err := json.Unmarshal([]byte(`[5,2,1,"eA=="]`), &arr); err != nil {
		t.Fatal(err)
	}
	if arr.Offset != 5 || arr.Gen != 2 || arr.Type != recordOut || string(arr.Data) != "x" {
		t.Fatalf("array = %+v", arr)
	}
}
