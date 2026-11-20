// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
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

func TestRestWireLogEnd(t *testing.T) {
	var followed string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		followed = r.URL.Query().Get("follow")
		if r.URL.Path != "/apis/stream.blip.dev/v1alpha1/namespaces/team/blipstreams/chat-x/log" {
			t.Errorf("path = %q", r.URL.Path)
		}
		fmt.Fprintln(w, `{"o":10,"g":1,"t":1,"d":""}`)
		fmt.Fprintln(w, `{"o":40,"g":2,"t":2,"d":""}`)
		fmt.Fprintln(w, `{"t":"gap","o":900}`)
	}))
	defer ts.Close()
	wire, err := NewWire(&rest.Config{
		Host:                 ts.URL,
		APIPath:              "/apis",
		GroupVersion:         &schema.GroupVersion{Group: "stream.blip.dev", Version: "v1alpha1"},
		NegotiatedSerializer: scheme.Codecs.WithoutConversion(),
	})
	if err != nil {
		t.Fatal(err)
	}
	end, err := wire.LogEnd(context.Background(), "team", "chat-x")
	if err != nil {
		t.Fatal(err)
	}
	if end != 40 {
		t.Fatalf("end = %d, want 40", end)
	}
	if followed != "false" {
		t.Fatalf("follow = %q", followed)
	}
}
