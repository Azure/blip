// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	// LogEnd is a cursor: the position just past the newest record.
	if end != 72 {
		t.Fatalf("end = %d, want 72", end)
	}
	if followed != "false" {
		t.Fatalf("follow = %q", followed)
	}
}

func TestRestWireSendStatus(t *testing.T) {
	for _, tt := range []struct {
		name   string
		code   int
		reason metav1.StatusReason
		want   error
	}{
		{"conflict", http.StatusConflict, metav1.StatusReasonConflict, ErrNotRunning},
		{"unavailable", http.StatusServiceUnavailable, metav1.StatusReasonServiceUnavailable, ErrUnavailable},
		{"too many requests", http.StatusTooManyRequests, metav1.StatusReasonTooManyRequests, ErrUnavailable},
		{"precondition", http.StatusPreconditionFailed, metav1.StatusReason("PreconditionFailed"), ErrPrecondition},
		{"internal error", http.StatusInternalServerError, metav1.StatusReasonInternalError, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("method = %q, want POST", r.Method)
				}
				if r.URL.Path != "/apis/stream.blip.dev/v1alpha1/namespaces/team/blipstreams/chat-x/stdin" {
					t.Errorf("path = %q", r.URL.Path)
				}
				if note := r.URL.Query().Get("note"); note != "true" {
					t.Errorf("note = %q, want true", note)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.code)
				_ = json.NewEncoder(w).Encode(metav1.Status{
					TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"},
					Status:   metav1.StatusFailure,
					Message:  "stream request failed",
					Reason:   tt.reason,
					Code:     int32(tt.code),
				})
			}))
			defer ts.Close()
			wire, err := NewWire(&rest.Config{Host: ts.URL})
			if err != nil {
				t.Fatal(err)
			}
			_, err = wire.Send(context.Background(), "team", "chat-x", []byte("note"), false, true, 0)
			if err == nil {
				t.Fatal("Send succeeded, want an error")
			}
			for _, sentinel := range []error{ErrNotRunning, ErrUnavailable, ErrPrecondition} {
				if got, want := errors.Is(err, sentinel), tt.want == sentinel; got != want {
					t.Errorf("errors.Is(%v, %v) = %v, want %v", err, sentinel, got, want)
				}
			}
			if tt.want == nil {
				var status apierrors.APIStatus
				if !errors.As(err, &status) || status.Status().Code != int32(tt.code) {
					t.Errorf("unmapped error = %v, want API status %d", err, tt.code)
				}
			}
		})
	}
}

func TestRestWireLogEndConflict(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q, want GET", r.Method)
		}
		if r.URL.Path != "/apis/stream.blip.dev/v1alpha1/namespaces/team/blipstreams/chat-x/log" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if follow := r.URL.Query().Get("follow"); follow != "false" {
			t.Errorf("follow = %q, want false", follow)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(metav1.Status{
			TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"},
			Status:   metav1.StatusFailure,
			Message:  "blip is not running",
			Reason:   metav1.StatusReasonConflict,
			Code:     http.StatusConflict,
		})
	}))
	defer ts.Close()
	wire, err := NewWire(&rest.Config{Host: ts.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wire.LogEnd(context.Background(), "team", "chat-x"); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("LogEnd error = %v, want ErrNotRunning", err)
	}
}

func TestWireError(t *testing.T) {
	if err := wireError(nil); err != nil {
		t.Errorf("wireError(nil) = %v", err)
	}
	ordinary := errors.New("connection failed")
	if err := wireError(ordinary); err != ordinary {
		t.Errorf("wireError(ordinary) = %v, want original error", err)
	}
	wrapped := fmt.Errorf("request failed: %w", &apierrors.StatusError{ErrStatus: metav1.Status{
		Code: http.StatusConflict,
	}})
	if err := wireError(wrapped); !errors.Is(err, ErrNotRunning) {
		t.Errorf("wireError(wrapped status) = %v, want ErrNotRunning", err)
	}
}
