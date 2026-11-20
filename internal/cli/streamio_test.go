// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"

	"github.com/Azure/blip/api/v1alpha1"
)

func testStreamClient(t *testing.T, h http.HandlerFunc) *streamClient {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	rc, err := rest.UnversionedRESTClientFor(&rest.Config{
		Host:                 srv.URL,
		NegotiatedSerializer: clientgoscheme.Codecs.WithoutConversion(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &streamClient{rest: rc}
}

func TestStreamClientLogRequest(t *testing.T) {
	var gotPath, gotQuery string
	sc := testStreamClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
		fmt.Fprint(w, `{"o":1,"g":2,"t":1,"d":"aGVsbG8K"}`+"\n")
		fmt.Fprint(w, `{"o":9,"g":2,"t":"err","d":"b29wcwo="}`+"\n")
	})
	rc, err := sc.Log(context.Background(), "ns", "root", 42, true)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	var out []string
	if err := decodeStream(rc, func(rec streamRecord) error {
		out = append(out, fmt.Sprintf("%d/%d/%d/%s", rec.Offset, rec.Gen, rec.Type, rec.Data))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/apis/stream.blip.dev/v1alpha1/namespaces/ns/blipstreams/root/log" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotQuery != "follow=true&offset=42" {
		t.Fatalf("query = %q", gotQuery)
	}
	if strings.Join(out, ",") != "1/2/1/hello\n,9/2/2/oops\n" {
		t.Fatalf("records = %q", out)
	}
}

func TestStreamClientStdinRequest(t *testing.T) {
	var gotPath, gotQuery, gotBody, gotMethod string
	sc := testStreamClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery, gotMethod = r.URL.Path, r.URL.RawQuery, r.Method
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		fmt.Fprint(w, `{}`)
	})
	if err := sc.Stdin(context.Background(), "ns", "root", []byte("raw\n"), true); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPost || gotPath != "/apis/stream.blip.dev/v1alpha1/namespaces/ns/blipstreams/root/stdin" {
		t.Fatalf("request = %s %s", gotMethod, gotPath)
	}
	if gotQuery != "eof=true" || gotBody != "raw\n" {
		t.Fatalf("query = %q body = %q", gotQuery, gotBody)
	}
}

func TestLogsResolvesBlipAndPrintsStreams(t *testing.T) {
	h := newHarness(t, runningBlip("agent"), readyState("agent-root"))
	h.stream.record("agent-root",
		streamRecord{Offset: 1, Type: streamKind(4), Data: streamBytes("go")},
		streamRecord{Offset: 2, Type: streamKind(1), Data: streamBytes("hello\n")},
		streamRecord{Offset: 3, Type: streamKind(2), Data: streamBytes("oops\n")},
		streamRecord{Offset: 4, Type: streamKind(3), Data: streamBytes("in\n")},
		streamRecord{Offset: 5, Type: streamKind(5), Data: streamBytes("done")},
	)
	code, out, errOut := h.run("", "logs", "agent")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if out != "hello\n" {
		t.Fatalf("stdout = %q", out)
	}
	mustContain(t, errOut, "oops\n", "> in\n", "start", "end")
}

func TestLogsRawAndOffset(t *testing.T) {
	h := newHarness(t, runningBlip("agent"), readyState("agent-root"))
	h.stream.record("agent-root",
		streamRecord{Offset: 7, Type: streamKind(1), Data: streamBytes("out\n")},
		streamRecord{Offset: 8, Type: streamKind(2), Data: streamBytes("err\n")},
	)
	code, out, errOut := h.run("", "logs", "agent", "--offset", "7", "--raw")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if out != "out\n" || errOut != "" {
		t.Fatalf("out %q err %q", out, errOut)
	}
	logs, _ := h.stream.calls()
	if len(logs) != 1 || logs[0].offset != 7 || logs[0].state != "agent-root" {
		t.Fatalf("calls = %+v", logs)
	}
}

func TestLogsStateTarget(t *testing.T) {
	h := newHarness(t, readyState("data"))
	h.stream.record("data", streamRecord{Offset: 1, Type: streamKind(1), Data: streamBytes("x")})
	code, out, errOut := h.run("", "logs", "--state", "data", "--raw")
	if code != 0 || out != "x" {
		t.Fatalf("code %d out %q err %q", code, out, errOut)
	}
}

func TestSendTextPipeAndEOF(t *testing.T) {
	h := newHarness(t, runningBlip("agent"), readyState("agent-root"))
	if code, _, errOut := h.run("", "send", "agent", "--text", "hello", "--eof"); code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if code, _, errOut := h.run("pipe\n", "send", "agent", "-"); code != 0 {
		t.Fatalf("pipe code %d: %s", code, errOut)
	}
	if code, _, errOut := h.run("", "send", "agent", "--eof"); code != 0 {
		t.Fatalf("eof code %d: %s", code, errOut)
	}
	_, stdins := h.stream.calls()
	if len(stdins) != 3 {
		t.Fatalf("stdins = %+v", stdins)
	}
	if string(stdins[0].data) != "hello" || !stdins[0].eof ||
		string(stdins[1].data) != "pipe\n" || stdins[1].eof || !stdins[2].eof {
		t.Fatalf("stdins = %+v", stdins)
	}
}

func TestSendConflictIsNotRunning(t *testing.T) {
	h := newHarness(t, runningBlip("agent"), readyState("agent-root"))
	h.stream.stdinErr = apierrors.NewConflict(v1alpha1.GroupVersion.WithResource("blipstreams").GroupResource(), "agent-root", nil)
	code, _, errOut := h.run("", "send", "agent", "--text", "x")
	if code != 1 || !strings.Contains(errOut, "not running") {
		t.Fatalf("code %d err %q", code, errOut)
	}
}

func TestRunInteractiveSkipsEOF(t *testing.T) {
	h := newHarness(t, readyState("base"))
	code, out, errOut := h.run("", "run", "--name", "job", "--from", "base", "--interactive", "--", "cat")
	if code != 0 || out != "job\n" {
		t.Fatalf("code %d out %q err %q", code, out, errOut)
	}
	if _, stdins := h.stream.calls(); len(stdins) != 0 {
		t.Fatalf("run closed interactive stdin: %+v", stdins)
	}
}

func TestStopStateStopsNewestBlip(t *testing.T) {
	old := runningBlip("old")
	old.Spec.State = "ws"
	old.CreationTimestamp = metav1.NewTime(time.Now().Add(-time.Hour))
	newer := runningBlip("new")
	newer.Spec.State = "ws"
	newer.CreationTimestamp = metav1.NewTime(time.Now())
	h := newHarness(t, old, newer, readyState("ws"))
	code, out, errOut := h.run("", "stop", "ws")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "blip/new stopped")
	if !h.blip("new").Spec.Stop {
		t.Fatal("newest blip not stopped")
	}
	if h.blip("old").Spec.Stop {
		t.Fatal("older blip stopped")
	}
}

func TestStopAllByState(t *testing.T) {
	first := runningBlip("a")
	first.Spec.State = "ws"
	second := runningBlip("b")
	second.Spec.State = "ws"
	h := newHarness(t, first, second, readyState("ws"))
	if code, _, errOut := h.run("", "stop", "--all", "ws"); code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if !h.blip("a").Spec.Stop || !h.blip("b").Spec.Stop {
		t.Fatal("--all did not stop every running blip")
	}
}

func TestGatherFollowReadsRetainedTrajectory(t *testing.T) {
	b := finishedBlip("w1", v1alpha1.BlipSucceeded, 0)
	h := newHarness(t, b, readyState("w1-root"))
	h.stream.record("w1-root",
		streamRecord{Offset: 1, Type: streamKind(4)},
		streamRecord{Offset: 2, Type: streamKind(1), Data: streamBytes("fast-out\n")},
		streamRecord{Offset: 3, Type: streamKind(2), Data: streamBytes("fast-err\n")},
		streamRecord{Offset: 4, Type: streamKind(5)},
	)
	code, out, errOut := h.run("", "gather", "w1", "--follow")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "fast-out\n")
	mustContain(t, errOut, "fast-err\n", "w1: start", "w1: end")
	if !h.gone("w1") {
		t.Fatal("gathered blip was kept")
	}
}

func TestRetryableStreamErrorCoversStartup(t *testing.T) {
	for _, msg := range []string{
		"peer: unknown node \"\"",
		`peer: blip-dev-worker /v1/stream/log: 404 Not Found: stream: state has no trajectory`,
		"stream: guest stdio is not connected",
	} {
		if !retryableStreamError(errors.New(msg)) {
			t.Errorf("retryableStreamError(%q) = false, want true", msg)
		}
	}
	if retryableStreamError(errors.New("blipstreams.stream.blip.dev is forbidden")) {
		t.Fatal("an authorization error must be terminal")
	}
}
