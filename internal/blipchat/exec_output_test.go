package blipchat

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/session"
	"github.com/Azure/blip/internal/session/fakeguest"
	"github.com/Azure/blip/internal/wire"
)

// A command may write far more than execIn returns. The writer must retain
// only the tail so a 128 MiB command cannot exhaust the coordinator's heap.
func TestTailWriterKeepsBoundedTail(t *testing.T) {
	w := newTailWriter(execTailBytes)
	chunk := bytes.Repeat([]byte("x"), 32<<10)
	const chunks = 4096 // 128 MiB
	for i := 0; i < chunks; i++ {
		if n, err := w.Write(chunk); err != nil || n != len(chunk) {
			t.Fatalf("write %d: n=%d err=%v", i, n, err)
		}
	}
	if len(w.buf) != execTailBytes {
		t.Errorf("retained %d bytes, want %d", len(w.buf), execTailBytes)
	}
	if cap(w.buf) > execTailBytes {
		t.Errorf("retained capacity %d, want at most %d", cap(w.buf), execTailBytes)
	}
	if want := int64(chunks * len(chunk)); w.total != want {
		t.Errorf("total = %d, want %d", w.total, want)
	}
	if got := w.String(); !strings.Contains(got, "output truncated") {
		t.Errorf("output does not report truncation: %q", got)
	}
}

func TestExecInKeepsBoundedOutput(t *testing.T) {
	thread := testThread()
	owner := Owner(&ThreadKey{Namespace: "ns", Name: "proj"})
	b := &v1.Blip{
		ObjectMeta: metav1.ObjectMeta{
			Name: "blip-a", Namespace: "ns",
			Labels: map[string]string{v1.LabelThread: "proj", v1.LabelOwner: owner},
		},
		Status: v1.BlipStatus{Phase: v1.BlipRunning, Pod: "pod-a"},
	}
	c := testClient(t, thread, b)
	g := &fakeguest.Guest{Run: func(s *fakeguest.Session) wire.Exit {
		s.Stdout("stdout-start\n")
		chunk := strings.Repeat("o", 32<<10)
		for sent := 0; sent < 1<<20; sent += len(chunk) {
			s.Stdout(chunk)
		}
		s.Stdout("\nstdout-end\n")
		s.Stderr("stderr-start\n")
		for sent := 0; sent < 1<<20; sent += len(chunk) {
			s.Stderr(chunk)
		}
		s.Stderr("\nstderr-end\n")
		return wire.Exit{Code: 0}
	}}
	srv := &Server{Client: c}
	srv.execClient = &session.Client{Connect: g.Connect}
	srv.execOnce.Do(func() {})

	out, err := srv.execIn(context.Background(), thread, "blip-a", []string{"yes"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) > 20<<10 {
		t.Fatalf("execIn returned %d bytes, want only the bounded tails", len(out))
	}
	if got := strings.Count(out, "output truncated"); got != 2 {
		t.Errorf("truncation notices = %d, want one for stdout and stderr: %q", got, out)
	}
	for _, want := range []string{"stdout-end", "stderr-end"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lost tail marker %q", want)
		}
	}
	for _, bad := range []string{"stdout-start", "stderr-start"} {
		if strings.Contains(out, bad) {
			t.Errorf("output retained the head marker %q", bad)
		}
	}
}
