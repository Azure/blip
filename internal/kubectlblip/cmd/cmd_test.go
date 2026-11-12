package cmd

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/example/blip/internal/api"
	"github.com/example/blip/internal/api/v1alpha1"
)

func TestWriteTable(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	dl := metav1.NewTime(now.Add(30 * time.Minute))
	items := []v1alpha1.Blip{{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "dev", CreationTimestamp: metav1.NewTime(now.Add(-2 * time.Hour)),
			Annotations: map[string]string{api.AnnotationSessionOwner: "alice"}},
		Status: v1alpha1.BlipStatus{Phase: v1alpha1.BlipRunning, Deadline: &dl},
	}, {ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "new", CreationTimestamp: metav1.NewTime(now)}}}
	var b bytes.Buffer
	writeTable(&b, items, true, now)
	got := b.String()
	for _, s := range []string{"NAMESPACE   NAME   PHASE", "ns          dev    Running   120m   in 30m     alice", "new    Pending", "<none>", "<unknown>"} {
		if !strings.Contains(got, s) {
			t.Errorf("missing %q in\n%s", s, got)
		}
	}
}

func TestRelay(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 5)
		_, _ = c.Read(buf)
		_, _ = c.Write(append([]byte("echo:"), buf...))
		c.Close()
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := relay(context.Background(), conn, strings.NewReader("hello"), &out, nil); err != nil {
		t.Fatal(err)
	}
	if out.String() != "echo:hello" {
		t.Fatal(out.String())
	}
}

func TestCommands(t *testing.T) {
	var out, errb bytes.Buffer
	root := NewRoot(strings.NewReader(""), &out, &errb)
	root.SetArgs([]string{"version"})
	if err := root.Execute(); err != nil || !strings.HasPrefix(out.String(), "kubectl-blip ") {
		t.Fatal(out.String(), err)
	}
	for _, args := range [][]string{{"shell"}, {"shell", "Bad_Name"}, {"proxy", "blip-UP"}, {"delete"}, {"shell", "a", "b", "--", "c"}} {
		root := NewRoot(strings.NewReader(""), &out, &errb)
		root.SetArgs(args)
		if err := root.Execute(); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
	t.Setenv("BLIP_HOME", t.TempDir())
	out.Reset()
	root = NewRoot(strings.NewReader(""), &out, &errb)
	root.SetArgs([]string{"ssh-config", "--context", "kind-blip"})
	if err := root.Execute(); err != nil || !strings.Contains(out.String(), "ProxyCommand kubectl blip proxy --context kind-blip %n") {
		t.Fatal(out.String(), err)
	}
}
