package main

import (
	"bytes"
	"testing"
)

func TestClosedStreamLog(t *testing.T) {
	cases := []struct {
		line string
		keep bool
	}{
		{`E1117 v2.go:167] "Unhandled Error" err="next reader: read tcp 1.2.3.4:443: use of closed network connection"`, false},
		{`E1117 websocket.go:500] Websocket Ping failed: use of closed network connection`, false},
		{`E1117 v2.go:167] "Unhandled Error" err="next reader: read tcp 1.2.3.4:443: connection reset by peer"`, true},
		{`I1117 server.go:100] connected`, true},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		w := closedStreamLog{&buf}
		n, err := w.Write([]byte(c.line + "\n"))
		if err != nil || n != len(c.line)+1 {
			t.Fatalf("Write(%q) = %d, %v", c.line, n, err)
		}
		got := buf.Len() > 0
		if got != c.keep {
			t.Errorf("keep(%q) = %v, want %v", c.line, got, c.keep)
		}
	}
}
