package slot

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeVsock is a Cloud Hypervisor hybrid vsock socket with a guest vsock
// listener on port allowed that echoes upper-cased data.
func fakeVsock(t *testing.T, sock string, allowed uint32) {
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				l, _ := readLine(c)
				if l != fmt.Sprintf("CONNECT %d", allowed) {
					return // no guest listener: closed without a reply
				}
				fmt.Fprint(c, "OK 1234\n")
				b, _ := io.ReadAll(c)
				c.Write([]byte(strings.ToUpper(string(b))))
				c.(*net.UnixConn).CloseWrite()
			}()
		}
	}()
}

func freePort(t *testing.T) uint32 {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return uint32(l.Addr().(*net.TCPAddr).Port)
}

func TestForwardPorts(t *testing.T) {
	dir := t.TempDir()
	p1, p2 := freePort(t), freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { forwardPorts(ctx, dir, 10*time.Millisecond); close(done) }()
	// The assignment arrives after blipd slot started; the VM comes later.
	time.Sleep(30 * time.Millisecond)
	b, _ := json.Marshal(Assignment{AllocationID: "a", Ports: []uint32{p1, p2}})
	if err := os.WriteFile(filepath.Join(dir, FileAssignment), b, 0o644); err != nil {
		t.Fatal(err)
	}
	var c net.Conn
	var err error
	for i := 0; i < 100; i++ {
		if c, err = net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", p1)); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	// No VM yet: the connection is closed after a short retry.
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if n, _ := c.Read(make([]byte, 1)); n != 0 {
		t.Fatal("data without a guest")
	}
	c.Close()

	fakeVsock(t, filepath.Join(dir, FileVsock), p1)
	c, err = net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", p1))
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte("hello"))
	c.(*net.TCPConn).CloseWrite() // half-close: the guest still answers
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "HELLO" {
		t.Fatalf("got %q %v", got, err)
	}
	c.Close()

	// A port the guest does not listen on.
	c, err = net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", p2))
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if got, _ := io.ReadAll(c); len(got) != 0 {
		t.Fatalf("refused port got %q", got)
	}
	c.Close()

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("forwarder did not stop")
	}
	if _, err := net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", p1)); err == nil {
		t.Fatal("listener still open")
	}
}
