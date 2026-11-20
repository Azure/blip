// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package nvme

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/sys/unix"
)

// fabricSystem models acceptance of the fabrics write separately from reading
// its result and namespace readiness. None of the initiator's connect/discovery
// helpers are replaced, so ambiguity and cancellation exercise real cleanup.
type fabricSystem struct {
	nqn         string
	connected   bool
	readyAt     time.Time
	multipath   bool
	fault       string
	opts        string
	deletes     int
	nodes       []string
	onNamespace func()
}

func (s *fabricSystem) ReadFile(p string) ([]byte, error) {
	switch p {
	case "/sys/class/misc/nvme-fabrics/dev":
		return []byte("10:241\n"), nil
	case "/sys/class/nvme/nvme7/subsysnqn":
		if s.connected {
			return []byte(s.nqn + "\n"), nil
		}
	case "/sys/class/block/nvme7n1/size":
		if time.Now().Before(s.readyAt) {
			return []byte("0\n"), nil
		}
		return []byte("8\n"), nil
	case "/sys/class/block/nvme7n1/dev":
		return []byte("259:7\n"), nil
	}
	return nil, os.ErrNotExist
}

func (s *fabricSystem) ReadDir(p string) ([]os.DirEntry, error) {
	dir := "/sys/class/nvme/nvme7"
	if s.multipath {
		dir = "/sys/class/nvme-subsystem/nvme-subsys7"
	}
	if s.connected && p == dir {
		return []os.DirEntry{namespaceEntry{}}, nil
	}
	return nil, os.ErrNotExist
}

type namespaceEntry struct{}

func (namespaceEntry) Name() string               { return "nvme7n1" }
func (namespaceEntry) IsDir() bool                { return true }
func (namespaceEntry) Type() fs.FileMode          { return fs.ModeDir }
func (namespaceEntry) Info() (fs.FileInfo, error) { return nil, errors.New("unused") }

func (s *fabricSystem) Glob(pattern string) ([]string, error) {
	if !s.connected {
		return nil, nil
	}
	switch pattern {
	case "/sys/class/nvme/nvme*":
		return []string{"/sys/class/nvme/nvme7"}, nil
	case "/sys/class/nvme-subsystem/*/nvme7":
		if s.multipath {
			return []string{"/sys/class/nvme-subsystem/nvme-subsys7/nvme7"}, nil
		}
	}
	return nil, nil
}
func (s *fabricSystem) OpenFabrics() (io.ReadWriteCloser, error) { return &fabricFile{s}, nil }
func (s *fabricSystem) EnsureNode(p, devnum string, mode uint32) error {
	if mode == unix.S_IFBLK && (p != "/dev/nvme7n1" || devnum != "259:7") {
		return errors.New("wrong block node")
	}
	s.nodes = append(s.nodes, p)
	if mode == unix.S_IFBLK && s.onNamespace != nil {
		s.onNamespace()
	}
	return nil
}
func (s *fabricSystem) WriteFile(p string, data []byte, _ os.FileMode) error {
	if p != "/sys/class/nvme/nvme7/delete_controller" || string(data) != "1" {
		return errors.New("wrong controller delete")
	}
	s.deletes++
	s.connected = false
	return nil
}

type fabricFile struct{ s *fabricSystem }

func (f *fabricFile) Close() error { return nil }
func (f *fabricFile) Write(b []byte) (int, error) {
	f.s.opts = string(b)
	if f.s.fault == "write-before" {
		return 0, errors.New("write failed")
	}
	f.s.connected = true
	if f.s.fault == "write-after" {
		return 0, errors.New("write result lost")
	}
	if f.s.fault == "short-write" {
		return len(b) - 1, nil
	}
	return len(b), nil
}
func (f *fabricFile) Read(b []byte) (int, error) {
	if f.s.fault == "read" {
		return 0, io.ErrUnexpectedEOF
	}
	if f.s.fault == "malformed-result" {
		return copy(b, "instance=../bad"), nil
	}
	return copy(b, "instance=7,cntlid=1\n"), nil
}

func TestInitiatorSimulationNamespaceDiscovery(t *testing.T) {
	for _, multipath := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			start := time.Now()
			s := &fabricSystem{nqn: SubsystemNQN("exporter", "lease1"), readyAt: start.Add(350 * time.Millisecond), multipath: multipath}
			i := NewInitiator(InitiatorOptions{System: s})
			key := bytes.Repeat([]byte{7}, 64)
			host := "nqn.2014-08.dev.blip:host:reader"
			dev, err := i.Connect(t.Context(), "192.0.2.5", 4420, s.nqn, host, key)
			if err != nil || dev != "/dev/nvme7n1" {
				t.Fatalf("connect=%q, %v", dev, err)
			}
			if time.Since(start) != 400*time.Millisecond {
				t.Fatal("namespace did not wait for readiness")
			}
			hostKey, ctrlKey := secrets(key, host)
			for _, part := range []string{"transport=tcp", "traddr=192.0.2.5", "trsvcid=4420", "nqn=" + s.nqn, "hostnqn=" + host, "hostid=" + HostID(host), "ctrl_loss_tmo=60", "dhchap_secret=" + hostKey, "dhchap_ctrl_secret=" + ctrlKey} {
				if !strings.Contains(s.opts, part) {
					t.Fatalf("missing fabrics option %s", strings.SplitN(part, "=", 2)[0])
				}
			}
			s.opts = ""
			if again, err := i.Connect(t.Context(), "192.0.2.5", 4420, s.nqn, host, key); err != nil || again != dev || s.opts != "" {
				t.Fatal("existing controller was not reused")
			}
			if err := i.Disconnect(s.nqn); err != nil {
				t.Fatal(err)
			}
			if err := i.Disconnect(s.nqn); err != nil || s.deletes != 1 {
				t.Fatal("disconnect is not idempotent")
			}
		})
	}
}

func TestInitiatorSimulationAmbiguousConnectCleanup(t *testing.T) {
	for _, fault := range []string{"write-before", "write-after", "short-write", "read", "malformed-result"} {
		t.Run(fault, func(t *testing.T) {
			s := &fabricSystem{nqn: SubsystemNQN("exporter", "lease1"), fault: fault}
			i := NewInitiator(InitiatorOptions{System: s})
			dev, err := i.Connect(t.Context(), "192.0.2.5", 4420, s.nqn, "host", bytes.Repeat([]byte{7}, 64))
			if err == nil || dev != "" || s.connected {
				t.Fatalf("ambiguous connect leaked a device: %q %v connected=%v", dev, err, s.connected)
			}
			if strings.Contains(err.Error(), "DHHC-") {
				t.Fatal("connect error leaked authentication secrets")
			}
			if fault != "write-before" && s.deletes != 1 {
				t.Fatal("accepted connect was not discovered and cleaned up")
			}
		})
	}
}

func TestInitiatorSimulationNamespaceTimeoutAndCancellation(t *testing.T) {
	for _, mode := range []string{"timeout", "already-canceled", "canceled-ready-namespace"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				s := &fabricSystem{nqn: SubsystemNQN("exporter", "lease1")}
				want := context.Canceled
				switch mode {
				case "timeout":
					s.readyAt = time.Now().Add(time.Hour)
					want = context.DeadlineExceeded
				case "already-canceled":
					cancel()
				case "canceled-ready-namespace":
					s.onNamespace = cancel
				}
				i := NewInitiator(InitiatorOptions{System: s})
				start := time.Now()
				dev, err := i.Connect(ctx, "192.0.2.5", 4420, s.nqn, "host", bytes.Repeat([]byte{7}, 64))
				if dev != "" || !errors.Is(err, want) || s.connected {
					t.Fatalf("connect=%q %v connected=%v", dev, err, s.connected)
				}
				if mode == "already-canceled" && s.opts != "" {
					t.Fatal("canceled connect touched fabrics")
				}
				if mode == "timeout" && time.Since(start) != 30*time.Second {
					t.Fatal("incorrect namespace timeout")
				}
			})
		})
	}
}
