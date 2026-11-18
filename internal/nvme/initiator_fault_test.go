package nvme

import (
	"bytes"
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

type faultSystem struct {
	InitiatorSystem
	readFile  func(string) ([]byte, error)
	glob      func(string) ([]string, error)
	writeFile func(string, []byte, os.FileMode) error
}

func (s faultSystem) ReadFile(p string) ([]byte, error) {
	if s.readFile != nil {
		return s.readFile(p)
	}
	return s.InitiatorSystem.ReadFile(p)
}
func (s faultSystem) Glob(p string) ([]string, error) {
	if s.glob != nil {
		return s.glob(p)
	}
	return s.InitiatorSystem.Glob(p)
}
func (s faultSystem) WriteFile(p string, b []byte, mode os.FileMode) error {
	if s.writeFile != nil {
		return s.writeFile(p, b, mode)
	}
	return s.InitiatorSystem.WriteFile(p, b, mode)
}

func TestNamespaceRequiresReadablePositiveSize(t *testing.T) {
	for _, value := range []string{"missing", "", "not-a-size", "-1", "000"} {
		t.Run(value, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				start := time.Now()
				base := &fabricSystem{nqn: SubsystemNQN("exporter", "lease1"), readyAt: start.Add(350 * time.Millisecond)}
				sys := faultSystem{InitiatorSystem: base, readFile: func(p string) ([]byte, error) {
					if strings.HasSuffix(p, "/size") && time.Now().Before(base.readyAt) {
						if value == "missing" {
							return nil, os.ErrNotExist
						}
						return []byte(value), nil
					}
					return base.ReadFile(p)
				}}
				i := NewInitiator(InitiatorOptions{System: sys})
				dev, err := i.Connect(t.Context(), "192.0.2.5", 4420, base.nqn, "host", bytes.Repeat([]byte{7}, 64))
				if err != nil || dev != "/dev/nvme7n1" || time.Since(start) != 400*time.Millisecond {
					t.Fatalf("namespace accepted before size became readable: device=%q err=%v elapsed=%s", dev, err, time.Since(start))
				}
				if err := i.Disconnect(base.nqn); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

func TestCancellationReportsFailedControllerCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	base := &fabricSystem{nqn: SubsystemNQN("exporter", "lease1"), onNamespace: cancel}
	busy := errors.New("controller busy")
	sys := faultSystem{InitiatorSystem: base, writeFile: func(string, []byte, os.FileMode) error { return busy }}
	i := NewInitiator(InitiatorOptions{System: sys})
	dev, err := i.Connect(ctx, "192.0.2.5", 4420, base.nqn, "host", bytes.Repeat([]byte{7}, 64))
	if dev != "" || !errors.Is(err, context.Canceled) || !errors.Is(err, busy) {
		t.Fatalf("cleanup failure hidden behind cancellation: device=%q err=%v", dev, err)
	}
	if !base.connected {
		t.Fatal("fault did not leave a controller for retry")
	}
	if err := NewInitiator(InitiatorOptions{System: base}).Disconnect(base.nqn); err != nil {
		t.Fatal(err)
	}
}

func TestControllerDiscoveryFailureIsNotAbsence(t *testing.T) {
	for _, stage := range []string{"glob", "identify"} {
		t.Run(stage, func(t *testing.T) {
			base := &fabricSystem{nqn: SubsystemNQN("exporter", "lease1"), connected: true}
			failure := errors.New("sysfs unreadable")
			sys := faultSystem{InitiatorSystem: base}
			if stage == "glob" {
				sys.glob = func(string) ([]string, error) { return nil, failure }
			} else {
				sys.readFile = func(p string) ([]byte, error) {
					if strings.HasSuffix(p, "/subsysnqn") {
						return nil, failure
					}
					return base.ReadFile(p)
				}
			}
			i := NewInitiator(InitiatorOptions{System: sys})
			if err := i.Disconnect(base.nqn); !errors.Is(err, failure) {
				t.Fatalf("disconnect reported absence on discovery failure: %v", err)
			}
			if _, err := i.Connect(t.Context(), "192.0.2.5", 4420, base.nqn, "host", bytes.Repeat([]byte{7}, 64)); !errors.Is(err, failure) {
				t.Fatalf("connect ignored failed discovery: %v", err)
			}
			if base.opts != "" || base.deletes != 0 {
				t.Fatal("failed discovery changed controller state")
			}
		})
	}
}

func TestDisconnectAttemptsEveryController(t *testing.T) {
	base := &fabricSystem{nqn: SubsystemNQN("exporter", "lease1"), connected: true}
	busy := errors.New("first controller busy")
	var deleted []string
	sys := faultSystem{InitiatorSystem: base,
		glob: func(string) ([]string, error) {
			return []string{"/sys/class/nvme/nvme6", "/sys/class/nvme/nvme7"}, nil
		},
		readFile: func(string) ([]byte, error) { return []byte(base.nqn), nil },
		writeFile: func(p string, b []byte, mode os.FileMode) error {
			deleted = append(deleted, p)
			if strings.Contains(p, "/nvme6/") {
				return busy
			}
			return base.WriteFile(p, b, mode)
		},
	}
	i := NewInitiator(InitiatorOptions{System: sys})
	if err := i.Disconnect(base.nqn); !errors.Is(err, busy) {
		t.Fatalf("disconnect lost deletion error: %v", err)
	}
	if want := []string{"/sys/class/nvme/nvme6/delete_controller", "/sys/class/nvme/nvme7/delete_controller"}; !slices.Equal(deleted, want) || base.connected {
		t.Fatalf("one failure prevented other controllers' cleanup: %v", deleted)
	}
}
