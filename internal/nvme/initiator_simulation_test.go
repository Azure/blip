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
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/sys/unix"
)

// fakeController is one controller in the fake sysfs tree.
type fakeController struct {
	name      string
	transport string
	address   string
	subsystem string // native-multipath subsystem, "" when the controller has none
}

// fakeGID is one GID of an InfiniBand port.
type fakeGID struct {
	name  string
	value string // colon-separated form used by sysfs
	typ   string // gid_attrs/types value
}

// fakeIBPort is one port of an InfiniBand device.
type fakeIBPort struct {
	path  string
	state string
	gids  []fakeGID
}

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
	onNamespace func() error

	// nvme7 is TCP at 192.0.2.5 unless a test says otherwise.
	baseTransport string
	baseAddr      string

	// controllers holds additional controllers, and deleteCalls records the
	// controllers removed through delete_controller.
	controllers []fakeController
	deleteCalls []string

	// instance is the controller instance the fabrics read returns.
	instance int
	// joinSubsystem overrides the subsystem new controllers join; empty uses
	// nvme-subsys7 when multipath is on.
	joinSubsystem string
	// onWrite runs before a fabrics write is accepted, letting a test model a
	// controller that appeared after the initiator discovered the subsystem.
	onWrite func(*fabricSystem)

	multipathParam string // exact /sys/module/nvme_core/parameters/multipath
	rdmaModule     bool
	ibPorts        []fakeIBPort
}

func (s *fabricSystem) baseTransportName() string {
	if s.baseTransport != "" {
		return s.baseTransport
	}
	return "tcp"
}

func (s *fabricSystem) baseAddrName() string {
	if s.baseAddr != "" {
		return s.baseAddr
	}
	return "192.0.2.5"
}

func (s *fabricSystem) instanceNumber() int {
	if s.instance == 0 {
		return 7
	}
	return s.instance
}

func (s *fabricSystem) instanceName() string {
	return "nvme" + strconv.Itoa(s.instanceNumber())
}

// controllersNow lists the controller tree, with nvme7 synthesized from the
// connected flag and subsystem layout.
func (s *fabricSystem) controllersNow() []fakeController {
	var out []fakeController
	if s.connected {
		sub := ""
		if s.multipath {
			sub = "nvme-subsys7"
		}
		out = append(out, fakeController{"nvme7", s.baseTransportName(), s.baseAddrName(), sub})
	}
	return append(out, s.controllers...)
}

func (s *fabricSystem) controller(name string) (fakeController, bool) {
	for _, c := range s.controllersNow() {
		if c.name == name {
			return c, true
		}
	}
	return fakeController{}, false
}

func (s *fabricSystem) ReadFile(p string) ([]byte, error) {
	switch p {
	case "/sys/class/misc/nvme-fabrics/dev":
		return []byte("10:241\n"), nil
	case "/sys/module/nvme_core/parameters/multipath":
		if s.multipathParam == "" {
			return nil, os.ErrNotExist
		}
		return []byte(s.multipathParam), nil
	case "/sys/class/block/nvme7n1/size":
		if time.Now().Before(s.readyAt) {
			return []byte("0\n"), nil
		}
		return []byte("8\n"), nil
	case "/sys/class/block/nvme7n1/dev":
		return []byte("259:7\n"), nil
	}
	for _, c := range s.controllersNow() {
		dir := "/sys/class/nvme/" + c.name
		switch p {
		case dir + "/subsysnqn":
			return []byte(s.nqn + "\n"), nil
		case dir + "/transport":
			return []byte(c.transport + "\n"), nil
		case dir + "/address":
			return []byte(c.address + "\n"), nil
		}
	}
	for _, port := range s.ibPorts {
		if p == port.path+"/state" {
			return []byte(port.state + "\n"), nil
		}
		if name, ok := strings.CutPrefix(p, port.path+"/gids/"); ok {
			for _, g := range port.gids {
				if name == g.name {
					return []byte(g.value + "\n"), nil
				}
			}
		}
		for _, g := range port.gids {
			if p == port.path+"/gid_attrs/types/"+g.name {
				return []byte(g.typ + "\n"), nil
			}
		}
	}
	return nil, os.ErrNotExist
}

func (s *fabricSystem) ReadDir(p string) ([]os.DirEntry, error) {
	if p == "/sys/module/nvme_rdma" || p == "/sys/module/nvmet_rdma" {
		if s.rdmaModule {
			return nil, nil
		}
		return nil, os.ErrNotExist
	}
	for _, c := range s.controllersNow() {
		if c.name != "nvme7" {
			continue
		}
		dir := "/sys/class/nvme/nvme7"
		if c.subsystem != "" {
			dir = "/sys/class/nvme-subsystem/" + c.subsystem
		}
		if p == dir {
			return []os.DirEntry{namespaceEntry{}}, nil
		}
	}
	return nil, os.ErrNotExist
}

type namespaceEntry struct{}

func (namespaceEntry) Name() string               { return "nvme7n1" }
func (namespaceEntry) IsDir() bool                { return true }
func (namespaceEntry) Type() fs.FileMode          { return fs.ModeDir }
func (namespaceEntry) Info() (fs.FileInfo, error) { return nil, errors.New("unused") }

func (s *fabricSystem) Glob(pattern string) ([]string, error) {
	switch pattern {
	case "/sys/class/nvme/nvme*":
		var out []string
		for _, c := range s.controllersNow() {
			out = append(out, "/sys/class/nvme/"+c.name)
		}
		return out, nil
	case "/sys/class/infiniband/*/ports/*":
		var out []string
		for _, port := range s.ibPorts {
			out = append(out, port.path)
		}
		return out, nil
	}
	if ctrl, ok := strings.CutPrefix(pattern, "/sys/class/nvme-subsystem/*/"); ok {
		var out []string
		for _, c := range s.controllersNow() {
			if c.name == ctrl && c.subsystem != "" {
				out = append(out, "/sys/class/nvme-subsystem/"+c.subsystem+"/"+ctrl)
			}
		}
		return out, nil
	}
	for _, port := range s.ibPorts {
		if pattern == port.path+"/gids/*" {
			var out []string
			for _, g := range port.gids {
				out = append(out, port.path+"/gids/"+g.name)
			}
			return out, nil
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
		// The callback runs after the namespace appears; returning its error
		// models setup interrupted before the device became usable.
		if err := s.onNamespace(); err != nil {
			return err
		}
	}
	return nil
}
func (s *fabricSystem) WriteFile(p string, data []byte, _ os.FileMode) error {
	name, ok := strings.CutPrefix(p, "/sys/class/nvme/")
	name, ok2 := strings.CutSuffix(name, "/delete_controller")
	if !ok || !ok2 || string(data) != "1" {
		return errors.New("wrong controller delete")
	}
	if name == "nvme7" && s.connected {
		s.deletes++
		s.deleteCalls = append(s.deleteCalls, name)
		s.connected = false
		return nil
	}
	for i, c := range s.controllers {
		if c.name == name {
			s.controllers = append(s.controllers[:i], s.controllers[i+1:]...)
			s.deletes++
			s.deleteCalls = append(s.deleteCalls, name)
			return nil
		}
	}
	return os.ErrNotExist
}

type fabricFile struct{ s *fabricSystem }

func (f *fabricFile) Close() error { return nil }
func (f *fabricFile) Write(b []byte) (int, error) {
	f.s.opts = string(b)
	if f.s.fault == "write-before" {
		return 0, errors.New("write failed")
	}
	if f.s.onWrite != nil {
		f.s.onWrite(f.s)
	}
	f.s.accept(string(b))
	if f.s.fault == "write-after" {
		return 0, errors.New("write result lost")
	}
	if f.s.fault == "short-write" {
		return len(b) - 1, nil
	}
	return len(b), nil
}

// accept adds the controller the kernel would create for a fabrics write.
func (s *fabricSystem) accept(opts string) {
	fields := make(map[string]string)
	for _, kv := range strings.Split(opts, ",") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			fields[k] = v
		}
	}
	c := fakeController{name: s.instanceName(), transport: fields["transport"], address: fields["traddr"]}
	if c.name == "nvme7" {
		s.connected = true
		s.baseTransport = c.transport
		s.baseAddr = c.address
		return
	}
	if s.joinSubsystem != "" {
		c.subsystem = s.joinSubsystem
	} else if s.multipath {
		c.subsystem = "nvme-subsys7"
	}
	s.controllers = append(s.controllers, c)
}

func (f *fabricFile) Read(b []byte) (int, error) {
	if f.s.fault == "read" {
		return 0, io.ErrUnexpectedEOF
	}
	if f.s.fault == "malformed-result" {
		return copy(b, "instance=../bad"), nil
	}
	return copy(b, "instance="+strconv.Itoa(f.s.instanceNumber())+",cntlid=1\n"), nil
}

func TestInitiatorSimulationNamespaceDiscovery(t *testing.T) {
	for _, multipath := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			start := time.Now()
			s := &fabricSystem{nqn: SubsystemNQN("exporter", "lease1"), readyAt: start.Add(350 * time.Millisecond), multipath: multipath}
			i := NewInitiator(InitiatorOptions{System: s})
			key := bytes.Repeat([]byte{7}, 64)
			host := "nqn.2014-08.dev.blip:host:reader"
			dev, err := i.Connect(t.Context(), Endpoint{TCP, "192.0.2.5", 4420}, s.nqn, host, key)
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
			if again, err := i.Connect(t.Context(), Endpoint{TCP, "192.0.2.5", 4420}, s.nqn, host, key); err != nil || again != dev || s.opts != "" {
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
			dev, err := i.Connect(t.Context(), Endpoint{TCP, "192.0.2.5", 4420}, s.nqn, "host", bytes.Repeat([]byte{7}, 64))
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
					s.onNamespace = func() error {
						cancel()
						return context.Canceled
					}
				}
				i := NewInitiator(InitiatorOptions{System: s})
				start := time.Now()
				dev, err := i.Connect(ctx, Endpoint{TCP, "192.0.2.5", 4420}, s.nqn, "host", bytes.Repeat([]byte{7}, 64))
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
