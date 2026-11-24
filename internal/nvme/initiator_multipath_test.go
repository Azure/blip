// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package nvme

import (
	"bytes"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
)

const testHostNQN = "nqn.2014-08.dev.blip:host:reader"

func testKey() []byte { return bytes.Repeat([]byte{7}, 64) }

func TestAddPathConnectsRDMAPath(t *testing.T) {
	s := &fabricSystem{
		nqn:            SubsystemNQN("exporter", "lease1"),
		connected:      true,
		multipath:      true,
		multipathParam: "Y\n",
		instance:       8,
	}
	ep := Endpoint{RDMA, "10.0.0.4", 61001}
	i := NewInitiator(InitiatorOptions{System: s})
	if err := i.AddPath(t.Context(), ep, s.nqn, testHostNQN, testKey()); err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{"transport=rdma", "traddr=10.0.0.4", "trsvcid=61001", "nqn=" + s.nqn, "hostnqn=" + testHostNQN} {
		if !strings.Contains(s.opts, part) {
			t.Fatalf("missing fabrics option %q in %q", part, s.opts)
		}
	}
	ctrl, ok := s.controller("nvme8")
	if !ok {
		t.Fatal("RDMA path did not create a controller")
	}
	if ctrl.transport != "rdma" || ctrl.address != "10.0.0.4" {
		t.Fatalf("new controller = %+v", ctrl)
	}
	if ctrl.subsystem != "nvme-subsys7" {
		t.Fatalf("new controller joined %q, want nvme-subsys7", ctrl.subsystem)
	}
	if got, head := i.subsystemOf("nvme8"), i.subsystemOf("nvme7"); got != head || got == "" {
		t.Fatalf("nvme8 subsystem %q, head %q", got, head)
	}
}

func TestAddPathReusesExistingPath(t *testing.T) {
	s := &fabricSystem{
		nqn:            SubsystemNQN("exporter", "lease1"),
		connected:      true,
		multipath:      true,
		multipathParam: "Y\n",
		controllers:    []fakeController{{name: "nvme8", transport: "rdma", address: "10.0.0.4", subsystem: "nvme-subsys7"}},
	}
	ep := Endpoint{RDMA, "10.0.0.4", 61001}
	if err := NewInitiator(InitiatorOptions{System: s}).AddPath(t.Context(), ep, s.nqn, testHostNQN, testKey()); err != nil {
		t.Fatal(err)
	}
	if s.opts != "" {
		t.Fatalf("existing path wrote fabrics options %q", s.opts)
	}
	if s.deletes != 0 {
		t.Fatalf("existing path was deleted %d times", s.deletes)
	}
}

func TestAddPathRequiresNativeMultipath(t *testing.T) {
	s := &fabricSystem{
		nqn:            SubsystemNQN("exporter", "lease1"),
		connected:      true,
		multipathParam: "N\n",
	}
	ep := Endpoint{RDMA, "10.0.0.4", 61001}
	err := NewInitiator(InitiatorOptions{System: s}).AddPath(t.Context(), ep, s.nqn, testHostNQN, testKey())
	if err == nil || !strings.Contains(err.Error(), "multipath") {
		t.Fatalf("add path with multipath off = %v", err)
	}
	if s.opts != "" {
		t.Fatalf("multipath off still wrote fabrics options %q", s.opts)
	}
}

func TestAddPathRemovesControllerThatDoesNotJoinSubsystem(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := &fabricSystem{
			nqn:            SubsystemNQN("exporter", "lease1"),
			connected:      true,
			multipath:      true,
			multipathParam: "Y\n",
			instance:       8,
			joinSubsystem:  "nvme-subsys9",
		}
		ep := Endpoint{RDMA, "10.0.0.4", 61001}
		err := NewInitiator(InitiatorOptions{System: s}).AddPath(t.Context(), ep, s.nqn, testHostNQN, testKey())
		if err == nil || !strings.Contains(err.Error(), "did not join the subsystem") {
			t.Fatalf("add path on an isolated controller = %v", err)
		}
		if want := []string{"nvme8"}; !slices.Equal(s.deleteCalls, want) {
			t.Fatalf("deleted %v, want %v", s.deleteCalls, want)
		}
		if _, ok := s.controller("nvme7"); !ok {
			t.Fatal("head path was removed with the failed path")
		}
		if ctrl, ok := s.controller("nvme8"); ok {
			t.Fatalf("failed path left controller %+v", ctrl)
		}
	})
}

func TestConnectFailureRemovesOnlyItsController(t *testing.T) {
	s := &fabricSystem{
		nqn:      SubsystemNQN("exporter", "lease1"),
		fault:    "read",
		instance: 8,
		onWrite: func(s *fabricSystem) {
			// A concurrent Connect created a TCP head for the same NQN after
			// this attempt discovered the (then empty) subsystem.
			s.connected = true
			s.baseTransport = "tcp"
			s.baseAddr = "192.0.2.9"
		},
	}
	ep := Endpoint{TCP, "192.0.2.5", 4420}
	dev, err := NewInitiator(InitiatorOptions{System: s}).Connect(t.Context(), ep, s.nqn, testHostNQN, testKey())
	if err == nil || dev != "" {
		t.Fatalf("failed connect = %q, %v", dev, err)
	}
	if want := []string{"nvme8"}; !slices.Equal(s.deleteCalls, want) {
		t.Fatalf("deleted %v, want %v", s.deleteCalls, want)
	}
	head, ok := s.controller("nvme7")
	if !ok || !s.connected {
		t.Fatal("cleanup removed the concurrently connected TCP controller")
	}
	if head.transport != "tcp" || head.address != "192.0.2.9" {
		t.Fatalf("remaining head = %+v", head)
	}
}

func TestMultipathReadsKernelParameter(t *testing.T) {
	for _, tc := range []struct {
		name  string
		param string
		want  bool
	}{
		{name: "enabled", param: "Y\n", want: true},
		{name: "disabled", param: "N\n", want: false},
		{name: "missing", param: "", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &fabricSystem{multipathParam: tc.param}
			if got := NewInitiator(InitiatorOptions{System: s}).Multipath(); got != tc.want {
				t.Fatalf("multipath %q = %v, want %v", tc.param, got, tc.want)
			}
		})
	}
}
