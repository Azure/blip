// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package nvme

import (
	"strconv"
	"strings"
	"testing"
)

func TestRDMAReady(t *testing.T) {
	// A real sysfs GID for the IPv4-mapped address 10.0.0.4.
	const gid10_0_0_4 = "0000:0000:0000:0000:0000:ffff:0a00:0004"
	ready := fakeIBPort{
		path:  "/sys/class/infiniband/mlx5_0/ports/1",
		state: "4: ACTIVE",
		gids:  []fakeGID{{name: "0", value: gid10_0_0_4, typ: "RoCE v2"}},
	}
	withoutState := func(port fakeIBPort, state string) fakeIBPort {
		port.state = state
		return port
	}
	withoutV2 := func(port fakeIBPort, typ string) fakeIBPort {
		port.gids = append([]fakeGID(nil), port.gids...)
		port.gids[0].typ = typ
		return port
	}
	for _, tc := range []struct {
		name    string
		hostIP  string
		module  bool
		ports   []fakeIBPort
		wantErr string
	}{
		{name: "ready", hostIP: "10.0.0.4", module: true, ports: []fakeIBPort{ready}},
		{name: "no nvme_rdma module", hostIP: "10.0.0.4", ports: []fakeIBPort{ready}, wantErr: "nvme_rdma"},
		{name: "port down", hostIP: "10.0.0.4", module: true, ports: []fakeIBPort{withoutState(ready, "1: DOWN")}, wantErr: "no active RoCE v2"},
		{name: "gid for another address", hostIP: "10.0.0.5", module: true, ports: []fakeIBPort{ready}, wantErr: "no active RoCE v2"},
		{name: "RoCE v1 gid", hostIP: "10.0.0.4", module: true, ports: []fakeIBPort{withoutV2(ready, "RoCE v1")}, wantErr: "no active RoCE v2"},
		{name: "invalid host address", hostIP: "not-an-ip", module: true, ports: []fakeIBPort{ready}, wantErr: "not an IPv4"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &fabricSystem{rdmaModule: tc.module, ibPorts: tc.ports}
			err := rdmaReady(tc.hostIP, s)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("rdmaReady(%q) = %v, want error containing %q", tc.hostIP, err, tc.wantErr)
			}
		})
	}
}

func TestRDMAPortIDOutsideTCPRange(t *testing.T) {
	for _, node := range []string{"node-a", "node-b", "exporter", "lease-1", "kind-control-plane"} {
		id := (&Target{node: node}).rdmaPortID()
		n, err := strconv.Atoi(id)
		if err != nil {
			t.Fatalf("rdmaPortID(%q) = %q: %v", node, id, err)
		}
		if n < 61000 || n > 63999 {
			t.Fatalf("rdmaPortID(%q) = %d, want 61000-63999", node, n)
		}
		if n >= 1000 && n <= 60999 {
			t.Fatalf("rdmaPortID(%q) = %d collides with the TCP port range", node, n)
		}
	}
}
