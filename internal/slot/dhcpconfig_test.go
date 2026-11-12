package slot

import "testing"

func TestDHCPConfig(t *testing.T) {
	n := &PodNetwork{
		MAC: "52:54:00:12:34:56", MTU: 1500,
		Addresses: []string{"fd00::5/128", "192.168.10.7/32"},
		Routes: []Route{
			{Destination: "169.254.1.1/32"},
			{Gateway: "169.254.1.1", Onlink: true},
			{Gateway: "fe80::1", IPv6: true},
			{Destination: "10.0.0.0/8", Gateway: "169.254.1.1"},
		},
	}
	c, err := DHCPConfig(n, []byte("nameserver 10.96.0.10\nsearch ns.svc.cluster.local cluster.local\n"), "vm1")
	if err != nil {
		t.Fatal(err)
	}
	if c.Addr.String() != "192.168.10.7/32" || c.Gateway.String() != "169.254.1.1" || c.ServerID != c.Gateway {
		t.Fatalf("%+v", c)
	}
	if len(c.Routes) != 2 || c.Routes[0].Dst.String() != "169.254.1.1/32" || c.Routes[0].Gateway.IsValid() || c.Routes[1].Gateway.String() != "169.254.1.1" {
		t.Fatalf("routes %+v", c.Routes)
	}
	if len(c.DNS) != 1 || len(c.Search) != 2 || c.Hostname != "vm1" || c.MTU != 1500 || c.ClientMAC.String() != n.MAC {
		t.Fatalf("%+v", c)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := DHCPConfig(&PodNetwork{MAC: n.MAC, Addresses: []string{"fd00::5/128"}}, nil, ""); err == nil {
		t.Fatal("want error without IPv4")
	}
}
