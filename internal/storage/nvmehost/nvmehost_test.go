package nvmehost

import (
	"strings"
	"testing"
)

func TestOptions(t *testing.T) {
	c := Conn{Addr: "10.0.0.1", Svc: 4421, SubNQN: "nqn.s", HostNQN: "nqn.h", HostID: "id", Keyring: 5, TLSKey: 9}
	got, err := Options(c)
	if err != nil {
		t.Fatal(err)
	}
	want := "transport=tcp,traddr=10.0.0.1,trsvcid=4421,nqn=nqn.s,hostnqn=nqn.h,hostid=id,nr_io_queues=4,ctrl_loss_tmo=60,fast_io_fail_tmo=5,reconnect_delay=2,tls,keyring=5,tls_key=9"
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	c.TLSKey = 0
	if _, err := Options(c); err == nil {
		t.Fatal("no TLS key must fail")
	}
	c.TLSKey = 9
	c.SubNQN = "a,b"
	if _, err := Options(c); err == nil || !strings.Contains(err.Error(), "bad option") {
		t.Fatal("comma must fail", err)
	}
}

func TestParseAddress(t *testing.T) {
	a, s := ParseAddress("traddr=10.99.0.1,trsvcid=4421,src_addr=10.99.0.4\n")
	if a != "10.99.0.1" || s != 4421 {
		t.Fatal(a, s)
	}
}

func TestIsNSName(t *testing.T) {
	for s, want := range map[string]bool{"nvme7n1": true, "nvme7c7n1": false, "nvme7": false, "ng7n1": false} {
		if isNSName(s) != want {
			t.Error(s)
		}
	}
}
