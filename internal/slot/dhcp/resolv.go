package dhcp

import (
	"bufio"
	"bytes"
	"net/netip"
	"strings"
)

// Resolv is the part of resolv.conf the server hands out.
type Resolv struct {
	Servers []netip.Addr
	Search  []string
	Domain  string
}

// ParseResolvConf parses resolv.conf. The last search or domain line
// wins, as in glibc; IPv6 servers are kept but not offered over DHCPv4.
func ParseResolvConf(b []byte) Resolv {
	var r Resolv
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "nameserver":
			if a, err := netip.ParseAddr(f[1]); err == nil {
				r.Servers = append(r.Servers, a.Unmap())
			}
		case "search":
			r.Search, r.Domain = f[1:], ""
		case "domain":
			r.Domain, r.Search = f[1], nil
		}
	}
	return r
}
