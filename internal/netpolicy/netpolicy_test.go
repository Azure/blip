package netpolicy

import "testing"

func TestRuleValidate(t *testing.T) {
	tests := []struct {
		name string
		rule Rule
		ok   bool
	}{
		{"any", Rule{CIDR: "10.0.0.0/8"}, true},
		{"host", Rule{CIDR: "10.1.2.3/32", Protocol: "tcp", Port: 443}, true},
		{"port range", Rule{CIDR: "10.0.0.0/8", Protocol: "UDP", Port: 53, EndPort: 54}, true},
		{"exception", Rule{CIDR: "10.0.0.0/8", Except: []string{"10.1.0.0/16"}}, true},
		{"exception equal", Rule{CIDR: "10.0.0.0/8", Except: []string{"10.0.0.0/8"}}, true},
		{"ipv6", Rule{CIDR: "::/0"}, false},
		{"bad cidr", Rule{CIDR: "10.0.0.0"}, false},
		{"exception outside", Rule{CIDR: "10.0.0.0/8", Except: []string{"192.168.0.0/16"}}, false},
		{"exception wider", Rule{CIDR: "10.1.0.0/16", Except: []string{"10.0.0.0/8"}}, false},
		{"bad protocol", Rule{CIDR: "10.0.0.0/8", Protocol: "icmp"}, false},
		{"port without protocol", Rule{CIDR: "10.0.0.0/8", Port: 80}, false},
		{"range without start", Rule{CIDR: "10.0.0.0/8", Protocol: "tcp", EndPort: 80}, false},
		{"backwards range", Rule{CIDR: "10.0.0.0/8", Protocol: "tcp", Port: 80, EndPort: 79}, false},
		{"port too large", Rule{CIDR: "10.0.0.0/8", Protocol: "tcp", Port: 65536}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			if (err == nil) != tt.ok {
				t.Fatalf("Validate() = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}

func TestPolicyValidate(t *testing.T) {
	var nilPolicy *Policy
	if err := nilPolicy.Validate(); err != nil {
		t.Fatalf("nil policy: %v", err)
	}
	if err := (&Policy{Layers: [][]Rule{{{CIDR: "10.0.0.0/8"}}}}).Validate(); err == nil {
		t.Fatal("empty revision accepted")
	}
	if err := (&Policy{Revision: "1", Layers: [][]Rule{{{CIDR: "::/0"}}}}).Validate(); err == nil {
		t.Fatal("invalid rule accepted")
	}
	if err := (&Policy{Revision: "1", Layers: [][]Rule{{{CIDR: "10.0.0.0/8"}}}}).Validate(); err != nil {
		t.Fatalf("valid policy: %v", err)
	}
}
