package controller

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

func TestValidateGatewaySpecAddressAndServerName(t *testing.T) {
	tests := []struct {
		name    string
		gateway *v1.GatewaySpec
		ok      bool
	}{
		{name: "omitted", gateway: nil, ok: true},
		{name: "service dns", gateway: &v1.GatewaySpec{Address: "gw.gateway-system.svc:443"}, ok: true},
		{name: "localhost", gateway: &v1.GatewaySpec{Address: "localhost:8443"}, ok: true},
		{name: "ipv4", gateway: &v1.GatewaySpec{Address: "10.0.0.1:443"}, ok: true},
		{name: "bracketed ipv6", gateway: &v1.GatewaySpec{Address: "[::1]:443"}, ok: true},
		{name: "uppercase and trailing dot", gateway: &v1.GatewaySpec{Address: "GATEWAY.Test.:443"}, ok: true},
		{name: "max port", gateway: &v1.GatewaySpec{Address: "gateway.test:65535"}, ok: true},
		{name: "explicit server name", gateway: &v1.GatewaySpec{Address: "10.0.0.1:443", ServerName: "gateway.test"}, ok: true},
		{name: "server name trailing dot", gateway: &v1.GatewaySpec{Address: "10.0.0.1:443", ServerName: "gateway.test."}, ok: true},
		{name: "server name ipv4", gateway: &v1.GatewaySpec{Address: "10.0.0.1:443", ServerName: "10.0.0.2"}, ok: true},
		{name: "server name ipv6", gateway: &v1.GatewaySpec{Address: "10.0.0.1:443", ServerName: "fd00::1"}, ok: true},

		{name: "non-numeric port", gateway: &v1.GatewaySpec{Address: "host:notaport"}, ok: false},
		{name: "url", gateway: &v1.GatewaySpec{Address: "https://host:443"}, ok: false},
		{name: "url with path", gateway: &v1.GatewaySpec{Address: "https://host:443/path"}, ok: false},
		{name: "missing port", gateway: &v1.GatewaySpec{Address: "host"}, ok: false},
		{name: "empty host", gateway: &v1.GatewaySpec{Address: ":443"}, ok: false},
		{name: "empty port", gateway: &v1.GatewaySpec{Address: "host:"}, ok: false},
		{name: "port zero", gateway: &v1.GatewaySpec{Address: "host:0"}, ok: false},
		{name: "port too large", gateway: &v1.GatewaySpec{Address: "host:65536"}, ok: false},
		{name: "leading zero port", gateway: &v1.GatewaySpec{Address: "host:0443"}, ok: false},
		{name: "signed port", gateway: &v1.GatewaySpec{Address: "host:+443"}, ok: false},
		{name: "whitespace", gateway: &v1.GatewaySpec{Address: "host: 443"}, ok: false},
		{name: "user info", gateway: &v1.GatewaySpec{Address: "user@host:443"}, ok: false},
		{name: "path", gateway: &v1.GatewaySpec{Address: "host/path:443"}, ok: false},
		{name: "unbracketed ipv6", gateway: &v1.GatewaySpec{Address: "::1:443"}, ok: false},
		{name: "unbracketed ipv6 with port", gateway: &v1.GatewaySpec{Address: "[::1]443"}, ok: false},
		{name: "empty ipv6", gateway: &v1.GatewaySpec{Address: "[]:443"}, ok: false},
		{name: "ipv6 zone", gateway: &v1.GatewaySpec{Address: "[fe80::1%eth0]:443"}, ok: false},
		{name: "host with underscore", gateway: &v1.GatewaySpec{Address: "bad_host:443"}, ok: false},
		{name: "empty label", gateway: &v1.GatewaySpec{Address: "a..b:443"}, ok: false},

		{name: "bad server name", gateway: &v1.GatewaySpec{Address: "gw.gateway-system.svc:443", ServerName: "bad/name"}, ok: false},
		{name: "server name scheme", gateway: &v1.GatewaySpec{Address: "gw.gateway-system.svc:443", ServerName: "https://gateway.test"}, ok: false},
		{name: "server name port", gateway: &v1.GatewaySpec{Address: "gw.gateway-system.svc:443", ServerName: "gateway.test:443"}, ok: false},
		{name: "server name brackets", gateway: &v1.GatewaySpec{Address: "gw.gateway-system.svc:443", ServerName: "[::1]"}, ok: false},
		{name: "server name whitespace", gateway: &v1.GatewaySpec{Address: "gw.gateway-system.svc:443", ServerName: "gate way"}, ok: false},
		{name: "server name wildcard", gateway: &v1.GatewaySpec{Address: "gw.gateway-system.svc:443", ServerName: "*"}, ok: false},
		{name: "server name empty label", gateway: &v1.GatewaySpec{Address: "gw.gateway-system.svc:443", ServerName: "a..b"}, ok: false},
		{name: "server name leading dash", gateway: &v1.GatewaySpec{Address: "gw.gateway-system.svc:443", ServerName: "-bad"}, ok: false},
		{name: "server name trailing dash", gateway: &v1.GatewaySpec{Address: "gw.gateway-system.svc:443", ServerName: "bad-"}, ok: false},
		{name: "server name underscore", gateway: &v1.GatewaySpec{Address: "gw.gateway-system.svc:443", ServerName: "bad_name"}, ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGatewaySpec(tt.gateway)
			if (err == nil) != tt.ok {
				t.Fatalf("validateGatewaySpec(%+v) = %v, want ok=%v", tt.gateway, err, tt.ok)
			}
		})
	}
}

// TestValidateGatewayAudience checks that the gateway token cannot be projected
// for an audience the Kubernetes API server accepts, while ordinary custom
// audiences keep working.
func TestValidateGatewayAudience(t *testing.T) {
	tests := []struct {
		audience string
		ok       bool
	}{
		{audience: "", ok: true},
		{audience: defaultGatewayAudience, ok: true},
		{audience: "custom-audience", ok: true},
		{audience: "https://gateway.example/audience", ok: true},
		{audience: "kubernetes.default.svc.example.com", ok: true},
		{audience: "not-kubernetes.default.svc", ok: true},
		{audience: "https://other.default.svc.cluster.local", ok: true},

		{audience: "https://kubernetes.default.svc", ok: false},
		{audience: "https://kubernetes.default.svc.", ok: false},
		{audience: "HTTPS://KUBERNETES.DEFAULT.SVC", ok: false},
		{audience: "https://kubernetes.default.svc.cluster.local", ok: false},
		{audience: "https://kubernetes.default.svc.cluster.local.", ok: false},
		{audience: "HTTPS://KUBERNETES.DEFAULT.SVC.CLUSTER.LOCAL", ok: false},
		{audience: "https://kubernetes.default.svc:443", ok: false},
		{audience: "https://kubernetes.default.svc.cluster.local:443/", ok: false},
		{audience: "kubernetes.default.svc", ok: false},
		{audience: "kubernetes.default.svc.", ok: false},
		{audience: "kubernetes.default.svc.cluster.local", ok: false},
		{audience: "kubernetes.default.svc.cluster.local.", ok: false},
		{audience: " kubernetes.default.svc.cluster.local ", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.audience, func(t *testing.T) {
			gateway := &v1.GatewaySpec{Address: "gw.gateway-system.svc:443", Audience: tt.audience}
			err := validateGatewaySpec(gateway)
			if (err == nil) != tt.ok {
				t.Fatalf("validateGatewaySpec(audience=%q) = %v, want ok=%v", tt.audience, err, tt.ok)
			}
		})
	}
}

// TestPoolReconcileRejectsInvalidGateway checks that a pool already stored in
// etcd with an unusable gateway fails reconciliation before it creates a VM
// pod whose api-proxy sidecar would crash-loop or carry an API-valid token.
func TestPoolReconcileRejectsInvalidGateway(t *testing.T) {
	tests := []struct {
		name    string
		gateway *v1.GatewaySpec
		want    string
	}{
		{
			name:    "address",
			gateway: &v1.GatewaySpec{Address: "gw.gateway-system.svc:notaport"},
			want:    "gateway.address",
		},
		{
			name:    "server name",
			gateway: &v1.GatewaySpec{Address: "gw.gateway-system.svc:443", ServerName: "bad/name"},
			want:    "gateway.serverName",
		},
		{
			name:    "audience",
			gateway: &v1.GatewaySpec{Address: "gw.gateway-system.svc:443", Audience: "https://kubernetes.default.svc.cluster.local"},
			want:    "gateway.audience",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			e.create(&v1.BlipPool{
				ObjectMeta: metav1.ObjectMeta{Name: "bad"},
				Spec: v1.BlipPoolSpec{
					ServiceAccountName: "vm",
					NodeSelector:       map[string]string{"blip.dev/node-pool": "default"},
					Gateway:            tt.gateway,
				},
			})
			_, err := e.pool.Reconcile(e.ctx, req(ns, "bad"))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("reconcile error = %v, want it to name %q", err, tt.want)
			}
			if pods := e.pods(); len(pods) != 0 {
				t.Fatalf("created %d pods for an invalid gateway: %+v", len(pods), pods)
			}
		})
	}
}
