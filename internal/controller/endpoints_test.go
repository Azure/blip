package controller

import (
	"strings"
	"testing"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

func TestValidateEndpoints(t *testing.T) {
	longName := strings.Repeat("a", 64)
	tests := []struct {
		name      string
		account   string
		audiences []string
		endpoints []v1.PoolEndpoint
		wantErr   string
	}{
		{name: "omitted"},
		{name: "valid", account: "vm", endpoints: []v1.PoolEndpoint{
			{Name: "whoami", URL: "https://whoami.example.com"},
			{Name: "whoami-8443", URL: "https://whoami.example.com:8443", Audience: "blip-gateway"},
			{Name: "with-ca", URL: "https://whoami.example.com", CAConfigMap: "whoami-ca"},
			{Name: "all", URL: "https://all.example.com:8443", Audience: "blip-gateway", CAConfigMap: "all-ca"},
		}},
		{name: "uppercase name", endpoints: []v1.PoolEndpoint{
			{Name: "Whoami", URL: "https://whoami.example.com"},
		}, wantErr: `endpoints[0] "Whoami": name must be`},
		{name: "name with underscore", endpoints: []v1.PoolEndpoint{
			{Name: "who_ami", URL: "https://whoami.example.com"},
		}, wantErr: "name must be"},
		{name: "name longer than 63", endpoints: []v1.PoolEndpoint{
			{Name: longName, URL: "https://whoami.example.com"},
		}, wantErr: "name must be"},
		{name: "reserved blip", endpoints: []v1.PoolEndpoint{
			{Name: "blip", URL: "https://whoami.example.com"},
		}, wantErr: `endpoints[0] "blip": name is reserved`},
		{name: "reserved localhost", endpoints: []v1.PoolEndpoint{
			{Name: "localhost", URL: "https://whoami.example.com"},
		}, wantErr: "name is reserved"},
		{name: "reserved kube-apiserver", endpoints: []v1.PoolEndpoint{
			{Name: "kube-apiserver", URL: "https://whoami.example.com"},
		}, wantErr: "name is reserved"},
		{name: "duplicate name", endpoints: []v1.PoolEndpoint{
			{Name: "whoami", URL: "https://whoami.example.com"},
			{Name: "whoami", URL: "https://other.example.com"},
		}, wantErr: `endpoints[1] "whoami": duplicate endpoint name`},
		{name: "http url", endpoints: []v1.PoolEndpoint{
			{Name: "whoami", URL: "http://whoami.example.com"},
		}, wantErr: "must use https"},
		{name: "path", endpoints: []v1.PoolEndpoint{
			{Name: "whoami", URL: "https://whoami.example.com/api"},
		}, wantErr: "must not contain a path"},
		{name: "query", endpoints: []v1.PoolEndpoint{
			{Name: "whoami", URL: "https://whoami.example.com?x=1"},
		}, wantErr: "must not contain a query"},
		{name: "fragment", endpoints: []v1.PoolEndpoint{
			{Name: "whoami", URL: "https://whoami.example.com#frag"},
		}, wantErr: "must not contain a query"},
		{name: "user info", endpoints: []v1.PoolEndpoint{
			{Name: "whoami", URL: "https://user@whoami.example.com"},
		}, wantErr: "must not contain user information"},
		{name: "ipv4 host", endpoints: []v1.PoolEndpoint{
			{Name: "whoami", URL: "https://10.0.0.1"},
		}, wantErr: "host must be a DNS name, not an IP address"},
		{name: "ipv6 host", endpoints: []v1.PoolEndpoint{
			{Name: "whoami", URL: "https://[::1]"},
		}, wantErr: "host must be a DNS name, not an IP address"},
		{name: "port zero", endpoints: []v1.PoolEndpoint{
			{Name: "whoami", URL: "https://whoami.example.com:0"},
		}, wantErr: "port must be a number between 1 and 65535"},
		{name: "port too large", endpoints: []v1.PoolEndpoint{
			{Name: "whoami", URL: "https://whoami.example.com:65536"},
		}, wantErr: "port must be a number between 1 and 65535"},
		{name: "non-numeric port", endpoints: []v1.PoolEndpoint{
			{Name: "whoami", URL: "https://whoami.example.com:nope"},
		}, wantErr: "must be a valid HTTPS URL"},
		{name: "audience without service account", endpoints: []v1.PoolEndpoint{
			{Name: "whoami", URL: "https://whoami.example.com", Audience: "blip-gateway"},
		}, wantErr: "audience requires spec.serviceAccountName"},
		{name: "api server audience", account: "vm", endpoints: []v1.PoolEndpoint{
			{Name: "whoami", URL: "https://whoami.example.com", Audience: "kubernetes.default.svc"},
		}, wantErr: "must not be a Kubernetes API server audience"},
		{name: "api server audience URL", account: "vm", endpoints: []v1.PoolEndpoint{
			{Name: "whoami", URL: "https://whoami.example.com", Audience: "https://kubernetes.default.svc.cluster.local/"},
		}, wantErr: "must not be a Kubernetes API server audience"},
		{name: "cluster issuer audience", account: "vm", audiences: []string{"https://oidc.prod-aks.azure.com/tenant/cluster/"}, endpoints: []v1.PoolEndpoint{
			{Name: "whoami", URL: "https://whoami.example.com", Audience: "https://oidc.prod-aks.azure.com/tenant/cluster/"},
		}, wantErr: "must not be a Kubernetes API server audience"},
		{name: "unrelated audience with cluster issuer", account: "vm", audiences: []string{"https://oidc.prod-aks.azure.com/tenant/cluster/"}, endpoints: []v1.PoolEndpoint{
			{Name: "whoami", URL: "https://whoami.example.com", Audience: "blip-gateway"},
		}},
		{name: "bad ca configmap", endpoints: []v1.PoolEndpoint{
			{Name: "whoami", URL: "https://whoami.example.com", CAConfigMap: "Bad_CA"},
		}, wantErr: "must be a DNS subdomain"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := &v1.BlipPool{Spec: v1.BlipPoolSpec{
				ServiceAccountName: tt.account,
				Endpoints:          tt.endpoints,
			}}
			err := validateEndpoints(pool, tt.audiences...)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateEndpoints: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validateEndpoints accepted, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}
