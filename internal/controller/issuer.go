package controller

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"k8s.io/client-go/rest"
)

// discoverAPIServerAudiences reads the API server's OpenID discovery
// document to learn the cluster's service-account issuer. When the API server
// has no --api-audiences override (the default), that issuer is an accepted
// API audience, so an endpoint token projected for it must be rejected.
//
// Discovery failure is not fatal: the built-in names still cover a cluster
// that uses the default issuer. A cluster with a custom --api-audiences value
// that differs from its issuer remains a documented limitation.
func discoverAPIServerAudiences(ctx context.Context, cfg *rest.Config) []string {
	if cfg == nil || cfg.Host == "" {
		return nil
	}
	client, err := rest.HTTPClientFor(rest.AnonymousClientConfig(cfg))
	if err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	url := strings.TrimRight(cfg.Host, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var document struct {
		Issuer string `json:"issuer"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&document); err != nil {
		return nil
	}
	if document.Issuer == "" {
		return nil
	}
	return []string{document.Issuer}
}
