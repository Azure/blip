package node

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/example/blip/internal/storage/image"
)

// dockerConfig is the content of a kubernetes.io/dockerconfigjson Secret.
type dockerConfig struct {
	Auths map[string]struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Auth     string `json:"auth"`
	} `json:"auths"`
}

// registryKey normalizes a registry name or URL from a docker config.
func registryKey(s string) string {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	s, _, _ = strings.Cut(s, "/")
	switch s {
	case "docker.io", "registry-1.docker.io":
		return name.DefaultRegistry
	}
	return s
}

// pullAuth returns the credentials for ref from a dockerconfigjson, or nil
// when cfg is empty or has no entry for the registry.
func pullAuth(cfg []byte, ref string) (*image.Auth, error) {
	if len(cfg) == 0 {
		return nil, nil
	}
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("image reference %q: %w", ref, err)
	}
	var dc dockerConfig
	if err := json.Unmarshal(cfg, &dc); err != nil {
		return nil, fmt.Errorf("pull secret: %w", err)
	}
	want := registryKey(r.Context().RegistryStr())
	for k, a := range dc.Auths {
		if registryKey(k) != want {
			continue
		}
		if a.Username == "" && a.Auth != "" {
			b, err := base64.StdEncoding.DecodeString(a.Auth)
			if err != nil {
				return nil, fmt.Errorf("pull secret auth for %s: %w", k, err)
			}
			u, p, ok := strings.Cut(string(b), ":")
			if !ok {
				return nil, fmt.Errorf("pull secret auth for %s is not user:password", k)
			}
			return &image.Auth{Username: u, Password: p}, nil
		}
		return &image.Auth{Username: a.Username, Password: a.Password}, nil
	}
	return nil, nil
}
