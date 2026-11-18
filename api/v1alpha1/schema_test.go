package v1alpha1

import (
	"os"
	"regexp"
	"testing"
	"time"

	"sigs.k8s.io/yaml"
)

// crdDocument is the minimal shape of a generated CRD needed to read the
// idleTimeout validation pattern.
type crdDocument struct {
	Spec struct {
		Versions []struct {
			Name   string `json:"name"`
			Schema struct {
				OpenAPIV3Schema struct {
					Properties map[string]struct {
						Properties map[string]struct {
							Pattern string `json:"pattern"`
						} `json:"properties"`
					} `json:"properties"`
				} `json:"openAPIV3Schema"`
			} `json:"schema"`
		} `json:"versions"`
	} `json:"spec"`
}

// TestIdleTimeoutCRDPattern guards the admission pattern for
// Blip.spec.idleTimeout. Without it, values that cannot be decoded into a
// metav1.Duration are admitted and break the controller's shared Blip
// informer cluster-wide.
func TestIdleTimeoutCRDPattern(t *testing.T) {
	data, err := os.ReadFile("../../deploy/crd/blip.dev_blips.yaml")
	if err != nil {
		t.Fatalf("read generated CRD: %v", err)
	}
	var doc crdDocument
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse generated CRD: %v", err)
	}

	pattern := ""
	found := false
	for _, version := range doc.Spec.Versions {
		if version.Name != "v1alpha1" {
			continue
		}
		found = true
		idleTimeout, ok := version.Schema.OpenAPIV3Schema.Properties["spec"].Properties["idleTimeout"]
		if !ok {
			t.Fatal("generated CRD has no spec.idleTimeout property")
		}
		pattern = idleTimeout.Pattern
	}
	if !found {
		t.Fatal("generated CRD has no v1alpha1 version")
	}
	if pattern == "" {
		t.Fatal("generated CRD has no spec.idleTimeout.pattern; malformed durations would be admitted")
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatalf("compile spec.idleTimeout.pattern %q: %v", pattern, err)
	}

	accept := []string{"30s", "1m30s", "0s", "1.5s", "500ms", "1us"}
	for _, value := range accept {
		if !re.MatchString(value) {
			t.Errorf("pattern %q rejects valid duration %q", pattern, value)
		}
		if _, err := time.ParseDuration(value); err != nil {
			t.Errorf("test case %q is not a valid Go duration: %v", value, err)
		}
	}

	reject := []string{"bogus", "-5s", "1d", ""}
	for _, value := range reject {
		if re.MatchString(value) {
			t.Errorf("pattern %q accepts invalid duration %q", pattern, value)
		}
	}
}
