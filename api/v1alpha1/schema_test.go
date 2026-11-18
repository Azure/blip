package v1alpha1

import (
	"os"
	"regexp"
	"testing"
	"time"

	"sigs.k8s.io/yaml"
)

// crdValidation is one x-kubernetes-validations entry.
type crdValidation struct {
	Rule    string `json:"rule"`
	Message string `json:"message"`
}

// crdSchema is the part of a generated CRD schema the tests inspect.
type crdSchema struct {
	Type         string               `json:"type"`
	Pattern      string               `json:"pattern"`
	Properties   map[string]crdSchema `json:"properties"`
	Items        *crdSchema           `json:"items"`
	XValidations []crdValidation      `json:"x-kubernetes-validations"`
}

type crdDocument struct {
	Spec struct {
		Versions []struct {
			Name   string `json:"name"`
			Schema struct {
				OpenAPIV3Schema crdSchema `json:"openAPIV3Schema"`
			} `json:"schema"`
		} `json:"versions"`
	} `json:"spec"`
}

// loadCRDSpec reads the generated CRD and returns the v1alpha1 spec schema.
func loadCRDSpec(t *testing.T, file string) crdSchema {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read generated CRD: %v", err)
	}
	var doc crdDocument
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse generated CRD: %v", err)
	}
	for _, version := range doc.Spec.Versions {
		if version.Name != "v1alpha1" {
			continue
		}
		spec, ok := version.Schema.OpenAPIV3Schema.Properties["spec"]
		if !ok {
			t.Fatalf("%s has no spec property", file)
		}
		return spec
	}
	t.Fatalf("%s has no v1alpha1 version", file)
	return crdSchema{}
}

// ruleFor returns the rule with the given message, failing the test when the
// generated CRD does not contain it.
func ruleFor(t *testing.T, rules []crdValidation, message string) string {
	t.Helper()
	for _, rule := range rules {
		if rule.Message == message {
			return rule.Rule
		}
	}
	t.Fatalf("generated CRD has no validation rule with message %q", message)
	return ""
}

// TestIdleTimeoutCRDPattern guards the admission pattern for
// Blip.spec.idleTimeout. Without it, values that cannot be decoded into a
// metav1.Duration are admitted and break the controller's shared Blip
// informer cluster-wide.
func TestIdleTimeoutCRDPattern(t *testing.T) {
	spec := loadCRDSpec(t, "../../deploy/crd/blip.dev_blips.yaml")
	idleTimeout, ok := spec.Properties["idleTimeout"]
	if !ok {
		t.Fatal("generated CRD has no spec.idleTimeout property")
	}
	pattern := idleTimeout.Pattern
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

// TestBlipRootImageOrStateCRDRules guards the admission rules for
// Blip.spec.image and Blip.spec.state. An explicitly empty image or state used
// to count as "set", so image: "" or state: "" was admitted and only later
// failed with InvalidSpec.
func TestBlipRootImageOrStateCRDRules(t *testing.T) {
	spec := loadCRDSpec(t, "../../deploy/crd/blip.dev_blips.yaml")

	const exactlyOne = "(has(self.image) && size(self.image) > 0) != (has(self.state) && size(self.state) > 0)"
	if rule := ruleFor(t, spec.XValidations, "set exactly one of image and state"); rule != exactlyOne {
		t.Errorf("exactly-one rule %q, want %q", rule, exactlyOne)
	}

	// The presence rule must use the same definition of "set" as the
	// exactly-one rule: an empty image is not a set root.
	const immutable = "(has(self.image) && size(self.image) > 0) == (has(oldSelf.image) && size(oldSelf.image) > 0) && has(self.command) == has(oldSelf.command)"
	if rule := ruleFor(t, spec.XValidations, "image, state, and command are immutable"); rule != immutable {
		t.Errorf("immutability rule %q, want %q", rule, immutable)
	}
}

// TestBlipStateSizeCRDRule guards the admission rule that rejects a zero or
// negative BlipState.spec.size, which otherwise reached the node agent and
// failed with an internal storage error.
func TestBlipStateSizeCRDRule(t *testing.T) {
	spec := loadCRDSpec(t, "../../deploy/crd/blip.dev_blipstates.yaml")
	size, ok := spec.Properties["size"]
	if !ok {
		t.Fatal("generated CRD has no spec.size property")
	}
	const want = "type(self) == string ? quantity(self).isGreaterThan(quantity('0')) : self > 0"
	if rule := ruleFor(t, size.XValidations, "size must be greater than 0"); rule != want {
		t.Errorf("size rule %q, want %q", rule, want)
	}
}
