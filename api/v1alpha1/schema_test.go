package v1alpha1

import (
	"context"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	crdvalidation "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/validation"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	celvalidation "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/cel"
	openapivalidation "k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	kubejson "k8s.io/apimachinery/pkg/util/json"
	"k8s.io/apimachinery/pkg/util/validation/field"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
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
	MaxLength    int64                `json:"maxLength"`
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

// Every execution requires a durable root; workload images and mounts belong
// to the state rather than the execution schema.
func TestBlipRootRequired(t *testing.T) {
	spec := loadCRDSpec(t, "../../deploy/crd/blip.dev_blips.yaml")
	for _, name := range []string{"image", "mounts", "imagePullSecrets"} {
		if _, exists := spec.Properties[name]; exists {
			t.Errorf("Blip schema retains spec.%s", name)
		}
	}
	validate := admissionValidator(t, "blips")
	for _, object := range []string{`{}`, `{"spec":{}}`, `{"spec":{"state":""}}`} {
		if errs := validate(object, ""); len(errs) == 0 {
			t.Errorf("admitted execution without a root: %s", object)
		}
	}
	root := `{"spec":{"state":"root"}}`
	if errs := validate(root, ""); len(errs) != 0 {
		t.Fatal(errs.ToAggregate())
	}
	if errs := validate(`{"spec":{"state":"other"}}`, root); len(errs) == 0 {
		t.Fatal("admitted root replacement")
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

// TestGatewayAddressAndServerNameCRDRules guards admission of
// BlipPool.spec.gateway.address and serverName. Values such as
// "host:notaport" or "https://host:443" used to pass only a
// contains(':') check, so the api-proxy sidecar crash-looped while the Blip
// waited for a VM forever.
func TestGatewayAddressAndServerNameCRDRules(t *testing.T) {
	spec := loadCRDSpec(t, "../../deploy/crd/blip.dev_blippools.yaml")
	gateway, ok := spec.Properties["gateway"]
	if !ok {
		t.Fatal("generated CRD has no spec.gateway property")
	}

	address, ok := gateway.Properties["address"]
	if !ok {
		t.Fatal("generated CRD has no spec.gateway.address property")
	}
	const addressPattern = `^(\[[0-9A-Fa-f:.]+\]|([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)([.][A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*[.]?):([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$`
	if address.Pattern != addressPattern {
		t.Errorf("gateway address pattern %q, want %q", address.Pattern, addressPattern)
	}
	if address.MaxLength != 259 {
		t.Errorf("gateway address maxLength %d, want 259", address.MaxLength)
	}
	addressRE, err := regexp.Compile(address.Pattern)
	if err != nil {
		t.Fatalf("compile gateway address pattern %q: %v", address.Pattern, err)
	}
	for _, value := range []string{
		"gw.gateway-system.svc:443", "localhost:8443", "10.0.0.1:443",
		"[::1]:443", "GATEWAY.Test.:443", "gateway.test:65535",
	} {
		if !addressRE.MatchString(value) {
			t.Errorf("gateway address pattern rejects valid address %q", value)
		}
	}
	for _, value := range []string{
		"host:notaport", "https://host:443", "https://host:443/path", "host",
		":443", "host:", "host:0", "host:65536", "host:0443", "host:+443",
		"host: 443", "user@host:443", "host/path:443", "::1:443", "[::1]443",
		"[]:443", "[fe80::1%eth0]:443", "bad_host:443", "a..b:443",
	} {
		if addressRE.MatchString(value) {
			t.Errorf("gateway address pattern accepts invalid address %q", value)
		}
	}

	serverName, ok := gateway.Properties["serverName"]
	if !ok {
		t.Fatal("generated CRD has no spec.gateway.serverName property")
	}
	if serverName.MaxLength != 253 {
		t.Errorf("gateway serverName maxLength %d, want 253", serverName.MaxLength)
	}
	rule := ruleFor(t, serverName.XValidations, "serverName must be a DNS name or IP address")
	const namePrefix = "self.serverName.matches('"
	i := strings.Index(rule, namePrefix)
	if i < 0 {
		t.Fatalf("serverName rule %q has no DNS matches() expression", rule)
	}
	i += len(namePrefix)
	j := strings.Index(rule[i:], "')")
	if j < 0 {
		t.Fatalf("serverName rule %q has no terminated DNS expression", rule)
	}
	nameRE, err := regexp.Compile(rule[i : i+j])
	if err != nil {
		t.Fatalf("compile serverName pattern: %v", err)
	}
	valid := func(name string) bool {
		return name == "" || net.ParseIP(name) != nil || nameRE.MatchString(name)
	}
	for _, value := range []string{
		"", "gateway.test", "gateway.test.", "GATEWAY.TEST", "localhost",
		"10.0.0.1", "::1", "fd00::1", "gw.gateway-system.svc",
	} {
		if !valid(value) {
			t.Errorf("gateway serverName validation rejects valid name %q", value)
		}
	}
	for _, value := range []string{
		"bad/name", "https://gateway.test", "gateway.test:443", "[::1]",
		"bad name", "*", "-bad", "bad-", "a..b", "bad_name", ".",
	} {
		if valid(value) {
			t.Errorf("gateway serverName validation accepts invalid name %q", value)
		}
	}
}

// TestMountPathCRDRules guards admission of Blip.spec.mounts paths. Paths used
// to be validated only by the controller after it had claimed a VM.
func TestMountPathCRDRules(t *testing.T) {
	spec := loadCRDSpec(t, "../../deploy/crd/blip.dev_blipstates.yaml")
	mounts, ok := spec.Properties["mounts"]
	if !ok || mounts.Items == nil {
		t.Fatal("generated CRD has no spec.mounts items")
	}
	path, ok := mounts.Items.Properties["path"]
	if !ok {
		t.Fatal("generated CRD has no spec.mounts.path property")
	}

	const pathPattern = `^/[^/]+(/[^/]+)*$`
	if path.Pattern != pathPattern {
		t.Errorf("mount path pattern %q, want %q", path.Pattern, pathPattern)
	}
	// CEL cost estimation needs a bound on the string length; without it the
	// split/exists rule blows the per-object admission budget.
	if path.MaxLength != 4096 {
		t.Errorf("mount path maxLength %d, want 4096", path.MaxLength)
	}
	const segments = "!self.split('/').exists(s, s == '.' || s == '..')"
	if rule := ruleFor(t, path.XValidations, "path must not contain . or .. segments"); rule != segments {
		t.Errorf("mount path segment rule %q, want %q", rule, segments)
	}
	const unique = "self.all(m, self.exists_one(o, o.path == m.path))"
	if rule := ruleFor(t, mounts.XValidations, "mount paths must be unique"); rule != unique {
		t.Errorf("mount path uniqueness rule %q, want %q", rule, unique)
	}

	re, err := regexp.Compile(path.Pattern)
	if err != nil {
		t.Fatalf("compile mount path pattern %q: %v", path.Pattern, err)
	}
	// validMountPath mirrors the generated pattern plus the segment rule.
	validMountPath := func(p string) bool {
		if !re.MatchString(p) {
			return false
		}
		for _, segment := range strings.Split(p, "/") {
			if segment == "." || segment == ".." {
				return false
			}
		}
		return true
	}

	accept := []string{"/mnt/a", "/tmp", "/a", "/a b/c", "/nested/path/here", "/.hidden", "/a.b/c"}
	for _, value := range accept {
		if !validMountPath(value) {
			t.Errorf("mount path validation rejects valid path %q", value)
		}
	}
	reject := []string{"", "data", "/", "/mnt/a/", "//mnt/a", "/mnt//a", "/a/./b", "/a/../b", "/.", "/..", "/a/.."}
	for _, value := range reject {
		if validMountPath(value) {
			t.Errorf("mount path validation accepts invalid path %q", value)
		}
	}
}

func TestStateProvisioningImmutableAndRuntimeMutable(t *testing.T) {
	validate := admissionValidator(t, "blipstates")
	for _, tc := range []struct{ name, initial, changed string }{
		{"image", `"busybox:1"`, `"busybox:2"`},
		{"copyFrom", `"source"`, `"other"`},
		{"size", `"1Gi"`, `"2Gi"`},
		{"replicas", `1`, `2`},
		{"nodeSelector", `{"role":"one"}`, `{"role":"two"}`},
		{"imagePullSecrets", `[{"name":"one"}]`, `[{"name":"two"}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := fmt.Sprintf(`{"spec":{%q:%s}}`, tc.name, tc.initial)
			after := fmt.Sprintf(`{"spec":{%q:%s}}`, tc.name, tc.changed)
			if errs := validate(before, ""); len(errs) != 0 {
				t.Fatal(errs.ToAggregate())
			}
			for _, pair := range [][2]string{{after, before}, {before, `{"spec":{}}`}, {`{"spec":{}}`, before}, {`{}`, before}} {
				if errs := validate(pair[0], pair[1]); len(errs) == 0 {
					t.Errorf("admitted provisioning change: %s -> %s", pair[1], pair[0])
				}
			}
		})
	}
	objects := []string{
		`{"spec":{"copyFrom":"source"}}`,
		`{"spec":{"copyFrom":"source","mounts":[{"state":"data","path":"/data","blipUID":"execution-uid"}],"runtime":{"env":[{"name":"A","value":"1"}],"workingDir":"/work","user":"1000","idleTimeout":"1m","network":{}}}}`,
		`{"spec":{"copyFrom":"source","mounts":[{"state":"data","path":"/updated","writable":true}],"runtime":{"env":[{"name":"A","value":"2"}],"workingDir":"/next","user":"1001","idleTimeout":"0s","network":{"egress":[{}]}}}}`,
	}
	for _, before := range objects {
		for _, after := range objects {
			if errs := validate(after, before); len(errs) != 0 {
				t.Errorf("runtime/mount update rejected: %v", errs.ToAggregate())
			}
		}
	}
	if errs := validate(`{"spec":{"runtime":{"idleTimeout":"bogus"}}}`, ""); len(errs) == 0 {
		t.Fatal("admitted malformed runtime idle timeout")
	}
}

// admissionValidator applies the same structural, OpenAPI, and CEL checks as
// the API server, including transition rules and their static cost limits.
func admissionValidator(t *testing.T, name string) func(object, old string) field.ErrorList {
	t.Helper()
	data, err := os.ReadFile("../../deploy/crd/blip.dev_" + name + ".yaml")
	if err != nil {
		t.Fatal(err)
	}
	var versioned apiextensionsv1.CustomResourceDefinition
	if err := yaml.Unmarshal(data, &versioned); err != nil {
		t.Fatal(err)
	}
	apiextensionsv1.SetDefaults_CustomResourceDefinition(&versioned)
	var crd apiextensions.CustomResourceDefinition
	if err := apiextensionsv1.Convert_v1_CustomResourceDefinition_To_apiextensions_CustomResourceDefinition(&versioned, &crd, nil); err != nil {
		t.Fatal(err)
	}
	if errs := crdvalidation.ValidateCustomResourceDefinition(context.Background(), &crd); len(errs) != 0 {
		t.Fatal(errs.ToAggregate())
	}
	root := crd.Spec.Validation.OpenAPIV3Schema
	openAPI, _, err := openapivalidation.NewSchemaValidator(root)
	if err != nil {
		t.Fatal(err)
	}
	structural, err := schema.NewStructural(root)
	if err != nil {
		t.Fatal(err)
	}
	cel := celvalidation.NewValidator(structural, true, celconfig.PerCallLimit)
	return func(object, old string) field.ErrorList {
		t.Helper()
		var current, previous interface{}
		if err := kubejson.Unmarshal([]byte(object), &current); err != nil {
			t.Fatal(err)
		}
		if old != "" {
			if err := kubejson.Unmarshal([]byte(old), &previous); err != nil {
				t.Fatal(err)
			}
		}
		errs := openapivalidation.ValidateCustomResource(field.NewPath("root"), current, openAPI)
		if len(errs) == 0 {
			celErrors, _ := cel.Validate(context.Background(), field.NewPath("root"), structural, current, previous, celconfig.RuntimeCELCostBudget)
			errs = append(errs, celErrors...)
		}
		return errs
	}
}
