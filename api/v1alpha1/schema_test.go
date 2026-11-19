package v1alpha1

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

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
	MinItems     int64                `json:"minItems"`
	MaxItems     int64                `json:"maxItems"`
	Required     []string             `json:"required"`
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

// loadCRDRoot reads the generated CRD and returns the v1alpha1 root schema.
func loadCRDRoot(t *testing.T, file string) crdSchema {
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
		if version.Name == "v1alpha1" {
			return version.Schema.OpenAPIV3Schema
		}
	}
	t.Fatalf("%s has no v1alpha1 version", file)
	return crdSchema{}
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

// loadCRDStatus reads the generated CRD and returns the v1alpha1 status schema.
func loadCRDStatus(t *testing.T, file string) crdSchema {
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
		status, ok := version.Schema.OpenAPIV3Schema.Properties["status"]
		if !ok {
			t.Fatalf("%s has no status property", file)
		}
		return status
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

// TestBlipCommandRequired guards that every Blip runs exactly one non-empty
// command: the CRD requires spec.command and rejects an empty list.
func TestBlipCommandRequired(t *testing.T) {
	spec := loadCRDSpec(t, "../../deploy/crd/blip.dev_blips.yaml")
	if !slices.Contains(spec.Required, "command") {
		t.Error("Blip schema does not require spec.command")
	}
	command, ok := spec.Properties["command"]
	if !ok {
		t.Fatal("generated CRD has no spec.command property")
	}
	if command.MinItems != 1 {
		t.Errorf("spec.command minItems %d, want 1", command.MinItems)
	}
	validate := admissionValidator(t, "blips")
	for _, object := range []string{
		`{"spec":{"state":"root"}}`,
		`{"spec":{"state":"root","command":[]}}`,
	} {
		if errs := validate(object, ""); len(errs) == 0 {
			t.Errorf("admitted blip without a command: %s", object)
		}
	}
	if errs := validate(`{"spec":{"state":"root","command":["true"]}}`, ""); len(errs) != 0 {
		t.Fatal(errs.ToAggregate())
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
	root := `{"spec":{"state":"root","command":["true"]}}`
	if errs := validate(root, ""); len(errs) != 0 {
		t.Fatal(errs.ToAggregate())
	}
	if errs := validate(`{"spec":{"state":"other","command":["true"]}}`, root); len(errs) == 0 {
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
		`{"spec":{"copyFrom":"source","mounts":[{"state":"data","path":"/data","blipUID":"execution-uid"}],"runtime":{"env":[{"name":"A","value":"1"}],"workingDir":"/work","user":"1000","network":{}}}}`,
		`{"spec":{"copyFrom":"source","mounts":[{"state":"data","path":"/updated","writable":true}],"runtime":{"env":[{"name":"A","value":"2"}],"workingDir":"/next","user":"1001","network":{"egress":[{}]}}}}`,
	}
	for _, before := range objects {
		for _, after := range objects {
			if errs := validate(after, before); len(errs) != 0 {
				t.Errorf("runtime/mount update rejected: %v", errs.ToAggregate())
			}
		}
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

// TestBlipTurnSchemaCaps guards the bounded turn payload: the engine renders
// every turn into a coordinator step, so text and attributes must stay small.
func TestBlipTurnSchemaCaps(t *testing.T) {
	spec := loadCRDSpec(t, "../../deploy/crd/blip.dev_blipturns.yaml")
	if got := spec.Properties["text"].MaxLength; got != 2048 {
		t.Errorf("spec.text maxLength = %d, want 2048", got)
	}
	if got := spec.Properties["subjects"].MaxLength; got != 0 {
		t.Errorf("spec.subjects unexpectedly has maxLength %d", got)
	}
	if got := spec.Properties["subjects"].MaxItems; got != 8 {
		t.Errorf("spec.subjects maxItems = %d, want 8", got)
	}
	if !slices.Contains(spec.Required, "author") || !slices.Contains(spec.Required, "thread") {
		t.Errorf("spec required = %v, want author and thread", spec.Required)
	}
	ruleFor(t, spec.Properties["attributes"].XValidations, "attribute keys are at most 63 and values at most 256 characters")
}

// TestBlipTurnThreadNamePattern guards that spec.thread can only name a
// BlipThread. Without the pattern an ordinary typo (a trailing space) created
// a turn that no thread could ever claim.
func TestBlipTurnThreadNamePattern(t *testing.T) {
	spec := loadCRDSpec(t, "../../deploy/crd/blip.dev_blipturns.yaml")
	thread, ok := spec.Properties["thread"]
	if !ok {
		t.Fatal("generated CRD has no spec.thread property")
	}
	re, err := regexp.Compile(thread.Pattern)
	if err != nil {
		t.Fatalf("compile thread pattern %q: %v", thread.Pattern, err)
	}
	for _, good := range []string{"project", "a.b", "a-1", "team.chat-2"} {
		if !re.MatchString(good) {
			t.Errorf("thread name %q rejected", good)
		}
	}
	for _, bad := range []string{"", "project ", " project", "Project", "proj_ect", "a..b", "-a"} {
		if re.MatchString(bad) {
			t.Errorf("thread name %q accepted", bad)
		}
	}

	validate := admissionValidator(t, "blipturns")
	if errs := validate(`{"spec":{"thread":"project ","author":{"kind":"ServiceAccount","name":"ci"}}}`, ""); len(errs) == 0 {
		t.Error("admitted a turn whose thread name cannot exist")
	}
	if errs := validate(`{"spec":{"thread":"project","author":{"kind":"ServiceAccount","name":"ci"}}}`, ""); len(errs) != 0 {
		t.Fatal(errs.ToAggregate())
	}
}

// TestBlipTurnImmutable guards that a producer cannot rewrite history.
func TestBlipTurnImmutable(t *testing.T) {
	data, err := os.ReadFile("../../deploy/crd/blip.dev_blipturns.yaml")
	if err != nil {
		t.Fatalf("read generated CRD: %v", err)
	}
	if !strings.Contains(string(data), "self.spec == oldSelf.spec") {
		t.Error("BlipTurn CRD does not make spec immutable")
	}
}

// TestBlipThreadDurationRules guards admission of every duration in
// BlipThread.spec. The typed client decodes metav1.Duration while watching
// threads, so one malformed value used to break the informer for every thread
// and stall blipchat in all namespaces.
func TestBlipThreadDurationRules(t *testing.T) {
	spec := loadCRDSpec(t, "../../deploy/crd/blip.dev_blipthreads.yaml")
	retention, ok := spec.Properties["retention"]
	if !ok {
		t.Fatal("generated CRD has no spec.retention property")
	}
	const want = "duration(self) >= duration('0s')"
	for _, tc := range []struct {
		field   crdSchema
		message string
	}{
		{spec.Properties["heartbeat"], "heartbeat must be a non-negative duration"},
		{retention.Properties["turns"], "retention.turns must be a non-negative duration"},
		{retention.Properties["closedTasks"], "retention.closedTasks must be a non-negative duration"},
	} {
		if got := ruleFor(t, tc.field.XValidations, tc.message); got != want {
			t.Errorf("%s rule %q, want %q", tc.message, got, want)
		}
	}

	validate := admissionValidator(t, "blipthreads")
	for _, object := range []string{
		`{"spec":{"pool":"p","heartbeat":"not-a-duration"}}`,
		`{"spec":{"pool":"p","heartbeat":"-1s"}}`,
		`{"spec":{"pool":"p","retention":{"turns":"bogus"}}}`,
		`{"spec":{"pool":"p","retention":{"turns":"-1h"}}}`,
		`{"spec":{"pool":"p","retention":{"closedTasks":"bogus"}}}`,
		`{"spec":{"pool":"p","retention":{"closedTasks":"-5m"}}}`,
	} {
		if errs := validate(object, ""); len(errs) == 0 {
			t.Errorf("admitted thread with an invalid duration: %s", object)
		}
	}
	for _, object := range []string{
		`{"spec":{"pool":"p"}}`,
		`{"spec":{"pool":"p","heartbeat":"0s"}}`,
		`{"spec":{"pool":"p","heartbeat":"30m"}}`,
		`{"spec":{"pool":"p","retention":{"turns":"168h","closedTasks":"72h"}}}`,
	} {
		if errs := validate(object, ""); len(errs) != 0 {
			t.Errorf("rejected thread with a valid duration: %s: %v", object, errs.ToAggregate())
		}
	}
}

// TestBlipThreadSpecRequired guards that every thread has a spec. Without the
// root requirement Kubernetes accepts an object with no spec at all and skips
// the nested required fields, so required spec.pool could be bypassed.
func TestBlipThreadSpecRequired(t *testing.T) {
	root := loadCRDRoot(t, "../../deploy/crd/blip.dev_blipthreads.yaml")
	if !slices.Contains(root.Required, "spec") {
		t.Errorf("BlipThread schema required = %v, want spec", root.Required)
	}
	validate := admissionValidator(t, "blipthreads")
	for _, object := range []string{
		`{}`,
		`{"metadata":{"name":"thread"}}`,
		`{"spec":{}}`,
		`{"spec":{"retention":{}}}`,
	} {
		if errs := validate(object, ""); len(errs) == 0 {
			t.Errorf("admitted thread without spec.pool: %s", object)
		}
	}
	for _, object := range []string{
		`{"spec":{"pool":"p"}}`,
		`{"spec":{"pool":"p","heartbeat":"30m"}}`,
	} {
		if errs := validate(object, ""); len(errs) != 0 {
			t.Errorf("rejected thread with a valid spec: %s: %v", object, errs.ToAggregate())
		}
	}
}

// TestBlipThreadTaskIDPattern guards that task ids are safe to use as labels.
func TestBlipThreadTaskIDPattern(t *testing.T) {
	status := loadCRDStatus(t, "../../deploy/crd/blip.dev_blipthreads.yaml")
	tasks, ok := status.Properties["tasks"]
	if !ok || tasks.Items == nil {
		t.Fatal("generated CRD has no status.tasks schema")
	}
	id, ok := tasks.Items.Properties["id"]
	if !ok {
		t.Fatal("generated CRD has no status.tasks[].id schema")
	}
	re, err := regexp.Compile(id.Pattern)
	if err != nil {
		t.Fatalf("compile task id pattern: %v", err)
	}
	for _, good := range []string{"t1", "auth-2", "a"} {
		if !re.MatchString(good) {
			t.Errorf("task id %q rejected", good)
		}
	}
	for _, bad := range []string{"T1", "a_b", "-a", "a-"} {
		if re.MatchString(bad) {
			t.Errorf("task id %q accepted", bad)
		}
	}
	if id.MaxLength != 16 {
		t.Errorf("task id maxLength = %d, want 16", id.MaxLength)
	}
}
