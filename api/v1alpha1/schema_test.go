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
	"k8s.io/apimachinery/pkg/api/resource"
	kubejson "k8s.io/apimachinery/pkg/util/json"
	"k8s.io/apimachinery/pkg/util/validation/field"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
	"sigs.k8s.io/yaml"

	"github.com/Azure/blip/internal/mountpath"
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
	Enum         []string             `json:"enum"`
	MaxLength    int64                `json:"maxLength"`
	Minimum      int64                `json:"minimum"`
	Maximum      int64                `json:"maximum"`
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

// TestBlipStateSizeCRDRule guards the admission rules that reject a zero,
// negative, or too-large BlipState.spec.size. Such sizes otherwise reached the
// node agent and failed with an internal storage error, or were stored and then
// failed terminally by the controller after admission.
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
	maxQuantity := resource.NewQuantity(MaxStateSizeBytes, resource.BinarySI).String()
	wantMax := fmt.Sprintf("type(self) == string ? !quantity(self).isGreaterThan(quantity('%s')) : self <= %d", maxQuantity, MaxStateSizeBytes)
	if rule := ruleFor(t, size.XValidations, "size must be at most 1Ti"); rule != wantMax {
		t.Errorf("size maximum rule %q, want %q", rule, wantMax)
	}

	validate := admissionValidator(t, "blipstates")
	for _, object := range []string{
		`{"spec":{"size":"1Ti"}}`,
		`{"spec":{"size":"1024Gi"}}`,
		`{"spec":{"size":"1099511627776"}}`,
		fmt.Sprintf(`{"spec":{"size":%d}}`, MaxStateSizeBytes),
	} {
		if errs := validate(object, ""); len(errs) != 0 {
			t.Errorf("admission rejected size at the maximum: %s: %v", object, errs.ToAggregate())
		}
	}
	for _, object := range []string{
		`{"spec":{"size":"2Ti"}}`,
		`{"spec":{"size":"1099511627777"}}`,
		fmt.Sprintf(`{"spec":{"size":%d}}`, MaxStateSizeBytes+1),
	} {
		if errs := validate(object, ""); len(errs) == 0 {
			t.Errorf("admission accepted size above the maximum: %s", object)
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
	// split/exists rule blows the per-object admission budget. The bound is
	// the longest path the guest can resolve under its root prefix.
	if path.MaxLength != int64(mountpath.MaxPath) {
		t.Errorf("mount path maxLength %d, want %d", path.MaxLength, mountpath.MaxPath)
	}
	const length = "bytes(self).size() <= 4086"
	if rule := ruleFor(t, path.XValidations, "path must be at most 4086 bytes: Linux PATH_MAX less the guest root prefix"); rule != length {
		t.Errorf("mount path length rule %q, want %q", rule, length)
	}
	const segments = "!self.split('/').exists(s, s == '.' || s == '..')"
	if rule := ruleFor(t, path.XValidations, "path must not contain . or .. segments"); rule != segments {
		t.Errorf("mount path segment rule %q, want %q", rule, segments)
	}
	// NAME_MAX is a byte limit: a 128-character multibyte component is 256
	// bytes and no guest can create it. The split limit and the component
	// cap keep the byte check within the CEL cost budget while still covering
	// every component a path may have.
	const nameMax = "self.split('/', 256).all(s, bytes(s).size() <= 255)"
	if rule := ruleFor(t, path.XValidations, "path components must be at most 255 bytes, the Linux NAME_MAX limit"); rule != nameMax {
		t.Errorf("mount path NAME_MAX rule %q, want %q", rule, nameMax)
	}
	const componentCap = "self.split('/').size() <= 256"
	if rule := ruleFor(t, path.XValidations, "path must have at most 255 components"); rule != componentCap {
		t.Errorf("mount path component cap rule %q, want %q", rule, componentCap)
	}
	const reserved = "!['/proc', '/sys', '/dev', '/run/blip', '/run/blip-collect', '/var/run/blip', '/var/run/blip-collect'].exists(r, self.path == r || self.path.startsWith(r + '/') || r.startsWith(self.path + '/')) || (self.path.startsWith('/run/blip-collect/') && self.path.split('/').size() == 4 && has(self.blipUID) && self.blipUID != '' && (!has(self.writable) || !self.writable))"
	if rule := ruleFor(t, mounts.Items.XValidations, "path must not be at, below, or above a guest-reserved path, except a read-only temporary collect mount"); rule != reserved {
		t.Errorf("mount path reserved rule %q, want %q", rule, reserved)
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

// TestMountPathAdmissionLimits proves admission rejects the same paths the
// guest cannot create. kubectl apply is the documented path for advanced state
// fields, so relying on the CLI preflight let impossible intent become durable.
func TestMountPathAdmissionLimits(t *testing.T) {
	validate := admissionValidator(t, "blipstates")
	object := func(p string) string {
		raw, err := kubejson.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		return `{"spec":{"mounts":[{"state":"data","path":` + string(raw) + `}]}}`
	}
	pathAtLimit := "/" + strings.Repeat(strings.Repeat("b", mountpath.NameMax)+"/", 15) + strings.Repeat("b", 245)
	if len(pathAtLimit) != mountpath.MaxPath {
		t.Fatalf("test path is %d bytes, want %d", len(pathAtLimit), mountpath.MaxPath)
	}
	pathOver := "/" + strings.Repeat(strings.Repeat("b", mountpath.NameMax)+"/", 15) + strings.Repeat("b", 244) + "/c"
	if len(pathOver) != mountpath.MaxPath+1 {
		t.Fatalf("test path is %d bytes, want %d", len(pathOver), mountpath.MaxPath+1)
	}
	componentsAtMax := "/" + strings.Repeat("c/", mountpath.MaxComponents-1) + "c"
	componentsOver := "/" + strings.Repeat("c/", mountpath.MaxComponents) + "c"
	for _, p := range []string{
		"/mnt/a", "/a b/c", "/.hidden", "/a.b/c", "/var/log", "/usr/bin", "/run/data",
		// Directory symlinks are resolved by the guest, so these are legal.
		"/bin", "/usr/lib/ssl/certs",
		"/" + strings.Repeat("a", mountpath.NameMax),
		// NAME_MAX is 255 bytes, so 127 two-byte characters (254 bytes) fit.
		"/" + strings.Repeat("é", 127),
		pathAtLimit,
		componentsAtMax,
	} {
		if errs := validate(object(p), ""); len(errs) != 0 {
			t.Errorf("admission rejected valid mount path (%d bytes): %v", len(p), errs.ToAggregate())
		}
	}
	for _, p := range []string{
		"/" + strings.Repeat("a", mountpath.NameMax+1),
		"/" + strings.Repeat("a", 300),
		// 128 two-byte characters are 256 bytes despite being 128 characters.
		"/" + strings.Repeat("é", 128),
		"/" + strings.Repeat("é", 3000),
		componentsOver,
		pathOver,
		"/" + strings.Repeat("a", mountpath.PathMax-1),
		"/a\x00b",
		"/a\tb",
		"/proc",
		"/proc/cpuinfo",
		"/dev",
		"/run",
		"/run/blip/x",
		"/run/blip-collect",
		// A durable mount (no blipUID) may not use the reserved collect root.
		"/run/blip-collect/data",
		"/run/blip-collect/data/deep",
		// /var/run is the standard image alias of /run.
		"/var/run",
		"/var/run/blip/x",
		"/etc/passwd",
		"/etc/passwd/x",
		"/etc/hosts",
		// /lib is the usr-merge alias of /usr/lib, so this is the image
		// file /usr/lib/os-release under another spelling.
		"/usr/lib/os-release",
		"/usr/lib/os-release/x",
		"/lib/os-release",
		"/lib/os-release/x",
	} {
		if errs := validate(object(p), ""); len(errs) == 0 {
			t.Errorf("admission accepted mount path no guest can create (%d bytes): %q", len(p), p)
		}
	}
	// The controller and the CLI create one temporary, read-only collect
	// mount below the reserved root; that form stays accepted.
	temporaryCollect := `{"spec":{"mounts":[{"state":"data","path":"/run/blip-collect/data","blipUID":"execution-uid"}]}}`
	if errs := validate(temporaryCollect, ""); len(errs) != 0 {
		t.Errorf("admission rejected the temporary collect mount: %v", errs.ToAggregate())
	}
	for _, object := range []string{
		`{"spec":{"mounts":[{"state":"data","path":"/run/blip-collect/data","blipUID":""}]}}`,
		`{"spec":{"mounts":[{"state":"data","path":"/run/blip-collect/data","blipUID":"execution-uid","writable":true}]}}`,
		`{"spec":{"mounts":[{"state":"data","path":"/run/blip-collect/data","writable":true}]}}`,
	} {
		if errs := validate(object, ""); len(errs) == 0 {
			t.Errorf("admission accepted a durable or writable mount at the reserved collect root: %s", object)
		}
	}
	// Every path the shared preflight rejects must also be rejected by the
	// generated schema, or the duplicated lists have drifted.
	for _, p := range append(append([]string{}, mountpath.Reserved...), mountpath.GuestFiles...) {
		if errs := validate(object(p), ""); len(errs) == 0 {
			t.Errorf("admission accepted preflight-rejected reserved path %q", p)
		}
	}
	for _, p := range mountpath.ImageFiles {
		if errs := validate(object(p), ""); len(errs) == 0 {
			t.Errorf("admission accepted preflight-rejected image file %q", p)
		}
	}
}

// TestMountOverlapAdmission proves admission rejects a mount topology the
// controller's validateMounts rejects on every execution: nested paths and
// paths that name one directory only after resolving a known image alias.
// Either shape left a Ready state whose every Blip failed InvalidSpec.
func TestMountOverlapAdmission(t *testing.T) {
	spec := loadCRDSpec(t, "../../deploy/crd/blip.dev_blipstates.yaml")
	mounts, ok := spec.Properties["mounts"]
	if !ok {
		t.Fatal("generated CRD has no spec.mounts")
	}
	ruleFor(t, mounts.XValidations, "mount paths must not overlap")

	validate := admissionValidator(t, "blipstates")
	object := func(paths ...string) string {
		var list []string
		for i, p := range paths {
			raw, err := kubejson.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			list = append(list, fmt.Sprintf(`{"state":"data%d","path":%s}`, i, raw))
		}
		return `{"spec":{"mounts":[` + strings.Join(list, ",") + `]}}`
	}
	for _, paths := range [][]string{
		{"/data", "/data/sub"},
		{"/data/sub", "/data"},
		{"/bin", "/usr/bin"},
		{"/bin/x", "/usr/bin/x"},
		{"/bin/x/sub", "/usr/bin/x"},
		{"/usr/bin/x", "/bin/x/sub"},
		{"/var/mail", "/var/spool/mail"},
		{"/var/mail/x", "/var/spool/mail/x"},
		{"/var/run/x", "/run/x"},
		{"/var/lock/x", "/run/lock/x"},
		{"/lib/x", "/usr/lib/x"},
		{"/lib64/x", "/usr/lib64/x"},
		{"/sbin/x", "/usr/sbin/x"},
	} {
		if errs := validate(object(paths...), ""); len(errs) == 0 {
			t.Errorf("admitted overlapping mount paths %v", paths)
		}
	}
	for _, paths := range [][]string{
		{"/data"},
		{"/bin/x"},
		{"/data", "/other"},
		{"/data", "/data2"},
		{"/var/log", "/var/log2"},
		// Distinct canonical siblings are not an overlap.
		{"/bin/x", "/usr/bin/y"},
		{"/var/mail/x", "/var/spool/mail/y"},
		{"/var/run/x", "/run/y"},
		{"/var/lock/x", "/run/lock/y"},
	} {
		if errs := validate(object(paths...), ""); len(errs) != 0 {
			t.Errorf("rejected distinct mount paths %v: %v", paths, errs.ToAggregate())
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

// TestBlipPoolReservedEndpointNames guards that admission rejects an endpoint
// whose name already names something else in the guest. Such a pool used to be
// accepted, then the controller failed validation on every reconcile, leaving
// empty status and no VMs while Blips waited for a VM indefinitely.
func TestBlipPoolReservedEndpointNames(t *testing.T) {
	spec := loadCRDSpec(t, "../../deploy/crd/blip.dev_blippools.yaml")
	endpoints, ok := spec.Properties["endpoints"]
	if !ok {
		t.Fatal("generated CRD has no spec.endpoints property")
	}
	ruleFor(t, endpoints.XValidations, "endpoint name is reserved")

	validate := admissionValidator(t, "blippools")
	for _, name := range []string{"blip", "kube-apiserver", "localhost"} {
		object := fmt.Sprintf(`{"spec":{"nodeSelector":{"blip.dev/node-pool":"default"},"endpoints":[{"name":%q,"url":"https://whoami.example.com"}]}}`, name)
		if errs := validate(object, ""); len(errs) == 0 {
			t.Errorf("admitted reserved endpoint name %q", name)
		}
	}
	for _, name := range []string{"whoami", "api", "whoami-8443"} {
		object := fmt.Sprintf(`{"spec":{"nodeSelector":{"blip.dev/node-pool":"default"},"endpoints":[{"name":%q,"url":"https://whoami.example.com"}]}}`, name)
		if errs := validate(object, ""); len(errs) != 0 {
			t.Errorf("rejected valid endpoint name %q: %v", name, errs.ToAggregate())
		}
	}
}

// TestBlipStatusPhaseAdmission guards that a status writer cannot store a
// phase no reconcile path understands. Such a phase used to wedge deletion.
func TestBlipStatusPhaseAdmission(t *testing.T) {
	status := loadCRDStatus(t, "../../deploy/crd/blip.dev_blips.yaml")
	phase, ok := status.Properties["phase"]
	if !ok {
		t.Fatal("generated CRD has no status.phase property")
	}
	want := []string{"Pending", "Running", "Saving", "Succeeded", "Failed"}
	if !slices.Equal(phase.Enum, want) {
		t.Errorf("status.phase enum = %v, want %v", phase.Enum, want)
	}
	validate := admissionValidator(t, "blips")
	object := func(p string) string {
		return fmt.Sprintf(`{"spec":{"state":"root","command":["true"]},"status":{"phase":%q}}`, p)
	}
	for _, p := range want {
		if errs := validate(object(p), ""); len(errs) != 0 {
			t.Errorf("rejected documented phase %q: %v", p, errs.ToAggregate())
		}
	}
	for _, p := range []string{"Hacked", "", "pending", "Stopped"} {
		if errs := validate(object(p), ""); len(errs) == 0 {
			t.Errorf("admitted unknown phase %q", p)
		}
	}
}

// TestBlipStateStatusPhaseAdmission guards the state phases the controller
// writes. An unknown phase stored by a status writer has no reconcile path
// that can advance or clean it up.
func TestBlipStateStatusPhaseAdmission(t *testing.T) {
	status := loadCRDStatus(t, "../../deploy/crd/blip.dev_blipstates.yaml")
	phase, ok := status.Properties["phase"]
	if !ok {
		t.Fatal("generated CRD has no status.phase property")
	}
	want := []string{StatePending, StateReady, StateInUse, StateSaving, StateFailed}
	if !slices.Equal(phase.Enum, want) {
		t.Errorf("status.phase enum = %v, want %v", phase.Enum, want)
	}
	validate := admissionValidator(t, "blipstates")
	object := func(p string) string {
		return fmt.Sprintf(`{"spec":{},"status":{"phase":%q}}`, p)
	}
	for _, p := range want {
		if errs := validate(object(p), ""); len(errs) != 0 {
			t.Errorf("rejected documented phase %q: %v", p, errs.ToAggregate())
		}
	}
	for _, p := range []string{"Hacked", "", "pending", "Stopped"} {
		if errs := validate(object(p), ""); len(errs) == 0 {
			t.Errorf("admitted unknown phase %q", p)
		}
	}
}

// TestBlipMountPhaseAdmission guards the mount phases the controller and CLI
// use to decide whether a mount is pending, usable, or saving.
func TestBlipMountPhaseAdmission(t *testing.T) {
	status := loadCRDStatus(t, "../../deploy/crd/blip.dev_blips.yaml")
	mounts, ok := status.Properties["mounts"]
	if !ok || mounts.Items == nil {
		t.Fatal("generated CRD has no status.mounts items schema")
	}
	phase, ok := mounts.Items.Properties["phase"]
	if !ok {
		t.Fatal("generated CRD has no status.mounts items phase property")
	}
	want := []string{MountPending, MountMounted, MountUnmounting, MountSaving, MountFailed}
	if !slices.Equal(phase.Enum, want) {
		t.Errorf("status.mounts.phase enum = %v, want %v", phase.Enum, want)
	}
	validate := admissionValidator(t, "blips")
	object := func(p string) string {
		return fmt.Sprintf(`{"spec":{"state":"root","command":["true"]},"status":{"mounts":[{"state":"root","path":"/m","phase":%q}]}}`, p)
	}
	for _, p := range want {
		if errs := validate(object(p), ""); len(errs) != 0 {
			t.Errorf("rejected documented mount phase %q: %v", p, errs.ToAggregate())
		}
	}
	for _, p := range []string{"Hacked", "", "pending", "Mounted "} {
		if errs := validate(object(p), ""); len(errs) == 0 {
			t.Errorf("admitted unknown mount phase %q", p)
		}
	}
}

// schemaAt walks a generated CRD schema to a property path.
func schemaAt(t *testing.T, root crdSchema, path ...string) crdSchema {
	t.Helper()
	current := root
	for _, name := range path {
		next, ok := current.Properties[name]
		if !ok {
			t.Fatalf("generated CRD has no %s property", strings.Join(path, "."))
		}
		current = next
	}
	return current
}

// TestInt32FieldsBounded guards every int32 field the API generates.
// format: int32 is metadata only: the API server stores 2147483648, and one
// such value makes the controller's cluster-wide typed list/watch decode fail,
// breaking every namespace. Maximums are therefore explicit in the schema.
func TestInt32FieldsBounded(t *testing.T) {
	type int32Field struct {
		crd  string
		root func(*testing.T) crdSchema
		path []string
		min  int64
	}
	const maxInt32 = 2147483647
	root := func(crd string) func(*testing.T) crdSchema {
		return func(t *testing.T) crdSchema { return loadCRDRoot(t, "../../deploy/crd/blip.dev_"+crd+".yaml") }
	}
	for _, tc := range []int32Field{
		{crd: "blips", root: root("blips"), path: []string{"spec", "ttlSecondsAfterFinished"}, min: 0},
		{crd: "blips", root: root("blips"), path: []string{"status", "exitCode"}, min: 0},
		{crd: "blippools", root: root("blippools"), path: []string{"spec", "cpus"}, min: 1},
		{crd: "blippools", root: root("blippools"), path: []string{"spec", "warmCount"}, min: 0},
		{crd: "blippools", root: root("blippools"), path: []string{"spec", "maxCount"}, min: 0},
		{crd: "blippools", root: root("blippools"), path: []string{"status", "ready"}, min: 0},
		{crd: "blippools", root: root("blippools"), path: []string{"status", "vacant"}, min: 0},
		{crd: "blippools", root: root("blippools"), path: []string{"status", "claimed"}, min: 0},
	} {
		field := schemaAt(t, tc.root(t), tc.path...)
		if field.Maximum != maxInt32 {
			t.Errorf("%s %s maximum = %d, want %d", tc.crd, strings.Join(tc.path, "."), field.Maximum, maxInt32)
		}
		if field.Minimum != tc.min {
			t.Errorf("%s %s minimum = %d, want %d", tc.crd, strings.Join(tc.path, "."), field.Minimum, tc.min)
		}
	}
}

// ownerTableDNSName returns a valid DNS-subdomain name of exactly n
// characters, as a service account name would be.
func ownerTableDNSName(n int) string {
	var s string
	for len(s) < n {
		if s != "" {
			s += "."
		}
		s += strings.Repeat("a", min(63, n-len(s)))
	}
	return s
}

// TestInt32AdmissionBoundaries proves admission rejects one past int32 max and
// still accepts the exact maximum.
func TestInt32AdmissionBoundaries(t *testing.T) {
	const tooBig = 2147483648
	blip := admissionValidator(t, "blips")
	for _, tc := range []struct {
		name   string
		object string
	}{
		{"ttl", fmt.Sprintf(`{"spec":{"state":"root","command":["true"],"ttlSecondsAfterFinished":%d}}`, tooBig)},
		{"exitCode", fmt.Sprintf(`{"spec":{"state":"root","command":["true"]},"status":{"exitCode":%d}}`, tooBig)},
	} {
		if errs := blip(tc.object, ""); len(errs) == 0 {
			t.Errorf("admitted out-of-range blip %s", tc.name)
		}
	}
	if errs := blip(`{"spec":{"state":"root","command":["true"],"ttlSecondsAfterFinished":2147483647}}`, ""); len(errs) != 0 {
		t.Errorf("rejected max int32 ttl: %v", errs.ToAggregate())
	}

	pool := admissionValidator(t, "blippools")
	for _, field := range []string{"cpus", "warmCount", "maxCount"} {
		object := fmt.Sprintf(`{"spec":{"nodeSelector":{"blip.dev/node-pool":"default"},"%s":%d}}`, field, tooBig)
		if errs := pool(object, ""); len(errs) == 0 {
			t.Errorf("admitted out-of-range pool spec.%s", field)
		}
	}
}

// TestActiveDeadlineOverflowRejected guards the seconds-to-duration bound.
// The controller multiplies activeDeadlineSeconds by time.Second; a value
// above 9223372036 overflows int64 nanoseconds, wrapped negative, and stopped
// the Blip immediately.
func TestActiveDeadlineOverflowRejected(t *testing.T) {
	spec := loadCRDSpec(t, "../../deploy/crd/blip.dev_blips.yaml")
	deadline := schemaAt(t, crdSchema{Properties: map[string]crdSchema{"spec": spec}}, "spec", "activeDeadlineSeconds")
	if deadline.Maximum != 9223372036 {
		t.Errorf("activeDeadlineSeconds maximum = %d, want 9223372036", deadline.Maximum)
	}

	validate := admissionValidator(t, "blips")
	blip := func(seconds int64) string {
		return fmt.Sprintf(`{"spec":{"state":"root","command":["true"],"activeDeadlineSeconds":%d}}`, seconds)
	}
	if errs := validate(blip(9223372036), ""); len(errs) != 0 {
		t.Errorf("rejected the largest safe deadline: %v", errs.ToAggregate())
	}
	for _, seconds := range []int64{9223372037, 9223372036854775807} {
		if errs := validate(blip(seconds), ""); len(errs) == 0 {
			t.Errorf("admitted overflowing deadline %d", seconds)
		}
	}
}

// TestBlipPoolMemoryMustBePositive guards that a negative or zero guest memory
// fails at admission. A negative value made the Pod request negative (the VMM
// overhead is added), so the pool retried forever with empty status and no
// Event while Blips waited for a VM that could never exist.
func TestBlipPoolMemoryMustBePositive(t *testing.T) {
	spec := loadCRDSpec(t, "../../deploy/crd/blip.dev_blippools.yaml")
	memory, ok := spec.Properties["memory"]
	if !ok {
		t.Fatal("generated CRD has no spec.memory property")
	}
	const rule = "type(self) == string ? quantity(self).isGreaterThan(quantity('0')) : self > 0"
	if got := ruleFor(t, memory.XValidations, "memory must be greater than 0"); got != rule {
		t.Errorf("memory rule %q, want %q", got, rule)
	}

	validate := admissionValidator(t, "blippools")
	for _, value := range []string{`"0"`, `"-1Gi"`, `0`, `-1`} {
		object := fmt.Sprintf(`{"spec":{"nodeSelector":{"blip.dev/node-pool":"default"},"memory":%s}}`, value)
		if errs := validate(object, ""); len(errs) == 0 {
			t.Errorf("admitted pool memory %s", value)
		}
	}
	// Omitted memory is defaulted to 2Gi by the API server; the raw schema test
	// cannot default, and a defaulted object is a valid positive quantity.
	for _, value := range []string{`"2Gi"`, `"512Mi"`, `1`} {
		object := fmt.Sprintf(`{"spec":{"nodeSelector":{"blip.dev/node-pool":"default"},"memory":%s}}`, value)
		if errs := validate(object, ""); len(errs) != 0 {
			t.Errorf("rejected valid pool memory %s: %v", value, errs.ToAggregate())
		}
	}
}

// TestReferenceNamesValidated guards that pool references look like Kubernetes
// object names. Names with '/', spaces, or underscores can never exist, so
// failing at admission avoids a Blip that waits forever for a VM.
func TestReferenceNamesValidated(t *testing.T) {
	blip := admissionValidator(t, "blips")
	for _, pool := range []string{"Bad/Pool", "Bad Pool", "Bad_Pool", ""} {
		object := fmt.Sprintf(`{"spec":{"pool":%q,"state":"root","command":["true"]}}`, pool)
		if errs := blip(object, ""); len(errs) == 0 {
			t.Errorf("admitted blip pool %q", pool)
		}
	}
	for _, pool := range []string{"default", "pool-1", "pool.one"} {
		object := fmt.Sprintf(`{"spec":{"pool":%q,"state":"root","command":["true"]}}`, pool)
		if errs := blip(object, ""); len(errs) != 0 {
			t.Errorf("rejected valid blip pool %q: %v", pool, errs.ToAggregate())
		}
	}
}

// TestStateReferenceNameLimits guards that a reference to a BlipState is no
// longer than a Kubernetes object name. A too-long reference can never name an
// object and used to leave the Blip pending until its start timeout.
func TestStateReferenceNameLimits(t *testing.T) {
	blip := admissionValidator(t, "blips")
	state := admissionValidator(t, "blipstates")
	name := func(n int) string { return strings.Repeat("s", n) }
	for _, n := range []int{253, 254, 300} {
		object := fmt.Sprintf(`{"spec":{"state":%q,"command":["true"]}}`, name(n))
		errs := blip(object, "")
		if n == 253 && len(errs) != 0 {
			t.Errorf("rejected %d-character Blip.spec.state: %v", n, errs.ToAggregate())
		}
		if n != 253 && len(errs) == 0 {
			t.Errorf("admitted %d-character Blip.spec.state", n)
		}
	}
	for _, n := range []int{253, 254, 300} {
		copyFrom := fmt.Sprintf(`{"spec":{"copyFrom":%q}}`, name(n))
		errs := state(copyFrom, "")
		if n == 253 && len(errs) != 0 {
			t.Errorf("rejected %d-character copyFrom: %v", n, errs.ToAggregate())
		}
		if n != 253 && len(errs) == 0 {
			t.Errorf("admitted %d-character copyFrom", n)
		}
		mount := fmt.Sprintf(`{"spec":{"mounts":[{"state":%q,"path":"/m"}]}}`, name(n))
		errs = state(mount, "")
		if n == 253 && len(errs) != 0 {
			t.Errorf("rejected %d-character mount state: %v", n, errs.ToAggregate())
		}
		if n != 253 && len(errs) == 0 {
			t.Errorf("admitted %d-character mount state", n)
		}
	}

	blipSpec := loadCRDSpec(t, "../../deploy/crd/blip.dev_blips.yaml")
	if got := blipSpec.Properties["state"].MaxLength; got != 253 {
		t.Errorf("Blip.spec.state maxLength = %d, want 253", got)
	}
	stateSpec := loadCRDSpec(t, "../../deploy/crd/blip.dev_blipstates.yaml")
	if got := stateSpec.Properties["copyFrom"].MaxLength; got != 253 {
		t.Errorf("BlipState.spec.copyFrom maxLength = %d, want 253", got)
	}
	if got := stateSpec.Properties["mounts"].Items.Properties["state"].MaxLength; got != 253 {
		t.Errorf("BlipState.spec.mounts[].state maxLength = %d, want 253", got)
	}
}

// TestBlipPoolServiceAccountNameFitsOwnerTable guards the same limit on the
// "sa.<name>" key. The field has no DNS pattern, so without a cap a 251-byte
// name was accepted and wedged the owner table.
func TestBlipPoolServiceAccountNameFitsOwnerTable(t *testing.T) {
	spec := loadCRDSpec(t, "../../deploy/crd/blip.dev_blippools.yaml")
	sa, ok := spec.Properties["serviceAccountName"]
	if !ok {
		t.Fatal("generated CRD has no spec.serviceAccountName property")
	}
	if sa.MaxLength != 250 {
		t.Errorf("spec.serviceAccountName maxLength = %d, want 250", sa.MaxLength)
	}

	validate := admissionValidator(t, "blippools")
	for _, n := range []int{0, 63, 250} {
		name := ownerTableDNSName(n)
		object := fmt.Sprintf(`{"spec":{"nodeSelector":{"a":"b"},"serviceAccountName":%q}}`, name)
		if errs := validate(object, ""); len(errs) != 0 {
			t.Errorf("rejected %d-character service account name: %v", n, errs.ToAggregate())
		}
	}
	name := ownerTableDNSName(251)
	object := fmt.Sprintf(`{"spec":{"nodeSelector":{"a":"b"},"serviceAccountName":%q}}`, name)
	if errs := validate(object, ""); len(errs) == 0 {
		t.Errorf("admitted 251-character service account name %q", name)
	}
}

// TestBlipStateEmptyImageIsUnset guards that an explicitly empty image is the
// same as an omitted image, matching the controller's `Image != ""` check. An
// empty image used to be treated as a configured image, forbidding copyFrom
// and replicas and making a real image immutable.
func TestBlipStateEmptyImageIsUnset(t *testing.T) {
	validate := admissionValidator(t, "blipstates")
	for _, object := range []string{
		`{"spec":{"image":""}}`,
		`{"spec":{"image":"","copyFrom":"source"}}`,
		`{"spec":{"image":"","replicas":2}}`,
		`{"spec":{"copyFrom":"source"}}`,
		`{"spec":{"replicas":2}}`,
	} {
		if errs := validate(object, ""); len(errs) != 0 {
			t.Errorf("rejected empty-image state %s: %v", object, errs.ToAggregate())
		}
	}

	// A real image is still exclusive with copyFrom and replicas.
	for _, object := range []string{
		`{"spec":{"image":"busybox:1","copyFrom":"source"}}`,
		`{"spec":{"image":"busybox:1","replicas":2}}`,
	} {
		if errs := validate(object, ""); len(errs) == 0 {
			t.Errorf("admitted %s", object)
		}
	}

	// Empty is interchangeable with absent, and a real image stays immutable.
	for _, tc := range []struct {
		name          string
		before, after string
		ok            bool
	}{
		{"empty to empty", `{"spec":{"image":""}}`, `{"spec":{"image":""}}`, true},
		{"empty to absent", `{"spec":{"image":""}}`, `{"spec":{}}`, true},
		{"absent to empty", `{"spec":{}}`, `{"spec":{"image":""}}`, true},
		{"real unchanged", `{"spec":{"image":"busybox:1"}}`, `{"spec":{"image":"busybox:1"}}`, true},
		{"empty to real", `{"spec":{"image":""}}`, `{"spec":{"image":"busybox:1"}}`, false},
		{"real to empty", `{"spec":{"image":"busybox:1"}}`, `{"spec":{"image":""}}`, false},
		{"real changed", `{"spec":{"image":"busybox:1"}}`, `{"spec":{"image":"busybox:2"}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			errs := validate(tc.after, tc.before)
			if tc.ok && len(errs) != 0 {
				t.Errorf("rejected %s -> %s: %v", tc.before, tc.after, errs.ToAggregate())
			}
			if !tc.ok && len(errs) == 0 {
				t.Errorf("admitted %s -> %s", tc.before, tc.after)
			}
		})
	}

	// nodeSelector and imagePullSecrets are removable when empty, but a real
	// value cannot be removed or changed. copyFrom's pattern already rejects
	// an explicit empty value, so only absent/real transitions apply.
	for _, tc := range []struct {
		name          string
		before, after string
		ok            bool
	}{
		{"copyFrom real to absent", `{"spec":{"copyFrom":"source"}}`, `{"spec":{}}`, false},
		{"copyFrom absent to real", `{"spec":{}}`, `{"spec":{"copyFrom":"source"}}`, false},
		{"copyFrom unchanged", `{"spec":{"copyFrom":"source"}}`, `{"spec":{"copyFrom":"source"}}`, true},
		{"copyFrom changed", `{"spec":{"copyFrom":"source"}}`, `{"spec":{"copyFrom":"other"}}`, false},
		{"nodeSelector empty removed", `{"spec":{"nodeSelector":{}}}`, `{"spec":{}}`, true},
		{"nodeSelector added empty", `{"spec":{}}`, `{"spec":{"nodeSelector":{}}}`, true},
		{"nodeSelector changed", `{"spec":{"nodeSelector":{"a":"b"}}}`, `{"spec":{"nodeSelector":{"a":"c"}}}`, false},
		{"nodeSelector real removed", `{"spec":{"nodeSelector":{"a":"b"}}}`, `{"spec":{}}`, false},
		{"imagePullSecrets empty removed", `{"spec":{"imagePullSecrets":[]}}`, `{"spec":{}}`, true},
		{"imagePullSecrets added empty", `{"spec":{}}`, `{"spec":{"imagePullSecrets":[]}}`, true},
		{"imagePullSecrets changed", `{"spec":{"imagePullSecrets":[{"name":"a"}]}}`, `{"spec":{"imagePullSecrets":[{"name":"b"}]}}`, false},
		{"replicas real removed", `{"spec":{"replicas":2}}`, `{"spec":{}}`, false},
		{"replicas changed", `{"spec":{"replicas":1}}`, `{"spec":{"replicas":2}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			errs := validate(tc.after, tc.before)
			if tc.ok && len(errs) != 0 {
				t.Errorf("rejected %s -> %s: %v", tc.before, tc.after, errs.ToAggregate())
			}
			if !tc.ok && len(errs) == 0 {
				t.Errorf("admitted %s -> %s", tc.before, tc.after)
			}
		})
	}
}
