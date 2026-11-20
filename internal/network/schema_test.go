// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package network

import (
	"context"
	"os"
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

// Validate generated schemas with the same structural/CEL checks used by the
// API server, including static CEL cost limits and transition-rule validity.
func TestGeneratedNetworkCRDsAreValid(t *testing.T) {
	for _, name := range []string{"blips", "blippools"} {
		t.Run(name, func(t *testing.T) {
			crd := readCRD(t, name)
			if errs := crdvalidation.ValidateCustomResourceDefinition(context.Background(), crd); len(errs) != 0 {
				t.Fatal(errs.ToAggregate())
			}
		})
	}
}

// TestSelectorFieldsAreGone ensures the API cannot silently prune a selector
// and leave an empty but valid peer. Selector support was removed on purpose.
func TestSelectorFieldsAreGone(t *testing.T) {
	for _, name := range []string{"blips", "blippools"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile("../../deploy/crd/blip.dev_" + name + ".yaml")
			if err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"podSelector", "namespaceSelector", "serviceSelector"} {
				if strings.Contains(string(data), field) {
					t.Errorf("CRD still documents %s", field)
				}
			}
		})
	}
}

// TestPoolDNSAdmission validates spec.dns on a pool. The resolvers are
// rejected unless every entry is a bare IPv4 address.
func TestPoolDNSAdmission(t *testing.T) {
	root := readCRD(t, "blippools").Spec.Validation.OpenAPIV3Schema
	openAPI, _, err := openapivalidation.NewSchemaValidator(root)
	if err != nil {
		t.Fatal(err)
	}
	structural, err := schema.NewStructural(root)
	if err != nil {
		t.Fatal(err)
	}
	cel := celvalidation.NewValidator(structural, true, celconfig.PerCallLimit)
	validate := func(nameservers []interface{}) field.ErrorList {
		obj := map[string]interface{}{"spec": map[string]interface{}{
			"nodeSelector": map[string]interface{}{"role": "worker"},
			"dns":          map[string]interface{}{"nameservers": nameservers},
		}}
		errs := openapivalidation.ValidateCustomResource(field.NewPath("root"), obj, openAPI)
		if len(errs) != 0 {
			return errs
		}
		celErrors, _ := cel.Validate(context.Background(), field.NewPath("root"), structural, obj, nil, celconfig.RuntimeCELCostBudget)
		return celErrors
	}
	for _, tt := range []struct {
		name        string
		nameservers []interface{}
		valid       bool
	}{
		{"public", []interface{}{"1.1.1.1", "8.8.8.8"}, true},
		{"private", []interface{}{"10.96.0.10"}, true},
		{"IPv6", []interface{}{"2606:4700:4700::1111"}, false},
		{"prefix", []interface{}{"1.1.1.1/32"}, false},
		{"hostname", []interface{}{"dns.example.com"}, false},
		{"too many", []interface{}{"1.1.1.1", "1.0.0.1", "8.8.8.8", "9.9.9.9"}, false},
		{"empty list", []interface{}{}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := len(validate(tt.nameservers)) == 0; got != tt.valid {
				t.Fatalf("valid = %v, want %v", got, tt.valid)
			}
		})
	}
}

// TestNetworkIPBlockRuleCompatibleWithKubernetes131 guards admission for the
// exception rule on Kubernetes 1.31. Running the v0.33 CEL libraries (as the
// test above does) does not catch the 1.31 containsCIDR bug: v0.31 compares an
// unmasked PrefixFrom(exceptionAddr, parentBits) and so rejects exceptions such
// as 10.1.0.0/16 inside 10.0.0.0/8. Assert the generated rule keeps using
// containsIP, which masks before comparing.
func TestNetworkIPBlockRuleCompatibleWithKubernetes131(t *testing.T) {
	for _, name := range []string{"blips", "blippools"} {
		t.Run(name, func(t *testing.T) {
			var rules []string
			var walk func(*apiextensions.JSONSchemaProps)
			walk = func(s *apiextensions.JSONSchemaProps) {
				if s == nil {
					return
				}
				for _, validation := range s.XValidations {
					if validation.Message == "exceptions must be IPv4 CIDRs strictly inside cidr" {
						rules = append(rules, validation.Rule)
					}
				}
				for name := range s.Properties {
					property := s.Properties[name]
					walk(&property)
				}
				if s.Items != nil {
					walk(s.Items.Schema)
					for i := range s.Items.JSONSchemas {
						walk(&s.Items.JSONSchemas[i])
					}
				}
				if s.AdditionalProperties != nil {
					walk(s.AdditionalProperties.Schema)
				}
				for i := range s.AllOf {
					walk(&s.AllOf[i])
				}
				for i := range s.AnyOf {
					walk(&s.AnyOf[i])
				}
				for i := range s.OneOf {
					walk(&s.OneOf[i])
				}
				walk(s.Not)
			}
			walk(readCRD(t, name).Spec.Validation.OpenAPIV3Schema)

			if len(rules) != 1 {
				t.Fatalf("found %d exception rules, want 1", len(rules))
			}
			rule := rules[0]
			if strings.Contains(rule, "containsCIDR") {
				t.Errorf("rule uses containsCIDR, which is broken before Kubernetes 1.32: %s", rule)
			}
			if !strings.Contains(rule, "containsIP(cidr(c).ip())") {
				t.Errorf("rule does not check containment with containsIP: %s", rule)
			}
			if !strings.Contains(rule, "cidr(c).prefixLength() > cidr(self.cidr).prefixLength()") {
				t.Errorf("rule does not require a strictly longer exception prefix: %s", rule)
			}
		})
	}
}

func TestNetworkAdmissionAndLiveUpdates(t *testing.T) {
	for _, name := range []string{"blips", "blippools"} {
		t.Run(name, func(t *testing.T) {
			root := readCRD(t, name).Spec.Validation.OpenAPIV3Schema
			openAPI, _, err := openapivalidation.NewSchemaValidator(root)
			if err != nil {
				t.Fatal(err)
			}
			structural, err := schema.NewStructural(root)
			if err != nil {
				t.Fatal(err)
			}
			cel := celvalidation.NewValidator(structural, true, celconfig.PerCallLimit)
			object := func(network string) map[string]interface{} {
				base := `{"spec":{"state":"root","pool":"default","command":["true"]}}`
				if name == "blippools" {
					base = `{"spec":{"nodeSelector":{"role":"worker"}}}`
				}
				var obj map[string]interface{}
				if err := kubejson.Unmarshal([]byte(base), &obj); err != nil {
					t.Fatal(err)
				}
				if network != "" {
					var value interface{}
					if err := kubejson.Unmarshal([]byte(network), &value); err != nil {
						t.Fatal(err)
					}
					obj["spec"].(map[string]interface{})["network"] = value
				}
				return obj
			}
			validate := func(obj, old map[string]interface{}) field.ErrorList {
				errs := openapivalidation.ValidateCustomResource(field.NewPath("root"), obj, openAPI)
				if len(errs) == 0 {
					var previous interface{}
					if old != nil {
						previous = old
					}
					celErrors, _ := cel.Validate(context.Background(), field.NewPath("root"), structural, obj, previous, celconfig.RuntimeCELCostBudget)
					errs = append(errs, celErrors...)
				}
				return errs
			}
			cases := []struct {
				name, policy string
				valid        bool
			}{
				{"omitted", ``, true},
				{"deny all", `{}`, true},
				{"allow all", `{"egress":[{}]}`, true},
				{"IPv4 exceptions", `{"egress":[{"to":[{"ipBlock":{"cidr":"10.0.0.0/8","except":["10.1.0.0/16"]}}]}]}`, true},
				{"IPv4 exception at parent network address", `{"egress":[{"to":[{"ipBlock":{"cidr":"10.0.0.0/8","except":["10.0.0.0/16"]}}]}]}`, true},
				{"all but private", `{"egress":[{"to":[{"ipBlock":{"cidr":"0.0.0.0/0","except":["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","169.254.0.0/16"]}}]}]}`, true},
				{"range", `{"egress":[{"ports":[{"protocol":"UDP","port":53,"endPort":55}]}]}`, true},
				{"empty peer", `{"egress":[{"to":[{}]}]}`, false},
				{"pod selector", `{"egress":[{"to":[{"podSelector":{}}]}]}`, false},
				{"namespace selector", `{"egress":[{"to":[{"namespaceSelector":{}}]}]}`, false},
				{"service selector", `{"egress":[{"to":[{"serviceSelector":{}}]}]}`, false},
				{"IPv6", `{"egress":[{"to":[{"ipBlock":{"cidr":"fd00::/64"}}]}]}`, false},
				{"bad CIDR", `{"egress":[{"to":[{"ipBlock":{"cidr":"10.0.0.0/99"}}]}]}`, false},
				{"bad exception", `{"egress":[{"to":[{"ipBlock":{"cidr":"10.0.0.0/8","except":["192.0.2.0/24"]}}]}]}`, false},
				{"equal exception", `{"egress":[{"to":[{"ipBlock":{"cidr":"10.0.0.0/8","except":["10.0.0.0/8"]}}]}]}`, false},
				{"less specific exception", `{"egress":[{"to":[{"ipBlock":{"cidr":"10.1.0.0/16","except":["10.0.0.0/8"]}}]}]}`, false},
				{"IPv6 exception", `{"egress":[{"to":[{"ipBlock":{"cidr":"10.0.0.0/8","except":["fd00::/64"]}}]}]}`, false},
				{"malformed exception", `{"egress":[{"to":[{"ipBlock":{"cidr":"10.0.0.0/8","except":["10.1.0.0/99"]}}]}]}`, false},
				{"no port", `{"egress":[{"ports":[{"protocol":"TCP"}]}]}`, false},
				{"named port", `{"egress":[{"ports":[{"port":"http"}]}]}`, false},
				{"zero port", `{"egress":[{"ports":[{"port":0}]}]}`, false},
				{"large port", `{"egress":[{"ports":[{"port":65536}]}]}`, false},
				{"unsupported protocol", `{"egress":[{"ports":[{"port":80,"protocol":"SCTP"}]}]}`, false},
				{"reversed range", `{"egress":[{"ports":[{"port":80,"endPort":79}]}]}`, false},
			}
			for _, tt := range cases {
				t.Run(tt.name, func(t *testing.T) {
					obj := object(tt.policy)
					errs := validate(obj, nil)
					if (len(errs) == 0) != tt.valid {
						t.Fatalf("valid = %v, want %v: %v", len(errs) == 0, tt.valid, errs.ToAggregate())
					}
					if tt.valid {
						// Network can be added, changed, and removed on a live object.
						for _, old := range []map[string]interface{}{object(""), object(`{"egress":[{}]}`)} {
							if errs := validate(obj, old); len(errs) != 0 {
								t.Fatalf("network update rejected: %v", errs.ToAggregate())
							}
						}
					}
				})
			}
		})
	}
}

func readCRD(t *testing.T, name string) *apiextensions.CustomResourceDefinition {
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
	return &crd
}
