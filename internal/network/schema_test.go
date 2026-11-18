package network

import (
	"context"
	"os"
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
				base := `{"spec":{"image":"busybox","pool":"default"}}`
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
			for _, tt := range []struct {
				name, policy string
				valid        bool
			}{
				{"omitted", ``, true},
				{"deny all", `{}`, true},
				{"allow all", `{"egress":[{}]}`, true},
				{"IPv4 exceptions", `{"egress":[{"to":[{"ipBlock":{"cidr":"10.0.0.0/8","except":["10.1.0.0/16"]}}]}]}`, true},
				{"namespace and pods", `{"egress":[{"to":[{"namespaceSelector":{},"podSelector":{}}]}]}`, true},
				{"namespace and services", `{"egress":[{"to":[{"namespaceSelector":{},"serviceSelector":{}}]}]}`, true},
				{"range", `{"egress":[{"ports":[{"protocol":"UDP","port":53,"endPort":55}]}]}`, true},
				{"empty peer", `{"egress":[{"to":[{}]}]}`, false},
				{"IP and selector", `{"egress":[{"to":[{"ipBlock":{"cidr":"10.0.0.0/8"},"podSelector":{}}]}]}`, false},
				{"pod and service", `{"egress":[{"to":[{"podSelector":{},"serviceSelector":{}}]}]}`, false},
				{"IPv6", `{"egress":[{"to":[{"ipBlock":{"cidr":"fd00::/64"}}]}]}`, false},
				{"bad CIDR", `{"egress":[{"to":[{"ipBlock":{"cidr":"10.0.0.0/99"}}]}]}`, false},
				{"bad exception", `{"egress":[{"to":[{"ipBlock":{"cidr":"10.0.0.0/8","except":["192.0.2.0/24"]}}]}]}`, false},
				{"IPv6 exception", `{"egress":[{"to":[{"ipBlock":{"cidr":"10.0.0.0/8","except":["fd00::/64"]}}]}]}`, false},
				{"no port", `{"egress":[{"ports":[{"protocol":"TCP"}]}]}`, false},
				{"named port", `{"egress":[{"ports":[{"port":"http"}]}]}`, false},
				{"zero port", `{"egress":[{"ports":[{"port":0}]}]}`, false},
				{"large port", `{"egress":[{"ports":[{"port":65536}]}]}`, false},
				{"unsupported protocol", `{"egress":[{"ports":[{"port":80,"protocol":"SCTP"}]}]}`, false},
				{"reversed range", `{"egress":[{"ports":[{"port":80,"endPort":79}]}]}`, false},
			} {
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
