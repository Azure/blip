package controller

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"slices"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"
)

// blipchatClusterRole returns the shipped blipchat ClusterRole.
func blipchatClusterRole(t *testing.T) *rbacv1.ClusterRole {
	t.Helper()
	raw, err := os.ReadFile("../../deploy/base/blipchat.yaml")
	if err != nil {
		t.Fatal(err)
	}
	r := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(raw)))
	for {
		doc, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(doc, []byte("kind: ClusterRole")) {
			continue
		}
		var role rbacv1.ClusterRole
		if err := yaml.UnmarshalStrict(doc, &role); err != nil {
			t.Fatal(err)
		}
		if role.Name == "blipchat" {
			return &role
		}
	}
	t.Fatal("blipchat ClusterRole not found")
	return nil
}

// A BlipThread's spec is administrator-owned. blipchat reads threads and
// writes only their status, so its ClusterRole must not grant update or patch
// on the resource itself: a compromised coordinator could otherwise rewrite
// every project's charter, system prompt, pool and base.
func TestBlipchatRBACThreadsReadOnly(t *testing.T) {
	role := blipchatClusterRole(t)
	verbs := func(resource string) []string {
		var out []string
		for _, rule := range role.Rules {
			if !slices.Contains(rule.APIGroups, "blip.dev") {
				continue
			}
			if slices.Contains(rule.Resources, "*") {
				t.Errorf("blipchat has a wildcard blip.dev rule: %+v", rule)
			}
			if slices.Contains(rule.Resources, resource) {
				out = append(out, rule.Verbs...)
			}
		}
		slices.Sort(out)
		return slices.Compact(out)
	}

	if got, want := verbs("blipthreads"), []string{"get", "list", "watch"}; !slices.Equal(got, want) {
		t.Errorf("blipchat blipthreads verbs = %v, want %v", got, want)
	}
	if got, want := verbs("blipthreads/status"), []string{"get", "patch", "update"}; !slices.Equal(got, want) {
		t.Errorf("blipchat blipthreads/status verbs = %v, want %v", got, want)
	}
}
