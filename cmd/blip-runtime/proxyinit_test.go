// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"os"
	"path/filepath"
	"testing"

	"sigs.k8s.io/yaml"
)

func readPlaceholder(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Resources []struct {
			Name          string `json:"name"`
			GenericSecret struct {
				Secret struct {
					InlineString string `json:"inline_string"`
				} `json:"secret"`
			} `json:"generic_secret"`
		} `json:"resources"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("placeholder is not valid YAML: %v\n%s", err, data)
	}
	if len(doc.Resources) != 1 {
		t.Fatalf("%s has %d resources", path, len(doc.Resources))
	}
	if got := doc.Resources[0].GenericSecret.Secret.InlineString; got != "Bearer -" {
		t.Errorf("placeholder credential = %q", got)
	}
	return doc.Resources[0].Name
}

func TestProxyInitSeedsWithoutClobbering(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "creds")
	names := []string{"kube-apiserver", "whoami", ""}
	if err := runProxyInit(dir, names); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"kube-apiserver", "whoami"} {
		path := filepath.Join(dir, name+".yaml")
		if got := readPlaceholder(t, path); got != name {
			t.Errorf("%s resource name = %q", name, got)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o440 {
			t.Errorf("%s mode = %o, want 440", name, info.Mode().Perm())
		}
	}
	if _, err := os.Stat(filepath.Join(dir, ".yaml")); !os.IsNotExist(err) {
		t.Errorf("empty name produced a file: %v", err)
	}

	// A restart must not overwrite a token the node agent already wrote.
	path := filepath.Join(dir, "whoami.yaml")
	real := []byte("real token\n")
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, real, 0o440); err != nil {
		t.Fatal(err)
	}
	if err := runProxyInit(dir, names); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(real) {
		t.Errorf("existing credential was overwritten: %q", got)
	}
}

func TestProxyInitRequiresDir(t *testing.T) {
	if err := runProxyInit("", nil); err == nil {
		t.Fatal("missing directory was accepted")
	}
}
