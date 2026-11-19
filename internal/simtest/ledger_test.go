// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package simtest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSimulationTestsAreInTestSimTarget keeps the focused race target in sync
// with the component models. A simulation test that is not listed there would
// still run in `go test ./...`, but would silently lose the race-detector and
// nightly campaign coverage.
func TestSimulationTestsAreInTestSimTarget(t *testing.T) {
	makefile, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	docs, err := os.ReadFile("../../docs/simulation.md")
	if err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob("../../internal/*/simulation_test.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no component simulation tests found")
	}
	for _, file := range files {
		dir := filepath.ToSlash(filepath.Dir(file))
		pkg := "./" + strings.TrimPrefix(dir, "../../")
		if !strings.Contains(string(makefile), pkg) {
			t.Errorf("%s is not listed in the test-sim target", pkg)
		}
		if !strings.Contains(string(docs), strings.TrimPrefix(pkg, "./")) {
			t.Errorf("%s has no coverage-map row", pkg)
		}
	}
}
