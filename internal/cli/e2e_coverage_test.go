// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

// e2eUncovered lists CLI flags that the kind e2e suite deliberately does not
// exercise, with the reason. Every other flag must appear in a `blip CMD`
// invocation under hack/e2e/.
var e2eUncovered = map[string]string{
	"kubeconfig": "the suite selects the cluster with --context",
	"context":    "the blip wrapper in hack/e2e.sh always passes it",
	"namespace":  "the suite runs in the default namespace",
}

// TestE2ECoversEveryFlag keeps the e2e suite in step with the CLI: adding a
// command or flag without an end-to-end test fails here.
func TestE2ECoversEveryFlag(t *testing.T) {
	calls := e2eInvocations(t)
	root := NewCommand(&Env{})
	check := func(cmd string, f *pflag.Flag) {
		if _, ok := e2eUncovered[f.Name]; ok {
			return
		}
		long := regexp.MustCompile(`(^|\s)--` + regexp.QuoteMeta(f.Name) + `(\s|=|$)`)
		short := regexp.MustCompile(`(^|\s)-` + regexp.QuoteMeta(f.Shorthand) + `(\s|$)`)
		for _, c := range calls[cmd] {
			if long.MatchString(c) || (f.Shorthand != "" && short.MatchString(c)) {
				return
			}
		}
		t.Errorf("no e2e scenario in hack/e2e runs `blip %s --%s`; add one or list it in e2eUncovered", cmd, f.Name)
	}
	root.PersistentFlags().VisitAll(func(f *pflag.Flag) { check("", f) })
	for _, sub := range root.Commands() {
		name := sub.Name()
		if len(calls[name]) == 0 {
			t.Errorf("no e2e scenario in hack/e2e runs `blip %s`", name)
			continue
		}
		sub.LocalFlags().VisitAll(func(f *pflag.Flag) {
			if f.Name != "help" {
				check(name, f)
			}
		})
	}
}

// e2eInvocations returns the e2e scripts' blip command lines by subcommand,
// with shell line continuations joined. The "" key holds every invocation.
func e2eInvocations(t *testing.T) map[string][]string {
	t.Helper()
	files, err := filepath.Glob("../../hack/e2e/*.sh")
	if err != nil || len(files) == 0 {
		t.Fatalf("no e2e scripts found: %v", err)
	}
	call := regexp.MustCompile(`(?:^|[\s;(|&$'"])blip(?:_shell\s+\S+)?\s+(.*)`)
	calls := map[string][]string{}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		text := regexp.MustCompile(`\\\n\s*`).ReplaceAllString(string(data), " ")
		for _, line := range strings.Split(text, "\n") {
			m := call.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			args := m[1]
			calls[""] = append(calls[""], args)
			if strings.Contains(m[0], "blip_shell") {
				calls["run"] = append(calls["run"], args)
				continue
			}
			if fields := strings.Fields(args); len(fields) > 0 {
				calls[fields[0]] = append(calls[fields[0]], args)
			}
		}
	}
	return calls
}
