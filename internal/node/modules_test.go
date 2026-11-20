// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package node

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"
)

func TestLoadKernelModules(t *testing.T) {
	loaded := make(map[string]bool, len(kernelModules))
	for _, name := range kernelModules {
		loaded[name] = true
	}
	tests := []struct {
		name     string
		loaded   map[string]bool
		fail     map[string]bool
		probes   []string
		warnings []string
	}{
		{
			name:   "already loaded modules are skipped",
			loaded: loaded,
		},
		{
			name:   "missing modules are probed",
			probes: kernelModules,
		},
		{
			name:     "probe failure logs and continues",
			loaded:   map[string]bool{"configfs": true},
			fail:     map[string]bool{"loop": true, "nvmet_tcp": true},
			probes:   kernelModules[1:],
			warnings: []string{"loop", "nvmet_tcp"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var probes []string
			var buf bytes.Buffer
			log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			loadKernelModules(context.Background(),
				func(name string) bool { return tt.loaded[name] },
				func(name string) error {
					probes = append(probes, name)
					if tt.fail[name] {
						return errors.New("modprobe failed")
					}
					return nil
				}, log)
			if !slices.Equal(probes, tt.probes) {
				t.Fatalf("probed %v, want %v", probes, tt.probes)
			}
			warned := 0
			for _, line := range strings.Split(buf.String(), "\n") {
				if !strings.Contains(line, "level=WARN") {
					continue
				}
				warned++
				if !strings.Contains(line, "module=") || !strings.Contains(line, "kernel=") || !strings.Contains(line, "err=") {
					t.Errorf("warning is missing fields: %s", line)
				}
			}
			if warned != len(tt.warnings) {
				t.Fatalf("warnings = %d, want %d:\n%s", warned, len(tt.warnings), buf.String())
			}
			for _, name := range tt.warnings {
				if !strings.Contains(buf.String(), "module="+name) {
					t.Errorf("warning does not mention module %s:\n%s", name, buf.String())
				}
			}
		})
	}
}
