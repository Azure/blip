// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package atomicfile

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestReplaceOS(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state")
	for _, data := range []string{"first", "replacement", ""} {
		if err := Replace(path, []byte(data), 0o640); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != data {
			t.Fatalf("read %q: %v, want %q", got, err, data)
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o640 {
			t.Fatalf("stat %v: %v", info, err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 1 {
			t.Fatalf("temporary file leaked: %v: %v", entries, err)
		}
	}
}

func TestReplaceRenameFailureCleansTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	err := Replace(path, []byte("new"), 0o600)
	var failure *Error
	if !errors.As(err, &failure) || failure.Kind != Rename || failure.Renamed {
		t.Fatalf("want pre-publication rename error, got %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || !entries[0].IsDir() {
		t.Fatalf("destination damaged or temp leaked: %v: %v", entries, err)
	}
}

func TestWriteAndFailureResults(t *testing.T) {
	for _, scenario := range []struct {
		name    string
		fault   Kind
		outcome string
		want    error
		renamed bool
	}{
		{"short writes", Write, "short", nil, true},
		{"zero progress", Write, "zero", io.ErrShortWrite, false},
		{"partial write error", Write, "partial-error", errDisk, false},
		{"create failure", Create, "fail", errDisk, false},
		{"chmod failure", Chmod, "fail", errDisk, false},
		{"sync failure", Sync, "fail", errDisk, false},
		{"close failure", Close, "fail", errDisk, false},
		{"rename failure", Rename, "fail", errDisk, false},
		{"dir sync failure", SyncDir, "fail", errDisk, true},
		{"dir sync ambiguous", SyncDir, "fail-after", errDisk, true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			m := newReplaceModel(true)
			for !m.op.Done() {
				e, _ := m.op.Next()
				outcome := "ok"
				if e.Kind == scenario.fault {
					outcome = scenario.outcome
				}
				if err := m.Step(string(e.Kind) + "/" + outcome); err != nil {
					t.Fatal(err)
				}
				if err := m.Step("complete"); err != nil {
					t.Fatal(err)
				}
				if err := m.Check(); err != nil {
					t.Fatal(err)
				}
			}
			if !errors.Is(m.op.Err(), scenario.want) || m.op.renamed != scenario.renamed {
				t.Fatalf("error=%v renamed=%t", m.op.Err(), m.op.renamed)
			}
			if scenario.want != nil {
				var failure *Error
				if !errors.As(m.op.Err(), &failure) || failure.Renamed != scenario.renamed {
					t.Fatalf("error did not report publication ambiguity: %v", m.op.Err())
				}
			}
			if len(m.disk.Names) != 1 {
				t.Fatalf("failed operation leaked temporary entry: %v", m.disk.Names)
			}
		})
	}
}
