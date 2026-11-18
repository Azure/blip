package image

import (
	"archive/tar"
	"bytes"
	"io"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
)

// flatten returns the entries writeTar emits for img, in order.
func flatten(t *testing.T, img v1.Image) []entry {
	t.Helper()
	return flattenStream(t, mutate.Extract(img))
}

// flattenStream returns the entries writeTar emits for a tar stream, in order.
func flattenStream(t *testing.T, r io.Reader) []entry {
	t.Helper()
	var buf bytes.Buffer
	if err := writeTar(&buf, r); err != nil {
		t.Fatal(err)
	}
	var out []entry
	tr := tar.NewReader(&buf)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		var body strings.Builder
		if _, err := io.Copy(&body, tr); err != nil {
			t.Fatal(err)
		}
		out = append(out, entry{hdr: *h, body: body.String()})
	}
}

func findEntry(entries []entry, name string) (entry, int) {
	for i, e := range entries {
		if e.hdr.Name == name {
			return e, i
		}
	}
	return entry{}, -1
}

func countEntry(entries []entry, name string) int {
	n := 0
	for _, e := range entries {
		if e.hdr.Name == name {
			n++
		}
	}
	return n
}

// checkParents asserts that every entry follows its parent directories.
func checkParents(t *testing.T, entries []entry) {
	t.Helper()
	seen := map[string]bool{}
	for _, e := range entries {
		if i := strings.LastIndexByte(e.hdr.Name, '/'); i >= 0 {
			if dir := e.hdr.Name[:i]; !seen[dir] {
				t.Errorf("%s comes before its directory %s", e.hdr.Name, dir)
			}
		}
		seen[e.hdr.Name] = true
	}
}

// A Debian-style base layer has /bin -> usr/bin. A later layer adds bin/app
// (Dockerfile: COPY app /bin/app). The file must land at usr/bin/app, because
// mke2fs replaces the real bin directory with the symlink and loses its
// contents otherwise.
func TestFlattenSymlinkedParent(t *testing.T) {
	debian := []entry{
		{hdr: tar.Header{Name: "usr/", Typeflag: tar.TypeDir, Mode: 0o755}},
		{hdr: tar.Header{Name: "usr/bin/", Typeflag: tar.TypeDir, Mode: 0o755}},
		{hdr: tar.Header{Name: "usr/bin/sh", Typeflag: tar.TypeReg, Mode: 0o755}, body: "sh"},
		{hdr: tar.Header{Name: "bin", Typeflag: tar.TypeSymlink, Linkname: "usr/bin"}},
	}
	app := entry{hdr: tar.Header{Name: "bin/app", Typeflag: tar.TypeReg, Mode: 0o755}, body: "app"}

	tests := []struct {
		name    string
		flatten func(t *testing.T) []entry
	}{
		{"across layers", func(t *testing.T) []entry {
			img, err := mutate.AppendLayers(empty.Image, layer(t, debian...), layer(t, app))
			if err != nil {
				t.Fatal(err)
			}
			return flatten(t, img)
		}},
		{"one layer after symlink", func(t *testing.T) []entry {
			return flattenStream(t, bytes.NewReader(tarBytes(t, append(debian, app)...)))
		}},
		{"one layer before symlink", func(t *testing.T) []entry {
			return flattenStream(t, bytes.NewReader(tarBytes(t, append([]entry{app}, debian...)...)))
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entries := tc.flatten(t)

			if n := countEntry(entries, "bin"); n != 1 {
				t.Errorf("tar has %d entries for bin, want 1: %v", n, names(entries))
			}
			bin, _ := findEntry(entries, "bin")
			if bin.hdr.Typeflag != tar.TypeSymlink || bin.hdr.Linkname != "usr/bin" {
				t.Errorf("bin = type %c link %q, want symlink to usr/bin", bin.hdr.Typeflag, bin.hdr.Linkname)
			}
			if n := countEntry(entries, "bin/app"); n != 0 {
				t.Errorf("tar has %d entries for bin/app, want 0: %v", n, names(entries))
			}
			got, i := findEntry(entries, "usr/bin/app")
			if i < 0 {
				t.Fatalf("tar lacks usr/bin/app, the resolved path: %v", names(entries))
			}
			if got.hdr.Typeflag != tar.TypeReg || got.body != "app" {
				t.Errorf("usr/bin/app = type %c body %q, want regular file %q", got.hdr.Typeflag, got.body, "app")
			}
			if sh, _ := findEntry(entries, "usr/bin/sh"); sh.body != "sh" {
				t.Errorf("usr/bin/sh body = %q, want %q", sh.body, "sh")
			}
			checkParents(t, entries)
		})
	}
}

func TestResolvePath(t *testing.T) {
	links := map[string]string{
		"bin":   "usr/bin",
		"lib":   "/usr/lib",
		"lib64": "lib64-arch",
		"run":   "var/run",
		"a":     "b",
		"b":     "a",
	}
	for p, want := range map[string]string{
		"bin/app":         "usr/bin/app",
		"bin/../etc":      "usr/etc",
		"lib/x":           "usr/lib/x",
		"lib64/ld.so":     "lib64-arch/ld.so",
		"run/sock":        "var/run/sock",
		"../bin/app":      "usr/bin/app",
		"bin/../../bin/x": "usr/bin/x",
		"plain/path":      "plain/path",
		"":                "",
	} {
		if got, ok := resolvePath(p, links); !ok || got != want {
			t.Errorf("resolvePath(%q) = %q, %v; want %q, true", p, got, ok, want)
		}
	}
	if got, ok := resolvePath("a/x", links); ok {
		t.Errorf("resolvePath(%q) = %q, true; want a symlink loop", "a/x", got)
	}
}

func names(entries []entry) []string {
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.hdr.Name
	}
	return out
}

// A symlink below a symlinked parent belongs at the resolved parent. The
// locations are a fixed point, because the parent's location is itself the
// result of resolving another symlink.
func TestResolveLinks(t *testing.T) {
	links := resolveLinks([]tarSymlink{
		{name: "var/run", target: "/run"},
		{name: "var/run/bar", target: "baz"},
	})
	want := map[string]string{"var/run": "/run", "run/bar": "baz"}
	if len(links) != len(want) {
		t.Fatalf("resolveLinks = %v, want %v", links, want)
	}
	for k, v := range want {
		if links[k] != v {
			t.Errorf("links[%q] = %q, want %q", k, links[k], v)
		}
	}
	if got, ok := resolvePath("run/bar", links); !ok || got != "run/baz" {
		t.Errorf("resolvePath(%q) = %q, %v; want %q, true", "run/bar", got, ok, "run/baz")
	}
}
