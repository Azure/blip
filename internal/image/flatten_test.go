// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package image

import (
	"archive/tar"
	"bytes"
	"io"
	"math/rand/v2"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
)

// flatten returns the entries writeTarTo emits for img, in order.
func flatten(t *testing.T, img v1.Image) []entry {
	t.Helper()
	return flattenStream(t, mutate.Extract(img))
}

// flattenStream returns the entries writeTarTo emits for a tar stream, in order.
func flattenStream(t *testing.T, r io.Reader) []entry {
	t.Helper()
	var buf bytes.Buffer
	if err := writeTarTo(&buf, r, t.TempDir()); err != nil {
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
// TestFlattenUniqueEntriesOrderIndependent shuffles unique directory and file
// entries from one layer. Duplicate paths would make first-wins precedence
// meaningful, so this test only uses unique paths; siblings may still be
// emitted in any order.
func TestFlattenUniqueEntriesOrderIndependent(t *testing.T) {
	base := []entry{
		{hdr: tar.Header{Name: "etc/", Typeflag: tar.TypeDir, Mode: 0o755}},
		{hdr: tar.Header{Name: "etc/hostname", Typeflag: tar.TypeReg}, body: "blip"},
		{hdr: tar.Header{Name: "usr/", Typeflag: tar.TypeDir, Mode: 0o755}},
		{hdr: tar.Header{Name: "usr/bin/", Typeflag: tar.TypeDir, Mode: 0o755}},
		{hdr: tar.Header{Name: "usr/bin/sh", Typeflag: tar.TypeReg, Mode: 0o755}, body: "sh"},
		{hdr: tar.Header{Name: "var/lib/", Typeflag: tar.TypeDir, Mode: 0o755}},
		{hdr: tar.Header{Name: "var/lib/data", Typeflag: tar.TypeReg}, body: "data"},
	}
	for seed := uint64(0); seed < 20; seed++ {
		shuffled := append([]entry(nil), base...)
		rng := rand.New(rand.NewPCG(seed, 0x5eed))
		rng.Shuffle(len(shuffled), func(i, j int) {
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		})
		got := flattenStream(t, bytes.NewReader(tarBytes(t, shuffled...)))
		checkParents(t, got)
		for _, want := range base {
			if n := countEntry(got, strings.TrimSuffix(want.hdr.Name, "/")); n != 1 {
				t.Fatalf("seed %d: entry %q emitted %d times", seed, want.hdr.Name, n)
			}
		}
	}
}

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

// A higher layer can replace a lower layer's symlink with a real directory.
// The shadowed symlink must not move the higher layer's children to its old
// target.
func TestFlattenSymlinkShadowedByDirectory(t *testing.T) {
	// writeTarTo sees the top layer first: the real directory and its child
	// come before the lower layer that still has the old symlink.
	entries := flattenStream(t, bytes.NewReader(tarBytes(t,
		entry{hdr: tar.Header{Name: "bin/", Typeflag: tar.TypeDir, Mode: 0o755}},
		entry{hdr: tar.Header{Name: "bin/app", Typeflag: tar.TypeReg, Mode: 0o755}, body: "app"},
		entry{hdr: tar.Header{Name: "usr/", Typeflag: tar.TypeDir, Mode: 0o755}},
		entry{hdr: tar.Header{Name: "usr/bin/", Typeflag: tar.TypeDir, Mode: 0o755}},
		entry{hdr: tar.Header{Name: "bin", Typeflag: tar.TypeSymlink, Linkname: "usr/bin"}},
	)))

	if n := countEntry(entries, "bin"); n != 1 {
		t.Errorf("tar has %d entries for bin, want 1: %v", n, names(entries))
	}
	bin, _ := findEntry(entries, "bin")
	if bin.hdr.Typeflag != tar.TypeDir {
		t.Errorf("bin = type %c, want a directory", bin.hdr.Typeflag)
	}
	if n := countEntry(entries, "usr/bin/app"); n != 0 {
		t.Errorf("tar has %d entries for usr/bin/app, want 0: %v", n, names(entries))
	}
	app, i := findEntry(entries, "bin/app")
	if i < 0 {
		t.Fatalf("tar lacks bin/app, the higher layer's path: %v", names(entries))
	}
	if app.hdr.Typeflag != tar.TypeReg || app.body != "app" {
		t.Errorf("bin/app = type %c body %q, want regular file %q", app.hdr.Typeflag, app.body, "app")
	}
	checkParents(t, entries)
}

// Without a bin entry of its own, the higher layer does not shadow the lower
// layer's symlink, so its child is still resolved through it.
func TestFlattenSymlinkFromLowerLayer(t *testing.T) {
	// The higher layer has no bin entry of its own, so the lower layer's
	// symlink is still the winner for bin.
	entries := flattenStream(t, bytes.NewReader(tarBytes(t,
		entry{hdr: tar.Header{Name: "bin/app", Typeflag: tar.TypeReg, Mode: 0o755}, body: "app"},
		entry{hdr: tar.Header{Name: "usr/", Typeflag: tar.TypeDir, Mode: 0o755}},
		entry{hdr: tar.Header{Name: "usr/bin/", Typeflag: tar.TypeDir, Mode: 0o755}},
		entry{hdr: tar.Header{Name: "bin", Typeflag: tar.TypeSymlink, Linkname: "usr/bin"}},
	)))

	bin, _ := findEntry(entries, "bin")
	if bin.hdr.Typeflag != tar.TypeSymlink || bin.hdr.Linkname != "usr/bin" {
		t.Errorf("bin = type %c link %q, want symlink to usr/bin", bin.hdr.Typeflag, bin.hdr.Linkname)
	}
	if n := countEntry(entries, "bin/app"); n != 0 {
		t.Errorf("tar has %d entries for bin/app, want 0: %v", n, names(entries))
	}
	app, i := findEntry(entries, "usr/bin/app")
	if i < 0 {
		t.Fatalf("tar lacks usr/bin/app, the resolved path: %v", names(entries))
	}
	if app.hdr.Typeflag != tar.TypeReg || app.body != "app" {
		t.Errorf("usr/bin/app = type %c body %q, want regular file %q", app.hdr.Typeflag, app.body, "app")
	}
	checkParents(t, entries)
}

// A higher layer can replace a lower layer's directory tree with a regular
// file. Children under that path cannot exist, so they must be dropped rather
// than emitted as orphans mke2fs would reject.
func TestFlattenChildOfRegularFileParent(t *testing.T) {
	entries := flattenStream(t, bytes.NewReader(tarBytes(t,
		entry{hdr: tar.Header{Name: "bin", Typeflag: tar.TypeReg, Mode: 0o644}, body: "file"},
		entry{hdr: tar.Header{Name: "usr/", Typeflag: tar.TypeDir, Mode: 0o755}},
		entry{hdr: tar.Header{Name: "usr/bin/", Typeflag: tar.TypeDir, Mode: 0o755}},
		entry{hdr: tar.Header{Name: "bin", Typeflag: tar.TypeSymlink, Linkname: "usr/bin"}},
		entry{hdr: tar.Header{Name: "bin/app", Typeflag: tar.TypeReg, Mode: 0o755}, body: "app"},
	)))

	bin, i := findEntry(entries, "bin")
	if i < 0 {
		t.Fatalf("tar lacks bin: %v", names(entries))
	}
	if bin.hdr.Typeflag != tar.TypeReg || bin.body != "file" {
		t.Errorf("bin = type %c body %q, want regular file %q", bin.hdr.Typeflag, bin.body, "file")
	}
	for _, name := range []string{"bin/app", "usr/bin/app"} {
		if n := countEntry(entries, name); n != 0 {
			t.Errorf("tar has %d entries for %s, want 0: %v", n, name, names(entries))
		}
	}
	checkParents(t, entries)
}

// A hardlink in a higher layer points at a file in a lower layer. mutate.Extract
// emits the link first; mke2fs needs the target first.
func TestFlattenHardlinkAcrossLayers(t *testing.T) {
	base := layer(t,
		entry{hdr: tar.Header{Name: "usr/", Typeflag: tar.TypeDir, Mode: 0o755}},
		entry{hdr: tar.Header{Name: "usr/bin/", Typeflag: tar.TypeDir, Mode: 0o755}},
		entry{hdr: tar.Header{Name: "usr/bin/x", Typeflag: tar.TypeReg, Mode: 0o755}, body: "x"},
	)
	top := layer(t, entry{hdr: tar.Header{Name: "usr/bin/y", Typeflag: tar.TypeLink, Linkname: "usr/bin/x"}})
	img, err := mutate.AppendLayers(empty.Image, base, top)
	if err != nil {
		t.Fatal(err)
	}
	entries := flatten(t, img)

	x, xi := findEntry(entries, "usr/bin/x")
	y, yi := findEntry(entries, "usr/bin/y")
	if xi < 0 || yi < 0 {
		t.Fatalf("tar lacks usr/bin/x or usr/bin/y: %v", names(entries))
	}
	if xi > yi {
		t.Errorf("hardlink usr/bin/y precedes its target usr/bin/x: %v", names(entries))
	}
	if y.hdr.Typeflag != tar.TypeLink || y.hdr.Linkname != "usr/bin/x" {
		t.Errorf("usr/bin/y = type %c link %q, want hardlink to usr/bin/x", y.hdr.Typeflag, y.hdr.Linkname)
	}
	if x.hdr.Typeflag != tar.TypeReg || x.body != "x" {
		t.Errorf("usr/bin/x = type %c body %q, want regular file %q", x.hdr.Typeflag, x.body, "x")
	}
	checkParents(t, entries)
}

// The hardlink target can sort after the link, and it may sit in another
// directory: the emitter must pull the target forward, parents included.
func TestFlattenHardlinkTargetSortsLater(t *testing.T) {
	base := layer(t,
		entry{hdr: tar.Header{Name: "z/", Typeflag: tar.TypeDir, Mode: 0o755}},
		entry{hdr: tar.Header{Name: "z/target", Typeflag: tar.TypeReg, Mode: 0o755}, body: "data"},
	)
	top := layer(t, entry{hdr: tar.Header{Name: "a", Typeflag: tar.TypeLink, Linkname: "z/target"}})
	img, err := mutate.AppendLayers(empty.Image, base, top)
	if err != nil {
		t.Fatal(err)
	}
	entries := flatten(t, img)

	target, ti := findEntry(entries, "z/target")
	link, li := findEntry(entries, "a")
	if ti < 0 || li < 0 {
		t.Fatalf("tar lacks z/target or a: %v", names(entries))
	}
	if ti > li {
		t.Errorf("hardlink a precedes its target z/target: %v", names(entries))
	}
	if link.hdr.Typeflag != tar.TypeLink || link.hdr.Linkname != "z/target" {
		t.Errorf("a = type %c link %q, want hardlink to z/target", link.hdr.Typeflag, link.hdr.Linkname)
	}
	if target.body != "data" {
		t.Errorf("z/target body = %q, want %q", target.body, "data")
	}
	checkParents(t, entries)
}

// A hardlink whose target is not in the flattened stream (a later layer
// whiteouted it) is materialised as a regular file so the import can proceed.
func TestFlattenHardlinkMissingTarget(t *testing.T) {
	img := layerImage(t, entry{hdr: tar.Header{Name: "y", Typeflag: tar.TypeLink, Linkname: "gone"}})
	entries := flatten(t, img)

	y, i := findEntry(entries, "y")
	if i < 0 {
		t.Fatalf("tar lacks y: %v", names(entries))
	}
	if y.hdr.Typeflag != tar.TypeReg || y.hdr.Linkname != "" || y.hdr.Size != 0 {
		t.Errorf("y = type %c link %q size %d, want an empty regular file", y.hdr.Typeflag, y.hdr.Linkname, y.hdr.Size)
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

func layerImage(t *testing.T, entries ...entry) v1.Image {
	t.Helper()
	img, err := mutate.AppendLayers(empty.Image, layer(t, entries...))
	if err != nil {
		t.Fatal(err)
	}
	return img
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
