package image

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

type ent struct {
	name, body, link string
	typ              byte
}

func layer(t *testing.T, ents ...ent) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range ents {
		h := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: 0o644, Linkname: e.link}
		if e.typ == 0 {
			h.Typeflag = tar.TypeReg
		}
		if h.Typeflag == tar.TypeDir {
			h.Mode = 0o755
		}
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	b := buf.Bytes()
	l, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil })
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func tree(t *testing.T, dir string) []string {
	var out []string
	filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || p == dir {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		s := rel
		switch {
		case fi.Mode()&os.ModeSymlink != 0:
			l, _ := os.Readlink(p)
			s += " -> " + l
		case fi.IsDir():
			s += "/"
		default:
			b, _ := os.ReadFile(p)
			s += " = " + string(b)
		}
		out = append(out, s)
		return nil
	})
	sort.Strings(out)
	return out
}

func extract(t *testing.T, layers ...v1.Layer) (string, error) {
	img, err := mutate.AppendLayers(empty.Image, layers...)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "root")
	return dir, Extract(context.Background(), img, dir, ExtractOptions{NoChown: true, SkipDevices: true})
}

func TestWhiteouts(t *testing.T) {
	l1 := layer(t,
		ent{name: "etc/", typ: tar.TypeDir},
		ent{name: "etc/a", body: "1"},
		ent{name: "etc/b", body: "1"},
		ent{name: "opt/", typ: tar.TypeDir},
		ent{name: "opt/old", body: "1"},
		ent{name: "opt/sub/", typ: tar.TypeDir},
		ent{name: "opt/sub/x", body: "1"},
		ent{name: "link", typ: tar.TypeSymlink, link: "/etc/a"},
		ent{name: "file-then-dir", body: "f"},
	)
	l2 := layer(t,
		ent{name: "etc/.wh.a"},
		ent{name: "etc/b", body: "2"},
		ent{name: "opt/new", body: "2"}, // same layer as the opaque marker
		ent{name: "opt/.wh..wh..opq"},
		ent{name: "hard", typ: tar.TypeLink, link: "etc/b"},
		ent{name: "file-then-dir/", typ: tar.TypeDir},
		ent{name: "file-then-dir/in", body: "3"},
	)
	dir, err := extract(t, l1, l2)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(tree(t, dir), "\n")
	want := strings.Join([]string{
		"etc/", "etc/b = 2", "file-then-dir/", "file-then-dir/in = 3", "hard = 2",
		"link -> /etc/a", "opt/", "opt/new = 2",
	}, "\n")
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

func TestTraversal(t *testing.T) {
	// "../x" is cleaned to "x" inside the root.
	dir, err := extract(t, layer(t, ent{name: "../../escape", body: "x"}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "escape")); err == nil {
		t.Fatal("escaped")
	}
	// Writing through a symlink that points outside must fail.
	outside := t.TempDir()
	_, err = extract(t,
		layer(t, ent{name: "evil", typ: tar.TypeSymlink, link: outside}),
		layer(t, ent{name: "evil/pwned", body: "x"}),
	)
	if err == nil {
		t.Fatal("write through symlink must fail")
	}
	if _, err := os.Stat(filepath.Join(outside, "pwned")); err == nil {
		t.Fatal("escaped through symlink")
	}
	// Hard link to a file outside the root must fail.
	if _, err := extract(t, layer(t, ent{name: "h", typ: tar.TypeLink, link: "../../etc/passwd"})); err == nil {
		t.Fatal("hard link outside must fail")
	}
}

func TestExtractNeedsEmptyDir(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "x"), nil, 0o644)
	img, _ := mutate.AppendLayers(empty.Image, layer(t, ent{name: "a", body: "1"}))
	if err := Extract(context.Background(), img, dir, ExtractOptions{NoChown: true}); err == nil {
		t.Fatal("non-empty dir must fail")
	}
}
