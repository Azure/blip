// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package image

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

type entry struct {
	hdr  tar.Header
	body string
}

func tarBytes(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := e.hdr
		h.Size = int64(len(e.body))
		if h.Mode == 0 {
			h.Mode = 0o644
		}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func layer(t *testing.T, entries ...entry) v1.Layer {
	t.Helper()
	data := tarBytes(t, entries...)
	l, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// testImage returns a two-layer linux/GOARCH image. The top layer deletes
// /etc/gone with a whiteout and lacks the entries of its parent directories.
func testImage(t *testing.T) v1.Image {
	t.Helper()
	base := layer(t,
		entry{hdr: tar.Header{Name: "etc/", Typeflag: tar.TypeDir, Mode: 0o755}},
		entry{hdr: tar.Header{Name: "etc/hello", Typeflag: tar.TypeReg}, body: "hello world\n"},
		entry{hdr: tar.Header{Name: "etc/gone", Typeflag: tar.TypeReg}, body: "x"},
		entry{hdr: tar.Header{Name: "tmp/", Typeflag: tar.TypeDir, Mode: 0o1777}},
	)
	top := layer(t,
		entry{hdr: tar.Header{Name: "etc/.wh.gone", Typeflag: tar.TypeReg}},
		entry{hdr: tar.Header{Name: "usr/bin/tool", Typeflag: tar.TypeReg, Mode: 0o755}, body: "#!/bin/sh\n"},
		entry{hdr: tar.Header{Name: "./usr/bin/tool2", Typeflag: tar.TypeLink, Linkname: "./usr/bin/tool"}},
		entry{hdr: tar.Header{Name: "bin", Typeflag: tar.TypeSymlink, Linkname: "usr/bin"}},
		entry{hdr: tar.Header{Name: "tmp/x", Typeflag: tar.TypeReg}, body: "x"},
	)
	img, err := mutate.AppendLayers(empty.Image, base, top)
	if err != nil {
		t.Fatal(err)
	}
	cf, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	cf = cf.DeepCopy()
	cf.OS, cf.Architecture = "linux", runtime.GOARCH
	cf.Config = v1.Config{Entrypoint: []string{"/bin/tool"}, Cmd: []string{"sh"}, Env: []string{"PATH=/usr/bin"}, WorkingDir: "/etc", User: "1000"}
	img, err = mutate.ConfigFile(img, cf)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func startRegistry(t *testing.T) (host string, insecure []string) {
	t.Helper()
	srv := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(srv.Close)
	host = strings.TrimPrefix(srv.URL, "http://")
	return host, []string{host}
}

func push(t *testing.T, ref string, insecure []string, w remote.Taggable) {
	t.Helper()
	r, err := ParseReference(ref, insecure)
	if err != nil {
		t.Fatal(err)
	}
	switch v := w.(type) {
	case v1.Image:
		err = remote.Write(r, v)
	case v1.ImageIndex:
		err = remote.WriteIndex(r, v)
	}
	if err != nil {
		t.Fatal(err)
	}
}

// tarNames returns the entry names of the tar file at path, in order.
func tarNames(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var names []string
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return names
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
	}
}

func TestPull(t *testing.T) {
	host, insecure := startRegistry(t)
	img := testImage(t)
	other, err := random.Image(64, 1)
	if err != nil {
		t.Fatal(err)
	}
	idx := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: other, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "not-" + runtime.GOARCH}}},
		mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: runtime.GOARCH}}},
	)
	push(t, host+"/test/single:v1", insecure, img)
	push(t, host+"/test/multi:v1", insecure, idx)
	ctx := context.Background()

	for _, repo := range []string{"single", "multi"} {
		t.Run(repo, func(t *testing.T) {
			want, _ := img.Digest()
			if repo == "multi" {
				want, _ = idx.Digest()
			}
			pinned := host + "/test/" + repo + "@" + want.String()
			if d, err := DigestOf(pinned); err != nil || d != want.String() {
				t.Fatalf("DigestOf(%q) = %q, %v; want %s", pinned, d, err, want)
			}

			dir := t.TempDir()
			cfg, path, err := Pull(ctx, pinned, Options{Insecure: insecure}, dir)
			if err != nil {
				t.Fatal(err)
			}
			if filepath.Dir(path) != dir {
				t.Fatalf("tar at %s, want in %s", path, dir)
			}
			if cfg.WorkingDir != "/etc" || cfg.User != "1000" || len(cfg.Cmd) != 1 || cfg.Entrypoint[0] != "/bin/tool" || cfg.Env[0] != "PATH=/usr/bin" {
				t.Fatalf("config = %+v", cfg)
			}
			names := tarNames(t, path)
			seen := map[string]bool{}
			for _, name := range names {
				if strings.Contains(name, "gone") {
					t.Errorf("whiteout not applied: %s in tar", name)
				}
				if dir := filepath.Dir(name); dir != "." && !seen[dir] {
					t.Errorf("%s comes before its directory: %v", name, names)
				}
				seen[name] = true
			}
			for _, name := range []string{"etc/hello", "usr/bin/tool", "usr/bin/tool2", "bin", "tmp/x"} {
				if !seen[name] {
					t.Errorf("tar lacks %s: %v", name, names)
				}
			}
		})
	}
}

func TestPullErrorLeavesNoFile(t *testing.T) {
	img := testImage(t)
	layers, err := img.Layers()
	if err != nil {
		t.Fatal(err)
	}
	broken, err := layers[1].Digest()
	if err != nil {
		t.Fatal(err)
	}
	reg := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, broken.String()) {
			http.Error(w, "gone", http.StatusInternalServerError)
			return
		}
		reg.ServeHTTP(w, r)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	insecure := []string{host}
	push(t, host+"/test/broken:v1", insecure, img)

	dir := t.TempDir()
	if _, _, err := Pull(context.Background(), host+"/test/broken:v1", Options{Insecure: insecure}, dir); err == nil {
		t.Fatal("pull with a broken layer succeeded")
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("left behind %v", ents)
	}
}

func TestPullRejectsWrongArch(t *testing.T) {
	host, insecure := startRegistry(t)
	img := testImage(t)
	cf, _ := img.ConfigFile()
	cf = cf.DeepCopy()
	cf.Architecture = "not-" + runtime.GOARCH
	img, err := mutate.ConfigFile(img, cf)
	if err != nil {
		t.Fatal(err)
	}
	push(t, host+"/test/arch:v1", insecure, img)
	if _, _, err := Pull(context.Background(), host+"/test/arch:v1", Options{Insecure: insecure}, t.TempDir()); err == nil {
		t.Fatal("pull of a foreign-arch image succeeded")
	}
}

func TestFSSize(t *testing.T) {
	for in, want := range map[int64]int64{0: 256 << 20, 1: 257 << 20, 100 << 20: 406 << 20} {
		if got := FSSize(in); got != want {
			t.Errorf("FSSize(%d) = %d, want %d", in, got, want)
		}
	}
}

// needMke2fsTar skips unless mke2fs can populate a filesystem from a tarball
// (e2fsprogs >= 1.47.1 built with libarchive).
func needMke2fsTar(t *testing.T) {
	t.Helper()
	t.Setenv("PATH", os.Getenv("PATH")+":/usr/sbin:/sbin")
	for _, tool := range []string{"mke2fs", "debugfs"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "probe.tar")
	if err := os.WriteFile(tarPath, tarBytes(t, entry{hdr: tar.Header{Name: "probe", Typeflag: tar.TypeReg}, body: "x"}), 0o644); err != nil {
		t.Fatal(err)
	}
	dev := filepath.Join(dir, "probe.ext4")
	if out, err := exec.Command("mke2fs", "-q", "-F", "-t", "ext4", "-d", tarPath, dev, "8M").CombinedOutput(); err != nil {
		t.Skipf("mke2fs cannot read tarballs: %v: %s", err, out)
	}
}

func TestMakeFS(t *testing.T) {
	needMke2fsTar(t)
	host, insecure := startRegistry(t)
	push(t, host+"/test/fs:v1", insecure, testImage(t))
	dir := t.TempDir()
	_, tarPath, err := Pull(context.Background(), host+"/test/fs:v1", Options{Insecure: insecure}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(tarPath)
	if err != nil {
		t.Fatal(err)
	}
	makeFS := func(name string) string {
		dev := filepath.Join(dir, name)
		f, err := os.Create(dev)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(FSSize(fi.Size())); err != nil {
			t.Fatal(err)
		}
		f.Close()
		if err := MakeFS(context.Background(), tarPath, dev, "sha256:1234"); err != nil {
			t.Fatal(err)
		}
		return dev
	}
	dev := makeFS("fs.ext4")
	// Conversion is reproducible: every node builds the same bytes.
	a, err := os.ReadFile(dev)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(makeFS("again.ext4"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("converting the same image twice gave different bytes")
	}

	debugfs := func(cmd string) string {
		out, err := exec.Command("debugfs", "-R", cmd, dev).CombinedOutput()
		if err != nil {
			t.Fatalf("debugfs %s: %v: %s", cmd, err, out)
		}
		return string(out)
	}
	if out := debugfs("cat /etc/hello"); !strings.Contains(out, "hello world") {
		t.Fatalf("cat /etc/hello: %s", out)
	}
	if out := debugfs("ls /etc"); strings.Contains(out, "gone") {
		t.Fatalf("whiteout not applied: %s", out)
	}
	if out := debugfs("stat /bin"); !strings.Contains(out, `Fast link dest: "usr/bin"`) {
		t.Fatalf("stat /bin: %s", out)
	}
	if out := debugfs("stat /usr/bin/tool2"); !strings.Contains(out, "Links: 2") {
		t.Fatalf("stat /usr/bin/tool2: %s", out)
	}
	if out := debugfs("stat /tmp"); !strings.Contains(out, "Mode:  01777") {
		t.Fatalf("stat /tmp: %s", out)
	}
	if out := debugfs("stat /"); !strings.Contains(out, "User:     0   Group:     0") {
		t.Fatalf("stat /: %s", out)
	}
	if out := debugfs("stats"); !strings.Contains(out, seedUUID("uuid", "sha256:1234")) {
		t.Fatalf("UUID is not derived from the seed: %s", out)
	}
}
