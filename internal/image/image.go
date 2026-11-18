// Package image pulls ordinary container images and turns them into ext4
// filesystems: Pull flattens the linux/GOARCH variant into one tar file and
// MakeFS writes it to a block device. See docs/ARCHITECTURE.md.
package image

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"runtime"
	"slices"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Config is the part of an image's OCI config that blip uses.
type Config struct {
	Entrypoint []string `json:"entrypoint,omitempty"`
	Cmd        []string `json:"cmd,omitempty"`
	Env        []string `json:"env,omitempty"`
	WorkingDir string   `json:"workingDir,omitempty"`
	User       string   `json:"user,omitempty"`
}

// Options configures registry access.
type Options struct {
	// Insecure lists registries (host or host:port) that are reached over
	// plain HTTP.
	Insecure []string
	// Keychain resolves registry credentials. Nil means the default Docker
	// keychain of the process.
	Keychain authn.Keychain
}

// ParseReference parses ref, treating registries listed in insecure as plain HTTP.
func ParseReference(ref string, insecure []string) (name.Reference, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, err
	}
	if slices.Contains(insecure, r.Context().RegistryStr()) {
		return name.ParseReference(ref, name.Insecure)
	}
	return r, nil
}

// DigestOf returns the "sha256:..." part of a pinned reference "repo@sha256:...".
func DigestOf(ref string) (string, error) {
	i := strings.LastIndex(ref, "@")
	if i < 0 {
		return "", fmt.Errorf("image reference %q is not pinned to a digest", ref)
	}
	h, err := v1.NewHash(ref[i+1:])
	if err != nil {
		return "", fmt.Errorf("image reference %q: %w", ref, err)
	}
	return h.String(), nil
}

// Resolve returns the pinned reference "repo@sha256:..." of ref. For a
// multi-platform image this is the digest of the index.
func Resolve(ctx context.Context, ref string, opts Options) (string, error) {
	r, err := ParseReference(ref, opts.Insecure)
	if err != nil {
		return "", err
	}
	desc, err := remote.Head(r, remoteOptions(ctx, opts)...)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", ref, err)
	}
	return r.Context().Digest(desc.Digest.String()).String(), nil
}

// Pull fetches the linux/GOARCH variant of ref and writes its flattened
// filesystem (layers applied, whiteouts removed, parent directories before
// their children) as a tar file in dir. The caller removes the file.
func Pull(ctx context.Context, ref string, opts Options, dir string) (Config, string, error) {
	cfg, path, err := pull(ctx, ref, opts, dir)
	if err != nil {
		return Config{}, "", fmt.Errorf("pull %s: %w", ref, err)
	}
	return cfg, path, nil
}

func pull(ctx context.Context, ref string, opts Options, dir string) (Config, string, error) {
	r, err := ParseReference(ref, opts.Insecure)
	if err != nil {
		return Config{}, "", err
	}
	img, err := remote.Image(r, remoteOptions(ctx, opts)...)
	if err != nil {
		return Config{}, "", err
	}
	cf, err := img.ConfigFile()
	if err != nil {
		return Config{}, "", err
	}
	if (cf.OS != "" && cf.OS != "linux") || (cf.Architecture != "" && cf.Architecture != runtime.GOARCH) {
		return Config{}, "", fmt.Errorf("image is %s/%s, need linux/%s", cf.OS, cf.Architecture, runtime.GOARCH)
	}
	c := cf.Config
	cfg := Config{Entrypoint: c.Entrypoint, Cmd: c.Cmd, Env: c.Env, WorkingDir: c.WorkingDir, User: c.User}
	f, err := os.CreateTemp(dir, "image-*.tar")
	if err != nil {
		return Config{}, "", err
	}
	rc := mutate.Extract(img)
	err = writeTarTo(f, rc, dir)
	if cerr := rc.Close(); err == nil {
		err = cerr
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(f.Name())
		return Config{}, "", err
	}
	return cfg, f.Name(), nil
}

// writeTar copies the flattened image stream r to w. writeTarTo is the same
// with temporary files in dir.
func writeTar(w io.Writer, r io.Reader) error {
	return writeTarTo(w, r, "")
}

// writeTarTo copies the tar stream r to w with clean relative names. It emits
// every path once, parents before their children, and resolves a parent path
// through a symlink the image defines in any layer (Debian's /bin -> usr/bin),
// so a child of that parent lands at the path the kernel would use. mke2fs
// applies tar entries strictly in order and does not follow a symlinked parent.
//
// The stream from mutate.Extract is ordered top layer first, so the symlink
// can appear after the entry that depends on it. writeTarTo therefore buffers
// the file bodies on disk and builds the merged namespace before writing
// anything.
func writeTarTo(w io.Writer, r io.Reader, dir string) error {
	spool, err := os.CreateTemp(dir, "image-*.body")
	if err != nil {
		return err
	}
	defer spool.Close()
	defer os.Remove(spool.Name())

	var (
		items []tarItem
		syms  []tarSymlink
		seen  = map[string]bool{}
	)
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			// Extract reports errors after the end-of-archive trailer.
			if _, err := io.Copy(io.Discard, r); err != nil {
				return err
			}
			break
		}
		if err != nil {
			return err
		}
		// tr.Next reuses its header, and writeHeader may be handed a modified
		// copy, so keep a value copy of every one.
		hdr := *h
		hdr.Name = cleanTarName(hdr.Name)
		if hdr.Name == "" {
			continue
		}
		off, err := spool.Seek(0, io.SeekCurrent)
		if err != nil {
			return err
		}
		if _, err := io.Copy(spool, tr); err != nil {
			return err
		}
		if hdr.Typeflag == tar.TypeSymlink && !seen[hdr.Name] {
			// The first entry for a name wins: the input is top layer first.
			seen[hdr.Name] = true
			syms = append(syms, tarSymlink{name: hdr.Name, target: hdr.Linkname})
		}
		items = append(items, tarItem{hdr: &hdr, off: off})
	}

	links := resolveLinks(syms)
	final := map[string]*tarEntry{}
	// addParents synthesises the directories mke2fs needs but an image layer
	// need not contain. A real directory entry replaces its synthetic parent
	// later, preserving its mode and owner.
	addParents := func(name string) {
		for i := 1; i < len(name); i++ {
			if name[i] != '/' {
				continue
			}
			p := name[:i]
			if _, ok := final[p]; !ok {
				final[p] = &tarEntry{
					hdr:       &tar.Header{Name: p, Typeflag: tar.TypeDir, Mode: 0o755},
					synthetic: true,
				}
			}
		}
	}
	for _, it := range items {
		h := it.hdr
		parent, ok := resolvePath(parentName(h.Name), links)
		if !ok {
			// The path goes through a symlink loop, so the kernel could not
			// reach it either.
			continue
		}
		name := joinName(parent, path.Base(h.Name))
		h.Name = name
		if h.Typeflag == tar.TypeLink {
			target := cleanTarName(h.Linkname)
			if target != "" {
				tparent, ok := resolvePath(parentName(target), links)
				if !ok {
					continue
				}
				h.Linkname = joinName(tparent, path.Base(target))
			}
		}
		e := &tarEntry{hdr: h, off: it.off}
		if old, ok := final[name]; !ok || old.synthetic {
			// Keep the highest layer's entry; only a synthetic directory may
			// be replaced by a real entry for the same path.
			final[name] = e
		}
		addParents(name)
	}

	tw := tar.NewWriter(w)
	names := make([]string, 0, len(final))
	for name := range final {
		names = append(names, name)
	}
	// Sorting puts a parent before every child because the parent is a prefix
	// of the child's name.
	slices.Sort(names)
	for _, name := range names {
		e := final[name]
		hdr := *e.hdr
		if err := tw.WriteHeader(&hdr); err != nil {
			return err
		}
		if hdr.Size > 0 && hdr.Typeflag != tar.TypeLink {
			if _, err := spool.Seek(e.off, io.SeekStart); err != nil {
				return err
			}
			if _, err := io.CopyN(tw, spool, hdr.Size); err != nil {
				return err
			}
		}
	}
	return tw.Close()
}

type tarItem struct {
	hdr *tar.Header
	off int64
}

type tarSymlink struct {
	name, target string
}

type tarEntry struct {
	hdr       *tar.Header
	off       int64
	synthetic bool
}

// cleanTarName turns an archive path into a clean path relative to the image
// root, so absolute names and ".." cannot escape it.
func cleanTarName(name string) string {
	return path.Clean("/" + name)[1:]
}

func parentName(name string) string {
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		return name[:i]
	}
	return ""
}

func joinName(dir, base string) string {
	if dir == "" {
		return base
	}
	return dir + "/" + base
}

// resolveLinks places every symlink in the merged tree. A symlink whose parent
// path is itself a symlink belongs at the resolved parent, not at its name in
// the layer. The locations are a fixed point: resolving one symlink can need
// the resolved location of another, so repeat until the map stops changing.
func resolveLinks(syms []tarSymlink) map[string]string {
	prev := map[string]string{}
	for range len(syms) + 1 {
		cur := make(map[string]string, len(syms))
		for _, s := range syms {
			parent, ok := resolvePath(parentName(s.name), prev)
			if !ok {
				continue
			}
			loc := joinName(parent, path.Base(s.name))
			if _, ok := cur[loc]; !ok {
				cur[loc] = s.target
			}
		}
		var same bool
		if same = len(cur) == len(prev); same {
			for k, v := range cur {
				if prev[k] != v {
					same = false
					break
				}
			}
		}
		if same {
			break
		}
		prev = cur
	}
	return prev
}

// resolvePath resolves every symlink in the root-relative path p. Relative
// targets are interpreted from the link's directory and absolute targets from
// the image root; ".." is clamped at the root, matching how the kernel
// resolves paths inside a container. The last bool is false when a symlink
// loop makes the path unreachable.
func resolvePath(p string, links map[string]string) (string, bool) {
	const maxHops = 255
	var out []string
	rest := p
	for hops := 0; rest != ""; {
		var c string
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			c, rest = rest[:i], rest[i+1:]
		} else {
			c, rest = rest, ""
		}
		switch c {
		case "", ".":
			continue
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
			continue
		}
		canonical := joinName(strings.Join(out, "/"), c)
		target, ok := links[canonical]
		if !ok {
			out = append(out, c)
			continue
		}
		hops++
		if hops > maxHops {
			return "", false
		}
		var tp string
		if strings.HasPrefix(target, "/") {
			tp = strings.TrimLeft(target, "/")
		} else {
			tp = joinName(strings.Join(out, "/"), target)
		}
		if rest != "" {
			tp = joinName(tp, rest)
		}
		out, rest = nil, tp
	}
	return strings.Join(out, "/"), true
}

// FSSize returns the ext4 size for a filesystem holding tarBytes of tar
// content: half again for metadata and slack plus 256MiB of free space,
// rounded up to 1MiB.
func FSSize(tarBytes int64) int64 {
	const mib = 1 << 20
	n := tarBytes + tarBytes/2 + 256*mib
	return (n + mib - 1) / mib * mib
}

// MakeFS creates an ext4 filesystem on dev populated from the tar file at
// tarPath. It needs mke2fs 1.47.1 or later built with libarchive.
//
// The result is reproducible: the same tar file, device size, and seed (the
// image digest) give the same bytes on every node. The UUID and directory
// hash seed derive from seed, the clock is fixed, and the RAID geometry,
// which mke2fs otherwise reads from the device, is set to the 64 KiB thin
// block.
func MakeFS(ctx context.Context, tarPath, dev, seed string) error {
	opts := "root_owner=0:0,nodiscard,lazy_itable_init=1,lazy_journal_init=1,stride=16,stripe_width=16," +
		"hash_seed=" + seedUUID("hash", seed)
	cmd := exec.CommandContext(ctx, "mke2fs", "-q", "-F", "-t", "ext4", "-b", "4096", "-i", "8192", "-m", "0",
		"-U", seedUUID("uuid", seed), "-d", tarPath, "-E", opts, dev)
	// libarchive rejects non-ASCII names unless the locale is UTF-8.
	cmd.Env = append(os.Environ(), "LC_ALL=C.UTF-8", "E2FSPROGS_FAKE_TIME="+fakeTime)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mke2fs %s: %w: %s", dev, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// fakeTime is the clock of reproducible e2fsprogs runs, shared with the
// storage package's filesystem growth (2025-01-01T00:00:00Z). Unlike
// SOURCE_DATE_EPOCH, E2FSPROGS_FAKE_TIME does not clamp file times.
const fakeTime = "1735689600"

// seedUUID derives a version 4 style UUID from seed.
func seedUUID(purpose, seed string) string {
	sum := sha256.Sum256([]byte("blip-mkfs-" + purpose + ":" + seed))
	b := sum[:16]
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func remoteOptions(ctx context.Context, opts Options) []remote.Option {
	kc := opts.Keychain
	if kc == nil {
		kc = authn.DefaultKeychain
	}
	return []remote.Option{
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(kc),
		remote.WithPlatform(v1.Platform{OS: "linux", Architecture: runtime.GOARCH}),
	}
}
