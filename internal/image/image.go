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
	err = writeTar(f, rc)
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

// writeTar copies the tar stream r to w with clean relative names, adding any
// missing parent directory before its first child: mke2fs requires it, and
// image layers need not contain their parent directories. A real directory
// entry that comes later still sets the directory's mode and owner.
func writeTar(w io.Writer, r io.Reader) error {
	tr, tw := tar.NewReader(r), tar.NewWriter(w)
	dirs := map[string]bool{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			// Extract reports errors after the end-of-archive trailer.
			if _, err := io.Copy(io.Discard, r); err != nil {
				return err
			}
			return tw.Close()
		}
		if err != nil {
			return err
		}
		h.Name = path.Clean("/" + h.Name)[1:]
		if h.Name == "" {
			continue
		}
		for i := range len(h.Name) {
			if p := h.Name[:i]; h.Name[i] == '/' && !dirs[p] {
				dirs[p] = true
				if err := tw.WriteHeader(&tar.Header{Name: p, Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
					return err
				}
			}
		}
		if h.Typeflag == tar.TypeDir {
			dirs[h.Name] = true
		}
		if h.Typeflag == tar.TypeLink {
			h.Linkname = path.Clean("/" + h.Linkname)[1:]
		}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if _, err := io.Copy(tw, tr); err != nil {
			return err
		}
	}
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
