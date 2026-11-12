// Package image turns an OCI image into an ext4 filesystem on a block
// device.
//
// Pull fetches an image with go-containerregistry and extracts its layers
// into a directory, applying whiteouts. MkfsExt4 then builds the
// filesystem from that directory with "mkfs.ext4 -d".
package image

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"golang.org/x/sys/unix"

	"github.com/example/blip/internal/storage/run"
)

// Auth holds registry credentials. A nil *Auth means anonymous.
type Auth struct {
	Username, Password string
}

// ErrPull marks errors from fetching the image from the registry.
var ErrPull = errors.New("image pull failed")

// Pull fetches ref for platform ("linux/amd64"; empty means this machine)
// and extracts it into dir, which must be empty or missing. It returns the
// manifest digest.
func Pull(ctx context.Context, ref string, auth *Auth, platform string, dir string) (string, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return "", fmt.Errorf("image reference %q: %w", ref, err)
	}
	if platform == "" {
		platform = runtime.GOOS + "/" + runtime.GOARCH
	}
	p, err := v1.ParsePlatform(platform)
	if err != nil {
		return "", err
	}
	opts := []remote.Option{remote.WithContext(ctx), remote.WithPlatform(*p)}
	if auth != nil {
		opts = append(opts, remote.WithAuth(&authn.Basic{Username: auth.Username, Password: auth.Password}))
	} else {
		opts = append(opts, remote.WithAuth(authn.Anonymous))
	}
	img, err := remote.Image(r, opts...)
	if err != nil {
		return "", fmt.Errorf("pull %s: %w: %w", ref, ErrPull, err)
	}
	d, err := img.Digest()
	if err != nil {
		return "", err
	}
	if err := Extract(ctx, img, dir, ExtractOptions{}); err != nil {
		return "", err
	}
	return d.String(), nil
}

// ExtractOptions changes extraction for tests that do not run as root.
type ExtractOptions struct {
	NoChown     bool // do not set owners
	SkipDevices bool // do not create device nodes and fifos
}

// Extract writes the flattened filesystem of img into dir.
func Extract(ctx context.Context, img v1.Image, dir string, opts ExtractOptions) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if ents, err := os.ReadDir(dir); err != nil || len(ents) > 0 {
		return fmt.Errorf("extract: %s must be an empty directory", dir)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	layers, err := img.Layers()
	if err != nil {
		return err
	}
	x := &extractor{root: root, opts: opts, dirTimes: map[string]time.Time{}}
	for i, l := range layers {
		if err := ctx.Err(); err != nil {
			return err
		}
		rc, err := l.Uncompressed()
		if err != nil {
			return fmt.Errorf("layer %d: %w", i, err)
		}
		err = x.layer(tar.NewReader(rc))
		rc.Close()
		if err != nil {
			return fmt.Errorf("layer %d: %w", i, err)
		}
	}
	return x.finish()
}

type extractor struct {
	root     *os.Root
	opts     ExtractOptions
	dirTimes map[string]time.Time
	added    map[string]bool // paths written by the current layer
}

// clean turns a tar name into a relative path inside the root, or "" for
// the root itself.
func clean(n string) (string, error) {
	p := path.Clean("/" + n)
	if p == "/" {
		return "", nil
	}
	p = strings.TrimPrefix(p, "/")
	return p, nil
}

const (
	whPrefix = ".wh."
	whOpaque = ".wh..wh..opq"
)

func (x *extractor) layer(tr *tar.Reader) error {
	x.added = map[string]bool{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		p, err := clean(h.Name)
		if err != nil {
			return err
		}
		if p == "" {
			continue
		}
		dir, base := path.Split(p)
		dir = strings.TrimSuffix(dir, "/")
		if base == whOpaque {
			if err := x.opaque(dir); err != nil {
				return err
			}
			continue
		}
		if strings.HasPrefix(base, whPrefix) {
			target := path.Join(dir, strings.TrimPrefix(base, whPrefix))
			if err := x.root.RemoveAll(target); err != nil {
				return fmt.Errorf("whiteout %s: %w", target, err)
			}
			continue
		}
		if err := x.entry(p, h, tr); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		x.added[p] = true
	}
}

// opaque removes everything in dir that earlier layers created.
func (x *extractor) opaque(dir string) error {
	d := dir
	if d == "" {
		d = "."
	}
	f, err := x.root.Open(d)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	names, err := f.Readdirnames(-1)
	f.Close()
	if err != nil {
		return err
	}
	for _, n := range names {
		p := path.Join(dir, n)
		if x.added[p] {
			continue
		}
		if err := x.root.RemoveAll(p); err != nil {
			return err
		}
	}
	return nil
}

func (x *extractor) entry(p string, h *tar.Header, r io.Reader) error {
	dir := path.Dir(p)
	if dir != "." {
		if err := x.root.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	// Replace whatever is there unless both are directories.
	if fi, err := x.root.Lstat(p); err == nil {
		if !(fi.IsDir() && h.Typeflag == tar.TypeDir) {
			if err := x.root.RemoveAll(p); err != nil {
				return err
			}
		}
	}
	mode := os.FileMode(h.Mode) & os.ModePerm
	switch h.Typeflag {
	case tar.TypeDir:
		if err := x.root.Mkdir(p, mode); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		x.dirTimes[p] = h.ModTime
	case tar.TypeReg, tar.TypeRegA:
		f, err := x.root.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if err != nil {
			return err
		}
		if _, err := io.Copy(f, r); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	case tar.TypeSymlink:
		if err := x.root.Symlink(h.Linkname, p); err != nil {
			return err
		}
	case tar.TypeLink:
		old, err := clean(h.Linkname)
		if err != nil || old == "" {
			return fmt.Errorf("bad hard link target %q", h.Linkname)
		}
		return x.root.Link(old, p) // shares metadata with the target
	case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
		if x.opts.SkipDevices {
			return nil
		}
		typ := uint32(unix.S_IFIFO)
		switch h.Typeflag {
		case tar.TypeChar:
			typ = unix.S_IFCHR
		case tar.TypeBlock:
			typ = unix.S_IFBLK
		}
		err := x.atParent(p, func(fd int, base string) error {
			return unix.Mknodat(fd, base, typ|uint32(mode), int(unix.Mkdev(uint32(h.Devmajor), uint32(h.Devminor))))
		})
		if err != nil {
			return err
		}
	default:
		return nil // other types (for example GNU sparse headers) are ignored
	}
	return x.meta(p, h)
}

// atParent opens the parent directory inside the root and calls fn with
// its descriptor and the base name.
func (x *extractor) atParent(p string, fn func(fd int, base string) error) error {
	dir, base := path.Split(p)
	if dir == "" {
		dir = "."
	}
	d, err := x.root.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return fn(int(d.Fd()), base)
}

func (x *extractor) meta(p string, h *tar.Header) error {
	return x.atParent(p, func(fd int, base string) error {
		if !x.opts.NoChown {
			if err := unix.Fchownat(fd, base, h.Uid, h.Gid, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return fmt.Errorf("chown: %w", err)
			}
		}
		if h.Typeflag != tar.TypeSymlink {
			// chown clears setuid bits, so set the mode after it.
			m := uint32(h.Mode & 0o7777)
			if err := unix.Fchmodat(fd, base, m, 0); err != nil {
				return fmt.Errorf("chmod: %w", err)
			}
		}
		for k, v := range h.PAXRecords {
			name, ok := strings.CutPrefix(k, "SCHILY.xattr.")
			if !ok {
				continue
			}
			full := fmt.Sprintf("/proc/self/fd/%d/%s", fd, base)
			if err := unix.Lsetxattr(full, name, []byte(v), 0); err != nil && !errors.Is(err, unix.ENOTSUP) {
				return fmt.Errorf("xattr %s: %w", name, err)
			}
		}
		if h.Typeflag != tar.TypeDir {
			ts := []unix.Timespec{unix.NsecToTimespec(h.ModTime.UnixNano()), unix.NsecToTimespec(h.ModTime.UnixNano())}
			if err := unix.UtimesNanoAt(fd, base, ts, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return fmt.Errorf("utimes: %w", err)
			}
		}
		return nil
	})
}

// finish sets directory times last, since adding entries changes them.
func (x *extractor) finish() error {
	for p, t := range x.dirTimes {
		if fi, err := x.root.Lstat(p); err != nil || !fi.IsDir() {
			continue
		}
		if err := x.root.Chtimes(p, t, t); err != nil {
			return err
		}
	}
	return nil
}

// MkfsOptions changes MkfsExt4.
type MkfsOptions struct {
	// UUID sets the filesystem UUID and hash seed. Empty means random.
	UUID string
	// Label sets the volume label. Default "blip".
	Label string
}

// MkfsExt4 creates an ext4 filesystem on device. If srcDir is not empty,
// the filesystem is filled from it ("mkfs.ext4 -d").
//
// The options are fixed so every root looks the same:
//   - -b 4096: 4KiB blocks, matching the page size and thin blocks.
//   - -m 0: no reserved blocks; the whole disk is for the workload.
//   - -E lazy_itable_init=0,lazy_journal_init=0: write all metadata now,
//     so the guest does not start a background init thread that would
//     dirty every block group of the thin device.
//   - -E nodiscard: do not discard the device first; a fresh thin LV
//     already reads as zeros, and discard would only cost time.
//   - -E root_owner=0:0: the root directory belongs to root.
//   - The journal is kept (default), so the guest can replay it after a
//     crash of the command.
func MkfsExt4(ctx context.Context, device, srcDir string, opts MkfsOptions) error {
	if opts.Label == "" {
		opts.Label = "blip"
	}
	ext := "lazy_itable_init=0,lazy_journal_init=0,nodiscard,root_owner=0:0"
	args := []string{"-F", "-q", "-t", "ext4", "-b", "4096", "-m", "0", "-L", opts.Label}
	if opts.UUID != "" {
		args = append(args, "-U", opts.UUID)
		ext += ",hash_seed=" + opts.UUID
	}
	// mke2fs keeps only the last -E, so all extended options go in one.
	args = append(args, "-E", ext)
	if srcDir != "" {
		abs, err := filepath.Abs(srcDir)
		if err != nil {
			return err
		}
		args = append(args, "-d", abs)
	}
	args = append(args, device)
	if _, err := run.Cmd(ctx, nil, "mkfs.ext4", args...); err != nil {
		return fmt.Errorf("mkfs.ext4 on %s: %w", device, err)
	}
	return nil
}
